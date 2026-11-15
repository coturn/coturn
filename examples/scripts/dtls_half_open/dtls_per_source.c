/* One host must not lock out every DTLS client via source-port rotation.
 *
 * usage: dtls_per_source <server-ip> <port> <attacker-bind-ip> <victim-bind-ip> <per-source-cap>
 *
 * 1. Victim completes a baseline handshake.
 * 2. Attacker opens <per-source-cap> stalled (cookie-verified) handshakes and holds them.
 * 3. Attacker tries one more stall: must be rejected (no server flight).
 * 4. Victim completes another handshake while attacker's slots are still held.
 *
 * Exit 0 = PASS, 1 = FAIL, 2 = harness error.
 */
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  return (int)recv(fd, buf, sizeof(buf), 0);
}

static void flush(int fd, BIO *w) {
  char o[65536];
  int n;
  while ((n = BIO_read(w, o, (int)sizeof(o))) > 0) {
    (void)send(fd, o, (size_t)n, 0);
  }
}

typedef struct {
  int fd;
  SSL *ssl;
  BIO *r;
  BIO *w;
} cl;

static int open_client(cl *c, const char *bind_ip, const char *srv_ip, int port, int lport, SSL_CTX *ctx) {
  c->fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in me = {0};
  me.sin_family = AF_INET;
  me.sin_port = htons((uint16_t)lport);
  if (inet_pton(AF_INET, bind_ip, &me.sin_addr) != 1) {
    perror("inet_pton bind");
    return -1;
  }
  if (bind(c->fd, (struct sockaddr *)&me, sizeof(me)) < 0) {
    perror("bind");
    return -1;
  }
  struct sockaddr_in srv = {0};
  srv.sin_family = AF_INET;
  srv.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, srv_ip, &srv.sin_addr) != 1) {
    perror("inet_pton srv");
    return -1;
  }
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

static int cookie_exchange(cl *c, int feed) {
  int n;
  int k = 0;
  SSL_do_handshake(c->ssl);
  flush(c->fd, c->w);
  if ((n = rx(c->fd, 2000)) <= 0) {
    return -1;
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

static int probe(const char *bind_ip, const char *srv_ip, int port, int lport, SSL_CTX *ctx, const char *label) {
  cl p;
  if (open_client(&p, bind_ip, srv_ip, port, lport, ctx) < 0) {
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
  printf("%-44s bind=%s sport=%d flight=%d %s\n", label, bind_ip, lport, k, hs == 1 ? "COMPLETED" : "NOT completed");
  fflush(stdout);
  if (hs == 1) {
    SSL_shutdown(p.ssl);
    flush(p.fd, p.w);
  }
  close(p.fd);
  return hs == 1;
}

static int hold(cl *h, const char *bind_ip, const char *srv_ip, int port, int lport, SSL_CTX *ctx) {
  if (open_client(h, bind_ip, srv_ip, port, lport, ctx) < 0) {
    return -1;
  }
  return cookie_exchange(h, 0) > 0;
}

int main(int argc, char **argv) {
  if (argc < 6) {
    return 2;
  }
  const char *srv = argv[1];
  int port = atoi(argv[2]);
  const char *attacker = argv[3];
  const char *victim = argv[4];
  int per_src = atoi(argv[5]);
  SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  cl *holds = calloc((size_t)per_src + 1u, sizeof(cl));
  if (!holds) {
    return 2;
  }

  int baseline = probe(victim, srv, port, 42000, ctx, "[1] victim baseline");
  if (baseline < 0) {
    return 2;
  }

  int held = 0;
  for (int i = 0; i < per_src; i++) {
    int r = hold(&holds[i], attacker, srv, port, 41000 + i, ctx);
    if (r < 0) {
      return 2;
    }
    held += r;
  }
  printf("[2] attacker held %d of %d per-source stalls\n", held, per_src);
  fflush(stdout);
  if (held != per_src) {
    printf("RESULT: FAIL harness could not fill per-source share\n");
    return 1;
  }

  cl extra;
  int extra_ok = hold(&extra, attacker, srv, port, 41000 + per_src, ctx);
  printf("[3] attacker stall beyond per-source share: %s\n", extra_ok == 1 ? "ACCEPTED (bad)" : "rejected");
  fflush(stdout);
  if (extra_ok == 1) {
    printf("RESULT: FAIL per-source share did not reject excess stalls\n");
    return 1;
  }

  int victim2 = probe(victim, srv, port, 42001, ctx, "[4] victim while attacker holds share");
  if (baseline != 1 || victim2 != 1) {
    printf("RESULT: FAIL victim locked out (baseline=%d second=%d)\n", baseline, victim2);
    return 1;
  }
  printf("RESULT: PASS other client completed while one host held its half-open share\n");
  return 0;
}
