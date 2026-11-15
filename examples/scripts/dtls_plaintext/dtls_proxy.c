/* DTLS client proxy for the plaintext-reject harness.
 * usage: dtls_proxy <server-ip> <server-port> <local-bind-port>
 * 127.0.0.1:7001 -> SSL_write on the DTLS association
 * 127.0.0.1:7002 -> raw send() on the same 5-tuple
 * Decrypted server records are forwarded to the last 7001 sender. */
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int udp_bind(const char *ip, int port) {
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  int one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a = {0};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  inet_pton(AF_INET, ip, &a.sin_addr);
  if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) {
    perror("bind");
    exit(2);
  }
  return s;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    return 2;
  }
  int fd = udp_bind("0.0.0.0", atoi(argv[3]));
  struct sockaddr_in srv = {0};
  srv.sin_family = AF_INET;
  srv.sin_port = htons(atoi(argv[2]));
  inet_pton(AF_INET, argv[1], &srv.sin_addr);
  if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
    perror("connect");
    return 2;
  }

  SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL *ssl = SSL_new(ctx);
  BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
  BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &srv);
  struct timeval tv = {2, 0};
  BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv);
  SSL_set_bio(ssl, bio, bio);
  if (SSL_connect(ssl) != 1) {
    fprintf(stderr, "PROXY: DTLS handshake failed\n");
    ERR_print_errors_fp(stderr);
    return 2;
  }
  fprintf(stderr, "PROXY: DTLS handshake done, %s %s\n", SSL_get_version(ssl), SSL_get_cipher(ssl));

  int enc = udp_bind("127.0.0.1", 7001), raw = udp_bind("127.0.0.1", 7002);
  struct sockaddr_in last = {0};
  socklen_t lastlen = 0;
  unsigned char buf[65536];
  struct pollfd p[3] = {{fd, POLLIN, 0}, {enc, POLLIN, 0}, {raw, POLLIN, 0}};
  for (;;) {
    if (poll(p, 3, -1) < 0) {
      continue;
    }
    if (p[1].revents & POLLIN) {
      lastlen = sizeof(last);
      int n = recvfrom(enc, buf, sizeof(buf), 0, (struct sockaddr *)&last, &lastlen);
      if (n > 0) {
        int w = SSL_write(ssl, buf, n);
        fprintf(stderr, "PROXY: enc %d bytes -> SSL_write %d\n", n, w);
      }
    }
    if (p[2].revents & POLLIN) {
      int n = recv(raw, buf, sizeof(buf), 0);
      if (n > 0) {
        int w = send(fd, buf, n, 0);
        fprintf(stderr, "PROXY: RAW %d bytes sent unencrypted on the DTLS 5-tuple (%d)\n", n, w);
      }
    }
    if (p[0].revents & POLLIN) {
      int n = SSL_read(ssl, buf, sizeof(buf));
      if (n > 0) {
        fprintf(stderr, "PROXY: SSL_read %d bytes from server (decrypted)\n", n);
        if (lastlen) {
          sendto(enc, buf, n, 0, (struct sockaddr *)&last, lastlen);
        }
      } else {
        int e = SSL_get_error(ssl, n);
        if (e != SSL_ERROR_WANT_READ) {
          fprintf(stderr, "PROXY: SSL_read error %d\n", e);
          ERR_print_errors_fp(stderr);
        }
      }
    }
  }
}
