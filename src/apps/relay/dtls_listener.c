/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* recvmmsg() and struct mmsghdr require _GNU_SOURCE on Linux */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "apputils.h"
#include "mainrelay.h"
#include <errno.h>

#include "dtls_listener.h"
#include "ns_ioalib_impl.h"
#include "ns_turn_ratelimit.h"
#include "ns_turn_utils.h"

#include "ns_turn_openssl.h"
#include "prom_server.h"

#include <pthread.h>
#include <stdint.h>

///////////////////////////////////////////////////
#if defined(WINDOWS)
// TODO: test it!
/* Type to represent a port.  */
typedef uint16_t in_port_t;
#endif

#define FUNCSTART                                                                                                      \
  if (server && eve(server->verbose))                                                                                  \
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s:%d:start\n", __FUNCTION__, __LINE__)
#define FUNCEND                                                                                                        \
  if (server && eve(server->verbose))                                                                                  \
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s:%d:end\n", __FUNCTION__, __LINE__)

#define COOKIE_SECRET_LENGTH (32)

#define MAX_SINGLE_UDP_BATCH IOA_UDP_RECVMMSG_MAX_BATCH
#define MAX_RECVMMSG_BATCH MAX_SINGLE_UDP_BATCH

#if defined(__linux__) && defined(CMSG_SPACE)
#if defined(IP_RECVTTL) || defined(IP_TTL)
#define RECVMMSG_IPV4_TTL_CMSG_SZ CMSG_SPACE(sizeof(int))
#else
#define RECVMMSG_IPV4_TTL_CMSG_SZ 0
#endif
#if defined(IP_RECVTOS) || defined(IP_TOS)
#define RECVMMSG_IPV4_TOS_CMSG_SZ CMSG_SPACE(sizeof(int))
#else
#define RECVMMSG_IPV4_TOS_CMSG_SZ 0
#endif
#if defined(IPV6_RECVHOPLIMIT) || defined(IPV6_HOPLIMIT)
#define RECVMMSG_IPV6_TTL_CMSG_SZ CMSG_SPACE(sizeof(int))
#else
#define RECVMMSG_IPV6_TTL_CMSG_SZ 0
#endif
#if defined(IPV6_RECVTCLASS) || defined(IPV6_TCLASS)
#define RECVMMSG_IPV6_TOS_CMSG_SZ CMSG_SPACE(sizeof(int))
#else
#define RECVMMSG_IPV6_TOS_CMSG_SZ 0
#endif
#define RECVMMSG_IPV4_CMSG_SZ (RECVMMSG_IPV4_TTL_CMSG_SZ + RECVMMSG_IPV4_TOS_CMSG_SZ)
#define RECVMMSG_IPV6_CMSG_SZ (RECVMMSG_IPV6_TTL_CMSG_SZ + RECVMMSG_IPV6_TOS_CMSG_SZ)
#define RECVMMSG_CMSG_SZ                                                                                               \
  ((RECVMMSG_IPV4_CMSG_SZ > RECVMMSG_IPV6_CMSG_SZ) ? RECVMMSG_IPV4_CMSG_SZ : RECVMMSG_IPV6_CMSG_SZ)
#define RECVMMSG_CMSG_ALLOC_SZ ((RECVMMSG_CMSG_SZ) > 0 ? (RECVMMSG_CMSG_SZ) : 1)
#endif

#if !defined(WINDOWS)
_Thread_local uint32_t packetcounter = 0;
#else
static uint32_t packetcounter = 0;
#endif

typedef enum {
  UDP_PACKET_CLASS_INVALID = 0,
  UDP_PACKET_CLASS_STUN_OR_CHANNEL,
  UDP_PACKET_CLASS_DTLS_HANDSHAKE,
  UDP_PACKET_CLASS_DTLS_OTHER,
  UDP_PACKET_CLASS_OLD_STUN
} udp_packet_classification_t;

struct dtls_listener_relay_server_info {
  char ifname[1025];
  ioa_addr addr;
  ioa_engine_handle e;
  turn_turnserver *ts;
  int verbose;
  struct event *udp_listen_ev;
  ioa_socket_handle udp_listen_s;
  ur_addr_map *children_ss; /* map of socket children on remote addr */
  struct message_to_relay sm;
  size_t slen0;
  ioa_engine_new_connection_event_handler connect_cb;
#if defined(__linux__)
  struct dtls_listener_recvmmsg_state *recvmmsg_state;
#endif
};

#if defined(__linux__)
struct dtls_listener_recvmmsg_state {
  struct mmsghdr msgs[MAX_RECVMMSG_BATCH];
  struct iovec iovecs[MAX_RECVMMSG_BATCH];
  char cmsgs[MAX_RECVMMSG_BATCH][RECVMMSG_CMSG_ALLOC_SZ];
  ioa_addr src_addrs[MAX_RECVMMSG_BATCH];
  int ttls[MAX_RECVMMSG_BATCH];
  int toss[MAX_RECVMMSG_BATCH];
  udp_packet_classification_t packet_types[MAX_RECVMMSG_BATCH];
  ioa_network_buffer_handle elems[MAX_RECVMMSG_BATCH];
};
#endif

///////////// forward declarations ////////

static int create_server_socket(dtls_listener_relay_server_type *server, int report_creation, int sock_buf_size);
static int clean_server(dtls_listener_relay_server_type *server);
static int reopen_server_socket(dtls_listener_relay_server_type *server, evutil_socket_t fd);
static int create_new_connected_udp_socket(dtls_listener_relay_server_type *server, ioa_socket_handle s);

///////////// dtls message types //////////

int is_dtls_handshake_message(const unsigned char *buf, int len);
int is_dtls_data_message(const unsigned char *buf, int len);
int is_dtls_alert_message(const unsigned char *buf, int len);
int is_dtls_cipher_change_message(const unsigned char *buf, int len);
int get_dtls_version(const unsigned char *buf, int len);

int is_dtls_message(const unsigned char *buf, int len);

int is_dtls_handshake_message(const unsigned char *buf, int len) {
  return (buf && len > 3 && buf[0] == 0x16 && buf[1] == 0xfe && ((buf[2] == 0xff) || (buf[2] == 0xfd)));
}

int is_dtls_data_message(const unsigned char *buf, int len) {
  return (buf && len > 3 && buf[0] == 0x17 && buf[1] == 0xfe && ((buf[2] == 0xff) || (buf[2] == 0xfd)));
}

int is_dtls_alert_message(const unsigned char *buf, int len) {
  return (buf && len > 3 && buf[0] == 0x15 && buf[1] == 0xfe && ((buf[2] == 0xff) || (buf[2] == 0xfd)));
}

int is_dtls_cipher_change_message(const unsigned char *buf, int len) {
  return (buf && len > 3 && buf[0] == 0x14 && buf[1] == 0xfe && ((buf[2] == 0xff) || (buf[2] == 0xfd)));
}

int is_dtls_message(const unsigned char *buf, int len) {
  if (buf && (len > 3) && (buf[1]) == 0xfe && ((buf[2] == 0xff) || (buf[2] == 0xfd))) {
    switch (buf[0]) {
    case 0x14:
    case 0x15:
    case 0x16:
    case 0x17:
      return 1;
    default:;
    }
  }
  return 0;
}

/* 0 - 1.0, 1 - 1.2 */
int get_dtls_version(const unsigned char *buf, int len) {
  if (buf && (len > 3) && (buf[2] == 0xfd)) {
    return 1;
  }
  return 0;
}

static size_t print_packet_txt2pcap(uint64_t now, uint8_t *payload, size_t payload_length, uint8_t *txt2pcap,
                                    size_t txt2pcap_length) {
  div_t dv = div(now, 24 * 60 * 60 * 1000);
  dv = div(dv.rem, 60 * 60 * 1000);
  uint32_t hours = dv.quot;
  dv = div(dv.rem, 60 * 1000);
  uint32_t minutes = dv.quot;
  dv = div(dv.rem, 1000);
  uint32_t seconds = dv.quot;
  uint32_t ms = dv.rem;

  size_t index = 0;
  index =
      snprintf((char *)(txt2pcap + index), txt2pcap_length - index, "%02d:%02d:%02d.%03d", hours, minutes, seconds, ms);
  index += snprintf((char *)(txt2pcap + index), txt2pcap_length - index, " 0000");

  for (size_t i = 0; i < payload_length; i++) {
    int n = snprintf((char *)(txt2pcap + index), txt2pcap_length - index, " %02x", payload[i]);
    if (n < 0 || (size_t)n >= txt2pcap_length - index) {
      break;
    }
    index += (size_t)n;
  }
  index += snprintf((char *)(txt2pcap + index), txt2pcap_length - index, " # STUN_PACKET ");
  return index;
}

///////////// utils /////////////////////

#if DTLS_SUPPORTED

/*
 * Upper bound on the handshake buffer OpenSSL grows for a DTLS peer.
 *
 * OpenSSL sizes the per-connection handshake buffer from the length declared in
 * the message header, capped by
 * max(DTLS1_HM_HEADER_LENGTH + SSL3_RT_MAX_ENCRYPTED_LENGTH, max_cert_list)
 * (dtls1_max_handshake_message_len() in ssl/statem/statem_dtls.c). A peer that
 * declares a large length and then sends a single fragment byte still forces
 * the whole allocation, so max_cert_list is what an unvalidated source can make
 * the server allocate per pending handshake.
 *
 * A source that has not answered the DTLS cookie challenge (RFC 6347, section
 * 4.2.1) is not validated at all, so keep this at the OpenSSL floor - lower
 * values have no further effect. The server does not ask for a client
 * certificate, so no client handshake message other than the ClientHello comes
 * close to the floor. Adding client-certificate support means raising this, and
 * giving up the bound on unvalidated sources unless it is raised only after the
 * cookie has been answered.
 */
#define TURN_DTLS_MAX_CERT_LIST (SSL3_RT_MAX_ENCRYPTED_LENGTH)

/*
 * Cap on concurrent half-open (handshake-incomplete) DTLS sockets, summed
 * across all relay threads. A DTLS ClientHello from a new source makes the
 * listener allocate a per-peer SSL + ioa_socket + ts_ur_super_session before
 * the source has answered the RFC 6347 cookie challenge, so a source-spoofing
 * flood of unanswered ClientHellos would otherwise accumulate unbounded state.
 * Once the cap is reached, new handshakes are dropped until in-progress ones
 * finish (freeing their slot) or are reaped by the allocate timeout.
 * Legitimate clients finish the handshake in a few
 * round trips and release their slot immediately, so this only bites under a
 * flood.
 *
 * The cap scales with server size: it is this many slots per relay thread, so a
 * bigger deployment (more relay threads) tolerates proportionally more
 * concurrent handshakes and a small box is not over-committed. The live count
 * is a single global counter rather than a hard per-thread partition, so a busy
 * relay thread can use headroom left idle by others while the process-wide
 * ceiling (this * relay-thread count) still bounds total memory. A fixed
 * per-thread bound for now; a --dtls-max-half-open option could expose it.
 */
#define TURN_DTLS_HALF_OPEN_PER_THREAD 16

/* Process-wide cap = per-thread budget * number of relay threads (>= 1). */
static uint32_t dtls_half_open_cap(void) {
  uint32_t threads = (uint32_t)turn_params.general_relay_servers_number;
  if (threads < 1) {
    threads = 1;
  }
  return TURN_DTLS_HALF_OPEN_PER_THREAD * threads;
}

static unsigned char dtls_cookie_secret[COOKIE_SECRET_LENGTH];
static pthread_once_t dtls_cookie_secret_once = PTHREAD_ONCE_INIT;

static void init_dtls_cookie_secret(void) {
  if (RAND_bytes(dtls_cookie_secret, sizeof(dtls_cookie_secret)) == 1) {
    return;
  }

  for (size_t i = 0; i < sizeof(dtls_cookie_secret); ++i) {
    dtls_cookie_secret[i] = (unsigned char)turn_random_number();
  }
}

static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
  unsigned char buffer[sizeof(struct in6_addr) + sizeof(in_port_t)];
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int length = 0;
  unsigned int resultlength;
  ioa_addr peer;

  pthread_once(&dtls_cookie_secret_once, init_dtls_cookie_secret);

  /* Read peer information */
  (void)BIO_dgram_get_peer(SSL_get_wbio(ssl), &peer);

  // TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: family=%u(1)\n",__FUNCTION__,(unsigned)peer.ss.sa_family);

  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.sa_family) {
  case AF_INET:
    length += sizeof(struct in_addr);
    break;
  case AF_INET6:
    length += sizeof(struct in6_addr);
    break;
  default:
    OPENSSL_assert(0);
    break;
  }
  length += sizeof(in_port_t);

  // TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: family=%u(2)\n",__FUNCTION__,(unsigned)peer.ss.sa_family);

  switch (peer.ss.sa_family) {
  case AF_INET:
    memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, sizeof(struct in_addr));
    break;
  case AF_INET6:
    memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr, sizeof(struct in6_addr));
    break;
  default:
    OPENSSL_assert(0);
    break;
  }

  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (const void *)dtls_cookie_secret, sizeof(dtls_cookie_secret), (const unsigned char *)buffer, length,
       result, &resultlength);

  memcpy(cookie, result, resultlength);
  *cookie_len = resultlength;

  return 1;
}

static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
  unsigned int resultlength = 0;
  unsigned char result[COOKIE_SECRET_LENGTH];

  generate_cookie(ssl, result, &resultlength);

  if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0) {
    // TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: cookies are OK, length=%u\n",__FUNCTION__,cookie_len);
    return 1;
  } else {
    // TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: cookies are OK, length=%u\n",__FUNCTION__,cookie_len);
    return 0;
  }
}

/////////////// io handlers ///////////////////

static ioa_socket_handle dtls_server_input_handler(dtls_listener_relay_server_type *server, ioa_socket_handle s,
                                                   ioa_network_buffer_handle nbh) {
  FUNCSTART;

  if (!server || !nbh) {
    return NULL;
  }

  /* RFC 8656 / RFC 6347 section 4.2.1 stateless cookie exchange, via
   * DTLSv1_listen(). A ClientHello without a valid cookie only elicits a
   * HelloVerifyRequest and leaves no per-source state: the SSL is built over a
   * memory BIO holding just this datagram and is freed immediately unless the
   * cookie verifies. Only a cookie-verified ClientHello - proof the source can
   * receive at its claimed address - is promoted to a real socket + session.
   * This is what the half-open cap could bound but not prevent:
   * a spoofed-source flood now creates zero state. */

  SSL *ssl = SSL_new(server->e->dtls_ctx);
  SSL_set_accept_state(ssl);
  SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE
#if defined(SSL_OP_NO_RENEGOTIATION)
                           | SSL_OP_NO_RENEGOTIATION
#endif
  );
  SSL_set_max_cert_list(ssl, TURN_DTLS_MAX_CERT_LIST);
  /* Release idle record buffers so a parked half-open handshake does not pin them. */
  SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);

  /* wbio: datagram BIO on the shared listener fd, addressed to this peer, so the
   * HelloVerifyRequest and the later handshake flights reach the right source
   * and the cookie callbacks can read the peer from it. rbio: the ClientHello we
   * already read off the fd, wrapped in a memory BIO (EOF -> WANT_READ). */
  BIO *wbio = BIO_new_dgram(s->fd, BIO_NOCLOSE);
  (void)BIO_dgram_set_peer(wbio, (struct sockaddr *)&(server->sm.m.sm.nd.src_addr));
  BIO *rbio = BIO_new_mem_buf(ioa_network_buffer_data(nbh), (int)ioa_network_buffer_get_size(nbh));
  BIO_set_mem_eof_return(rbio, -1);
  SSL_set_bio(ssl, rbio, wbio); /* SSL owns both BIOs from here. */

  BIO_ADDR *bpeer = BIO_ADDR_new();
  const int lret = DTLSv1_listen(ssl, bpeer);
  BIO_ADDR_free(bpeer);

  if (lret <= 0) {
    /* 0: no valid cookie yet (HelloVerifyRequest sent). <0: listen error.
     * Nothing was retained - drop the datagram with no per-source state. */
    SSL_free(ssl);
    return NULL;
  }

  /* Cookie verified: charge the now-return-routable peer against the half-open
   * cap. A completing or closing handshake releases the slot, so the cap still
   * guards against a flood of validated peers that stall mid-handshake. */
  if (!turn_dtls_half_open_try_inc(dtls_half_open_cap())) {
    SSL_free(ssl);
    return NULL;
  }

  ioa_socket_handle ioas = create_ioa_socket_from_ssl(server->e, s, ssl, DTLS_SOCKET, CLIENT_SOCKET,
                                                      &(server->sm.m.sm.nd.src_addr), &(server->addr));
  if (!ioas) {
    turn_dtls_half_open_dec();
    SSL_free(ssl);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create ioa_socket from SSL\n");
    return NULL;
  }

  ioas->dtls_half_open = true;
  set_ioa_socket_buf_size(ioas, server->ts->sock_buf_size);
  server->sm.m.sm.nd.recv_ttl = TTL_IGNORE;
  server->sm.m.sm.nd.recv_tos = TOS_IGNORE;
  server->sm.m.sm.s = ioas;

  addr_debug_print(server->verbose, &(server->sm.m.sm.nd.src_addr), "Accepted connection from");

  /* The cookie-bearing ClientHello is consumed; drive the handshake once so the
   * ServerHello flight goes out now instead of after the client's retransmit.
   * The rest of the handshake completes over the child socket's read path. */
  SSL_do_handshake(ssl);

  FUNCEND;
  return ioas;
}

#endif

/* Answer a plain STUN Binding request from an unknown UDP source straight from
 * the listener. handle_turn_binding() derives the whole response from the
 * request bytes and the socket's own addresses, so the child socket and the
 * session the relay would build for it are pure overhead - and they are held
 * for the to-be-allocated timeout, in the default configuration, for traffic
 * that authenticates nothing. Returns true when the packet was fully handled
 * here; false means "fall through to the regular per-session path". Every
 * branch below is matched against handle_turn_command's behavior for a
 * brand-new session so that the bytes on the wire are identical. */
static bool udp_stateless_binding_fast_path(dtls_listener_relay_server_type *server, ioa_socket_handle listen_s,
                                            ioa_net_data *nd) {
  turn_turnserver *ts = server->ts;

  if (!ts || turn_params.no_udp || !server->udp_listen_s || !listen_s) {
    return false;
  }

  const uint8_t *data = ioa_network_buffer_data(nd->nbh);
  const size_t len = ioa_network_buffer_get_size(nd->nbh);

  bool enforce_fingerprints = false;
  if (!stun_is_command_message_full_check_str(data, len, false, &enforce_fingerprints) ||
      !stun_is_request_str(data, len) || (stun_get_method_str(data, len) != STUN_METHOD_BINDING)) {
    return false;
  }

  /* --secure-stun makes BINDING an authenticated method, which is
   * check_stun_auth's business, not the listener's. */
  if (*(ts->secure_stun)) {
    return false;
  }

  if (*(ts->no_stun)) {
    /* handle_turn_command ignores the request without a reply. Do the same,
     * minus the session it would have left behind. */
    return true;
  }

  /* --log-binding is a debugging aid whose per-session lines only the relay can
   * produce, so leave the old path in place while it is on. */
  if (server->e->verbose && ts->log_binding && *(ts->log_binding)) {
    return false;
  }

  /* The attribute walk mirrors handle_turn_binding's, including which
   * attributes are silently accepted and which count as unknown. */
  uint16_t unknown_attrs[MAX_NUMBER_OF_UNKNOWN_ATTRS] = {0};
  uint16_t ua_num = 0;

  stun_attr_ref sar = stun_attr_get_first_str(data, len);
  while (sar && (ua_num < MAX_NUMBER_OF_UNKNOWN_ATTRS)) {
    const int attr_type = stun_attr_get_type(sar);
    switch (attr_type) {
    case STUN_ATTRIBUTE_CHANGE_REQUEST:
    case STUN_ATTRIBUTE_PADDING:
    case STUN_ATTRIBUTE_RESPONSE_PORT:
      /* RFC 5780 probes are answered from an alternate address or port, which
       * only the relay's alternate sockets can do. */
      return false;
    case OLD_STUN_ATTRIBUTE_RESPONSE_ADDRESS:
    case STUN_ATTRIBUTE_OAUTH_ACCESS_TOKEN:
    case STUN_ATTRIBUTE_PRIORITY:
    case STUN_ATTRIBUTE_FINGERPRINT:
    case STUN_ATTRIBUTE_MESSAGE_INTEGRITY:
    case STUN_ATTRIBUTE_USERNAME:
    case STUN_ATTRIBUTE_REALM:
    case STUN_ATTRIBUTE_NONCE:
    case STUN_ATTRIBUTE_ORIGIN:
      break;
    default:
      if (attr_type >= 0x0000 && attr_type <= 0x7FFF) {
        unknown_attrs[ua_num++] = nswap16(attr_type);
      }
    };
    sar = stun_attr_get_next_covered_str(data, len, sar);
  }

  stun_report_binding(NULL, STUN_PROMETHEUS_METRIC_TYPE_REQUEST);

  stun_tid tid;
  stun_tid_from_message_str(data, len, &tid);

  ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
  size_t rlen = ioa_network_buffer_get_size(nbh);

  if (ua_num > 0) {
    stun_init_error_response_str(STUN_METHOD_BINDING, ioa_network_buffer_data(nbh), &rlen, 420, NULL, &tid,
                                 ts->include_reason_string);
    stun_attr_add_str(ioa_network_buffer_data(nbh), &rlen, STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES,
                      (const uint8_t *)unknown_attrs, (ua_num * 2));
  } else {
    if (!stun_set_binding_response_str(ioa_network_buffer_data(nbh), &rlen, &tid, &(nd->src_addr), 0, NULL, 0, false,
                                       *(ts->stun_backward_compatibility), ts->include_reason_string)) {
      ioa_network_buffer_delete(server->e, nbh);
      return false;
    }
    /* An RFC 5780 server advertises its alternate address on every Binding
     * response, not only on the CHANGE-REQUEST probes. */
    if (ts->rfc5780 && ts->alt_addr_cb) {
      ioa_addr *response_origin = get_local_addr_from_ioa_socket(listen_s);
      ioa_addr other_address = {0};
      if (response_origin && (ts->alt_addr_cb(response_origin, &other_address) == 0)) {
        stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &rlen, STUN_ATTRIBUTE_RESPONSE_ORIGIN, response_origin);
        stun_attr_add_addr_str(ioa_network_buffer_data(nbh), &rlen, STUN_ATTRIBUTE_OTHER_ADDRESS, &other_address);
      }
    }
  }

  if (ts->software_attribute) {
    const char *software = get_version(ts);
    stun_attr_add_str(ioa_network_buffer_data(nbh), &rlen, STUN_ATTRIBUTE_SOFTWARE, (const uint8_t *)software,
                      strlen(software));
  }
  if (ts->fingerprint || enforce_fingerprints) {
    if (!stun_attr_add_fingerprint_str(ioa_network_buffer_data(nbh), &rlen)) {
      ioa_network_buffer_delete(server->e, nbh);
      return true;
    }
  }
  ioa_network_buffer_set_size(nbh, rlen);

  stun_report_binding(NULL, ua_num ? STUN_PROMETHEUS_METRIC_TYPE_ERROR : STUN_PROMETHEUS_METRIC_TYPE_RESPONSE);

  udp_send_message(server, nbh, &(nd->src_addr));
  ioa_network_buffer_delete(server->e, nbh);

  return true;
}

/* Copy a NUL-terminated attribute value out of a request. An over-long value
 * is truncated exactly as check_stun_auth() truncates it, so both paths judge
 * the same string. Returns false when the attribute is absent. */
static bool udp_get_string_attr(const uint8_t *data, size_t len, uint16_t attr_type, char *out, size_t out_size) {
  stun_attr_ref sar = stun_attr_get_first_by_type_str(data, len, attr_type);
  if (!sar) {
    return false;
  }
  const size_t alen = min((size_t)stun_attr_get_len(sar), out_size - 1);
  memcpy(out, stun_attr_get_value(sar), alen);
  out[alen] = 0;
  return true;
}

/* Charge one unauthenticated reply to this source's --unauthorized-ratelimit
 * budget - the same bucket the 401 challenge uses, since every reply to an
 * unverified source is a reflection surface whatever its error code. Returns
 * true when the caller must stay silent. */
static bool udp_unauthenticated_reply_ratelimited(dtls_listener_relay_server_type *server, const ioa_addr *src,
                                                  int err_code) {
  turn_turnserver *ts = server->ts;

  if (!ts->ratelimit_unauthorized_requests || !*(ts->ratelimit_unauthorized_requests)) {
    return false;
  }

  bool first_drop = false;
  bool first_collision = false;
  const bool over = ratelimit_consume_address(src, (uint32_t) * (ts->ratelimit_unauthorized_requests_per_sec),
                                              &first_drop, &first_collision);

  if (first_collision) {
    char raddr[INET6_ADDRSTRLEN + 1] = {0};
    addr_to_string_no_port(src, raddr);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                  "401 rate-limit bucket collision from %s, sharing active bucket budget for this window\n", raddr);
  }
  if (over && first_drop) {
    char raddr[INET6_ADDRSTRLEN + 1] = {0};
    addr_to_string_no_port(src, raddr);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                  "unauthorized-response rate-limit exceeded from %s (error %d), suppressing responses for this "
                  "window\n",
                  raddr, err_code);
  }

  return over;
}

/* Emit the reply handle_turn_command would build for a brand-new session: the
 * error response, the challenge attributes when `nonce` is given (as
 * create_challenge_response does), then SOFTWARE and FINGERPRINT. */
static void udp_send_stateless_error(dtls_listener_relay_server_type *server, ioa_net_data *nd, uint16_t method,
                                     stun_tid *tid, int err_code, const uint8_t *reason, const char *nonce,
                                     const char *realm, bool enforce_fingerprints) {
  turn_turnserver *ts = server->ts;

  ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(server->e);
  size_t rlen = ioa_network_buffer_get_size(nbh);
  stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &rlen, err_code, reason, tid,
                               ts->include_reason_string);
  if (nonce) {
    stun_attr_add_str(ioa_network_buffer_data(nbh), &rlen, STUN_ATTRIBUTE_NONCE, (const uint8_t *)nonce,
                      (int)strlen(nonce));
    stun_attr_add_str(ioa_network_buffer_data(nbh), &rlen, STUN_ATTRIBUTE_REALM, (const uint8_t *)realm,
                      (int)strlen(realm));
    if (ts->oauth) {
      const char *server_name = ts->oauth_server_name;
      if (!(server_name && server_name[0])) {
        server_name = realm;
      }
      stun_attr_add_str(ioa_network_buffer_data(nbh), &rlen, STUN_ATTRIBUTE_THIRD_PARTY_AUTHORIZATION,
                        (const uint8_t *)server_name, strlen(server_name));
    }
  }
  if (ts->software_attribute) {
    const char *software = get_version(ts);
    stun_attr_add_str(ioa_network_buffer_data(nbh), &rlen, STUN_ATTRIBUTE_SOFTWARE, (const uint8_t *)software,
                      strlen(software));
  }
  if (ts->fingerprint || enforce_fingerprints) {
    if (!stun_attr_add_fingerprint_str(ioa_network_buffer_data(nbh), &rlen)) {
      ioa_network_buffer_delete(server->e, nbh);
      return;
    }
  }
  ioa_network_buffer_set_size(nbh, rlen);

  udp_send_message(server, nbh, &(nd->src_addr));
  ioa_network_buffer_delete(server->e, nbh);
}

/* Stateless-nonce fast path (issue #1999): answer a request from an unknown
 * UDP source with the derived-nonce 401 challenge directly from the listener,
 * without creating a child socket or session. A request that does carry
 * MESSAGE-INTEGRITY is admitted to the session path only once its NONCE is
 * shown to be one this server issued to that very source address.
 * Packets the relay would silently ignore for a fresh source (indications,
 * unbound channel data, malformed-but-classifiable STUN) are swallowed with
 * no state either. Returns true when the packet was fully handled here;
 * false means "fall through to the regular per-session path". Every branch
 * below is matched against handle_turn_command's behavior for a brand-new
 * session so that the bytes on the wire are identical. */
static bool udp_stateless_nonce_fast_path(dtls_listener_relay_server_type *server, ioa_net_data *nd) {
  turn_turnserver *ts = server->ts;

  if (!turn_server_stateless_nonce_enabled(ts) || turn_params.no_udp || !server->udp_listen_s) {
    return false;
  }

  /* Only long-term-credential setups issue 401 challenges. */
  if (ts->ct != TURN_CREDENTIALS_LONG_TERM) {
    return false;
  }

  const uint8_t *data = ioa_network_buffer_data(nd->nbh);
  const size_t len = ioa_network_buffer_get_size(nd->nbh);

  {
    /* Channel data from a source with no allocation: the relay would create a
     * session and drop the message (no channel is bound). */
    size_t blen = len;
    uint16_t chnum = 0;
    if (stun_is_channel_message_str(data, &blen, &chnum, false)) {
      return true;
    }
  }

  bool enforce_fingerprints = false;
  if (!stun_is_command_message_full_check_str(data, len, false, &enforce_fingerprints)) {
    /* Classified as STUN but fails the full check (e.g. bad FINGERPRINT):
     * the relay would create a session and ignore the message. */
    return true;
  }

  if (stun_is_indication_str(data, len)) {
    /* Indications never get a response, and without an allocation the relay
     * drops them. */
    return true;
  }

  if (!stun_is_request_str(data, len)) {
    /* Success/error "responses" from a client: handle_turn_command treats
     * them as wrong messages and stays silent. */
    return true;
  }

  /* MESSAGE-INTEGRITY is acted upon further down, after the method-specific
   * branches. check_stun_auth() answers any other length with the same 401
   * challenge as a missing attribute, so treat it as missing here. */
  stun_attr_ref mi_attr = stun_attr_get_first_by_type_str(data, len, STUN_ATTRIBUTE_MESSAGE_INTEGRITY);
  if (mi_attr && (stun_attr_get_len(mi_attr) != SHA1SIZEBYTES)) {
    mi_attr = NULL;
  }

  const uint16_t method = stun_get_method_str(data, len);

  /* BINDING keeps its session-based path: it is answerable without auth
   * (unless --secure-stun) and may involve RFC 5780 alternate sockets. */
  if (method == STUN_METHOD_BINDING) {
    return false;
  }

  if (*(ts->stun_only)) {
    /* Non-BINDING methods are silently ignored in STUN-only mode. */
    return true;
  }

  if (method == STUN_METHOD_ALLOCATE) {
    /* An ALLOCATE may be redirected (300) before authentication; keep the
     * session path when any UDP-relevant alternate-server list is set. */
    if ((ts->alternate_servers_list && ts->alternate_servers_list->size) ||
        (ts->udp_alternate_servers_list && ts->udp_alternate_servers_list->size) ||
        (ts->self_udp_balance && ts->aux_servers_list && ts->aux_servers_list->size)) {
      return false;
    }
  } else if (method == STUN_METHOD_REFRESH) {
    /* With --mobility a REFRESH can resume a session using MOBILITY-TICKET
     * instead of a first-pass challenge. */
    if (*(ts->mobility)) {
      return false;
    }
  } else if (method == STUN_METHOD_CONNECTION_BIND) {
    /* CONNECTION-BIND is exempt from the auth challenge. */
    return false;
  }

  /* Every remaining request method reaches check_stun_auth() before any
   * method-specific processing. Its replies - the 401 challenge below, and the
   * pre-credential rejections in the MESSAGE-INTEGRITY block - are rebuilt here
   * attribute for attribute: error response, NONCE, REALM,
   * [THIRD-PARTY-AUTHORIZATION], [SOFTWARE], [FINGERPRINT]. */

  realm_options_t realm_options;
  get_default_realm_options(&realm_options);

  if (method == STUN_METHOD_ALLOCATE) {
    /* Realm selection by ORIGIN, as in handle_turn_command for a session
     * whose origin is not pinned yet. */
    stun_attr_ref sar = stun_attr_get_first_str(data, len);
    bool origin_found = false;
    while (sar && !origin_found) {
      if (stun_attr_get_type(sar) == STUN_ATTRIBUTE_ORIGIN) {
        const int sarlen = stun_attr_get_len(sar);
        if (sarlen > 0) {
          char *o = (char *)turn_malloc(sarlen + 1);
          memcpy(o, stun_attr_get_value(sar), sarlen);
          o[sarlen] = 0;
          char corigin[STUN_MAX_ORIGIN_SIZE + 1] = {0};
          if (get_canonic_origin(o, corigin, STUN_MAX_ORIGIN_SIZE) < 0) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Wrong origin format: %s\n", __FUNCTION__, o);
          }
          free(o);
          origin_found = get_realm_options_by_origin(corigin, &realm_options);
        }
      }
      sar = stun_attr_get_next_covered_str(data, len, sar);
    }
  }

  stun_tid tid;
  stun_tid_from_message_str(data, len, &tid);

  if (mi_attr) {
    /* A nonce this server issued to this source address is what proves the
     * source return-routable, and it is a strict prerequisite for any
     * successful authentication - so a flood carrying a forged
     * MESSAGE-INTEGRITY gets no session here either. Every rejection ahead of
     * the credential lookup is decided by the request bytes alone; the checks
     * below follow check_stun_auth()'s order exactly. */
    char realm[STUN_MAX_REALM_SIZE + 1] = {0};
    char usname[STUN_MAX_USERNAME_SIZE + 1] = {0};
    char client_nonce[STUN_MAX_NONCE_SIZE + 1] = {0};

    int err_code = 400;
    const uint8_t *reason = NULL;
    bool challenge = false;

    if (!udp_get_string_attr(data, len, STUN_ATTRIBUTE_REALM, realm, sizeof(realm)) ||
        !is_secure_string((const uint8_t *)realm, 0)) {
      ;
    } else if (strcmp(realm, realm_options.name)) {
      if (method == STUN_METHOD_ALLOCATE) {
        err_code = 437;
        reason = (const uint8_t *)"Allocation mismatch: wrong credentials: the realm value is incorrect";
      } else {
        err_code = 441;
        reason = (const uint8_t *)"Wrong credentials: the realm value is incorrect";
      }
    } else if (!udp_get_string_attr(data, len, STUN_ATTRIBUTE_USERNAME, usname, sizeof(usname)) ||
               !is_secure_string((const uint8_t *)usname, 1)) {
      ;
    } else if (!udp_get_string_attr(data, len, STUN_ATTRIBUTE_NONCE, client_nonce, sizeof(client_nonce))) {
      ;
    } else if (turn_check_stateless_nonce(ts->stateless_nonce_key, ts->stateless_nonce_key_size, &(nd->src_addr),
                                          (uint32_t)turn_time(), turn_server_stateless_nonce_lifetime(ts), client_nonce,
                                          NULL)) {
      /* The source is proven return-routable and the credentials now have to be
       * looked up, possibly asynchronously - that needs a session. */
      return false;
    } else {
      err_code = 438;
      reason = (const uint8_t *)"Wrong nonce";
      challenge = true;
    }

    /* These replies go to an unverified source, so they share the 401's
     * per-source budget: a real client needs one 438 to re-authenticate after
     * its nonce expires, a spoofed flood gets one per window. */
    if (udp_unauthenticated_reply_ratelimited(server, &(nd->src_addr), err_code)) {
      return true;
    }

    char fresh_nonce[TURN_STATELESS_NONCE_SIZE] = {0};
    if (challenge &&
        !turn_generate_stateless_nonce(ts->stateless_nonce_key, ts->stateless_nonce_key_size, &(nd->src_addr),
                                       (uint32_t)turn_time(), fresh_nonce, sizeof(fresh_nonce))) {
      return false;
    }

    udp_send_stateless_error(server, nd, method, &tid, err_code, reason, challenge ? fresh_nonce : NULL,
                             realm_options.name, enforce_fingerprints);
    return true;
  }

  char nonce[TURN_STATELESS_NONCE_SIZE] = {0};
  if (!turn_generate_stateless_nonce(ts->stateless_nonce_key, ts->stateless_nonce_key_size, &(nd->src_addr),
                                     (uint32_t)turn_time(), nonce, sizeof(nonce))) {
    return false;
  }

  if (ts->unauthenticated_401_request_cb) {
    ts->unauthenticated_401_request_cb();
  }

  bool first_drop = false;
  bool first_collision = false;
  if (ts->ratelimit_unauthorized_requests && *(ts->ratelimit_unauthorized_requests) &&
      ratelimit_consume_address(&(nd->src_addr), (uint32_t) * (ts->ratelimit_unauthorized_requests_per_sec),
                                &first_drop, &first_collision)) {
    if (ts->unauthenticated_401_dropped_response_cb) {
      ts->unauthenticated_401_dropped_response_cb();
    }
    if (first_drop) {
      char raddr[INET6_ADDRSTRLEN + 1] = {0};
      addr_to_string_no_port(&(nd->src_addr), raddr);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "401 rate-limit exceeded from %s, suppressing responses for this window\n",
                    raddr);
    }
    return true;
  }
  if (first_collision) {
    char raddr[INET6_ADDRSTRLEN + 1] = {0};
    addr_to_string_no_port(&(nd->src_addr), raddr);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                  "401 rate-limit bucket collision from %s, sharing active bucket budget for this window\n", raddr);
  }

  if (ts->unauthenticated_401_response_cb) {
    ts->unauthenticated_401_response_cb();
  }

  /* One-time operational marker (also asserted by
   * examples/run_tests_stateless_nonce.sh). Benign race: worst case the
   * line is logged once per listener thread. */
  static volatile bool fast_path_logged = false;
  if (!fast_path_logged) {
    fast_path_logged = true;
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "stateless-nonce: listener fast-path challenge active\n");
  }

  udp_send_stateless_error(server, nd, method, &tid, 401, NULL, nonce, realm_options.name, enforce_fingerprints);

  return true;
}

static int handle_udp_packet(dtls_listener_relay_server_type *server, struct message_to_relay *sm,
                             ioa_engine_handle ioa_eng, turn_turnserver *ts, udp_packet_classification_t packet_type) {
  const int verbose = ioa_eng->verbose;
  ioa_socket_handle s = sm->m.sm.s;

  ur_addr_map_value_type mvt = 0;
  if (!(server->children_ss)) {
    server->children_ss = (ur_addr_map *)allocate_super_memory_engine(server->e, sizeof(ur_addr_map));
    ur_addr_map_init(server->children_ss);
  }
  ur_addr_map *amap = server->children_ss;

  ioa_socket_handle chs = NULL;
  if ((ur_addr_map_get(amap, &(sm->m.sm.nd.src_addr), &mvt) > 0) && mvt) {
    chs = (ioa_socket_handle)mvt;
  }

  if (chs && !ioa_socket_tobeclosed(chs) && (chs->sockets_container == amap) && (chs->magic == SOCKET_MAGIC)) {
    s = chs;
    sm->m.sm.s = s;
    if (s->ssl) {
      const int sslret = ssl_read(s->fd, s->ssl, sm->m.sm.nd.nbh, verbose);
      if (sslret < 0) {
        ioa_network_buffer_delete(ioa_eng, sm->m.sm.nd.nbh);
        sm->m.sm.nd.nbh = NULL;
        ts_ur_super_session *ss = (ts_ur_super_session *)s->session;
        if (ss) {
          turn_turnserver *server = (turn_turnserver *)ss->server;
          if (server) {
            shutdown_client_connection(server, ss, 0, "SSL read error");
          }
        } else {
          close_ioa_socket(s);
        }
        ur_addr_map_del(amap, &(sm->m.sm.nd.src_addr), NULL);
        sm->m.sm.s = NULL;
        s = NULL;
        chs = NULL;
      } else if (ioa_network_buffer_get_size(sm->m.sm.nd.nbh) > 0) {
        ;
      } else {
        ioa_network_buffer_delete(ioa_eng, sm->m.sm.nd.nbh);
        sm->m.sm.nd.nbh = NULL;
      }
    }

    /* The DTLS handshake just finished on this session's socket: release its
     * half-open slot so it no longer counts against the cap (it is now a
     * return-routable, fully-established peer). */
    if (s && s->dtls_half_open && s->ssl && SSL_is_init_finished(s->ssl)) {
      s->dtls_half_open = false;
      turn_dtls_half_open_dec();
    }

    if (s && ioa_socket_check_bandwidth(s, sm->m.sm.nd.nbh, 1)) {
      s->e = ioa_eng;
      if (s && s->read_cb && sm->m.sm.nd.nbh) {
        s->read_cb(s, IOA_EV_READ, &(sm->m.sm.nd), s->read_ctx, 1);
        ioa_network_buffer_delete(ioa_eng, sm->m.sm.nd.nbh);
        sm->m.sm.nd.nbh = NULL;

        if (ioa_socket_tobeclosed(s)) {
          ts_ur_super_session *ss = (ts_ur_super_session *)s->session;
          if (ss) {
            turn_turnserver *server = (turn_turnserver *)ss->server;
            if (server) {
              shutdown_client_connection(server, ss, 0, "UDP packet processing error");
            }
          }
        }
      }
    }
  } else {
    if (chs && ioa_socket_tobeclosed(chs)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: socket to be closed\n", __FUNCTION__);
      {
        char saddr[MAX_IOA_ADDR_STRING];
        char rsaddr[MAX_IOA_ADDR_STRING];
        addr_to_string(get_local_addr_from_ioa_socket(chs), saddr);
        addr_to_string(get_remote_addr_from_ioa_socket(chs), rsaddr);
        long thrid = 0;
#ifdef WINDOWS
        thrid = GetCurrentThreadId();
#else
        thrid = (long)pthread_self();
#endif
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                      "%s: 111.111: thrid=0x%lx: Amap = %p, socket container=%p, local addr %s, remote addr %s, "
                      "s=%p, done=%d, tbc=%d\n",
                      __FUNCTION__, thrid, amap, chs->sockets_container, (char *)saddr, (char *)rsaddr, s,
                      (int)(chs->done), (int)(chs->tobeclosed));
      }
    }

    if (chs && (chs->magic != SOCKET_MAGIC)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: wrong socket magic\n", __FUNCTION__);
    }

    if (chs && (chs->sockets_container != amap)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: wrong socket container\n", __FUNCTION__);
      {
        char saddr[MAX_IOA_ADDR_STRING];
        char rsaddr[MAX_IOA_ADDR_STRING];
        addr_to_string(get_local_addr_from_ioa_socket(chs), saddr);
        addr_to_string(get_remote_addr_from_ioa_socket(chs), rsaddr);
        long thrid = 0;
#ifdef WINDOWS
        thrid = GetCurrentThreadId();
#else
        thrid = (long)pthread_self();
#endif
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                      "%s: 111.222: thrid=0x%lx: Amap = %p, socket container=%p, local addr %s, remote addr %s, "
                      "s=%p, done=%d, tbc=%d, st=%d, sat=%d\n",
                      __FUNCTION__, thrid, amap, chs->sockets_container, (char *)saddr, (char *)rsaddr, (void *)chs,
                      (int)(chs->done), (int)(chs->tobeclosed), (int)(chs->st), (int)(chs->sat));
      }
    }

    chs = NULL;

#if DTLS_SUPPORTED
    if (turn_params.dtls && (packet_type == UDP_PACKET_CLASS_DTLS_HANDSHAKE)) {
      chs = dtls_server_input_handler(server, s, sm->m.sm.nd.nbh);
      ioa_network_buffer_delete(server->e, sm->m.sm.nd.nbh);
      sm->m.sm.nd.nbh = NULL;
      if (!chs) {
        /* The handshake produced no DTLS socket: the half-open cap was reached
         * or the handshake errored. Drop it - a DTLS handshake datagram must
         * never fall through to create_ioa_socket_from_fd below and become a
         * plain-UDP socket + session. */
        return 0;
      }
    } else if (turn_params.dtls && (packet_type == UDP_PACKET_CLASS_DTLS_OTHER)) {
      /* A non-handshake DTLS record (ApplicationData / Alert /
       * ChangeCipherSpec) from a source with no established DTLS session - the
       * per-source lookup at the top of this function already missed, so there
       * are no session keys to decrypt it and it cannot advance any handshake.
       * Drop it instead of falling through to create_ioa_socket_from_fd below. */
      ioa_network_buffer_delete(server->e, sm->m.sm.nd.nbh);
      sm->m.sm.nd.nbh = NULL;
      return 0;
    }
#endif

    /* A Binding request is answerable from the request bytes and this socket's
     * addresses alone, so it never needs a child socket or a session. */
    if (!chs && (packet_type == UDP_PACKET_CLASS_STUN_OR_CHANNEL) &&
        udp_stateless_binding_fast_path(server, s, &(sm->m.sm.nd))) {
      return 0;
    }

    /* Stateless-nonce mode: a first packet that only needs the derived-nonce
     * 401 challenge (or that the relay would ignore anyway) is answered or
     * dropped right here, without a child socket or session (issue #1999). */
    if (!chs && (packet_type == UDP_PACKET_CLASS_STUN_OR_CHANNEL) &&
        udp_stateless_nonce_fast_path(server, &(sm->m.sm.nd))) {
      return 0;
    }

    if (!chs) {
      // Disallow raw UDP if no_udp is enabled
      if (turn_params.no_udp) {
        return -1;
      }
      chs = create_ioa_socket_from_fd(ioa_eng, s->fd, s, UDP_SOCKET, CLIENT_SOCKET, &(sm->m.sm.nd.src_addr),
                                      get_local_addr_from_ioa_socket(s));
    }

    s = chs;
    sm->m.sm.s = s;

    if (s) {
      if (verbose && turn_params.log_binding) {
        char saddr[MAX_IOA_ADDR_STRING];
        char rsaddr[MAX_IOA_ADDR_STRING];
        addr_to_string(get_local_addr_from_ioa_socket(s), saddr);
        addr_to_string(get_remote_addr_from_ioa_socket(s), rsaddr);
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: New UDP endpoint: local addr %s, remote addr %s\n", __FUNCTION__,
                      (char *)saddr, (char *)rsaddr);
      }
      s->e = ioa_eng;
      set_ioa_socket_buf_size(s, ts->sock_buf_size);
      add_socket_to_map(s, amap);
      if (open_client_connection_session(ts, &(sm->m.sm)) < 0) {
        return -1;
      }
    }
  }

  return 0;
}

static int process_udp_datagram(dtls_listener_relay_server_type *server, ioa_socket_handle s,
                                ioa_network_buffer_handle elem, const ioa_addr *src_addr, ssize_t bsize, int recv_ttl,
                                int recv_tos, int packet_type, uint32_t *packets_processed, uint32_t *packets_dropped) {
  int rc = 0;

  server->sm.m.sm.s = s;
  server->sm.m.sm.nd.nbh = elem;
  server->sm.m.sm.nd.recv_ttl = recv_ttl;
  server->sm.m.sm.nd.recv_tos = recv_tos;
  server->sm.m.sm.can_resume = 1;
  addr_cpy(&(server->sm.m.sm.nd.src_addr), src_addr);

  ioa_network_buffer_set_size(elem, (size_t)bsize);

  uint8_t *data = ioa_network_buffer_data(elem);
  const bool is_valid_packet = (packet_type != UDP_PACKET_CLASS_INVALID);

  if (turn_params.drop_invalid_packets && !is_valid_packet) {
    packetcounter++;
    if (turn_params.drop_invalid_packets_log && (packetcounter % 1000 == 0)) {
      uint8_t txt2pcap[1000]; // 1000 is enough to print ~300B packet (3 chars per byte) with extras
      print_packet_txt2pcap(packetcounter, data, (size_t)bsize, txt2pcap, sizeof(txt2pcap));
      TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "TXT2PCAP: %s\n", txt2pcap);
    }
    ++(*packets_dropped);
  } else {
    ++(*packets_processed);

    if (server->connect_cb) {
      rc = create_new_connected_udp_socket(server, s);
      if (rc < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot handle UDP packet, size %d\n", (int)bsize);
      }
    } else {
      rc = handle_udp_packet(server, &(server->sm), server->e, server->ts, (udp_packet_classification_t)packet_type);
    }

    if (rc < 0 && eve(server->e->verbose)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot handle UDP event\n");
    }
  }

  if (server->sm.m.sm.nd.nbh != NULL) {
    /* buffer was not consumed downstream, return ownership to the caller */
    server->sm.m.sm.nd.nbh = NULL;
    return 1;
  }

  return 0;
}

static udp_packet_classification_t classify_udp_packet(const uint8_t *data, size_t blen) {
  size_t candidate_len = blen;
  uint16_t chnum = 0;
  uint32_t old_stun_cookie = 0;

  if (stun_is_channel_message_str(data, &candidate_len, &chnum, false) ||
      stun_is_command_message_str(data, candidate_len)) {
    return UDP_PACKET_CLASS_STUN_OR_CHANNEL;
  }
#if DTLS_SUPPORTED
  if (turn_params.dtls && is_dtls_handshake_message(data, (int)blen)) {
    return UDP_PACKET_CLASS_DTLS_HANDSHAKE;
  }
  if (turn_params.dtls && is_dtls_message(data, (int)blen)) {
    return UDP_PACKET_CLASS_DTLS_OTHER;
  }
#endif
  if (turn_params.rfc3489_compatibility && old_stun_is_command_message_str(data, blen, &old_stun_cookie)) {
    return UDP_PACKET_CLASS_OLD_STUN;
  }

  return UDP_PACKET_CLASS_INVALID;
}
#if defined(__linux__)
static int ensure_recvmmsg_state(dtls_listener_relay_server_type *server) {
  if (!server) {
    return -1;
  }

  if (server->recvmmsg_state) {
    return 0;
  }

  server->recvmmsg_state =
      (struct dtls_listener_recvmmsg_state *)turn_calloc(1, sizeof(struct dtls_listener_recvmmsg_state));

  for (unsigned int i = 0; i < MAX_RECVMMSG_BATCH; ++i) {
    ioa_init_recvmmsg_hdr(&(server->recvmmsg_state->msgs[i]), &(server->recvmmsg_state->iovecs[i]),
                          &(server->recvmmsg_state->src_addrs[i]), server->recvmmsg_state->cmsgs[i], RECVMMSG_CMSG_SZ,
                          (socklen_t)server->slen0, NULL, 0);
    server->recvmmsg_state->elems[i] = ioa_network_buffer_allocate(server->e);
    if (!server->recvmmsg_state->elems[i]) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot allocate recvmmsg batch buffer\n", __FUNCTION__);
      return -1;
    }
  }

  return 0;
}

static int receive_udp_batch_recvmmsg(dtls_listener_relay_server_type *server, evutil_socket_t fd) {
  unsigned int i = 0;

  if (ensure_recvmmsg_state(server) < 0) {
    return -1;
  }

  struct dtls_listener_recvmmsg_state *state = server->recvmmsg_state;

  for (i = 0; i < MAX_RECVMMSG_BATCH; ++i) {
    if (!state->elems[i]) {
      state->elems[i] = ioa_network_buffer_allocate(server->e);
      if (!state->elems[i]) {
        ioa_engine_record_udp_recvmmsg_no_buffer(server->e);
        break;
      }
    }

    ioa_network_buffer_reset(state->elems[i]);
    addr_set_any(&(state->src_addrs[i]));
    state->ttls[i] = TTL_IGNORE;
    state->toss[i] = TOS_IGNORE;
    state->packet_types[i] = UDP_PACKET_CLASS_INVALID;
    ioa_init_recvmmsg_hdr(&(state->msgs[i]), &(state->iovecs[i]), &(state->src_addrs[i]), state->cmsgs[i],
                          RECVMMSG_CMSG_SZ, (socklen_t)server->slen0, ioa_network_buffer_data(state->elems[i]),
                          ioa_network_buffer_get_capacity_udp());
  }

  if (i == 0) {
    return -1;
  }

  const int rc = recvmmsg(fd, state->msgs, i, MSG_DONTWAIT, NULL);
  if (rc <= 0) {
    if (rc == 0 || would_block()) {
      ioa_engine_record_udp_recvmmsg_wouldblock(server->e);
    }
    return rc;
  }

  ioa_engine_record_udp_recvmmsg_batch(server->e, rc);

  for (int j = 0; j < rc; ++j) {
    ioa_network_buffer_set_size(state->elems[j], state->msgs[j].msg_len);
    ioa_parse_udp_recvmsg_cmsg(&(state->msgs[j].msg_hdr), &(state->ttls[j]), &(state->toss[j]), NULL);
    state->packet_types[j] =
        classify_udp_packet(ioa_network_buffer_data(state->elems[j]), ioa_network_buffer_get_size(state->elems[j]));
  }

  return rc;
}
#endif

static int create_new_connected_udp_socket(dtls_listener_relay_server_type *server, ioa_socket_handle s) {

  evutil_socket_t udp_fd = socket(s->local_addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
  if (udp_fd < 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot allocate new socket. Error: %s\n", __FUNCTION__, strerror(errno));
    return -1;
  }

  if (sock_bind_to_device(udp_fd, (unsigned char *)(s->e->relay_ifname)) < 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot bind udp server socket to device %s\n", (char *)(s->e->relay_ifname));
  }

  ioa_socket_handle ret = (ioa_socket *)turn_calloc(1, sizeof(ioa_socket));

  ret->magic = SOCKET_MAGIC;

  ret->fd = udp_fd;

  ret->family = s->family;
  ret->st = s->st;
  ret->sat = CLIENT_SOCKET;
  ret->local_addr_known = 1;
  addr_cpy(&(ret->local_addr), &(s->local_addr));

  if (addr_bind(udp_fd, &(s->local_addr), 1, 1, UDP_SOCKET) < 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot bind new detached udp server socket to local addr\n");
    IOA_CLOSE_SOCKET(ret);
    return -1;
  }
  ret->bound = 1;

  {
    int connect_err = 0;
    if (addr_connect(udp_fd, &(server->sm.m.sm.nd.src_addr), &connect_err) < 0) {
      char sl[MAX_IOA_ADDR_STRING];
      char sr[MAX_IOA_ADDR_STRING];
      addr_to_string(&(ret->local_addr), sl);
      addr_to_string(&(server->sm.m.sm.nd.src_addr), sr);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                    "Cannot connect new detached udp client socket from local addr %s to remote addr %s\n", sl, sr);
      IOA_CLOSE_SOCKET(ret);
      return -1;
    }
  }
  ret->connected = 1;
  addr_cpy(&(ret->remote_addr), &(server->sm.m.sm.nd.src_addr));

  set_socket_options(ret);

  ret->current_ttl = s->current_ttl;
  ret->default_ttl = s->default_ttl;

  ret->current_tos = s->current_tos;
  ret->default_tos = s->default_tos;

#if DTLS_SUPPORTED
  if (turn_params.dtls && is_dtls_handshake_message(ioa_network_buffer_data(server->sm.m.sm.nd.nbh),
                                                    (int)ioa_network_buffer_get_size(server->sm.m.sm.nd.nbh))) {

    SSL *connecting_ssl = NULL;

    BIO *wbio = NULL;
    struct timeval timeout;

    /* Create BIO */
    wbio = BIO_new_dgram(ret->fd, BIO_NOCLOSE);
    (void)BIO_dgram_set_peer(wbio, (struct sockaddr *)&(server->sm.m.sm.nd.src_addr));

    BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &(server->sm.m.sm.nd.src_addr));

    /* Set and activate timeouts */
    timeout.tv_sec = DTLS_MAX_RECV_TIMEOUT;
    timeout.tv_usec = 0;
    BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    connecting_ssl = SSL_new(server->e->dtls_ctx);

    SSL_set_accept_state(connecting_ssl);

    SSL_set_bio(connecting_ssl, NULL, wbio);

    SSL_set_options(connecting_ssl, SSL_OP_COOKIE_EXCHANGE
#if defined(SSL_OP_NO_RENEGOTIATION)
                                        | SSL_OP_NO_RENEGOTIATION
#endif
    );

    SSL_set_max_cert_list(connecting_ssl, TURN_DTLS_MAX_CERT_LIST);
    const int rc = ssl_read(ret->fd, connecting_ssl, server->sm.m.sm.nd.nbh, server->verbose);

    if (rc < 0) {
      if (!(SSL_get_shutdown(connecting_ssl) & SSL_SENT_SHUTDOWN)) {
        SSL_set_shutdown(connecting_ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(connecting_ssl);
      }
      SSL_free(connecting_ssl);
      IOA_CLOSE_SOCKET(ret);
      return -1;
    }

    addr_debug_print(server->verbose, &(server->sm.m.sm.nd.src_addr), "Accepted DTLS connection from");

    ret->ssl = connecting_ssl;

    ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
    server->sm.m.sm.nd.nbh = NULL;

    ret->st = DTLS_SOCKET;
  }
#endif

  server->sm.m.sm.s = ret;
  return server->connect_cb(server->e, &(server->sm));
}

static void udp_server_input_handler(evutil_socket_t fd, short what, void *arg) {

  if (!arg) {
    return;
  }

  int cycle = 0;

  dtls_listener_relay_server_type *server = (dtls_listener_relay_server_type *)arg;
  ioa_socket_handle s = server->udp_listen_s;

  FUNCSTART;

  if (!(what & EV_READ)) {
    return;
  }

  // printf_server_socket(server, fd);

  ioa_network_buffer_handle elem = NULL;
  uint32_t packets_processed = 0;
  uint32_t packets_dropped = 0;

#if defined(__linux__)
  if (turn_params.udp_recvmmsg) {
    const int batch_rc = receive_udp_batch_recvmmsg(server, fd);

    if (batch_rc > 0) {
      struct dtls_listener_recvmmsg_state *state = server->recvmmsg_state;
      udp_sendmmsg_batch_begin();
      for (int i = 0; i < batch_rc; ++i) {
        if (!state->elems[i]) {
          continue;
        }
        const int keep_elem = process_udp_datagram(
            server, s, state->elems[i], &(state->src_addrs[i]), (ssize_t)ioa_network_buffer_get_size(state->elems[i]),
            state->ttls[i], state->toss[i], state->packet_types[i], &packets_processed, &packets_dropped);
        if (keep_elem) {
          ioa_network_buffer_reset(state->elems[i]);
        } else {
          state->elems[i] = NULL;
        }
      }
      udp_sendmmsg_batch_end();

      ioa_engine_record_packets(server->e, packets_processed, packets_dropped);
      FUNCEND;
      return;
    }

    if (batch_rc < 0) {
      if (errno == ENOSYS || errno == EINVAL || errno == EOPNOTSUPP) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                      "%s: recvmmsg() is unavailable on this system, disabling udp-recvmmsg fast path\n", __FUNCTION__);
        ioa_engine_record_udp_recvmmsg_unavailable(server->e);
        turn_params.udp_recvmmsg = false;
      } else if (would_block()) {
        ioa_engine_record_packets(server->e, packets_processed, packets_dropped);
        FUNCEND;
        return;
      } else if (is_connreset()) {
        reopen_server_socket(server, fd);
        ioa_engine_record_packets(server->e, packets_processed, packets_dropped);
        FUNCEND;
        return;
      }
    }
  }
#endif

start_udp_cycle:

  if (!elem) {
    elem = ioa_network_buffer_allocate(server->e);
  }

  server->sm.m.sm.nd.nbh = elem;
  server->sm.m.sm.nd.recv_ttl = TTL_IGNORE;
  server->sm.m.sm.nd.recv_tos = TOS_IGNORE;
  server->sm.m.sm.can_resume = 1;

  addr_set_any(&(server->sm.m.sm.nd.src_addr));

  ssize_t bsize = 0;
#if defined(WINDOWS)
  int flags = 0;
  u_long iMode = 1;
  ioctlsocket(fd, FIONBIO, &iMode);
#else
  const int flags = MSG_DONTWAIT;
#endif
  bsize = udp_recvfrom(fd, &(server->sm.m.sm.nd.src_addr), &(server->addr), (char *)ioa_network_buffer_data(elem),
                       (int)ioa_network_buffer_get_capacity_udp(), &(server->sm.m.sm.nd.recv_ttl),
                       &(server->sm.m.sm.nd.recv_tos), server->e->cmsg, flags, NULL);

  int conn_reset = is_connreset();
  int to_block = would_block();

#if defined(WINDOWS)
  iMode = 0;
  ioctlsocket(fd, FIONBIO, &iMode);
#endif

  if (bsize < 0) {

    if (to_block) {
      ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
      server->sm.m.sm.nd.nbh = NULL;
      FUNCEND;
      return;
    }

#if defined(MSG_ERRQUEUE)

#if defined(WINDOWS)
    int eflags = MSG_ERRQUEUE;
    iMode = 1;
    ioctlsocket(fd, FIONBIO, &iMode);
#else
    // Linux
    const int eflags = MSG_ERRQUEUE | MSG_DONTWAIT;
#endif
    static char buffer[65535];
    uint32_t errcode = 0;
    ioa_addr orig_addr = {0};
    int ttl = 0;
    int tos = 0;
    socklen_t slen = server->slen0;
    udp_recvfrom(fd, &orig_addr, &(server->addr), buffer, (int)sizeof(buffer), &ttl, &tos, server->e->cmsg, eflags,
                 &errcode);
    // try again...
    do {
      bsize = recvfrom(fd, ioa_network_buffer_data(elem), ioa_network_buffer_get_capacity_udp(), flags,
                       (struct sockaddr *)&(server->sm.m.sm.nd.src_addr), &slen);
    } while (bsize < 0 && socket_eintr());

    conn_reset = is_connreset();
    to_block = would_block();

#if defined(WINDOWS)
    iMode = 0;
    ioctlsocket(fd, FIONBIO, &iMode);
#endif

#endif

    if (conn_reset) {
      ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
      server->sm.m.sm.nd.nbh = NULL;
      reopen_server_socket(server, fd);
      FUNCEND;
      return;
    }
  }

  if (bsize < 0) {
    if (!to_block && !conn_reset) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: recvfrom error %d\n", __FUNCTION__, socket_errno());
    }
    ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
    server->sm.m.sm.nd.nbh = NULL;
    FUNCEND;
    return;
  }

  int keep_elem = 1;
  if (bsize > 0) {
    udp_sendmmsg_batch_begin();
    keep_elem = process_udp_datagram(server, s, elem, &(server->sm.m.sm.nd.src_addr), bsize,
                                     server->sm.m.sm.nd.recv_ttl, server->sm.m.sm.nd.recv_tos,
                                     (int)classify_udp_packet(ioa_network_buffer_data(elem), (size_t)bsize),
                                     &packets_processed, &packets_dropped);
    udp_sendmmsg_batch_end();
  }

  if (keep_elem) {
    /* buffer was not consumed downstream, reuse it on the next iteration.
     * Reset offset/len first (as the recvmmsg path does): recvfrom()/ssl_read()
     * write at buf + offset with a fixed capacity, so a stale offset left by a
     * kept DTLS packet accumulates and eventually walks past the buffer. */
    ioa_network_buffer_reset(elem);
    server->sm.m.sm.nd.nbh = NULL;
  } else {
    /* buffer was consumed (and freed) downstream, need a fresh one next time */
    elem = NULL;
  }

  if ((bsize > 0) && (cycle++ < MAX_SINGLE_UDP_BATCH)) {
    goto start_udp_cycle;
  }

  ioa_network_buffer_delete(server->e, elem);
  elem = NULL;

  ioa_engine_record_packets(server->e, packets_processed, packets_dropped);

  FUNCEND;
}

///////////////////// operations //////////////////////////

static int create_server_socket(dtls_listener_relay_server_type *server, int report_creation, int sock_buf_size) {

  FUNCSTART;

  if (!server) {
    return -1;
  }

  clean_server(server);

  {
    ioa_socket_raw udp_listen_fd = -1;

    udp_listen_fd = socket(server->addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
    if (udp_listen_fd < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: socket error: %s\n", __FUNCTION__, strerror(errno));
      return -1;
    }

    server->udp_listen_s =
        create_ioa_socket_from_fd(server->e, udp_listen_fd, NULL, UDP_SOCKET, LISTENER_SOCKET, NULL, &(server->addr));

    set_ioa_socket_buf_size(server->udp_listen_s, sock_buf_size);

    if (sock_bind_to_device(udp_listen_fd, (unsigned char *)server->ifname) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Cannot bind listener socket to device %s\n", server->ifname);
    }

    set_raw_socket_ttl_options(udp_listen_fd, server->addr.ss.sa_family);
    set_raw_socket_tos_options(udp_listen_fd, server->addr.ss.sa_family);

    {
      const int max_binding_time = 60;
      int addr_bind_cycle = 0;
    retry_addr_bind:

      if (addr_bind(udp_listen_fd, &server->addr, 1, 1, UDP_SOCKET) < 0) {
        char saddr[MAX_IOA_ADDR_STRING];
        addr_to_string(&server->addr, saddr);
        TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Cannot bind DTLS/UDP listener socket to addr %s. Error: %s\n", saddr,
                      strerror(errno));
        if (addr_bind_cycle++ < max_binding_time) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Trying to bind DTLS/UDP listener socket to addr %s, again...\n", saddr);
          sleep(1);
          goto retry_addr_bind;
        }
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                      "Fatal final failure: cannot bind DTLS/UDP listener socket to addr %s. Error: %s\n", saddr,
                      strerror(errno));
        exit(-1);
      }
    }

    server->udp_listen_ev =
        event_new(server->e->event_base, udp_listen_fd, EV_READ | EV_PERSIST, udp_server_input_handler, server);

    event_add(server->udp_listen_ev, NULL);
  }

  if (report_creation) {
    if (!turn_params.no_udp && turn_params.dtls) {
      addr_debug_print(server->verbose, &server->addr, "DTLS/UDP listener opened on");
    } else if (turn_params.dtls) {
      addr_debug_print(server->verbose, &server->addr, "DTLS listener opened on");
    } else if (!turn_params.no_udp) {
      addr_debug_print(server->verbose, &server->addr, "UDP listener opened on");
    }
  }

  FUNCEND;

  return 0;
}

static int reopen_server_socket(dtls_listener_relay_server_type *server, evutil_socket_t fd) {
  UNUSED_ARG(fd);

  if (!server) {
    return 0;
  }

  FUNCSTART;

  {
    EVENT_DEL(server->udp_listen_ev);

    if (server->udp_listen_s->fd >= 0) {
      socket_closesocket(server->udp_listen_s->fd);
      server->udp_listen_s->fd = -1;
    }

    if (!(server->udp_listen_s)) {
      return create_server_socket(server, 1, turn_params.sock_buf_size);
    }

    const ioa_socket_raw udp_listen_fd =
        socket(server->addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
    if (udp_listen_fd < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: socket error: %s\n", __FUNCTION__, strerror(errno));
      FUNCEND;
      return -1;
    }

    server->udp_listen_s->fd = udp_listen_fd;

    /* some UDP sessions may fail due to the race condition here */

    set_socket_options(server->udp_listen_s);
    set_ioa_socket_buf_size(server->udp_listen_s, server->ts->sock_buf_size);

    if (sock_bind_to_device(udp_listen_fd, (unsigned char *)server->ifname) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot bind listener socket to device %s. Error: %s\n", server->ifname,
                    strerror(errno));
    }

    if (addr_bind(udp_listen_fd, &server->addr, 1, 1, UDP_SOCKET) < 0) {
      char saddr[MAX_IOA_ADDR_STRING];
      addr_to_string(&server->addr, saddr);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot bind local socket to addr %s. Error: %s\n", saddr, strerror(errno));
      return -1;
    }

    server->udp_listen_ev =
        event_new(server->e->event_base, udp_listen_fd, EV_READ | EV_PERSIST, udp_server_input_handler, server);

    event_add(server->udp_listen_ev, NULL);
  }

  if (!turn_params.no_udp && turn_params.dtls) {
    addr_debug_print(server->verbose, &server->addr, "DTLS/UDP listener opened on ");
  } else if (turn_params.dtls) {
    addr_debug_print(server->verbose, &server->addr, "DTLS listener opened on ");
  } else if (!turn_params.no_udp) {
    addr_debug_print(server->verbose, &server->addr, "UDP listener opened on ");
  }

  FUNCEND;

  return 0;
}

static int init_server(dtls_listener_relay_server_type *server, const char *ifname, const char *local_address,
                       uint16_t port, int sock_buf_size, int verbose, ioa_engine_handle e, turn_turnserver *ts,
                       int report_creation, ioa_engine_new_connection_event_handler send_socket) {

  if (!server) {
    return -1;
  }

  server->ts = ts;
  server->connect_cb = send_socket;

  if (ifname) {
    STRCPY(server->ifname, ifname);
  }

  if (make_ioa_addr((const uint8_t *)local_address, port, &server->addr) < 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create a DTLS/UDP listener for address: %s\n", local_address);
    return -1;
  }

  server->slen0 = get_ioa_addr_len(&(server->addr));

  server->verbose = verbose;

  server->e = e;

  return create_server_socket(server, report_creation, sock_buf_size);
}

static int clean_server(dtls_listener_relay_server_type *server) {
  if (server) {
    EVENT_DEL(server->udp_listen_ev);
    close_ioa_socket(server->udp_listen_s);
    server->udp_listen_s = NULL;
#if defined(__linux__)
    if (server->recvmmsg_state) {
      for (unsigned int i = 0; i < MAX_RECVMMSG_BATCH; ++i) {
        ioa_network_buffer_delete(server->e, server->recvmmsg_state->elems[i]);
        server->recvmmsg_state->elems[i] = NULL;
      }
      free(server->recvmmsg_state);
      server->recvmmsg_state = NULL;
    }
#endif
  }
  return 0;
}

///////////////////////////////////////////////////////////

#if DTLS_SUPPORTED
void setup_dtls_callbacks(SSL_CTX *ctx) {
  if (!ctx) {
    return;
  }

  SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
  SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
}
#endif

dtls_listener_relay_server_type *create_dtls_listener_server(const char *ifname, const char *local_address,
                                                             uint16_t port, int sock_buf_size, int verbose,
                                                             ioa_engine_handle e, turn_turnserver *ts,
                                                             int report_creation,
                                                             ioa_engine_new_connection_event_handler send_socket) {

  dtls_listener_relay_server_type *server =
      (dtls_listener_relay_server_type *)allocate_super_memory_engine(e, sizeof(dtls_listener_relay_server_type));

  if (init_server(server, ifname, local_address, port, sock_buf_size, verbose, e, ts, report_creation, send_socket) <
      0) {
    return NULL;
  } else {
    return server;
  }
}

ioa_engine_handle get_engine(dtls_listener_relay_server_type *server) {
  if (server) {
    return server->e;
  }
  return NULL;
}

//////////// UDP send ////////////////

void udp_send_message(dtls_listener_relay_server_type *server, ioa_network_buffer_handle nbh, ioa_addr *dest) {
  if (server && dest && nbh && (server->udp_listen_s)) {
    udp_send(server->udp_listen_s, dest, (char *)ioa_network_buffer_data(nbh), (int)ioa_network_buffer_get_size(nbh));
  }
}

//////////////////////////////////////////////////////////////////
