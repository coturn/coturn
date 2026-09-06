/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Unit-test harness for the TURN server core, src/server/ns_turn_server.c,
 * plus its first tests: Send indication peer-address selection.
 *
 * ns_turn_server.c is written against the abstract ioa_* interface in
 * src/server/ns_turn_ioalib.h, which src/apps/relay implements with real
 * sockets, libevent timers and a database. That interface is the seam this
 * harness uses: the functional stubs below stand in for the relay, so the
 * server core runs in-process with no socket, no event loop and no I/O, and a
 * test can hand it a STUN message and inspect exactly what it decided to
 * relay. Everything the tested paths never touch is an abort()ing link stub in
 * test_turn_server_stubs.c.
 *
 * ns_turn_server.c is compiled into this translation unit (the same pattern
 * test_alt_server_list.c uses for netengine.c) because the per-method handlers
 * are static.
 *
 * Adding a test for another method: build the request with the client library
 * as make_send_indication() does, call the handler, and assert on
 * sent_capture / the session state. A handler that reaches a path currently
 * covered by an abort() stub will abort with the symbol name, which tells you
 * which stub to promote from test_turn_server_stubs.c to a functional one
 * here.
 */

#include <unity.h>

#include <stdint.h>
#include <string.h>

#include "ns_turn_server.c"

/* ---------------------------------------------------------------- *
 * Network buffers                                                   *
 * ---------------------------------------------------------------- */

/* Mirrors the offset/coffset arithmetic of the real stun_buffer_list_elem in
 * src/apps/relay/ns_ioalib_engine_impl.c, so the DATA-payload offset handling
 * in handle_turn_send() is exercised as it is in production rather than
 * simplified away. */
typedef struct {
  uint8_t buf[65536];
  size_t len;
  uint16_t offset;
  uint8_t coffset;
} test_buffer;

static test_buffer test_nbh;

uint8_t *ioa_network_buffer_data(ioa_network_buffer_handle nbh) {
  test_buffer *b = (test_buffer *)nbh;
  return b->buf + b->offset - b->coffset;
}

size_t ioa_network_buffer_get_size(ioa_network_buffer_handle nbh) {
  if (!nbh) {
    return 0;
  }
  return ((test_buffer *)nbh)->len;
}

void ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len) { ((test_buffer *)nbh)->len = len; }

void ioa_network_buffer_add_offset_size(ioa_network_buffer_handle nbh, uint16_t offset, uint8_t coffset, size_t len) {
  test_buffer *b = (test_buffer *)nbh;
  b->len = len;
  b->offset = (uint16_t)(b->offset + offset);
  b->coffset = (uint8_t)(b->coffset + coffset);
}

void ioa_network_buffer_header_init(ioa_network_buffer_handle nbh) { UNUSED_ARG(nbh); }

size_t ioa_network_buffer_get_capacity_udp(void) { return sizeof(test_nbh.buf); }

ioa_network_buffer_handle ioa_network_buffer_allocate(ioa_engine_handle e) {
  UNUSED_ARG(e);
  return &test_nbh;
}

void ioa_network_buffer_delete(ioa_engine_handle e, ioa_network_buffer_handle nbh) {
  UNUSED_ARG(e);
  UNUSED_ARG(nbh);
}

/* ---------------------------------------------------------------- *
 * Relay socket                                                      *
 * ---------------------------------------------------------------- */

/* Stands in for an ioa_socket_handle. Only its address is compared, except for
 * the family/type the multiplex-peer check reads. */
typedef struct {
  int family;
} test_socket;

static test_socket relay_socket_v4 = {AF_INET};

int get_ioa_socket_address_family(const ioa_socket_handle s) { return ((const test_socket *)s)->family; }

SOCKET_TYPE get_ioa_socket_type(const ioa_socket_handle s) {
  (void)s;
  return UDP_SOCKET;
}

/* What the server decided to relay, captured instead of sent. */
static struct {
  int calls;
  ioa_addr dest;
  size_t len;
  uint8_t payload[1500];
  ioa_socket_handle s;
  int ttl;
  int tos;
  int df;
} sent_capture;

int send_data_from_ioa_socket_nbh(ioa_socket_handle s, ioa_addr *dest_addr, ioa_network_buffer_handle nbh, int ttl,
                                  int tos, int *skip) {
  sent_capture.calls++;
  sent_capture.s = s;
  sent_capture.ttl = ttl;
  sent_capture.tos = tos;
  if (dest_addr) {
    addr_cpy(&(sent_capture.dest), dest_addr);
  }
  sent_capture.len = ioa_network_buffer_get_size(nbh);
  if (sent_capture.len > sizeof(sent_capture.payload)) {
    sent_capture.len = sizeof(sent_capture.payload);
  }
  memcpy(sent_capture.payload, ioa_network_buffer_data(nbh), sent_capture.len);
  if (skip) {
    *skip = 0;
  }
  return (int)sent_capture.len;
}

int set_df_on_ioa_socket(ioa_socket_handle s, int value) {
  UNUSED_ARG(s);
  sent_capture.df = value;
  return 0;
}

void turn_report_session_usage(void *session, int force_invalid) {
  UNUSED_ARG(session);
  UNUSED_ARG(force_invalid);
}

/* Reached from clear_allocation() in tearDown(). The relay socket is a plain
 * struct here, so tearing it down is a no-op. */
void turn_report_allocation_delete(void *a, SOCKET_TYPE socket_type) {
  UNUSED_ARG(a);
  UNUSED_ARG(socket_type);
}

void clear_ioa_socket_session_if(ioa_socket_handle s, void *ss_arg) {
  UNUSED_ARG(s);
  UNUSED_ARG(ss_arg);
}

void close_ioa_socket(ioa_socket_handle s) { UNUSED_ARG(s); }

/* is_multiplex_peer_udp_relay() short-circuits on !server->multiplex_peer_mode,
 * so this is only reached if a test opts into multiplex-peer mode. */
ioa_socket_handle mp_get_socket(ioa_engine_handle e, int family) {
  UNUSED_ARG(e);
  UNUSED_ARG(family);
  return NULL;
}

/* Engine-wide peer access lists, consulted by good_peer_addr() on the
 * CreatePermission and ChannelBind paths. Empty here: the per-server lists in
 * turn_turnserver are what the tests configure. */
const ip_range_list_t *ioa_get_whitelist(ioa_engine_handle e) {
  UNUSED_ARG(e);
  return NULL;
}

const ip_range_list_t *ioa_get_blacklist(ioa_engine_handle e) {
  UNUSED_ARG(e);
  return NULL;
}

void ioa_lock_whitelist(ioa_engine_handle e) { UNUSED_ARG(e); }
void ioa_unlock_whitelist(ioa_engine_handle e) { UNUSED_ARG(e); }
void ioa_lock_blacklist(ioa_engine_handle e) { UNUSED_ARG(e); }
void ioa_unlock_blacklist(ioa_engine_handle e) { UNUSED_ARG(e); }

/* ---------------------------------------------------------------- *
 * Fixture                                                           *
 * ---------------------------------------------------------------- */

static turn_turnserver server;
static ts_ur_super_session ss;

/* Response buffer for the handlers that build one. Separate from test_nbh so a
 * test can inspect request and response independently. */
static test_buffer response_nbh;

/* Backing storage for the turn_turnserver fields that are pointers to config
 * values. good_peer_addr() and update_turn_permission_lifetime() dereference
 * these unconditionally. */
static bool allow_loopback_peers;
static bool no_multicast_peers;
static vint permission_lifetime;
static vint channel_lifetime;

/* TTL presented on the incoming datagram; a test lowers it to reach the
 * TTL-exhausted path. */
static int recv_ttl;

/* Number of comprehension-required attributes the handler could not process,
 * recorded so a test can assert on the 420 path. */
static uint16_t last_ua_num;

#define PEER_A "127.0.0.1"
#define PEER_B "127.0.0.2"
#define PEER_PORT_A (4000)
#define PEER_PORT_B (5000)

static void make_addr(ioa_addr *addr, const char *ip, uint16_t port) {
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)ip, port, addr));
}

void setUp(void) {
  memset(&server, 0, sizeof(server));
  memset(&ss, 0, sizeof(ss));
  memset(&sent_capture, 0, sizeof(sent_capture));
  memset(&test_nbh, 0, sizeof(test_nbh));
  memset(&response_nbh, 0, sizeof(response_nbh));

  server.dont_fragment = DONT_FRAGMENT_UNSUPPORTED;

  /* The tests relay to 127.0.0.x, which good_peer_addr() rejects by default. */
  allow_loopback_peers = true;
  no_multicast_peers = false;
  server.allow_loopback_peers = &allow_loopback_peers;
  server.no_multicast_peers = &no_multicast_peers;

  permission_lifetime = STUN_DEFAULT_PERMISSION_LIFETIME;
  channel_lifetime = STUN_DEFAULT_CHANNEL_LIFETIME;
  server.permission_lifetime = &permission_lifetime;
  server.channel_lifetime = &channel_lifetime;

  recv_ttl = 64;
  last_ua_num = 0;

  /* update_turn_permission_lifetime() reaches the server through the session. */
  ss.server = &server;

  init_allocation(&ss, &(ss.alloc), NULL);
  set_allocation_valid(&(ss.alloc), true);
  ss.alloc.relay_sessions[ALLOC_INDEX(AF_INET)].s = (ioa_socket_handle)&relay_socket_v4;
}

void tearDown(void) { clear_allocation(&(ss.alloc), UDP_SOCKET); }

static void add_permission(const char *ip, uint16_t port) {
  ioa_addr addr;
  make_addr(&addr, ip, port);
  TEST_ASSERT_NOT_NULL(allocation_add_permission(&(ss.alloc), &addr));
}

/* Incremental message builder over the fixture buffer, so a test can compose an
 * attribute sequence a conformant client would never send. */
static size_t msg_len;

static void msg_begin(uint16_t method, bool indication) {
  msg_len = 0;
  if (indication) {
    stun_init_indication_str(method, test_nbh.buf, &msg_len);
  } else {
    stun_init_request_str(method, test_nbh.buf, &msg_len);
  }
}

static void msg_add_peer(const ioa_addr *peer) {
  TEST_ASSERT_TRUE(stun_attr_add_addr_str(test_nbh.buf, &msg_len, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer));
}

static void msg_add_data(const uint8_t *payload, size_t payload_len) {
  TEST_ASSERT_TRUE(stun_attr_add_str(test_nbh.buf, &msg_len, STUN_ATTRIBUTE_DATA, payload, (int)payload_len));
}

static void msg_add_dont_fragment(void) {
  TEST_ASSERT_TRUE(stun_attr_add_str(test_nbh.buf, &msg_len, STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0));
}

static void msg_add_channel_number(uint16_t chnum) {
  TEST_ASSERT_TRUE(stun_attr_add_channel_number_str(test_nbh.buf, &msg_len, chnum));
}

static void msg_finish(void) {
  test_nbh.len = msg_len;
  test_nbh.offset = 0;
  test_nbh.coffset = 0;
}

/* Builds a Send indication carrying peer_count XOR-PEER-ADDRESS attributes
 * followed by a DATA attribute, and loads it into the fixture buffer. */
static void make_send_indication(const ioa_addr *peers, size_t peer_count, const uint8_t *payload, size_t payload_len) {
  msg_begin(STUN_METHOD_SEND, true);
  for (size_t i = 0; i < peer_count; ++i) {
    msg_add_peer(&(peers[i]));
  }
  msg_add_data(payload, payload_len);
  msg_finish();
}

/* Drives handle_turn_send() over the fixture buffer and returns its err_code
 * (0 when the indication was accepted). */
static int run_send(void) {
  ioa_net_data in_buffer;
  memset(&in_buffer, 0, sizeof(in_buffer));
  in_buffer.nbh = &test_nbh;
  in_buffer.recv_ttl = recv_ttl;
  in_buffer.recv_tos = 0;

  int err_code = 0;
  const uint8_t *reason = NULL;
  uint16_t unknown_attrs[MAX_NUMBER_OF_UNKNOWN_ATTRS];
  uint16_t ua_num = 0;
  memset(unknown_attrs, 0, sizeof(unknown_attrs));

  TEST_ASSERT_EQUAL_INT(0, handle_turn_send(&server, &ss, &err_code, &reason, unknown_attrs, &ua_num, &in_buffer));
  last_ua_num = ua_num;
  return err_code;
}

/* Drives handle_turn_create_permission() over the fixture buffer. Returns the
 * err_code; resp_constructed reports whether a success response was built. */
static int run_create_permission(int *resp_constructed) {
  ioa_net_data in_buffer;
  memset(&in_buffer, 0, sizeof(in_buffer));
  in_buffer.nbh = &test_nbh;
  in_buffer.recv_ttl = recv_ttl;

  stun_tid tid;
  memset(&tid, 0, sizeof(tid));
  stun_tid_from_message_str(test_nbh.buf, test_nbh.len, &tid);

  int err_code = 0;
  int constructed = 0;
  const uint8_t *reason = NULL;
  uint16_t unknown_attrs[MAX_NUMBER_OF_UNKNOWN_ATTRS];
  uint16_t ua_num = 0;
  memset(unknown_attrs, 0, sizeof(unknown_attrs));

  handle_turn_create_permission(&server, &ss, &tid, &constructed, &err_code, &reason, unknown_attrs, &ua_num,
                                &in_buffer, &response_nbh);
  last_ua_num = ua_num;
  if (resp_constructed) {
    *resp_constructed = constructed;
  }
  return err_code;
}

/* Drives handle_turn_channel_bind() over the fixture buffer. Returns the
 * err_code; resp_constructed reports whether a success response was built. */
static int run_channel_bind(int *resp_constructed) {
  ioa_net_data in_buffer;
  memset(&in_buffer, 0, sizeof(in_buffer));
  in_buffer.nbh = &test_nbh;
  in_buffer.recv_ttl = recv_ttl;

  stun_tid tid;
  memset(&tid, 0, sizeof(tid));
  stun_tid_from_message_str(test_nbh.buf, test_nbh.len, &tid);

  int err_code = 0;
  int constructed = 0;
  const uint8_t *reason = NULL;
  uint16_t unknown_attrs[MAX_NUMBER_OF_UNKNOWN_ATTRS];
  uint16_t ua_num = 0;
  memset(unknown_attrs, 0, sizeof(unknown_attrs));

  handle_turn_channel_bind(&server, &ss, &tid, &constructed, &err_code, &reason, unknown_attrs, &ua_num, &in_buffer,
                           &response_nbh);
  last_ua_num = ua_num;
  if (resp_constructed) {
    *resp_constructed = constructed;
  }
  return err_code;
}

static bool has_permission(const char *ip, uint16_t port) {
  ioa_addr addr;
  make_addr(&addr, ip, port);
  return allocation_get_permission(&(ss.alloc), &addr) != NULL;
}

/* ---------------------------------------------------------------- *
 * Tests                                                             *
 * ---------------------------------------------------------------- */

/* Harness sanity: the ordinary one-peer case must relay the DATA payload
 * verbatim to the peer named by the single XOR-PEER-ADDRESS. */
static void test_send_relays_payload_to_the_permitted_peer(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);

  const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef, 0x01};
  make_send_indication(&peer, 1, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(1, sent_capture.calls);
  TEST_ASSERT_TRUE(addr_eq(&peer, &(sent_capture.dest)));
  TEST_ASSERT_EQUAL_size_t(sizeof(payload), sent_capture.len);
  TEST_ASSERT_EQUAL_MEMORY(payload, sent_capture.payload, sizeof(payload));
  /* RFC 8656 Section 11.2: the relayed datagram carries the received TTL minus one. */
  TEST_ASSERT_EQUAL_INT(63, sent_capture.ttl);
}

/* RFC 8489 Section 14: only the first occurrence of a repeated attribute needs
 * to be processed. The peer that receives the data must therefore be the one
 * named first, whatever follows it. */
static void test_send_uses_first_of_duplicate_peer_addresses(void) {
  ioa_addr peers[2];
  make_addr(&(peers[0]), PEER_A, PEER_PORT_A);
  make_addr(&(peers[1]), PEER_B, PEER_PORT_B);
  add_permission(PEER_A, PEER_PORT_A);
  add_permission(PEER_B, PEER_PORT_B);

  const uint8_t payload[] = {0x11, 0x22, 0x33, 0x44};
  make_send_indication(peers, 2, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(1, sent_capture.calls);
  TEST_ASSERT_TRUE(addr_eq(&(peers[0]), &(sent_capture.dest)));
  TEST_ASSERT_FALSE(addr_eq(&(peers[1]), &(sent_capture.dest)));
  TEST_ASSERT_EQUAL_MEMORY(payload, sent_capture.payload, sizeof(payload));
}

/* The permission check applies to the address actually used, so a trailing
 * permitted address cannot smuggle data past a first address that has none. */
static void test_send_is_dropped_when_only_a_later_peer_is_permitted(void) {
  ioa_addr peers[2];
  make_addr(&(peers[0]), PEER_A, PEER_PORT_A);
  make_addr(&(peers[1]), PEER_B, PEER_PORT_B);
  add_permission(PEER_B, PEER_PORT_B);

  const uint8_t payload[] = {0x55, 0x66};
  make_send_indication(peers, 2, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(0, sent_capture.calls);
}

/* Six repetitions, to show the choice is the first occurrence rather than an
 * artifact of pairwise ordering. */
static void test_send_uses_first_of_many_duplicate_peer_addresses(void) {
  ioa_addr peers[6];
  make_addr(&(peers[0]), PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);
  for (size_t i = 1; i < 6; ++i) {
    make_addr(&(peers[i]), PEER_B, (uint16_t)(PEER_PORT_B + i));
    add_permission(PEER_B, (uint16_t)(PEER_PORT_B + i));
  }

  const uint8_t payload[] = {0x77};
  make_send_indication(peers, 6, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(1, sent_capture.calls);
  TEST_ASSERT_TRUE(addr_eq(&(peers[0]), &(sent_capture.dest)));
}

/* RFC 8656 Section 11.2: a Send indication without XOR-PEER-ADDRESS is
 * discarded. */
static void test_send_without_peer_address_is_discarded(void) {
  const uint8_t payload[] = {0x88, 0x99};
  make_send_indication(NULL, 0, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_INT(400, run_send());
  TEST_ASSERT_EQUAL_INT(0, sent_capture.calls);
}

/* RFC 8656 Section 11.2: Send indications do not install permissions, so an
 * unpermitted peer is silently dropped rather than answered. */
static void test_send_to_unpermitted_peer_is_dropped_without_error(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);

  const uint8_t payload[] = {0xaa};
  make_send_indication(&peer, 1, payload, sizeof(payload));

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(0, sent_capture.calls);
  TEST_ASSERT_NULL(allocation_get_permission(&(ss.alloc), &peer));
}

/* RFC 8656 Section 11.2: the DATA attribute is allowed to carry zero bytes. */
static void test_send_relays_zero_length_data(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);

  msg_begin(STUN_METHOD_SEND, true);
  msg_add_peer(&peer);
  msg_add_data(NULL, 0);
  msg_finish();

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(1, sent_capture.calls);
  TEST_ASSERT_TRUE(addr_eq(&peer, &(sent_capture.dest)));
  TEST_ASSERT_EQUAL_size_t(0, sent_capture.len);
}

/* RFC 8656 Section 11.2: a Send indication must carry a DATA attribute, and one
 * that does not is discarded. */
static void test_send_without_data_is_discarded(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);

  msg_begin(STUN_METHOD_SEND, true);
  msg_add_peer(&peer);
  msg_finish();

  TEST_ASSERT_EQUAL_INT(400, run_send());
  TEST_ASSERT_EQUAL_INT(0, sent_capture.calls);
}

/* RFC 8489 Section 14: a repeated DATA attribute is not an error - the first
 * occurrence is relayed and the duplicate ignored, as for XOR-PEER-ADDRESS. */
static void test_send_uses_first_of_duplicate_data(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);

  const uint8_t first[] = {0x01, 0x02};
  const uint8_t second[] = {0x03, 0x04};
  msg_begin(STUN_METHOD_SEND, true);
  msg_add_peer(&peer);
  msg_add_data(first, sizeof(first));
  msg_add_data(second, sizeof(second));
  msg_finish();

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(1, sent_capture.calls);
  TEST_ASSERT_EQUAL_size_t(sizeof(first), sent_capture.len);
  TEST_ASSERT_EQUAL_MEMORY(first, sent_capture.payload, sizeof(first));
}

/* RFC 8656 Section 14.9 (DONT-FRAGMENT is comprehension-required): a server
 * that cannot set DF reports it as an unknown attribute, and the indication is
 * not relayed. */
static void test_send_dont_fragment_is_unknown_when_unsupported(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);

  const uint8_t payload[] = {0xab};
  server.dont_fragment = DONT_FRAGMENT_UNSUPPORTED;
  msg_begin(STUN_METHOD_SEND, true);
  msg_add_peer(&peer);
  msg_add_dont_fragment();
  msg_add_data(payload, sizeof(payload));
  msg_finish();

  TEST_ASSERT_EQUAL_INT(420, run_send());
  TEST_ASSERT_EQUAL_UINT16(1, last_ua_num);
  TEST_ASSERT_EQUAL_INT(0, sent_capture.calls);
}

/* RFC 8656 Section 11.2: when the server supports it, DONT-FRAGMENT sets the DF
 * bit on the relayed datagram. */
static void test_send_dont_fragment_sets_df_when_supported(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);

  const uint8_t payload[] = {0xcd};
  server.dont_fragment = DONT_FRAGMENT_SUPPORTED;
  msg_begin(STUN_METHOD_SEND, true);
  msg_add_peer(&peer);
  msg_add_dont_fragment();
  msg_add_data(payload, sizeof(payload));
  msg_finish();

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(1, sent_capture.calls);
  TEST_ASSERT_EQUAL_INT(1, sent_capture.df);
}

/* RFC 6062 Section 5.3: Send and Data indications are not used with a TCP
 * allocation. */
static void test_send_over_a_tcp_relay_is_rejected(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);

  const uint8_t payload[] = {0x01};
  make_send_indication(&peer, 1, payload, sizeof(payload));
  ss.is_tcp_relay = true;

  TEST_ASSERT_EQUAL_INT(403, run_send());
  TEST_ASSERT_EQUAL_INT(0, sent_capture.calls);
}

/* A session whose allocation has gone away relays nothing, and says nothing:
 * an indication has no response to carry an error. */
static void test_send_without_a_valid_allocation_is_dropped(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);

  const uint8_t payload[] = {0x01};
  make_send_indication(&peer, 1, payload, sizeof(payload));
  set_allocation_valid(&(ss.alloc), false);

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(0, sent_capture.calls);
}

/* The relayed datagram carries the received TTL minus one, so a datagram that
 * arrives with the TTL already exhausted is dropped rather than relayed with a
 * negative value. */
static void test_send_with_exhausted_ttl_is_dropped(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);
  add_permission(PEER_A, PEER_PORT_A);

  const uint8_t payload[] = {0x01};
  make_send_indication(&peer, 1, payload, sizeof(payload));
  recv_ttl = 0;

  TEST_ASSERT_EQUAL_INT(0, run_send());
  TEST_ASSERT_EQUAL_INT(0, sent_capture.calls);
}

/* RFC 8656 Section 9.2: a CreatePermission request may carry several
 * XOR-PEER-ADDRESS attributes, and a permission is installed for each. This is
 * why CreatePermission counts addresses where Send takes only the first. */
static void test_create_permission_installs_every_peer_address(void) {
  ioa_addr peers[3];
  make_addr(&(peers[0]), PEER_A, PEER_PORT_A);
  make_addr(&(peers[1]), PEER_B, PEER_PORT_B);
  make_addr(&(peers[2]), PEER_B, (uint16_t)(PEER_PORT_B + 1));

  msg_begin(STUN_METHOD_CREATE_PERMISSION, false);
  for (size_t i = 0; i < 3; ++i) {
    msg_add_peer(&(peers[i]));
  }
  msg_finish();

  int resp_constructed = 0;
  TEST_ASSERT_EQUAL_INT(0, run_create_permission(&resp_constructed));
  TEST_ASSERT_EQUAL_INT(1, resp_constructed);
  TEST_ASSERT_TRUE(has_permission(PEER_A, PEER_PORT_A));
  TEST_ASSERT_TRUE(has_permission(PEER_B, PEER_PORT_B));
}

/* RFC 8656 Section 9.2: a permission covers the peer's IP address only, so one
 * created for a given port also admits traffic on another. The permission
 * hashtable keys on the address without the port, so this holds end to end
 * rather than resting on the handler zeroing the port. */
static void test_create_permission_ignores_the_port(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);

  msg_begin(STUN_METHOD_CREATE_PERMISSION, false);
  msg_add_peer(&peer);
  msg_finish();

  TEST_ASSERT_EQUAL_INT(0, run_create_permission(NULL));
  TEST_ASSERT_TRUE(has_permission(PEER_A, (uint16_t)(PEER_PORT_A + 1234)));
}

/* A CreatePermission naming no peer at all is malformed. */
static void test_create_permission_without_peer_address_is_rejected(void) {
  msg_begin(STUN_METHOD_CREATE_PERMISSION, false);
  msg_finish();

  TEST_ASSERT_EQUAL_INT(400, run_create_permission(NULL));
}

/* A channel number in the strict RFC 8656 Section 12 range. */
#define TEST_CHANNEL_NUMBER (0x4001)

/* Harness sanity for the ChannelBind path: one peer address binds that peer to
 * the channel and a success response is built. */
static void test_channel_bind_binds_the_peer_address(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);

  msg_begin(STUN_METHOD_CHANNEL_BIND, false);
  msg_add_channel_number(TEST_CHANNEL_NUMBER);
  msg_add_peer(&peer);
  msg_finish();

  int constructed = 0;
  TEST_ASSERT_EQUAL_INT(0, run_channel_bind(&constructed));
  TEST_ASSERT_TRUE(constructed);

  ch_info *chn = allocation_get_ch_info(&(ss.alloc), TEST_CHANNEL_NUMBER);
  TEST_ASSERT_NOT_NULL(chn);
  TEST_ASSERT_TRUE(addr_eq(&peer, &(chn->peer_addr)));
}

/* RFC 8656 Section 5: for any request other than Allocate, a 5-tuple that
 * does not identify an existing allocation is rejected with 437 (Allocation
 * Mismatch). A ChannelBind received after its allocation expires reports
 * that rather than falling through to the generic Bad Request response. */
static void test_channel_bind_without_a_valid_allocation_reports_mismatch(void) {
  ioa_addr peer;
  make_addr(&peer, PEER_A, PEER_PORT_A);

  msg_begin(STUN_METHOD_CHANNEL_BIND, false);
  msg_add_channel_number(TEST_CHANNEL_NUMBER);
  msg_add_peer(&peer);
  msg_finish();
  set_allocation_valid(&(ss.alloc), false);

  int constructed = 0;
  TEST_ASSERT_EQUAL_INT(437, run_channel_bind(&constructed));
  TEST_ASSERT_FALSE(constructed);
}

/* RFC 8489 Section 14: only the first occurrence of a repeated attribute needs
 * to be processed. A channel binds to exactly one peer, so the first
 * XOR-PEER-ADDRESS must win however many follow it - otherwise the bound peer
 * is attribute-order dependent. */
static void test_channel_bind_uses_first_of_duplicate_peer_addresses(void) {
  ioa_addr peers[2];
  make_addr(&(peers[0]), PEER_A, PEER_PORT_A);
  make_addr(&(peers[1]), PEER_B, PEER_PORT_B);

  msg_begin(STUN_METHOD_CHANNEL_BIND, false);
  msg_add_channel_number(TEST_CHANNEL_NUMBER);
  msg_add_peer(&(peers[0]));
  msg_add_peer(&(peers[1]));
  msg_finish();

  TEST_ASSERT_EQUAL_INT(0, run_channel_bind(NULL));

  ch_info *chn = allocation_get_ch_info(&(ss.alloc), TEST_CHANNEL_NUMBER);
  TEST_ASSERT_NOT_NULL(chn);
  TEST_ASSERT_TRUE(addr_eq(&(peers[0]), &(chn->peer_addr)));
  TEST_ASSERT_FALSE(addr_eq(&(peers[1]), &(chn->peer_addr)));
}

/* The permission installed alongside the channel follows the same first-wins
 * choice, so a trailing address cannot open a permission of its own. */
static void test_channel_bind_permits_only_the_first_peer(void) {
  ioa_addr peers[2];
  make_addr(&(peers[0]), PEER_A, PEER_PORT_A);
  make_addr(&(peers[1]), PEER_B, PEER_PORT_B);

  msg_begin(STUN_METHOD_CHANNEL_BIND, false);
  msg_add_channel_number(TEST_CHANNEL_NUMBER);
  msg_add_peer(&(peers[0]));
  msg_add_peer(&(peers[1]));
  msg_finish();

  TEST_ASSERT_EQUAL_INT(0, run_channel_bind(NULL));
  TEST_ASSERT_TRUE(has_permission(PEER_A, PEER_PORT_A));
  TEST_ASSERT_FALSE(has_permission(PEER_B, PEER_PORT_B));
}

/* Spelled as a literal, not as TURN_RANDOM_NONCE_LENGTH: the generator bounds
 * itself with that macro, so asserting it would hold for any width the macro
 * happened to take. 16 is the wire format. */
#define RANDOM_NONCE_WIRE_LENGTH 16

/* The legacy challenge nonce is 16 lowercase hex chars on every platform. It
 * is written into a buffer sized for the longer stateless nonce, so a
 * generator bound by the buffer rather than by its own format emits 24 chars
 * (64-bit) or 20 (LLP64/32-bit) instead - a wire-format change for servers
 * that never enabled --stateless-nonce. Loop, because only draws above 2^32
 * overflow the format. */
static void test_random_challenge_nonce_is_sixteen_lowercase_hex_chars(void) {
  TEST_ASSERT_EQUAL_size_t(RANDOM_NONCE_WIRE_LENGTH, (size_t)TURN_RANDOM_NONCE_LENGTH);

  for (int attempt = 0; attempt < 64; ++attempt) {
    uint8_t nonce[NONCE_MAX_SIZE];
    memset(nonce, 0xff, sizeof(nonce));

    generate_random_challenge_nonce(nonce);

    TEST_ASSERT_EQUAL_size_t(RANDOM_NONCE_WIRE_LENGTH, strlen((char *)nonce));
    for (size_t i = 0; i < RANDOM_NONCE_WIRE_LENGTH; ++i) {
      const char c = (char)nonce[i];
      TEST_ASSERT_TRUE(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')));
    }
    /* The generator gets a NONCE_MAX_SIZE buffer but may only use its own
     * format's size, so everything past the terminator is still untouched. */
    for (size_t i = RANDOM_NONCE_WIRE_LENGTH + 1; i < sizeof(nonce); ++i) {
      TEST_ASSERT_EQUAL_HEX8(0xff, nonce[i]);
    }
  }
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_send_relays_payload_to_the_permitted_peer);
  RUN_TEST(test_send_uses_first_of_duplicate_peer_addresses);
  RUN_TEST(test_send_is_dropped_when_only_a_later_peer_is_permitted);
  RUN_TEST(test_send_uses_first_of_many_duplicate_peer_addresses);
  RUN_TEST(test_send_without_peer_address_is_discarded);
  RUN_TEST(test_send_to_unpermitted_peer_is_dropped_without_error);
  RUN_TEST(test_send_relays_zero_length_data);
  RUN_TEST(test_send_without_data_is_discarded);
  RUN_TEST(test_send_uses_first_of_duplicate_data);
  RUN_TEST(test_send_dont_fragment_is_unknown_when_unsupported);
  RUN_TEST(test_send_dont_fragment_sets_df_when_supported);
  RUN_TEST(test_send_over_a_tcp_relay_is_rejected);
  RUN_TEST(test_send_without_a_valid_allocation_is_dropped);
  RUN_TEST(test_send_with_exhausted_ttl_is_dropped);
  RUN_TEST(test_create_permission_installs_every_peer_address);
  RUN_TEST(test_create_permission_ignores_the_port);
  RUN_TEST(test_create_permission_without_peer_address_is_rejected);
  RUN_TEST(test_channel_bind_binds_the_peer_address);
  RUN_TEST(test_channel_bind_without_a_valid_allocation_reports_mismatch);
  RUN_TEST(test_channel_bind_uses_first_of_duplicate_peer_addresses);
  RUN_TEST(test_channel_bind_permits_only_the_first_peer);
  RUN_TEST(test_random_challenge_nonce_is_sixteen_lowercase_hex_chars);
  return UNITY_END();
}
