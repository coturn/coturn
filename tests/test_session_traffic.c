/* SPDX-License-Identifier: BSD-3-Clause
 * Exercise the real reporting paths with counters beyond the 32-bit limit.
 * Redis and Prometheus are captured locally; no servers or sockets are needed.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unity.h>

static void capture_log(const char *format, ...);
#define TURN_LOG_FUNC(level, ...) capture_log(__VA_ARGS__)
#include "ns_ioalib_engine_impl.c"

static ioa_engine engine;
static turn_turnserver server;
static ts_ur_super_session session;
static char peer_log[1024];
static char peer_traffic[256];
static char peer_total[256];
static char client_total[256];
static uint64_t prom_values[2][4];
static unsigned int prom_calls;
static const uint64_t big = UINT64_C(4294967296);

static void capture_log(const char *format, ...) {
  if (strncmp(format, "peer usage:", 11) == 0) {
    va_list args;
    va_start(args, format);
    vsnprintf(peer_log, sizeof(peer_log), format, args);
    va_end(args);
  }
}

void send_message_to_redis(redis_context_handle rch, const char *command, const char *key, const char *format, ...) {
  UNUSED_ARG(rch);
  TEST_ASSERT_TRUE(strcmp(command, "publish") == 0 || strcmp(command, "del") == 0);
  char *dest = NULL;
  if (strstr(key, "/total_traffic/peer")) {
    dest = peer_total;
  } else if (strstr(key, "/total_traffic")) {
    dest = client_total;
  } else if (strstr(key, "/traffic/peer")) {
    dest = peer_traffic;
  }
  if (dest) {
    va_list args;
    va_start(args, format);
    vsnprintf(dest, 256, format, args);
    va_end(args);
  }
}

void prom_set_finished_traffic(const char *realm, const char *user, uint64_t rsvp, uint64_t rsvb, uint64_t sentp,
                               uint64_t sentb, bool peer) {
  TEST_ASSERT_EQUAL_STRING(session.realm_options.name[0] ? session.realm_options.name : NULL, realm);
  TEST_ASSERT_EQUAL_STRING("test", user);
  prom_values[peer][0] = rsvp;
  prom_values[peer][1] = rsvb;
  prom_values[peer][2] = sentp;
  prom_values[peer][3] = sentb;
  ++prom_calls;
}

ioa_engine_handle turn_server_get_engine(turn_turnserver *s) {
  TEST_ASSERT_EQUAL_PTR(&server, s);
  return &engine;
}
turn_time_t get_turn_server_time(turn_turnserver *s) {
  UNUSED_ARG(s);
  return session.start_time + 10;
}
int report_turn_session_info(turn_turnserver *s, ts_ur_super_session *ss, int force_invalid) {
  UNUSED_ARG(s);
  UNUSED_ARG(force_invalid);
  TEST_ASSERT_EQUAL_PTR(&session, ss);
  return 0;
}
const turn_dbdriver_t *get_dbdriver(void) { return NULL; }
void prom_dec_allocation(SOCKET_TYPE type, int family) {
  UNUSED_ARG(type);
  UNUSED_ARG(family);
}
void decrement_global_allocation_count(void) {}

void setUp(void) {
  memset(&engine, 0, sizeof(engine));
  memset(&server, 0, sizeof(server));
  memset(&session, 0, sizeof(session));
  memset(prom_values, 0, sizeof(prom_values));
  prom_calls = 0;
  peer_log[0] = peer_traffic[0] = peer_total[0] = client_total[0] = '\0';
  engine.verbose = TURN_VERBOSE_NORMAL;
  session.server = &server;
  session.alloc.owner = &session;
  session.start_time = 100;
  strcpy((char *)session.username, "test");
}
void tearDown(void) {}

static void test_peer_usage_preserves_64_bit_counters(void) {
  session.peer_received_packets = big + 1;
  session.peer_received_bytes = big + 2;
  session.peer_sent_packets = big + 3;
  session.peer_sent_bytes = big + 4;
  session.t_peer_received_packets = big;
  session.t_peer_received_bytes = big;
  session.t_peer_sent_packets = big;
  session.t_peer_sent_bytes = big;
  session.t_received_bytes = big + 5;
  session.t_sent_bytes = big + 6;

  turn_report_session_usage(&session, 1);

  TEST_ASSERT_EQUAL_STRING("rcvp=4294967297, rcvb=4294967298, sentp=4294967299, sentb=4294967300", peer_traffic);
  TEST_ASSERT_NOT_NULL(strstr(peer_log, "rp=4294967297, rb=4294967298, sp=4294967299, sb=4294967300"));
  TEST_ASSERT_EQUAL_UINT64(2 * big + 1, session.t_peer_received_packets);
  TEST_ASSERT_EQUAL_UINT64(2 * big + 2, session.t_peer_received_bytes);
  TEST_ASSERT_EQUAL_UINT64(2 * big + 3, session.t_peer_sent_packets);
  TEST_ASSERT_EQUAL_UINT64(2 * big + 4, session.t_peer_sent_bytes);
  TEST_ASSERT_EQUAL_UINT32((2 * big + 2) / 10, session.peer_received_rate);
  TEST_ASSERT_EQUAL_UINT32((2 * big + 4) / 10, session.peer_sent_rate);
  TEST_ASSERT_EQUAL_UINT32((2 * big + 2) / 10 + (2 * big + 4) / 10, session.peer_total_rate);
  TEST_ASSERT_EQUAL_UINT32((big + 5) / 10, session.received_rate);
  TEST_ASSERT_EQUAL_UINT32((big + 6) / 10, session.sent_rate);
  TEST_ASSERT_EQUAL_UINT32((big + 5) / 10 + (big + 6) / 10, session.total_rate);
  TEST_ASSERT_EQUAL_UINT64(0, session.peer_received_packets);
  TEST_ASSERT_EQUAL_UINT64(0, session.peer_received_bytes);
  TEST_ASSERT_EQUAL_UINT64(0, session.peer_sent_packets);
  TEST_ASSERT_EQUAL_UINT64(0, session.peer_sent_bytes);

  /* A second interval adds to, rather than replacing or truncating, totals. */
  session.peer_received_packets = 1;
  session.peer_received_bytes = 2;
  session.peer_sent_packets = 3;
  session.peer_sent_bytes = 4;
  turn_report_session_usage(&session, 1);
  TEST_ASSERT_EQUAL_UINT64(2 * big + 2, session.t_peer_received_packets);
  TEST_ASSERT_EQUAL_UINT64(2 * big + 4, session.t_peer_received_bytes);
  TEST_ASSERT_EQUAL_UINT64(2 * big + 6, session.t_peer_sent_packets);
  TEST_ASSERT_EQUAL_UINT64(2 * big + 8, session.t_peer_sent_bytes);
}

static void check_finished_traffic(void) {
  session.t_received_packets = big + 1;
  session.t_received_bytes = big + 2;
  session.t_sent_packets = big + 3;
  session.t_sent_bytes = big + 4;
  session.t_peer_received_packets = 2 * big + 1;
  session.t_peer_received_bytes = 2 * big + 2;
  session.t_peer_sent_packets = 2 * big + 3;
  session.t_peer_sent_bytes = 2 * big + 4;

  turn_report_allocation_delete(&session.alloc, UDP_SOCKET);

  TEST_ASSERT_EQUAL_STRING("rcvp=4294967297, rcvb=4294967298, sentp=4294967299, sentb=4294967300", client_total);
  TEST_ASSERT_EQUAL_STRING("rcvp=8589934593, rcvb=8589934594, sentp=8589934595, sentb=8589934596", peer_total);
  TEST_ASSERT_EQUAL_UINT(2, prom_calls);
  for (unsigned int i = 0; i < 4; ++i) {
    TEST_ASSERT_EQUAL_UINT64(big + i + 1, prom_values[0][i]);
    TEST_ASSERT_EQUAL_UINT64(2 * big + i + 1, prom_values[1][i]);
  }
}
static void test_finished_traffic_without_realm(void) { check_finished_traffic(); }
static void test_finished_traffic_with_realm(void) {
  strcpy(session.realm_options.name, "example.org");
  check_finished_traffic();
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_peer_usage_preserves_64_bit_counters);
  RUN_TEST(test_finished_traffic_without_realm);
  RUN_TEST(test_finished_traffic_with_realm);
  return UNITY_END();
}
