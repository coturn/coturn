/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * The multiplex-peer demux table is shared by every session on a relay thread
 * and is keyed by exact peer IP:port, so one permitted peer IP covers 65535
 * distinct keys. Registrations must stay within the per-session limit, and
 * deregistration must not walk entries belonging to other sessions.
 */

#include "mp_peer_table.h"

#include "ns_turn_utils.h"

#include <unity.h>

#include <stdio.h>

static void *const SESSION_A = (void *)0x1000;
static void *const SESSION_B = (void *)0x2000;

static mp_peer_table table;

static ioa_addr peer(const char *ip, uint16_t port) {
  ioa_addr addr = {0};
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)ip, port, &addr));
  return addr;
}

void setUp(void) { mp_peer_table_init(&table, 0); }

void tearDown(void) { mp_peer_table_clean(&table); }

static void test_register_and_lookup(void) {
  ioa_addr p = peer("203.0.113.7", 5000);

  TEST_ASSERT_EQUAL_INT(MP_REGISTER_OK, mp_peer_table_register(&table, &p, SESSION_A));
  TEST_ASSERT_EQUAL_PTR(SESSION_A, mp_peer_table_lookup(&table, &p));
  TEST_ASSERT_EQUAL_size_t(1, mp_peer_table_count(&table));

  /* Re-registering the same endpoint is idempotent, not a second entry. */
  TEST_ASSERT_EQUAL_INT(MP_REGISTER_OK, mp_peer_table_register(&table, &p, SESSION_A));
  TEST_ASSERT_EQUAL_size_t(1, mp_peer_table_count(&table));

  ioa_addr other = peer("203.0.113.7", 5001);
  TEST_ASSERT_NULL(mp_peer_table_lookup(&table, &other));
}

static void test_endpoint_owned_by_another_session_conflicts(void) {
  ioa_addr p = peer("203.0.113.7", 5000);

  TEST_ASSERT_EQUAL_INT(MP_REGISTER_OK, mp_peer_table_register(&table, &p, SESSION_A));
  TEST_ASSERT_EQUAL_INT(MP_REGISTER_CONFLICT, mp_peer_table_register(&table, &p, SESSION_B));

  TEST_ASSERT_EQUAL_PTR(SESSION_A, mp_peer_table_lookup(&table, &p));
  TEST_ASSERT_EQUAL_size_t(1, mp_peer_table_count(&table));
  TEST_ASSERT_EQUAL_size_t(0, mp_peer_table_session_count(&table, SESSION_B));
}

/* One permitted peer IP, a fresh port per SEND indication: growth must stop
 * at the per-session limit. */
static void test_port_flood_is_capped_per_session(void) {
  mp_peer_table_clean(&table);
  mp_peer_table_init(&table, 64);

  size_t accepted = 0;
  size_t refused = 0;
  for (unsigned int port = 1024; port < 1024 + 4096; ++port) {
    ioa_addr p = peer("203.0.113.7", (uint16_t)port);
    if (mp_peer_table_register(&table, &p, SESSION_A) == MP_REGISTER_OK) {
      ++accepted;
    } else {
      ++refused;
    }
  }

  TEST_ASSERT_EQUAL_size_t(64, accepted);
  TEST_ASSERT_EQUAL_size_t(4096 - 64, refused);
  TEST_ASSERT_EQUAL_size_t(64, mp_peer_table_count(&table));
  TEST_ASSERT_EQUAL_size_t(64, mp_peer_table_session_count(&table, SESSION_A));
}

static void test_limit_is_per_session_not_global(void) {
  mp_peer_table_clean(&table);
  mp_peer_table_init(&table, 4);

  for (unsigned int port = 1024; port < 1032; ++port) {
    ioa_addr p = peer("203.0.113.7", (uint16_t)port);
    mp_peer_table_register(&table, &p, SESSION_A);
  }
  TEST_ASSERT_EQUAL_size_t(4, mp_peer_table_session_count(&table, SESSION_A));

  ioa_addr p = peer("198.51.100.4", 6000);
  TEST_ASSERT_EQUAL_INT(MP_REGISTER_OK, mp_peer_table_register(&table, &p, SESSION_B));
  TEST_ASSERT_EQUAL_PTR(SESSION_B, mp_peer_table_lookup(&table, &p));
}

static void test_freed_slots_are_reusable(void) {
  mp_peer_table_clean(&table);
  mp_peer_table_init(&table, 2);

  ioa_addr p1 = peer("203.0.113.7", 5000);
  ioa_addr p2 = peer("203.0.113.7", 5001);
  ioa_addr p3 = peer("203.0.113.7", 5002);

  TEST_ASSERT_EQUAL_INT(MP_REGISTER_OK, mp_peer_table_register(&table, &p1, SESSION_A));
  TEST_ASSERT_EQUAL_INT(MP_REGISTER_OK, mp_peer_table_register(&table, &p2, SESSION_A));
  TEST_ASSERT_EQUAL_INT(MP_REGISTER_LIMIT, mp_peer_table_register(&table, &p3, SESSION_A));

  mp_peer_table_deregister(&table, &p1, SESSION_A);
  TEST_ASSERT_NULL(mp_peer_table_lookup(&table, &p1));
  TEST_ASSERT_EQUAL_INT(MP_REGISTER_OK, mp_peer_table_register(&table, &p3, SESSION_A));
  TEST_ASSERT_EQUAL_size_t(2, mp_peer_table_count(&table));
}

/* Permission expiry drops every port of that peer IP, and nothing else. */
static void test_deregister_ip_drops_only_that_ip_of_that_session(void) {
  ioa_addr a1 = peer("203.0.113.7", 5000);
  ioa_addr a2 = peer("203.0.113.7", 5001);
  ioa_addr a3 = peer("198.51.100.4", 5000);
  ioa_addr b1 = peer("203.0.113.7", 6000);

  mp_peer_table_register(&table, &a1, SESSION_A);
  mp_peer_table_register(&table, &a2, SESSION_A);
  mp_peer_table_register(&table, &a3, SESSION_A);
  mp_peer_table_register(&table, &b1, SESSION_B);

  mp_peer_table_deregister_ip(&table, &a1, SESSION_A);

  TEST_ASSERT_NULL(mp_peer_table_lookup(&table, &a1));
  TEST_ASSERT_NULL(mp_peer_table_lookup(&table, &a2));
  TEST_ASSERT_EQUAL_PTR(SESSION_A, mp_peer_table_lookup(&table, &a3));
  TEST_ASSERT_EQUAL_PTR(SESSION_B, mp_peer_table_lookup(&table, &b1));
  TEST_ASSERT_EQUAL_size_t(2, mp_peer_table_count(&table));
}

static void test_deregister_session_honours_address_family(void) {
  ioa_addr v4 = peer("203.0.113.7", 5000);
  ioa_addr v6 = peer("2001:db8::1", 5000);

  mp_peer_table_register(&table, &v4, SESSION_A);
  mp_peer_table_register(&table, &v6, SESSION_A);

  mp_peer_table_deregister_session(&table, SESSION_A, AF_INET);
  TEST_ASSERT_NULL(mp_peer_table_lookup(&table, &v4));
  TEST_ASSERT_EQUAL_PTR(SESSION_A, mp_peer_table_lookup(&table, &v6));

  mp_peer_table_deregister_session(&table, SESSION_A, 0);
  TEST_ASSERT_NULL(mp_peer_table_lookup(&table, &v6));
  TEST_ASSERT_EQUAL_size_t(0, mp_peer_table_count(&table));
}

/* Deregistration must cost the session's own endpoints, not the size of the
 * table every other session on the thread shares with it. */
static void test_deregistration_does_not_scan_foreign_entries(void) {
  for (unsigned int port = 1024; port < 1024 + 200; ++port) {
    ioa_addr noise = peer("198.51.100.4", (uint16_t)port);
    TEST_ASSERT_EQUAL_INT(MP_REGISTER_OK, mp_peer_table_register(&table, &noise, SESSION_B));
  }

  ioa_addr own1 = peer("203.0.113.7", 5000);
  ioa_addr own2 = peer("203.0.113.7", 5001);
  ioa_addr own3 = peer("192.0.2.9", 7000);
  mp_peer_table_register(&table, &own1, SESSION_A);
  mp_peer_table_register(&table, &own2, SESSION_A);
  mp_peer_table_register(&table, &own3, SESSION_A);

  table.deregister_ops = 0;
  mp_peer_table_deregister_ip(&table, &own1, SESSION_A);
  TEST_ASSERT_EQUAL_size_t(201, mp_peer_table_count(&table));
  TEST_ASSERT_TRUE(table.deregister_ops <= 6);

  table.deregister_ops = 0;
  mp_peer_table_deregister_session(&table, SESSION_A, 0);
  TEST_ASSERT_TRUE(table.deregister_ops <= 2);

  TEST_ASSERT_EQUAL_size_t(200, mp_peer_table_count(&table));
  TEST_ASSERT_EQUAL_size_t(200, mp_peer_table_session_count(&table, SESSION_B));
}

int main(void) {
  /* The limit warning must not spill a log file into the build environment. */
  set_logfile("stdout");

  UNITY_BEGIN();
  RUN_TEST(test_register_and_lookup);
  RUN_TEST(test_endpoint_owned_by_another_session_conflicts);
  RUN_TEST(test_port_flood_is_capped_per_session);
  RUN_TEST(test_limit_is_per_session_not_global);
  RUN_TEST(test_freed_slots_are_reusable);
  RUN_TEST(test_deregister_ip_drops_only_that_ip_of_that_session);
  RUN_TEST(test_deregister_session_honours_address_family);
  RUN_TEST(test_deregistration_does_not_scan_foreign_entries);
  return UNITY_END();
}
