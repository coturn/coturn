/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Regression tests for the alternate-server list management in
 * src/apps/relay/netengine.c (add_alt_server / del_alt_server).
 *
 * The main regression pinned here is #1988: del_alt_server used to call
 * turn_malloc(sizeof(ioa_addr) * (list->size - 1)) when removing an entry.
 * With a single-entry list that is turn_malloc(0), which returns NULL for a
 * zero-size request, and the subsequent `if (!new_addrs) return;` bailed out
 * with list->m still locked and the entry still present. Every later
 * add/del/set_alternate_server on the same list then blocked forever. The fix
 * only allocates when more than one entry survives, so removing the last
 * entry must leave an empty list AND an unlocked mutex.
 *
 * netengine.c is compiled into this test translation unit (the same pattern
 * test_redis_format.c uses for hiredis_libevent2.c) so the tests can drive the
 * static add_alt_server/del_alt_server directly on a local list; the rest of
 * the relay symbols it references are satisfied by test_alt_server_stubs.c.
 */

#include <unity.h>

#include <pthread.h>
#include <string.h>

#include "netengine.c"

/* mainrelay.c normally defines this; in the test we own it. The tests below
 * operate on a local list, so a zeroed instance is enough. */
turn_params_t turn_params;

static turn_server_addrs_list_t list;

void setUp(void) {
  memset(&list, 0, sizeof(list));
  TEST_ASSERT_EQUAL_INT(0, TURN_MUTEX_INIT(&list.m));
}

void tearDown(void) {
  free(list.addrs);
  list.addrs = NULL;
  list.size = 0;
  TURN_MUTEX_DESTROY(&list.m);
}

/* 0 = mutex was free (and is re-released here); non-zero = still locked. */
static int trylock_result(turn_server_addrs_list_t *l) {
  int r = pthread_mutex_trylock((pthread_mutex_t *)l->m.mutex);
  if (r == 0) {
    pthread_mutex_unlock((pthread_mutex_t *)l->m.mutex);
  }
  return r;
}

static void expect_addr(const char *saddr, const ioa_addr *got) {
  ioa_addr want;
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr_from_full_string((const uint8_t *)saddr, 3478, &want));
  TEST_ASSERT_TRUE(addr_eq(&want, got));
}

/* The #1988 regression: removing the only entry must empty the list and
 * release the mutex instead of bailing out with it held. */
static void test_del_last_entry_empties_list_and_releases_mutex(void) {
  add_alt_server("1.2.3.4:3478", 3478, &list);
  TEST_ASSERT_EQUAL_size_t(1, list.size);

  del_alt_server("1.2.3.4:3478", 3478, &list);

  TEST_ASSERT_EQUAL_size_t(0, list.size);
  TEST_ASSERT_NULL(list.addrs);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, trylock_result(&list),
                                "del_alt_server returned with the list mutex still locked (#1988)");
}

/* After draining the list, it must still be usable: the old code left the
 * mutex locked, so this add would deadlock. */
static void test_list_usable_after_removing_last_entry(void) {
  add_alt_server("1.2.3.4:3478", 3478, &list);
  del_alt_server("1.2.3.4:3478", 3478, &list);

  add_alt_server("5.6.7.8:9999", 3478, &list);
  TEST_ASSERT_EQUAL_size_t(1, list.size);
  expect_addr("5.6.7.8:9999", &list.addrs[0]);
  TEST_ASSERT_EQUAL_INT(0, trylock_result(&list));
}

/* Drain a multi-entry list one entry at a time down to zero; the last del
 * takes the same size==1 path as the single-entry case. */
static void test_drain_multi_entry_list_to_zero(void) {
  add_alt_server("1.1.1.1:1111", 3478, &list);
  add_alt_server("2.2.2.2:2222", 3478, &list);
  add_alt_server("3.3.3.3:3333", 3478, &list);
  TEST_ASSERT_EQUAL_size_t(3, list.size);

  del_alt_server("2.2.2.2:2222", 3478, &list);
  TEST_ASSERT_EQUAL_size_t(2, list.size);
  expect_addr("1.1.1.1:1111", &list.addrs[0]);
  expect_addr("3.3.3.3:3333", &list.addrs[1]);

  del_alt_server("1.1.1.1:1111", 3478, &list);
  TEST_ASSERT_EQUAL_size_t(1, list.size);
  expect_addr("3.3.3.3:3333", &list.addrs[0]);

  del_alt_server("3.3.3.3:3333", 3478, &list);
  TEST_ASSERT_EQUAL_size_t(0, list.size);
  TEST_ASSERT_NULL(list.addrs);
  TEST_ASSERT_EQUAL_INT(0, trylock_result(&list));
}

/* Removing an address that is not in the list must not modify it. */
static void test_del_missing_entry_is_a_noop(void) {
  add_alt_server("1.2.3.4:3478", 3478, &list);

  del_alt_server("9.9.9.9:3478", 3478, &list);

  TEST_ASSERT_EQUAL_size_t(1, list.size);
  expect_addr("1.2.3.4:3478", &list.addrs[0]);
  TEST_ASSERT_EQUAL_INT(0, trylock_result(&list));
}

/* Same host, different port is a different alternate server. */
static void test_del_matches_port_too(void) {
  add_alt_server("1.2.3.4:1111", 3478, &list);

  del_alt_server("1.2.3.4:2222", 3478, &list);
  TEST_ASSERT_EQUAL_size_t(1, list.size);

  del_alt_server("1.2.3.4:1111", 3478, &list);
  TEST_ASSERT_EQUAL_size_t(0, list.size);
  TEST_ASSERT_EQUAL_INT(0, trylock_result(&list));
}

/* A malformed address must be rejected without touching the list and without
 * keeping the mutex (this path logs and falls through to the unlock). */
static void test_del_bad_address_releases_mutex(void) {
  add_alt_server("1.2.3.4:3478", 3478, &list);

  del_alt_server("not-an-address::::", 3478, &list);

  TEST_ASSERT_EQUAL_size_t(1, list.size);
  TEST_ASSERT_EQUAL_INT(0, trylock_result(&list));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_del_last_entry_empties_list_and_releases_mutex);
  RUN_TEST(test_list_usable_after_removing_last_entry);
  RUN_TEST(test_drain_multi_entry_list_to_zero);
  RUN_TEST(test_del_missing_entry_is_a_noop);
  RUN_TEST(test_del_matches_port_too);
  RUN_TEST(test_del_bad_address_releases_mutex);
  return UNITY_END();
}
