/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * RFC 6062 TCP connections are stored on the allocation by full peer address.
 * Distinct ports on one IP must count, and the cap must still apply after
 * CONNECTION-BIND drops the id from the process-wide map.
 */

#include "ns_turn_allocation.h"
#include "ns_turn_utils.h"

#include <unity.h>

#include <string.h>

void turn_report_allocation_delete(void *a, SOCKET_TYPE socket_type) {
  (void)a;
  (void)socket_type;
}

void delete_ioa_timer(ioa_timer_handle th) { (void)th; }

void close_ioa_socket(ioa_socket_handle s) { (void)s; }

void ioa_network_buffer_delete(ioa_engine_handle e, ioa_network_buffer_handle nbh) {
  (void)e;
  (void)nbh;
}

int get_ioa_socket_address_family(ioa_socket_handle s) {
  (void)s;
  return AF_INET;
}

void clear_ioa_socket_session_if(ioa_socket_handle s, void *ss) {
  (void)s;
  (void)ss;
}

static ur_map *map;
static allocation alloc;

static ioa_addr v4(uint16_t port) {
  ioa_addr addr = {0};
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"203.0.113.10", port, &addr));
  return addr;
}

static ioa_addr v6(uint16_t port) {
  ioa_addr addr = {0};
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"2001:db8::10", port, &addr));
  return addr;
}

static size_t live_count(const allocation *a) {
  size_t n = 0;
  if (!a->tcs.elems) {
    return 0;
  }
  for (size_t i = 0; i < a->tcs.sz; ++i) {
    if (a->tcs.elems[i]) {
      ++n;
    }
  }
  return n;
}

static tcp_connection *add_peer(allocation *a, ioa_addr *peer, int *err) {
  *err = 0;
  return create_tcp_connection(1, a, NULL, peer, err);
}

void setUp(void) {
  map = ur_map_create();
  TEST_ASSERT_NOT_NULL(map);
  init_allocation(NULL, &alloc, map);
}

void tearDown(void) {
  clear_allocation(&alloc, TCP_SOCKET);
  ur_map_free(&map);
}

static void test_distinct_ports_on_one_ip_fill_the_cap(void) {
  for (uint16_t port = 1; port <= TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION; ++port) {
    ioa_addr peer = v4(port);
    int err = 0;
    tcp_connection *tc = add_peer(&alloc, &peer, &err);
    TEST_ASSERT_NOT_NULL(tc);
    TEST_ASSERT_EQUAL_INT(0, err);
  }

  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION, alloc.tcs.sz);
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION, live_count(&alloc));
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION, ur_map_size(map));
}

static void test_one_past_the_cap_is_508_and_does_not_grow(void) {
  test_distinct_ports_on_one_ip_fill_the_cap();

  tcp_connection **elems_before = alloc.tcs.elems;
  ioa_addr extra = v4(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION + 1);
  int err = 0;
  tcp_connection *tc = add_peer(&alloc, &extra, &err);

  TEST_ASSERT_NULL(tc);
  TEST_ASSERT_EQUAL_INT(508, err);
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION, alloc.tcs.sz);
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION, ur_map_size(map));
  TEST_ASSERT_EQUAL_PTR(elems_before, alloc.tcs.elems);
  TEST_ASSERT_NULL(get_tcp_connection_by_peer(&alloc, &extra));
}

static void test_duplicate_at_cap_is_446(void) {
  test_distinct_ports_on_one_ip_fill_the_cap();

  ioa_addr again = v4(1);
  int err = 0;
  tcp_connection *tc = add_peer(&alloc, &again, &err);

  TEST_ASSERT_NULL(tc);
  TEST_ASSERT_EQUAL_INT(446, err);
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION, live_count(&alloc));
}

static void test_cap_holds_after_connection_bind_drops_the_map_entry(void) {
  test_distinct_ports_on_one_ip_fill_the_cap();

  for (size_t i = 0; i < alloc.tcs.sz; ++i) {
    tcp_connection *tc = alloc.tcs.elems[i];
    TEST_ASSERT_NOT_NULL(tc);
    TEST_ASSERT_EQUAL_PTR(tc, get_and_clean_tcp_connection_by_id(map, tc->id));
  }
  TEST_ASSERT_EQUAL_size_t(0, ur_map_size(map));
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION, live_count(&alloc));

  ioa_addr extra = v4(40000);
  int err = 0;
  TEST_ASSERT_NULL(add_peer(&alloc, &extra, &err));
  TEST_ASSERT_EQUAL_INT(508, err);
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION, alloc.tcs.sz);
  TEST_ASSERT_EQUAL_size_t(0, ur_map_size(map));

  ioa_addr again = v4(1);
  err = 0;
  TEST_ASSERT_NULL(add_peer(&alloc, &again, &err));
  TEST_ASSERT_EQUAL_INT(446, err);
}

static void test_delete_reuses_a_hole_without_growing(void) {
  test_distinct_ports_on_one_ip_fill_the_cap();

  tcp_connection *gone = alloc.tcs.elems[3];
  const size_t sz_before = alloc.tcs.sz;
  delete_tcp_connection(gone);
  alloc.tcs.elems[3] = NULL;

  TEST_ASSERT_EQUAL_size_t(sz_before, alloc.tcs.sz);
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION - 1, live_count(&alloc));

  ioa_addr extra = v4(40000);
  int err = 0;
  tcp_connection *tc = add_peer(&alloc, &extra, &err);
  TEST_ASSERT_NOT_NULL(tc);
  TEST_ASSERT_EQUAL_INT(0, err);
  TEST_ASSERT_EQUAL_PTR(tc, alloc.tcs.elems[3]);
  TEST_ASSERT_EQUAL_size_t(sz_before, alloc.tcs.sz);
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION, live_count(&alloc));

  ioa_addr overflow = v4(40001);
  err = 0;
  TEST_ASSERT_NULL(add_peer(&alloc, &overflow, &err));
  TEST_ASSERT_EQUAL_INT(508, err);
}

static void test_same_port_on_another_ip_is_a_different_connection(void) {
  ioa_addr a = v4(9);
  ioa_addr b = {0};
  int err = 0;

  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"203.0.113.11", 9, &b));
  TEST_ASSERT_NOT_NULL(add_peer(&alloc, &a, &err));
  TEST_ASSERT_NOT_NULL(add_peer(&alloc, &b, &err));
  TEST_ASSERT_EQUAL_size_t(2, live_count(&alloc));
}

static void test_ipv6_ports_count_toward_the_same_cap(void) {
  for (uint16_t port = 1; port <= TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION; ++port) {
    ioa_addr peer = v6(port);
    int err = 0;
    TEST_ASSERT_NOT_NULL(add_peer(&alloc, &peer, &err));
  }

  ioa_addr extra = v6(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION + 1);
  int err = 0;
  TEST_ASSERT_NULL(add_peer(&alloc, &extra, &err));
  TEST_ASSERT_EQUAL_INT(508, err);
}

static void test_cap_is_per_allocation(void) {
  allocation other;
  init_allocation(NULL, &other, map);
  test_distinct_ports_on_one_ip_fill_the_cap();

  for (uint16_t port = 1; port <= TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION; ++port) {
    ioa_addr peer = v4(port);
    int err = 0;
    TEST_ASSERT_NOT_NULL(add_peer(&other, &peer, &err));
  }

  ioa_addr extra = v4(40000);
  int err = 0;
  TEST_ASSERT_NULL(add_peer(&alloc, &extra, &err));
  TEST_ASSERT_EQUAL_INT(508, err);
  err = 0;
  TEST_ASSERT_NULL(add_peer(&other, &extra, &err));
  TEST_ASSERT_EQUAL_INT(508, err);
  TEST_ASSERT_EQUAL_size_t(TURN_MAX_TCP_CONNECTIONS_PER_ALLOCATION * 2, ur_map_size(map));

  clear_allocation(&other, TCP_SOCKET);
}

static void test_permission_does_not_bound_distinct_ports(void) {
  ioa_addr perm_addr = v4(0);
  TEST_ASSERT_NOT_NULL(allocation_add_permission(&alloc, &perm_addr));

  test_distinct_ports_on_one_ip_fill_the_cap();

  ioa_addr extra = v4(40000);
  int err = 0;
  TEST_ASSERT_NULL(add_peer(&alloc, &extra, &err));
  TEST_ASSERT_EQUAL_INT(508, err);
}

int main(void) {
  set_logfile("stdout");

  UNITY_BEGIN();
  RUN_TEST(test_distinct_ports_on_one_ip_fill_the_cap);
  RUN_TEST(test_one_past_the_cap_is_508_and_does_not_grow);
  RUN_TEST(test_duplicate_at_cap_is_446);
  RUN_TEST(test_cap_holds_after_connection_bind_drops_the_map_entry);
  RUN_TEST(test_delete_reuses_a_hole_without_growing);
  RUN_TEST(test_same_port_on_another_ip_is_a_different_connection);
  RUN_TEST(test_ipv6_ports_count_toward_the_same_cap);
  RUN_TEST(test_cap_is_per_allocation);
  RUN_TEST(test_permission_does_not_bound_distinct_ports);
  return UNITY_END();
}
