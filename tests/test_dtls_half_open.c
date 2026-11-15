#include "turn_dtls_half_open.h"

#include <unity.h>

#include <stdio.h>

void setUp(void) { turn_dtls_half_open_reset(); }
void tearDown(void) {}

static void make_v4(const char *ip, uint16_t port, ioa_addr *addr) {
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)ip, port, addr));
}

static void make_v6(const char *ip, uint16_t port, ioa_addr *addr) {
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)ip, port, addr));
}

static void test_try_inc_succeeds_under_global_cap(void) {
  ioa_addr a = {0};
  make_v4("203.0.113.10", 40000, &a);

  TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(8u, &a));
  TEST_ASSERT_EQUAL_UINT32(1u, turn_dtls_half_open_count());
}

static void test_try_inc_rejects_at_global_cap(void) {
  ioa_addr a = {0};
  ioa_addr b = {0};
  make_v4("203.0.113.10", 40000, &a);
  make_v4("203.0.113.11", 40001, &b);

  TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(1u, &a));
  TEST_ASSERT_FALSE(turn_dtls_half_open_try_inc(1u, &b));
  TEST_ASSERT_EQUAL_UINT32(1u, turn_dtls_half_open_count());
}

static void test_per_source_cap_blocks_same_ip(void) {
  ioa_addr a = {0};
  make_v4("198.51.100.7", 50000, &a);

  for (uint32_t i = 0; i < TURN_DTLS_HALF_OPEN_PER_SOURCE; i++) {
    TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(64u, &a));
  }
  TEST_ASSERT_FALSE(turn_dtls_half_open_try_inc(64u, &a));
  TEST_ASSERT_EQUAL_UINT32(TURN_DTLS_HALF_OPEN_PER_SOURCE, turn_dtls_half_open_count());
}

static void test_port_rotation_shares_per_source_budget(void) {
  ioa_addr ports[TURN_DTLS_HALF_OPEN_PER_SOURCE + 1] = {{0}};

  for (uint32_t i = 0; i < TURN_DTLS_HALF_OPEN_PER_SOURCE + 1; i++) {
    make_v4("198.51.100.8", (uint16_t)(40000u + i), &ports[i]);
  }

  for (uint32_t i = 0; i < TURN_DTLS_HALF_OPEN_PER_SOURCE; i++) {
    TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(64u, &ports[i]));
  }
  /* Same IP, new source port: still counts against the per-source share. */
  TEST_ASSERT_FALSE(turn_dtls_half_open_try_inc(64u, &ports[TURN_DTLS_HALF_OPEN_PER_SOURCE]));
  TEST_ASSERT_EQUAL_UINT32(TURN_DTLS_HALF_OPEN_PER_SOURCE, turn_dtls_half_open_count());
}

static void test_distinct_ipv4_sources_share_global_only(void) {
  char ip[32] = {0};
  uint32_t reserved = 0;

  for (unsigned int host = 1; host <= 16 && reserved < 8; host++) {
    ioa_addr a = {0};
    snprintf(ip, sizeof(ip), "203.0.113.%u", host);
    make_v4(ip, 3478, &a);
    if (turn_dtls_half_open_try_inc(8u, &a)) {
      reserved++;
    }
  }

  TEST_ASSERT_EQUAL_UINT32(8u, reserved);
  TEST_ASSERT_EQUAL_UINT32(8u, turn_dtls_half_open_count());

  ioa_addr extra = {0};
  make_v4("203.0.113.99", 3478, &extra);
  TEST_ASSERT_FALSE(turn_dtls_half_open_try_inc(8u, &extra));
}

static void test_dec_releases_global_and_per_source(void) {
  ioa_addr a = {0};
  make_v4("203.0.113.20", 40000, &a);

  for (uint32_t i = 0; i < TURN_DTLS_HALF_OPEN_PER_SOURCE; i++) {
    TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(64u, &a));
  }
  TEST_ASSERT_FALSE(turn_dtls_half_open_try_inc(64u, &a));

  turn_dtls_half_open_dec(&a);
  TEST_ASSERT_EQUAL_UINT32(TURN_DTLS_HALF_OPEN_PER_SOURCE - 1u, turn_dtls_half_open_count());
  TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(64u, &a));
  TEST_ASSERT_EQUAL_UINT32(TURN_DTLS_HALF_OPEN_PER_SOURCE, turn_dtls_half_open_count());
}

static void test_dec_on_empty_is_noop(void) {
  ioa_addr a = {0};
  make_v4("203.0.113.21", 40000, &a);

  turn_dtls_half_open_dec(&a);
  TEST_ASSERT_EQUAL_UINT32(0u, turn_dtls_half_open_count());
}

static void test_ipv6_same_64_shares_budget(void) {
  ioa_addr a = {0};
  ioa_addr b = {0};
  /* Same /64, different interface IDs. */
  make_v6("2001:db8:1:2::1", 40000, &a);
  make_v6("2001:db8:1:2::99", 40001, &b);

  for (uint32_t i = 0; i < TURN_DTLS_HALF_OPEN_PER_SOURCE; i++) {
    TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(64u, &a));
  }
  TEST_ASSERT_FALSE(turn_dtls_half_open_try_inc(64u, &b));
  TEST_ASSERT_EQUAL_UINT32(TURN_DTLS_HALF_OPEN_PER_SOURCE, turn_dtls_half_open_count());
}

static void test_ipv6_different_64_independent(void) {
  ioa_addr a = {0};
  ioa_addr b = {0};
  make_v6("2001:db8:1:2::1", 40000, &a);
  make_v6("2001:db8:1:3::1", 40000, &b);

  for (uint32_t i = 0; i < TURN_DTLS_HALF_OPEN_PER_SOURCE; i++) {
    TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(64u, &a));
  }
  TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(64u, &b));
  TEST_ASSERT_EQUAL_UINT32(TURN_DTLS_HALF_OPEN_PER_SOURCE + 1u, turn_dtls_half_open_count());
}

static void test_global_reject_rolls_back_per_source(void) {
  ioa_addr a = {0};
  ioa_addr b = {0};
  make_v4("203.0.113.30", 40000, &a);
  make_v4("203.0.113.31", 40000, &b);

  TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(1u, &a));
  /* Global full: try_inc must not leave a sticky per-source reservation. */
  TEST_ASSERT_FALSE(turn_dtls_half_open_try_inc(1u, &b));
  TEST_ASSERT_EQUAL_UINT32(1u, turn_dtls_half_open_count());

  turn_dtls_half_open_dec(&a);
  TEST_ASSERT_EQUAL_UINT32(0u, turn_dtls_half_open_count());

  for (uint32_t i = 0; i < TURN_DTLS_HALF_OPEN_PER_SOURCE; i++) {
    TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(64u, &b));
  }
  TEST_ASSERT_FALSE(turn_dtls_half_open_try_inc(64u, &b));
}

static void test_reset_clears_state(void) {
  ioa_addr a = {0};
  make_v4("203.0.113.40", 40000, &a);

  TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(8u, &a));
  TEST_ASSERT_EQUAL_UINT32(1u, turn_dtls_half_open_count());

  turn_dtls_half_open_reset();
  TEST_ASSERT_EQUAL_UINT32(0u, turn_dtls_half_open_count());
  TEST_ASSERT_TRUE(turn_dtls_half_open_try_inc(8u, &a));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_try_inc_succeeds_under_global_cap);
  RUN_TEST(test_try_inc_rejects_at_global_cap);
  RUN_TEST(test_per_source_cap_blocks_same_ip);
  RUN_TEST(test_port_rotation_shares_per_source_budget);
  RUN_TEST(test_distinct_ipv4_sources_share_global_only);
  RUN_TEST(test_dec_releases_global_and_per_source);
  RUN_TEST(test_dec_on_empty_is_noop);
  RUN_TEST(test_ipv6_same_64_shares_budget);
  RUN_TEST(test_ipv6_different_64_independent);
  RUN_TEST(test_global_reject_rolls_back_per_source);
  RUN_TEST(test_reset_clears_state);
  return UNITY_END();
}
