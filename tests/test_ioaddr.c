#include "ns_turn_ioaddr.h"

#include <unity.h>

#include <arpa/inet.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_make_ioa_addr_ipv4_sets_family_and_port(void) {
  ioa_addr addr = {0};
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"127.0.0.1", 3478, &addr));
  TEST_ASSERT_EQUAL_INT(AF_INET, addr.ss.sa_family);
  TEST_ASSERT_EQUAL_UINT16(3478, addr_get_port(&addr));
}

static void test_make_ioa_addr_ipv6_sets_family_and_port(void) {
  ioa_addr addr = {0};
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"::1", 5349, &addr));
  TEST_ASSERT_EQUAL_INT(AF_INET6, addr.ss.sa_family);
  TEST_ASSERT_EQUAL_UINT16(5349, addr_get_port(&addr));
}

static void test_make_ioa_addr_rejects_garbage(void) {
  ioa_addr addr = {0};
  TEST_ASSERT_NOT_EQUAL(0, make_ioa_addr((const uint8_t *)"not-an-address", 1234, &addr));
}

static void test_addr_set_port_max_value_roundtrips(void) {
  ioa_addr addr = {0};
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"127.0.0.1", 0, &addr));
  addr_set_port(&addr, 65535);
  TEST_ASSERT_EQUAL_UINT16(65535, addr_get_port(&addr));
}

static void test_addr_eq_distinguishes_ports(void) {
  ioa_addr a = {0}, b = {0};
  make_ioa_addr((const uint8_t *)"10.0.0.1", 1000, &a);
  make_ioa_addr((const uint8_t *)"10.0.0.1", 1001, &b);
  TEST_ASSERT_FALSE(addr_eq(&a, &b));
  TEST_ASSERT_TRUE(addr_eq_no_port(&a, &b));
}

static void test_addr_to_string_roundtrip_ipv4(void) {
  ioa_addr addr = {0};
  char buf[MAX_IOA_ADDR_STRING] = {0};
  make_ioa_addr((const uint8_t *)"192.168.1.42", 8080, &addr);
  TEST_ASSERT_EQUAL_INT(0, addr_to_string(&addr, buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "192.168.1.42"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "8080"));
}

static void test_is_loopback_ipv4(void) {
  ioa_addr addr = {0};
  make_ioa_addr((const uint8_t *)"127.0.0.1", 3478, &addr);
  TEST_ASSERT_TRUE(ioa_addr_is_loopback(&addr));
}

static void test_is_loopback_ipv6(void) {
  ioa_addr addr = {0};
  make_ioa_addr((const uint8_t *)"::1", 3478, &addr);
  TEST_ASSERT_TRUE(ioa_addr_is_loopback(&addr));
}

/* Regression for GHSA-w4hf-cr3w-6h79: the IPv4-mapped form of 127.0.0.1 must be
 * classified as loopback, otherwise the default loopback peer guard is bypassed. */
static void test_is_loopback_mapped_ipv4_loopback(void) {
  ioa_addr addr = {0};
  make_ioa_addr((const uint8_t *)"::ffff:127.0.0.1", 3478, &addr);
  TEST_ASSERT_TRUE(ioa_addr_is_loopback(&addr));
}

static void test_is_loopback_mapped_ipv4_loopback_other(void) {
  ioa_addr addr = {0};
  make_ioa_addr((const uint8_t *)"::ffff:127.0.0.2", 3478, &addr);
  TEST_ASSERT_TRUE(ioa_addr_is_loopback(&addr));
}

static void test_is_loopback_non_loopback(void) {
  ioa_addr addr = {0};
  make_ioa_addr((const uint8_t *)"8.8.8.8", 3478, &addr);
  TEST_ASSERT_FALSE(ioa_addr_is_loopback(&addr));
}

static void test_is_loopback_mapped_non_loopback(void) {
  ioa_addr addr = {0};
  make_ioa_addr((const uint8_t *)"::ffff:8.8.8.8", 3478, &addr);
  TEST_ASSERT_FALSE(ioa_addr_is_loopback(&addr));
}

/* The mapped any-address is not loopback but must still be caught by the zero guard. */
static void test_is_zero_mapped_any(void) {
  ioa_addr addr = {0};
  make_ioa_addr((const uint8_t *)"::ffff:0.0.0.0", 3478, &addr);
  TEST_ASSERT_FALSE(ioa_addr_is_loopback(&addr));
  TEST_ASSERT_TRUE(ioa_addr_is_zero(&addr));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_make_ioa_addr_ipv4_sets_family_and_port);
  RUN_TEST(test_make_ioa_addr_ipv6_sets_family_and_port);
  RUN_TEST(test_make_ioa_addr_rejects_garbage);
  RUN_TEST(test_addr_set_port_max_value_roundtrips);
  RUN_TEST(test_addr_eq_distinguishes_ports);
  RUN_TEST(test_addr_to_string_roundtrip_ipv4);
  RUN_TEST(test_is_loopback_ipv4);
  RUN_TEST(test_is_loopback_ipv6);
  RUN_TEST(test_is_loopback_mapped_ipv4_loopback);
  RUN_TEST(test_is_loopback_mapped_ipv4_loopback_other);
  RUN_TEST(test_is_loopback_non_loopback);
  RUN_TEST(test_is_loopback_mapped_non_loopback);
  RUN_TEST(test_is_zero_mapped_any);
  return UNITY_END();
}
