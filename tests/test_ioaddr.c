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

/* ---- IPv4-in-IPv6 canonicalization ---- */

static void make_addr(const char *s, ioa_addr *a) {
  memset(a, 0, sizeof(*a));
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)s, 0, a));
}

static void make_v4_range(ioa_addr_range *r, const char *lo, const char *hi) {
  ioa_addr a = {0}, b = {0};
  make_addr(lo, &a);
  make_addr(hi, &b);
  ioa_addr_range_set(r, &a, &b);
}

/* ioa_addr_get_embedded_ipv4 must reduce every IPv4-in-IPv6 encoding of
 * 10.0.0.5 to the bare IPv4, and refuse non-embedding addresses. */
static void test_embedded_ipv4_all_encodings(void) {
  const char *encodings[] = {
      "::ffff:10.0.0.5", /* IPv4-mapped   */
      "::10.0.0.5",      /* IPv4-compat   */
      "2002:a00:5::",    /* 6to4          */
      "64:ff9b::a00:5",  /* NAT64         */
  };
  ioa_addr expected = {0};
  make_addr("10.0.0.5", &expected);
  for (size_t i = 0; i < sizeof(encodings) / sizeof(encodings[0]); ++i) {
    ioa_addr in = {0}, out = {0};
    make_addr(encodings[i], &in);
    TEST_ASSERT_TRUE_MESSAGE(ioa_addr_get_embedded_ipv4(&in, &out), encodings[i]);
    TEST_ASSERT_EQUAL_INT(AF_INET, out.ss.sa_family);
    TEST_ASSERT_TRUE_MESSAGE(addr_eq_no_port(&out, &expected), encodings[i]);
  }
}

static void test_embedded_ipv4_rejects_non_embedding(void) {
  const char *non[] = {"::1", "::", "2001:db8::1", "fc00::1", "8.8.8.8"};
  for (size_t i = 0; i < sizeof(non) / sizeof(non[0]); ++i) {
    ioa_addr in = {0}, out = {0};
    make_addr(non[i], &in);
    TEST_ASSERT_FALSE_MESSAGE(ioa_addr_get_embedded_ipv4(&in, &out), non[i]);
  }
}

/* The core ACL bypass: a denied IPv4 range must match every IPv4-in-IPv6
 * encoding of an address inside it, not just the ::ffff: form. */
static void test_in_range_matches_all_ipv4_in_ipv6_encodings(void) {
  ioa_addr_range denied = {0};
  make_v4_range(&denied, "10.0.0.0", "10.255.255.255");

  const char *encodings[] = {
      "::ffff:10.0.0.5",
      "::10.0.0.5",
      "2002:a00:5::",
      "64:ff9b::a00:5",
  };
  for (size_t i = 0; i < sizeof(encodings) / sizeof(encodings[0]); ++i) {
    ioa_addr peer = {0};
    make_addr(encodings[i], &peer);
    TEST_ASSERT_TRUE_MESSAGE(ioa_addr_in_range(&denied, &peer), encodings[i]);
  }
}

/* A native IPv6 peer with no embedded IPv4 must not spuriously match an IPv4
 * range (no false positives from the canonicalization). */
static void test_in_range_native_ipv6_not_matched_by_ipv4_range(void) {
  ioa_addr_range denied = {0};
  make_v4_range(&denied, "10.0.0.0", "10.255.255.255");
  ioa_addr peer = {0};
  make_addr("2001:db8::a00:5", &peer);
  TEST_ASSERT_FALSE(ioa_addr_in_range(&denied, &peer));
}

/* Loopback must be detected through every IPv4-in-IPv6 encoding of 127.x. */
static void test_is_loopback_all_ipv4_in_ipv6_encodings(void) {
  const char *encodings[] = {
      "::ffff:127.0.0.1",
      "::127.0.0.1",
      "2002:7f00:1::",
      "64:ff9b::7f00:1",
  };
  for (size_t i = 0; i < sizeof(encodings) / sizeof(encodings[0]); ++i) {
    ioa_addr addr = {0};
    make_addr(encodings[i], &addr);
    TEST_ASSERT_TRUE_MESSAGE(ioa_addr_is_loopback(&addr), encodings[i]);
  }
}

/* Multicast and zero must likewise be detected through a non-::ffff: encoding. */
static void test_is_multicast_and_zero_through_nat64(void) {
  ioa_addr mc = {0}, zero = {0};
  make_addr("64:ff9b::e000:1", &mc); /* 224.0.0.1 */
  TEST_ASSERT_TRUE(ioa_addr_is_multicast(&mc));
  make_addr("64:ff9b::0:0", &zero); /* 0.0.0.0 */
  TEST_ASSERT_TRUE(ioa_addr_is_zero(&zero));
}

/* ---- Secure-default internal-scope deny ---- */

static void test_internal_deny_default_flags_internal_scopes(void) {
  const char *internal[] = {
      "169.254.169.254",        /* IPv4 link-local / cloud metadata */
      "169.254.1.1",            /* IPv4 link-local                  */
      "::ffff:169.254.169.254", /* mapped metadata                  */
      "64:ff9b::a9fe:a9fe",     /* NAT64 metadata 169.254.169.254   */
      "fe80::1",                /* IPv6 link-local                  */
      "fc00::1",                /* IPv6 ULA (fc00::/8)              */
      "fd12:3456::99",          /* IPv6 ULA (fd00::/8)              */
      "fec0::1",                /* IPv6 site-local (deprecated)     */
  };
  for (size_t i = 0; i < sizeof(internal) / sizeof(internal[0]); ++i) {
    ioa_addr a = {0};
    make_addr(internal[i], &a);
    TEST_ASSERT_TRUE_MESSAGE(ioa_addr_is_internal_deny_default(&a), internal[i]);
  }
}

/* Loopback and RFC1918 must NOT be flagged here: loopback keeps its own
 * allow-loopback-peers gate, and private ranges stay relayable for legitimate
 * LAN/enterprise TURN deployments. */
static void test_internal_deny_default_allows_other_scopes(void) {
  const char *other[] = {
      "8.8.8.8", "10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1", "::1", "127.0.0.1", "2001:db8::1",
  };
  for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); ++i) {
    ioa_addr a = {0};
    make_addr(other[i], &a);
    TEST_ASSERT_FALSE_MESSAGE(ioa_addr_is_internal_deny_default(&a), other[i]);
  }
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
  RUN_TEST(test_embedded_ipv4_all_encodings);
  RUN_TEST(test_embedded_ipv4_rejects_non_embedding);
  RUN_TEST(test_in_range_matches_all_ipv4_in_ipv6_encodings);
  RUN_TEST(test_in_range_native_ipv6_not_matched_by_ipv4_range);
  RUN_TEST(test_is_loopback_all_ipv4_in_ipv6_encodings);
  RUN_TEST(test_is_multicast_and_zero_through_nat64);
  RUN_TEST(test_internal_deny_default_flags_internal_scopes);
  RUN_TEST(test_internal_deny_default_allows_other_scopes);
  return UNITY_END();
}
