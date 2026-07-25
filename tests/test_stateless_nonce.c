/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Unit tests for the stateless challenge nonce (issue #1999):
 * turn_generate_stateless_nonce() / turn_check_stateless_nonce(). The nonce is
 * an authenticated timestamp cookie - <8 hex chars issue time> || <16 hex
 * chars truncated HMAC over "<addr>|<ts-hex>"> - so the tests cover the
 * format, determinism, per-input divergence, MAC integrity (any tampering
 * fails), and the freshness rules (max age, bounded future clock skew).
 */

#include "ns_turn_ioaddr.h"
#include "ns_turn_msg.h"

#include <unity.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static ioa_addr make_addr(const char *ip, uint16_t port) {
  ioa_addr addr;
  memset(&addr, 0, sizeof(addr));
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)ip, port, &addr));
  return addr;
}

static const uint8_t test_key[TURN_STATELESS_NONCE_KEY_SIZE] = "0123456789abcdef0123456789abcde";

#define TEST_TS ((uint32_t)0x64c0ffeeu)
#define TEST_LIFETIME ((uint32_t)600)

static void generate_ok(const ioa_addr *addr, uint32_t ts, char nonce[TURN_STATELESS_NONCE_SIZE]) {
  memset(nonce, 0, TURN_STATELESS_NONCE_SIZE);
  TEST_ASSERT_TRUE(
      turn_generate_stateless_nonce(test_key, sizeof(test_key), addr, ts, nonce, TURN_STATELESS_NONCE_SIZE));
}

static void test_format_is_timestamp_then_mac_in_hex(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char nonce[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&addr, TEST_TS, nonce);

  TEST_ASSERT_EQUAL_size_t(TURN_STATELESS_NONCE_LENGTH, strlen(nonce));
  for (size_t i = 0; i < strlen(nonce); ++i) {
    const char c = nonce[i];
    TEST_ASSERT_TRUE(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')));
  }

  char expected_ts[TURN_STATELESS_NONCE_TIMESTAMP_LENGTH + 1] = {0};
  snprintf(expected_ts, sizeof(expected_ts), "%08lx", (unsigned long)TEST_TS);
  TEST_ASSERT_EQUAL_INT(0, strncmp(nonce, expected_ts, TURN_STATELESS_NONCE_TIMESTAMP_LENGTH));
}

static void test_same_inputs_same_nonce(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char n1[TURN_STATELESS_NONCE_SIZE];
  char n2[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&addr, TEST_TS, n1);
  generate_ok(&addr, TEST_TS, n2);
  TEST_ASSERT_EQUAL_STRING(n1, n2);
}

static void test_different_inputs_different_mac(void) {
  const ioa_addr a1 = make_addr("192.0.2.7", 51000);
  const ioa_addr a2 = make_addr("192.0.2.8", 51000);
  const ioa_addr a3 = make_addr("192.0.2.7", 51001);
  uint8_t other_key[TURN_STATELESS_NONCE_KEY_SIZE];
  memset(other_key, 0x5a, sizeof(other_key));

  char base[TURN_STATELESS_NONCE_SIZE];
  char other[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&a1, TEST_TS, base);

  /* Different IP. */
  generate_ok(&a2, TEST_TS, other);
  TEST_ASSERT_TRUE(strcmp(base, other) != 0);

  /* Different port. */
  generate_ok(&a3, TEST_TS, other);
  TEST_ASSERT_TRUE(strcmp(base, other) != 0);

  /* Different timestamp (MAC half must change too, not just the prefix). */
  generate_ok(&a1, TEST_TS + 1, other);
  TEST_ASSERT_TRUE(
      strcmp(base + TURN_STATELESS_NONCE_TIMESTAMP_LENGTH, other + TURN_STATELESS_NONCE_TIMESTAMP_LENGTH) != 0);

  /* Different key. */
  memset(other, 0, sizeof(other));
  TEST_ASSERT_TRUE(turn_generate_stateless_nonce(other_key, sizeof(other_key), &a1, TEST_TS, other, sizeof(other)));
  TEST_ASSERT_TRUE(strcmp(base, other) != 0);
}

static void test_check_accepts_fresh_nonce(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char nonce[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&addr, TEST_TS, nonce);

  uint32_t issued_at = 0;
  TEST_ASSERT_TRUE(
      turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, TEST_LIFETIME, nonce, &issued_at));
  TEST_ASSERT_EQUAL_UINT32(TEST_TS, issued_at);

  /* Still valid at the age limit, with a NULL timestamp out-param. */
  TEST_ASSERT_TRUE(turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS + TEST_LIFETIME, TEST_LIFETIME,
                                              nonce, NULL));
}

static void test_check_rejects_expired_nonce(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char nonce[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&addr, TEST_TS, nonce);

  TEST_ASSERT_FALSE(turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS + TEST_LIFETIME + 1,
                                               TEST_LIFETIME, nonce, NULL));
}

static void test_check_bounds_future_clock_skew(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char nonce[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&addr, TEST_TS, nonce);

  /* A nonce slightly ahead of the validator's clock is accepted... */
  TEST_ASSERT_TRUE(turn_check_stateless_nonce(
      test_key, sizeof(test_key), &addr, TEST_TS - TURN_STATELESS_NONCE_MAX_CLOCK_SKEW, TEST_LIFETIME, nonce, NULL));
  /* ...but not beyond the skew allowance. */
  TEST_ASSERT_FALSE(turn_check_stateless_nonce(test_key, sizeof(test_key), &addr,
                                               TEST_TS - TURN_STATELESS_NONCE_MAX_CLOCK_SKEW - 1, TEST_LIFETIME, nonce,
                                               NULL));
}

static void test_check_rejects_wrong_address_or_key(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  const ioa_addr other_ip = make_addr("192.0.2.8", 51000);
  const ioa_addr other_port = make_addr("192.0.2.7", 51001);
  uint8_t other_key[TURN_STATELESS_NONCE_KEY_SIZE];
  memset(other_key, 0x5a, sizeof(other_key));

  char nonce[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&addr, TEST_TS, nonce);

  TEST_ASSERT_FALSE(
      turn_check_stateless_nonce(test_key, sizeof(test_key), &other_ip, TEST_TS, TEST_LIFETIME, nonce, NULL));
  TEST_ASSERT_FALSE(
      turn_check_stateless_nonce(test_key, sizeof(test_key), &other_port, TEST_TS, TEST_LIFETIME, nonce, NULL));
  TEST_ASSERT_FALSE(
      turn_check_stateless_nonce(other_key, sizeof(other_key), &addr, TEST_TS, TEST_LIFETIME, nonce, NULL));
}

static void test_check_rejects_any_tampered_character(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char nonce[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&addr, TEST_TS, nonce);

  /* Flipping any single character - timestamp half (breaks the MAC binding)
   * or MAC half (breaks the compare) - must invalidate the nonce. */
  for (size_t i = 0; i < TURN_STATELESS_NONCE_LENGTH; ++i) {
    char tampered[TURN_STATELESS_NONCE_SIZE];
    memcpy(tampered, nonce, sizeof(tampered));
    tampered[i] = (tampered[i] == 'a') ? 'b' : 'a';
    TEST_ASSERT_FALSE(
        turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, TEST_LIFETIME, tampered, NULL));
  }
}

static void test_check_rejects_malformed_nonces(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char nonce[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&addr, TEST_TS, nonce);

  /* Too short / too long. */
  char shorter[TURN_STATELESS_NONCE_SIZE];
  memcpy(shorter, nonce, sizeof(shorter));
  shorter[TURN_STATELESS_NONCE_LENGTH - 1] = 0;
  TEST_ASSERT_FALSE(
      turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, TEST_LIFETIME, shorter, NULL));

  char longer[TURN_STATELESS_NONCE_SIZE + 1] = {0};
  memcpy(longer, nonce, TURN_STATELESS_NONCE_LENGTH);
  longer[TURN_STATELESS_NONCE_LENGTH] = '0';
  TEST_ASSERT_FALSE(
      turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, TEST_LIFETIME, longer, NULL));

  /* Non-hex and uppercase-hex characters are rejected outright. */
  char nonhex[TURN_STATELESS_NONCE_SIZE];
  memcpy(nonhex, nonce, sizeof(nonhex));
  nonhex[3] = 'g';
  TEST_ASSERT_FALSE(
      turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, TEST_LIFETIME, nonhex, NULL));
  nonhex[3] = 'A';
  TEST_ASSERT_FALSE(
      turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, TEST_LIFETIME, nonhex, NULL));

  /* Legacy random-style 16-char nonces are not stateless nonces. */
  TEST_ASSERT_FALSE(
      turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, TEST_LIFETIME, "0123456789abcdef", NULL));
}

static void test_ipv6_roundtrip(void) {
  const ioa_addr addr = make_addr("2001:db8::1", 51000);
  char nonce[TURN_STATELESS_NONCE_SIZE];
  generate_ok(&addr, TEST_TS, nonce);

  uint32_t issued_at = 0;
  TEST_ASSERT_TRUE(
      turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS + 5, TEST_LIFETIME, nonce, &issued_at));
  TEST_ASSERT_EQUAL_UINT32(TEST_TS, issued_at);
}

static void test_bad_arguments_rejected(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char nonce[TURN_STATELESS_NONCE_SIZE] = {0};

  TEST_ASSERT_FALSE(turn_generate_stateless_nonce(NULL, sizeof(test_key), &addr, TEST_TS, nonce, sizeof(nonce)));
  TEST_ASSERT_FALSE(turn_generate_stateless_nonce(test_key, 0, &addr, TEST_TS, nonce, sizeof(nonce)));
  TEST_ASSERT_FALSE(turn_generate_stateless_nonce(test_key, sizeof(test_key), NULL, TEST_TS, nonce, sizeof(nonce)));
  TEST_ASSERT_FALSE(turn_generate_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, NULL, sizeof(nonce)));
  /* Undersized output buffer. */
  TEST_ASSERT_FALSE(
      turn_generate_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, nonce, TURN_STATELESS_NONCE_SIZE - 1));

  generate_ok(&addr, TEST_TS, nonce);
  TEST_ASSERT_FALSE(turn_check_stateless_nonce(NULL, sizeof(test_key), &addr, TEST_TS, TEST_LIFETIME, nonce, NULL));
  TEST_ASSERT_FALSE(turn_check_stateless_nonce(test_key, 0, &addr, TEST_TS, TEST_LIFETIME, nonce, NULL));
  TEST_ASSERT_FALSE(turn_check_stateless_nonce(test_key, sizeof(test_key), NULL, TEST_TS, TEST_LIFETIME, nonce, NULL));
  TEST_ASSERT_FALSE(turn_check_stateless_nonce(test_key, sizeof(test_key), &addr, TEST_TS, TEST_LIFETIME, NULL, NULL));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_format_is_timestamp_then_mac_in_hex);
  RUN_TEST(test_same_inputs_same_nonce);
  RUN_TEST(test_different_inputs_different_mac);
  RUN_TEST(test_check_accepts_fresh_nonce);
  RUN_TEST(test_check_rejects_expired_nonce);
  RUN_TEST(test_check_bounds_future_clock_skew);
  RUN_TEST(test_check_rejects_wrong_address_or_key);
  RUN_TEST(test_check_rejects_any_tampered_character);
  RUN_TEST(test_check_rejects_malformed_nonces);
  RUN_TEST(test_ipv6_roundtrip);
  RUN_TEST(test_bad_arguments_rejected);
  return UNITY_END();
}
