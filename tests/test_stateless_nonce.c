/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Unit tests for turn_compute_stateless_nonce() (issue #1999): the derived
 * challenge nonce must be deterministic for (key, client address, window),
 * distinct across any of those inputs, well-formed for the STUN NONCE
 * attribute, and defensive about bad arguments.
 */

#include "ns_turn_ioaddr.h"
#include "ns_turn_msg.h"

#include <unity.h>

#include <stdint.h>
#include <string.h>

/* Mirrors NONCE_MAX_SIZE in src/server/ns_turn_session.h: 16 hex chars + NUL. */
#define TEST_NONCE_SIZE (17)

void setUp(void) {}
void tearDown(void) {}

static ioa_addr make_addr(const char *ip, uint16_t port) {
  ioa_addr addr;
  memset(&addr, 0, sizeof(addr));
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)ip, port, &addr));
  return addr;
}

static const uint8_t test_key[TURN_STATELESS_NONCE_KEY_SIZE] = "0123456789abcdef0123456789abcde";

static void test_same_inputs_same_nonce(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char n1[TEST_NONCE_SIZE] = {0};
  char n2[TEST_NONCE_SIZE] = {0};

  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1234, n1, sizeof(n1)));
  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1234, n2, sizeof(n2)));
  TEST_ASSERT_EQUAL_STRING(n1, n2);
}

static void test_nonce_is_hex_and_full_length(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char nonce[TEST_NONCE_SIZE] = {0};

  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 42, nonce, sizeof(nonce)));
  TEST_ASSERT_EQUAL_size_t(TEST_NONCE_SIZE - 1, strlen(nonce));
  for (size_t i = 0; i < strlen(nonce); ++i) {
    const char c = nonce[i];
    TEST_ASSERT_TRUE(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')));
  }
}

static void test_different_window_different_nonce(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char n1[TEST_NONCE_SIZE] = {0};
  char n2[TEST_NONCE_SIZE] = {0};

  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1234, n1, sizeof(n1)));
  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1235, n2, sizeof(n2)));
  TEST_ASSERT_TRUE(strcmp(n1, n2) != 0);
}

static void test_different_ip_different_nonce(void) {
  const ioa_addr a1 = make_addr("192.0.2.7", 51000);
  const ioa_addr a2 = make_addr("192.0.2.8", 51000);
  char n1[TEST_NONCE_SIZE] = {0};
  char n2[TEST_NONCE_SIZE] = {0};

  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &a1, 1234, n1, sizeof(n1)));
  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &a2, 1234, n2, sizeof(n2)));
  TEST_ASSERT_TRUE(strcmp(n1, n2) != 0);
}

static void test_different_port_different_nonce(void) {
  const ioa_addr a1 = make_addr("192.0.2.7", 51000);
  const ioa_addr a2 = make_addr("192.0.2.7", 51001);
  char n1[TEST_NONCE_SIZE] = {0};
  char n2[TEST_NONCE_SIZE] = {0};

  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &a1, 1234, n1, sizeof(n1)));
  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &a2, 1234, n2, sizeof(n2)));
  TEST_ASSERT_TRUE(strcmp(n1, n2) != 0);
}

static void test_different_key_different_nonce(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  uint8_t other_key[TURN_STATELESS_NONCE_KEY_SIZE] = {0};
  memset(other_key, 0x5a, sizeof(other_key));
  char n1[TEST_NONCE_SIZE] = {0};
  char n2[TEST_NONCE_SIZE] = {0};

  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1234, n1, sizeof(n1)));
  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(other_key, sizeof(other_key), &addr, 1234, n2, sizeof(n2)));
  TEST_ASSERT_TRUE(strcmp(n1, n2) != 0);
}

static void test_ipv6_address_supported(void) {
  const ioa_addr addr = make_addr("2001:db8::1", 51000);
  char n1[TEST_NONCE_SIZE] = {0};
  char n2[TEST_NONCE_SIZE] = {0};

  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1234, n1, sizeof(n1)));
  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1234, n2, sizeof(n2)));
  TEST_ASSERT_EQUAL_STRING(n1, n2);
  TEST_ASSERT_EQUAL_size_t(TEST_NONCE_SIZE - 1, strlen(n1));
}

static void test_bad_arguments_rejected(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char nonce[TEST_NONCE_SIZE] = {0};

  TEST_ASSERT_FALSE(turn_compute_stateless_nonce(NULL, sizeof(test_key), &addr, 1, nonce, sizeof(nonce)));
  TEST_ASSERT_FALSE(turn_compute_stateless_nonce(test_key, 0, &addr, 1, nonce, sizeof(nonce)));
  TEST_ASSERT_FALSE(turn_compute_stateless_nonce(test_key, sizeof(test_key), NULL, 1, nonce, sizeof(nonce)));
  TEST_ASSERT_FALSE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1, NULL, sizeof(nonce)));
  TEST_ASSERT_FALSE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1, nonce, 1));
  /* Larger than a SHA-256 digest can fill. */
  char big[80] = {0};
  TEST_ASSERT_FALSE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1, big, sizeof(big)));
}

static void test_short_nonce_buffer_truncates_cleanly(void) {
  const ioa_addr addr = make_addr("192.0.2.7", 51000);
  char full[TEST_NONCE_SIZE] = {0};
  char shorter[9] = {0};

  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1234, full, sizeof(full)));
  TEST_ASSERT_TRUE(turn_compute_stateless_nonce(test_key, sizeof(test_key), &addr, 1234, shorter, sizeof(shorter)));
  TEST_ASSERT_EQUAL_size_t(sizeof(shorter) - 1, strlen(shorter));
  /* A shorter derivation is a prefix of the longer one for the same inputs. */
  TEST_ASSERT_EQUAL_INT(0, strncmp(full, shorter, strlen(shorter)));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_same_inputs_same_nonce);
  RUN_TEST(test_nonce_is_hex_and_full_length);
  RUN_TEST(test_different_window_different_nonce);
  RUN_TEST(test_different_ip_different_nonce);
  RUN_TEST(test_different_port_different_nonce);
  RUN_TEST(test_different_key_different_nonce);
  RUN_TEST(test_ipv6_address_supported);
  RUN_TEST(test_bad_arguments_rejected);
  RUN_TEST(test_short_nonce_buffer_truncates_cleanly);
  return UNITY_END();
}
