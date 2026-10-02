/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * MESSAGE-INTEGRITY keyed by an OAuth mac_key (RFC 7635). The expected HMACs
 * are computed directly with OpenSSL, independently of coturn's own helpers,
 * so a regression that changes both signing and checking in the same way is
 * still caught.
 */

#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"

#include <unity.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdint.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* RFC 7635 Appendix B sample mac_key (160 bits). */
static const uint8_t MAC_KEY[SHA1SIZEBYTES] = {'Z', 'k', 's', 'j', 'p', 'w', 'e', 'o', 'i', 'x',
                                               'X', 'm', 'v', 'n', '6', '7', '5', '3', '4', 'm'};

#define TEST_KID ((const uint8_t *)"north")
#define TEST_REALM ((const uint8_t *)"north.gov")
#define TEST_NONCE ((const uint8_t *)"0123456789abcdef")

/* An ALLOCATE carrying USERNAME/NONCE/REALM and a MESSAGE-INTEGRITY whose value
   is HMAC-SHA1 over key[0..key_len) — what an RFC 7635 client sends for key_len 20. */
static void build_request_sealed_by_openssl(uint8_t *buf, size_t *len, const uint8_t *key, int key_len) {
  hmackey_t placeholder = {1};

  *len = 0;
  stun_init_request_str(STUN_METHOD_ALLOCATE, buf, len);
  TEST_ASSERT_TRUE(turn_attr_add_integrity_by_key_len_str(buf, len, TEST_KID, TEST_REALM, placeholder, SHA1SIZEBYTES,
                                                          TEST_NONCE, SHATYPE_SHA1));

  unsigned int mac_len = SHA1SIZEBYTES;
  TEST_ASSERT_NOT_NULL(
      HMAC(EVP_sha1(), key, key_len, buf, *len - 4 - SHA1SIZEBYTES, buf + *len - SHA1SIZEBYTES, &mac_len));
  TEST_ASSERT_EQUAL_UINT(SHA1SIZEBYTES, mac_len);
}

static void key_from(hmackey_t key, const uint8_t *src) {
  memset(key, 0, sizeof(hmackey_t));
  memcpy(key, src, SHA1SIZEBYTES);
}

static void test_oauth_hmackey_size_uses_whole_mac_key_by_default(void) {
  TEST_ASSERT_EQUAL_size_t(SHA1SIZEBYTES, turn_oauth_hmackey_size(SHA1SIZEBYTES, SHATYPE_SHA1, false));
  TEST_ASSERT_EQUAL_size_t(16, turn_oauth_hmackey_size(SHA1SIZEBYTES, SHATYPE_SHA1, true));
  TEST_ASSERT_EQUAL_size_t(32, turn_oauth_hmackey_size(32, SHATYPE_SHA256, false));
  TEST_ASSERT_EQUAL_size_t(32, turn_oauth_hmackey_size(32, SHATYPE_SHA256, true));
}

static void test_rfc7635_client_request_verifies_with_whole_mac_key(void) {
  uint8_t buf[512] = {0};
  size_t len = 0;
  hmackey_t key;
  key_from(key, MAC_KEY);

  build_request_sealed_by_openssl(buf, &len, MAC_KEY, SHA1SIZEBYTES);

  TEST_ASSERT_EQUAL_INT(1, turn_check_message_integrity_by_key_len_str(TURN_CREDENTIALS_LONG_TERM, buf, len, key,
                                                                       SHA1SIZEBYTES, NULL, SHATYPE_SHA1));
  /* The truncated legacy key computes a different HMAC. */
  TEST_ASSERT_EQUAL_INT(0, turn_check_message_integrity_by_key_len_str(TURN_CREDENTIALS_LONG_TERM, buf, len, key, 16,
                                                                       NULL, SHATYPE_SHA1));
}

static void test_legacy_truncated_request_verifies_only_in_legacy_mode(void) {
  uint8_t buf[512] = {0};
  size_t len = 0;
  hmackey_t key;
  key_from(key, MAC_KEY);

  build_request_sealed_by_openssl(buf, &len, MAC_KEY, 16);

  TEST_ASSERT_EQUAL_INT(1, turn_check_message_integrity_by_key_len_str(
                               TURN_CREDENTIALS_LONG_TERM, buf, len, key,
                               turn_oauth_hmackey_size(SHA1SIZEBYTES, SHATYPE_SHA1, true), NULL, SHATYPE_SHA1));
  TEST_ASSERT_EQUAL_INT(0, turn_check_message_integrity_by_key_len_str(
                               TURN_CREDENTIALS_LONG_TERM, buf, len, key,
                               turn_oauth_hmackey_size(SHA1SIZEBYTES, SHATYPE_SHA1, false), NULL, SHATYPE_SHA1));
}

static void test_response_signed_with_whole_mac_key(void) {
  uint8_t buf[512] = {0};
  size_t len = 0;
  hmackey_t key;
  key_from(key, MAC_KEY);
  password_t pwd = {0};

  stun_init_success_response_str(STUN_METHOD_ALLOCATE, buf, &len, NULL);
  TEST_ASSERT_TRUE(turn_attr_add_integrity_key_len_str(TURN_CREDENTIALS_LONG_TERM, buf, &len, key, SHA1SIZEBYTES, pwd,
                                                       SHATYPE_SHA1));

  uint8_t expected[SHA1SIZEBYTES] = {0};
  unsigned int mac_len = SHA1SIZEBYTES;
  TEST_ASSERT_NOT_NULL(HMAC(EVP_sha1(), MAC_KEY, SHA1SIZEBYTES, buf, len - 4 - SHA1SIZEBYTES, expected, &mac_len));
  TEST_ASSERT_EQUAL_MEMORY(expected, buf + len - SHA1SIZEBYTES, SHA1SIZEBYTES);
}

/* A mac_key whose last 4 bytes are zero hashes the same either way (HMAC
   zero-pads short keys), so such keys keep working across the change. */
static void test_zero_tail_mac_key_interoperates_with_both_modes(void) {
  uint8_t zero_tail[SHA1SIZEBYTES] = {0};
  memcpy(zero_tail, MAC_KEY, 16);
  hmackey_t key;
  key_from(key, zero_tail);
  uint8_t buf[512] = {0};
  size_t len = 0;

  build_request_sealed_by_openssl(buf, &len, zero_tail, SHA1SIZEBYTES);

  TEST_ASSERT_EQUAL_INT(1, turn_check_message_integrity_by_key_len_str(TURN_CREDENTIALS_LONG_TERM, buf, len, key,
                                                                       SHA1SIZEBYTES, NULL, SHATYPE_SHA1));
  TEST_ASSERT_EQUAL_INT(1, turn_check_message_integrity_by_key_len_str(TURN_CREDENTIALS_LONG_TERM, buf, len, key, 16,
                                                                       NULL, SHATYPE_SHA1));
}

static void test_out_of_range_key_length_is_rejected(void) {
  uint8_t buf[512] = {0};
  size_t len = 0;
  hmackey_t key;
  key_from(key, MAC_KEY);
  password_t pwd = {0};

  build_request_sealed_by_openssl(buf, &len, MAC_KEY, SHA1SIZEBYTES);
  TEST_ASSERT_EQUAL_INT(-1, turn_check_message_integrity_by_key_len_str(TURN_CREDENTIALS_LONG_TERM, buf, len, key, 0,
                                                                        NULL, SHATYPE_SHA1));
  TEST_ASSERT_EQUAL_INT(-1, turn_check_message_integrity_by_key_len_str(TURN_CREDENTIALS_LONG_TERM, buf, len, key,
                                                                        sizeof(hmackey_t) + 1, NULL, SHATYPE_SHA1));

  len = 0;
  stun_init_success_response_str(STUN_METHOD_ALLOCATE, buf, &len, NULL);
  TEST_ASSERT_FALSE(turn_attr_add_integrity_key_len_str(TURN_CREDENTIALS_LONG_TERM, buf, &len, key,
                                                        sizeof(hmackey_t) + 1, pwd, SHATYPE_SHA1));
}

/* The fixed-size wrappers keep the long-term-credential key size. */
static void test_legacy_wrappers_keep_16_byte_key(void) {
  uint8_t buf[512] = {0};
  size_t len = 0;
  hmackey_t key;
  key_from(key, MAC_KEY);

  build_request_sealed_by_openssl(buf, &len, MAC_KEY, 16);
  TEST_ASSERT_EQUAL_INT(
      1, stun_check_message_integrity_by_key_str(TURN_CREDENTIALS_LONG_TERM, buf, len, key, NULL, SHATYPE_DEFAULT));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_oauth_hmackey_size_uses_whole_mac_key_by_default);
  RUN_TEST(test_rfc7635_client_request_verifies_with_whole_mac_key);
  RUN_TEST(test_legacy_truncated_request_verifies_only_in_legacy_mode);
  RUN_TEST(test_response_signed_with_whole_mac_key);
  RUN_TEST(test_zero_tail_mac_key_interoperates_with_both_modes);
  RUN_TEST(test_out_of_range_key_length_is_rejected);
  RUN_TEST(test_legacy_wrappers_keep_16_byte_key);
  return UNITY_END();
}
