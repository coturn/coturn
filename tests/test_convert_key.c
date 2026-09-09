/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Regression test for convert_string_key_to_binary() in
 * src/apps/relay/dbdrivers/dbdriver.c. The helper decodes 2*sz hex chars from
 * its source string; a source shorter than that must not be read past its
 * terminating NUL. The short-key inputs below are heap-allocated so a read
 * past the string trips AddressSanitizer.
 */

#include "dbdrivers/dbdriver.h" /* convert_string_key_to_binary */
#include "ns_turn_msg.h"        /* hmackey_t, get_hmackey_size, SHATYPE_DEFAULT */

#include <unity.h>

#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* A full-length key still decodes exactly as before. */
static void test_full_length_key_decodes(void) {
  const size_t sz = get_hmackey_size(SHATYPE_DEFAULT); /* 16 */
  char *src = strdup("0011223344556677889900aabbccddee");
  hmackey_t key;
  memset(key, 0xAA, sizeof(key));

  convert_string_key_to_binary(src, key, sz);
  free(src);

  TEST_ASSERT_EQUAL_UINT8(0x00, key[0]);
  TEST_ASSERT_EQUAL_UINT8(0x11, key[1]);
  TEST_ASSERT_EQUAL_UINT8(0xee, key[15]);
}

/* An even-length key shorter than 2*sz must stop at the NUL, not read past the
   heap allocation. */
static void test_short_key_is_not_oob(void) {
  const size_t sz = get_hmackey_size(SHATYPE_DEFAULT); /* 16 */
  /* 4 hex chars decode to 2 key bytes, but sz asks for 32 chars. */
  char *src = strdup("1234");
  hmackey_t key;
  memset(key, 0xAA, sizeof(key));

  convert_string_key_to_binary(src, key, sz);
  free(src);

  TEST_ASSERT_EQUAL_UINT8(0x12, key[0]);
  TEST_ASSERT_EQUAL_UINT8(0x34, key[1]);
  /* Loop stopped at the NUL: the untouched byte keeps its sentinel. */
  TEST_ASSERT_EQUAL_UINT8(0xAA, key[2]);
}

/* An odd-length key ends mid-byte; the second hex char of that byte is the NUL
   terminator, so it must be read as the terminator and not overstepped. */
static void test_odd_length_key_is_not_oob(void) {
  const size_t sz = get_hmackey_size(SHATYPE_DEFAULT); /* 16 */
  /* 3 chars: "12" then '3' followed by the NUL terminator. */
  char *src = strdup("123");
  hmackey_t key;
  memset(key, 0xAA, sizeof(key));

  convert_string_key_to_binary(src, key, sz);
  free(src);

  TEST_ASSERT_EQUAL_UINT8(0x12, key[0]);
  TEST_ASSERT_EQUAL_UINT8(0xAA, key[1]);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_full_length_key_decodes);
  RUN_TEST(test_short_key_is_not_oob);
  RUN_TEST(test_odd_length_key_is_not_oob);
  return UNITY_END();
}
