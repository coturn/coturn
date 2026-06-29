#include "apputils.h"

#include <unity.h>

#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_decode_roundtrips_ascii(void) {
  size_t out_len = 0;
  unsigned char *out = base64_decode("Zm9vYmFy", 8, &out_len); /* "foobar" */

  TEST_ASSERT_NOT_NULL(out);
  TEST_ASSERT_EQUAL_size_t(6, out_len);
  TEST_ASSERT_EQUAL_MEMORY("foobar", out, 6);
  free(out);
}

/* Bytes with the high bit set are not valid base64 characters. They must be
   looked up as unsigned indices into the 256-entry decoding table (where they
   map to 0), not sign-extended to a negative offset that reads before it. */
static void test_decode_high_bit_bytes_are_not_oob(void) {
  const char in[4] = {(char)0x80, (char)0xC0, (char)0xFF, (char)0x80};
  size_t out_len = 0;
  unsigned char *out = base64_decode(in, sizeof(in), &out_len);

  TEST_ASSERT_NOT_NULL(out);
  TEST_ASSERT_EQUAL_size_t(3, out_len);
  TEST_ASSERT_EQUAL_UINT8(0, out[0]);
  TEST_ASSERT_EQUAL_UINT8(0, out[1]);
  TEST_ASSERT_EQUAL_UINT8(0, out[2]);
  free(out);
}

static void test_decode_one_padding_char(void) {
  size_t out_len = 0;
  unsigned char *out = base64_decode("Zm8=", 4, &out_len); /* "fo" */

  TEST_ASSERT_NOT_NULL(out);
  TEST_ASSERT_EQUAL_size_t(2, out_len);
  TEST_ASSERT_EQUAL_MEMORY("fo", out, 2);
  free(out);
}

static void test_decode_two_padding_chars(void) {
  size_t out_len = 0;
  unsigned char *out = base64_decode("Zg==", 4, &out_len); /* "f" */

  TEST_ASSERT_NOT_NULL(out);
  TEST_ASSERT_EQUAL_size_t(1, out_len);
  TEST_ASSERT_EQUAL_MEMORY("f", out, 1);
  free(out);
}

/* Empty input must not read data[-1]/data[-2] when probing for padding. */
static void test_decode_empty_input_returns_null(void) {
  size_t out_len = 123;
  unsigned char *out = base64_decode("", 0, &out_len);

  TEST_ASSERT_NULL(out);
  TEST_ASSERT_EQUAL_size_t(0, out_len);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_decode_roundtrips_ascii);
  RUN_TEST(test_decode_high_bit_bytes_are_not_oob);
  RUN_TEST(test_decode_one_padding_char);
  RUN_TEST(test_decode_two_padding_chars);
  RUN_TEST(test_decode_empty_input_returns_null);
  return UNITY_END();
}
