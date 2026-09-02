#include "ns_turn_msg.h"

#include <unity.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static bool run_saslprep(const char *in) {
  uint8_t buf[64] = {0};
  memcpy(buf, in, strlen(in));
  return SASLprep(buf);
}

static void test_plain_ascii_is_accepted(void) { TEST_ASSERT_TRUE(run_saslprep("user")); }

/* RFC 4013 Section 2.3 / RFC 3454 Table C.2.1: the ASCII control range is
   U+0000-U+001F. Every byte in it (0x1F included) must be rejected. */
static void test_ascii_control_range_is_rejected(void) {
  for (int c = 0x01; c <= 0x1F; ++c) {
    uint8_t buf[4] = {(uint8_t)'a', (uint8_t)c, (uint8_t)'b', 0};
    char msg[64];
    snprintf(msg, sizeof(msg), "control byte 0x%02x must be rejected", c);
    TEST_ASSERT_FALSE_MESSAGE(SASLprep(buf), msg);
  }
}

static void test_del_and_c1_controls_are_rejected(void) {
  uint8_t del[3] = {(uint8_t)'a', 0x7F, 0};
  TEST_ASSERT_FALSE(SASLprep(del));
  uint8_t c1[3] = {(uint8_t)'a', 0x9F, 0};
  TEST_ASSERT_FALSE(SASLprep(c1));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_plain_ascii_is_accepted);
  RUN_TEST(test_ascii_control_range_is_rejected);
  RUN_TEST(test_del_and_c1_controls_are_rejected);
  return UNITY_END();
}
