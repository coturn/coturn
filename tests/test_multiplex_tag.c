/*
 * Unit tests for the multiplex-peer mux-id trailer codec
 * (src/apps/relay/multiplex_peer_tag.h).
 *
 * The codec is the wire contract between turnserver --multiplex-peer-tag and
 * turnutils_peer --multiplex: a fixed 4-byte big-endian per-session mux-id
 * appended as a TRAILER to relay<->peer UDP datagrams. These tests pin the
 * encode/decode round trip, byte order, boundary conditions, and the
 * append/strip inverse relationship.
 */

#include "multiplex_peer_tag.h"

#include <unity.h>

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_append_then_strip_roundtrips(void) {
  uint8_t buf[64] = {0};
  const char payload[] = "hello-peer";
  size_t len = strlen(payload);
  memcpy(buf, payload, len);

  TEST_ASSERT_TRUE(multiplex_peer_tag_append(buf, &len, sizeof(buf), 0xDEADBEEFu));
  TEST_ASSERT_EQUAL_size_t(strlen(payload) + MULTIPLEX_PEER_TAG_SIZE, len);

  uint32_t mux_id = 0;
  TEST_ASSERT_TRUE(multiplex_peer_tag_strip(buf, &len, &mux_id));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEFu, mux_id);
  TEST_ASSERT_EQUAL_size_t(strlen(payload), len);
  /* Payload is left intact ahead of where the trailer was. */
  TEST_ASSERT_EQUAL_MEMORY(payload, buf, strlen(payload));
}

static void test_trailer_is_big_endian(void) {
  uint8_t buf[8] = {0};
  size_t len = 0;
  TEST_ASSERT_TRUE(multiplex_peer_tag_append(buf, &len, sizeof(buf), 0x01020304u));
  TEST_ASSERT_EQUAL_size_t(MULTIPLEX_PEER_TAG_SIZE, len);
  TEST_ASSERT_EQUAL_HEX8(0x01, buf[0]);
  TEST_ASSERT_EQUAL_HEX8(0x02, buf[1]);
  TEST_ASSERT_EQUAL_HEX8(0x03, buf[2]);
  TEST_ASSERT_EQUAL_HEX8(0x04, buf[3]);
}

static void test_append_refuses_unassigned_id(void) {
  uint8_t buf[8] = {0};
  size_t len = 2;
  TEST_ASSERT_FALSE(multiplex_peer_tag_append(buf, &len, sizeof(buf), MULTIPLEX_PEER_TAG_NONE));
  TEST_ASSERT_EQUAL_size_t(2, len); /* len untouched on refusal */
}

static void test_append_refuses_without_tailroom(void) {
  uint8_t buf[8] = {0};
  size_t len = 6; /* 6 + 4 > 8 capacity */
  TEST_ASSERT_FALSE(multiplex_peer_tag_append(buf, &len, sizeof(buf), 0x11223344u));
  TEST_ASSERT_EQUAL_size_t(6, len);

  /* Exactly fits: 4 + 4 == 8. */
  len = 4;
  TEST_ASSERT_TRUE(multiplex_peer_tag_append(buf, &len, sizeof(buf), 0x11223344u));
  TEST_ASSERT_EQUAL_size_t(8, len);
}

static void test_strip_rejects_short_datagram(void) {
  uint8_t buf[8] = {1, 2, 3};
  size_t len = MULTIPLEX_PEER_TAG_SIZE - 1; /* too short to hold a trailer */
  uint32_t mux_id = 0xAAAAAAAAu;
  TEST_ASSERT_FALSE(multiplex_peer_tag_strip(buf, &len, &mux_id));
  TEST_ASSERT_EQUAL_size_t(MULTIPLEX_PEER_TAG_SIZE - 1, len); /* untouched */
  TEST_ASSERT_EQUAL_HEX32(0xAAAAAAAAu, mux_id);               /* untouched */
}

static void test_strip_exact_trailer_only(void) {
  /* A datagram that is exactly the trailer (zero payload) is valid. */
  uint8_t buf[MULTIPLEX_PEER_TAG_SIZE] = {0};
  size_t len = 0;
  TEST_ASSERT_TRUE(multiplex_peer_tag_append(buf, &len, sizeof(buf), 0x7F00FF01u));
  uint32_t mux_id = 0;
  TEST_ASSERT_TRUE(multiplex_peer_tag_strip(buf, &len, &mux_id));
  TEST_ASSERT_EQUAL_HEX32(0x7F00FF01u, mux_id);
  TEST_ASSERT_EQUAL_size_t(0, len);
}

static void test_max_id_roundtrips(void) {
  uint8_t buf[16] = {0};
  size_t len = 4;
  TEST_ASSERT_TRUE(multiplex_peer_tag_append(buf, &len, sizeof(buf), 0xFFFFFFFFu));
  uint32_t mux_id = 0;
  TEST_ASSERT_TRUE(multiplex_peer_tag_strip(buf, &len, &mux_id));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFFu, mux_id);
  TEST_ASSERT_EQUAL_size_t(4, len);
}

static void test_null_args_are_safe(void) {
  uint8_t buf[8] = {0};
  size_t len = 4;
  uint32_t mux_id = 0;
  TEST_ASSERT_FALSE(multiplex_peer_tag_append(NULL, &len, sizeof(buf), 1));
  TEST_ASSERT_FALSE(multiplex_peer_tag_append(buf, NULL, sizeof(buf), 1));
  TEST_ASSERT_FALSE(multiplex_peer_tag_strip(NULL, &len, &mux_id));
  TEST_ASSERT_FALSE(multiplex_peer_tag_strip(buf, NULL, &mux_id));
  TEST_ASSERT_FALSE(multiplex_peer_tag_strip(buf, &len, NULL));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_append_then_strip_roundtrips);
  RUN_TEST(test_trailer_is_big_endian);
  RUN_TEST(test_append_refuses_unassigned_id);
  RUN_TEST(test_append_refuses_without_tailroom);
  RUN_TEST(test_strip_rejects_short_datagram);
  RUN_TEST(test_strip_exact_trailer_only);
  RUN_TEST(test_max_id_roundtrips);
  RUN_TEST(test_null_args_are_safe);
  return UNITY_END();
}
