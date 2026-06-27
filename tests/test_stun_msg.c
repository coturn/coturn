#include "ns_turn_ioaddr.h"
#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"

#include <unity.h>

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_init_request_produces_valid_stun_header(void) {
  uint8_t buf[1024] = {0};
  size_t len = 0;

  stun_init_request_str(STUN_METHOD_BINDING, buf, &len);

  TEST_ASSERT_EQUAL_size_t(STUN_HEADER_LENGTH, len);
  TEST_ASSERT_TRUE(stun_is_command_message_str(buf, len));
  TEST_ASSERT_TRUE(stun_is_request_str(buf, len));
  TEST_ASSERT_EQUAL_UINT16(STUN_METHOD_BINDING, stun_get_method_str(buf, len));
}

static void test_init_indication_is_not_request(void) {
  uint8_t buf[1024] = {0};
  size_t len = 0;

  stun_init_indication_str(STUN_METHOD_BINDING, buf, &len);

  TEST_ASSERT_TRUE(stun_is_command_message_str(buf, len));
  TEST_ASSERT_FALSE(stun_is_request_str(buf, len));
  TEST_ASSERT_TRUE(stun_is_indication_str(buf, len));
}

static void test_success_response_carries_transaction_id(void) {
  uint8_t req[1024] = {0};
  size_t req_len = 0;
  stun_init_request_str(STUN_METHOD_ALLOCATE, req, &req_len);

  stun_tid tid = {0};
  stun_tid_from_message_str(req, req_len, &tid);

  uint8_t resp[1024] = {0};
  size_t resp_len = 0;
  stun_init_success_response_str(STUN_METHOD_ALLOCATE, resp, &resp_len, &tid);

  TEST_ASSERT_TRUE(stun_is_success_response_str(resp, resp_len));
  TEST_ASSERT_EQUAL_UINT16(STUN_METHOD_ALLOCATE, stun_get_method_str(resp, resp_len));

  stun_tid resp_tid = {0};
  stun_tid_from_message_str(resp, resp_len, &resp_tid);
  TEST_ASSERT_EQUAL_MEMORY(tid.tsx_id, resp_tid.tsx_id, STUN_TID_SIZE);
}

static void test_error_response_carries_error_code(void) {
  uint8_t buf[1024] = {0};
  size_t len = 0;
  stun_tid tid = {0};

  stun_init_error_response_str(STUN_METHOD_ALLOCATE, buf, &len, 401, (const uint8_t *)"Unauthorized", &tid, true);

  TEST_ASSERT_TRUE(stun_is_command_message_str(buf, len));

  int err_code = 0;
  uint8_t err_msg[128] = {0};
  TEST_ASSERT_TRUE(stun_is_error_response_str(buf, len, &err_code, err_msg, sizeof(err_msg)));
  TEST_ASSERT_EQUAL_INT(401, err_code);
}

static void test_error_response_without_reason_string_still_parses(void) {
  uint8_t buf[1024] = {0};
  size_t len = 0;
  stun_tid tid = {0};

  stun_init_error_response_str(STUN_METHOD_ALLOCATE, buf, &len, 437, (const uint8_t *)"ignored", &tid, false);

  TEST_ASSERT_TRUE(stun_is_command_message_str(buf, len));

  int err_code = 0;
  uint8_t err_msg[128] = {0};
  TEST_ASSERT_TRUE(stun_is_error_response_str(buf, len, &err_code, err_msg, sizeof(err_msg)));
  TEST_ASSERT_EQUAL_INT(437, err_code);
}

static void test_truncated_buffer_is_not_command_message(void) {
  uint8_t buf[10] = {0};
  TEST_ASSERT_FALSE(stun_is_command_message_str(buf, sizeof(buf)));
}

static void test_zeroed_buffer_is_not_command_message(void) {
  uint8_t buf[STUN_HEADER_LENGTH] = {0};
  TEST_ASSERT_FALSE(stun_is_command_message_str(buf, sizeof(buf)));
}

static void test_channel_message_roundtrip(void) {
  uint8_t buf[1024] = {0};
  size_t len = 0;
  const uint16_t channel = 0x4000;
  const int payload_len = 200;

  TEST_ASSERT_TRUE(stun_init_channel_message_str(channel, buf, &len, payload_len, false));

  uint16_t parsed_channel = 0;
  size_t blen = len;
  TEST_ASSERT_TRUE(stun_is_channel_message_str(buf, &blen, &parsed_channel, false));
  TEST_ASSERT_EQUAL_UINT16(channel, parsed_channel);
}

static void test_challenge_response_null_terminates_max_length_server_name(void) {
  uint8_t buf[MAX_STUN_MESSAGE_SIZE] = {0};
  size_t len = 0;
  stun_tid tid = {0};

  stun_init_error_response_str(STUN_METHOD_ALLOCATE, buf, &len, 401, (const uint8_t *)"Unauthorized", &tid, true);

  uint8_t realm[] = "example.org";
  TEST_ASSERT_TRUE(stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_REALM, realm, (int)(sizeof(realm) - 1)));

  /* A malicious server can send a THIRD-PARTY-AUTHORIZATION value as long as the
   * receiving buffer, leaving no room for an implicit terminator. */
  uint8_t long_name[STUN_MAX_SERVER_NAME_SIZE];
  memset(long_name, 'a', sizeof(long_name));
  TEST_ASSERT_TRUE(
      stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_THIRD_PARTY_AUTHORIZATION, long_name, (int)sizeof(long_name)));

  uint8_t nonce[] = "0123456789abcdef";
  TEST_ASSERT_TRUE(stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_NONCE, nonce, (int)(sizeof(nonce) - 1)));

  int err_code = 0;
  uint8_t err_msg[128] = {0};
  uint8_t out_realm[STUN_MAX_REALM_SIZE + 1] = {0};
  uint8_t out_nonce[STUN_MAX_NONCE_SIZE + 1] = {0};
  uint8_t server_name[STUN_MAX_SERVER_NAME_SIZE + 1];
  memset(server_name, 0xFF, sizeof(server_name));
  bool oauth = false;

  TEST_ASSERT_TRUE(stun_is_challenge_response_str(buf, len, &err_code, err_msg, sizeof(err_msg), out_realm, out_nonce,
                                                  server_name, &oauth));
  TEST_ASSERT_TRUE(oauth);
  TEST_ASSERT_NOT_NULL(memchr(server_name, 0, sizeof(server_name)));
  TEST_ASSERT_EQUAL_size_t(STUN_MAX_SERVER_NAME_SIZE, strlen((const char *)server_name));
}

/* Build a minimal valid STUN message header with a chosen body length field,
 * so we can drive stun_get_message_len_str() across the uint16_t-overflow
 * boundary. */
static void make_stun_header(uint8_t *buf, uint16_t body_len) {
  /* Type: top two bits clear, not a valid channel number. Use BINDING. */
  buf[0] = (uint8_t)(STUN_METHOD_BINDING >> 8);
  buf[1] = (uint8_t)(STUN_METHOD_BINDING & 0xFF);
  /* Body length (network byte order). */
  buf[2] = (uint8_t)(body_len >> 8);
  buf[3] = (uint8_t)(body_len & 0xFF);
  /* Magic cookie. */
  buf[4] = 0x21;
  buf[5] = 0x12;
  buf[6] = 0xA4;
  buf[7] = 0x42;
  /* Transaction id (bytes 8..19) left as-is by the caller. */
}

static void test_message_len_does_not_overflow_uint16(void) {
  /* Body lengths that are 4-byte aligned and within 16 of 0xFFFF: len + 20
   * wraps a uint16_t to 4/8/12/16. With only a header-sized buffer present,
   * the truncated value would falsely pass the `<= blen` bounds check and the
   * function would claim a tiny message, orphaning the rest of the TCP stream.
   * The fix computes the length in uint32_t, so each of these must instead be
   * reported as "incomplete" (return -1) given a short buffer. */
  const uint16_t overflow_body_lens[] = {65520, 65524, 65528, 65532};

  for (size_t i = 0; i < sizeof(overflow_body_lens) / sizeof(overflow_body_lens[0]); ++i) {
    uint8_t buf[STUN_HEADER_LENGTH] = {0};
    make_stun_header(buf, overflow_body_lens[i]);

    size_t app_len = 12345; /* sentinel; must not be written on the short path */
    const int mlen = stun_get_message_len_str(buf, sizeof(buf), 1, &app_len);

    /* Without the uint32_t widening this returned a small positive value
     * (4/8/12/16) that the TCP framing layer would act on
     * (mlen > 0 && mlen <= blen), consuming only a few bytes. With the fix the
     * real length (body + 20) exceeds blen, so the function reports
     * "incomplete" (-1) and the framing layer waits for more data instead of
     * desynchronizing. The key property is that it is never a small positive
     * value here. */
    TEST_ASSERT_EQUAL_INT(-1, mlen);
    TEST_ASSERT_FALSE(mlen > 0 && mlen <= (int)sizeof(buf));
    TEST_ASSERT_EQUAL_size_t(12345, app_len);
  }
}

static void test_message_len_accepts_full_well_formed_message(void) {
  /* A genuine, fully-present STUN message is still parsed correctly. */
  const uint16_t body_len = 8;
  uint8_t buf[STUN_HEADER_LENGTH + 8] = {0};
  make_stun_header(buf, body_len);

  size_t app_len = 0;
  const int mlen = stun_get_message_len_str(buf, sizeof(buf), 1, &app_len);

  TEST_ASSERT_EQUAL_INT((int)(STUN_HEADER_LENGTH + body_len), mlen);
  TEST_ASSERT_EQUAL_size_t((size_t)(STUN_HEADER_LENGTH + body_len), app_len);
}

static void test_http_message_len_handles_non_null_terminated_buffer(void) {
  uint8_t buf[] = {'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n', '\r', '\n'};
  size_t app_len = 0;

  TEST_ASSERT_EQUAL_INT((int)sizeof(buf), stun_get_message_len_str(buf, sizeof(buf), 1, &app_len));
  TEST_ASSERT_EQUAL_size_t(sizeof(buf), app_len);
  TEST_ASSERT_EQUAL_INT((int)sizeof(buf), is_http((const char *)buf, sizeof(buf)));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_init_request_produces_valid_stun_header);
  RUN_TEST(test_init_indication_is_not_request);
  RUN_TEST(test_success_response_carries_transaction_id);
  RUN_TEST(test_error_response_carries_error_code);
  RUN_TEST(test_error_response_without_reason_string_still_parses);
  RUN_TEST(test_truncated_buffer_is_not_command_message);
  RUN_TEST(test_zeroed_buffer_is_not_command_message);
  RUN_TEST(test_channel_message_roundtrip);
  RUN_TEST(test_challenge_response_null_terminates_max_length_server_name);
  RUN_TEST(test_message_len_does_not_overflow_uint16);
  RUN_TEST(test_message_len_accepts_full_well_formed_message);
  RUN_TEST(test_http_message_len_handles_non_null_terminated_buffer);
  return UNITY_END();
}
