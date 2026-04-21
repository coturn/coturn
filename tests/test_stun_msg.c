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
  RUN_TEST(test_truncated_buffer_is_not_command_message);
  RUN_TEST(test_zeroed_buffer_is_not_command_message);
  RUN_TEST(test_channel_message_roundtrip);
  RUN_TEST(test_http_message_len_handles_non_null_terminated_buffer);
  return UNITY_END();
}
