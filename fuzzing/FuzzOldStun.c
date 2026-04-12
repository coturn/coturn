/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Fuzzing target for old (pre-RFC 5389) STUN message detection.
 *
 * Exercises old_stun_is_command_message_str() which accepts messages
 * without the 0x2112A442 magic cookie -- a separate validation path
 * from the modern STUN parser.
 *
 * Includes an invariant check: if modern STUN accepts a message,
 * old STUN must also accept it (old is a superset).
 */

#include <stdint.h>
#include <string.h>

#include "ns_turn_msg.h"

#define kMinInputLength STUN_HEADER_LENGTH
#define kMaxInputLength 5120

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 0;
  }

  uint8_t buf[kMaxInputLength];
  memcpy(buf, Data, Size);

  /* Old STUN: any magic cookie accepted, returns the cookie value */
  uint32_t cookie = 0;
  bool is_old = old_stun_is_command_message_str(buf, Size, &cookie);

  /* Modern STUN for comparison */
  bool is_modern = stun_is_command_message_str(buf, Size);

  /* Invariant: modern STUN messages are a subset of old STUN messages
   * (old accepts any cookie, modern requires 0x2112A442) */
  if (is_modern && !is_old) {
    __builtin_trap();
  }

  /* If old STUN accepted it, exercise message type extraction */
  if (is_old) {
    uint16_t msg_type = stun_get_msg_type_str(buf, Size);
    uint16_t method = stun_get_method_str(buf, Size);
    (void)msg_type;
    (void)method;

    stun_is_request_str(buf, Size);
    stun_is_indication_str(buf, Size);
    stun_is_success_response_str(buf, Size);

    int err_code = 0;
    uint8_t err_msg[256] = {0};
    stun_is_error_response_str(buf, Size, &err_code, err_msg, sizeof(err_msg));

    /* Full check with fingerprint validation */
    int fp_present = 0;
    stun_is_command_message_full_check_str(buf, Size, 1, &fp_present);
    stun_is_command_message_full_check_str(buf, Size, 0, &fp_present);

    /* Binding-specific checks */
    stun_is_binding_request_str(buf, Size, 0);
    stun_is_binding_response_str(buf, Size);

    /* Attribute iteration on old STUN messages */
    stun_attr_ref sar = stun_attr_get_first_str(buf, Size);
    while (sar) {
      (void)stun_attr_get_type(sar);
      (void)stun_attr_get_len(sar);
      sar = stun_attr_get_next_str(buf, Size, sar);
    }
  }

  return 0;
}
