#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apputils.h"
#include "ns_turn_utils.h"
#include "stun_buffer.h"

#define kMinInputLength 10
#define kMaxInputLength 5120

extern int LLVMFuzzerTestOneInput(const uint8_t *Data,
                                  size_t Size) { // stunclient.c

  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 1;
  }

  stun_buffer buf;

  buf.len = Size;
  memcpy(buf.buf, Data, buf.len);

  if (stun_is_command_message(&buf)) {
    /* Message type and method extraction */
    uint16_t method = stun_get_method_str(buf.buf, buf.len);
    uint16_t msg_type = stun_get_msg_type_str(buf.buf, buf.len);
    (void)method;
    (void)msg_type;

    if (stun_is_response(&buf)) {
      if (stun_is_success_response(&buf)) {
        if (stun_is_binding_response(&buf)) {
          return 0;
        }
      }
    }

    /* Indication and error response checks */
    stun_is_indication_str(buf.buf, buf.len);

    int err_code = 0;
    uint8_t err_msg[256] = {0};
    stun_is_error_response_str(buf.buf, buf.len, &err_code, err_msg, sizeof(err_msg));
  }

  return 1;
}
