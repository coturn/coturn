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
    if (stun_is_response(&buf)) {
      if (stun_is_success_response(&buf)) {
        if (stun_is_binding_response(&buf)) {
          return 0;
        }
      }
    }
  }

  return 1;
}
