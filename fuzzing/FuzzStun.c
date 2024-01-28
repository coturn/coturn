#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apputils.h"
#include "ns_turn_utils.h"
#include "stun_buffer.h"

static SHATYPE shatype = SHATYPE_SHA1;

#define kMinInputLength 10
#define kMaxInputLength 5120

extern int LLVMFuzzerTestOneInput(const uint8_t *Data,
                                  size_t Size) { // rfc5769check

  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 1;
  }

  stun_is_command_message_full_check_str((uint8_t *)Data, Size, 1, NULL);

  uint8_t uname[33];
  uint8_t realm[33];
  uint8_t upwd[33];
  strcpy((char *)upwd, "VOkJxbRl1RmTxUk/WvJxBt");
  stun_check_message_integrity_str(TURN_CREDENTIALS_SHORT_TERM, (uint8_t *)Data, Size, uname, realm, upwd, shatype);
  return 0;
}
