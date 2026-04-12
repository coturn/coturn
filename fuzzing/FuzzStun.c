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

  uint8_t uname[STUN_MAX_USERNAME_SIZE + 1] = "fuzzuser";
  uint8_t realm[STUN_MAX_REALM_SIZE + 1] = "fuzz.realm";
  uint8_t upwd[STUN_MAX_PWD_SIZE + 1] = "VOkJxbRl1RmTxUk/WvJxBt";

  /* Short-term credentials, SHA1 (original path) */
  stun_check_message_integrity_str(TURN_CREDENTIALS_SHORT_TERM, (uint8_t *)Data, Size, uname, realm, upwd, shatype);

  /* Long-term credentials, SHA256 */
  stun_check_message_integrity_str(TURN_CREDENTIALS_LONG_TERM, (uint8_t *)Data, Size, uname, realm, upwd,
                                   SHATYPE_SHA256);

  return 0;
}
