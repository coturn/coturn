/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Fuzzing target for STUN message integrity across all SHA types
 * and credential modes.
 *
 * Exercises stun_check_message_integrity_str() with:
 *   - SHATYPE_SHA1, SHATYPE_SHA256, SHATYPE_SHA384, SHATYPE_SHA512
 *   - TURN_CREDENTIALS_SHORT_TERM, TURN_CREDENTIALS_LONG_TERM
 *
 * The existing FuzzStun only tests SHA1 with short-term credentials.
 */

#include <stdint.h>
#include <string.h>

#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"

#define kMinInputLength STUN_HEADER_LENGTH
#define kMaxInputLength 5120

static const SHATYPE kShaTypes[] = {SHATYPE_SHA1, SHATYPE_SHA256, SHATYPE_SHA384, SHATYPE_SHA512};

#define kNumShaTypes (sizeof(kShaTypes) / sizeof(kShaTypes[0]))

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 0;
  }

  uint8_t buf[kMaxInputLength];

  uint8_t uname[STUN_MAX_USERNAME_SIZE + 1] = "fuzzuser";
  uint8_t realm[STUN_MAX_REALM_SIZE + 1] = "fuzz.realm";
  uint8_t upwd[STUN_MAX_PWD_SIZE + 1] = "VOkJxbRl1RmTxUk/WvJxBt";

  for (size_t s = 0; s < kNumShaTypes; s++) {
    /* Short-term credentials */
    memcpy(buf, Data, Size);
    stun_is_command_message_full_check_str(buf, Size, 1, NULL);
    stun_check_message_integrity_str(TURN_CREDENTIALS_SHORT_TERM, buf, Size, uname, realm, upwd, kShaTypes[s]);

    /* Long-term credentials */
    memcpy(buf, Data, Size);
    stun_check_message_integrity_str(TURN_CREDENTIALS_LONG_TERM, buf, Size, uname, realm, upwd, kShaTypes[s]);
  }

  return 0;
}
