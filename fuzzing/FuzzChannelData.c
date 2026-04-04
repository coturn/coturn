/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Fuzzing target for ChannelData TCP framing (issue #1837).
 *
 * Exercises stun_get_message_len_str() and stun_is_channel_message_str()
 * against arbitrary input, with focus on:
 *   - uint16_t overflow when data_len >= 0xFFFD (4 + data_len wraps)
 *   - Consistency between the two framing functions
 *   - Padding boundary conditions
 *   - Invalid channel numbers (outside 0x4000–0x7FFF)
 */

#include <stdint.h>
#include <string.h>

#include "ns_turn_msg.h"

#define kMinInputLength 4
#define kMaxInputLength 8192

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 0;
  }

  /* Work on a mutable copy — stun_get_message_len_str takes uint8_t * */
  uint8_t buf[kMaxInputLength];
  memcpy(buf, Data, Size);

  size_t app_len_tcp = 0;
  size_t app_len_udp = 0;

  /* Test TCP framing (padding=1): the overflow path that triggered #1837 */
  int mlen_tcp = stun_get_message_len_str(buf, Size, 1, &app_len_tcp);

  /* Test UDP framing (padding=0): should be consistent with TCP result for
   * data_len values that are already 4-byte aligned */
  int mlen_udp = stun_get_message_len_str(buf, Size, 0, &app_len_udp);

  /* Invariant: if TCP framing accepted the message, app_len must be <= Size
   * and the padded total (mlen_tcp) must also be <= Size. */
  if (mlen_tcp > 0) {
    if (app_len_tcp > Size) {
      __builtin_trap();
    }
    if ((size_t)mlen_tcp > Size) {
      __builtin_trap();
    }
    /* TCP padded length must be >= the unpadded app_len */
    if ((size_t)mlen_tcp < app_len_tcp) {
      __builtin_trap();
    }
  }

  if (mlen_udp > 0) {
    if (app_len_udp > Size) {
      __builtin_trap();
    }
    if ((size_t)mlen_udp > Size) {
      __builtin_trap();
    }
  }

  /* stun_is_channel_message_str: mandatory_padding=1 (TCP), then optional */
  size_t blen_tcp = Size;
  uint16_t chn_tcp = 0;
  bool is_chan_tcp = stun_is_channel_message_str(buf, &blen_tcp, &chn_tcp, true);

  size_t blen_udp = Size;
  uint16_t chn_udp = 0;
  bool is_chan_udp = stun_is_channel_message_str(buf, &blen_udp, &chn_udp, false);

  /* If stun_is_channel_message_str accepted it, the reported length must be
   * within the buffer and at least 4 bytes (header). */
  if (is_chan_tcp) {
    if (blen_tcp < 4 || blen_tcp > Size) {
      __builtin_trap();
    }
  }
  if (is_chan_udp) {
    if (blen_udp < 4 || blen_udp > Size) {
      __builtin_trap();
    }
  }

  return 0;
}
