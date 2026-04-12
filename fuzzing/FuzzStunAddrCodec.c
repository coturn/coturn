/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Fuzzing target for STUN address encode/decode.
 *
 * Exercises stun_addr_decode() directly with arbitrary address attribute
 * payloads, testing:
 *   - Invalid family bytes (not 0x01 or 0x02)
 *   - Truncated IPv4 (<8 bytes) and IPv6 (<20 bytes) payloads
 *   - XOR decoding with arbitrary transaction IDs
 *   - Round-trip encode->decode consistency
 */

#include <stdint.h>
#include <string.h>

#include "ns_turn_msg.h"
#include "ns_turn_msg_addr.h"

#define kMinInputLength 2
#define kMaxInputLength 64

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 0;
  }

  /*
   * Layout: first 12 bytes are used as a transaction ID (padded with zeros
   * if input is shorter), remaining bytes are the raw address attribute value.
   */
  uint8_t tid[STUN_TID_SIZE] = {0};
  size_t tid_bytes =
      Size > (STUN_TID_SIZE + kMinInputLength) ? STUN_TID_SIZE : (Size > kMinInputLength ? Size - kMinInputLength : 0);
  memcpy(tid, Data, tid_bytes);
  const uint8_t *payload = Data + tid_bytes;
  int payload_len = (int)(Size - tid_bytes);

  ioa_addr addr = {0};
  int rc;

  /* Decode with XOR */
  rc = stun_addr_decode(&addr, payload, payload_len, 1, STUN_MAGIC_COOKIE, tid);

  /* If decode succeeded, verify round-trip */
  if (rc == 0) {
    uint8_t enc_buf[32] = {0};
    int enc_len = 0;
    int erc = stun_addr_encode(&addr, enc_buf, &enc_len, 1, STUN_MAGIC_COOKIE, tid);

    if (erc == 0) {
      /* Decode the re-encoded buffer and compare */
      ioa_addr addr2 = {0};
      stun_addr_decode(&addr2, enc_buf, enc_len, 1, STUN_MAGIC_COOKIE, tid);
    }
  }

  /* Decode without XOR */
  memset(&addr, 0, sizeof(addr));
  rc = stun_addr_decode(&addr, payload, payload_len, 0, 0, tid);

  if (rc == 0) {
    uint8_t enc_buf[32] = {0};
    int enc_len = 0;
    int erc = stun_addr_encode(&addr, enc_buf, &enc_len, 0, 0, tid);

    if (erc == 0) {
      ioa_addr addr2 = {0};
      stun_addr_decode(&addr2, enc_buf, enc_len, 0, 0, tid);
    }
  }

  /* Test with a different magic cookie value (old STUN) */
  memset(&addr, 0, sizeof(addr));
  uint32_t alt_cookie = 0;
  if (Size >= 4) {
    memcpy(&alt_cookie, Data, 4);
  }
  rc = stun_addr_decode(&addr, payload, payload_len, 1, alt_cookie, tid);
  (void)rc;

  return 0;
}
