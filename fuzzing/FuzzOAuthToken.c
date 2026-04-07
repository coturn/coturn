/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Fuzzing target for OAuth token decoding (issue #1838).
 *
 * Exercises decode_oauth_token() against arbitrary input, with focus on:
 *   - Stack buffer overflow when nonce_length field > OAUTH_MAX_NONCE_SIZE (256)
 *   - encoded_field_size underflow in unsigned subtraction
 *   - OpenSSL GCM IV-length handling with out-of-range nonce lengths
 *
 * The fuzz input is treated as the raw bytes of an encoded_oauth_token.  A
 * fixed oauth_key with a known algorithm is used so the fuzzer exercises the
 * parsing and bounds-checking paths rather than key derivation.
 */

#include <stdint.h>
#include <string.h>

#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"

/* 16-byte all-zero key for A128GCM (128-bit key size). */
static const uint8_t kFuzzAsRsKey[16] = {0};

/* Minimum meaningful token: 2 (nonce_len) + nonce + 4 (key_len) + 8
 * (timestamp) + OAUTH_GCM_TAG_SIZE (16) + 1 (at least one ciphertext byte)
 * With nonce_len = 0 that is 2 + 0 + 4 + 8 + 16 + 1 = 31. */
#define kMinInputLength 31
#define kMaxInputLength MAX_ENCODED_OAUTH_TOKEN_SIZE

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 0;
  }

  oauth_key key = {0};
  key.as_rs_alg = A128GCM;
  memcpy(key.as_rs_key, kFuzzAsRsKey, sizeof(kFuzzAsRsKey));
  key.as_rs_key_size = sizeof(kFuzzAsRsKey);
  /* auth_key_size must be non-zero for the integrity path; use the same key. */
  memcpy(key.auth_key, kFuzzAsRsKey, sizeof(kFuzzAsRsKey));
  key.auth_key_size = sizeof(kFuzzAsRsKey);

  encoded_oauth_token etoken = {0};
  etoken.size = Size;
  memcpy(etoken.token, Data, Size);

  oauth_token dtoken = {0};

  /*
   * The return value is intentionally ignored: we are looking for crashes
   * (buffer overflows, use-after-free, etc.), not for decryption success.
   *
   * Invariant: if decoding claims success, the nonce_length stored in
   * dtoken must fit within the nonce buffer.
   */
  bool ok = decode_oauth_token((const uint8_t *)"fuzz-server", &etoken, &key, &dtoken);

  if (ok) {
    /* nonce_length must be within the fixed buffer declared in the struct. */
    if (dtoken.enc_block.nonce_length > OAUTH_MAX_NONCE_SIZE) {
      __builtin_trap();
    }
  }

  return 0;
}
