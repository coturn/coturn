/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Fuzzing target for OAuth token encode/decode round-trip.
 *
 * Exercises:
 *   - encode_oauth_token() serialization (currently unfuzzed)
 *   - decode_oauth_token() with A256GCM (FuzzOAuthToken only tests A128GCM)
 *   - Round-trip consistency: encode then decode
 *   - Raw fuzz bytes as encoded token with A256GCM key
 */

#include <stdint.h>
#include <string.h>

#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"

/* 32-byte all-zero key for A256GCM */
static const uint8_t kFuzzKey256[32] = {0};
/* 16-byte all-zero key for A128GCM */
static const uint8_t kFuzzKey128[16] = {0};

#define kMinInputLength 16
#define kMaxInputLength 512

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 0;
  }

  /* Split fuzz input: first 12 bytes = nonce, rest = token fields */
  uint8_t nonce[OAUTH_GCM_NONCE_SIZE] = {0};
  size_t nonce_len = Size > OAUTH_GCM_NONCE_SIZE ? OAUTH_GCM_NONCE_SIZE : Size;
  memcpy(nonce, Data, nonce_len);

  /* Build a token from fuzz data for the encode path */
  oauth_token src_token = {0};
  if (Size > OAUTH_GCM_NONCE_SIZE + sizeof(uint64_t) + sizeof(uint32_t)) {
    const uint8_t *p = Data + OAUTH_GCM_NONCE_SIZE;
    memcpy(&src_token.enc_block.timestamp, p, sizeof(uint64_t));
    p += sizeof(uint64_t);
    memcpy(&src_token.enc_block.lifetime, p, sizeof(uint32_t));
    p += sizeof(uint32_t);
    size_t key_len = Size - (size_t)(p - Data);
    if (key_len > MAXSHASIZE) {
      key_len = MAXSHASIZE;
    }
    src_token.enc_block.key_length = (uint16_t)key_len;
    memcpy(src_token.enc_block.mac_key, p, key_len);
  }

  /* Test A256GCM encode + decode round-trip */
  {
    oauth_key key = {0};
    key.as_rs_alg = A256GCM;
    memcpy(key.as_rs_key, kFuzzKey256, sizeof(kFuzzKey256));
    key.as_rs_key_size = sizeof(kFuzzKey256);
    memcpy(key.auth_key, kFuzzKey256, sizeof(kFuzzKey256));
    key.auth_key_size = sizeof(kFuzzKey256);

    encoded_oauth_token etoken = {0};
    bool enc_ok = encode_oauth_token((const uint8_t *)"fuzz-server", &etoken, &key, &src_token, nonce);

    if (enc_ok) {
      oauth_token dec_token = {0};
      bool dec_ok = decode_oauth_token((const uint8_t *)"fuzz-server", &etoken, &key, &dec_token);

      /* If round-trip succeeded, nonce_length must be valid */
      if (dec_ok && dec_token.enc_block.nonce_length > OAUTH_MAX_NONCE_SIZE) {
        __builtin_trap();
      }
    }
  }

  /* Test A128GCM encode + decode round-trip */
  {
    oauth_key key = {0};
    key.as_rs_alg = A128GCM;
    memcpy(key.as_rs_key, kFuzzKey128, sizeof(kFuzzKey128));
    key.as_rs_key_size = sizeof(kFuzzKey128);
    memcpy(key.auth_key, kFuzzKey128, sizeof(kFuzzKey128));
    key.auth_key_size = sizeof(kFuzzKey128);

    encoded_oauth_token etoken = {0};
    bool enc_ok = encode_oauth_token((const uint8_t *)"fuzz-server", &etoken, &key, &src_token, nonce);

    if (enc_ok) {
      oauth_token dec_token = {0};
      bool dec_ok = decode_oauth_token((const uint8_t *)"fuzz-server", &etoken, &key, &dec_token);

      if (dec_ok && dec_token.enc_block.nonce_length > OAUTH_MAX_NONCE_SIZE) {
        __builtin_trap();
      }
    }
  }

  /* Also test raw fuzz bytes as an encoded token with A256GCM
   * (complements FuzzOAuthToken which uses A128GCM) */
  if (Size <= MAX_ENCODED_OAUTH_TOKEN_SIZE) {
    oauth_key key = {0};
    key.as_rs_alg = A256GCM;
    memcpy(key.as_rs_key, kFuzzKey256, sizeof(kFuzzKey256));
    key.as_rs_key_size = sizeof(kFuzzKey256);
    memcpy(key.auth_key, kFuzzKey256, sizeof(kFuzzKey256));
    key.auth_key_size = sizeof(kFuzzKey256);

    encoded_oauth_token etoken = {0};
    etoken.size = Size;
    memcpy(etoken.token, Data, Size);

    oauth_token dec_token = {0};
    bool dec_ok = decode_oauth_token((const uint8_t *)"fuzz-server", &etoken, &key, &dec_token);

    if (dec_ok && dec_token.enc_block.nonce_length > OAUTH_MAX_NONCE_SIZE) {
      __builtin_trap();
    }
  }

  return 0;
}
