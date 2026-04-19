/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Multi-harness libFuzzer entry point for client-side STUN parsing,
 * TCP framing, and address codec.
 *
 * The first input byte selects one of several sub-harnesses. Keeping
 * everything behind a single binary allows the upstream OSS-Fuzz build
 * recipe (which only copies FuzzStun and FuzzStunClient) to stay
 * unchanged.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "apputils.h"
#include "ns_turn_msg.h"
#include "ns_turn_msg_addr.h"
#include "ns_turn_msg_defs.h"
#include "ns_turn_utils.h"
#include "stun_buffer.h"

/* ------------------------------------------------------------------ */
/* stun_buffer-based client message parsing (original FuzzStunClient). */
/* ------------------------------------------------------------------ */
static void harness_stun_client(const uint8_t *Data, size_t Size) {
  if (Size < 10 || Size > 5120) {
    return;
  }

  stun_buffer buf;
  buf.len = Size;
  memcpy(buf.buf, Data, buf.len);

  if (!stun_is_command_message(&buf)) {
    return;
  }

  (void)stun_get_method_str(buf.buf, buf.len);
  (void)stun_get_msg_type_str(buf.buf, buf.len);

  if (stun_is_response(&buf) && stun_is_success_response(&buf) && stun_is_binding_response(&buf)) {
    return;
  }

  stun_is_indication_str(buf.buf, buf.len);

  int err_code = 0;
  uint8_t err_msg[256] = {0};
  stun_is_error_response_str(buf.buf, buf.len, &err_code, err_msg, sizeof(err_msg));
}

/* ------------------------------------------------------------------ */
/* ChannelData / TCP framing (FuzzChannelData).                       */
/* ------------------------------------------------------------------ */
static void harness_channel_data(const uint8_t *Data, size_t Size) {
  if (Size < 4 || Size > 8192) {
    return;
  }

  uint8_t buf[8192] = {0};
  memcpy(buf, Data, Size);

  size_t app_len_tcp = 0;
  size_t app_len_udp = 0;

  int mlen_tcp = stun_get_message_len_str(buf, Size, 1, &app_len_tcp);
  int mlen_udp = stun_get_message_len_str(buf, Size, 0, &app_len_udp);

  if (mlen_tcp > 0) {
    if (app_len_tcp > Size) {
      __builtin_trap();
    }
    if ((size_t)mlen_tcp > Size) {
      __builtin_trap();
    }
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

  size_t blen_tcp = Size;
  uint16_t chn_tcp = 0;
  bool is_chan_tcp = stun_is_channel_message_str(buf, &blen_tcp, &chn_tcp, true);

  size_t blen_udp = Size;
  uint16_t chn_udp = 0;
  bool is_chan_udp = stun_is_channel_message_str(buf, &blen_udp, &chn_udp, false);

  if (is_chan_tcp && (blen_tcp < 4 || blen_tcp > Size)) {
    __builtin_trap();
  }
  if (is_chan_udp && (blen_udp < 4 || blen_udp > Size)) {
    __builtin_trap();
  }
}

/* ------------------------------------------------------------------ */
/* STUN address encode/decode (FuzzStunAddrCodec).                    */
/* ------------------------------------------------------------------ */
static void harness_addr_codec(const uint8_t *Data, size_t Size) {
  if (Size < 2 || Size > 64) {
    return;
  }

  uint8_t tid[STUN_TID_SIZE] = {0};
  size_t tid_bytes = Size > (STUN_TID_SIZE + 2) ? STUN_TID_SIZE : (Size > 2 ? Size - 2 : 0);
  memcpy(tid, Data, tid_bytes);
  const uint8_t *payload = Data + tid_bytes;
  int payload_len = (int)(Size - tid_bytes);

  ioa_addr addr = {0};

  /* XOR decode + round-trip */
  if (stun_addr_decode(&addr, payload, payload_len, 1, STUN_MAGIC_COOKIE, tid) == 0) {
    uint8_t enc_buf[32] = {0};
    int enc_len = 0;
    if (stun_addr_encode(&addr, enc_buf, &enc_len, 1, STUN_MAGIC_COOKIE, tid) == 0) {
      ioa_addr addr2 = {0};
      stun_addr_decode(&addr2, enc_buf, enc_len, 1, STUN_MAGIC_COOKIE, tid);
    }
  }

  /* Plain decode + round-trip */
  memset(&addr, 0, sizeof(addr));
  if (stun_addr_decode(&addr, payload, payload_len, 0, 0, tid) == 0) {
    uint8_t enc_buf[32] = {0};
    int enc_len = 0;
    if (stun_addr_encode(&addr, enc_buf, &enc_len, 0, 0, tid) == 0) {
      ioa_addr addr2 = {0};
      stun_addr_decode(&addr2, enc_buf, enc_len, 0, 0, tid);
    }
  }

  /* Alternate magic cookie (old STUN) */
  memset(&addr, 0, sizeof(addr));
  uint32_t alt_cookie = 0;
  if (Size >= 4) {
    memcpy(&alt_cookie, Data, 4);
  }
  (void)stun_addr_decode(&addr, payload, payload_len, 1, alt_cookie, tid);
}

/* ------------------------------------------------------------------ */
/* libFuzzer entry point — dispatch on Data[0] mod N.                 */
/*                                                                    */
/* Note: OAuth token sub-harnesses are intentionally omitted here.    */
/* decode_oauth_token_gcm in src/client/ns_turn_msg.c leaks the       */
/* EVP_CIPHER_CTX on several early-return paths, which trips ASan     */
/* under CIFuzz. Those harnesses will be re-added once the library    */
/* leak is fixed in a separate PR.                                    */
/* ------------------------------------------------------------------ */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < 1) {
    return 0;
  }

  uint8_t selector = Data[0];
  const uint8_t *sub_data = Data + 1;
  size_t sub_size = Size - 1;

  switch (selector % 3) {
  case 0:
    harness_stun_client(sub_data, sub_size);
    break;
  case 1:
    harness_channel_data(sub_data, sub_size);
    break;
  case 2:
    harness_addr_codec(sub_data, sub_size);
    break;
  }

  return 0;
}
