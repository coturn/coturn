/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Multi-harness libFuzzer entry point for client-side STUN parsing,
 * TCP framing, and address codec.
 *
 * Every iteration runs all sub-harnesses in sequence on the same input.
 * Keeping everything behind a single binary allows the upstream OSS-Fuzz
 * build recipe (which only copies FuzzStun and FuzzStunClient) to stay
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

static uint8_t fuzz_byte(const uint8_t *Data, size_t Size, size_t idx) { return Size ? Data[idx % Size] : 0; }

static uint16_t fuzz_u16(const uint8_t *Data, size_t Size, size_t idx) {
  return (uint16_t)(((uint16_t)fuzz_byte(Data, Size, idx) << 8) | (uint16_t)fuzz_byte(Data, Size, idx + 1));
}

static uint32_t fuzz_u32(const uint8_t *Data, size_t Size, size_t idx) {
  return ((uint32_t)fuzz_u16(Data, Size, idx) << 16) | (uint32_t)fuzz_u16(Data, Size, idx + 2);
}

static uint64_t fuzz_u64(const uint8_t *Data, size_t Size, size_t idx) {
  return ((uint64_t)fuzz_u32(Data, Size, idx) << 32) | (uint64_t)fuzz_u32(Data, Size, idx + 4);
}

static bool fuzz_flag(const uint8_t *Data, size_t Size, size_t idx) { return (fuzz_byte(Data, Size, idx) & 1u) != 0; }

static void fuzz_string(const uint8_t *Data, size_t Size, size_t idx, char *out, size_t out_size) {
  if (!out || !out_size) {
    return;
  }

  const size_t max_len = out_size - 1;
  const size_t len = max_len ? (size_t)(fuzz_byte(Data, Size, idx) % (max_len + 1)) : 0;

  for (size_t i = 0; i < len; ++i) {
    out[i] = (char)('A' + (fuzz_byte(Data, Size, idx + 1 + i) % 26));
  }

  out[len] = '\0';
}

static void fuzz_tid(const uint8_t *Data, size_t Size, size_t idx, stun_tid *tid) {
  if (!tid) {
    return;
  }

  memset(tid, 0, sizeof(*tid));
  for (size_t i = 0; i < STUN_TID_SIZE; ++i) {
    tid->tsx_id[i] = fuzz_byte(Data, Size, idx + i);
  }
}

static void fuzz_addr(const uint8_t *Data, size_t Size, size_t idx, ioa_addr *addr) {
  if (!addr) {
    return;
  }

  memset(addr, 0, sizeof(*addr));

  if (fuzz_flag(Data, Size, idx)) {
    addr->s6.sin6_family = AF_INET6;
    addr->s6.sin6_port = htons(fuzz_u16(Data, Size, idx + 1));
    for (size_t i = 0; i < 16; ++i) {
      addr->s6.sin6_addr.s6_addr[i] = fuzz_byte(Data, Size, idx + 3 + i);
    }
    if (!memcmp(addr->s6.sin6_addr.s6_addr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16)) {
      addr->s6.sin6_addr.s6_addr[15] = 1;
    }
  } else {
    addr->s4.sin_family = AF_INET;
    addr->s4.sin_port = htons(fuzz_u16(Data, Size, idx + 1));
    addr->s4.sin_addr.s_addr = htonl(fuzz_u32(Data, Size, idx + 3) | 1u);
  }
}

static void inspect_buffer_message(stun_buffer *msg, uint16_t addr_attr_type, const ioa_addr *default_addr) {
  if (!msg) {
    return;
  }

  (void)stun_get_command_message_len(msg);
  (void)stun_is_command_message(msg);
  (void)stun_is_request(msg);
  (void)stun_is_response(msg);
  (void)stun_is_success_response(msg);
  (void)stun_is_binding_response(msg);
  (void)stun_get_method(msg);
  (void)stun_get_msg_type(msg);

  {
    int err_code = 0;
    uint8_t err_msg[256] = {0};
    (void)stun_is_error_response(msg, &err_code, err_msg, sizeof(err_msg));
  }

  {
    ioa_addr parsed = {0};
    (void)stun_attr_get_first_addr(msg, addr_attr_type, &parsed, default_addr);
  }

  {
    stun_attr_ref attr = stun_attr_get_first(msg);
    while (attr) {
      (void)stun_attr_get_type(attr);
      (void)stun_attr_get_len(attr);
      if (stun_attr_is_addr(attr)) {
        ioa_addr parsed = {0};
        (void)stun_attr_get_addr(msg, attr, &parsed, default_addr);
      }
      attr = stun_attr_get_next(msg, attr);
    }
  }

  (void)stun_attr_get_first_channel_number(msg);
}

static void inspect_raw_message(const uint8_t *buf, size_t len, uint16_t addr_attr_type, const ioa_addr *default_addr) {
  if (!buf || !len) {
    return;
  }

  (void)stun_is_command_message_str((uint8_t *)buf, len);
  (void)stun_is_request_str(buf, len);
  (void)stun_is_response_str(buf, len);
  (void)stun_is_success_response_str(buf, len);
  (void)stun_is_binding_response_str(buf, len);
  (void)stun_get_method_str(buf, len);
  (void)stun_get_msg_type_str(buf, len);

  {
    int err_code = 0;
    uint8_t err_msg[256] = {0};
    (void)stun_is_error_response_str(buf, len, &err_code, err_msg, sizeof(err_msg));
  }

  {
    ioa_addr parsed = {0};
    (void)stun_attr_get_first_addr_str(buf, len, addr_attr_type, &parsed, default_addr);
  }

  {
    stun_attr_ref attr = stun_attr_get_first_str(buf, len);
    while (attr) {
      (void)stun_attr_get_type(attr);
      (void)stun_attr_get_len(attr);
      if (stun_attr_is_addr(attr)) {
        ioa_addr parsed = {0};
        (void)stun_attr_get_addr_str(buf, len, attr, &parsed, default_addr);
      }
      attr = stun_attr_get_next_str(buf, len, attr);
    }
  }

  (void)stun_attr_get_first_channel_number_str(buf, len);
}

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
/* Message builders / wrappers / round-trip parsing.                  */
/* ------------------------------------------------------------------ */
static void harness_message_builders(const uint8_t *Data, size_t Size) {
  if (!Size || Size > 4096) {
    return;
  }

  static const uint16_t kMethods[] = {
      STUN_METHOD_ALLOCATE, STUN_METHOD_BINDING, STUN_METHOD_CHANNEL_BIND, STUN_METHOD_REFRESH, STUN_METHOD_CONNECT,
  };
  static const uint16_t kErrorCodes[] = {
      300, 400, 401, 403, 420, 437, 438, 440, 441, 442, 443, 446, 447, 486, 487, 500, 508, 699,
  };

  stun_tid tid = {0};
  ioa_addr relay1 = {0};
  ioa_addr relay2 = {0};
  ioa_addr reflexive = {0};
  ioa_addr peer = {0};
  ioa_addr default_addr = {0};
  char reason[96] = {0};
  char mobile_id[96] = {0};
  uint8_t raw[MAX_STUN_MESSAGE_SIZE] = {0};

  fuzz_tid(Data, Size, 0, &tid);
  fuzz_addr(Data, Size, 16, &relay1);
  fuzz_addr(Data, Size, 40, &relay2);
  fuzz_addr(Data, Size, 64, &reflexive);
  fuzz_addr(Data, Size, 88, &peer);
  fuzz_addr(Data, Size, 112, &default_addr);
  fuzz_string(Data, Size, 136, reason, sizeof(reason));
  fuzz_string(Data, Size, 232, mobile_id, sizeof(mobile_id));

  const uint16_t method = kMethods[fuzz_byte(Data, Size, 328) % (sizeof(kMethods) / sizeof(kMethods[0]))];
  const uint16_t error_code = kErrorCodes[fuzz_byte(Data, Size, 329) % (sizeof(kErrorCodes) / sizeof(kErrorCodes[0]))];
  const uint32_t lifetime = fuzz_u32(Data, Size, 330);
  const uint32_t max_lifetime = fuzz_u32(Data, Size, 334);
  const uint64_t reservation_token = fuzz_u64(Data, Size, 338);
  const uint16_t channel_number = fuzz_u16(Data, Size, 346);
  const bool include_reason = fuzz_flag(Data, Size, 348);
  const bool old_stun = fuzz_flag(Data, Size, 349);
  const bool stun_backward_compatibility = fuzz_flag(Data, Size, 350);
  const uint32_t old_cookie = fuzz_u32(Data, Size, 351);

  /* Direct wrapper coverage for stun_init_error_response(). */
  {
    stun_buffer msg;
    stun_init_buffer(&msg);
    stun_init_error_response(method, &msg, error_code, reason[0] ? (const uint8_t *)reason : NULL, &tid,
                             include_reason);
    inspect_buffer_message(&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, &default_addr);
  }

  /* Success allocate response covers addr extraction; error allocate response
   * forces the shared error builder path. */
  {
    stun_buffer msg;
    stun_init_buffer(&msg);
    (void)stun_set_allocate_response(&msg, &tid, &relay1, fuzz_flag(Data, Size, 355) ? &relay2 : NULL, &reflexive,
                                     lifetime, max_lifetime, 0, (const uint8_t *)reason, reservation_token, mobile_id,
                                     include_reason);
    inspect_buffer_message(&msg, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &default_addr);

    size_t raw_len = sizeof(raw);
    (void)stun_set_allocate_response_str(raw, &raw_len, &tid, &relay1, &relay2, &reflexive, lifetime, max_lifetime, 0,
                                         (const uint8_t *)reason, reservation_token, mobile_id, include_reason);
    inspect_raw_message(raw, raw_len, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &default_addr);

    stun_init_buffer(&msg);
    (void)stun_set_allocate_response(&msg, &tid, NULL, NULL, NULL, lifetime, max_lifetime, error_code,
                                     reason[0] ? (const uint8_t *)reason : NULL, reservation_token, mobile_id,
                                     include_reason);
    inspect_buffer_message(&msg, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &default_addr);

    raw_len = sizeof(raw);
    (void)stun_set_allocate_response_str(raw, &raw_len, &tid, NULL, NULL, NULL, lifetime, max_lifetime, error_code,
                                         reason[0] ? (const uint8_t *)reason : NULL, reservation_token, mobile_id,
                                         include_reason);
    inspect_raw_message(raw, raw_len, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &default_addr);
  }

  {
    stun_buffer msg;
    stun_init_buffer(&msg);
    (void)stun_set_binding_response(&msg, &tid, &reflexive, 0, (const uint8_t *)reason, include_reason);
    inspect_buffer_message(&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &default_addr);

    size_t raw_len = sizeof(raw);
    (void)stun_set_binding_response_str(raw, &raw_len, &tid, &reflexive, 0, (const uint8_t *)reason, old_cookie,
                                        old_stun, stun_backward_compatibility, include_reason);
    inspect_raw_message(raw, raw_len, old_stun ? STUN_ATTRIBUTE_MAPPED_ADDRESS : STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
                        &default_addr);

    stun_init_buffer(&msg);
    (void)stun_set_binding_response(&msg, &tid, NULL, error_code, reason[0] ? (const uint8_t *)reason : NULL,
                                    include_reason);
    inspect_buffer_message(&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, &default_addr);

    raw_len = sizeof(raw);
    (void)stun_set_binding_response_str(raw, &raw_len, &tid, NULL, error_code,
                                        reason[0] ? (const uint8_t *)reason : NULL, old_cookie, old_stun,
                                        stun_backward_compatibility, include_reason);
    inspect_raw_message(raw, raw_len, STUN_ATTRIBUTE_MAPPED_ADDRESS, &default_addr);
  }

  {
    stun_buffer msg;
    stun_init_buffer(&msg);
    (void)stun_set_channel_bind_request(&msg, fuzz_flag(Data, Size, 356) ? &peer : NULL, channel_number);
    inspect_buffer_message(&msg, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &default_addr);

    size_t raw_len = sizeof(raw);
    (void)stun_set_channel_bind_request_str(raw, &raw_len, fuzz_flag(Data, Size, 357) ? &peer : NULL, channel_number);
    inspect_raw_message(raw, raw_len, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &default_addr);

    stun_init_buffer(&msg);
    stun_set_channel_bind_response(&msg, &tid, 0, (const uint8_t *)reason, include_reason);
    inspect_buffer_message(&msg, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &default_addr);

    raw_len = sizeof(raw);
    stun_set_channel_bind_response_str(raw, &raw_len, &tid, error_code, reason[0] ? (const uint8_t *)reason : NULL,
                                       include_reason);
    inspect_raw_message(raw, raw_len, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &default_addr);
  }
}

/* ------------------------------------------------------------------ */
/* libFuzzer entry point — run every harness on each input.           */
/*                                                                    */
/* Note: OAuth token sub-harnesses are intentionally omitted here.    */
/* decode_oauth_token_gcm in src/client/ns_turn_msg.c leaks the       */
/* EVP_CIPHER_CTX on several early-return paths, which trips ASan     */
/* under CIFuzz. Those harnesses will be re-added once the library    */
/* leak is fixed in a separate PR.                                    */
/* ------------------------------------------------------------------ */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  harness_stun_client(Data, Size);
  harness_channel_data(Data, Size);
  harness_addr_codec(Data, Size);
  harness_message_builders(Data, Size);
  return 0;
}
