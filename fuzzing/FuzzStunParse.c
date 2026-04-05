/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Fuzzing target for STUN attribute parsing.
 *
 * Constructs a valid STUN header from fuzz-controlled message type and
 * transaction ID, then feeds the remaining bytes as raw TLV attributes
 * into the parsing and address extraction functions.
 */

#include <stdint.h>
#include <string.h>

#include "ns_turn_msg.h"

#define kMinInputLength 16
#define kMaxInputLength 4096

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 0;
  }

  /* consume first 2 bytes as message type, next 12 as transaction ID,
   * remainder as raw STUN attributes */
  uint16_t msg_type = (Data[0] & 0x3F) << 8 | Data[1];
  const uint8_t *txid = Data + 2;
  const uint8_t *attr_data = Data + 14;
  size_t attr_len = (Size - 14) & ~(size_t)3u; /* 4-byte aligned per STUN spec */
  if (attr_len == 0) {
    return 0;
  }

  uint8_t buf[STUN_HEADER_LENGTH + kMaxInputLength];
  size_t total = STUN_HEADER_LENGTH + attr_len;

  /* build valid STUN header */
  buf[0] = (msg_type >> 8) & 0x3F;
  buf[1] = msg_type & 0xFF;
  uint16_t net_len = nswap16((uint16_t)attr_len);
  memcpy(buf + 2, &net_len, 2);
  buf[4] = 0x21;
  buf[5] = 0x12;
  buf[6] = 0xA4;
  buf[7] = 0x42;
  memcpy(buf + 8, txid, 12);

  memcpy(buf + STUN_HEADER_LENGTH, attr_data, attr_len);

  int fp = 0;
  if (!stun_is_command_message_full_check_str(buf, total, 0, &fp)) {
    return 0;
  }

  /* walk all attributes */
  stun_attr_ref attr = stun_attr_get_first_str(buf, total);
  while (attr) {
    stun_attr_get_type(attr);
    stun_attr_get_len(attr);
    attr = stun_attr_get_next_str(buf, total, attr);
  }

  /* address extraction */
  ioa_addr ca;
  memset(&ca, 0, sizeof(ca));
  ioa_addr default_addr;
  memset(&default_addr, 0, sizeof(default_addr));
  default_addr.ss.sa_family = AF_INET;

  stun_attr_get_first_addr_str(buf, total, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &ca, &default_addr);
  stun_attr_get_first_addr_str(buf, total, STUN_ATTRIBUTE_MAPPED_ADDRESS, &ca, &default_addr);
  stun_attr_get_first_addr_str(buf, total, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &ca, &default_addr);
  stun_attr_get_first_addr_str(buf, total, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &ca, &default_addr);

  /* also try with IPv6 default */
  default_addr.ss.sa_family = AF_INET6;
  stun_attr_get_first_addr_str(buf, total, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &ca, &default_addr);

  /* error and challenge response parsing */
  int err_code = 0;
  uint8_t err_msg[256];
  stun_is_error_response_str(buf, total, &err_code, err_msg, sizeof(err_msg));

  uint8_t realm[STUN_MAX_REALM_SIZE + 1];
  uint8_t nonce[STUN_MAX_NONCE_SIZE + 1];
  uint8_t server_name[STUN_MAX_SERVER_NAME_SIZE + 1];
  bool oauth = false;
  stun_is_challenge_response_str(buf, total, &err_code, err_msg, sizeof(err_msg), realm, nonce, server_name, &oauth);

  stun_attr_get_first_channel_number_str(buf, total);

  return 0;
}
