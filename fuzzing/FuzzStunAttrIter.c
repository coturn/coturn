/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Fuzzing target for STUN attribute TLV iteration and typed extraction.
 *
 * Exercises the attribute iterator and every per-type accessor against
 * arbitrary input, catching OOB reads in the TLV chain, address XOR
 * decoding, and value extraction for all defined attribute types.
 */

#include <stdint.h>
#include <string.h>

#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"

#define kMinInputLength STUN_HEADER_LENGTH
#define kMaxInputLength 8192

/* Every attribute type defined in coturn */
static const uint16_t kAllAttrTypes[] = {
    STUN_ATTRIBUTE_MAPPED_ADDRESS,
    OLD_STUN_ATTRIBUTE_RESPONSE_ADDRESS,
    STUN_ATTRIBUTE_CHANGE_REQUEST,
    OLD_STUN_ATTRIBUTE_SOURCE_ADDRESS,
    OLD_STUN_ATTRIBUTE_CHANGED_ADDRESS,
    STUN_ATTRIBUTE_USERNAME,
    OLD_STUN_ATTRIBUTE_PASSWORD,
    STUN_ATTRIBUTE_MESSAGE_INTEGRITY,
    STUN_ATTRIBUTE_ERROR_CODE,
    STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES,
    OLD_STUN_ATTRIBUTE_REFLECTED_FROM,
    STUN_ATTRIBUTE_CHANNEL_NUMBER,
    STUN_ATTRIBUTE_LIFETIME,
    STUN_ATTRIBUTE_BANDWIDTH,
    STUN_ATTRIBUTE_XOR_PEER_ADDRESS,
    STUN_ATTRIBUTE_DATA,
    STUN_ATTRIBUTE_REALM,
    STUN_ATTRIBUTE_NONCE,
    STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,
    STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY,
    STUN_ATTRIBUTE_EVEN_PORT,
    STUN_ATTRIBUTE_REQUESTED_TRANSPORT,
    STUN_ATTRIBUTE_DONT_FRAGMENT,
    STUN_ATTRIBUTE_OAUTH_ACCESS_TOKEN,
    STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    OLD_STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_TIMER_VAL,
    STUN_ATTRIBUTE_RESERVATION_TOKEN,
    STUN_ATTRIBUTE_PRIORITY,
    STUN_ATTRIBUTE_PADDING,
    STUN_ATTRIBUTE_RESPONSE_PORT,
    STUN_ATTRIBUTE_CONNECTION_ID,
    STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY,
    STUN_ATTRIBUTE_ADDRESS_ERROR_CODE,
    STUN_ATTRIBUTE_SOFTWARE,
    STUN_ATTRIBUTE_ALTERNATE_SERVER,
    STUN_ATTRIBUTE_FINGERPRINT,
    STUN_ATTRIBUTE_ICE_CONTROLLED,
    STUN_ATTRIBUTE_RESPONSE_ORIGIN,
    STUN_ATTRIBUTE_OTHER_ADDRESS,
    STUN_ATTRIBUTE_THIRD_PARTY_AUTHORIZATION,
    STUN_ATTRIBUTE_ORIGIN,
    STUN_ATTRIBUTE_MOBILITY_TICKET,
    STUN_ATTRIBUTE_NEW_BANDWIDTH,
};

#define kNumAttrTypes (sizeof(kAllAttrTypes) / sizeof(kAllAttrTypes[0]))

/* All address-type attributes that use XOR or plain address encoding */
static const uint16_t kAddrAttrs[] = {
    STUN_ATTRIBUTE_MAPPED_ADDRESS,   STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,  OLD_STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_XOR_PEER_ADDRESS, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, STUN_ATTRIBUTE_ALTERNATE_SERVER,
    STUN_ATTRIBUTE_RESPONSE_ORIGIN,  STUN_ATTRIBUTE_OTHER_ADDRESS,
};

#define kNumAddrAttrs (sizeof(kAddrAttrs) / sizeof(kAddrAttrs[0]))

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 0;
  }

  uint8_t buf[kMaxInputLength];
  memcpy(buf, Data, Size);

  /* Gate on valid STUN envelope so the fuzzer focuses on attribute internals */
  if (!stun_is_command_message_str(buf, Size)) {
    return 0;
  }

  /* Phase 1: iterate all attributes via the TLV chain */
  stun_attr_ref sar = stun_attr_get_first_str(buf, Size);
  while (sar) {
    int attr_type = stun_attr_get_type(sar);
    int attr_len = stun_attr_get_len(sar);
    const uint8_t *attr_val = stun_attr_get_value(sar);
    bool is_addr = stun_attr_is_addr(sar);
    (void)attr_type;
    (void)attr_len;
    (void)attr_val;
    (void)is_addr;

    sar = stun_attr_get_next_str(buf, Size, sar);
  }

  /* Phase 2: extract typed values for address attributes */
  ioa_addr addr;
  for (size_t i = 0; i < kNumAddrAttrs; i++) {
    sar = stun_attr_get_first_by_type_str(buf, Size, kAddrAttrs[i]);
    if (sar) {
      memset(&addr, 0, sizeof(addr));
      stun_attr_get_addr_str(buf, Size, sar, &addr, NULL);
    }
    /* Also test the combined find+decode helper */
    memset(&addr, 0, sizeof(addr));
    stun_attr_get_first_addr_str(buf, Size, kAddrAttrs[i], &addr, NULL);
  }

  /* Phase 3: scalar attribute extractors */

  /* Channel number */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_CHANNEL_NUMBER);
  if (sar) {
    uint16_t chn = stun_attr_get_channel_number(sar);
    (void)chn;
  }
  /* Also via the first-channel helper */
  {
    uint16_t first_chn = stun_attr_get_first_channel_number_str(buf, Size);
    (void)first_chn;
  }

  /* Requested address family */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY);
  if (sar) {
    int fam = stun_get_requested_address_family(sar);
    (void)fam;
  }

  /* Additional address family (RFC 8656) */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY);
  if (sar) {
    int fam = stun_get_requested_address_family(sar);
    (void)fam;
  }

  /* Even port */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_EVEN_PORT);
  if (sar) {
    uint8_t ep = stun_attr_get_even_port(sar);
    (void)ep;
  }

  /* Bandwidth */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_BANDWIDTH);
  if (sar) {
    band_limit_t bw = stun_attr_get_bandwidth(sar);
    (void)bw;
  }

  /* New bandwidth (experimental) */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_NEW_BANDWIDTH);
  if (sar) {
    band_limit_t bw = stun_attr_get_bandwidth(sar);
    (void)bw;
  }

  /* Reservation token */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_RESERVATION_TOKEN);
  if (sar) {
    uint64_t tok = stun_attr_get_reservation_token_value(sar);
    (void)tok;
  }

  /* RFC 5780: CHANGE-REQUEST */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_CHANGE_REQUEST);
  if (sar) {
    bool change_ip = false, change_port = false;
    stun_attr_get_change_request_str(sar, &change_ip, &change_port);
  }

  /* RFC 5780: RESPONSE-PORT */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_RESPONSE_PORT);
  if (sar) {
    int rport = stun_attr_get_response_port_str(sar);
    (void)rport;
  }

  /* RFC 5780: PADDING */
  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_PADDING);
  if (sar) {
    int pad_len = stun_attr_get_padding_len_str(sar);
    (void)pad_len;
  }

  /* Phase 4: error response parsing */
  {
    int err_code = 0;
    uint8_t err_msg[1024] = {0};
    stun_is_error_response_str(buf, Size, &err_code, err_msg, sizeof(err_msg));
  }

  /* Challenge response parsing (401/438 with realm+nonce) */
  {
    int err_code = 0;
    uint8_t err_msg[1024] = {0};
    uint8_t realm[STUN_MAX_REALM_SIZE + 1] = {0};
    uint8_t nonce[STUN_MAX_NONCE_SIZE + 1] = {0};
    uint8_t server_name[STUN_MAX_SERVER_NAME_SIZE + 1] = {0};
    bool oauth = false;
    stun_is_challenge_response_str(buf, Size, &err_code, err_msg, sizeof(err_msg), realm, nonce, server_name, &oauth);
  }

  /* Phase 5: search for every defined attribute type */
  for (size_t i = 0; i < kNumAttrTypes; i++) {
    sar = stun_attr_get_first_by_type_str(buf, Size, kAllAttrTypes[i]);
    if (sar) {
      (void)stun_attr_get_type(sar);
      (void)stun_attr_get_len(sar);
      (void)stun_attr_get_value(sar);
    }
  }

  return 0;
}
