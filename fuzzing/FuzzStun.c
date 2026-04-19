/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Multi-harness libFuzzer entry point for server-side STUN parsing.
 *
 * Every iteration runs all sub-harnesses in sequence on the same input:
 * RFC 5769 integrity checks, multi-SHA/credential integrity, attribute
 * iteration, attribute serialization, and legacy (pre-RFC 5389) STUN
 * detection. Keeping everything behind a single binary allows the
 * upstream OSS-Fuzz build recipe to stay unchanged.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "apputils.h"
#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"
#include "ns_turn_utils.h"
#include "stun_buffer.h"

/* ------------------------------------------------------------------ */
/* Integrity: SHA1 short-term + SHA256 long-term (original FuzzStun). */
/* ------------------------------------------------------------------ */
static void harness_integrity_sha1(const uint8_t *Data, size_t Size) {
  if (Size < 10 || Size > 5120) {
    return;
  }

  stun_is_command_message_full_check_str((uint8_t *)Data, Size, 1, NULL);

  uint8_t uname[STUN_MAX_USERNAME_SIZE + 1] = "fuzzuser";
  uint8_t realm[STUN_MAX_REALM_SIZE + 1] = "fuzz.realm";
  uint8_t upwd[STUN_MAX_PWD_SIZE + 1] = "VOkJxbRl1RmTxUk/WvJxBt";

  stun_check_message_integrity_str(TURN_CREDENTIALS_SHORT_TERM, (uint8_t *)Data, Size, uname, realm, upwd,
                                   SHATYPE_SHA1);
  stun_check_message_integrity_str(TURN_CREDENTIALS_LONG_TERM, (uint8_t *)Data, Size, uname, realm, upwd,
                                   SHATYPE_SHA256);
}

/* ------------------------------------------------------------------ */
/* Integrity across all SHA types + credential modes (FuzzStunIntegrity). */
/* ------------------------------------------------------------------ */
static void harness_integrity_multi(const uint8_t *Data, size_t Size) {
  if (Size < STUN_HEADER_LENGTH || Size > 5120) {
    return;
  }

  uint8_t buf[5120];
  uint8_t uname[STUN_MAX_USERNAME_SIZE + 1] = "fuzzuser";
  uint8_t realm[STUN_MAX_REALM_SIZE + 1] = "fuzz.realm";
  uint8_t upwd[STUN_MAX_PWD_SIZE + 1] = "VOkJxbRl1RmTxUk/WvJxBt";

  static const SHATYPE sha_types[] = {SHATYPE_SHA1, SHATYPE_SHA256, SHATYPE_SHA384, SHATYPE_SHA512};
  const size_t num_sha = sizeof(sha_types) / sizeof(sha_types[0]);

  for (size_t s = 0; s < num_sha; s++) {
    memcpy(buf, Data, Size);
    stun_is_command_message_full_check_str(buf, Size, 1, NULL);
    stun_check_message_integrity_str(TURN_CREDENTIALS_SHORT_TERM, buf, Size, uname, realm, upwd, sha_types[s]);

    memcpy(buf, Data, Size);
    stun_check_message_integrity_str(TURN_CREDENTIALS_LONG_TERM, buf, Size, uname, realm, upwd, sha_types[s]);
  }
}

/* ------------------------------------------------------------------ */
/* Attribute TLV iteration + typed extraction (FuzzStunAttrIter).     */
/* ------------------------------------------------------------------ */
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

static const uint16_t kAddrAttrs[] = {
    STUN_ATTRIBUTE_MAPPED_ADDRESS,   STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,  OLD_STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
    STUN_ATTRIBUTE_XOR_PEER_ADDRESS, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, STUN_ATTRIBUTE_ALTERNATE_SERVER,
    STUN_ATTRIBUTE_RESPONSE_ORIGIN,  STUN_ATTRIBUTE_OTHER_ADDRESS,
};

static void harness_attr_iter(const uint8_t *Data, size_t Size) {
  if (Size < STUN_HEADER_LENGTH || Size > 8192) {
    return;
  }

  uint8_t buf[8192];
  memcpy(buf, Data, Size);

  if (!stun_is_command_message_str(buf, Size)) {
    return;
  }

  stun_attr_ref sar = stun_attr_get_first_str(buf, Size);
  while (sar) {
    (void)stun_attr_get_type(sar);
    (void)stun_attr_get_len(sar);
    (void)stun_attr_get_value(sar);
    (void)stun_attr_is_addr(sar);
    sar = stun_attr_get_next_str(buf, Size, sar);
  }

  ioa_addr addr;
  const size_t num_addr_attrs = sizeof(kAddrAttrs) / sizeof(kAddrAttrs[0]);
  for (size_t i = 0; i < num_addr_attrs; i++) {
    sar = stun_attr_get_first_by_type_str(buf, Size, kAddrAttrs[i]);
    if (sar) {
      memset(&addr, 0, sizeof(addr));
      stun_attr_get_addr_str(buf, Size, sar, &addr, NULL);
    }
    memset(&addr, 0, sizeof(addr));
    stun_attr_get_first_addr_str(buf, Size, kAddrAttrs[i], &addr, NULL);
  }

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_CHANNEL_NUMBER);
  if (sar) {
    (void)stun_attr_get_channel_number(sar);
  }
  (void)stun_attr_get_first_channel_number_str(buf, Size);

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY);
  if (sar) {
    (void)stun_get_requested_address_family(sar);
  }

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY);
  if (sar) {
    (void)stun_get_requested_address_family(sar);
  }

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_EVEN_PORT);
  if (sar) {
    (void)stun_attr_get_even_port(sar);
  }

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_BANDWIDTH);
  if (sar) {
    (void)stun_attr_get_bandwidth(sar);
  }

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_NEW_BANDWIDTH);
  if (sar) {
    (void)stun_attr_get_bandwidth(sar);
  }

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_RESERVATION_TOKEN);
  if (sar) {
    (void)stun_attr_get_reservation_token_value(sar);
  }

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_CHANGE_REQUEST);
  if (sar) {
    bool change_ip = false, change_port = false;
    stun_attr_get_change_request_str(sar, &change_ip, &change_port);
  }

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_RESPONSE_PORT);
  if (sar) {
    (void)stun_attr_get_response_port_str(sar);
  }

  sar = stun_attr_get_first_by_type_str(buf, Size, STUN_ATTRIBUTE_PADDING);
  if (sar) {
    (void)stun_attr_get_padding_len_str(sar);
  }

  {
    int err_code = 0;
    uint8_t err_msg[1024] = {0};
    stun_is_error_response_str(buf, Size, &err_code, err_msg, sizeof(err_msg));
  }
  {
    int err_code = 0;
    uint8_t err_msg[1024] = {0};
    uint8_t chal_realm[STUN_MAX_REALM_SIZE + 1] = {0};
    uint8_t chal_nonce[STUN_MAX_NONCE_SIZE + 1] = {0};
    uint8_t server_name[STUN_MAX_SERVER_NAME_SIZE + 1] = {0};
    bool oauth = false;
    stun_is_challenge_response_str(buf, Size, &err_code, err_msg, sizeof(err_msg), chal_realm, chal_nonce, server_name,
                                   &oauth);
  }

  const size_t num_all_attrs = sizeof(kAllAttrTypes) / sizeof(kAllAttrTypes[0]);
  for (size_t i = 0; i < num_all_attrs; i++) {
    sar = stun_attr_get_first_by_type_str(buf, Size, kAllAttrTypes[i]);
    if (sar) {
      (void)stun_attr_get_type(sar);
      (void)stun_attr_get_len(sar);
      (void)stun_attr_get_value(sar);
    }
  }
}

/* ------------------------------------------------------------------ */
/* Attribute serialization / append paths (FuzzStunAttrAdd).          */
/* ------------------------------------------------------------------ */
static void harness_attr_add(const uint8_t *Data, size_t Size) {
  if (Size < STUN_HEADER_LENGTH || Size > 4096) {
    return;
  }

  uint8_t buf[MAX_STUN_MESSAGE_SIZE] = {0};
  memcpy(buf, Data, Size);
  size_t len = Size;

  if (!stun_is_command_message_str(buf, len)) {
    return;
  }

  uint8_t test_uname[] = "fuzzuser@fuzz.realm";
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_USERNAME, test_uname, (int)(sizeof(test_uname) - 1));

  uint8_t test_realm[] = "fuzz.realm";
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_REALM, test_realm, (int)(sizeof(test_realm) - 1));

  uint8_t test_nonce[] = "fuzznonce0123456789abcdef";
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_NONCE, test_nonce, (int)(sizeof(test_nonce) - 1));

  uint8_t test_sw[] = "coturn-fuzz/1.0";
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_SOFTWARE, test_sw, (int)(sizeof(test_sw) - 1));

  uint8_t lifetime_val[4] = {0x00, 0x00, 0x02, 0x58};
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_LIFETIME, lifetime_val, 4);

  uint8_t transport_val[4] = {STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE, 0x00, 0x00, 0x00};
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_REQUESTED_TRANSPORT, transport_val, 4);

  uint8_t af_val[4] = {STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4, 0x00, 0x00, 0x00};
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY, af_val, 4);

  uint8_t even_port_val[1] = {0x80};
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_EVEN_PORT, even_port_val, 1);

  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);

  stun_attr_add_channel_number_str(buf, &len, 0x4001);

  stun_attr_add_bandwidth_str(buf, &len, 1000000);

  ioa_addr addr4 = {0};
  addr4.s4.sin_family = AF_INET;
  addr4.s4.sin_port = htons(12345);
  addr4.s4.sin_addr.s_addr = htonl(0xC0A80001);
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &addr4);
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &addr4);
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &addr4);
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_MAPPED_ADDRESS, &addr4);

  ioa_addr addr6 = {0};
  addr6.s6.sin6_family = AF_INET6;
  addr6.s6.sin6_port = htons(54321);
  addr6.s6.sin6_addr.s6_addr[15] = 1;
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &addr6);
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &addr6);

  stun_attr_add_address_error_code(buf, &len, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6, 440);

  stun_attr_add_change_request_str(buf, &len, true, true);
  stun_attr_add_response_port_str(buf, &len, 3479);
  stun_attr_add_padding_str(buf, &len, 64);

  if (Size > STUN_HEADER_LENGTH + 4) {
    int data_len = (int)(Size - STUN_HEADER_LENGTH);
    if (data_len > 1024) {
      data_len = 1024;
    }
    stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_DATA, Data + STUN_HEADER_LENGTH, data_len);
  }

  stun_attr_add_fingerprint_str(buf, &len);
}

/* ------------------------------------------------------------------ */
/* Legacy (pre-RFC 5389) STUN detection (FuzzOldStun).                */
/* ------------------------------------------------------------------ */
static void harness_old_stun(const uint8_t *Data, size_t Size) {
  if (Size < STUN_HEADER_LENGTH || Size > 5120) {
    return;
  }

  uint8_t buf[5120];
  memcpy(buf, Data, Size);

  uint32_t cookie = 0;
  bool is_old = old_stun_is_command_message_str(buf, Size, &cookie);
  (void)stun_is_command_message_str(buf, Size);

  if (is_old) {
    (void)stun_get_msg_type_str(buf, Size);
    (void)stun_get_method_str(buf, Size);

    stun_is_request_str(buf, Size);
    stun_is_indication_str(buf, Size);
    stun_is_success_response_str(buf, Size);

    int err_code = 0;
    uint8_t err_msg[256] = {0};
    stun_is_error_response_str(buf, Size, &err_code, err_msg, sizeof(err_msg));

    int fp_present = 0;
    stun_is_command_message_full_check_str(buf, Size, 1, &fp_present);
    stun_is_command_message_full_check_str(buf, Size, 0, &fp_present);

    stun_is_binding_request_str(buf, Size, 0);
    stun_is_binding_response_str(buf, Size);

    stun_attr_ref sar = stun_attr_get_first_str(buf, Size);
    while (sar) {
      (void)stun_attr_get_type(sar);
      (void)stun_attr_get_len(sar);
      sar = stun_attr_get_next_str(buf, Size, sar);
    }
  }
}

/* ------------------------------------------------------------------ */
/* libFuzzer entry point — run every harness on each input.           */
/* ------------------------------------------------------------------ */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  harness_integrity_sha1(Data, Size);
  harness_integrity_multi(Data, Size);
  harness_attr_iter(Data, Size);
  harness_attr_add(Data, Size);
  harness_old_stun(Data, Size);
  return 0;
}
