/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Fuzzing target for STUN attribute serialization.
 *
 * Exercises stun_attr_add_str(), stun_attr_add_addr_str(), and related
 * serialization functions by treating fuzz input as a partial STUN message
 * and attempting to append various attribute types.  Tests buffer bounds
 * checking in the write path.
 */

#include <stdint.h>
#include <string.h>

#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"

#define kMinInputLength STUN_HEADER_LENGTH
#define kMaxInputLength 4096

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size < kMinInputLength || Size > kMaxInputLength) {
    return 0;
  }

  /* Large buffer to allow room for appending attributes */
  uint8_t buf[MAX_STUN_MESSAGE_SIZE] = {0};
  memcpy(buf, Data, Size);
  size_t len = Size;

  if (!stun_is_command_message_str(buf, len)) {
    return 0;
  }

  /* String attribute (USERNAME) */
  uint8_t test_uname[] = "fuzzuser@fuzz.realm";
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_USERNAME, test_uname, (int)(sizeof(test_uname) - 1));

  /* String attribute (REALM) */
  uint8_t test_realm[] = "fuzz.realm";
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_REALM, test_realm, (int)(sizeof(test_realm) - 1));

  /* String attribute (NONCE) */
  uint8_t test_nonce[] = "fuzznonce0123456789abcdef";
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_NONCE, test_nonce, (int)(sizeof(test_nonce) - 1));

  /* String attribute (SOFTWARE) */
  uint8_t test_sw[] = "coturn-fuzz/1.0";
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_SOFTWARE, test_sw, (int)(sizeof(test_sw) - 1));

  /* 4-byte attribute (LIFETIME) */
  uint8_t lifetime_val[4] = {0x00, 0x00, 0x02, 0x58}; /* 600 seconds */
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_LIFETIME, lifetime_val, 4);

  /* 4-byte attribute (REQUESTED-TRANSPORT) */
  uint8_t transport_val[4] = {STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE, 0x00, 0x00, 0x00};
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_REQUESTED_TRANSPORT, transport_val, 4);

  /* 4-byte attribute (REQUESTED-ADDRESS-FAMILY) */
  uint8_t af_val[4] = {STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4, 0x00, 0x00, 0x00};
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY, af_val, 4);

  /* 1-byte attribute (EVEN-PORT) */
  uint8_t even_port_val[1] = {0x80}; /* R bit set */
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_EVEN_PORT, even_port_val, 1);

  /* 0-byte attribute (DONT-FRAGMENT) */
  stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);

  /* Channel number */
  stun_attr_add_channel_number_str(buf, &len, 0x4001);

  /* Bandwidth */
  stun_attr_add_bandwidth_str(buf, &len, 1000000);

  /* Address attribute - IPv4 */
  ioa_addr addr4;
  memset(&addr4, 0, sizeof(addr4));
  addr4.s4.sin_family = AF_INET;
  addr4.s4.sin_port = htons(12345);
  addr4.s4.sin_addr.s_addr = htonl(0xC0A80001); /* 192.168.0.1 */
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &addr4);
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &addr4);
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &addr4);
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_MAPPED_ADDRESS, &addr4);

  /* Address attribute - IPv6 */
  ioa_addr addr6;
  memset(&addr6, 0, sizeof(addr6));
  addr6.s6.sin6_family = AF_INET6;
  addr6.s6.sin6_port = htons(54321);
  /* ::1 */
  addr6.s6.sin6_addr.s6_addr[15] = 1;
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &addr6);
  stun_attr_add_addr_str(buf, &len, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &addr6);

  /* Address error code (RFC 8656) */
  stun_attr_add_address_error_code(buf, &len, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6, 440);

  /* RFC 5780 attributes */
  stun_attr_add_change_request_str(buf, &len, true, true);
  stun_attr_add_response_port_str(buf, &len, 3479);
  stun_attr_add_padding_str(buf, &len, 64);

  /* DATA attribute with fuzz payload */
  if (Size > STUN_HEADER_LENGTH + 4) {
    int data_len = (int)(Size - STUN_HEADER_LENGTH);
    if (data_len > 1024) {
      data_len = 1024;
    }
    stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_DATA, Data + STUN_HEADER_LENGTH, data_len);
  }

  /* Fingerprint - must be last */
  stun_attr_add_fingerprint_str(buf, &len);

  return 0;
}
