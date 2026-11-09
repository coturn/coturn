/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * RFC 8489 password algorithms: the SHA-256 long-term key, MESSAGE-INTEGRITY-SHA256, the nonce cookie and the
 * bid-down checks. Expected values come from the RFC 8489 Appendix B.1 vector or directly from OpenSSL.
 */

#include "ns_turn_ioaddr.h"
#include "ns_turn_msg.h"
#include "ns_turn_msg_defs.h"

#include <unity.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdint.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* RFC 8489 Appendix B.1 as corrected by Verified Erratum 6268: header Length 0x0090 (the printed 0x009c is the whole
   message size), PASSWORD-ALGORITHM (SHA-256) added, and the MESSAGE-INTEGRITY-SHA256 recomputed. */
static const uint8_t B1_MSG[] = {
    0x00, 0x01, 0x00, 0x90, 0x21, 0x12, 0xa4, 0x42, 0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41,
    0x2e, 0x00, 0x1e, 0x00, 0x20, 0x4a, 0x3c, 0xf3, 0x8f, 0xef, 0x69, 0x92, 0xbd, 0xa9, 0x52, 0xc6, 0x78, 0x04, 0x17,
    0xda, 0x0f, 0x24, 0x81, 0x94, 0x15, 0x56, 0x9e, 0x60, 0xb2, 0x05, 0xc4, 0x6e, 0x41, 0x40, 0x7f, 0x17, 0x04, 0x00,
    0x15, 0x00, 0x29, 0x6f, 0x62, 0x4d, 0x61, 0x74, 0x4a, 0x6f, 0x73, 0x32, 0x41, 0x41, 0x41, 0x43, 0x66, 0x2f, 0x2f,
    0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36, 0x4f, 0x4c, 0x33, 0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54,
    0x76, 0x79, 0x36, 0x34, 0x73, 0x41, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
    0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x1d, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x20, 0xb5,
    0xc7, 0xbf, 0x00, 0x5b, 0x6c, 0x52, 0xa2, 0x1c, 0x51, 0xc5, 0xe8, 0x92, 0xf8, 0x19, 0x24, 0x13, 0x62, 0x96, 0xcb,
    0x92, 0x7c, 0x43, 0x14, 0x93, 0x09, 0x27, 0x8c, 0xc6, 0x51, 0x8e, 0x65};

/* U+30DE U+30C8 U+30EA U+30C3 U+30AF U+30B9; OpaqueString leaves it unchanged. */
static const uint8_t B1_USER[] = "\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9";
/* The password after OpaqueString ("The\xc2\xad" "M\xc2\xaa" "tr\xe2\x85\xa8" prepares to this). */
static const uint8_t B1_PWD[] = "TheMatrIX";
static const uint8_t B1_REALM[] = "example.org";

static const uint8_t KEY[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

static void test_b1_sha256_key_and_integrity(void) {
  hmackey_t key = {0};
  TEST_ASSERT_TRUE(turn_produce_password_key(TURN_PASSWORD_ALG_SHA256, B1_USER, B1_REALM, B1_PWD, key));

  /* The key is a plain SHA-256 of "username:realm:password". */
  uint8_t expected[32] = {0};
  unsigned int el = 0;
  const char *str = "\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9:example.org:TheMatrIX";
  TEST_ASSERT_TRUE(EVP_Digest(str, strlen(str), expected, &el, EVP_sha256(), NULL));
  TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, key, 32);

  /* The corrected vector verifies through the production verifier, and fails with a wrong key or a flipped bit. */
  uint8_t msg[sizeof(B1_MSG)];
  memcpy(msg, B1_MSG, sizeof(msg));
  TEST_ASSERT_EQUAL_INT(
      1, turn_check_integrity_attr_key_len_str(STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256, msg, sizeof(msg), key, 32));
  TEST_ASSERT_EQUAL_INT(
      0, turn_check_integrity_attr_key_len_str(STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256, msg, sizeof(msg), KEY, 32));
  msg[40] ^= 1;
  TEST_ASSERT_EQUAL_INT(
      0, turn_check_integrity_attr_key_len_str(STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256, msg, sizeof(msg), key, 32));
}

static void test_md5_key_is_16_bytes(void) {
  hmackey_t key = {0};
  TEST_ASSERT_TRUE(turn_produce_password_key(TURN_PASSWORD_ALG_MD5, (const uint8_t *)"user", (const uint8_t *)"realm",
                                             (const uint8_t *)"pass", key));
  uint8_t expected[16] = {0};
  unsigned int el = 0;
  TEST_ASSERT_TRUE(EVP_Digest("user:realm:pass", 15, expected, &el, EVP_md5(), NULL));
  TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, key, 16);
  TEST_ASSERT_EQUAL_size_t(16, turn_password_alg_key_size(TURN_PASSWORD_ALG_MD5));
  TEST_ASSERT_EQUAL_size_t(32, turn_password_alg_key_size(TURN_PASSWORD_ALG_SHA256));
}

/* Rebuild the B.1 request with a consistent header and check it with the library, both integrity types and both
   key lengths. */
static void build_signed(uint8_t *buf, size_t *len, uint16_t attr, const uint8_t *key, size_t key_len) {
  *len = 0;
  stun_init_request_str(STUN_METHOD_ALLOCATE, buf, len);
  TEST_ASSERT_TRUE(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_USERNAME, B1_USER, (int)strlen((const char *)B1_USER)));
  TEST_ASSERT_TRUE(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_REALM, B1_REALM, (int)strlen((const char *)B1_REALM)));
  TEST_ASSERT_TRUE(turn_attr_add_integrity_attr_key_len_str(attr, buf, len, key, key_len));
}

static void test_integrity_attr_roundtrip_and_type_binding(void) {
  const uint16_t attrs[2] = {STUN_ATTRIBUTE_MESSAGE_INTEGRITY, STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256};
  const size_t key_lens[2] = {16, 32};
  for (int a = 0; a < 2; ++a) {
    for (int k = 0; k < 2; ++k) {
      uint8_t buf[512] = {0};
      size_t len = 0;
      build_signed(buf, &len, attrs[a], KEY, key_lens[k]);
      TEST_ASSERT_EQUAL_UINT16(attrs[a], turn_request_integrity_attr(buf, len));
      TEST_ASSERT_EQUAL_INT(1, turn_check_integrity_attr_key_len_str(attrs[a], buf, len, KEY, key_lens[k]));
      /* Wrong key length, and the other attribute type, do not verify. */
      TEST_ASSERT_NOT_EQUAL_INT(1, turn_check_integrity_attr_key_len_str(attrs[a], buf, len, KEY, key_lens[1 - k]));
      TEST_ASSERT_NOT_EQUAL_INT(1, turn_check_integrity_attr_key_len_str(attrs[1 - a], buf, len, KEY, key_lens[k]));
    }
  }
}

static void test_sha256_integrity_value_matches_openssl(void) {
  uint8_t buf[512] = {0};
  size_t len = 0;
  build_signed(buf, &len, STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256, KEY, 32);
  uint8_t mac[32] = {0};
  unsigned int ml = 0;
  TEST_ASSERT_NOT_NULL(HMAC(EVP_sha256(), KEY, 32, buf, len - 36, mac, &ml));
  TEST_ASSERT_EQUAL_HEX8_ARRAY(mac, buf + len - 32, 32);
}

static void test_fingerprint_after_integrity_sha256(void) {
  uint8_t buf[512] = {0};
  size_t len = 0;
  build_signed(buf, &len, STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256, KEY, 32);
  TEST_ASSERT_TRUE(stun_attr_add_fingerprint_str(buf, &len));
  bool fp = false;
  TEST_ASSERT_TRUE(stun_is_command_message_full_check_str(buf, len, true, &fp));
  TEST_ASSERT_TRUE(fp);
  TEST_ASSERT_EQUAL_INT(
      1, turn_check_integrity_attr_key_len_str(STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256, buf, len, KEY, 32));
}

static void test_covered_lookups_stop_at_integrity_sha256(void) {
  uint8_t buf[512] = {0};
  size_t len = 0;
  build_signed(buf, &len, STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256, KEY, 32);
  TEST_ASSERT_TRUE(stun_attr_add_str(buf, &len, STUN_ATTRIBUTE_NONCE, (const uint8_t *)"late", 4));
  TEST_ASSERT_NOT_NULL(stun_attr_get_first_by_type_str(buf, len, STUN_ATTRIBUTE_NONCE));
  TEST_ASSERT_NULL(stun_attr_get_first_covered_by_type_str(buf, len, STUN_ATTRIBUTE_NONCE));
  TEST_ASSERT_NOT_NULL(stun_attr_get_first_covered_by_type_str(buf, len, STUN_ATTRIBUTE_REALM));
}

static ioa_addr make_addr(const char *ip, uint16_t port) {
  ioa_addr addr;
  memset(&addr, 0, sizeof(addr));
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)ip, port, &addr));
  return addr;
}

#define TS ((uint32_t)0x64c0ffeeu)

static void test_cookie_encode_decode(void) {
  char cookie[TURN_NONCE_COOKIE_LENGTH + 1] = {0};
  TEST_ASSERT_TRUE(turn_nonce_cookie_encode(TURN_SECURITY_FEATURE_PASSWORD_ALGORITHMS, cookie));
  TEST_ASSERT_EQUAL_STRING("obMatJos2AAAB", cookie);

  uint32_t f = 0;
  TEST_ASSERT_TRUE(turn_nonce_cookie_decode("obMatJos2AAABdeadbeef", &f));
  TEST_ASSERT_EQUAL_HEX32(TURN_SECURITY_FEATURE_PASSWORD_ALGORITHMS, f);
  /* The RFC 8489 Appendix B.1 nonce carries bit 1 (user anonymity, matching its USERHASH) and not password
     algorithms (Verified Erratum 6290: bit 0 is the rightmost bit). */
  TEST_ASSERT_TRUE(turn_nonce_cookie_decode("obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA", &f));
  TEST_ASSERT_EQUAL_HEX32(0x000002, f);
  TEST_ASSERT_FALSE(f & TURN_SECURITY_FEATURE_PASSWORD_ALGORITHMS);
  TEST_ASSERT_FALSE(turn_nonce_cookie_decode("0123456789abcdef", &f));
  TEST_ASSERT_FALSE(turn_nonce_cookie_decode("obMatJos2gAA", &f));
  TEST_ASSERT_FALSE(turn_nonce_cookie_decode("obMatJos2g!AA", &f));
}

static void test_stateless_nonce_cookie_is_covered_by_mac(void) {
  const uint8_t key[TURN_STATELESS_NONCE_KEY_SIZE] = "0123456789abcdef0123456789abcde";
  ioa_addr addr = make_addr("192.0.2.1", 4000);
  char nonce[TURN_NONCE_MAX_SIZE] = {0};
  uint32_t ts = 0, feat = 0;

  TEST_ASSERT_TRUE(turn_generate_stateless_nonce_ex(key, sizeof(key), &addr, TS,
                                                    TURN_SECURITY_FEATURE_PASSWORD_ALGORITHMS, nonce, sizeof(nonce)));
  TEST_ASSERT_EQUAL_size_t(TURN_NONCE_COOKIE_LENGTH + TURN_STATELESS_NONCE_LENGTH, strlen(nonce));
  TEST_ASSERT_EQUAL_INT(0, strncmp(nonce, "obMatJos2AAAB", 13));
  TEST_ASSERT_TRUE(turn_check_stateless_nonce_ex(key, sizeof(key), &addr, TS, 600, true, nonce, &ts, &feat));
  TEST_ASSERT_EQUAL_HEX32(TS, ts);
  TEST_ASSERT_EQUAL_HEX32(TURN_SECURITY_FEATURE_PASSWORD_ALGORITHMS, feat);

  /* Stripped cookie: not a valid legacy nonce either, since the MAC covered the cookie. */
  TEST_ASSERT_FALSE(turn_check_stateless_nonce_ex(key, sizeof(key), &addr, TS, 600, false, nonce + 13, NULL, NULL));
  TEST_ASSERT_FALSE(turn_check_stateless_nonce_ex(key, sizeof(key), &addr, TS, 600, true, nonce + 13, NULL, NULL));
  /* Altered cookie (feature bits cleared). */
  char altered[TURN_NONCE_MAX_SIZE] = {0};
  memcpy(altered, nonce, sizeof(altered));
  memcpy(altered + 9, "AAAA", 4);
  TEST_ASSERT_FALSE(turn_check_stateless_nonce_ex(key, sizeof(key), &addr, TS, 600, true, altered, NULL, NULL));
  /* A legacy nonce is refused in RFC 8489 mode, and a cookie nonce in legacy mode. */
  char legacy[TURN_STATELESS_NONCE_SIZE] = {0};
  TEST_ASSERT_TRUE(turn_generate_stateless_nonce_ex(key, sizeof(key), &addr, TS, 0, legacy, sizeof(legacy)));
  TEST_ASSERT_FALSE(turn_check_stateless_nonce_ex(key, sizeof(key), &addr, TS, 600, true, legacy, NULL, NULL));
  TEST_ASSERT_TRUE(turn_check_stateless_nonce_ex(key, sizeof(key), &addr, TS, 600, false, legacy, NULL, NULL));
  TEST_ASSERT_FALSE(turn_check_stateless_nonce_ex(key, sizeof(key), &addr, TS, 600, false, nonce, NULL, NULL));
  /* A cookie nonce needs the larger buffer. */
  TEST_ASSERT_FALSE(turn_generate_stateless_nonce_ex(
      key, sizeof(key), &addr, TS, TURN_SECURITY_FEATURE_PASSWORD_ALGORITHMS, legacy, sizeof(legacy)));
}

/* The original libturnclient entry points keep producing and accepting the legacy nonce only. */
static void test_original_stateless_nonce_api_is_legacy(void) {
  const uint8_t key[TURN_STATELESS_NONCE_KEY_SIZE] = "0123456789abcdef0123456789abcde";
  ioa_addr addr = make_addr("192.0.2.1", 4000);
  char nonce[TURN_STATELESS_NONCE_SIZE] = {0};
  char legacy_ex[TURN_STATELESS_NONCE_SIZE] = {0};
  char cookie[TURN_NONCE_MAX_SIZE] = {0};
  uint32_t ts = 0;

  TEST_ASSERT_TRUE(turn_generate_stateless_nonce(key, sizeof(key), &addr, TS, nonce, sizeof(nonce)));
  TEST_ASSERT_EQUAL_size_t(TURN_STATELESS_NONCE_LENGTH, strlen(nonce));
  TEST_ASSERT_TRUE(turn_generate_stateless_nonce_ex(key, sizeof(key), &addr, TS, 0, legacy_ex, sizeof(legacy_ex)));
  TEST_ASSERT_EQUAL_STRING(legacy_ex, nonce);
  TEST_ASSERT_TRUE(turn_check_stateless_nonce(key, sizeof(key), &addr, TS, 600, nonce, &ts));
  TEST_ASSERT_EQUAL_HEX32(TS, ts);

  TEST_ASSERT_TRUE(turn_generate_stateless_nonce_ex(key, sizeof(key), &addr, TS,
                                                    TURN_SECURITY_FEATURE_PASSWORD_ALGORITHMS, cookie, sizeof(cookie)));
  TEST_ASSERT_FALSE(turn_check_stateless_nonce(key, sizeof(key), &addr, TS, 600, cookie, NULL));
}

static void test_parse_lists(void) {
  turn_password_algorithms c;
  TEST_ASSERT_TRUE(turn_password_algorithms_parse("md5", &c));
  TEST_ASSERT_EQUAL_size_t(1, c.n);
  TEST_ASSERT_TRUE(turn_password_algorithms_parse("sha256,md5", &c));
  TEST_ASSERT_EQUAL_size_t(2, c.n);
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_SHA256, c.alg[0]);
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_MD5, c.alg[1]);
  TEST_ASSERT_TRUE(turn_password_algorithms_parse("md5,sha256", &c));
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_MD5, c.alg[0]);
  TEST_ASSERT_FALSE(turn_password_algorithms_parse("", &c));
  TEST_ASSERT_FALSE(turn_password_algorithms_parse("sha1", &c));
  TEST_ASSERT_FALSE(turn_password_algorithms_parse("sha256,sha256", &c));
  TEST_ASSERT_FALSE(turn_password_algorithms_parse("sha256,", &c));
  TEST_ASSERT_FALSE(turn_password_algorithms_parse("md5,sha256,md5", &c));
}

enum { NO_ATTRS = 0, ONLY_LIST = 1, ONLY_SEL = 2, BOTH = 3 };

/* A request with a nonce carrying (or not) the password-algorithms bit, and the given PASSWORD-ALGORITHM(S). */
static void build_request(uint8_t *buf, size_t *len, bool cookie, const char *list, int which, turn_password_alg sel) {
  *len = 0;
  stun_init_request_str(STUN_METHOD_ALLOCATE, buf, len);
  const char *nonce = cookie ? "obMatJos2AAAB0123456789abcdef" : "0123456789abcdef";
  TEST_ASSERT_TRUE(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_NONCE, (const uint8_t *)nonce, (int)strlen(nonce)));
  if (which & ONLY_LIST) {
    turn_password_algorithms c;
    TEST_ASSERT_TRUE(turn_password_algorithms_parse(list, &c));
    TEST_ASSERT_TRUE(turn_attr_add_password_algorithms_str(buf, len, &c));
  }
  if (which & ONLY_SEL) {
    TEST_ASSERT_TRUE(turn_attr_add_password_algorithm_str(buf, len, sel));
  }
}

static int select_for(const char *cfg_list, bool cookie, const char *list, int which, turn_password_alg sel,
                      turn_password_alg *out) {
  turn_password_algorithms cfg;
  uint8_t buf[512] = {0};
  size_t len = 0;
  TEST_ASSERT_TRUE(turn_password_algorithms_parse(cfg_list, &cfg));
  build_request(buf, &len, cookie, list, which, sel);
  return turn_password_alg_select(&cfg, buf, len, out);
}

static void test_wire_encoding_of_the_list(void) {
  turn_password_algorithms cfg;
  uint8_t buf[64] = {0};
  size_t len = 0;
  TEST_ASSERT_TRUE(turn_password_algorithms_parse("sha256,md5", &cfg));
  stun_init_request_str(STUN_METHOD_ALLOCATE, buf, &len);
  TEST_ASSERT_TRUE(turn_attr_add_password_algorithms_str(buf, &len, &cfg));
  stun_attr_ref a = stun_attr_get_first_by_type_str(buf, len, STUN_ATTRIBUTE_PASSWORD_ALGORITHMS);
  TEST_ASSERT_NOT_NULL(a);
  const uint8_t want[8] = {0, 2, 0, 0, 0, 1, 0, 0};
  TEST_ASSERT_EQUAL_INT(8, stun_attr_get_len(a));
  TEST_ASSERT_EQUAL_HEX8_ARRAY(want, stun_attr_get_value(a), 8);
}

static void test_select_md5_only(void) {
  turn_password_alg alg = TURN_PASSWORD_ALG_NONE;
  /* RFC 8489 mode with md5 alone: neither attribute means MD5; negotiating md5 explicitly works too. */
  TEST_ASSERT_EQUAL_INT(0, select_for("md5", true, NULL, NO_ATTRS, 0, &alg));
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_MD5, alg);
  TEST_ASSERT_EQUAL_INT(0, select_for("md5", true, "md5", BOTH, TURN_PASSWORD_ALG_MD5, &alg));
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_MD5, alg);
  TEST_ASSERT_EQUAL_INT(400, select_for("md5", true, "md5", BOTH, TURN_PASSWORD_ALG_SHA256, &alg));
}

static void test_select_sha256_only(void) {
  turn_password_alg alg = TURN_PASSWORD_ALG_NONE;
  TEST_ASSERT_EQUAL_INT(0, select_for("sha256", true, "sha256", BOTH, TURN_PASSWORD_ALG_SHA256, &alg));
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_SHA256, alg);
  /* MD5 (neither attribute) is refused with a fresh challenge; MD5 cannot be selected either. */
  TEST_ASSERT_EQUAL_INT(401, select_for("sha256", true, NULL, NO_ATTRS, 0, &alg));
  TEST_ASSERT_EQUAL_INT(400, select_for("sha256", true, "sha256", BOTH, TURN_PASSWORD_ALG_MD5, &alg));
  /* A client that never saw the cookie (legacy nonce) is an MD5 client. */
  TEST_ASSERT_EQUAL_INT(401, select_for("sha256", false, NULL, NO_ATTRS, 0, &alg));
}

static void test_select_sha256_then_md5(void) {
  turn_password_alg alg = TURN_PASSWORD_ALG_NONE;
  TEST_ASSERT_EQUAL_INT(0, select_for("sha256,md5", true, "sha256,md5", BOTH, TURN_PASSWORD_ALG_SHA256, &alg));
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_SHA256, alg);
  TEST_ASSERT_EQUAL_INT(0, select_for("sha256,md5", true, "sha256,md5", BOTH, TURN_PASSWORD_ALG_MD5, &alg));
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_MD5, alg);
  TEST_ASSERT_EQUAL_INT(0, select_for("sha256,md5", true, NULL, NO_ATTRS, 0, &alg));
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_MD5, alg);
}

static void test_select_bid_down_is_rejected(void) {
  turn_password_alg alg = TURN_PASSWORD_ALG_NONE;
  /* On-path removal of SHA-256 from the offered list, a reordered list, or a list with extra entries. */
  TEST_ASSERT_EQUAL_INT(400, select_for("sha256,md5", true, "md5", BOTH, TURN_PASSWORD_ALG_MD5, &alg));
  TEST_ASSERT_EQUAL_INT(400, select_for("sha256,md5", true, "md5,sha256", BOTH, TURN_PASSWORD_ALG_MD5, &alg));
  TEST_ASSERT_EQUAL_INT(400, select_for("sha256", true, "sha256,md5", BOTH, TURN_PASSWORD_ALG_SHA256, &alg));
  /* One attribute without the other. */
  TEST_ASSERT_EQUAL_INT(400, select_for("sha256,md5", true, "sha256,md5", ONLY_LIST, 0, &alg));
  TEST_ASSERT_EQUAL_INT(400, select_for("sha256,md5", true, NULL, ONLY_SEL, TURN_PASSWORD_ALG_MD5, &alg));
}

static void test_select_off_is_md5(void) {
  turn_password_algorithms off = {0};
  uint8_t buf[512] = {0};
  size_t len = 0;
  turn_password_alg alg = TURN_PASSWORD_ALG_NONE;
  build_request(buf, &len, false, NULL, NO_ATTRS, 0);
  TEST_ASSERT_EQUAL_INT(0, turn_password_alg_select(&off, buf, len, &alg));
  TEST_ASSERT_EQUAL_INT(TURN_PASSWORD_ALG_MD5, alg);
  TEST_ASSERT_EQUAL_INT(0, turn_password_alg_select(NULL, buf, len, &alg));
}

static uint16_t response_attr_for(const char *cfg_list, const char *list, int which, turn_password_alg sel,
                                  uint16_t fallback) {
  turn_password_algorithms cfg;
  uint8_t buf[512] = {0};
  size_t len = 0;
  TEST_ASSERT_TRUE(turn_password_algorithms_parse(cfg_list, &cfg));
  build_request(buf, &len, true, list, which, sel);
  return turn_response_integrity_attr(&cfg, buf, len, fallback);
}

/* RFC 8489 Section 9.2.4: negotiated -> MESSAGE-INTEGRITY-SHA256, implied MD5 -> MESSAGE-INTEGRITY. */
static void test_response_integrity_attr_follows_negotiation(void) {
  const uint16_t mi = STUN_ATTRIBUTE_MESSAGE_INTEGRITY, sha = STUN_ATTRIBUTE_MESSAGE_INTEGRITY_SHA256;
  /* Whatever integrity attribute the request itself used (the fallback), a negotiated request gets SHA-256. */
  TEST_ASSERT_EQUAL_UINT16(sha, response_attr_for("sha256", "sha256", BOTH, TURN_PASSWORD_ALG_SHA256, mi));
  TEST_ASSERT_EQUAL_UINT16(sha, response_attr_for("sha256,md5", "sha256,md5", BOTH, TURN_PASSWORD_ALG_MD5, mi));
  TEST_ASSERT_EQUAL_UINT16(sha, response_attr_for("md5", "md5", BOTH, TURN_PASSWORD_ALG_MD5, mi));
  /* Implied MD5 keeps MESSAGE-INTEGRITY even if the request was signed with MI-SHA256. */
  TEST_ASSERT_EQUAL_UINT16(mi, response_attr_for("sha256,md5", NULL, NO_ATTRS, 0, sha));
  TEST_ASSERT_EQUAL_UINT16(mi, response_attr_for("md5", NULL, NO_ATTRS, 0, sha));
  /* RFC 8489 mode off: unchanged. */
  turn_password_algorithms off = {0};
  uint8_t buf[512] = {0};
  size_t len = 0;
  build_request(buf, &len, false, NULL, NO_ATTRS, 0);
  TEST_ASSERT_EQUAL_UINT16(mi, turn_response_integrity_attr(&off, buf, len, mi));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_b1_sha256_key_and_integrity);
  RUN_TEST(test_md5_key_is_16_bytes);
  RUN_TEST(test_integrity_attr_roundtrip_and_type_binding);
  RUN_TEST(test_sha256_integrity_value_matches_openssl);
  RUN_TEST(test_fingerprint_after_integrity_sha256);
  RUN_TEST(test_covered_lookups_stop_at_integrity_sha256);
  RUN_TEST(test_cookie_encode_decode);
  RUN_TEST(test_stateless_nonce_cookie_is_covered_by_mac);
  RUN_TEST(test_original_stateless_nonce_api_is_legacy);
  RUN_TEST(test_parse_lists);
  RUN_TEST(test_wire_encoding_of_the_list);
  RUN_TEST(test_select_md5_only);
  RUN_TEST(test_select_sha256_only);
  RUN_TEST(test_select_sha256_then_md5);
  RUN_TEST(test_select_bid_down_is_rejected);
  RUN_TEST(test_select_off_is_md5);
  RUN_TEST(test_response_integrity_attr_follows_negotiation);
  return UNITY_END();
}
