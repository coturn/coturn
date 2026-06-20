/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Unit tests for the Redis connection-string parser (src/apps/relay/dbdrivers/
 * dbd_redis_conninfo.c). The parser is dependency-free, so these tests link it
 * directly with no Redis server, hiredis library, or relay stubs.
 *
 * Coverage focuses on the TLS options added on top of the historical
 * host/port/user/password/db keys, plus the secure defaults and the error
 * handling for malformed input.
 */

#include "unity.h"

#include "dbdrivers/dbd_redis_conninfo.h"

#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---------------- defaults ---------------- */

static void test_defaults_applied_for_empty_string(void) {
  Ryconninfo *co = RyconninfoParse("", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_STRING("127.0.0.1", co->host);
  TEST_ASSERT_EQUAL_STRING("0", co->dbname);
  TEST_ASSERT_EQUAL_INT(0, co->use_tls);
  TEST_ASSERT_EQUAL_INT(1, co->tls_verify); /* secure default */
  TEST_ASSERT_EQUAL_UINT(0, co->port);
  RyconninfoFree(co);
}

static void test_defaults_applied_for_null_string(void) {
  Ryconninfo *co = RyconninfoParse(NULL, NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_STRING("127.0.0.1", co->host);
  TEST_ASSERT_EQUAL_STRING("0", co->dbname);
  RyconninfoFree(co);
}

/* ---------------- legacy (non-TLS) fields still parse ---------------- */

static void test_legacy_fields_parse(void) {
  Ryconninfo *co =
      RyconninfoParse("host=redis.example port=6390 user=turn password=s3cret dbname=2 connect_timeout=7", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_STRING("redis.example", co->host);
  TEST_ASSERT_EQUAL_UINT(6390, co->port);
  TEST_ASSERT_EQUAL_STRING("turn", co->user);
  TEST_ASSERT_EQUAL_STRING("s3cret", co->password);
  TEST_ASSERT_EQUAL_STRING("2", co->dbname);
  TEST_ASSERT_EQUAL_UINT(7, co->connect_timeout);
  TEST_ASSERT_EQUAL_INT(0, co->use_tls);
  RyconninfoFree(co);
}

/* ---------------- TLS enable + files ---------------- */

static void test_tls_enabled_with_ca(void) {
  Ryconninfo *co = RyconninfoParse("host=localhost tls=true ca=/etc/coturn/ca.crt", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_INT(1, co->use_tls);
  TEST_ASSERT_EQUAL_STRING("/etc/coturn/ca.crt", co->tls_ca);
  TEST_ASSERT_EQUAL_INT(1, co->tls_verify); /* peer verification on by default */
  RyconninfoFree(co);
}

static void test_tls_mutual_and_sni(void) {
  Ryconninfo *co =
      RyconninfoParse("tls=on tls-ca=/c/ca.pem tls-cert=/c/client.crt tls-key=/c/client.key tls-sni=redis.prod", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_INT(1, co->use_tls);
  TEST_ASSERT_EQUAL_STRING("/c/ca.pem", co->tls_ca);
  TEST_ASSERT_EQUAL_STRING("/c/client.crt", co->tls_cert);
  TEST_ASSERT_EQUAL_STRING("/c/client.key", co->tls_key);
  TEST_ASSERT_EQUAL_STRING("redis.prod", co->tls_sni);
  RyconninfoFree(co);
}

static void test_tls_aliases(void) {
  /* ssl/cacert/cert/clientkey/servername/capath are accepted aliases. */
  Ryconninfo *co = RyconninfoParse(
      "ssl=1 cacert=/a/ca capath=/a/cadir cert=/a/c.crt clientkey=/a/c.key servername=name.example", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_INT(1, co->use_tls);
  TEST_ASSERT_EQUAL_STRING("/a/ca", co->tls_ca);
  TEST_ASSERT_EQUAL_STRING("/a/cadir", co->tls_capath);
  TEST_ASSERT_EQUAL_STRING("/a/c.crt", co->tls_cert);
  TEST_ASSERT_EQUAL_STRING("/a/c.key", co->tls_key);
  TEST_ASSERT_EQUAL_STRING("name.example", co->tls_sni);
  RyconninfoFree(co);
}

/* ---------------- boolean parsing ---------------- */

static void test_tls_boolean_false_values(void) {
  const char *off[] = {"tls=0", "tls=false", "tls=no", "tls=off", "ssl=0"};
  for (size_t i = 0; i < sizeof(off) / sizeof(off[0]); i++) {
    Ryconninfo *co = RyconninfoParse(off[i], NULL);
    TEST_ASSERT_NOT_NULL(co);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, co->use_tls, off[i]);
    RyconninfoFree(co);
  }
}

static void test_tls_boolean_true_values(void) {
  const char *on[] = {"tls=1", "tls=true", "tls=yes", "tls=on"};
  for (size_t i = 0; i < sizeof(on) / sizeof(on[0]); i++) {
    Ryconninfo *co = RyconninfoParse(on[i], NULL);
    TEST_ASSERT_NOT_NULL(co);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, co->use_tls, on[i]);
    RyconninfoFree(co);
  }
}

/* ---------------- verify tri-state ---------------- */

static void test_verify_none_disables_verification(void) {
  Ryconninfo *co = RyconninfoParse("tls=true verify=none", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_INT(0, co->tls_verify);
  RyconninfoFree(co);
}

static void test_verify_explicit_peer(void) {
  Ryconninfo *co = RyconninfoParse("tls=true tls-verify=peer", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_INT(1, co->tls_verify);
  RyconninfoFree(co);
}

static void test_verify_false_disables_verification(void) {
  Ryconninfo *co = RyconninfoParse("tls=true verify=false", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_INT(0, co->tls_verify);
  RyconninfoFree(co);
}

/* ---------------- last-value-wins for repeated keys ---------------- */

static void test_repeated_key_keeps_last_value(void) {
  Ryconninfo *co = RyconninfoParse("host=a host=b ca=/x ca=/y", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_STRING("b", co->host);
  TEST_ASSERT_EQUAL_STRING("/y", co->tls_ca);
  RyconninfoFree(co);
}

/* ---------------- error handling ---------------- */

static void test_unknown_key_rejected(void) {
  char *errmsg = NULL;
  Ryconninfo *co = RyconninfoParse("host=localhost boguskey=1", &errmsg);
  TEST_ASSERT_NULL(co);
  TEST_ASSERT_NOT_NULL(errmsg);
  TEST_ASSERT_EQUAL_STRING("boguskey", errmsg);
  free(errmsg);
}

static void test_token_without_equals_rejected(void) {
  char *errmsg = NULL;
  Ryconninfo *co = RyconninfoParse("host=localhost garbage", &errmsg);
  TEST_ASSERT_NULL(co);
  TEST_ASSERT_NOT_NULL(errmsg);
  TEST_ASSERT_EQUAL_STRING("garbage", errmsg);
  free(errmsg);
}

/* Trailing/leading/multiple spaces are tolerated (not treated as bad tokens). */
static void test_surrounding_spaces_tolerated(void) {
  Ryconninfo *co = RyconninfoParse("  host=localhost   tls=true  ", NULL);
  TEST_ASSERT_NOT_NULL(co);
  TEST_ASSERT_EQUAL_STRING("localhost", co->host);
  TEST_ASSERT_EQUAL_INT(1, co->use_tls);
  RyconninfoFree(co);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_defaults_applied_for_empty_string);
  RUN_TEST(test_defaults_applied_for_null_string);
  RUN_TEST(test_legacy_fields_parse);
  RUN_TEST(test_tls_enabled_with_ca);
  RUN_TEST(test_tls_mutual_and_sni);
  RUN_TEST(test_tls_aliases);
  RUN_TEST(test_tls_boolean_false_values);
  RUN_TEST(test_tls_boolean_true_values);
  RUN_TEST(test_verify_none_disables_verification);
  RUN_TEST(test_verify_explicit_peer);
  RUN_TEST(test_verify_false_disables_verification);
  RUN_TEST(test_repeated_key_keeps_last_value);
  RUN_TEST(test_unknown_key_rejected);
  RUN_TEST(test_token_without_equals_rejected);
  RUN_TEST(test_surrounding_spaces_tolerated);
  return UNITY_END();
}
