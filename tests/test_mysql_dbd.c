/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Interface tests for the MySQL user-DB driver (src/apps/relay/dbdrivers/
 * dbd_mysql.c). libmysqlclient is replaced by a capturing mock
 * (test_mysql_stub.c) so no server is needed. The tests assert the driver uses
 * prepared statements with '?' placeholders and binds caller values out-of-band
 * (write/delete paths), correctly round-trips a fed result row (read paths via
 * mysql_stmt_bind_result/fetch), and never lets an injection payload reach the
 * SQL text.
 *
 * Against the old string-interpolated driver these tests fail (it calls
 * mysql_query() with values baked in and prepares nothing); against the new
 * prepared-statement driver they pass.
 */

#include "unity.h"

#include "apputils.h"            /* oauth_key_data_raw */
#include "dbdrivers/dbd_mysql.h" /* get_mysql_dbdriver */
#include "dbdrivers/dbdriver.h"  /* turn_dbdriver_t */
#include "ns_turn_msg.h"         /* hmackey_t, password_t, get_hmackey_size, SHATYPE_DEFAULT */
#include "userdb.h"              /* secrets_list_t */

#include "test_mysql_stub.h"
#include "test_sqlite_support.h" /* test_sqlite_support_init (shared relay stubs) */

#include <string.h>

static const turn_dbdriver_t *db;

void setUp(void) { mystub_reset(); }
void tearDown(void) {}

static void assert_prepared(const char *expect_cmd, int nparams) {
  TEST_ASSERT_TRUE_MESSAGE(mystub_used_stmt(), "expected a prepared statement, got mysql_query()");
  TEST_ASSERT_EQUAL_STRING(expect_cmd, mystub_last_command());
  TEST_ASSERT_EQUAL_INT(nparams, mystub_nparams());
}

/////////////////////////// write / delete paths ///////////////////////////

static void test_set_user_key(void) {
  db->set_user_key((uint8_t *)"alice", (uint8_t *)"north.gov", "deadbeef");
  assert_prepared("insert into turnusers_lt (realm,name,hmackey) values(?,?,?)", 3);
  TEST_ASSERT_EQUAL_STRING("north.gov", mystub_param(0));
  TEST_ASSERT_EQUAL_STRING("alice", mystub_param(1));
  TEST_ASSERT_EQUAL_STRING("deadbeef", mystub_param(2));
}

static void test_del_user(void) {
  db->del_user((uint8_t *)"alice", (uint8_t *)"north.gov");
  assert_prepared("delete from turnusers_lt where name=? and realm=?", 2);
  TEST_ASSERT_EQUAL_STRING("alice", mystub_param(0));
  TEST_ASSERT_EQUAL_STRING("north.gov", mystub_param(1));
}

static void test_set_secret(void) {
  db->set_secret((uint8_t *)"s3cr3t", (uint8_t *)"north.gov");
  assert_prepared("insert into turn_secret (realm,value) values(?,?)", 2);
  TEST_ASSERT_EQUAL_STRING("north.gov", mystub_param(0));
  TEST_ASSERT_EQUAL_STRING("s3cr3t", mystub_param(1));
}

static void test_del_secret_with_value(void) {
  db->del_secret((uint8_t *)"s3cr3t", (uint8_t *)"north.gov");
  assert_prepared("delete from turn_secret where value=? and realm=?", 2);
  TEST_ASSERT_EQUAL_STRING("s3cr3t", mystub_param(0));
  TEST_ASSERT_EQUAL_STRING("north.gov", mystub_param(1));
}

static void test_set_oauth_key(void) {
  oauth_key_data_raw k;
  memset(&k, 0, sizeof(k));
  strcpy(k.kid, "kid1");
  strcpy(k.ikm_key, "aGVsbG8=");
  k.timestamp = 1748000000ULL;
  k.lifetime = 3600;
  strcpy(k.as_rs_alg, "hs256");
  strcpy(k.realm, "north.gov");
  db->set_oauth_key(&k);
  assert_prepared("insert into oauth_key (kid,ikm_key,timestamp,lifetime,as_rs_alg,realm) values(?,?,?,?,?,?)", 6);
  TEST_ASSERT_EQUAL_STRING("kid1", mystub_param(0));
  TEST_ASSERT_EQUAL_STRING("1748000000", mystub_param(2)); /* integer -> bound text */
  TEST_ASSERT_EQUAL_STRING("3600", mystub_param(3));
}

static void test_permission_ip(void) {
  db->set_permission_ip("allowed", (uint8_t *)"north.gov", "10.0.0.0/8", 0);
  assert_prepared("insert into allowed_peer_ip (realm,ip_range) values(?,?)", 2);
  TEST_ASSERT_EQUAL_STRING("north.gov", mystub_param(0));
  TEST_ASSERT_EQUAL_STRING("10.0.0.0/8", mystub_param(1));

  mystub_reset();
  db->set_permission_ip("denied", (uint8_t *)"north.gov", "10.0.0.0/8", 1);
  assert_prepared("delete from denied_peer_ip where realm = ?  and ip_range = ?", 2);
  TEST_ASSERT_EQUAL_STRING("10.0.0.0/8", mystub_param(1));
}

static void test_realm_option(void) {
  db->set_realm_option_one((uint8_t *)"north.gov", 1000000, "max-bps");
  /* delete then insert; insert is the last captured statement */
  assert_prepared("insert into turn_realm_option (realm,opt,value) values(?,?,?)", 3);
  TEST_ASSERT_EQUAL_STRING("north.gov", mystub_param(0));
  TEST_ASSERT_EQUAL_STRING("max-bps", mystub_param(1));
  TEST_ASSERT_EQUAL_STRING("1000000", mystub_param(2));
}

static void test_admin_user_set_del(void) {
  password_t pwd;
  memset(pwd, 0, sizeof(pwd));
  strncpy((char *)pwd, "secrethash", sizeof(pwd) - 1);
  db->set_admin_user((uint8_t *)"wadmin", (uint8_t *)"north.gov", pwd);
  assert_prepared("insert into admin_user (realm,name,password) values(?,?,?)", 3);
  TEST_ASSERT_EQUAL_STRING("north.gov", mystub_param(0));
  TEST_ASSERT_EQUAL_STRING("wadmin", mystub_param(1));
  TEST_ASSERT_EQUAL_STRING("secrethash", mystub_param(2));

  mystub_reset();
  db->del_admin_user((const uint8_t *)"wadmin");
  assert_prepared("delete from admin_user where name=?", 1);
  TEST_ASSERT_EQUAL_STRING("wadmin", mystub_param(0));
}

/////////////////////////// read paths (with a fed row) ///////////////////////////

static void test_get_user_key_roundtrip(void) {
  const char *hexkey = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee";
  const char *const row[] = {hexkey};
  mystub_set_row(1, row);

  hmackey_t key;
  memset(key, 0, sizeof(key));
  int r = db->get_user_key((uint8_t *)"alice", (uint8_t *)"north.gov", key);
  assert_prepared("select hmackey from turnusers_lt where name=? and realm=?", 2);
  TEST_ASSERT_EQUAL_STRING("alice", mystub_param(0));
  TEST_ASSERT_EQUAL_INT(0, r);
  TEST_ASSERT_EQUAL_HEX8(0x00, key[0]);
  TEST_ASSERT_EQUAL_HEX8(0x11, key[1]);
  TEST_ASSERT_EQUAL_HEX8(0x22, key[2]);
  TEST_ASSERT_EQUAL_HEX8(0x33, key[3]);
}

static void test_get_oauth_key_roundtrip(void) {
  const char *const row[] = {"aGVsbG8=", "1748000000", "3600", "hs256", "north.gov"};
  mystub_set_row(5, row);

  oauth_key_data_raw out;
  memset(&out, 0, sizeof(out));
  int r = db->get_oauth_key((const uint8_t *)"kid1", &out);
  assert_prepared("select ikm_key,timestamp,lifetime,as_rs_alg,realm from oauth_key where kid=?", 1);
  TEST_ASSERT_EQUAL_INT(0, r);
  TEST_ASSERT_EQUAL_STRING("kid1", out.kid);
  TEST_ASSERT_EQUAL_STRING("aGVsbG8=", out.ikm_key);
  TEST_ASSERT_EQUAL_UINT64(1748000000ULL, out.timestamp);
  TEST_ASSERT_EQUAL_UINT(3600, out.lifetime);
  TEST_ASSERT_EQUAL_STRING("hs256", out.as_rs_alg);
  TEST_ASSERT_EQUAL_STRING("north.gov", out.realm);
}

static void test_get_admin_user_roundtrip(void) {
  const char *const row[] = {"north.gov", "secrethash"};
  mystub_set_row(2, row);

  password_t pwd;
  uint8_t realm[STUN_MAX_REALM_SIZE + 1];
  memset(pwd, 0, sizeof(pwd));
  memset(realm, 0, sizeof(realm));
  int r = db->get_admin_user((const uint8_t *)"wadmin", realm, pwd);
  assert_prepared("select realm,password from admin_user where name=?", 1);
  TEST_ASSERT_EQUAL_INT(0, r);
  TEST_ASSERT_EQUAL_STRING("wadmin", mystub_param(0));
  TEST_ASSERT_EQUAL_STRING("north.gov", (char *)realm);
  TEST_ASSERT_EQUAL_STRING("secrethash", (char *)pwd);
}

static void test_get_auth_secrets_roundtrip(void) {
  const char *const row[] = {"s3cr3t"};
  mystub_set_row(1, row);

  secrets_list_t sl = {0};
  int r = db->get_auth_secrets(&sl, (uint8_t *)"north.gov");
  assert_prepared("select value from turn_secret where realm=?", 1);
  TEST_ASSERT_EQUAL_INT(0, r);
  TEST_ASSERT_EQUAL_INT(1, (int)sl.sz);
  TEST_ASSERT_EQUAL_STRING("s3cr3t", sl.secrets[0]);
}

/////////////////////////// security regression ///////////////////////////

static void test_sql_injection_neutralized(void) {
  const char *payload = "zzz' OR '1'='1";

  db->del_user((uint8_t *)payload, (uint8_t *)"r1");
  TEST_ASSERT_TRUE_MESSAGE(mystub_used_stmt(), "del_user used mysql_query (interpolated) instead of a prepared stmt");
  TEST_ASSERT_EQUAL_STRING(payload, mystub_param(0));
  TEST_ASSERT_NULL_MESSAGE(strstr(mystub_last_command(), "OR '1'='1"), "injection payload leaked into the SQL text");

  mystub_reset();
  db->del_secret((uint8_t *)"nope", (uint8_t *)"r1' OR '1'='1");
  TEST_ASSERT_TRUE_MESSAGE(mystub_used_stmt(), "del_secret used mysql_query (interpolated) instead of a prepared stmt");
  TEST_ASSERT_EQUAL_STRING("r1' OR '1'='1", mystub_param(1));
  TEST_ASSERT_NULL_MESSAGE(strstr(mystub_last_command(), "OR '1'='1"), "injection payload leaked into the SQL text");
}

int main(void) {
  test_sqlite_support_init("host=localhost dbname=coturn"); /* conninfo; mock ignores it */
  db = get_mysql_dbdriver();
  if (!db) {
    return 2;
  }

  UNITY_BEGIN();
  RUN_TEST(test_set_user_key);
  RUN_TEST(test_del_user);
  RUN_TEST(test_set_secret);
  RUN_TEST(test_del_secret_with_value);
  RUN_TEST(test_set_oauth_key);
  RUN_TEST(test_permission_ip);
  RUN_TEST(test_realm_option);
  RUN_TEST(test_admin_user_set_del);
  RUN_TEST(test_get_user_key_roundtrip);
  RUN_TEST(test_get_oauth_key_roundtrip);
  RUN_TEST(test_get_admin_user_roundtrip);
  RUN_TEST(test_get_auth_secrets_roundtrip);
  RUN_TEST(test_sql_injection_neutralized);
  return UNITY_END();
}
