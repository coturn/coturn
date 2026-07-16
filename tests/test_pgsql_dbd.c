/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Interface tests for the PostgreSQL user-DB driver (src/apps/relay/dbdrivers/
 * dbd_pgsql.c). libpq is replaced by a capturing mock (test_pgsql_stub.c) so no
 * server is needed: each test drives the driver's public vtable and asserts the
 * emitted statement is parameterized ($1,$2,...) with caller values bound
 * out-of-band rather than interpolated into the SQL text.
 *
 * Against the old string-interpolated driver these tests fail (it calls PQexec
 * with values baked into the SQL and binds nothing); against the new
 * parameterized driver they pass. test_sql_injection_neutralized makes the
 * security difference explicit.
 */

#include "unity.h"

#include "apputils.h"            /* oauth_key_data_raw */
#include "dbdrivers/dbd_pgsql.h" /* get_pgsql_dbdriver */
#include "dbdrivers/dbdriver.h"  /* turn_dbdriver_t */
#include "ns_turn_msg.h"         /* password_t */
#include "userdb.h"              /* secrets_list_t */

#include "test_pgsql_stub.h"
#include "test_sqlite_support.h" /* test_sqlite_support_init (shared relay stubs) */

#include <string.h>

static const turn_dbdriver_t *db;

void setUp(void) { pgstub_reset(); }
void tearDown(void) {}

static void assert_parameterized(const char *expect_cmd, int nparams) {
  TEST_ASSERT_TRUE_MESSAGE(pgstub_used_params(), "expected a parameterized query (PQexecParams), got PQexec");
  TEST_ASSERT_EQUAL_STRING(expect_cmd, pgstub_last_command());
  TEST_ASSERT_EQUAL_INT(nparams, pgstub_last_nparams());
}

/////////////////////////// tests ///////////////////////////

static void test_get_auth_secrets(void) {
  secrets_list_t sl = {0};
  db->get_auth_secrets(&sl, (uint8_t *)"north.gov");
  assert_parameterized("select value from turn_secret where realm=$1", 1);
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(0));
}

static void test_get_user_key(void) {
  hmackey_t key;
  db->get_user_key((uint8_t *)"alice", (uint8_t *)"north.gov", key);
  assert_parameterized("select hmackey from turnusers_lt where name=$1 and realm=$2", 2);
  TEST_ASSERT_EQUAL_STRING("alice", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(1));
}

static void test_set_user_key(void) {
  db->set_user_key((uint8_t *)"alice", (uint8_t *)"north.gov", "deadbeef");
  assert_parameterized("insert into turnusers_lt (realm,name,hmackey) values($1,$2,$3)", 3);
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("alice", pgstub_last_param(1));
  TEST_ASSERT_EQUAL_STRING("deadbeef", pgstub_last_param(2));
}

static void test_del_user(void) {
  db->del_user((uint8_t *)"alice", (uint8_t *)"north.gov");
  assert_parameterized("delete from turnusers_lt where name=$1 and realm=$2", 2);
  TEST_ASSERT_EQUAL_STRING("alice", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(1));
}

static void test_set_secret(void) {
  db->set_secret((uint8_t *)"s3cr3t", (uint8_t *)"north.gov");
  assert_parameterized("insert into turn_secret (realm,value) values($1,$2)", 2);
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("s3cr3t", pgstub_last_param(1));
}

static void test_del_secret_with_value(void) {
  db->del_secret((uint8_t *)"s3cr3t", (uint8_t *)"north.gov");
  assert_parameterized("delete from turn_secret where value=$1 and realm=$2", 2);
  TEST_ASSERT_EQUAL_STRING("s3cr3t", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(1));
}

static void test_oauth_set_get_del(void) {
  oauth_key_data_raw k;
  memset(&k, 0, sizeof(k));
  strcpy(k.kid, "kid1");
  strcpy(k.ikm_key, "aGVsbG8=");
  k.timestamp = 1748000000ULL;
  k.lifetime = 3600;
  strcpy(k.as_rs_alg, "hs256");
  strcpy(k.realm, "north.gov");

  db->set_oauth_key(&k);
  assert_parameterized(
      "insert into oauth_key (kid,ikm_key,timestamp,lifetime,as_rs_alg,realm) values($1,$2,$3,$4,$5,$6)", 6);
  TEST_ASSERT_EQUAL_STRING("kid1", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("1748000000", pgstub_last_param(2)); /* integer -> bound text */
  TEST_ASSERT_EQUAL_STRING("3600", pgstub_last_param(3));

  pgstub_reset();
  oauth_key_data_raw out;
  db->get_oauth_key((const uint8_t *)"kid1", &out);
  assert_parameterized("select ikm_key,timestamp,lifetime,as_rs_alg,realm from oauth_key where kid=$1", 1);
  TEST_ASSERT_EQUAL_STRING("kid1", pgstub_last_param(0));

  pgstub_reset();
  db->del_oauth_key((const uint8_t *)"kid1");
  assert_parameterized("delete from oauth_key where kid = $1", 1);
  TEST_ASSERT_EQUAL_STRING("kid1", pgstub_last_param(0));
}

static void test_origin_add_del(void) {
  db->add_origin((uint8_t *)"http://o.example", (uint8_t *)"north.gov");
  assert_parameterized("insert into turn_origin_to_realm (origin,realm) values($1,$2)", 2);
  TEST_ASSERT_EQUAL_STRING("http://o.example", pgstub_last_param(0));

  pgstub_reset();
  db->del_origin((uint8_t *)"http://o.example");
  assert_parameterized("delete from turn_origin_to_realm where origin=$1", 1);
  TEST_ASSERT_EQUAL_STRING("http://o.example", pgstub_last_param(0));
}

static void test_realm_option(void) {
  db->set_realm_option_one((uint8_t *)"north.gov", 1000000, "max-bps");
  /* delete then insert; the insert is the last captured statement */
  assert_parameterized("insert into turn_realm_option (realm,opt,value) values($1,$2,$3)", 3);
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("max-bps", pgstub_last_param(1));
  TEST_ASSERT_EQUAL_STRING("1000000", pgstub_last_param(2));
}

static void test_permission_ip(void) {
  db->set_permission_ip("allowed", (uint8_t *)"north.gov", "10.0.0.0/8", 0);
  assert_parameterized("insert into allowed_peer_ip (realm,ip_range) values($1,$2)", 2);
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("10.0.0.0/8", pgstub_last_param(1));

  pgstub_reset();
  db->set_permission_ip("denied", (uint8_t *)"north.gov", "10.0.0.0/8", 1);
  assert_parameterized("delete from denied_peer_ip where realm = $1  and ip_range = $2", 2);
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("10.0.0.0/8", pgstub_last_param(1));
}

static void test_admin_user(void) {
  password_t pwd;
  memset(pwd, 0, sizeof(pwd));
  strncpy((char *)pwd, "secrethash", sizeof(pwd) - 1);

  db->set_admin_user((uint8_t *)"wadmin", (uint8_t *)"north.gov", pwd);
  assert_parameterized("insert into admin_user (realm,name,password) values($1,$2,$3)", 3);
  TEST_ASSERT_EQUAL_STRING("north.gov", pgstub_last_param(0));
  TEST_ASSERT_EQUAL_STRING("wadmin", pgstub_last_param(1));
  TEST_ASSERT_EQUAL_STRING("secrethash", pgstub_last_param(2));

  pgstub_reset();
  password_t out;
  uint8_t realm_out[STUN_MAX_REALM_SIZE + 1];
  db->get_admin_user((const uint8_t *)"wadmin", realm_out, out);
  assert_parameterized("select realm,password from admin_user where name=$1", 1);
  TEST_ASSERT_EQUAL_STRING("wadmin", pgstub_last_param(0));

  pgstub_reset();
  db->del_admin_user((const uint8_t *)"wadmin");
  assert_parameterized("delete from admin_user where name=$1", 1);
  TEST_ASSERT_EQUAL_STRING("wadmin", pgstub_last_param(0));
}

/* The security regression test: a boolean-injection payload must travel as an
 * opaque bound parameter, never as part of the SQL text. Fails on the old
 * interpolating driver (which calls PQexec with the payload baked in), passes on
 * the parameterized driver. */
static void test_sql_injection_neutralized(void) {
  const char *payload = "zzz' OR '1'='1";

  db->del_user((uint8_t *)payload, (uint8_t *)"r1");
  TEST_ASSERT_TRUE_MESSAGE(pgstub_used_params(), "del_user used PQexec (interpolated) instead of PQexecParams");
  TEST_ASSERT_EQUAL_STRING(payload, pgstub_last_param(0));
  TEST_ASSERT_NULL_MESSAGE(strstr(pgstub_last_command(), "OR '1'='1"), "injection payload leaked into the SQL text");

  pgstub_reset();
  db->del_secret((uint8_t *)"nope", (uint8_t *)"r1' OR '1'='1");
  TEST_ASSERT_TRUE_MESSAGE(pgstub_used_params(), "del_secret used PQexec (interpolated) instead of PQexecParams");
  TEST_ASSERT_EQUAL_STRING("r1' OR '1'='1", pgstub_last_param(1));
  TEST_ASSERT_NULL_MESSAGE(strstr(pgstub_last_command(), "OR '1'='1"), "injection payload leaked into the SQL text");
}

int main(void) {
  test_sqlite_support_init("host=localhost dbname=coturn"); /* conninfo; mock ignores it */
  db = get_pgsql_dbdriver();
  if (!db) {
    return 2;
  }

  UNITY_BEGIN();
  RUN_TEST(test_get_auth_secrets);
  RUN_TEST(test_get_user_key);
  RUN_TEST(test_set_user_key);
  RUN_TEST(test_del_user);
  RUN_TEST(test_set_secret);
  RUN_TEST(test_del_secret_with_value);
  RUN_TEST(test_oauth_set_get_del);
  RUN_TEST(test_origin_add_del);
  RUN_TEST(test_realm_option);
  RUN_TEST(test_permission_ip);
  RUN_TEST(test_admin_user);
  RUN_TEST(test_sql_injection_neutralized);
  return UNITY_END();
}
