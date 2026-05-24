/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Interface tests for the SQLite user-DB driver (src/apps/relay/dbdrivers/
 * dbd_sqlite.c), driven through the public turn_dbdriver_t vtable returned by
 * get_sqlite_dbdriver().
 *
 * Two purposes:
 *   1. Behavioral coverage of every value-carrying driver entry point
 *      (users, secrets, origins, realm options, oauth keys, permission IPs,
 *      admin users). These pass identically against the old string-interpolated
 *      driver and the new parameterized one -> they pin down behavior parity.
 *   2. A SQL-injection test that the old driver fails and the new one passes,
 *      demonstrating the parameterization actually closes the hole.
 *
 * The tests use a throwaway on-disk SQLite database and a second, test-owned
 * SQLite connection (`vfy`) to inspect/clean rows independently of the driver's
 * own per-thread connection.
 */

#include "unity.h"

#include "apputils.h"             /* oauth_key_data_raw */
#include "dbdrivers/dbd_sqlite.h" /* get_sqlite_dbdriver */
#include "dbdrivers/dbdriver.h"   /* turn_dbdriver_t */
#include "ns_turn_msg.h"          /* hmackey_t, password_t, get_hmackey_size, SHATYPE_DEFAULT */
#include "userdb.h"               /* secrets_list_t */

#include "test_sqlite_support.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const turn_dbdriver_t *db;
static sqlite3 *vfy;
static char dbpath[256];

/* 64 hex chars == 32 bytes, long enough for any SHATYPE_DEFAULT key size. */
static const char *const HEXKEY = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee";

/////////////////////// small verification helpers ///////////////////////

static void exec_vfy(const char *sql) {
  char *err = NULL;
  sqlite3_exec(vfy, sql, NULL, NULL, &err);
  if (err) {
    sqlite3_free(err);
  }
}

static int count_rows(const char *sql) {
  sqlite3_stmt *s = NULL;
  int n = -1;
  if (sqlite3_prepare_v2(vfy, sql, -1, &s, NULL) == SQLITE_OK) {
    if (sqlite3_step(s) == SQLITE_ROW) {
      n = sqlite3_column_int(s, 0);
    }
  }
  sqlite3_finalize(s);
  return n;
}

static const char *str_query(const char *sql) {
  static char buf[512];
  buf[0] = 0;
  sqlite3_stmt *s = NULL;
  if (sqlite3_prepare_v2(vfy, sql, -1, &s, NULL) == SQLITE_OK) {
    if (sqlite3_step(s) == SQLITE_ROW) {
      const unsigned char *t = sqlite3_column_text(s, 0);
      if (t) {
        strncpy(buf, (const char *)t, sizeof(buf) - 1);
      }
    }
  }
  sqlite3_finalize(s);
  return buf;
}

static int list_has(secrets_list_t *sl, const char *v) {
  for (size_t i = 0; i < sl->sz; i++) {
    if (sl->secrets[i] && strcmp(sl->secrets[i], v) == 0) {
      return 1;
    }
  }
  return 0;
}

static void list_free(secrets_list_t *sl) {
  for (size_t i = 0; i < sl->sz; i++) {
    free(sl->secrets[i]);
  }
  free(sl->secrets);
  sl->secrets = NULL;
  sl->sz = 0;
}

///////////////////////////// fixture /////////////////////////////

void setUp(void) {
  exec_vfy("delete from turnusers_lt; delete from turn_secret; delete from turn_origin_to_realm;"
           "delete from turn_realm_option; delete from oauth_key; delete from admin_user;"
           "delete from allowed_peer_ip; delete from denied_peer_ip;");
  list_free(&g_test_ip_ranges);
}

void tearDown(void) {}

///////////////////////////// tests /////////////////////////////

static void test_user_roundtrip(void) {
  db->set_user_key((uint8_t *)"alice", (uint8_t *)"north.gov", HEXKEY);

  TEST_ASSERT_EQUAL_INT(1, count_rows("select count(*) from turnusers_lt where name='alice' and realm='north.gov'"));
  TEST_ASSERT_EQUAL_STRING(HEXKEY, str_query("select hmackey from turnusers_lt where name='alice'"));

  hmackey_t key;
  memset(key, 0, sizeof(key));
  TEST_ASSERT_EQUAL_INT(0, db->get_user_key((uint8_t *)"alice", (uint8_t *)"north.gov", key));
  /* first bytes must decode from HEXKEY (00 11 22 33 ...) */
  TEST_ASSERT_EQUAL_HEX8(0x00, key[0]);
  TEST_ASSERT_EQUAL_HEX8(0x11, key[1]);
  TEST_ASSERT_EQUAL_HEX8(0x22, key[2]);
  TEST_ASSERT_EQUAL_HEX8(0x33, key[3]);

  secrets_list_t users = {0};
  secrets_list_t realms = {0};
  TEST_ASSERT_EQUAL_INT(0, db->list_users((uint8_t *)"north.gov", &users, &realms));
  TEST_ASSERT_TRUE(list_has(&users, "alice"));
  list_free(&users);
  list_free(&realms);

  TEST_ASSERT_EQUAL_INT(0, db->del_user((uint8_t *)"alice", (uint8_t *)"north.gov"));
  TEST_ASSERT_EQUAL_INT(0, count_rows("select count(*) from turnusers_lt"));
}

static void test_secret_roundtrip(void) {
  db->set_secret((uint8_t *)"s3cr3t", (uint8_t *)"north.gov");
  TEST_ASSERT_EQUAL_INT(1, count_rows("select count(*) from turn_secret where value='s3cr3t' and realm='north.gov'"));

  secrets_list_t sl = {0};
  TEST_ASSERT_EQUAL_INT(0, db->get_auth_secrets(&sl, (uint8_t *)"north.gov"));
  TEST_ASSERT_TRUE(list_has(&sl, "s3cr3t"));
  list_free(&sl);

  db->del_secret((uint8_t *)"s3cr3t", (uint8_t *)"north.gov");
  TEST_ASSERT_EQUAL_INT(0, count_rows("select count(*) from turn_secret"));
}

static void test_origin_roundtrip(void) {
  db->add_origin((uint8_t *)"http://o.example", (uint8_t *)"north.gov");
  TEST_ASSERT_EQUAL_INT(
      1, count_rows("select count(*) from turn_origin_to_realm where origin='http://o.example' and realm='north.gov'"));

  db->del_origin((uint8_t *)"http://o.example");
  TEST_ASSERT_EQUAL_INT(0, count_rows("select count(*) from turn_origin_to_realm"));
}

static void test_realm_option(void) {
  db->set_realm_option_one((uint8_t *)"north.gov", 1000000, "max-bps");
  TEST_ASSERT_EQUAL_STRING("1000000",
                           str_query("select value from turn_realm_option where realm='north.gov' and opt='max-bps'"));
}

static void test_oauth_roundtrip(void) {
  oauth_key_data_raw k;
  memset(&k, 0, sizeof(k));
  strcpy(k.kid, "kid1");
  strcpy(k.ikm_key, "aGVsbG8=");
  k.timestamp = 1748000000ULL;
  k.lifetime = 3600;
  strcpy(k.as_rs_alg, "hs256");
  strcpy(k.realm, "north.gov");
  db->set_oauth_key(&k);

  oauth_key_data_raw out;
  memset(&out, 0, sizeof(out));
  TEST_ASSERT_EQUAL_INT(0, db->get_oauth_key((const uint8_t *)"kid1", &out));
  TEST_ASSERT_EQUAL_STRING("aGVsbG8=", out.ikm_key);
  TEST_ASSERT_EQUAL_UINT64(1748000000ULL, out.timestamp); /* integer->text bind must preserve this */
  TEST_ASSERT_EQUAL_UINT(3600, out.lifetime);
  TEST_ASSERT_EQUAL_STRING("hs256", out.as_rs_alg);
  TEST_ASSERT_EQUAL_STRING("north.gov", out.realm);

  db->del_oauth_key((const uint8_t *)"kid1");
  TEST_ASSERT_EQUAL_INT(0, count_rows("select count(*) from oauth_key"));
}

static void test_permission_ip_roundtrip(void) {
  /* kind ("allowed") is the table name and stays interpolated; realm + ip are bound. */
  db->set_permission_ip("allowed", (uint8_t *)"north.gov", "10.0.0.0/8", 0);
  TEST_ASSERT_EQUAL_INT(
      1, count_rows("select count(*) from allowed_peer_ip where ip_range='10.0.0.0/8' and realm='north.gov'"));

  TEST_ASSERT_EQUAL_INT(0, db->get_ip_list("allowed", NULL));
  TEST_ASSERT_TRUE(list_has(&g_test_ip_ranges, "10.0.0.0/8"));

  db->set_permission_ip("allowed", (uint8_t *)"north.gov", "10.0.0.0/8", 1);
  TEST_ASSERT_EQUAL_INT(0, count_rows("select count(*) from allowed_peer_ip"));
}

static void test_admin_user_roundtrip(void) {
  password_t pwd_in;
  memset(pwd_in, 0, sizeof(pwd_in));
  strncpy((char *)pwd_in, "secrethash", sizeof(pwd_in) - 1);
  db->set_admin_user((uint8_t *)"wadmin", (uint8_t *)"north.gov", pwd_in);

  password_t pwd_out;
  uint8_t realm_out[STUN_MAX_REALM_SIZE + 1];
  memset(pwd_out, 0, sizeof(pwd_out));
  memset(realm_out, 0, sizeof(realm_out));
  TEST_ASSERT_EQUAL_INT(0, db->get_admin_user((const uint8_t *)"wadmin", realm_out, pwd_out));
  TEST_ASSERT_EQUAL_STRING("north.gov", (char *)realm_out);
  TEST_ASSERT_EQUAL_STRING("secrethash", (char *)pwd_out);

  db->del_admin_user((const uint8_t *)"wadmin");
  TEST_ASSERT_EQUAL_INT(0, count_rows("select count(*) from admin_user"));
}

/* The security regression test. With the old string-interpolated driver the
 * boolean-injection payloads neutralize the WHERE clause and delete unintended
 * rows; with the parameterized driver they are treated as opaque literal values
 * that match nothing. This test therefore FAILS on the old driver and PASSES on
 * the new one. */
static void test_sql_injection_neutralized(void) {
  db->set_user_key((uint8_t *)"alice", (uint8_t *)"r1", HEXKEY);
  db->set_user_key((uint8_t *)"bob", (uint8_t *)"r1", HEXKEY);
  db->set_secret((uint8_t *)"keep-me", (uint8_t *)"r1");
  TEST_ASSERT_EQUAL_INT(2, count_rows("select count(*) from turnusers_lt where realm='r1'"));

  /* name = zzz' OR '1'='1  ->  delete ... where name='zzz' OR '1'='1' and realm='r1' */
  db->del_user((uint8_t *)"zzz' OR '1'='1", (uint8_t *)"r1");
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, count_rows("select count(*) from turnusers_lt where realm='r1'"),
                                "del_user name parameter is SQL-injectable: unintended user rows were deleted");

  /* realm = r1' OR '1'='1 against the secret delete */
  db->del_secret((uint8_t *)"nope", (uint8_t *)"r1' OR '1'='1");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, count_rows("select count(*) from turn_secret where realm='r1'"),
                                "del_secret realm parameter is SQL-injectable: unintended secret rows were deleted");
}

///////////////////////////// main /////////////////////////////

int main(void) {
  snprintf(dbpath, sizeof(dbpath), "/tmp/coturn_test_sqlite_%d.db", (int)getpid());
  unlink(dbpath);

  test_sqlite_support_init(dbpath);
  db = get_sqlite_dbdriver();
  if (!db) {
    fprintf(stderr, "no sqlite driver\n");
    return 2;
  }

  /* First driver call creates the schema; open the verification handle after. */
  secrets_list_t tmp = {0};
  db->list_users((uint8_t *)"force-init", &tmp, NULL);
  list_free(&tmp);

  if (sqlite3_open(dbpath, &vfy) != SQLITE_OK) {
    fprintf(stderr, "cannot open verification db\n");
    return 2;
  }

  UNITY_BEGIN();
  RUN_TEST(test_user_roundtrip);
  RUN_TEST(test_secret_roundtrip);
  RUN_TEST(test_origin_roundtrip);
  RUN_TEST(test_realm_option);
  RUN_TEST(test_oauth_roundtrip);
  RUN_TEST(test_permission_ip_roundtrip);
  RUN_TEST(test_admin_user_roundtrip);
  RUN_TEST(test_sql_injection_neutralized);
  int rc = UNITY_END();

  sqlite3_close(vfy);
  unlink(dbpath);
  return rc;
}
