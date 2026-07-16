/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Minimal support/stub layer that lets tests/test_sqlite_dbd.c link
 * src/apps/relay/dbdrivers/dbd_sqlite.c in isolation, without dragging in the
 * whole turnserver. It provides just the relay/server symbols the SQLite
 * driver references: the userdb path accessor, the per-thread connection key,
 * the hex->binary key conversion, and trivial implementations of the realm /
 * secrets-list / origin-map helpers the driver calls into.
 *
 * The same stubs are used for both the old (string-interpolated) and the new
 * (parameterized) driver, so any behavior difference the tests observe comes
 * from the driver under test, not from this layer.
 */

#include "mainrelay.h"

#include "dbdrivers/dbdriver.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "test_sqlite_support.h"

/* Globals the driver expects to exist. mainrelay.c normally defines these; in
 * the test we own them. */
turn_params_t turn_params;
pthread_key_t connection_key;

static persistent_users_db_t g_pud;

void test_sqlite_support_init(const char *dbpath) {
  static int key_created = 0;
  if (!key_created) {
    (void)pthread_key_create(&connection_key, NULL);
    key_created = 1;
  }
  memset(&g_pud, 0, sizeof(g_pud));
  strncpy(g_pud.userdb, dbpath, sizeof(g_pud.userdb) - 1);
}

persistent_users_db_t *get_persistent_users_db(void) { return &g_pud; }

/* Verbatim from dbdriver.c (relay), which we do not link here. */
void convert_string_key_to_binary(const char *keysource, hmackey_t key, size_t sz) {
  char is[3] = {0};
  is[2] = 0;
  for (size_t i = 0; i < sz; i++) {
    is[0] = keysource[i * 2];
    is[1] = keysource[i * 2 + 1];
    unsigned int v = 0;
    sscanf(is, "%02x", &v);
    key[i] = (unsigned char)v;
  }
}

/* --- secrets_list_t helpers: minimal append so the driver's list-producing
 * functions can be observed by the test. --- */
void add_to_secrets_list(secrets_list_t *sl, const char *elem) {
  if (!sl) {
    return;
  }
  char **n = (char **)realloc(sl->secrets, (sl->sz + 1) * sizeof(char *));
  if (!n) {
    return;
  }
  sl->secrets = n;
  sl->secrets[sl->sz++] = strdup(elem ? elem : "");
}

/* The driver forwards (kind table -> rows) into add_ip_list_range(); capture the
 * ranges into a list the test can inspect. The ip_range_list_t argument is the
 * test-owned (here ignored) sink. */
secrets_list_t g_test_ip_ranges;

int add_ip_list_range(const char *range, const char *realm, ip_range_list_t *list) {
  (void)realm;
  (void)list;
  add_to_secrets_list(&g_test_ip_ranges, range);
  return 0;
}

/* Only reached by sqlite_reread_realms(), which the tests do not exercise; these
 * exist purely to satisfy the linker. */
static realm_params_t g_realm;
realm_params_t *get_realm(char *name) {
  (void)name;
  return &g_realm;
}
void lock_realms(void) {}
void unlock_realms(void) {}
void update_o_to_realm(ur_string_map *o_to_realm_new) { (void)o_to_realm_new; }
ur_string_map *ur_string_map_create(ur_string_map_func del_value_func) {
  (void)del_value_func;
  return NULL;
}
void ur_string_map_free(ur_string_map **map) {
  if (map) {
    *map = NULL;
  }
}
bool ur_string_map_put(ur_string_map *map, const ur_string_map_key_type key, ur_string_map_value_type value) {
  (void)map;
  (void)key;
  (void)value;
  return true;
}
