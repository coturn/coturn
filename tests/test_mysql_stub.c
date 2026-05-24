/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Link-seam mock of the subset of libmysqlclient that dbd_mysql.c uses, so the
 * MySQL driver can be unit-tested with no server. It captures what the driver
 * sends:
 *   - the prepared-statement path (new code): the prepared SQL text and the
 *     bound parameter values;
 *   - the classic mysql_query() path (old code): the interpolated SQL.
 * It can also feed one canned result row so the read paths' result handling is
 * exercised.
 *
 * dbd_mysql.c is compiled against the real <mysql.h>, so these definitions must
 * match the real prototypes; only the implementations are fake.
 */

#include <mysql.h>

#include <stdio.h>
#include <string.h>

#include "test_mysql_stub.h"

/* matches the declaration in mainrelay.h; only used as an opaque pointer here */
struct ctr_state;

#define MYSTUB_MAX 8
#define MYSTUB_STR 2048

static char g_command[MYSTUB_STR];
static int g_used_stmt;
static int g_nparams;
static char g_params[MYSTUB_MAX][MYSTUB_STR];
static int g_param_count_expected; /* number of '?' in last prepared stmt */

/* one canned result row */
static int g_row_ncols;
static int g_row_pending;
static char g_row_vals[MYSTUB_MAX][MYSTUB_STR];
static MYSQL_BIND *g_result_binds;

static char g_myc_sentinel;
static char g_stmt_sentinel;
static char g_res_sentinel;

void mystub_reset(void) {
  g_command[0] = 0;
  g_used_stmt = 0;
  g_nparams = 0;
  g_param_count_expected = 0;
  g_row_ncols = 0;
  g_row_pending = 0;
  g_result_binds = NULL;
}

const char *mystub_last_command(void) { return g_command; }
int mystub_used_stmt(void) { return g_used_stmt; }
int mystub_nparams(void) { return g_nparams; }
const char *mystub_param(int i) {
  if (i < 0 || i >= g_nparams || i >= MYSTUB_MAX) {
    return NULL;
  }
  return g_params[i];
}
void mystub_set_row(int ncols, const char *const *vals) {
  g_row_ncols = (ncols > MYSTUB_MAX) ? MYSTUB_MAX : ncols;
  for (int i = 0; i < g_row_ncols; ++i) {
    snprintf(g_row_vals[i], sizeof(g_row_vals[i]), "%s", vals[i] ? vals[i] : "");
  }
  g_row_pending = 1;
}

static int count_placeholders(const char *s) {
  int n = 0;
  for (; s && *s; ++s) {
    if (*s == '?') {
      ++n;
    }
  }
  return n;
}

/////////////////////// connection ///////////////////////

MYSQL *mysql_init(MYSQL *mysql) {
  (void)mysql;
  return (MYSQL *)&g_myc_sentinel;
}
int mysql_ping(MYSQL *mysql) {
  (void)mysql;
  return 0;
}
void mysql_close(MYSQL *sock) { (void)sock; }
MYSQL *mysql_real_connect(MYSQL *mysql, const char *host, const char *user, const char *passwd, const char *db,
                          unsigned int port, const char *unix_socket, unsigned long clientflag) {
  (void)host;
  (void)user;
  (void)passwd;
  (void)db;
  (void)port;
  (void)unix_socket;
  (void)clientflag;
  return mysql;
}
int mysql_options(MYSQL *mysql, enum mysql_option option, const void *arg) {
  (void)mysql;
  (void)option;
  (void)arg;
  return 0;
}
int mysql_select_db(MYSQL *mysql, const char *db) {
  (void)mysql;
  (void)db;
  return 0;
}
const char *mysql_error(MYSQL *mysql) {
  (void)mysql;
  return "";
}
bool mysql_ssl_set(MYSQL *mysql, const char *key, const char *cert, const char *ca, const char *capath,
                   const char *cipher) {
  (void)mysql;
  (void)key;
  (void)cert;
  (void)ca;
  (void)capath;
  (void)cipher;
  return false;
}

/////////////////////// prepared statements ///////////////////////

MYSQL_STMT *mysql_stmt_init(MYSQL *mysql) {
  (void)mysql;
  return (MYSQL_STMT *)&g_stmt_sentinel;
}
int mysql_stmt_prepare(MYSQL_STMT *stmt, const char *query, unsigned long length) {
  (void)stmt;
  (void)length;
  g_used_stmt = 1;
  g_nparams = 0;
  g_result_binds = NULL;
  snprintf(g_command, sizeof(g_command), "%s", query ? query : "");
  g_param_count_expected = count_placeholders(g_command);
  return 0;
}
bool mysql_stmt_bind_param(MYSQL_STMT *stmt, MYSQL_BIND *bnd) {
  (void)stmt;
  g_nparams = g_param_count_expected;
  for (int i = 0; i < g_nparams && i < MYSTUB_MAX; ++i) {
    unsigned long len = bnd[i].buffer_length;
    if (len >= MYSTUB_STR) {
      len = MYSTUB_STR - 1;
    }
    if (bnd[i].buffer) {
      memcpy(g_params[i], bnd[i].buffer, len);
    }
    g_params[i][len] = 0;
  }
  return false;
}
int mysql_stmt_execute(MYSQL_STMT *stmt) {
  (void)stmt;
  return 0;
}
bool mysql_stmt_bind_result(MYSQL_STMT *stmt, MYSQL_BIND *bnd) {
  (void)stmt;
  g_result_binds = bnd;
  return false;
}
int mysql_stmt_fetch(MYSQL_STMT *stmt) {
  (void)stmt;
  if (!g_row_pending || !g_result_binds) {
    return MYSQL_NO_DATA;
  }
  for (int i = 0; i < g_row_ncols; ++i) {
    MYSQL_BIND *b = &g_result_binds[i];
    unsigned long len = (unsigned long)strlen(g_row_vals[i]);
    unsigned long cap = b->buffer_length;
    unsigned long n = (len > cap) ? cap : len;
    if (b->buffer) {
      memcpy(b->buffer, g_row_vals[i], n);
    }
    if (b->length) {
      *(b->length) = len;
    }
  }
  g_row_pending = 0;
  return 0;
}
bool mysql_stmt_close(MYSQL_STMT *stmt) {
  (void)stmt;
  return false;
}
const char *mysql_stmt_error(MYSQL_STMT *stmt) {
  (void)stmt;
  return "";
}

/////////////////////// classic API (only the old driver uses these) ///////////////////////

int mysql_query(MYSQL *mysql, const char *q) {
  (void)mysql;
  g_used_stmt = 0;
  g_nparams = 0;
  snprintf(g_command, sizeof(g_command), "%s", q ? q : "");
  return 0;
}
MYSQL_RES *mysql_store_result(MYSQL *mysql) {
  (void)mysql;
  return (MYSQL_RES *)&g_res_sentinel; /* non-NULL; 0 rows via fetch_row below */
}
MYSQL_ROW mysql_fetch_row(MYSQL_RES *result) {
  (void)result;
  return NULL;
}
unsigned long *mysql_fetch_lengths(MYSQL_RES *result) {
  (void)result;
  return NULL;
}
unsigned int mysql_field_count(MYSQL *mysql) {
  (void)mysql;
  return 2;
}
void mysql_free_result(MYSQL_RES *result) { (void)result; }

/////////////////////// decryptPassword() deps (compiled but never called) ///////////////////////

unsigned char *base64decode(const void *b64_decode_this, int decode_this_many_bytes) {
  (void)b64_decode_this;
  (void)decode_this_many_bytes;
  return NULL;
}
int decodedTextSize(char *input) {
  (void)input;
  return 0;
}
int init_ctr(struct ctr_state *state, const unsigned char iv[8]) {
  (void)state;
  (void)iv;
  return 0;
}
