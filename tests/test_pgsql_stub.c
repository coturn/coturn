/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Link-seam mock of the subset of libpq that dbd_pgsql.c uses. It lets the
 * PostgreSQL driver be unit-tested with no server: every statement the driver
 * issues is captured (command text, whether it was parameterized, and the bound
 * parameter values) so the test can assert the driver keeps caller values out
 * of the SQL text. SELECTs return an empty (0-row) result, which is all the
 * tests need -- they assert the emitted command/params, not row contents.
 *
 * dbd_pgsql.c is compiled against the real <libpq-fe.h>, so these definitions
 * must match the real prototypes; only the implementations are fake.
 */

#include <libpq-fe.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "test_pgsql_stub.h"

/* opaque libpq types, completed here */
struct pg_conn {
  int dummy;
};
struct pg_result {
  ExecStatusType status;
};

static struct pg_conn g_conn;
static struct pg_result g_result;

#define PGSTUB_MAX_PARAMS 8
#define PGSTUB_STR 2048

static char g_command[PGSTUB_STR];
static int g_nparams;
static int g_used_params;
static char g_params[PGSTUB_MAX_PARAMS][PGSTUB_STR];

void pgstub_reset(void) {
  g_command[0] = 0;
  g_nparams = 0;
  g_used_params = 0;
}

const char *pgstub_last_command(void) { return g_command; }
int pgstub_last_nparams(void) { return g_nparams; }
int pgstub_used_params(void) { return g_used_params; }
const char *pgstub_last_param(int i) {
  if (i < 0 || i >= g_nparams || i >= PGSTUB_MAX_PARAMS) {
    return NULL;
  }
  return g_params[i];
}

static struct pg_result *result_for(const char *command) {
  const char *p = command;
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
    ++p;
  }
  /* SELECTs return rows; everything else is a command. */
  g_result.status = (strncasecmp(p, "select", 6) == 0) ? PGRES_TUPLES_OK : PGRES_COMMAND_OK;
  return &g_result;
}

/////////////////////// connection ///////////////////////

ConnStatusType PQstatus(const PGconn *conn) {
  (void)conn;
  return CONNECTION_OK;
}
void PQfinish(PGconn *conn) { (void)conn; }
PGconn *PQconnectdb(const char *conninfo) {
  (void)conninfo;
  return &g_conn;
}
PQconninfoOption *PQconninfoParse(const char *conninfo, char **errmsg) {
  (void)conninfo;
  if (errmsg) {
    *errmsg = NULL;
  }
  /* non-NULL so the driver proceeds; it only frees this, never reads it. */
  static PQconninfoOption opt;
  return &opt;
}
void PQconninfoFree(PQconninfoOption *connOptions) { (void)connOptions; }
char *PQerrorMessage(const PGconn *conn) {
  (void)conn;
  return (char *)"";
}

/////////////////////// statements ///////////////////////

PGresult *PQexec(PGconn *conn, const char *query) {
  (void)conn;
  g_used_params = 0;
  g_nparams = 0;
  snprintf(g_command, sizeof(g_command), "%s", query ? query : "");
  return result_for(g_command);
}

PGresult *PQexecParams(PGconn *conn, const char *command, int nParams, const Oid *paramTypes,
                       const char *const *paramValues, const int *paramLengths, const int *paramFormats,
                       int resultFormat) {
  (void)conn;
  (void)paramTypes;
  (void)paramLengths;
  (void)paramFormats;
  (void)resultFormat;
  g_used_params = 1;
  g_nparams = nParams;
  snprintf(g_command, sizeof(g_command), "%s", command ? command : "");
  for (int i = 0; i < nParams && i < PGSTUB_MAX_PARAMS; ++i) {
    snprintf(g_params[i], sizeof(g_params[i]), "%s", (paramValues && paramValues[i]) ? paramValues[i] : "");
  }
  return result_for(g_command);
}

/////////////////////// results ///////////////////////

ExecStatusType PQresultStatus(const PGresult *res) { return res ? res->status : PGRES_FATAL_ERROR; }
int PQntuples(const PGresult *res) {
  (void)res;
  return 0;
}
char *PQgetvalue(const PGresult *res, int tup_num, int field_num) {
  (void)res;
  (void)tup_num;
  (void)field_num;
  return (char *)"";
}
int PQgetlength(const PGresult *res, int tup_num, int field_num) {
  (void)res;
  (void)tup_num;
  (void)field_num;
  return 0;
}
void PQclear(PGresult *res) { (void)res; }
