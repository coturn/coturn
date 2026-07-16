/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 */

#ifndef TEST_PGSQL_STUB_H
#define TEST_PGSQL_STUB_H

/* Inspect what the driver last sent through the mocked libpq. */
void pgstub_reset(void);
const char *pgstub_last_command(void); /* SQL text the driver emitted */
int pgstub_last_nparams(void);         /* number of bound parameters */
int pgstub_used_params(void);          /* 1 if via PQexecParams, 0 if PQexec */
const char *pgstub_last_param(int i);  /* bound value i, or NULL */

#endif /* TEST_PGSQL_STUB_H */
