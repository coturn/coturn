/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 */

#ifndef TEST_MYSQL_STUB_H
#define TEST_MYSQL_STUB_H

/* Inspect what the driver last sent through the mocked libmysqlclient. */
void mystub_reset(void);
const char *mystub_last_command(void); /* SQL text the driver emitted */
int mystub_used_stmt(void);            /* 1 if via prepared statement, 0 if mysql_query */
int mystub_nparams(void);              /* number of bound parameters */
const char *mystub_param(int i);       /* bound value i, or NULL */

/* Queue one result row to be returned by the next read query's fetch. */
void mystub_set_row(int ncols, const char *const *vals);

#endif /* TEST_MYSQL_STUB_H */
