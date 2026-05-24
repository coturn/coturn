/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 */

#ifndef TEST_SQLITE_SUPPORT_H
#define TEST_SQLITE_SUPPORT_H

#include "userdb.h" /* secrets_list_t */

/* Point the SQLite driver at `dbpath` and lazily create the per-thread
 * connection key. Call once before driving the driver. */
void test_sqlite_support_init(const char *dbpath);

/* Ranges captured from the driver's get_ip_list() path, for assertions. */
extern secrets_list_t g_test_ip_ranges;

#endif /* TEST_SQLITE_SUPPORT_H */
