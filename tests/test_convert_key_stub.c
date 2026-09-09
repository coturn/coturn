/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Link seam for test_convert_key: dbdriver.c is compiled into the test to reach
 * the real convert_string_key_to_binary(), which pulls in get_dbdriver() and
 * its turn_params reference. The test never calls those, so provide the minimal
 * definitions the linker needs and nothing more.
 */

#include "dbdrivers/dbdriver.h"
#include "mainrelay.h"

turn_params_t turn_params;

const turn_dbdriver_t *get_redis_dbdriver(void) { return NULL; }
