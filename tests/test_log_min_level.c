/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "ns_turn_utils.h"

#include <unity.h>

void setUp(void) { log_min_level = TURN_LOG_LEVEL_DEBUG; }

void tearDown(void) { log_min_level = TURN_LOG_LEVEL_DEBUG; }

static void test_accepts_each_level_name(void) {
  set_log_min_level("debug");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_DEBUG, log_min_level);

  set_log_min_level("info");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_INFO, log_min_level);

  set_log_min_level("warning");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_WARNING, log_min_level);

  set_log_min_level("error");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_ERROR, log_min_level);
}

static void test_level_name_is_case_insensitive(void) {
  set_log_min_level("WARNING");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_WARNING, log_min_level);

  set_log_min_level("Error");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_ERROR, log_min_level);
}

/* An unrecognized value must be ignored, leaving the previous level in place --
 * it must never silently fall through to "log nothing". */
static void test_invalid_value_is_ignored(void) {
  set_log_min_level("warning");

  set_log_min_level("bogus");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_WARNING, log_min_level);

  set_log_min_level("");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_WARNING, log_min_level);

  set_log_min_level(NULL);
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_WARNING, log_min_level);
}

/* Numeric arguments used to be the interface. They are no longer accepted, and
 * must not be able to push the level past ERROR and mute the server entirely. */
static void test_numeric_value_is_rejected(void) {
  set_log_min_level("info");

  set_log_min_level("3");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_INFO, log_min_level);

  set_log_min_level("4");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_INFO, log_min_level);

  set_log_min_level("-1");
  TEST_ASSERT_EQUAL_INT(TURN_LOG_LEVEL_INFO, log_min_level);
}

/* Whatever the configured minimum, ERROR must always survive the filter. */
static void test_error_is_never_filtered_out(void) {
  set_log_min_level("error");
  TEST_ASSERT_TRUE(TURN_LOG_LEVEL_ERROR >= log_min_level);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_accepts_each_level_name);
  RUN_TEST(test_level_name_is_case_insensitive);
  RUN_TEST(test_invalid_value_is_ignored);
  RUN_TEST(test_numeric_value_is_rejected);
  RUN_TEST(test_error_is_never_filtered_out);
  return UNITY_END();
}
