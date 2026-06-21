/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2026 coturn project
 *
 * Unit tests for the vendored, self-contained Prometheus client
 * (src/prometheus). Exercises counter/gauge math, label handling, value
 * escaping and the text-exposition serializer used by prom_server.c.
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

#include "prom.h"
#include "unity.h"

#include <stdlib.h>
#include <string.h>

/* The default registry is process-global and has no teardown in the minimal
 * client (it lives for the lifetime of turnserver), so initialize it once and
 * register each test's metrics under fresh, uniquely named series. */
void setUp(void) { TEST_ASSERT_EQUAL_INT(0, prom_collector_registry_default_init()); }
void tearDown(void) {}

static char *render(void) {
  char *out = (char *)prom_collector_registry_bridge(PROM_COLLECTOR_REGISTRY_DEFAULT);
  TEST_ASSERT_NOT_NULL(out);
  return out;
}

static void test_counter_accumulates_per_label_set(void) {
  const char *keys[] = {"realm", "user"};
  prom_counter_t *c =
      prom_collector_registry_must_register_metric(prom_counter_new("t_traffic", "rcv packets", 2, keys));
  TEST_ASSERT_NOT_NULL(c);

  const char *bob[] = {"north.gov", "bob"};
  const char *alice[] = {"north.gov", "alice"};
  prom_counter_add(c, 5, bob);
  prom_counter_add(c, 3, bob); /* same series -> 8 */
  prom_counter_add(c, 7, alice);

  char *out = render();
  TEST_ASSERT_NOT_NULL(strstr(out, "# TYPE t_traffic counter"));
  TEST_ASSERT_NOT_NULL(strstr(out, "t_traffic{realm=\"north.gov\",user=\"bob\"} 8"));
  TEST_ASSERT_NOT_NULL(strstr(out, "t_traffic{realm=\"north.gov\",user=\"alice\"} 7"));
  free(out);
}

static void test_counter_ignores_negative_delta(void) {
  prom_counter_t *c = prom_collector_registry_must_register_metric(prom_counter_new("t_monotonic", "h", 0, NULL));
  prom_counter_add(c, 10, NULL);
  TEST_ASSERT_NOT_EQUAL(0, prom_counter_add(c, -4, NULL)); /* rejected */

  char *out = render();
  TEST_ASSERT_NOT_NULL(strstr(out, "t_monotonic 10"));
  free(out);
}

static void test_gauge_inc_dec(void) {
  const char *keys[] = {"type"};
  prom_gauge_t *g = prom_collector_registry_must_register_metric(prom_gauge_new("t_allocations", "allocs", 1, keys));
  const char *udp[] = {"udp"};
  prom_gauge_inc(g, udp);
  prom_gauge_inc(g, udp);
  prom_gauge_dec(g, udp); /* -> 1 */

  char *out = render();
  TEST_ASSERT_NOT_NULL(strstr(out, "# TYPE t_allocations gauge"));
  TEST_ASSERT_NOT_NULL(strstr(out, "t_allocations{type=\"udp\"} 1"));
  free(out);
}

static void test_label_value_escaping(void) {
  const char *keys[] = {"user"};
  prom_counter_t *c = prom_collector_registry_must_register_metric(prom_counter_new("t_escape", "h", 1, keys));
  const char *weird[] = {"a\"b\\c\nd"};
  prom_counter_add(c, 1, weird);

  char *out = render();
  /* backslash, double-quote and newline must be escaped per text format. */
  TEST_ASSERT_NOT_NULL(strstr(out, "t_escape{user=\"a\\\"b\\\\c\\nd\"} 1"));
  free(out);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_counter_accumulates_per_label_set);
  RUN_TEST(test_counter_ignores_negative_delta);
  RUN_TEST(test_gauge_inc_dec);
  RUN_TEST(test_label_value_escaping);
  return UNITY_END();
}
