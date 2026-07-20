/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Regression test for issue #1649: the relay port allocator tracks its
 * free-port ring with two monotonically increasing uint32_t cursors
 * (low advances on every allocation attempt, high on every release).
 * After ~4 billion operations on one pool the cursors wrap; with the old
 * empty-pool guard `tp->high <= tp->low` a wrapped `high` and a not yet
 * wrapped `low` made the guard permanently true, so the pool never
 * allocated again until restart. The guard must use wrap-safe unsigned
 * arithmetic (`(high - low) == 0`) instead.
 *
 * The test compiles the real src/apps/relay/turn_ports.c into this
 * translation unit to reach the static turnports_* functions and the
 * private struct layout, then fast-forwards the cursors to just below
 * UINT32_MAX and drives real allocate/release cycles across the 2^32
 * boundary.
 */

#include "unity.h"

#include "../src/apps/relay/turn_ports.c"

#include <stdio.h>
#include <stdlib.h>

/* ---- link stubs --------------------------------------------------------
 * turn_ports.c also carries the turnipports_* layer, which references the
 * super-memory allocator and ur_addr_map. The tests drive only the
 * per-pool turnports_* level, so the map functions must never run. */

void *allocate_super_memory_region_func(super_memory_t *region, size_t size, const char *file, const char *func,
                                        int line) {
  (void)region;
  (void)file;
  (void)func;
  (void)line;
  return calloc(1, size);
}

void ur_addr_map_init(ur_addr_map *map) {
  (void)map;
  abort();
}

bool ur_addr_map_put(ur_addr_map *map, ioa_addr *key, ur_addr_map_value_type value) {
  (void)map;
  (void)key;
  (void)value;
  abort();
}

bool ur_addr_map_get(const ur_addr_map *map, ioa_addr *key, ur_addr_map_value_type *value) {
  (void)map;
  (void)key;
  (void)value;
  abort();
}

/* ---- helpers ----------------------------------------------------------- */

#define TEST_PORT_START 50000
#define TEST_NPORTS 16
#define TEST_PORT_END (TEST_PORT_START + TEST_NPORTS - 1)

/* Advance both cursors (and every live queue-position entry in status[])
 * by the same delta, as if delta alloc/release operations had already
 * happened. delta must be a multiple of 0x10000 so the `cursor & 0xFFFF`
 * ring positions - and therefore the ports[] layout - stay valid. */
static void fast_forward(turnports *t, uint32_t delta) {
  TEST_ASSERT_EQUAL_UINT32(0, delta & 0xFFFF);
  t->low += delta;
  t->high += delta;
  for (size_t p = 0; p < PORTS_SIZE; ++p) {
    if ((t->status[p] != TPS_OUT_OF_RANGE) && !is_taken(t->status[p])) {
      t->status[p] += delta;
    }
  }
}

/* ---- tests ------------------------------------------------------------- */

static void test_basic_allocate_release_cycle(void) {
  turnports *t = turnports_create(NULL, TEST_PORT_START, TEST_PORT_END);
  TEST_ASSERT_NOT_NULL(t);
  TEST_ASSERT_EQUAL_UINT16(TEST_NPORTS, turnports_size(t));

  uint8_t seen[TEST_NPORTS] = {0};
  int ports[TEST_NPORTS] = {0};
  for (int i = 0; i < TEST_NPORTS; ++i) {
    const int port = turnports_allocate(t);
    TEST_ASSERT_TRUE(port >= TEST_PORT_START && port <= TEST_PORT_END);
    TEST_ASSERT_FALSE(seen[port - TEST_PORT_START]);
    seen[port - TEST_PORT_START] = 1;
    ports[i] = port;
    TEST_ASSERT_TRUE(turnports_is_allocated(t, (uint16_t)port));
  }

  /* Pool exhausted: the guard must report empty, not spin. */
  TEST_ASSERT_EQUAL_INT(-1, turnports_allocate(t));
  TEST_ASSERT_EQUAL_UINT16(0, turnports_size(t));

  for (int i = 0; i < TEST_NPORTS; ++i) {
    turnports_release(t, (uint16_t)ports[i]);
  }
  TEST_ASSERT_EQUAL_UINT16(TEST_NPORTS, turnports_size(t));
  TEST_ASSERT_TRUE(turnports_allocate(t) >= TEST_PORT_START);

  free(t);
}

static void test_allocate_survives_counter_wraparound(void) {
  turnports *t = turnports_create(NULL, TEST_PORT_START, TEST_PORT_END);
  TEST_ASSERT_NOT_NULL(t);

  /* Park the cursors just below UINT32_MAX, then walk real alloc/release
   * cycles across the 2^32 boundary. With the pre-#1724 guard this fails
   * permanently at the iteration where high wraps to 0 while low is still
   * large. */
  fast_forward(t, 0xFFFE0000u);
  TEST_ASSERT_EQUAL_UINT16(TEST_NPORTS, turnports_size(t));

  const uint32_t start_low = t->low;
  int wrapped = 0;
  for (uint32_t i = 0; i < 3 * 0x10000u; ++i) {
    const int port = turnports_allocate(t);
    if (port < 0) {
      char msg[128] = {0};
      snprintf(msg, sizeof(msg), "allocation failed at iteration %u (low=%u, high=%u)", i, t->low, t->high);
      TEST_FAIL_MESSAGE(msg);
    }
    TEST_ASSERT_TRUE(port >= TEST_PORT_START && port <= TEST_PORT_END);
    turnports_release(t, (uint16_t)port);
    if (t->low < start_low) {
      wrapped = 1;
    }
  }
  TEST_ASSERT_TRUE_MESSAGE(wrapped, "test never drove the cursors across the 2^32 boundary");

  /* The pool must still be usable after the wrap. Up to 4 ports may be
   * lost when high passes through the TPS_* sentinel values
   * (0xFFFFFFFC..0xFFFFFFFF) - a known residual of the counter-wrap
   * design - but the pool must not degrade beyond that. */
  int live = 0;
  int drained[TEST_NPORTS] = {0};
  while (live < TEST_NPORTS) {
    const int port = turnports_allocate(t);
    if (port < 0) {
      break;
    }
    drained[live++] = port;
  }
  TEST_ASSERT_GREATER_OR_EQUAL_INT_MESSAGE(TEST_NPORTS - 4, live, "too many ports leaked across the counter wrap");
  for (int i = 0; i < live; ++i) {
    turnports_release(t, (uint16_t)drained[i]);
  }

  free(t);
}

/* ---- harness ----------------------------------------------------------- */

void setUp(void) {}
void tearDown(void) {}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_basic_allocate_release_cycle);
  RUN_TEST(test_allocate_survives_counter_wraparound);
  return UNITY_END();
}
