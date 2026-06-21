#include "ns_turn_ratelimit.h"

#include <unity.h>

#include <stdio.h>

void setUp(void) { ratelimit_init(); }
void tearDown(void) {}

static void test_live_bucket_collision_shares_exhausted_budget(void) {
  ioa_addr victim = {0};
  ioa_addr collider = {0};
  bool found_collision = false;

  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"203.0.113.9", 3478, &victim));

  for (unsigned int i = 0; i < 65536 && !found_collision; ++i) {
    char candidate[INET_ADDRSTRLEN] = {0};
    bool first_drop = false;
    bool first_collision = false;

    snprintf(candidate, sizeof(candidate), "198.18.%u.%u", i >> 8, i & 0xffu);
    TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)candidate, 3478, &collider));

    ratelimit_init();
    TEST_ASSERT_FALSE(ratelimit_consume_address(&victim, 1u, NULL, NULL));
    found_collision =
        ratelimit_consume_address(&collider, 1u, &first_drop, &first_collision) && first_drop && first_collision;
  }

  TEST_ASSERT_TRUE_MESSAGE(found_collision, "failed to locate a bucket collision for regression coverage");

  ratelimit_init();
  TEST_ASSERT_FALSE(ratelimit_consume_address(&victim, 1u, NULL, NULL));

  bool first_drop = false;
  bool first_collision = false;
  TEST_ASSERT_TRUE(ratelimit_consume_address(&collider, 1u, &first_drop, &first_collision));
  TEST_ASSERT_TRUE(first_drop);
  TEST_ASSERT_TRUE(first_collision);

  first_drop = false;
  first_collision = false;
  TEST_ASSERT_TRUE(ratelimit_consume_address(&collider, 1u, &first_drop, &first_collision));
  TEST_ASSERT_FALSE(first_drop);
  TEST_ASSERT_FALSE(first_collision);

  first_drop = false;
  first_collision = false;
  TEST_ASSERT_TRUE(ratelimit_consume_address(&victim, 1u, &first_drop, &first_collision));
  TEST_ASSERT_FALSE(first_drop);
  TEST_ASSERT_FALSE(first_collision);
}

static void test_capacity_is_nonzero_power_of_two(void) {
  uint32_t cap = ratelimit_get_capacity();
  TEST_ASSERT_GREATER_THAN_UINT32(0u, cap);
  TEST_ASSERT_EQUAL_UINT32(0u, cap & (cap - 1u));
}

static void test_occupancy_tracks_live_buckets(void) {
  ioa_addr a = {0};
  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"203.0.113.9", 3478, &a));

  ratelimit_init();
  TEST_ASSERT_EQUAL_UINT32(0u, ratelimit_count_occupied());

  /* The first consume opens a window in exactly one bucket. */
  TEST_ASSERT_FALSE(ratelimit_consume_address(&a, 5u, NULL, NULL));
  TEST_ASSERT_EQUAL_UINT32(1u, ratelimit_count_occupied());
}

static void test_collision_counter_counts_every_collision(void) {
  ioa_addr victim = {0};
  ioa_addr collider = {0};
  bool found_collision = false;

  TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)"203.0.113.9", 3478, &victim));

  /* Locate an address that hashes into the victim's bucket. */
  for (unsigned int i = 0; i < 65536 && !found_collision; ++i) {
    char candidate[INET_ADDRSTRLEN] = {0};
    bool first_collision = false;

    snprintf(candidate, sizeof(candidate), "198.18.%u.%u", i >> 8, i & 0xffu);
    TEST_ASSERT_EQUAL_INT(0, make_ioa_addr((const uint8_t *)candidate, 3478, &collider));

    ratelimit_init();
    TEST_ASSERT_FALSE(ratelimit_consume_address(&victim, 1u, NULL, NULL));
    found_collision = ratelimit_consume_address(&collider, 1u, NULL, &first_collision) && first_collision;
  }
  TEST_ASSERT_TRUE_MESSAGE(found_collision, "failed to locate a bucket collision for counter coverage");

  ratelimit_init();
  TEST_ASSERT_EQUAL_UINT32(0u, ratelimit_get_collisions());

  /* The bucket owner's own request is never a collision. */
  TEST_ASSERT_FALSE(ratelimit_consume_address(&victim, 1u, NULL, NULL));
  TEST_ASSERT_EQUAL_UINT32(0u, ratelimit_get_collisions());

  /* Every colliding request is counted, not just the first one in the window. */
  ratelimit_consume_address(&collider, 1u, NULL, NULL);
  TEST_ASSERT_EQUAL_UINT32(1u, ratelimit_get_collisions());
  ratelimit_consume_address(&collider, 1u, NULL, NULL);
  TEST_ASSERT_EQUAL_UINT32(2u, ratelimit_get_collisions());
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_live_bucket_collision_shares_exhausted_budget);
  RUN_TEST(test_capacity_is_nonzero_power_of_two);
  RUN_TEST(test_occupancy_tracks_live_buckets);
  RUN_TEST(test_collision_counter_counts_every_collision);
  return UNITY_END();
}
