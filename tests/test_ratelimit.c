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
    TEST_ASSERT_FALSE(ratelimit_consume_address(&victim, 1u, 60u, NULL, NULL));
    found_collision =
        ratelimit_consume_address(&collider, 1u, 60u, &first_drop, &first_collision) && first_drop && first_collision;
  }

  TEST_ASSERT_TRUE_MESSAGE(found_collision, "failed to locate a bucket collision for regression coverage");

  ratelimit_init();
  TEST_ASSERT_FALSE(ratelimit_consume_address(&victim, 1u, 60u, NULL, NULL));

  bool first_drop = false;
  bool first_collision = false;
  TEST_ASSERT_TRUE(ratelimit_consume_address(&collider, 1u, 60u, &first_drop, &first_collision));
  TEST_ASSERT_TRUE(first_drop);
  TEST_ASSERT_TRUE(first_collision);

  first_drop = false;
  first_collision = false;
  TEST_ASSERT_TRUE(ratelimit_consume_address(&collider, 1u, 60u, &first_drop, &first_collision));
  TEST_ASSERT_FALSE(first_drop);
  TEST_ASSERT_FALSE(first_collision);

  first_drop = false;
  first_collision = false;
  TEST_ASSERT_TRUE(ratelimit_consume_address(&victim, 1u, 60u, &first_drop, &first_collision));
  TEST_ASSERT_FALSE(first_drop);
  TEST_ASSERT_FALSE(first_collision);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_live_bucket_collision_shares_exhausted_budget);
  return UNITY_END();
}
