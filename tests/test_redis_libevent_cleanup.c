/*
 * Regression tests for Redis/libevent cleanup on connection and event setup
 * failures. The real hiredis and libevent implementations are used; only
 * event_new() is wrapped so each allocation failure can be injected
 * deterministically. redisAsyncFree() is wrapped to count calls before
 * delegating to the real hiredis implementation.
 */

#include <unity.h>

#include <event2/event.h>
#include <hiredis/async.h>
#include <hiredis/hiredis.h>

#include <stdlib.h>
#include <string.h>

static int fail_event_new_call;
static int event_new_calls;
static int redis_async_free_calls;

static struct event *call_real_event_new(struct event_base *base, evutil_socket_t fd, short events,
                                         event_callback_fn callback, void *arg) {
  return event_new(base, fd, events, callback, arg);
}

static struct event *fault_event_new(struct event_base *base, evutil_socket_t fd, short events,
                                     event_callback_fn callback, void *arg) {
  ++event_new_calls;
  if (event_new_calls == fail_event_new_call) {
    return NULL;
  }
  return call_real_event_new(base, fd, events, callback, arg);
}

static void call_real_redis_async_free(redisAsyncContext *ac) { redisAsyncFree(ac); }

static void tracking_redis_async_free(redisAsyncContext *ac) {
  ++redis_async_free_calls;
  call_real_redis_async_free(ac);
}

#define event_new fault_event_new
#define redisAsyncFree tracking_redis_async_free
#include "hiredis_libevent2.c"
#undef redisAsyncFree
#undef event_new

static struct event_base *base;

static void reset_faults(void) {
  fail_event_new_call = 0;
  event_new_calls = 0;
  redis_async_free_calls = 0;
}

static struct redisLibeventEvents *make_reconnect_handle(const char *ip, int port) {
  struct redisLibeventEvents *e = turn_calloc(1, sizeof(*e));
  e->allocated = 1;
  e->invalid = 1;
  e->base = base;
  e->ip = turn_strdup(ip);
  e->port = port;
  return e;
}

static void free_handle(struct redisLibeventEvents *e) {
  if (!e) {
    return;
  }
  if (e->context) {
    call_real_redis_async_free(e->context);
    e->context = NULL;
  } else {
    if (e->rev) {
      event_free(e->rev);
    }
    if (e->wev) {
      event_free(e->wev);
    }
  }
  free(e->ip);
  free(e->user);
  free(e->pwd);
  free(e);
}

void setUp(void) {
  reset_faults();
  base = event_base_new();
  TEST_ASSERT_NOT_NULL(base);
}

void tearDown(void) {
  event_base_free(base);
  base = NULL;
}

static void test_attach_frees_hiredis_error_context(void) {
  redis_context_handle handle = redisLibeventAttach(base, "256.256.256.256", 6379, NULL, NULL, 0, NULL);

  TEST_ASSERT_NULL(handle);
  TEST_ASSERT_EQUAL_INT(1, redis_async_free_calls);
}

static void assert_attach_event_failure_is_cleaned(int failed_call) {
  fail_event_new_call = failed_call;

  redis_context_handle handle = redisLibeventAttach(base, "127.0.0.1", 1, "user", "password", 0, NULL);

  TEST_ASSERT_NULL(handle);
  TEST_ASSERT_EQUAL_INT(1, redis_async_free_calls);
  TEST_ASSERT_EQUAL_INT(2, event_new_calls);
}

static void test_attach_cleans_up_when_read_event_creation_fails(void) { assert_attach_event_failure_is_cleaned(1); }

static void test_attach_cleans_up_when_write_event_creation_fails(void) { assert_attach_event_failure_is_cleaned(2); }

static void test_reconnect_frees_hiredis_error_context(void) {
  struct redisLibeventEvents *e = make_reconnect_handle("256.256.256.256", 6379);

  redis_reconnect(e);

  TEST_ASSERT_NULL(e->context);
  TEST_ASSERT_NULL(e->rev);
  TEST_ASSERT_NULL(e->wev);
  TEST_ASSERT_EQUAL_INT(1, redis_async_free_calls);
  free_handle(e);
}

static void assert_reconnect_event_failure_is_recoverable(int failed_call) {
  struct redisLibeventEvents *e = make_reconnect_handle("127.0.0.1", 1);
  fail_event_new_call = failed_call;

  redis_reconnect(e);

  TEST_ASSERT_NULL(e->context);
  TEST_ASSERT_NULL(e->rev);
  TEST_ASSERT_NULL(e->wev);
  TEST_ASSERT_EQUAL_INT(1, redis_async_free_calls);
  TEST_ASSERT_EQUAL_INT(2, event_new_calls);

  reset_faults();
  redis_reconnect(e);
  TEST_ASSERT_NOT_NULL(e->context);
  TEST_ASSERT_NOT_NULL(e->rev);
  TEST_ASSERT_NOT_NULL(e->wev);
  TEST_ASSERT_EQUAL_INT(0, e->invalid);
  free_handle(e);
}

static void test_reconnect_recovers_after_read_event_creation_fails(void) {
  assert_reconnect_event_failure_is_recoverable(1);
}

static void test_reconnect_recovers_after_write_event_creation_fails(void) {
  assert_reconnect_event_failure_is_recoverable(2);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_attach_frees_hiredis_error_context);
  RUN_TEST(test_attach_cleans_up_when_read_event_creation_fails);
  RUN_TEST(test_attach_cleans_up_when_write_event_creation_fails);
  RUN_TEST(test_reconnect_frees_hiredis_error_context);
  RUN_TEST(test_reconnect_recovers_after_read_event_creation_fails);
  RUN_TEST(test_reconnect_recovers_after_write_event_creation_fails);
  return UNITY_END();
}
