/*
 * Regression tests for the Redis format-string injection fixed in
 * GHSA-4g7c-p5wg-j4hp (CWE-134).
 *
 * Background: send_message_to_redis() used to build the Redis command's
 * *format string* by embedding the Redis key, which contains attacker
 * controlled STUN USERNAME / REALM values (e.g. "user%s%x%n"). It then passed
 * that string as the format argument to redisAsyncCommand() with only a single
 * variadic argument, so any '%' specifier carried in the key made hiredis read
 * past the end of the va_list -> crash (DoS) or stack disclosure.
 *
 * The fix passes command/key/value strictly as *data arguments* to a constant
 * "%s %s %s" format string. These tests compile the real hiredis_libevent2.c
 * with a capturing redisAsyncCommand() stub and assert exactly that invariant:
 *   - the format string is a constant containing no attacker bytes, and
 *   - every conversion specifier in the format is backed by a supplied
 *     argument (the property whose violation caused the over-read).
 *
 * Run against the pre-fix code these tests fail: cap_format would contain the
 * key bytes and the specifier count would exceed the supplied argument count.
 */

#include <unity.h>

#include <hiredis/async.h>
#include <hiredis/hiredis.h>

#include <stdarg.h>
#include <string.h>

/* ---------------- capture state, written by the stub ---------------- */

#define CAP_MAX_ARGS 8
#define CAP_STR 1024

static int cap_calls;
static char cap_format[2048];
static char cap_args[CAP_MAX_ARGS][CAP_STR];
static int cap_nargs;

static void cap_reset(void) {
  cap_calls = 0;
  cap_nargs = 0;
  cap_format[0] = 0;
  for (int i = 0; i < CAP_MAX_ARGS; i++) {
    cap_args[i][0] = 0;
  }
}

/* Count "%s" conversion specifiers in a format string (the production code
 * only ever emits %s for the command/key/value triple). */
static int count_s_specifiers(const char *fmt) {
  int n = 0;
  for (const char *p = fmt; *p; ++p) {
    if (p[0] == '%' && p[1] == 's') {
      n++;
      ++p;
    }
  }
  return n;
}

/* ---------------- hiredis stubs ---------------- */

/* Capturing replacement for hiredis' redisAsyncCommand(). Records the format
 * string verbatim and pulls one char* per "%s" specifier. This mirrors how the
 * real hiredis consumes the va_list: if the format carried more specifiers than
 * the caller supplied arguments (the vulnerability), the corresponding va_arg
 * reads would run off the end of the list. */
int redisAsyncCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *format, ...) {
  (void)ac;
  (void)fn;
  (void)privdata;

  cap_calls++;
  strncpy(cap_format, format, sizeof(cap_format) - 1);
  cap_format[sizeof(cap_format) - 1] = 0;

  cap_nargs = 0;
  va_list ap;
  va_start(ap, format);
  for (const char *p = format; *p && cap_nargs < CAP_MAX_ARGS; ++p) {
    if (p[0] == '%' && p[1] == 's') {
      const char *s = va_arg(ap, const char *);
      strncpy(cap_args[cap_nargs], s ? s : "(null)", CAP_STR - 1);
      cap_args[cap_nargs][CAP_STR - 1] = 0;
      cap_nargs++;
      ++p;
    }
  }
  va_end(ap);
  return REDIS_OK;
}

redisAsyncContext *redisAsyncConnect(const char *ip, int port) {
  (void)ip;
  (void)port;
  return NULL;
}
void redisAsyncFree(redisAsyncContext *ac) { (void)ac; }
void redisAsyncHandleRead(redisAsyncContext *ac) { (void)ac; }
void redisAsyncHandleWrite(redisAsyncContext *ac) { (void)ac; }

/* Pull in the unit under test. Including the .c makes its file-local
 * struct redisLibeventEvents visible so a valid handle can be built without a
 * live Redis server / event loop. */
#include "hiredis_libevent2.c"

/* ---------------- fixtures ---------------- */

static struct redisLibeventEvents g_events;
static redisAsyncContext g_ac;

/* Build a handle that passes redis_le_valid() so send_message_to_redis()
 * reaches the redisAsyncCommand() sink. */
static redis_context_handle make_handle(void) {
  memset(&g_events, 0, sizeof(g_events));
  memset(&g_ac, 0, sizeof(g_ac));
  g_events.context = &g_ac;
  g_events.invalid = 0;
  g_events.allocated = 0;
  return (redis_context_handle)&g_events;
}

void setUp(void) { cap_reset(); }
void tearDown(void) {}

/* ---------------- tests ---------------- */

/* Core regression: a USERNAME carrying printf specifiers must reach Redis as a
 * single opaque data argument, never as part of the format string. */
static void test_username_format_specifiers_are_data_not_format(void) {
  redis_context_handle rch = make_handle();
  const char *key = "turn/realm/north.gov/user/pwned%s%s%x%n/allocation/000000000000000001/status";

  send_message_to_redis(rch, "set", key, "%s lifetime=%lu", "active", (unsigned long)600);

  TEST_ASSERT_EQUAL_INT(1, cap_calls);

  /* The fix: the format string is a constant with no attacker-controlled bytes. */
  TEST_ASSERT_EQUAL_STRING("%s %s %s", cap_format);
  TEST_ASSERT_NULL(strstr(cap_format, "pwned"));
  TEST_ASSERT_NULL(strstr(cap_format, "%x"));
  TEST_ASSERT_NULL(strstr(cap_format, "%n"));

  /* command / key / value all arrived as separate, verbatim data arguments. */
  TEST_ASSERT_EQUAL_INT(3, cap_nargs);
  TEST_ASSERT_EQUAL_STRING("set", cap_args[0]);
  TEST_ASSERT_EQUAL_STRING(key, cap_args[1]);
  TEST_ASSERT_EQUAL_STRING("active lifetime=600", cap_args[2]);

  /* The vulnerability was a specifier/argument mismatch: every specifier in the
   * format must be backed by a supplied argument or hiredis over-reads. */
  TEST_ASSERT_EQUAL_INT(count_s_specifiers(cap_format), cap_nargs);
}

/* The REALM is also embedded in the key; a malicious realm must be inert too. */
static void test_realm_format_specifiers_are_data_not_format(void) {
  redis_context_handle rch = make_handle();
  const char *key = "turn/realm/%n%n%n/user/bob/allocation/000000000000000002/status";

  send_message_to_redis(rch, "publish", key, "%s lifetime=%lu", "active", (unsigned long)0);

  TEST_ASSERT_EQUAL_INT(1, cap_calls);
  TEST_ASSERT_EQUAL_STRING("%s %s %s", cap_format);
  TEST_ASSERT_NULL(strstr(cap_format, "%n"));
  TEST_ASSERT_EQUAL_INT(3, cap_nargs);
  TEST_ASSERT_EQUAL_STRING("publish", cap_args[0]);
  TEST_ASSERT_EQUAL_STRING(key, cap_args[1]);
  TEST_ASSERT_EQUAL_INT(count_s_specifiers(cap_format), cap_nargs);
}

/* Behaviour preserved: a benign key and a no-specifier value still produce the
 * expected three-argument "<command> <key> <value>" Redis command. */
static void test_benign_key_and_value_passthrough(void) {
  redis_context_handle rch = make_handle();
  const char *key = "turn/user/alice/allocation/000000000000000003/status";

  send_message_to_redis(rch, "publish", key, "deleted");

  TEST_ASSERT_EQUAL_INT(1, cap_calls);
  TEST_ASSERT_EQUAL_STRING("%s %s %s", cap_format);
  TEST_ASSERT_EQUAL_INT(3, cap_nargs);
  TEST_ASSERT_EQUAL_STRING("publish", cap_args[0]);
  TEST_ASSERT_EQUAL_STRING(key, cap_args[1]);
  TEST_ASSERT_EQUAL_STRING("deleted", cap_args[2]);
}

/* An empty value format (the "del" call site) yields an empty value argument,
 * not a dropped or misaligned argument. */
static void test_empty_value_argument(void) {
  redis_context_handle rch = make_handle();
  const char *key = "turn/user/carol/allocation/000000000000000004/status";

  send_message_to_redis(rch, "del", key, "");

  TEST_ASSERT_EQUAL_INT(1, cap_calls);
  TEST_ASSERT_EQUAL_STRING("%s %s %s", cap_format);
  TEST_ASSERT_EQUAL_INT(3, cap_nargs);
  TEST_ASSERT_EQUAL_STRING("del", cap_args[0]);
  TEST_ASSERT_EQUAL_STRING(key, cap_args[1]);
  TEST_ASSERT_EQUAL_STRING("", cap_args[2]);
}

/* A null handle is a no-op: nothing reaches the sink. */
static void test_null_handle_is_noop(void) {
  send_message_to_redis(NULL, "set", "turn/user/%n/x", "active");
  TEST_ASSERT_EQUAL_INT(0, cap_calls);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_username_format_specifiers_are_data_not_format);
  RUN_TEST(test_realm_format_specifiers_are_data_not_format);
  RUN_TEST(test_benign_key_and_value_passthrough);
  RUN_TEST(test_empty_value_argument);
  RUN_TEST(test_null_handle_is_noop);
  return UNITY_END();
}
