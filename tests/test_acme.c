/*
 * SPDX-License-Identifier: MIT
 *
 * Regression test for the ACME-redirect signed->unsigned conversion bug
 * (GHSA-m23x-5qf5-988g): is_acme_req() returns a negative int on every
 * rejection path; storing it in a size_t wrapped it past the lower-bound
 * guard, leaving the request path un-terminated and leaking adjacent heap
 * through the 301 Location header.
 *
 * try_acme_redirect() rejects a request with return code 2 *before* it ever
 * touches the socket, so these cases can be exercised with a dummy handle.
 */

#include "acme.h"

#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

// A non-NULL placeholder handle: rejected requests return before dereferencing
// it, so its contents are never read.
static ioa_socket_handle dummy_socket(void) {
  static char placeholder;
  return (ioa_socket_handle)&placeholder;
}

#define URL "https://acme.example/"

// The advisory PoC: an ordinary "GET / HTTP/1.1" that is not an acme-challenge
// path. is_acme_req() returns -1; pre-fix this slipped through (return 0) and
// disclosed heap. It must now be rejected with 2.
void test_non_acme_get_is_rejected(void) {
  char req[256] = {0};
  const char *prefix = "GET / HTTP/1.1\r\nHost: ";
  size_t len = strlen(prefix);
  memcpy(req, prefix, len);
  // pad with a header value so the total length clears the >= 64 lower bound
  // and stays under the 480 upper bound the guard enforces.
  memset(req + len, 'z', 48);
  len += 48;
  memcpy(req + len, "\r\n\r\n", 4);
  len += 4;

  TEST_ASSERT_EQUAL_INT(2, try_acme_redirect(req, len, URL, dummy_socket()));
}

// A well-formed acme prefix but with a too-short / bad trailer path -> -2.
void test_bad_trailer_is_rejected(void) {
  char req[256] = {0};
  const char *r = "GET /.well-known/acme-challenge/short BADTRAILER____________________";
  size_t len = strlen(r);
  memcpy(req, r, len);
  TEST_ASSERT_EQUAL_INT(2, try_acme_redirect(req, len, URL, dummy_socket()));
}

// Disallowed character in the path -> -3.
void test_bad_char_is_rejected(void) {
  char req[256] = {0};
  const char *r = "GET /.well-known/acme-challenge/abc/def!ghijkl HTTP/1.1\r\nHost: a\r\n\r\n";
  size_t len = strlen(r);
  memcpy(req, r, len);
  TEST_ASSERT_EQUAL_INT(2, try_acme_redirect(req, len, URL, dummy_socket()));
}

// Guard rejects an over-long request before is_acme_req() runs.
void test_oversized_request_is_rejected(void) {
  char req[600];
  memset(req, 'A', sizeof(req));
  TEST_ASSERT_EQUAL_INT(2, try_acme_redirect(req, sizeof(req), URL, dummy_socket()));
}

// Empty/NULL url is a configuration rejection (return 1), independent of the path.
void test_null_url_is_rejected(void) {
  char req[64] = {0};
  TEST_ASSERT_EQUAL_INT(1, try_acme_redirect(req, sizeof(req), NULL, dummy_socket()));
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_non_acme_get_is_rejected);
  RUN_TEST(test_bad_trailer_is_rejected);
  RUN_TEST(test_bad_char_is_rejected);
  RUN_TEST(test_oversized_request_is_rejected);
  RUN_TEST(test_null_url_is_rejected);
  return UNITY_END();
}
