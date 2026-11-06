/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Regression tests for detach_ioa_socket() TTL/TOS cache handling.
 *
 * A UDP child socket shares the listener's fd and may carry a stale
 * current_ttl / current_tos (inherited while the listener was poisoned by a
 * relayed datagram, or left behind after set_socket_ttl redirected to the
 * parent). detach_ioa_socket() creates a fresh fd for that child: the cache on
 * the detached socket must come from set_socket_options() on the new fd, not
 * from the stale child fields. When there is no parent (same fd is reused),
 * the existing cache must be preserved.
 *
 * create_new_connected_udp_socket() in dtls_listener.c has the same "new fd"
 * rule (always keep set_socket_options; never copy the listener cache).
 */

#include "apputils.h"
#include "ns_ioalib_impl.h"
#include "ns_turn_utils.h"

#include <unity.h>

#include <string.h>
#include <unistd.h>

void setUp(void) {}
void tearDown(void) {}

static void make_loopback_pair(ioa_addr *local, ioa_addr *remote, evutil_socket_t *fd_out) {
  evutil_socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
  TEST_ASSERT_TRUE(fd >= 0);

  /* detach_ioa_socket() re-binds a new fd to the same local addr; both sockets
   * need reuse (SO_REUSEADDR / SO_REUSEPORT) the way the real listener does. */
  TEST_ASSERT_EQUAL_INT(0, socket_set_reusable(fd, 1, UDP_SOCKET));

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;
  TEST_ASSERT_EQUAL_INT(0, bind(fd, (struct sockaddr *)&sa, sizeof(sa)));

  socklen_t slen = sizeof(sa);
  TEST_ASSERT_EQUAL_INT(0, getsockname(fd, (struct sockaddr *)&sa, &slen));
  addr_cpy(local, (const ioa_addr *)&sa);

  /* Distinct remote so addr_connect in detach has somewhere to go. */
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(9); /* discard */
  addr_cpy(remote, (const ioa_addr *)&sa);

  *fd_out = fd;
}

static ioa_engine_handle make_engine(void) {
  ioa_engine_handle e = (ioa_engine_handle)turn_calloc(1, sizeof(ioa_engine));
  return e;
}

static ioa_socket_handle make_parent(ioa_engine_handle e, evutil_socket_t fd, const ioa_addr *local) {
  ioa_socket_handle s = create_ioa_socket_from_fd(e, fd, NULL, UDP_SOCKET, LISTENER_SOCKET, NULL, local);
  TEST_ASSERT_NOT_NULL(s);
  TEST_ASSERT_TRUE(s->default_ttl > 1);
  TEST_ASSERT_EQUAL_INT(s->default_ttl, s->current_ttl);
  return s;
}

static ioa_socket_handle make_child(ioa_engine_handle e, ioa_socket_handle parent, const ioa_addr *local,
                                    const ioa_addr *remote) {
  ioa_socket_handle s = create_ioa_socket_from_fd(e, -1, parent, UDP_SOCKET, CLIENT_SOCKET, remote, local);
  TEST_ASSERT_NOT_NULL(s);
  TEST_ASSERT_EQUAL_PTR(parent, s->parent_s);
  TEST_ASSERT_EQUAL_INT(parent->fd, s->fd);
  return s;
}

/* Child with a poisoned TTL/TOS cache must not keep that cache after detach. */
static void test_detach_new_fd_rejects_stale_child_ttl_tos_cache(void) {
  ioa_engine_handle e = make_engine();
  ioa_addr local = {0};
  ioa_addr remote = {0};
  evutil_socket_t listen_fd = -1;
  make_loopback_pair(&local, &remote, &listen_fd);

  ioa_socket_handle parent = make_parent(e, listen_fd, &local);
  ioa_socket_handle child = make_child(e, parent, &local, &remote);

  const int kernel_ttl = parent->default_ttl;
  const int kernel_tos = parent->default_tos;
  TEST_ASSERT_TRUE(kernel_ttl > 1);

  /* Simulate a child created (or left) while the shared listener TTL was 1. */
  child->current_ttl = 1;
  child->current_tos = (kernel_tos == 0) ? 0x2e : 0;

  ioa_socket_handle detached = detach_ioa_socket(child);
  TEST_ASSERT_NOT_NULL(detached);
  TEST_ASSERT_NULL(detached->parent_s);
  TEST_ASSERT_TRUE(detached->fd >= 0);
  TEST_ASSERT_NOT_EQUAL_INT(listen_fd, detached->fd);

  const int fresh_ttl = get_raw_socket_ttl(detached->fd, AF_INET);
  const int fresh_tos = get_raw_socket_tos(detached->fd, AF_INET);
  TEST_ASSERT_TRUE(fresh_ttl > 1);
  TEST_ASSERT_EQUAL_INT(fresh_ttl, detached->current_ttl);
  TEST_ASSERT_EQUAL_INT(fresh_ttl, detached->default_ttl);
  TEST_ASSERT_EQUAL_INT(fresh_tos, detached->current_tos);
  TEST_ASSERT_EQUAL_INT(fresh_tos, detached->default_tos);
  TEST_ASSERT_NOT_EQUAL_INT(1, detached->current_ttl);

  close_ioa_socket(detached);
  close_ioa_socket(child);
  close_ioa_socket(parent);
  free(e);
}

/* Without a parent, detach reuses the same fd and must keep the cache. */
static void test_detach_same_fd_preserves_ttl_tos_cache(void) {
  ioa_engine_handle e = make_engine();
  ioa_addr local = {0};
  ioa_addr remote = {0};
  evutil_socket_t fd = -1;
  make_loopback_pair(&local, &remote, &fd);

  ioa_socket_handle s = create_ioa_socket_from_fd(e, fd, NULL, UDP_SOCKET, CLIENT_SOCKET, &remote, &local);
  TEST_ASSERT_NOT_NULL(s);
  TEST_ASSERT_NULL(s->parent_s);

  const int keep_ttl = s->default_ttl > 2 ? 2 : s->default_ttl;
  const int keep_tos = (s->default_tos == 0) ? 0x2e : 0;
  TEST_ASSERT_EQUAL_INT(0, set_raw_socket_ttl(s->fd, AF_INET, keep_ttl));
  TEST_ASSERT_EQUAL_INT(0, set_raw_socket_tos(s->fd, AF_INET, keep_tos));
  s->current_ttl = keep_ttl;
  s->current_tos = keep_tos;

  ioa_socket_handle detached = detach_ioa_socket(s);
  TEST_ASSERT_NOT_NULL(detached);
  TEST_ASSERT_EQUAL_INT(fd, detached->fd);
  TEST_ASSERT_EQUAL_INT(keep_ttl, detached->current_ttl);
  TEST_ASSERT_EQUAL_INT(keep_tos, detached->current_tos);
  TEST_ASSERT_EQUAL_INT(s->default_ttl, detached->default_ttl);
  TEST_ASSERT_EQUAL_INT(s->default_tos, detached->default_tos);

  close_ioa_socket(detached);
  close_ioa_socket(s);
  free(e);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_detach_new_fd_rejects_stale_child_ttl_tos_cache);
  RUN_TEST(test_detach_same_fd_preserves_ttl_tos_cache);
  return UNITY_END();
}
