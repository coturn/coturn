/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Regression: handle_udp_packet() must not read the new child socket after
 * open_client_connection_session(). That call runs the first datagram and, for
 * a stateless-nonce 401 or 438, shuts the session down and frees the socket
 * via close_ioa_socket() before returning 0. Reading the socket after that
 * is a use-after-free on plain UDP as well as DTLS.
 *
 * The freed socket is modeled by dropping access to the child. A later read
 * faults. Handshake completion is released on a later datagram, not here.
 */

#include <unity.h>

#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

#ifndef MAP_ANON
#ifdef MAP_ANONYMOUS
#define MAP_ANON MAP_ANONYMOUS
#endif
#endif

#include "dtls_listener.c"

/* mainrelay.c normally defines this. The new-socket path only reads no_udp,
 * dtls, and log_binding, all of which stay false in a zeroed instance. */
turn_params_t turn_params;

static size_t guard_len;
static ioa_socket_handle guarded_socket;
static int session_opened;
static sigjmp_buf fault_jmp;

static void on_fault(int signo) {
  (void)signo;
  siglongjmp(fault_jmp, 1);
}

/* Page-aligned so access can be dropped for the whole struct and nothing else.
 * A read after open_client_connection_session() then faults. */
static ioa_socket_handle map_guarded_socket(void) {
  const long page = sysconf(_SC_PAGESIZE);
  const size_t pagesize = (page > 0) ? (size_t)page : 4096u;
  const size_t need = sizeof(ioa_socket);

  guard_len = (need + pagesize - 1u) & ~(pagesize - 1u);
  void *mem = mmap(NULL, guard_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (mem == MAP_FAILED) {
    guard_len = 0;
    guarded_socket = NULL;
    return NULL;
  }
  memset(mem, 0, sizeof(ioa_socket));
  guarded_socket = (ioa_socket_handle)mem;
  return guarded_socket;
}

static void unmap_guarded_socket(void) {
  if (guarded_socket && guard_len) {
    munmap(guarded_socket, guard_len);
  }
  guarded_socket = NULL;
  guard_len = 0;
}

ioa_socket_handle create_ioa_socket_from_fd(ioa_engine_handle e, ioa_socket_raw fd, ioa_socket_handle parent_s,
                                            SOCKET_TYPE st, SOCKET_APP_TYPE sat, const ioa_addr *remote_addr,
                                            const ioa_addr *local_addr) {
  (void)e;
  (void)fd;
  (void)parent_s;
  (void)st;
  (void)sat;
  (void)remote_addr;
  (void)local_addr;
  return map_guarded_socket();
}

ioa_addr *get_local_addr_from_ioa_socket(ioa_socket_handle s) {
  static ioa_addr local;
  (void)s;
  return &local;
}

int set_ioa_socket_buf_size(ioa_socket_handle s, int sz) {
  (void)s;
  (void)sz;
  return 0;
}

void add_socket_to_map(ioa_socket_handle s, ur_addr_map *amap) {
  (void)s;
  (void)amap;
}

bool ur_addr_map_get(const ur_addr_map *map, ioa_addr *key, ur_addr_map_value_type *value) {
  (void)map;
  (void)key;
  if (value) {
    *value = 0;
  }
  return false;
}

/* Stand-in for the real function: it may free the socket and still return 0
 * (the 401/438 teardown). Drop access to the child so any later use faults. */
#if defined(__GNUC__)
__attribute__((noinline))
#endif
int open_client_connection_session(turn_turnserver *server, struct socket_message *sm) {
  (void)server;
  session_opened = 1;
  if (sm && sm->s && (sm->s == guarded_socket) && guard_len) {
    if (mprotect(sm->s, guard_len, PROT_NONE) != 0) {
      return -1;
    }
  }
  return 0;
}

void setUp(void) {
  session_opened = 0;
  unmap_guarded_socket();
}

void tearDown(void) { unmap_guarded_socket(); }

static void test_new_socket_not_used_after_session_open(void) {
  /* Non-NULL so the path does not allocate a map. Nothing dereferences it:
   * the lookup stub reports a miss, which is the new-socket path. */
  static int children_placeholder;
  dtls_listener_relay_server_type listener = {0};
  struct message_to_relay sm = {0};
  ioa_engine *eng = (ioa_engine *)turn_calloc(1, sizeof(*eng));
  turn_turnserver *ts = (turn_turnserver *)turn_calloc(1, sizeof(*ts));
  ioa_socket_handle parent = (ioa_socket_handle)turn_calloc(1, sizeof(*parent));
  struct sigaction sa = {0};
  struct sigaction old_segv;
  struct sigaction old_bus;
  int jumped;
  int rc = -1;

  listener.children_ss = (ur_addr_map *)&children_placeholder;
  sm.m.sm.s = parent;

  sa.sa_handler = on_fault;
  sigemptyset(&sa.sa_mask);
  TEST_ASSERT_EQUAL_INT(0, sigaction(SIGSEGV, &sa, &old_segv));
  TEST_ASSERT_EQUAL_INT(0, sigaction(SIGBUS, &sa, &old_bus));

  jumped = sigsetjmp(fault_jmp, 1);
  if (!jumped) {
    /* OLD_STUN skips both listener fast paths, so this still creates a child
     * socket and opens a session: the same tail a STUN Allocate with
     * MESSAGE-INTEGRITY takes after the fast path declines it. */
    rc = handle_udp_packet(&listener, &sm, eng, ts, UDP_PACKET_CLASS_OLD_STUN);
  }

  sigaction(SIGSEGV, &old_segv, NULL);
  sigaction(SIGBUS, &old_bus, NULL);

  TEST_ASSERT_TRUE(session_opened);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, jumped, "child socket was used after open_client_connection_session() returned");
  TEST_ASSERT_EQUAL_INT(0, rc);

  free(parent);
  free(eng);
  free(ts);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_new_socket_not_used_after_session_open);
  return UNITY_END();
}
