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

/* recvmmsg(2) and struct mmsghdr require _GNU_SOURCE on glibc. Must be
 * defined before any system header. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "uclient.h"
#include "apputils.h"
#include "ns_turn_ioalib.h"
#include "ns_turn_utils.h"
#include "session.h"
#include "startuclient.h"

#if defined(__linux__)
#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
/* UDP_SEGMENT is the Linux UDP-GSO cmsg type. Older glibc may not define
 * it even though the kernel supports it; provide a fallback so the build
 * works on slightly stale toolchains and the runtime probe will detect
 * actual kernel support. */
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#endif
#include <pthread.h>
#include <time.h>

#if defined(__MINGW32__)
#ifndef usleep
#define usleep Sleep
#endif
#endif

/* ===== Portability shims for MSVC =====
 * MSVC does not understand the GCC/Clang __attribute__((aligned)),
 * __atomic_* built-ins, or _Thread_local. Provide equivalents so the
 * Windows MSVC build of turnutils_uclient links the same listener-pool
 * recv path used on POSIX. The semantics we need are relaxed atomics
 * (no inter-thread ordering, just race-free read-modify-write and load
 * of an 8-byte counter), which map cleanly onto MSVC's Interlocked64
 * intrinsics on x86_64. */
#if defined(_MSC_VER)
#include <windows.h>
#if !defined(_Thread_local)
#define _Thread_local __declspec(thread)
#endif
#define UCLIENT_CACHE_ALIGNED(N) __declspec(align(N))
static inline uint64_t uclient_atomic_load_u64(const uint64_t *p) { return (uint64_t)(*(const volatile __int64 *)p); }
static inline uint64_t uclient_atomic_fetch_add_u64(uint64_t *p, uint64_t v) {
  return (uint64_t)InterlockedExchangeAdd64((volatile LONG64 *)p, (LONG64)v);
}
static inline uint64_t uclient_atomic_exchange_u64(uint64_t *p, uint64_t v) {
  return (uint64_t)InterlockedExchange64((volatile LONG64 *)p, (LONG64)v);
}
static inline size_t uclient_atomic_fetch_add_size(size_t *p, size_t v) {
#if SIZE_MAX > 0xFFFFFFFFu
  return (size_t)InterlockedExchangeAdd64((volatile LONG64 *)p, (LONG64)v);
#else
  return (size_t)InterlockedExchangeAdd((volatile LONG *)p, (LONG)v);
#endif
}
static inline size_t uclient_atomic_exchange_size(size_t *p, size_t v) {
#if SIZE_MAX > 0xFFFFFFFFu
  return (size_t)InterlockedExchange64((volatile LONG64 *)p, (LONG64)v);
#else
  return (size_t)InterlockedExchange((volatile LONG *)p, (LONG)v);
#endif
}
#else
#define UCLIENT_CACHE_ALIGNED(N) __attribute__((aligned(N)))
static inline uint64_t uclient_atomic_load_u64(const uint64_t *p) { return __atomic_load_n(p, __ATOMIC_RELAXED); }
static inline uint64_t uclient_atomic_fetch_add_u64(uint64_t *p, uint64_t v) {
  return __atomic_fetch_add(p, v, __ATOMIC_RELAXED);
}
static inline uint64_t uclient_atomic_exchange_u64(uint64_t *p, uint64_t v) {
  return __atomic_exchange_n(p, v, __ATOMIC_RELAXED);
}
static inline size_t uclient_atomic_fetch_add_size(size_t *p, size_t v) {
  return __atomic_fetch_add(p, v, __ATOMIC_RELAXED);
}
static inline size_t uclient_atomic_exchange_size(size_t *p, size_t v) {
  return __atomic_exchange_n(p, v, __ATOMIC_RELAXED);
}
#endif

static int verbose_packets = 0;

static size_t current_clients_number = 0;

static bool start_full_timer = false;
static uint32_t tot_messages = 0;
static uint32_t tot_send_messages = 0;
static uint64_t tot_send_bytes = 0;
static uint32_t tot_recv_messages = 0;
static uint64_t tot_recv_bytes = 0;
static uint64_t tot_send_dropped = 0;
static uint64_t tot_allocations = 0;
static uint64_t load_sent_packets = 0;
static uint64_t load_last_sent_packets = 0;
/* Mirror of load_last_sent_packets for the recv side. recv_count_snapshot()
 * (atomic-load reduction over listener slabs) gives the current total; we
 * remember the previous report's value and divide the delta by elapsed
 * wall-clock to get recv_pps. Reset alongside load_last_sent_packets in
 * reset_load_generator_rate_stats(). */
static uint64_t load_last_recv_packets = 0;
static uint64_t load_last_report_time = 0;
static uint64_t synthetic_peer_counter = 0;

struct event_base *client_event_base = NULL;

static int client_write(app_ur_session *elem);
static int client_shutdown(app_ur_session *elem);

static uint64_t current_time = 0;
static uint64_t current_mstime = 0;

static char buffer_to_send[65536] = "\0";

static int total_clients = 0;

/* Patch for unlimited number of clients provided by ucudbm@gmail.com */
static app_ur_session **elems = NULL;

#define SLEEP_INTERVAL (234)

#define MAX_LISTENING_CYCLE_NUMBER (7)

int RTP_PACKET_INTERVAL = 20;

static inline int64_t time_minus(uint64_t t1, uint64_t t2) { return ((int64_t)t1 - (int64_t)t2); }

static uint64_t total_loss = 0;
static uint64_t total_jitter = 0;
static uint64_t total_latency = 0;

static uint64_t min_latency = 0xFFFFFFFF;
static uint64_t max_latency = 0;
static uint64_t min_jitter = 0xFFFFFFFF;
static uint64_t max_jitter = 0;

static bool show_statistics = false;

/* ===== Multi-threaded listener (recv) pool =====
 *
 * The main thread keeps owning the sender timer, the lifecycle, and the
 * control plane. EV_READ events for client UDP sockets are routed to one of
 * N listener threads, each with its own libevent base. Per-session state
 * touched by the recv path (recvmsgnum, loss, latency, jitter, recvtimems,
 * rmsgnum) is mutated only by the owning listener thread, which avoids
 * locking; the few globals that the recv path accumulates into use either
 * atomic adds (tot_recv_messages, tot_recv_bytes) or per-thread accumulators
 * reduced into the global on the main thread after pthread_join (min/max
 * latency/jitter).
 *
 * num_listener_threads = 0 disables the pool and reverts to the legacy
 * single-event-base behaviour. The real-Linux bench (c-4 / 4 vCPU)
 * shows K=0 winning at -m 1 and -m 2 (4.6k / 6.2k recv pps vs ~3.2k
 * for K=1) and K=1 winning decisively from -m 4 upward, so the
 * default is K=0 with an auto-bump to K=1 once -m crosses
 * UCLIENT_AUTO_LISTENERS_THRESHOLD. Auto-scale is suppressed when
 * the user passes -K explicitly. */

int num_listener_threads = 0;               /* CLI override; auto-bumped when -m >= UCLIENT_AUTO_LISTENERS_THRESHOLD */
bool num_listener_threads_explicit = false; /* set by mainuclient when -K is supplied */

/* Cache-line size (assumed 64 B for x86_64 / arm64). Aligning the
 * uclient_listener struct prevents two listeners' counter slabs from
 * sharing a cache line, which is what caused the K=2/K=4 regression in
 * the earlier bench: every per-packet __atomic_fetch_add into the global
 * tot_recv_messages was bouncing the line across cores. With slabs the
 * counter writes are thread-local; alignment closes the false-sharing
 * door for the rest of the slab. */
#define UCLIENT_LISTENER_CACHE_LINE 64

typedef struct UCLIENT_CACHE_ALIGNED(UCLIENT_LISTENER_CACHE_LINE) uclient_listener_s {
  int id;
  pthread_t thread;
  struct event_base *event_base;
  /* Per-thread accumulators. Updated only by this listener thread; read
   * by main on-demand (atomic load) during the test and authoritatively
   * after pthread_join. The reads-during-run race is benign -- progress
   * prints and the completion-check threshold (tot_recv_messages >=
   * tot_messages) tolerate a few stale increments. */
  uint64_t l_tot_recv_messages;
  uint64_t l_tot_recv_bytes;
  uint64_t l_min_latency;
  uint64_t l_max_latency;
  uint64_t l_min_jitter;
  uint64_t l_max_jitter;
  volatile int stop;
  /* pthread_t is a struct on the Windows pthreads-win32 shim, so it can
   * neither be cast from 0 nor compared with a truthy check. Track the
   * "thread has been spawned" state explicitly. */
  bool started;
} uclient_listener;

static uclient_listener *listeners = NULL;
static int listener_assignment_counter = 0; /* main-thread-only writes */
static _Thread_local uclient_listener *current_listener = NULL;

/* True iff caller is one of the listener threads (i.e. NOT the main thread). */
static inline bool on_listener_thread(void) { return current_listener != NULL; }

/* Per-packet counter writes go into a per-listener slab (when running on
 * a listener thread) or directly into the global (when running on main,
 * i.e. the K=0 legacy path). The slab strategy eliminates the cross-
 * thread cache-line bouncing that __atomic_fetch_add on a single global
 * was causing -- in the K=2/K=4 bench, every recv was an L1-invalidation
 * on every other listener's core, which crashed throughput by ~19x. With
 * slabs, writes are thread-local; main reads them on-demand via the
 * snapshot helpers below (atomic loads, no contention with writers). */
static inline void recv_count_add(uint32_t n) {
  if (current_listener) {
    current_listener->l_tot_recv_messages += n;
  } else {
    tot_recv_messages += n;
  }
}
static inline void recv_bytes_add(uint64_t n) {
  if (current_listener) {
    current_listener->l_tot_recv_bytes += n;
  } else {
    tot_recv_bytes += n;
  }
}

/* On-demand reductions: main thread reads tot_recv_messages /
 * tot_recv_bytes through these snapshots while listeners are running.
 * Race semantics match the pre-slab implementation -- progress prints
 * and the completion threshold tolerate a slightly stale value. After
 * stop_listener_threads() folds the slabs back into the globals these
 * helpers degenerate to a plain global read (listeners == NULL). */
static inline uint32_t recv_count_snapshot(void) {
  uint32_t s = tot_recv_messages;
  if (listeners) {
    for (int i = 0; i < num_listener_threads; ++i) {
      s += (uint32_t)uclient_atomic_load_u64(&listeners[i].l_tot_recv_messages);
    }
  }
  return s;
}
static inline uint64_t recv_bytes_snapshot(void) {
  uint64_t s = tot_recv_bytes;
  if (listeners) {
    for (int i = 0; i < num_listener_threads; ++i) {
      s += uclient_atomic_load_u64(&listeners[i].l_tot_recv_bytes);
    }
  }
  return s;
}

/* Returns the event_base that should host the EV_READ event for a session.
 * Picks a listener via round-robin and stamps elem->listener_id so we can
 * find the right per-thread accumulator at recv time. Called only from the
 * main thread during start_client / start_c2c, so the rr counter doesn't
 * need to be atomic. */
static struct event_base *pick_listener_base(app_ur_session *elem) {
  if (num_listener_threads <= 0 || !listeners) {
    if (elem) {
      elem->listener_id = -1;
    }
    return client_event_base;
  }
  const int idx = listener_assignment_counter++ % num_listener_threads;
  if (elem) {
    elem->listener_id = idx;
  }
  return listeners[idx].event_base;
}

static void *uclient_listener_thread_main(void *arg) {
  uclient_listener *l = (uclient_listener *)arg;
  current_listener = l;

  while (!l->stop) {
    /* 100 ms loopexit cap so we can poll the stop flag promptly even if
     * no events are firing on this thread. */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    event_base_loopexit(l->event_base, &tv);
    event_base_dispatch(l->event_base);
  }
  return NULL;
}

static int start_listener_threads(void) {
  /* Show how the pool is configured for this run, regardless of whether
   * the count came from -K or auto-scaling. Surfacing the actual number
   * (and whether it was auto-derived) is the only way an operator can
   * tell from the log that the pool did or didn't engage. */
  const char *origin = num_listener_threads_explicit ? "explicit -K" : "auto";
  if (num_listener_threads <= 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "uclient: listener pool disabled (single-threaded recv on main; %s)\n", origin);
    return 0;
  }
  if (num_listener_threads > UCLIENT_MAX_LISTENER_THREADS) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "uclient: clamping --listener-threads %d to max %d\n", num_listener_threads,
                  UCLIENT_MAX_LISTENER_THREADS);
    num_listener_threads = UCLIENT_MAX_LISTENER_THREADS;
  }

  listeners = (uclient_listener *)calloc((size_t)num_listener_threads, sizeof(uclient_listener));
  if (!listeners) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "uclient: cannot allocate listener pool\n");
    num_listener_threads = 0;
    return -1;
  }
  for (int i = 0; i < num_listener_threads; ++i) {
    listeners[i].id = i;
    listeners[i].event_base = turn_event_base_new();
    listeners[i].l_min_latency = 0xFFFFFFFFu;
    listeners[i].l_min_jitter = 0xFFFFFFFFu;
    listeners[i].stop = 0;
    if (pthread_create(&listeners[i].thread, NULL, uclient_listener_thread_main, &listeners[i]) != 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "uclient: pthread_create listener %d failed\n", i);
      /* Leave started=false so stop_listener_threads doesn't pthread_join
       * a handle that was never spawned (pthread_t may be a struct on
       * Windows, so a zero-valued sentinel isn't portable). */
      return -1;
    }
    listeners[i].started = true;
  }
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "uclient: started %d listener thread(s) (%s)\n", num_listener_threads, origin);
  return 0;
}

static void stop_listener_threads(void) {
  if (num_listener_threads <= 0 || !listeners) {
    return;
  }
  for (int i = 0; i < num_listener_threads; ++i) {
    listeners[i].stop = 1;
    if (listeners[i].event_base) {
      event_base_loopbreak(listeners[i].event_base);
    }
  }
  for (int i = 0; i < num_listener_threads; ++i) {
    if (listeners[i].started) {
      pthread_join(listeners[i].thread, NULL);
      listeners[i].started = false;
    }
  }
  /* Reduce per-thread counters into the globals before reporting runs.
   * Includes the slab counters (l_tot_recv_messages / l_tot_recv_bytes)
   * that were diverted from the shared atomics to dodge cross-core
   * cache-line bouncing during the test. After this point the globals
   * are authoritative and the snapshot helpers degenerate to a plain
   * global read. */
  for (int i = 0; i < num_listener_threads; ++i) {
    tot_recv_messages += (uint32_t)listeners[i].l_tot_recv_messages;
    tot_recv_bytes += listeners[i].l_tot_recv_bytes;
    if (listeners[i].l_min_latency < min_latency) {
      min_latency = listeners[i].l_min_latency;
    }
    if (listeners[i].l_max_latency > max_latency) {
      max_latency = listeners[i].l_max_latency;
    }
    if (listeners[i].l_min_jitter < min_jitter) {
      min_jitter = listeners[i].l_min_jitter;
    }
    if (listeners[i].l_max_jitter > max_jitter) {
      max_jitter = listeners[i].l_max_jitter;
    }
  }
  for (int i = 0; i < num_listener_threads; ++i) {
    if (listeners[i].event_base) {
      event_base_free(listeners[i].event_base);
      listeners[i].event_base = NULL;
    }
  }
  free(listeners);
  listeners = NULL;
}

/* ============================================================
 * Per-thread send-side batching with UDP-GSO.
 *
 * The sender pool below opens a batching window around its per-tick
 * iteration of the session shard. Within that window send_buffer
 * (plaintext-UDP path only) does not call send(2) directly; it copies
 * the payload into a per-thread slot and appends to a scatter-gather
 * iov[]. Flush triggers:
 *
 *   1. Different fd (next session) — auto-flush.
 *   2. Different segment size — auto-flush (UDP-GSO requires uniform
 *      size; only the last segment may be shorter, but we conservatively
 *      flush instead of relying on that).
 *   3. count == UCLIENT_TX_BATCH — capacity flush.
 *   4. uclient_send_batch_end at end of timer iteration.
 *
 * Flush emits ONE sendmsg(2) with UDP_SEGMENT cmsg when count > 1 and
 * the kernel accepts it; otherwise falls back to sendmmsg(2) or to
 * per-entry send(2) on older systems. UDP-GSO is sticky-disabled per
 * thread on EINVAL/ENOPROTOOPT/EOPNOTSUPP so we don't probe every flush
 * after we know the kernel won't accept it.
 *
 * The copy is unavoidable because the caller reuses elem->out_buffer
 * across the burst's iterations; pointing iov[i] at elem->out_buffer
 * would alias all entries to the same content. The copy cost is
 * justified by collapsing N sendmsg(2) syscalls into one UDP-GSO
 * sendmsg per session-burst, which crushes the kernel-entry/skb-alloc
 * cost on the loadgen. */

#if defined(__linux__)
#define UCLIENT_TX_BATCH 64
#define UCLIENT_TX_SLOT_SZ 2048

typedef struct uclient_tx_state_s {
  unsigned int depth;
  unsigned int count;
  evutil_socket_t fd;
  uint16_t seg_size;
  bool same_size;
  bool gso_disabled; /* sticky after first kernel refusal */
  struct iovec iov[UCLIENT_TX_BATCH];
  int lens[UCLIENT_TX_BATCH];
  uint8_t bufs[UCLIENT_TX_BATCH][UCLIENT_TX_SLOT_SZ];
} uclient_tx_state;

static _Thread_local uclient_tx_state uclient_tx_batch = {0};

/* Forward declaration. The helper itself is defined further down, next
 * to the per-sender send-counter slab plumbing it touches. Declared up
 * here so GCC doesn't infer an implicit non-static declaration when
 * uclient_tx_flush() below references it. */
static void send_dropped_inc_helper(void);

static int uclient_tx_flush_gso(void) {
  uclient_tx_state *st = &uclient_tx_batch;
  struct msghdr mh = {0};
  mh.msg_iov = st->iov;
  mh.msg_iovlen = st->count;

  /* msg_name=NULL on a connected UDP socket; iov_len[i] are the
   * per-segment payload sizes. Kernel splits the assembled UDP payload
   * at seg_size boundaries; with iov_len[i] == seg_size this gives one
   * sendmsg() per N segments. */
  union {
    struct cmsghdr align;
    char buf[CMSG_SPACE(sizeof(uint16_t))];
  } cmsg_buf = {0};
  mh.msg_control = cmsg_buf.buf;
  mh.msg_controllen = sizeof(cmsg_buf.buf);
  struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
  cm->cmsg_level = SOL_UDP;
  cm->cmsg_type = UDP_SEGMENT;
  cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
  uint16_t seg = st->seg_size;
  memcpy(CMSG_DATA(cm), &seg, sizeof(seg));

  ssize_t rc;
  do {
    rc = sendmsg(st->fd, &mh, 0);
  } while (rc < 0 && errno == EINTR);

  if (rc < 0) {
    if (errno == EINVAL || errno == ENOPROTOOPT || errno == EOPNOTSUPP) {
      /* Kernel/NIC does not support UDP_SEGMENT for this socket. Sticky-
       * disable so the rest of the test uses the sendmmsg/per-entry
       * fallback without re-probing every flush. */
      st->gso_disabled = true;
    }
    return -1;
  }
  return (int)st->count;
}

static int uclient_tx_flush_mmsg(void) {
  uclient_tx_state *st = &uclient_tx_batch;
  struct mmsghdr msgs[UCLIENT_TX_BATCH];
  for (unsigned int i = 0; i < st->count; ++i) {
    memset(&msgs[i], 0, sizeof(msgs[i]));
    msgs[i].msg_hdr.msg_iov = &(st->iov[i]);
    msgs[i].msg_hdr.msg_iovlen = 1;
  }
  unsigned int sent = 0;
  while (sent < st->count) {
    int rc;
    do {
      rc = sendmmsg(st->fd, &msgs[sent], st->count - sent, 0);
    } while (rc < 0 && errno == EINTR);
    if (rc <= 0) {
      break;
    }
    sent += (unsigned int)rc;
  }
  return (int)sent;
}

static int uclient_tx_flush(void) {
  uclient_tx_state *st = &uclient_tx_batch;
  if (st->count == 0) {
    return 0;
  }

  int sent = 0;
  bool gso_ok = false;
  if (st->count > 1 && st->same_size && !st->gso_disabled) {
    const int r = uclient_tx_flush_gso();
    if (r >= 0) {
      sent = r;
      gso_ok = true;
    }
  }
  if (!gso_ok) {
    sent = uclient_tx_flush_mmsg();
  }

  /* Any leftover (partial sendmmsg or short last segment of a failed
   * GSO attempt that left some entries unsent) goes via plain send(2). */
  for (unsigned int i = (unsigned int)sent; i < st->count; ++i) {
    ssize_t rc;
    do {
      rc = send(st->fd, st->iov[i].iov_base, st->iov[i].iov_len, 0);
    } while (rc < 0 && errno == EINTR);
    if (rc > 0) {
      ++sent;
    } else {
      send_dropped_inc_helper();
    }
  }

  st->count = 0;
  st->fd = -1;
  st->seg_size = 0;
  st->same_size = true;
  return sent;
}

void uclient_send_batch_begin(void) {
  uclient_tx_state *st = &uclient_tx_batch;
  if (st->depth == 0) {
    st->count = 0;
    st->fd = -1;
    st->seg_size = 0;
    st->same_size = true;
  }
  ++st->depth;
}

void uclient_send_batch_end(void) {
  uclient_tx_state *st = &uclient_tx_batch;
  if (st->depth == 0) {
    return;
  }
  if (--st->depth == 0) {
    uclient_tx_flush();
  }
}

static bool uclient_tx_enqueue(evutil_socket_t fd, const void *data, size_t len) {
  uclient_tx_state *st = &uclient_tx_batch;
  if (st->depth == 0 || fd < 0 || len == 0 || len > UCLIENT_TX_SLOT_SZ) {
    return false;
  }
  if (st->count > 0 && st->fd != fd) {
    uclient_tx_flush();
  }
  if (st->count == UCLIENT_TX_BATCH) {
    uclient_tx_flush();
  }
  if (st->count == 0) {
    st->fd = fd;
    st->seg_size = (uint16_t)len;
    st->same_size = true;
  } else if ((uint16_t)len != st->seg_size) {
    /* Size change kills GSO eligibility for this batch. Flush now and
     * start a new batch at the new size; cheaper than sending the prior
     * group via sendmmsg fallback. */
    uclient_tx_flush();
    st->fd = fd;
    st->seg_size = (uint16_t)len;
    st->same_size = true;
  }

  uint8_t *slot = st->bufs[st->count];
  memcpy(slot, data, len);
  st->iov[st->count].iov_base = slot;
  st->iov[st->count].iov_len = len;
  st->lens[st->count] = (int)len;
  ++st->count;
  return true;
}
#else  /* !__linux__ */
void uclient_send_batch_begin(void) {}
void uclient_send_batch_end(void) {}
static bool uclient_tx_enqueue(evutil_socket_t fd, const void *data, size_t len) {
  (void)fd;
  (void)data;
  (void)len;
  return false;
}
#endif /* __linux__ */

/* ============================================================
 * SENDER thread pool — mirror of the listener pool.
 *
 * The legacy single-threaded model runs timer_handler on the main
 * client_event_base, walks elems[] every tick, and calls client_write
 * (which calls send_buffer / send) inline. With -m >= a few sessions and
 * a 100us tick, this saturates one CPU on the loadgen long before the
 * NIC or the relay does, capping send_pps at roughly one core's worth of
 * syscall + STUN-framing overhead.
 *
 * With the pool engaged, sessions are sharded across N sender threads
 * round-robin at allocation time (elem->sender_id). Each sender thread
 * owns its own libevent base and a single timer event that fires the
 * same RTP_PACKET_INTERVAL/100us cadence and iterates only its session
 * shard. Send-side counters (tot_send_messages, tot_send_bytes,
 * tot_send_dropped, load_sent_packets) and the completion accumulators
 * touched by client_timer_handler (total_loss / total_latency /
 * total_jitter) are written into per-thread, cache-line-aligned slabs
 * and reduced into the globals after pthread_join in
 * stop_sender_threads(). This avoids the cross-core cache-line bouncing
 * that an atomic-counter design would have introduced.
 *
 * num_sender_threads = 0 disables the pool and reverts to the legacy
 * main-thread iteration. */

#define UCLIENT_SENDER_CACHE_LINE 64

typedef struct UCLIENT_CACHE_ALIGNED(UCLIENT_SENDER_CACHE_LINE) uclient_sender_s {
  int id;
  pthread_t thread;
  struct event_base *event_base;
  struct event *timer_ev;
  /* Per-thread accumulators -- updated only by this sender thread. */
  uint64_t s_tot_send_messages;
  uint64_t s_tot_send_bytes;
  uint64_t s_tot_send_dropped;
  uint64_t s_load_sent_packets;
  uint64_t s_total_loss;
  uint64_t s_total_latency;
  uint64_t s_total_jitter;
  volatile int stop;
  bool started;
} uclient_sender;

int num_sender_threads = 0;
bool num_sender_threads_explicit = false;
static uclient_sender *senders = NULL;
static int sender_assignment_counter = 0; /* main-thread-only writes */
static _Thread_local uclient_sender *current_sender = NULL;

static inline bool on_sender_thread(void) { return current_sender != NULL; }

/* Per-packet send counter writes go into a per-sender slab when on a
 * sender thread, or directly into the global on main. */
static inline void send_count_add(uint32_t n) {
  if (current_sender) {
    current_sender->s_tot_send_messages += n;
  } else {
    tot_send_messages += n;
  }
}
static inline void send_bytes_add(uint64_t n) {
  if (current_sender) {
    current_sender->s_tot_send_bytes += n;
  } else {
    tot_send_bytes += n;
  }
}
static inline void send_dropped_add(uint64_t n) {
  if (current_sender) {
    current_sender->s_tot_send_dropped += n;
  } else {
    tot_send_dropped += n;
  }
}

#if defined(__linux__)
/* Definition of the forward-declared helper used by the GSO flush
 * fallback. Kept thin so the batching code above doesn't have to know
 * about the per-sender slab plumbing. */
static void send_dropped_inc_helper(void) { send_dropped_add(1); }
#endif
static inline void load_sent_add(uint64_t n) {
  if (current_sender) {
    current_sender->s_load_sent_packets += n;
  } else {
    load_sent_packets += n;
  }
}

/* Snapshot helpers — main thread reads during the run. The
 * accumulators are reduced into the globals authoritatively in
 * stop_sender_threads(). */
static inline uint64_t send_count_snapshot(void) {
  uint64_t s = tot_send_messages;
  if (senders) {
    for (int i = 0; i < num_sender_threads; ++i) {
      s += uclient_atomic_load_u64(&senders[i].s_tot_send_messages);
    }
  }
  return s;
}
static inline uint64_t send_bytes_snapshot(void) {
  uint64_t s = tot_send_bytes;
  if (senders) {
    for (int i = 0; i < num_sender_threads; ++i) {
      s += uclient_atomic_load_u64(&senders[i].s_tot_send_bytes);
    }
  }
  return s;
}
static inline uint64_t load_sent_snapshot(void) {
  uint64_t s = load_sent_packets;
  if (senders) {
    for (int i = 0; i < num_sender_threads; ++i) {
      s += uclient_atomic_load_u64(&senders[i].s_load_sent_packets);
    }
  }
  return s;
}

/* Used by client_timer_handler when a session completes -- the
 * exchange-and-zero of per-session stats accumulates into a sender-
 * thread-local total to avoid touching the global from N threads. */
static inline void completion_loss_add(size_t n) {
  if (current_sender) {
    current_sender->s_total_loss += (uint64_t)n;
  } else {
    total_loss += n;
  }
}
static inline void completion_latency_add(uint64_t n) {
  if (current_sender) {
    current_sender->s_total_latency += n;
  } else {
    total_latency += n;
  }
}
static inline void completion_jitter_add(uint64_t n) {
  if (current_sender) {
    current_sender->s_total_jitter += n;
  } else {
    total_jitter += n;
  }
}

static int pick_sender_id(void) {
  if (num_sender_threads <= 0 || !senders) {
    return -1;
  }
  return sender_assignment_counter++ % num_sender_threads;
}

/* Forward declaration: the per-sender timer handler iterates a session
 * shard and calls into client_timer_handler exactly like the legacy
 * main-thread timer_handler did. */
static void sender_timer_handler(evutil_socket_t fd, short event, void *arg);

static void *uclient_sender_thread_main(void *arg) {
  uclient_sender *s = (uclient_sender *)arg;
  current_sender = s;
  while (!s->stop) {
    /* 100 ms cap so we can poll the stop flag promptly even when there
     * are no events besides our timer firing. */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    event_base_loopexit(s->event_base, &tv);
    event_base_dispatch(s->event_base);
  }
  return NULL;
}

static int start_sender_threads(void) {
  const char *origin = num_sender_threads_explicit ? "explicit -J" : "auto";
  if (num_sender_threads <= 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "uclient: sender pool disabled (single-threaded send on main; %s)\n", origin);
    return 0;
  }
  if (num_sender_threads > UCLIENT_MAX_SENDER_THREADS) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "uclient: clamping --sender-threads %d to max %d\n", num_sender_threads,
                  UCLIENT_MAX_SENDER_THREADS);
    num_sender_threads = UCLIENT_MAX_SENDER_THREADS;
  }
  senders = (uclient_sender *)calloc((size_t)num_sender_threads, sizeof(uclient_sender));
  if (!senders) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "uclient: cannot allocate sender pool\n");
    num_sender_threads = 0;
    return -1;
  }
  for (int i = 0; i < num_sender_threads; ++i) {
    senders[i].id = i;
    senders[i].event_base = turn_event_base_new();
    senders[i].stop = 0;

    /* Each sender installs its own timer on its own base. Cadence
     * matches the legacy main-thread timer: 100us in flood modes,
     * 1ms otherwise. */
    senders[i].timer_ev =
        event_new(senders[i].event_base, -1, EV_TIMEOUT | EV_PERSIST, sender_timer_handler, &senders[i]);
    if (!senders[i].timer_ev) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "uclient: cannot create sender %d timer event\n", i);
      return -1;
    }
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = (is_packet_flood_mode() || is_invalid_flood_mode()) ? 100 : 1000;
    evtimer_add(senders[i].timer_ev, &tv);

    if (pthread_create(&senders[i].thread, NULL, uclient_sender_thread_main, &senders[i]) != 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "uclient: pthread_create sender %d failed\n", i);
      return -1;
    }
    senders[i].started = true;
  }
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "uclient: started %d sender thread(s) (%s)\n", num_sender_threads, origin);
  return 0;
}

static void stop_sender_threads(void) {
  if (num_sender_threads <= 0 || !senders) {
    return;
  }
  for (int i = 0; i < num_sender_threads; ++i) {
    senders[i].stop = 1;
    if (senders[i].event_base) {
      event_base_loopbreak(senders[i].event_base);
    }
  }
  for (int i = 0; i < num_sender_threads; ++i) {
    if (senders[i].started) {
      pthread_join(senders[i].thread, NULL);
      senders[i].started = false;
    }
  }
  /* Reduce per-thread slabs into the globals. */
  for (int i = 0; i < num_sender_threads; ++i) {
    tot_send_messages += (uint32_t)senders[i].s_tot_send_messages;
    tot_send_bytes += senders[i].s_tot_send_bytes;
    tot_send_dropped += senders[i].s_tot_send_dropped;
    load_sent_packets += senders[i].s_load_sent_packets;
    total_loss += (size_t)senders[i].s_total_loss;
    total_latency += senders[i].s_total_latency;
    total_jitter += senders[i].s_total_jitter;
  }
  for (int i = 0; i < num_sender_threads; ++i) {
    if (senders[i].timer_ev) {
      event_free(senders[i].timer_ev);
      senders[i].timer_ev = NULL;
    }
    if (senders[i].event_base) {
      event_base_free(senders[i].event_base);
      senders[i].event_base = NULL;
    }
  }
  free(senders);
  senders = NULL;
}

static bool uses_turn_allocation(void) { return !is_invalid_flood_mode(); }

static bool uses_unlimited_message_count(const app_ur_session *elem) {
  return elem && is_load_generator_mode() && (elem->tot_msgnum <= 0);
}

static int get_send_burst_limit(void) { return is_packet_flood_mode() || is_invalid_flood_mode() ? 4096 : 50; }

static size_t get_invalid_packet_length(void) {
  if (clmessage_length < 1) {
    return 1;
  }
  if (clmessage_length > (int)STUN_BUFFER_SIZE) {
    return STUN_BUFFER_SIZE;
  }
  return (size_t)clmessage_length;
}

static void reset_load_generator_rate_stats(void) {
  load_sent_packets = 0;
  load_last_sent_packets = 0;
  load_last_recv_packets = 0;
  load_last_report_time = current_time;
}

static void print_load_generator_rate(const char *context) {
  if (!is_load_generator_mode()) {
    return;
  }

  if (current_time <= load_last_report_time) {
    return;
  }

  const uint64_t elapsed = current_time - load_last_report_time;

  const uint64_t now_sent = load_sent_snapshot();
  const uint64_t delta_sent = now_sent - load_last_sent_packets;
  const double send_pps = (double)delta_sent / (double)elapsed;

  /* Round-trip throughput: packets received back from the relay/peer
   * loop. With aggressive sender-side batching this can be 1-2 orders
   * of magnitude lower than send_pps -- most drops happen at the
   * turnserver UDP recv buffer or the peer once uclient pushes past
   * the relay's per-thread saturation. Reporting both makes the actual
   * end-to-end ceiling visible at a glance. recv_count_snapshot() is
   * a sum of per-listener slabs (atomic loads, no contention with
   * writers). */
  const uint64_t now_recv = (uint64_t)recv_count_snapshot();
  const uint64_t delta_recv = (now_recv >= load_last_recv_packets) ? (now_recv - load_last_recv_packets) : 0;
  const double recv_pps = (double)delta_recv / (double)elapsed;

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: send_pps=%.2f, recv_pps=%.2f, total_sent=%llu, total_recv=%llu\n", context,
                send_pps, recv_pps, (unsigned long long)now_sent, (unsigned long long)now_recv);

  load_last_report_time = current_time;
  load_last_sent_packets = now_sent;
  load_last_recv_packets = now_recv;
}

static void generate_unique_allocation_peer(ioa_addr *peer_addr) {
  if (!peer_addr) {
    return;
  }

  const uint64_t peer_index = synthetic_peer_counter++;
  const uint16_t port = (uint16_t)(1024 + (peer_index % (uint64_t)(0x10000 - 1024)));
  char peer_saddr[129];

  if (default_address_family == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6) {
    const uint64_t host_index = peer_index / (uint64_t)(0x10000 - 1024);
    snprintf(peer_saddr, sizeof(peer_saddr), "2001:db8:%x:%x::1", (unsigned int)((host_index >> 16) & 0xffffU),
             (unsigned int)(host_index & 0xffffU));
  } else {
    const uint64_t host_index = 1 + (peer_index / (uint64_t)(0x10000 - 1024));
    snprintf(peer_saddr, sizeof(peer_saddr), "198.%u.%u.%u", 18 + (unsigned int)((host_index >> 16) & 0x1U),
             (unsigned int)((host_index >> 8) & 0xffU), (unsigned int)(host_index & 0xffU));
  }

  if (make_ioa_addr((const uint8_t *)peer_saddr, port, peer_addr) < 0) {
    addr_set_any(peer_addr);
  }
}

///////////////////////////////////////////////////////////////////////////////

static void __turn_getMSTime(void) {
  static uint64_t start_sec = 0;
  uint64_t sec = 0;
  uint64_t msec_in_sec = 0;
#if defined(_MSC_VER)
  /* MSVC build uses the in-tree shim from apputils.h, which has signature
   * clock_gettime(int, struct timeval *) and fills tv_sec / tv_usec. */
  struct timeval tp = {0, 0};
#if defined(CLOCK_REALTIME)
  clock_gettime(CLOCK_REALTIME, &tp);
#else
  tp.tv_sec = (long)time(NULL);
#endif
  sec = (uint64_t)tp.tv_sec;
  msec_in_sec = (uint64_t)tp.tv_usec / 1000u;
#else
  struct timespec tp = {0, 0};
#if defined(CLOCK_REALTIME)
  clock_gettime(CLOCK_REALTIME, &tp);
#else
  tp.tv_sec = time(NULL);
#endif
  sec = (uint64_t)tp.tv_sec;
  msec_in_sec = (uint64_t)tp.tv_nsec / 1000000u;
#endif
  if (!start_sec) {
    start_sec = sec;
  }
  const uint64_t new_time = sec - start_sec;
  if (current_time != new_time) {
    show_statistics = true;
  }
  current_time = new_time;
  current_mstime = current_time * 1000 + msec_in_sec;
}

////////////////////////////////////////////////////////////////////

static int refresh_channel(app_ur_session *elem, uint16_t method, uint32_t lt);

//////////////////////// SS ////////////////////////////////////////

static app_ur_session *init_app_session(app_ur_session *ss) {
  if (ss) {
    memset(ss, 0, sizeof(app_ur_session));
    ss->pinfo.fd = -1;
    /* -1 = not yet routed to a listener thread (legacy single-threaded
     * mode or session lives on the main event_base). pick_listener_base()
     * stamps the assigned index when routing recv events. */
    ss->listener_id = -1;
    /* -1 = not yet routed to a sender thread (legacy single-threaded
     * send path; main thread's timer_handler owns iteration). */
    ss->sender_id = -1;
  }
  return ss;
}

static app_ur_session *create_new_ss(void) {
  ++current_clients_number;
  app_ur_session *ss = init_app_session((app_ur_session *)malloc(sizeof(app_ur_session)));
  if (ss) {
    /* Sender pool routing: when the pool is engaged, round-robin assign
     * this session to a sender thread. -1 keeps the legacy single-thread
     * (main timer_handler) path. */
    ss->sender_id = pick_sender_id();
  }
  return ss;
}

static void uc_delete_session_elem_data(app_ur_session *cdi) {
  if (cdi) {
    EVENT_DEL(cdi->input_ev);
    EVENT_DEL(cdi->input_tcp_data_ev);
    if (cdi->pinfo.tcp_conn) {
      for (int i = 0; i < (int)(cdi->pinfo.tcp_conn_number); ++i) {
        if (cdi->pinfo.tcp_conn[i]) {
          if (cdi->pinfo.tcp_conn[i]->tcp_data_ssl && !(cdi->pinfo.broken)) {
            if (!(SSL_get_shutdown(cdi->pinfo.tcp_conn[i]->tcp_data_ssl) & SSL_SENT_SHUTDOWN)) {
              SSL_set_shutdown(cdi->pinfo.tcp_conn[i]->tcp_data_ssl, SSL_RECEIVED_SHUTDOWN);
              SSL_shutdown(cdi->pinfo.tcp_conn[i]->tcp_data_ssl);
            }
            if (cdi->pinfo.tcp_conn[i]->tcp_data_ssl) {
              SSL_free(cdi->pinfo.tcp_conn[i]->tcp_data_ssl);
            }
            if (cdi->pinfo.tcp_conn[i]->tcp_data_fd >= 0) {
              socket_closesocket(cdi->pinfo.tcp_conn[i]->tcp_data_fd);
              cdi->pinfo.tcp_conn[i]->tcp_data_fd = -1;
            }
            free(cdi->pinfo.tcp_conn[i]);
            cdi->pinfo.tcp_conn[i] = NULL;
          }
        }
      }
      cdi->pinfo.tcp_conn_number = 0;
      if (cdi->pinfo.tcp_conn) {
        free(cdi->pinfo.tcp_conn);
        cdi->pinfo.tcp_conn = NULL;
      }
    }
    if (cdi->pinfo.ssl && !(cdi->pinfo.broken)) {
      if (!(SSL_get_shutdown(cdi->pinfo.ssl) & SSL_SENT_SHUTDOWN)) {
        SSL_set_shutdown(cdi->pinfo.ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(cdi->pinfo.ssl);
      }
    }
    if (cdi->pinfo.ssl) {
      SSL_free(cdi->pinfo.ssl);
    }
    if (cdi->pinfo.fd >= 0) {
      socket_closesocket(cdi->pinfo.fd);
    }
    cdi->pinfo.fd = -1;
  }
}

static int remove_all_from_ss(app_ur_session *ss) {
  if (ss) {
    uc_delete_session_elem_data(ss);

    --current_clients_number;
  }

  return 0;
}

///////////////////////////////////////////////////////////////////////////////

int send_buffer(app_ur_conn_info *clnet_info, stun_buffer *message, bool data_connection, app_tcp_conn_info *atc) {

  int ret = -1;

  char *buffer = (char *)(message->buf);

  if (negative_protocol_test && (message->len > 0)) {
    if (turn_random_number() % 10 == 0) {
      int np = (int)((unsigned long)turn_random_number() % 10);
      while (np-- > 0) {
        int pos = (int)((unsigned long)turn_random_number() % (unsigned long)message->len);
        int val = (int)((unsigned long)turn_random_number() % 256);
        message->buf[pos] = (uint8_t)val;
      }
    }
  }

  SSL *ssl = clnet_info->ssl;
  ioa_socket_raw fd = clnet_info->fd;

  if (data_connection) {
    if (atc) {
      ssl = atc->tcp_data_ssl;
      fd = atc->tcp_data_fd;
    } else if (is_TCP_relay()) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "trying to send tcp data buffer over unready connection: size=%d\n",
                    (int)(message->len));
      return -1;
    }
  }

  if (ssl) {

    bool message_sent = false;
    while (!message_sent) {

      if (SSL_get_shutdown(ssl)) {
        return -1;
      }

      int len = 0;
      do {
        len = SSL_write(ssl, buffer, (int)message->len);
      } while (len < 0 && (socket_eintr() || socket_enobufs()));

      if (len == (int)message->len) {
        if (clnet_verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "buffer sent: size=%d\n", len);
        }

        message_sent = true;
        ret = len;
      } else {
        switch (SSL_get_error(ssl, len)) {
        case SSL_ERROR_NONE:
          /* Try again ? */
          break;
        case SSL_ERROR_WANT_WRITE:
          /* Just try again later */
          break;
        case SSL_ERROR_WANT_READ:
          /* continue with reading */
          break;
        case SSL_ERROR_ZERO_RETURN:
          /* Try again */
          break;
        case SSL_ERROR_SYSCALL:
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Socket write error 111.666: \n");
          if (handle_socket_error()) {
            break;
          }
          /* Falls through. */
        case SSL_ERROR_SSL: {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL write error: \n");
          char buf[1024];
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s (%d)\n", ERR_error_string(ERR_get_error(), buf),
                        SSL_get_error(ssl, len));
        }
        /* Falls through. */
        default:
          clnet_info->broken = true;
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unexpected error while writing!\n");
          return -1;
        }
      }
    }

  } else if (fd >= 0) {

    /* When a send-batch window is open on this thread (sender-pool's
     * per-tick iteration), enqueue and return success. The actual
     * sendmsg (UDP-GSO when eligible) happens at flush time. */
    if (uclient_tx_enqueue(fd, message->buf, message->len)) {
      ret = (int)message->len;
    } else {
      size_t left = message->len;

      ssize_t rc = 0;

      while (left > 0) {
        do {
          rc = send(fd, buffer, left, 0);
        } while (rc <= 0 && (socket_eintr() || socket_enobufs() || socket_eagain()));
        if (rc > 0) {
          left -= rc;
          buffer += rc;
        } else {
          send_dropped_add(1);
          break;
        }
      }

      if (left > 0) {
        return -1;
      }

      ret = (int)message->len;
    }
  }

  if ((ret > 0) && is_load_generator_mode()) {
    load_sent_add(1);
  }

  return ret;
}

static int wait_fd(int fd, unsigned int cycle) {

  if (fd >= (int)FD_SETSIZE) {
    return 1;
  } else {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    if (dos && cycle == 0) {
      return 0;
    }

    struct timeval start_time;
    struct timeval ctime;
    gettimeofday(&start_time, NULL);

    ctime.tv_sec = start_time.tv_sec;
    ctime.tv_usec = start_time.tv_usec;

    int rc = 0;

    do {
      struct timeval timeout = {0, 0};
      if (cycle == 0) {
        timeout.tv_usec = 500000;
      } else {

        timeout.tv_sec = 1;
        while (--cycle) {
          timeout.tv_sec = timeout.tv_sec + timeout.tv_sec;
        }

        if (ctime.tv_sec > start_time.tv_sec) {
          if (ctime.tv_sec >= start_time.tv_sec + timeout.tv_sec) {
            break;
          } else {
            timeout.tv_sec -= (ctime.tv_sec - start_time.tv_sec);
          }
        }
      }
      rc = select(fd + 1, &fds, NULL, NULL, &timeout);
      if ((rc < 0) && socket_eintr()) {
        gettimeofday(&ctime, NULL);
      } else {
        break;
      }
    } while (1);

    return rc;
  }
}

int recv_buffer(app_ur_conn_info *clnet_info, stun_buffer *message, bool sync, bool data_connection,
                app_tcp_conn_info *atc, stun_buffer *request_message) {

  int rc = 0;

  stun_tid tid;
  uint16_t method = 0;

  if (request_message) {
    stun_tid_from_message(request_message, &tid);
    method = stun_get_method(request_message);
  }

  ioa_socket_raw fd = clnet_info->fd;
  if (atc) {
    fd = atc->tcp_data_fd;
  }

  SSL *ssl = clnet_info->ssl;
  if (atc) {
    ssl = atc->tcp_data_ssl;
  }

recv_again:

  if (!use_tcp && sync && request_message && (fd >= 0)) {

    unsigned int cycle = 0;
    while (cycle < MAX_LISTENING_CYCLE_NUMBER) {
      int serc = wait_fd(fd, cycle);
      if (serc > 0) {
        break;
      }
      if (serc < 0) {
        return -1;
      }
      if (send_buffer(clnet_info, request_message, data_connection, atc) <= 0) {
        return -1;
      }
      ++cycle;
    }
  }

  if (!use_secure && !use_tcp && fd >= 0) {

    /* Plain UDP */

    do {
      rc = recv(fd, message->buf, sizeof(message->buf) - 1, 0);
    } while (rc < 0 && (socket_eintr() || (socket_eagain() && sync)));

    if (rc < 0) {
      return -1;
    }

    message->len = rc;

  } else if (use_secure && !use_tcp && ssl && !(clnet_info->broken)) {

    /* DTLS */

    int message_received = 0;
    int cycle = 0;
    while (!message_received && cycle++ < 100) {

      if (SSL_get_shutdown(ssl)) {
        return -1;
      }

      rc = 0;
      do {
        rc = SSL_read(ssl, message->buf, sizeof(message->buf) - 1);
        if (rc < 0 && socket_eagain() && sync) {
          continue;
        }
      } while (rc < 0 && socket_eintr());

      if (rc > 0) {

        if (clnet_verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "response received: size=%d\n", rc);
        }
        message->len = rc;
        message_received = 1;

      } else {

        int sslerr = SSL_get_error(ssl, rc);

        switch (sslerr) {
        case SSL_ERROR_NONE:
          /* Try again ? */
          break;
        case SSL_ERROR_WANT_WRITE:
          /* Just try again later */
          break;
        case SSL_ERROR_WANT_READ:
          /* continue with reading */
          break;
        case SSL_ERROR_ZERO_RETURN:
          /* Try again */
          break;
        case SSL_ERROR_SYSCALL:
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Socket read error 111.999: \n");
          if (handle_socket_error()) {
            break;
          }
          /* Falls through. */
        case SSL_ERROR_SSL: {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL write error: \n");
          char buf[1024];
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s (%d)\n", ERR_error_string(ERR_get_error(), buf),
                        SSL_get_error(ssl, rc));
        }
        /* Falls through. */
        default:
          clnet_info->broken = true;
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unexpected error while reading: rc=%d, sslerr=%d\n", rc, sslerr);
          return -1;
        }

        if (!sync) {
          break;
        }
      }
    }

  } else if (use_secure && use_tcp && ssl && !(clnet_info->broken)) {

    /* TLS*/

    bool message_received = false;
    int cycle = 0;
    while (!message_received && cycle++ < 100) {

      if (SSL_get_shutdown(ssl)) {
        return -1;
      }
      rc = 0;
      do {
        rc = SSL_read(ssl, message->buf, sizeof(message->buf) - 1);
        if (rc < 0 && socket_eagain() && sync) {
          continue;
        }
      } while (rc < 0 && socket_eintr());

      if (rc > 0) {

        if (clnet_verbose) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "response received: size=%d\n", rc);
        }
        message->len = rc;
        message_received = true;

      } else {

        int sslerr = SSL_get_error(ssl, rc);

        switch (sslerr) {
        case SSL_ERROR_NONE:
          /* Try again ? */
          break;
        case SSL_ERROR_WANT_WRITE:
          /* Just try again later */
          break;
        case SSL_ERROR_WANT_READ:
          /* continue with reading */
          break;
        case SSL_ERROR_ZERO_RETURN:
          /* Try again */
          break;
        case SSL_ERROR_SYSCALL:
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Socket read error 111.999: \n");
          if (handle_socket_error()) {
            break;
          }
          /* Falls through. */
        case SSL_ERROR_SSL: {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SSL write error: \n");
          char buf[1024];
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s (%d)\n", ERR_error_string(ERR_get_error(), buf),
                        SSL_get_error(ssl, rc));
        }
        /* Falls through. */
        default:
          clnet_info->broken = true;
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unexpected error while reading: rc=%d, sslerr=%d\n", rc, sslerr);
          return -1;
        }

        if (!sync) {
          break;
        }
      }
    }

  } else if (!use_secure && use_tcp && fd >= 0) {

    /* Plain TCP */

    do {
      rc = recv(fd, message->buf, sizeof(message->buf) - 1, MSG_PEEK);
    } while (rc < 0 && (socket_eintr() || (socket_eagain() && sync)));

    if (rc > 0) {
      int mlen = rc;
      size_t app_msg_len = (size_t)rc;
      if (!atc) {
        mlen = stun_get_message_len_str(message->buf, rc, 1, &app_msg_len);
      } else {
        if (!sync) {
          mlen = clmessage_length;
        }

        if (mlen > clmessage_length) {
          mlen = clmessage_length;
        }

        app_msg_len = (size_t)mlen;
      }

      if (mlen > 0) {

        int rcr = 0;
        int rsf = 0;
        int cycle = 0;
        while (rsf < mlen && cycle++ < 128) {
          do {
            rcr = recv(fd, message->buf + rsf, (size_t)mlen - (size_t)rsf, 0);
          } while (rcr < 0 && (socket_eintr() || (socket_eagain() && sync)));

          if (rcr > 0) {
            rsf += rcr;
          }
        }

        if (rsf < 1) {
          return -1;
        }

        if (rsf < (int)app_msg_len) {
          if ((size_t)(app_msg_len / (size_t)rsf) * ((size_t)(rsf)) != app_msg_len) {
            return -1;
          }
        }

        message->len = app_msg_len;

        rc = app_msg_len;

      } else {
        rc = 0;
      }
    }
  }

  if (rc > 0) {
    if (request_message) {

      stun_tid recv_tid;
      uint16_t recv_method = 0;

      stun_tid_from_message(message, &recv_tid);
      recv_method = stun_get_method(message);

      if (method != recv_method) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Received wrong response method: 0x%x, expected 0x%x; trying again...\n",
                      (unsigned int)recv_method, (unsigned int)method);
        goto recv_again;
      }

      if (memcmp(tid.tsx_id, recv_tid.tsx_id, STUN_TID_SIZE)) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Received wrong response tid; trying again...\n");
        goto recv_again;
      }
    }
  }

  return rc;
}

/* Process one already-received buffer. The caller must populate
 * elem->in_buffer.{buf,len} (len reflects the recv length). Returns rc
 * (the recv length) on success, 0 on benign skip, -1 on fatal session error.
 * Extracted from client_read() so the Linux recvmmsg batch path can reuse
 * the per-packet processing without going through recv_buffer() again. */
static int process_received_buffer(app_ur_session *elem, int is_tcp_data, app_tcp_conn_info *atc, int rc) {

  app_ur_conn_info *clnet_info = &(elem->pinfo);
  int err_code = 0;
  uint8_t err_msg[129];
  int applen = 0;

  if (rc > 0) {

    elem->in_buffer.len = rc;

    uint16_t chnumber = 0;

    message_info mi;
    bool miset = false;
    size_t buffers = 1;

    if (is_tcp_data) {
      if ((int)elem->in_buffer.len == clmessage_length) {
        memcpy(&mi, (elem->in_buffer.buf), sizeof(message_info));
        miset = true;
      } else {
        /* TODO: make a more clean fix */
        buffers = (int)elem->in_buffer.len / clmessage_length;
      }
    } else if (stun_is_indication(&(elem->in_buffer))) {

      uint16_t method = stun_get_method(&elem->in_buffer);

      if ((method == STUN_METHOD_CONNECTION_ATTEMPT) && is_TCP_relay()) {
        stun_attr_ref sar = stun_attr_get_first(&(elem->in_buffer));
        uint32_t cid = 0;
        while (sar) {
          int attr_type = stun_attr_get_type(sar);
          if (attr_type == STUN_ATTRIBUTE_CONNECTION_ID) {
            cid = *((const uint32_t *)stun_attr_get_value(sar));
            break;
          }
          sar = stun_attr_get_next_str(elem->in_buffer.buf, elem->in_buffer.len, sar);
        }
        if (negative_test) {
          tcp_data_connect(elem, (uint64_t)turn_random_number());
        } else {
          /* positive test */
          tcp_data_connect(elem, cid);
        }
        return rc;
      } else if (method != STUN_METHOD_DATA) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ERROR: received indication message has wrong method: 0x%x\n", (int)method);
        return rc;
      } else {

        stun_attr_ref sar = stun_attr_get_first_by_type(&(elem->in_buffer), STUN_ATTRIBUTE_DATA);
        if (!sar) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ERROR: received DATA message has no data, size=%d\n", rc);
          return rc;
        }

        int rlen = stun_attr_get_len(sar);
        applen = rlen;
        if (rlen != clmessage_length) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ERROR: received DATA message has wrong len: %d, must be %d\n", rlen,
                        clmessage_length);
          /* recv_bytes_add routes to the per-listener slab when called
           * from a listener thread, otherwise to the global directly. */
          recv_bytes_add((uint64_t)applen);
          return rc;
        }

        const uint8_t *data = stun_attr_get_value(sar);

        memcpy(&mi, data, sizeof(message_info));
        miset = true;
      }

    } else if (stun_is_success_response(&(elem->in_buffer))) {

      if (elem->pinfo.nonce[0]) {
        if (check_integrity(&(elem->pinfo), &(elem->in_buffer)) < 0) {
          return -1;
        }
      }

      if (is_TCP_relay() && (stun_get_method(&(elem->in_buffer)) == STUN_METHOD_CONNECT)) {
        stun_attr_ref sar = stun_attr_get_first(&(elem->in_buffer));
        uint32_t cid = 0;
        while (sar) {
          int attr_type = stun_attr_get_type(sar);
          if (attr_type == STUN_ATTRIBUTE_CONNECTION_ID) {
            cid = *((const uint32_t *)stun_attr_get_value(sar));
            break;
          }
          sar = stun_attr_get_next_str(elem->in_buffer.buf, elem->in_buffer.len, sar);
        }
        tcp_data_connect(elem, cid);
      }

      return rc;
    } else if (stun_is_challenge_response_str(elem->in_buffer.buf, elem->in_buffer.len, &err_code, err_msg,
                                              sizeof(err_msg), clnet_info->realm, clnet_info->nonce,
                                              clnet_info->server_name, &(clnet_info->oauth))) {
      if (is_TCP_relay() && (stun_get_method(&(elem->in_buffer)) == STUN_METHOD_CONNECT)) {
        turn_tcp_connect(clnet_verbose, &(elem->pinfo), &(elem->pinfo.peer_addr));
      } else if (stun_get_method(&(elem->in_buffer)) == STUN_METHOD_REFRESH) {
        refresh_channel(elem, stun_get_method(&elem->in_buffer), 600);
      }
      return rc;
    } else if (stun_is_error_response(&(elem->in_buffer), NULL, NULL, 0)) {
      return rc;
    } else if (stun_is_channel_message(&(elem->in_buffer), &chnumber, use_tcp)) {
      if (elem->chnum != chnumber) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ERROR: received message has wrong channel: %d\n", (int)chnumber);
        return rc;
      }

      if (elem->in_buffer.len >= 4) {
        if (((int)(elem->in_buffer.len - 4) < clmessage_length) ||
            ((int)(elem->in_buffer.len - 4) > clmessage_length + 3)) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ERROR: received buffer have wrong length: %d, must be %d, len=%d\n", rc,
                        clmessage_length + 4, (int)elem->in_buffer.len);
          return rc;
        }

        memcpy(&mi, elem->in_buffer.buf + 4, sizeof(message_info));
        miset = true;
        applen = elem->in_buffer.len - 4;
      }
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "ERROR: Unknown message received of size: %d\n", (int)(elem->in_buffer.len));
      return rc;
    }

    if (miset) {
      /*
      printf("%s: 111.111: msgnum=%d, rmsgnum=%d, sent=%lu, recv=%lu\n",__FUNCTION__,
              mi->msgnum,elem->recvmsgnum,(unsigned long)mi->mstime,(unsigned long)current_mstime);
              */
      if (mi.msgnum != elem->recvmsgnum + 1) {
        /* Atomic increment: the timer thread on main harvests elem->loss
         * with an atomic exchange-and-zero (see client_timer_handler);
         * this builtin pairs with that to make the harvest race-free. */
        (void)uclient_atomic_fetch_add_size(&elem->loss, (size_t)1);
      } else {
        uint64_t clatency = (uint64_t)time_minus(current_mstime, mi.mstime);
        /* min/max latency: use this thread's per-listener accumulator when
         * running on a listener thread, otherwise the legacy global. The
         * listener accumulators are reduced into the globals after
         * pthread_join (see stop_listener_threads). */
        if (on_listener_thread()) {
          if (clatency > current_listener->l_max_latency) {
            current_listener->l_max_latency = clatency;
          }
          if (clatency < current_listener->l_min_latency) {
            current_listener->l_min_latency = clatency;
          }
        } else {
          if (clatency > max_latency) {
            max_latency = clatency;
          }
          if (clatency < min_latency) {
            min_latency = clatency;
          }
        }
        (void)uclient_atomic_fetch_add_u64(&elem->latency, clatency);
        if (elem->rmsgnum > 0) {
          uint64_t cjitter = abs((int)(current_mstime - elem->recvtimems) - RTP_PACKET_INTERVAL);

          if (on_listener_thread()) {
            if (cjitter > current_listener->l_max_jitter) {
              current_listener->l_max_jitter = cjitter;
            }
            if (cjitter < current_listener->l_min_jitter) {
              current_listener->l_min_jitter = cjitter;
            }
          } else {
            if (cjitter > max_jitter) {
              max_jitter = cjitter;
            }
            if (cjitter < min_jitter) {
              min_jitter = cjitter;
            }
          }

          (void)uclient_atomic_fetch_add_u64(&elem->jitter, cjitter);
        }
      }

      elem->recvmsgnum = mi.msgnum;
    }

    elem->rmsgnum += buffers;
    /* recv_count_add / recv_bytes_add route to the per-listener slab
     * on a listener thread or to the global directly on main. */
    recv_count_add((uint32_t)buffers);
    recv_bytes_add(applen > 0 ? (uint64_t)applen : (uint64_t)elem->in_buffer.len);
    elem->recvtimems = current_mstime;
    elem->wait_cycles = 0;

  } else if (rc == 0) {
    return 0;
  } else {
    return -1;
  }

  return rc;
}

static int client_read(app_ur_session *elem, int is_tcp_data, app_tcp_conn_info *atc) {

  if (!elem) {
    return -1;
  }

  if (elem->state != UR_STATE_READY) {
    return -1;
  }

  elem->ctime = current_time;

  app_ur_conn_info *clnet_info = &(elem->pinfo);

  if (clnet_verbose && verbose_packets) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "before read ...\n");
  }

  int rc = recv_buffer(clnet_info, &(elem->in_buffer), 0, is_tcp_data, atc, NULL);

  if (clnet_verbose && verbose_packets) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "read %d bytes\n", (int)rc);
  }

  return process_received_buffer(elem, is_tcp_data, atc, rc);
}

#if defined(__linux__)
/* Linux-only batched UDP receive for the input handler hot path. One
 * recvmmsg(2) drains up to UCLIENT_RECVMMSG_BATCH datagrams from the kernel
 * queue with a single syscall, then per-packet processing runs without
 * additional kernel transitions. At ~1k+ pps per session this typically cuts
 * the recv-side syscall rate by 10-20x and is the difference between
 * "phantom" loss (queue overflow at the kernel boundary) and real loss.
 *
 * Limited to the plain-UDP, non-secure, non-TCP-relay case. SSL_read /
 * SSL_pending and the TCP-relay sub-connections still use the legacy
 * single-recv path via client_read(). */
#define UCLIENT_RECVMMSG_BATCH (32)
/* Per-slot scratch buffer; deliberately smaller than STUN_BUFFER_SIZE (~64K)
 * to keep the static allocation under 64 KB total. TURN/STUN datagrams over
 * UDP are bounded by the path MTU; 2 KB covers any realistic packet and
 * truncated payloads will be reported via MSG_TRUNC. */
#define UCLIENT_RECVMMSG_BUF (2048)

static int client_read_batch_udp(app_ur_session *elem) {
  static struct mmsghdr msgs[UCLIENT_RECVMMSG_BATCH];
  static struct iovec iovecs[UCLIENT_RECVMMSG_BATCH];
  static uint8_t scratch[UCLIENT_RECVMMSG_BATCH][UCLIENT_RECVMMSG_BUF];

  if (!elem || elem->state != UR_STATE_READY) {
    return -1;
  }
  evutil_socket_t fd = elem->pinfo.fd;
  if (fd < 0) {
    return -1;
  }

  int total = 0;
  while (1) {
    for (int i = 0; i < UCLIENT_RECVMMSG_BATCH; ++i) {
      iovecs[i].iov_base = scratch[i];
      iovecs[i].iov_len = sizeof(scratch[i]);
      msgs[i].msg_hdr.msg_name = NULL;
      msgs[i].msg_hdr.msg_namelen = 0;
      msgs[i].msg_hdr.msg_iov = &iovecs[i];
      msgs[i].msg_hdr.msg_iovlen = 1;
      msgs[i].msg_hdr.msg_control = NULL;
      msgs[i].msg_hdr.msg_controllen = 0;
      msgs[i].msg_hdr.msg_flags = 0;
      msgs[i].msg_len = 0;
    }

    int n = recvmmsg(fd, msgs, UCLIENT_RECVMMSG_BATCH, MSG_DONTWAIT, NULL);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return total;
      }
      return total > 0 ? total : -1;
    }
    if (n == 0) {
      return total;
    }

    elem->ctime = current_time;
    for (int i = 0; i < n; ++i) {
      int rc = (int)msgs[i].msg_len;
      if (rc <= 0) {
        continue;
      }
      const size_t cap = sizeof(elem->in_buffer.buf) - 1;
      if ((size_t)rc > cap) {
        rc = (int)cap;
      }
      memcpy(elem->in_buffer.buf, scratch[i], (size_t)rc);
      elem->in_buffer.len = (size_t)rc;
      (void)process_received_buffer(elem, /*is_tcp_data=*/0, /*atc=*/NULL, rc);
      ++total;
    }

    /* If recvmmsg returned a short batch the kernel queue is empty; no
     * point in another syscall right now -- the EV_READ event will refire
     * when more arrives. */
    if (n < UCLIENT_RECVMMSG_BATCH) {
      return total;
    }
  }
}
#endif /* __linux__ */

static int client_shutdown(app_ur_session *elem) {

  if (!elem) {
    return -1;
  }

  elem->state = UR_STATE_DONE;

  elem->ctime = current_time;

  remove_all_from_ss(elem);

  if (clnet_verbose) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "done, connection %p closed.\n", elem);
  }

  return 0;
}

static int client_write(app_ur_session *elem) {

  if (!elem) {
    return -1;
  }

  if (elem->state != UR_STATE_READY) {
    return -1;
  }

  elem->ctime = current_time;

  app_tcp_conn_info *atc = NULL;
  size_t payload_len = (size_t)clmessage_length;

  if (is_invalid_flood_mode()) {
    payload_len = get_invalid_packet_length();
    memset(elem->out_buffer.buf, 0xA5, payload_len);
    if (payload_len >= 8) {
      elem->out_buffer.buf[0] = 0x00;
      elem->out_buffer.buf[1] = 0x01;
      elem->out_buffer.buf[2] = 0x7f;
      elem->out_buffer.buf[3] = 0x7f;
      memcpy(elem->out_buffer.buf + 4, &(elem->wmsgnum), sizeof(elem->wmsgnum));
    }
    elem->out_buffer.len = payload_len;
  } else {
    message_info *mi = (message_info *)buffer_to_send;
    mi->msgnum = elem->wmsgnum;
    mi->mstime = current_mstime;
  }

  if (!is_invalid_flood_mode() && is_TCP_relay()) {

    memcpy(elem->out_buffer.buf, buffer_to_send, clmessage_length);
    elem->out_buffer.len = clmessage_length;

    if (elem->pinfo.is_peer) {
      if (send(elem->pinfo.fd, elem->out_buffer.buf, clmessage_length, 0) >= 0) {
        ++elem->wmsgnum;
        elem->to_send_timems += RTP_PACKET_INTERVAL;
        send_count_add(1);
        send_bytes_add(payload_len);
      }
      return 0;
    }

    if (!(elem->pinfo.tcp_conn) || !(elem->pinfo.tcp_conn_number)) {
      return -1;
    }
    int i = (unsigned int)(turn_random_number()) % elem->pinfo.tcp_conn_number;
    atc = elem->pinfo.tcp_conn[i];
    if (!atc->tcp_data_bound) {
      printf("%s: Uninitialized atc: i=%d, atc=%p\n", __FUNCTION__, i, atc);
      return -1;
    }
  } else if (!is_invalid_flood_mode() && !do_not_use_channel) {
    /* Let's always do padding: */
    stun_init_channel_message(elem->chnum, &(elem->out_buffer), clmessage_length, mandatory_channel_padding || use_tcp);
    memcpy(elem->out_buffer.buf + 4, buffer_to_send, clmessage_length);
  } else if (!is_invalid_flood_mode()) {
    stun_init_indication(STUN_METHOD_SEND, &(elem->out_buffer));
    stun_attr_add(&(elem->out_buffer), STUN_ATTRIBUTE_DATA, buffer_to_send, clmessage_length);
    stun_attr_add_addr(&(elem->out_buffer), STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(elem->pinfo.peer_addr));
    if (dont_fragment) {
      stun_attr_add(&(elem->out_buffer), STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);
    }

    if (use_fingerprints) {
      stun_attr_add_fingerprint_str(elem->out_buffer.buf, (size_t *)&(elem->out_buffer.len));
    }
  }

  if (elem->out_buffer.len > 0) {

    if (clnet_verbose && verbose_packets) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "before write ...\n");
    }

    int rc = send_buffer(&(elem->pinfo), &(elem->out_buffer), 1, atc);

    ++elem->wmsgnum;
    elem->to_send_timems += RTP_PACKET_INTERVAL;

    if (rc >= 0) {
      if (clnet_verbose && verbose_packets) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "wrote %d bytes\n", (int)rc);
      }
      send_count_add(1);
      send_bytes_add(payload_len);
    } else {
      return -1;
    }
  }

  return 0;
}

void client_input_handler(evutil_socket_t fd, short what, void *arg) {

  if (!(what & EV_READ) || !arg) {
    return;
  }

  UNUSED_ARG(fd);

  app_ur_session *elem = (app_ur_session *)arg;
  if (!elem) {
    return;
  }

  switch (elem->state) {
  case UR_STATE_READY:
#if defined(__linux__)
    /* Plain-UDP fast path: drain the kernel queue with a single recvmmsg(2)
     * batch. The legacy per-packet recv() loop below remains for SSL/DTLS,
     * TCP, and TCP-relay sub-connections (atc), where recvmmsg doesn't
     * apply or doesn't help. */
    if (!use_secure && !use_tcp && !elem->pinfo.tcp_conn && fd == elem->pinfo.fd) {
      (void)client_read_batch_udp(elem);
      break;
    }
#endif
    do {
      app_tcp_conn_info *atc = NULL;
      int is_tcp_data = 0;
      if (elem->pinfo.tcp_conn) {
        int i = 0;
        for (i = 0; i < (int)(elem->pinfo.tcp_conn_number); ++i) {
          if (elem->pinfo.tcp_conn[i]) {
            if ((fd == elem->pinfo.tcp_conn[i]->tcp_data_fd) && (elem->pinfo.tcp_conn[i]->tcp_data_bound)) {
              is_tcp_data = 1;
              atc = elem->pinfo.tcp_conn[i];
              break;
            }
          }
        }
      }
      int rc = client_read(elem, is_tcp_data, atc);
      if (rc <= 0) {
        break;
      }
    } while (1);

    break;
  default:;
  }
}

static void client_discard_input_handler(evutil_socket_t fd, short what, void *arg) {
  if (!(what & EV_READ) || !arg) {
    return;
  }

  UNUSED_ARG(fd);

  app_ur_session *elem = (app_ur_session *)arg;
  if (!elem || (elem->state != UR_STATE_READY)) {
    return;
  }

  uint8_t buffer[STUN_BUFFER_SIZE];

  if (elem->pinfo.ssl) {
    int rc = 0;
    do {
      rc = SSL_read(elem->pinfo.ssl, buffer, (int)sizeof(buffer));
    } while ((rc > 0) || (rc < 0 && socket_eintr()));
  } else if (elem->pinfo.fd >= 0) {
    ssize_t rc = 0;
    do {
      rc = recv(elem->pinfo.fd, buffer, sizeof(buffer), 0);
    } while ((rc > 0) || (rc < 0 && socket_eintr()));
  }
}

static void run_events(int short_burst) {
  struct timeval timeout;

  if (!short_burst) {
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
  } else {
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
  }

  event_base_loopexit(client_event_base, &timeout);

  event_base_dispatch(client_event_base);
}

////////////////////// main method /////////////////

static int start_invalid_client(const char *remote_address, uint16_t port, const unsigned char *ifname,
                                const char *local_address, int messagenumber, int i) {

  app_ur_session *ss = create_new_ss();
  app_ur_conn_info *clnet_info = &(ss->pinfo);

  if (start_raw_connection(port, remote_address, ifname, local_address, clnet_verbose, clnet_info) < 0) {
    exit(-1);
  }

  socket_set_nonblocking(clnet_info->fd);

  struct event *ev =
      event_new(client_event_base, clnet_info->fd, EV_READ | EV_PERSIST, client_discard_input_handler, ss);
  event_add(ev, NULL);

  ss->state = UR_STATE_READY;
  ss->input_ev = ev;
  ss->tot_msgnum = messagenumber;
  ss->recvmsgnum = -1;
  ss->chnum = 0;

  elems[i] = ss;

  return 0;
}

static int start_client(const char *remote_address, uint16_t port, const unsigned char *ifname,
                        const char *local_address, int messagenumber, int i) {

  app_ur_session *ss = create_new_ss();
  app_ur_session *ss_rtcp = NULL;

  if (!no_rtcp) {
    ss_rtcp = create_new_ss();
  }

  app_ur_conn_info clnet_info_probe; /* for load balancing probe */
  memset(&clnet_info_probe, 0, sizeof(clnet_info_probe));
  clnet_info_probe.fd = -1;

  app_ur_conn_info *clnet_info = &(ss->pinfo);
  app_ur_conn_info *clnet_info_rtcp = NULL;

  if (!no_rtcp) {
    clnet_info_rtcp = &(ss_rtcp->pinfo);
  }

  uint16_t chnum = 0;
  uint16_t chnum_rtcp = 0;

  start_connection(port, remote_address, ifname, local_address, clnet_verbose, &clnet_info_probe, clnet_info, &chnum,
                   clnet_info_rtcp, &chnum_rtcp);

  if (clnet_info_probe.ssl) {
    SSL_free(clnet_info_probe.ssl);
    clnet_info_probe.fd = -1;
  } else if (clnet_info_probe.fd != -1) {
    socket_closesocket(clnet_info_probe.fd);
    clnet_info_probe.fd = -1;
  }

  socket_set_nonblocking(clnet_info->fd);

  if (!no_rtcp) {
    socket_set_nonblocking(clnet_info_rtcp->fd);
  }

  struct event *ev = event_new(pick_listener_base(ss), clnet_info->fd, EV_READ | EV_PERSIST, client_input_handler, ss);

  event_add(ev, NULL);

  struct event *ev_rtcp = NULL;

  if (!no_rtcp) {
    ev_rtcp = event_new(pick_listener_base(ss_rtcp), clnet_info_rtcp->fd, EV_READ | EV_PERSIST, client_input_handler,
                        ss_rtcp);

    event_add(ev_rtcp, NULL);
  }

  ss->state = UR_STATE_READY;

  ss->input_ev = ev;
  ss->tot_msgnum = messagenumber;
  ss->recvmsgnum = -1;
  ss->chnum = chnum;

  if (!no_rtcp) {

    ss_rtcp->state = UR_STATE_READY;

    ss_rtcp->input_ev = ev_rtcp;
    ss_rtcp->tot_msgnum = ss->tot_msgnum;
    if (ss_rtcp->tot_msgnum < 1) {
      ss_rtcp->tot_msgnum = 1;
    }
    ss_rtcp->recvmsgnum = -1;
    ss_rtcp->chnum = chnum_rtcp;
  }

  elems[i] = ss;

  refresh_channel(ss, 0, 600);

  if (!no_rtcp) {
    elems[i + 1] = ss_rtcp;
  }

  return 0;
}

static void start_allocation_flood(const char *remote_address, uint16_t port, const unsigned char *ifname,
                                   const char *local_address, int allocation_count, int mclient) {

  const bool unlimited = allocation_count <= 0;
  const uint64_t per_client_target = unlimited ? 0 : (uint64_t)allocation_count;
  const uint64_t total_target = unlimited ? 0 : (per_client_target * (uint64_t)mclient);

  __turn_getMSTime();
  const uint64_t start_time = current_time;
  tot_allocations = 0;
  synthetic_peer_counter = 0;
  reset_load_generator_rate_stats();

  while (unlimited || (tot_allocations < total_target)) {
    for (int i = 0; i < mclient; ++i) {
      app_ur_conn_info clnet_info_probe;
      app_ur_conn_info clnet_info;
      ioa_addr synthetic_peer_addr;
      memset(&clnet_info_probe, 0, sizeof(clnet_info_probe));
      memset(&clnet_info, 0, sizeof(clnet_info));
      memset(&synthetic_peer_addr, 0, sizeof(synthetic_peer_addr));
      clnet_info_probe.fd = -1;
      clnet_info.fd = -1;

      generate_unique_allocation_peer(&synthetic_peer_addr);

      if (start_allocate_only_connection(port, remote_address, ifname, local_address, clnet_verbose, &clnet_info_probe,
                                         &clnet_info, &synthetic_peer_addr) < 0) {
        exit(-1);
      }

      turn_refresh_allocation(clnet_verbose, &clnet_info, 0);

      app_ur_session ss_probe;
      app_ur_session ss_alloc;
      memset(&ss_probe, 0, sizeof(ss_probe));
      memset(&ss_alloc, 0, sizeof(ss_alloc));
      ss_probe.pinfo = clnet_info_probe;
      ss_alloc.pinfo = clnet_info;
      if (ss_probe.pinfo.fd >= 0 || ss_probe.pinfo.ssl) {
        uc_delete_session_elem_data(&ss_probe);
      }
      uc_delete_session_elem_data(&ss_alloc);

      ++tot_allocations;

      __turn_getMSTime();
      if (show_statistics) {
        print_load_generator_rate(__FUNCTION__);
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: total_allocations=%llu\n", __FUNCTION__,
                      (unsigned long long)tot_allocations);
        show_statistics = false;
      }

      if (!unlimited && (tot_allocations >= total_target)) {
        break;
      }
    }
  }

  __turn_getMSTime();
  print_load_generator_rate(__FUNCTION__);
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: total_allocations=%llu\n", __FUNCTION__, (unsigned long long)tot_allocations);
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total allocation flood time is %u\n", (unsigned int)(current_time - start_time));
}

static int start_c2c(const char *remote_address, uint16_t port, const unsigned char *ifname, const char *local_address,
                     int messagenumber, int i) {

  app_ur_session *ss1 = create_new_ss();
  app_ur_session *ss1_rtcp = NULL;

  if (!no_rtcp) {
    ss1_rtcp = create_new_ss();
  }

  app_ur_session *ss2 = create_new_ss();
  app_ur_session *ss2_rtcp = NULL;

  if (!no_rtcp) {
    ss2_rtcp = create_new_ss();
  }

  app_ur_conn_info clnet_info_probe; /* for load balancing probe */
  memset(&clnet_info_probe, 0, sizeof(clnet_info_probe));
  clnet_info_probe.fd = -1;

  app_ur_conn_info *clnet_info1 = &(ss1->pinfo);
  app_ur_conn_info *clnet_info1_rtcp = NULL;

  if (!no_rtcp) {
    clnet_info1_rtcp = &(ss1_rtcp->pinfo);
  }

  app_ur_conn_info *clnet_info2 = &(ss2->pinfo);
  app_ur_conn_info *clnet_info2_rtcp = NULL;

  if (!no_rtcp) {
    clnet_info2_rtcp = &(ss2_rtcp->pinfo);
  }

  uint16_t chnum1 = 0;
  uint16_t chnum1_rtcp = 0;
  uint16_t chnum2 = 0;
  uint16_t chnum2_rtcp = 0;

  start_c2c_connection(port, remote_address, ifname, local_address, clnet_verbose, &clnet_info_probe, clnet_info1,
                       &chnum1, clnet_info1_rtcp, &chnum1_rtcp, clnet_info2, &chnum2, clnet_info2_rtcp, &chnum2_rtcp);

  if (clnet_info_probe.ssl) {
    SSL_free(clnet_info_probe.ssl);
    clnet_info_probe.fd = -1;
  } else if (clnet_info_probe.fd != -1) {
    socket_closesocket(clnet_info_probe.fd);
    clnet_info_probe.fd = -1;
  }

  socket_set_nonblocking(clnet_info1->fd);

  if (!no_rtcp) {
    socket_set_nonblocking(clnet_info1_rtcp->fd);
  }

  socket_set_nonblocking(clnet_info2->fd);

  if (!no_rtcp) {
    socket_set_nonblocking(clnet_info2_rtcp->fd);
  }

  struct event *ev1 =
      event_new(pick_listener_base(ss1), clnet_info1->fd, EV_READ | EV_PERSIST, client_input_handler, ss1);

  event_add(ev1, NULL);

  struct event *ev1_rtcp = NULL;

  if (!no_rtcp) {
    ev1_rtcp = event_new(pick_listener_base(ss1_rtcp), clnet_info1_rtcp->fd, EV_READ | EV_PERSIST, client_input_handler,
                         ss1_rtcp);

    event_add(ev1_rtcp, NULL);
  }

  struct event *ev2 =
      event_new(pick_listener_base(ss2), clnet_info2->fd, EV_READ | EV_PERSIST, client_input_handler, ss2);

  event_add(ev2, NULL);

  struct event *ev2_rtcp = NULL;

  if (!no_rtcp) {
    ev2_rtcp = event_new(pick_listener_base(ss2_rtcp), clnet_info2_rtcp->fd, EV_READ | EV_PERSIST, client_input_handler,
                         ss2_rtcp);

    event_add(ev2_rtcp, NULL);
  }

  ss1->state = UR_STATE_READY;

  ss1->input_ev = ev1;
  ss1->tot_msgnum = messagenumber;
  ss1->recvmsgnum = -1;
  ss1->chnum = chnum1;

  if (!no_rtcp) {

    ss1_rtcp->state = UR_STATE_READY;

    ss1_rtcp->input_ev = ev1_rtcp;
    ss1_rtcp->tot_msgnum = ss1->tot_msgnum;
    if (ss1_rtcp->tot_msgnum < 1) {
      ss1_rtcp->tot_msgnum = 1;
    }
    ss1_rtcp->recvmsgnum = -1;
    ss1_rtcp->chnum = chnum1_rtcp;
  }

  ss2->state = UR_STATE_READY;

  ss2->input_ev = ev2;
  ss2->tot_msgnum = ss1->tot_msgnum;
  ss2->recvmsgnum = -1;
  ss2->chnum = chnum2;

  if (!no_rtcp) {
    ss2_rtcp->state = UR_STATE_READY;

    ss2_rtcp->input_ev = ev2_rtcp;
    ss2_rtcp->tot_msgnum = ss1_rtcp->tot_msgnum;
    ss2_rtcp->recvmsgnum = -1;
    ss2_rtcp->chnum = chnum2_rtcp;
  }

  elems[i++] = ss1;
  if (!no_rtcp) {
    elems[i++] = ss1_rtcp;
  }
  elems[i++] = ss2;
  if (!no_rtcp) {
    elems[i++] = ss2_rtcp;
  }

  return 0;
}

static int refresh_channel(app_ur_session *elem, uint16_t method, uint32_t lt) {

  stun_buffer message;
  app_ur_conn_info *clnet_info = &(elem->pinfo);

  if (clnet_info->is_peer) {
    return 0;
  }

  if (!method || (method == STUN_METHOD_REFRESH)) {
    stun_init_request(STUN_METHOD_REFRESH, &message);
    lt = htonl(lt);
    stun_attr_add(&message, STUN_ATTRIBUTE_LIFETIME, (const char *)&lt, 4);

    if (dual_allocation && !mobility) {
      int t = ((uint8_t)turn_random_number()) % 3;
      if (t) {
        uint8_t field[4];
        field[0] = (t == 1) ? (uint8_t)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4
                            : (uint8_t)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
        field[1] = 0;
        field[2] = 0;
        field[3] = 0;
        stun_attr_add(&message, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY, (const char *)field, 4);
      }
    }

    add_origin(&message);
    if (add_integrity(clnet_info, &message) < 0) {
      return -1;
    }
    if (use_fingerprints) {
      stun_attr_add_fingerprint_str(message.buf, (size_t *)&(message.len));
    }
    send_buffer(clnet_info, &message, 0, 0);
  }

  if (lt && !addr_any(&(elem->pinfo.peer_addr))) {

    if (!no_permissions) {
      if (!method || (method == STUN_METHOD_CREATE_PERMISSION)) {
        stun_init_request(STUN_METHOD_CREATE_PERMISSION, &message);
        stun_attr_add_addr(&message, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(elem->pinfo.peer_addr));
        add_origin(&message);
        if (add_integrity(clnet_info, &message) < 0) {
          return -1;
        }
        if (use_fingerprints) {
          stun_attr_add_fingerprint_str(message.buf, (size_t *)&(message.len));
        }
        send_buffer(&(elem->pinfo), &message, 0, 0);
      }
    }

    if (!method || (method == STUN_METHOD_CHANNEL_BIND)) {
      if (STUN_VALID_CHANNEL(elem->chnum)) {
        stun_set_channel_bind_request(&message, &(elem->pinfo.peer_addr), elem->chnum);
        add_origin(&message);
        if (add_integrity(clnet_info, &message) < 0) {
          return -1;
        }
        if (use_fingerprints) {
          stun_attr_add_fingerprint_str(message.buf, (size_t *)&(message.len));
        }
        send_buffer(&(elem->pinfo), &message, 1, 0);
      }
    }
  }

  elem->refresh_time = current_mstime + 30 * 1000;

  return 0;
}

static inline int client_timer_handler(app_ur_session *elem, int *done) {
  if (elem) {
    if (uses_turn_allocation() && !turn_time_before(current_mstime, elem->refresh_time)) {
      refresh_channel(elem, 0, 600);
    }

    if (hang_on && elem->completed) {
      return 0;
    }

    const bool unlimited = uses_unlimited_message_count(elem);
    int max_num = get_send_burst_limit();
    int cur_num = 0;

    while (!turn_time_before(current_mstime, elem->to_send_timems)) {
      if (cur_num++ >= max_num) {
        break;
      }
      if (!unlimited && (elem->wmsgnum >= elem->tot_msgnum)) {
        if (!turn_time_before(current_mstime, elem->finished_time) ||
            (!is_invalid_flood_mode() && (recv_count_snapshot() >= tot_messages))) {
          /*
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: elem=0x%x: 111.111: c=%d, t=%d, r=%d,
          w=%d\n",__FUNCTION__,(int)elem,elem->wait_cycles,elem->tot_msgnum,elem->rmsgnum,elem->wmsgnum);
          */
          /*
           TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: 111.222: ly=%llu, ls=%llu, j=%llu\n",__FUNCTION__,
           (unsigned long long)elem->latency,
           (unsigned long long)elem->loss,
           (unsigned long long)elem->jitter);
          */
          /* Atomic exchange-and-zero on each per-elem stat. The listener
           * thread that owns this session may still be running, so a
           * plain read+store would race with __atomic_fetch_add on the
           * listener side; __atomic_exchange_n returns the previous
           * value and zeroes the slot in one indivisible step so no
           * increment is lost or double-counted. */
          completion_loss_add(uclient_atomic_exchange_size(&elem->loss, (size_t)0));
          completion_latency_add(uclient_atomic_exchange_u64(&elem->latency, (uint64_t)0));
          completion_jitter_add(uclient_atomic_exchange_u64(&elem->jitter, (uint64_t)0));
          elem->completed = 1;
          if (!hang_on) {
            refresh_channel(elem, 0, 0);
            client_shutdown(elem);
            return 1;
          } else {
            return 0;
          }
        }
      } else {
        *done += 1;
        if (client_write(elem) < 0) {
          client_shutdown(elem);
          return 1;
        }
        elem->finished_time = current_mstime + STOPPING_TIME * 1000;
      }
    }
  }

  return 0;
}

static void timer_handler(evutil_socket_t fd, short event, void *arg) {
  UNUSED_ARG(fd);
  UNUSED_ARG(event);
  UNUSED_ARG(arg);

  __turn_getMSTime();

  if (start_full_timer) {
    /* When the sender pool is engaged, the per-sender timers own session
     * iteration and the main thread's timer is idle (it still fires so
     * lifecycle code and __turn_getMSTime stay current on main). */
    if (num_sender_threads > 0 && senders) {
      return;
    }
    int done = 0;
    for (int i = 0; i < total_clients; ++i) {
      if (elems[i]) {
        int finished = client_timer_handler(elems[i], &done);
        if (finished) {
          elems[i] = NULL;
        }
      }
    }
    if (done > 5 && (dos || random_disconnect)) {
      for (int i = 0; i < total_clients; ++i) {
        if (elems[i]) {
          socket_closesocket(elems[i]->pinfo.fd);
          elems[i]->pinfo.fd = -1;
        }
      }
    }
  }
}

/* Per-sender-thread timer: iterates only the sessions sharded onto this
 * sender. Cadence and burst semantics match the legacy timer_handler. */
static void sender_timer_handler(evutil_socket_t fd, short event, void *arg) {
  UNUSED_ARG(fd);
  UNUSED_ARG(event);
  uclient_sender *s = (uclient_sender *)arg;
  if (!s || !start_full_timer) {
    return;
  }
  __turn_getMSTime();
  int done = 0;
  /* Open the send batch for the duration of this tick's iteration so that
   * each session's burst coalesces into a single UDP-GSO sendmsg (or a
   * single sendmmsg when GSO is unavailable). Fd-change between sessions
   * auto-flushes; uclient_send_batch_end flushes the final group. */
  uclient_send_batch_begin();
  for (int i = 0; i < total_clients; ++i) {
    app_ur_session *elem = elems[i];
    if (!elem || elem->sender_id != s->id) {
      continue;
    }
    int finished = client_timer_handler(elem, &done);
    if (finished) {
      /* Single-writer per slot: this sender thread is the only one that
       * iterates entries with sender_id == s->id, so this store does not
       * race with another sender. Main thread reads elems[i] without
       * locks under the same legacy invariant. */
      elems[i] = NULL;
    }
  }
  uclient_send_batch_end();
  if (done > 5 && (dos || random_disconnect)) {
    for (int i = 0; i < total_clients; ++i) {
      app_ur_session *elem = elems[i];
      if (elem && elem->sender_id == s->id) {
        socket_closesocket(elem->pinfo.fd);
        elem->pinfo.fd = -1;
      }
    }
  }
}

void start_mclient(const char *remote_address, uint16_t port, const unsigned char *ifname, const char *local_address,
                   int messagenumber, int mclient) {

  if (mclient < 1) {
    mclient = 1;
  }

  total_clients = mclient;

  if (is_alloc_flood_mode()) {
    start_allocation_flood(remote_address, port, ifname, local_address, messagenumber, mclient);
    return;
  }

  if (c2c) {
    // mclient must be a multiple of 4:
    if (!no_rtcp) {
      mclient += ((4 - (mclient & 0x00000003)) & 0x00000003);
    } else if (mclient & 0x1) {
      ++mclient;
    }
  } else {
    if (!no_rtcp) {
      if (mclient & 0x1) {
        ++mclient;
      }
    }
  }

  elems = (app_ur_session **)malloc(sizeof(app_ur_session) * ((mclient * 2) + 1) + sizeof(void *));
  if (elems == NULL) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s: failure in call to malloc !!!\n", __FUNCTION__);
    return;
  }

  __turn_getMSTime();
  uint32_t stime = current_time;
  reset_load_generator_rate_stats();

  memset(buffer_to_send, 7, clmessage_length);

  client_event_base = turn_event_base_new();

  /* Auto-scale listener thread count based on the requested concurrency
   * unless the user explicitly set -K. The single-threaded default keeps
   * -m 1 cheap (no context-switch overhead from a worker thread that
   * would have nothing to share); from -m UCLIENT_AUTO_LISTENERS_THRESHOLD
   * upward the recv path becomes the bottleneck, so we bump to
   * UCLIENT_AUTO_LISTENERS_TARGET. Cap is enforced at the user-facing
   * argument layer (UCLIENT_MAX_LISTENER_THREADS). */
  if (!num_listener_threads_explicit && mclient >= UCLIENT_AUTO_LISTENERS_THRESHOLD &&
      num_listener_threads < UCLIENT_AUTO_LISTENERS_TARGET) {
    num_listener_threads = UCLIENT_AUTO_LISTENERS_TARGET;
  }

  /* Start the listener thread pool BEFORE any session creation. Each new
   * session's recv events will be registered against the assigned
   * listener's event_base via pick_listener_base() inside start_client /
   * start_c2c. The pool runs concurrently with the main thread for the
   * lifetime of the test. */
  if (start_listener_threads() < 0) {
    /* Falling back to legacy single-threaded model is safer than aborting
     * a load test; pick_listener_base() returns client_event_base when
     * num_listener_threads is 0 or listeners is NULL. */
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "uclient: listener pool init failed, falling back to single-threaded\n");
    num_listener_threads = 0;
  }

  /* Auto-scale sender thread count. Mirrors the listener auto-scale rule
   * but with a higher threshold (UCLIENT_AUTO_SENDERS_THRESHOLD): at low
   * -m the single sender on main is cheaper than waking a worker, while
   * at -m >= threshold the timer_handler iteration is the choke. */
  if (!num_sender_threads_explicit && mclient >= UCLIENT_AUTO_SENDERS_THRESHOLD &&
      num_sender_threads < UCLIENT_AUTO_SENDERS_TARGET) {
    num_sender_threads = UCLIENT_AUTO_SENDERS_TARGET;
  }

  /* Start the sender thread pool BEFORE start_full_timer is set so the
   * per-sender timers exist by the time iteration begins. Session
   * sender_id assignment happens during create_new_ss / per-session
   * setup (pick_sender_id), so the pool must be live at that point. */
  if (start_sender_threads() < 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "uclient: sender pool init failed, falling back to single-threaded\n");
    num_sender_threads = 0;
  }

  int tot_clients = 0;

  if (c2c) {
    if (!no_rtcp) {
      for (int i = 0; i < (mclient >> 2); i++) {
        if (!dos && !is_load_generator_mode()) {
          usleep(SLEEP_INTERVAL);
        }
        if (start_c2c(remote_address, port, ifname, local_address, messagenumber, i << 2) < 0) {
          exit(-1);
        }
        tot_clients += 4;
      }
    } else {
      for (int i = 0; i < (mclient >> 1); i++) {
        if (!dos && !is_load_generator_mode()) {
          usleep(SLEEP_INTERVAL);
        }
        if (start_c2c(remote_address, port, ifname, local_address, messagenumber, i << 1) < 0) {
          exit(-1);
        }
        tot_clients += 2;
      }
    }
  } else {
    if (!no_rtcp) {
      for (int i = 0; i < (mclient >> 1); i++) {
        if (!dos && !is_load_generator_mode()) {
          usleep(SLEEP_INTERVAL);
        }
        if (start_client(remote_address, port, ifname, local_address, messagenumber, i << 1) < 0) {
          exit(-1);
        }
        tot_clients += 2;
      }
    } else {
      for (int i = 0; i < mclient; i++) {
        if (!dos && !is_load_generator_mode()) {
          usleep(SLEEP_INTERVAL);
        }
        const int rc = is_invalid_flood_mode()
                           ? start_invalid_client(remote_address, port, ifname, local_address, messagenumber, i)
                           : start_client(remote_address, port, ifname, local_address, messagenumber, i);
        if (rc < 0) {
          exit(-1);
        }
        tot_clients++;
      }
    }
  }

  if (dos) {
    _exit(0);
  }

  total_clients = tot_clients;

  __turn_getMSTime();

  struct event *ev = event_new(client_event_base, -1, EV_TIMEOUT | EV_PERSIST, timer_handler, NULL);
  struct timeval tv;

  tv.tv_sec = 0;
  if (num_sender_threads > 0) {
    /* Per-sender timers own session iteration. Main thread's timer only
     * needs to refresh current_mstime for lifecycle code that runs there,
     * so a slow cadence is enough and avoids burning a core on no-op
     * wake-ups. */
    tv.tv_usec = 10000; /* 10 ms */
  } else {
    tv.tv_usec = (is_packet_flood_mode() || is_invalid_flood_mode()) ? 100 : 1000;
  }

  evtimer_add(ev, &tv);

  for (int i = 0; i < total_clients; i++) {

    if (is_TCP_relay()) {
      if (passive_tcp) {
        if (elems && elems[i]->pinfo.is_peer) {
          int connect_err = 0;
          socket_connect(elems[i]->pinfo.fd, &(elems[i]->pinfo.remote_addr), &connect_err);
        }
      } else {
        for (int j = i + 1; j < total_clients; j++) {
          if (turn_tcp_connect(clnet_verbose, &(elems[i]->pinfo), &(elems[j]->pinfo.relay_addr)) < 0) {
            exit(-1);
          }
        }
      }
    }
    run_events(1);
  }

  __turn_getMSTime();

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total connect time is %u\n", ((unsigned int)(current_time - stime)));

  stime = current_time;

  if (is_TCP_relay()) {
    uint64_t connect_wait_start_time = current_time;
    while (1) {
      int completed = 0;
      if (passive_tcp) {
        for (int i = 0; i < total_clients; ++i) {
          if (elems[i]->pinfo.is_peer) {
            completed += 1;
          } else if (elems[i]->pinfo.tcp_conn_number > 0 && elems[i]->pinfo.tcp_conn[0]->tcp_data_bound) {
            completed += elems[i]->pinfo.tcp_conn_number;
          }
        }
        if (completed >= total_clients) {
          break;
        }
      } else {
        for (int i = 0; i < total_clients; ++i) {
          for (int j = 0; j < (int)elems[i]->pinfo.tcp_conn_number; j++) {
            if (elems[i]->pinfo.tcp_conn[j]->tcp_data_bound) {
              completed++;
            }
          }
        }
        if (completed >= total_clients * (total_clients - 1)) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%d connections are completed\n", (int)(completed));
          break;
        }
      }
      run_events(0);
      if (current_time > connect_wait_start_time + STARTING_TCP_RELAY_TIME + total_clients) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: %d connections are completed, not enough\n", (int)(completed));
        break;
      }
    }
  }

  __turn_getMSTime();
  stime = current_time;

  for (int i = 0; i < total_clients; i++) {
    if (is_packet_flood_mode() || is_invalid_flood_mode()) {
      elems[i]->to_send_timems = current_mstime;
    } else {
      elems[i]->to_send_timems = current_mstime + 1000 + ((uint32_t)turn_random_number()) % 5000;
    }
  }

  tot_messages = elems[0]->tot_msgnum * total_clients;

  start_full_timer = true;

  while (true) {

    run_events(1);

    int msz = (int)current_clients_number;
    if (msz < 1) {
      break;
    }

    if (show_statistics) {
      print_load_generator_rate(__FUNCTION__);
      /* Snapshot for the live progress print -- senders/listeners haven't joined yet. */
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
                    "%s: msz=%d, tot_send_msgs=%lu, tot_recv_msgs=%lu, tot_send_bytes ~ %llu, tot_recv_bytes ~ %llu\n",
                    __FUNCTION__, msz, (unsigned long)send_count_snapshot(), (unsigned long)recv_count_snapshot(),
                    (unsigned long long)send_bytes_snapshot(), (unsigned long long)recv_bytes_snapshot());
      show_statistics = false;
    }
  }

  __turn_getMSTime();
  print_load_generator_rate(__FUNCTION__);

  /* Quiesce sender threads BEFORE listener threads. The senders own the
   * session mutation side (wmsgnum, to_send_timems, finished flag,
   * shutdown). Joining them first prevents a race where a listener
   * thread accumulates a stat into a session whose owning sender is
   * still iterating it. stop_sender_threads() also folds the per-
   * sender slabs into the globals (tot_send_*, total_loss, etc.). */
  stop_sender_threads();

  /* Quiesce listener threads BEFORE freeing event bases or printing
   * totals: stop_listener_threads() reduces per-thread min/max latency/
   * jitter accumulators into the globals, and the event_base_free below
   * is illegal while a thread is still dispatching on it. */
  stop_listener_threads();

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: tot_send_msgs=%lu, tot_recv_msgs=%lu\n", __FUNCTION__,
                (unsigned long)tot_send_messages, (unsigned long)tot_recv_messages);

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: tot_send_bytes ~ %lu, tot_recv_bytes ~ %lu\n", __FUNCTION__,
                (unsigned long)tot_send_bytes, (unsigned long)tot_recv_bytes);

  if (client_event_base) {
    event_base_free(client_event_base);
  }

  if (tot_send_messages < tot_recv_messages) {
    tot_recv_messages = tot_send_messages;
  }

  total_loss = tot_send_messages - tot_recv_messages;

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total transmit time is %u\n", ((unsigned int)(current_time - stime)));
  if (is_invalid_flood_mode()) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total send dropped %llu (%f%c)\n", (unsigned long long)tot_send_dropped,
                  (((double)tot_send_dropped /
                    (double)((tot_send_messages + tot_send_dropped) ? (tot_send_messages + tot_send_dropped) : 1)) *
                   100.00),
                  '%');
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total lost packets %llu (%f%c), total send dropped %llu (%f%c)\n",
                  (unsigned long long)total_loss,
                  (((double)total_loss / (double)(tot_send_messages ? tot_send_messages : 1)) * 100.00), '%',
                  (unsigned long long)tot_send_dropped,
                  (((double)tot_send_dropped /
                    (double)((tot_send_messages + tot_send_dropped) ? (tot_send_messages + tot_send_dropped) : 1)) *
                   100.00),
                  '%');
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Average round trip delay %f ms; min = %lu ms, max = %lu ms\n",
                  ((double)total_latency / (double)((tot_recv_messages < 1) ? 1 : tot_recv_messages)),
                  (unsigned long)min_latency, (unsigned long)max_latency);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Average jitter %f ms; min = %lu ms, max = %lu ms\n",
                  ((double)total_jitter / (double)((tot_recv_messages < 1) ? 1 : tot_recv_messages)),
                  (unsigned long)min_jitter, (unsigned long)max_jitter);
  }

  free(elems);
}

///////////////////////////////////////////

turn_credential_type get_turn_credentials_type(void) { return TURN_CREDENTIALS_LONG_TERM; }

int add_integrity(app_ur_conn_info *clnet_info, stun_buffer *message) {
  if (clnet_info->nonce[0]) {

    if (oauth && clnet_info->oauth) {

      uint16_t method = stun_get_method_str(message->buf, message->len);

      int cok = clnet_info->cok;

      if (((method == STUN_METHOD_ALLOCATE) || (method == STUN_METHOD_REFRESH)) || !(clnet_info->key_set)) {

        cok = ((unsigned short)turn_random_number()) % 3;
        clnet_info->cok = cok;
        oauth_token otoken;
        encoded_oauth_token etoken;
        uint8_t nonce[12];
        RAND_bytes((unsigned char *)nonce, 12);
        long halflifetime = OAUTH_SESSION_LIFETIME / 2;
        long random_lifetime = 0;
        while (!random_lifetime) {
          random_lifetime = turn_random_number();
        }
        if (random_lifetime < 0) {
          random_lifetime = -random_lifetime;
        }
        random_lifetime = random_lifetime % halflifetime;
        otoken.enc_block.lifetime = (uint32_t)(halflifetime + random_lifetime);
        otoken.enc_block.timestamp = ((uint64_t)turn_time()) << 16;
        if (shatype == SHATYPE_SHA256) {
          otoken.enc_block.key_length = 32;
        } else if (shatype == SHATYPE_SHA384) {
          otoken.enc_block.key_length = 48;
        } else if (shatype == SHATYPE_SHA512) {
          otoken.enc_block.key_length = 64;
        } else {
          otoken.enc_block.key_length = 20;
        }
        RAND_bytes((unsigned char *)(otoken.enc_block.mac_key), otoken.enc_block.key_length);
        if (!encode_oauth_token(clnet_info->server_name, &etoken, &(okey_array[cok]), &otoken, nonce)) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, " Cannot encode token\n");
          return -1;
        }
        stun_attr_add_str(message->buf, &(message->len), STUN_ATTRIBUTE_OAUTH_ACCESS_TOKEN,
                          (const uint8_t *)etoken.token, (int)etoken.size);

        memcpy(clnet_info->key, otoken.enc_block.mac_key, otoken.enc_block.key_length);
        clnet_info->key_set = true;
      }

      if (!stun_attr_add_integrity_by_key_str(message->buf, &(message->len), (uint8_t *)okey_array[cok].kid,
                                              clnet_info->realm, clnet_info->key, clnet_info->nonce, shatype)) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, " Cannot add integrity to the message\n");
        return -1;
      }

      // self-test:
      {
        password_t pwd;
        if (stun_check_message_integrity_by_key_str(get_turn_credentials_type(), message->buf, message->len,
                                                    clnet_info->key, pwd, shatype) < 1) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, " Self-test of integrity does not comple correctly !\n");
          return -1;
        }
      }
    } else {
      if (!stun_attr_add_integrity_by_user_str(message->buf, (size_t *)&(message->len), g_uname, clnet_info->realm,
                                               g_upwd, clnet_info->nonce, shatype)) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, " Cannot add integrity to the message\n");
        return -1;
      }
    }
  }

  return 0;
}

int check_integrity(app_ur_conn_info *clnet_info, stun_buffer *message) {
  SHATYPE sht = shatype;

  if (oauth && clnet_info->oauth) {

    password_t pwd;

    return stun_check_message_integrity_by_key_str(get_turn_credentials_type(), message->buf, (size_t)(message->len),
                                                   clnet_info->key, pwd, sht);

  } else {

    if (stun_check_message_integrity_str(get_turn_credentials_type(), message->buf, (size_t)(message->len), g_uname,
                                         clnet_info->realm, g_upwd, sht) < 1) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Wrong integrity in a message received from server\n");
      return -1;
    }
  }

  return 0;
}

SOCKET_TYPE get_socket_type(void) {
  if (use_sctp) {
    if (use_secure) {
      return TLS_SCTP_SOCKET;
    } else {
      return SCTP_SOCKET;
    }
  } else if (use_tcp) {
    if (use_secure) {
      return TLS_SOCKET;
    } else {
      return TCP_SOCKET;
    }
  } else {
    if (use_secure) {
      return DTLS_SOCKET;
    } else {
      return UDP_SOCKET;
    }
  }
}
///////////////////////////////////////////
