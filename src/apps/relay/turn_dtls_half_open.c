/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Concurrent DTLS handshakes that have not finished yet.
 * Per-source table stops one host from taking every global slot by rotating
 * UDP source ports.
 */

#include "turn_dtls_half_open.h"

#include "ns_turn_atomic.h"

#include <string.h>

static turn_atomic_u32 turn_dtls_half_open = 0;

#define TURN_DTLS_HALF_OPEN_SRC_BUCKETS 1024u
#define TURN_DTLS_HALF_OPEN_SRC_MASK (TURN_DTLS_HALF_OPEN_SRC_BUCKETS - 1u)

typedef struct {
  turn_atomic_u32 tag;   /* non-zero hash of source IP (/64 for v6); 0 = empty */
  turn_atomic_u32 count; /* concurrent half-open handshakes for this tag */
} turn_dtls_half_open_src_bucket;

static turn_dtls_half_open_src_bucket turn_dtls_half_open_src[TURN_DTLS_HALF_OPEN_SRC_BUCKETS];

/* Hash IPv4 fully; IPv6 by /64 so one network cannot rotate host IDs either. */
static uint32_t turn_dtls_half_open_src_tag(const ioa_addr *src) {
  uint32_t h = 0;
  if (!src) {
    return 1u;
  }
  if (src->ss.sa_family == AF_INET6) {
    const uint8_t *b = (const uint8_t *)&src->s6.sin6_addr;
    h = 2166136261u;
    for (int i = 0; i < 8; i++) {
      h ^= b[i];
      h *= 16777619u;
    }
  } else {
    h = (uint32_t)src->s4.sin_addr.s_addr;
    h ^= h >> 16;
    h *= 0x7feb352du;
    h ^= h >> 15;
    h *= 0x846ca68bu;
    h ^= h >> 16;
  }
  return h ? h : 1u;
}

static bool turn_dtls_half_open_src_try_inc(const ioa_addr *src) {
  const uint32_t tag = turn_dtls_half_open_src_tag(src);
  turn_dtls_half_open_src_bucket *b = &turn_dtls_half_open_src[tag & TURN_DTLS_HALF_OPEN_SRC_MASK];
  for (;;) {
    const uint32_t cur_tag = turn_atomic_load_u32(&b->tag);
    const uint32_t cur = turn_atomic_load_u32(&b->count);

    if (cur == 0) {
      /* Empty or stale: claim the bucket for this source. */
      if (cur_tag != 0 && !turn_atomic_cas_u32(&b->tag, cur_tag, tag)) {
        continue;
      }
      if (cur_tag == 0 && !turn_atomic_cas_u32(&b->tag, 0, tag)) {
        continue;
      }
      if (turn_atomic_cas_u32(&b->count, 0, 1)) {
        return true;
      }
      continue;
    }

    if (cur >= TURN_DTLS_HALF_OPEN_PER_SOURCE) {
      return false;
    }

    /* Same tag, or a live collision: share the existing budget. */
    if (turn_atomic_cas_u32(&b->count, cur, cur + 1)) {
      return true;
    }
  }
}

static void turn_dtls_half_open_src_dec(const ioa_addr *src) {
  turn_dtls_half_open_src_bucket *b =
      &turn_dtls_half_open_src[turn_dtls_half_open_src_tag(src) & TURN_DTLS_HALF_OPEN_SRC_MASK];
  for (;;) {
    const uint32_t cur = turn_atomic_load_u32(&b->count);
    if (cur == 0) {
      return;
    }
    if (turn_atomic_cas_u32(&b->count, cur, cur - 1)) {
      if (cur == 1) {
        turn_atomic_store_u32(&b->tag, 0);
      }
      return;
    }
  }
}

bool turn_dtls_half_open_try_inc(uint32_t global_cap, const ioa_addr *src) {
  if (!turn_dtls_half_open_src_try_inc(src)) {
    return false;
  }
  for (;;) {
    const uint32_t cur = turn_atomic_load_u32(&turn_dtls_half_open);
    if (cur >= global_cap) {
      turn_dtls_half_open_src_dec(src);
      return false;
    }
    if (turn_atomic_cas_u32(&turn_dtls_half_open, cur, cur + 1)) {
      return true;
    }
  }
}

void turn_dtls_half_open_dec(const ioa_addr *src) {
  turn_dtls_half_open_src_dec(src);
  for (;;) {
    const uint32_t cur = turn_atomic_load_u32(&turn_dtls_half_open);
    if (cur == 0) {
      return;
    }
    if (turn_atomic_cas_u32(&turn_dtls_half_open, cur, cur - 1)) {
      return;
    }
  }
}

uint32_t turn_dtls_half_open_count(void) { return turn_atomic_load_u32(&turn_dtls_half_open); }

void turn_dtls_half_open_reset(void) {
  turn_atomic_store_u32(&turn_dtls_half_open, 0);
  memset(turn_dtls_half_open_src, 0, sizeof(turn_dtls_half_open_src));
}
