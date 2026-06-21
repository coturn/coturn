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

#include "ns_turn_ratelimit.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "ns_turn_atomic.h" // for turn_atomic_* portable atomics
#include "ns_turn_defs.h"   // for turn_time_t / turn_time()

/* Power-of-two bucket count. 4096 buckets * 20 B/bucket = ~80 KiB resident.
 * Increasing this lowers hash-collision probability for legit traffic. Live
 * collisions share the existing budget so they cannot expand 401 output. */
#define RATELIMIT_BUCKETS 4096u
#define RATELIMIT_MASK (RATELIMIT_BUCKETS - 1u)

/* The limit is expressed per second, so the window is a fixed 1 second. */
#define RATELIMIT_WINDOW_SECS 1u

typedef struct {
  turn_atomic_u32 tag;              /* hash of source IP (port stripped); 0 = empty */
  turn_atomic_u32 window_start;     /* turn_time() value when the current window opened */
  turn_atomic_u32 count;            /* requests counted in this window */
  turn_atomic_u32 logged;           /* 1 once we've logged a drop in this window */
  turn_atomic_u32 collision_logged; /* 1 once we've logged a collision in this window */
} ratelimit_bucket;

static ratelimit_bucket ratelimit_table[RATELIMIT_BUCKETS];

/* Monotonic count of hash-bucket collisions: requests whose source hashed to
 * a bucket currently owned by a different address. A single global atomic,
 * touched only on the (rare) collision branch of the 401 path, so it adds no
 * cost to the common case. Read at scrape time via ratelimit_get_collisions().
 * Wraps at 2^32; the exporter recovers the increment via unsigned subtraction. */
static turn_atomic_u32 ratelimit_collisions;

/* 32-bit hash over the address bytes, ignoring port. Returns a value
 * != 0 so we can reserve 0 as the "empty bucket" tag. */
static uint32_t ratelimit_hash(const ioa_addr *a) {
  uint32_t h;
  if (a->ss.sa_family == AF_INET6) {
    /* FNV-1a 32-bit over the 16-byte v6 address. */
    const uint8_t *b = (const uint8_t *)&a->s6.sin6_addr;
    h = 2166136261u;
    for (int i = 0; i < 16; i++) {
      h ^= b[i];
      h *= 16777619u;
    }
  } else {
    /* splitmix-style finalizer on the 32-bit v4 address. */
    h = (uint32_t)a->s4.sin_addr.s_addr;
    h ^= h >> 16;
    h *= 0x7feb352du;
    h ^= h >> 15;
    h *= 0x846ca68bu;
    h ^= h >> 16;
  }
  return h ? h : 1u;
}

void ratelimit_init(void) {
  /* Static storage is zero-initialized; this is here so the symbol
   * exists for callers and the intent is explicit. */
  memset(ratelimit_table, 0, sizeof(ratelimit_table));
  turn_atomic_store_u32(&ratelimit_collisions, 0u);
}

bool ratelimit_consume_address(const ioa_addr *address, uint32_t max_requests_per_sec, bool *first_drop,
                               bool *first_collision) {
  if (first_drop) {
    *first_drop = false;
  }
  if (first_collision) {
    *first_collision = false;
  }
  if (!address || max_requests_per_sec == 0) {
    return false;
  }

  const uint32_t h = ratelimit_hash(address);
  ratelimit_bucket *b = &ratelimit_table[h & RATELIMIT_MASK];
  const uint32_t now = (uint32_t)turn_time();

  const uint32_t tag = turn_atomic_load_u32(&b->tag);
  const uint32_t ws = turn_atomic_load_u32(&b->window_start);

  if (tag == 0u || (now - ws) >= RATELIMIT_WINDOW_SECS) {
    /* Empty bucket or expired window: establish a fresh owner.
     * Two concurrent resets are fine: the second one wins, and both
     * see count == 1 by the time the store on the tag lands. */
    turn_atomic_store_u32(&b->window_start, now);
    turn_atomic_store_u32(&b->logged, 0u);
    turn_atomic_store_u32(&b->collision_logged, 0u);
    turn_atomic_store_u32(&b->count, 1u);
    turn_atomic_store_u32(&b->tag, h);
    return false;
  }

  if (tag != h) {
    /* A colliding source landed on a live bucket owned by another address.
     * Count every collision for telemetry; the diagnostic log line is still
     * latched to once per (bucket, window) via collision_logged. */
    turn_atomic_fetch_add_u32(&ratelimit_collisions, 1u);
    if (first_collision && turn_atomic_cas_u32(&b->collision_logged, 0u, 1u)) {
      *first_collision = true;
    }
  }

  /* A live collision uses the existing bucket budget. Replacing the owner
   * here would let alternating colliders repeatedly obtain a fresh allowance. */
  /* fetch_add returns the value BEFORE the increment, so prev == max
   * means this request is exactly the (max+1)-th in the window — the
   * first that crosses the threshold. */
  const uint32_t prev = turn_atomic_fetch_add_u32(&b->count, 1u);
  if (prev < max_requests_per_sec) {
    return false;
  }

  if (first_drop) {
    /* Emit a single log line per (bucket, window) by CAS'ing the
     * `logged` flag from 0 to 1. Subsequent drops in the same window
     * silently increment the counter but don't log. */
    if (turn_atomic_cas_u32(&b->logged, 0u, 1u)) {
      *first_drop = true;
    }
  }
  return true;
}

uint32_t ratelimit_get_collisions(void) { return turn_atomic_load_u32(&ratelimit_collisions); }

uint32_t ratelimit_get_capacity(void) { return RATELIMIT_BUCKETS; }

uint32_t ratelimit_count_occupied(void) {
  /* Whole-table scan: cheap (one pass over RATELIMIT_BUCKETS atomic loads) and
   * intended to run only at metrics-scrape time, never on the data path. A
   * bucket counts as occupied when it holds a tag and its window has not yet
   * expired, mirroring the liveness test in ratelimit_consume_address(). */
  const uint32_t now = (uint32_t)turn_time();
  uint32_t occupied = 0u;
  for (uint32_t i = 0; i < RATELIMIT_BUCKETS; i++) {
    ratelimit_bucket *b = &ratelimit_table[i];
    if (turn_atomic_load_u32(&b->tag) != 0u && (now - turn_atomic_load_u32(&b->window_start)) < RATELIMIT_WINDOW_SECS) {
      occupied++;
    }
  }
  return occupied;
}
