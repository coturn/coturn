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

#ifndef __TURN_RATE_LIMIT__
#define __TURN_RATE_LIMIT__

#include <stdbool.h>
#include <stdint.h>

#include "ns_turn_ioaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Default for the unauthorized rate-limit feature. The PR opts in via
 * --unauthorized-ratelimit; once enabled, --unauthorized-ratelimit-rps
 * tunes the per-second response threshold. */
#define RATELIMIT_DEFAULT_MAX_REQUESTS_PER_SEC 10u

/*
 * Lock-free per-source-IP rate-limit, designed for the unauthorized-response
 * reflection attack mitigation in handle_turn_command.
 *
 * Design:
 *  - Fixed-size table of buckets (no malloc/free on the hot path).
 *  - Each bucket holds a 32-bit tag derived from the source address,
 *    the start of the current window, and a counter — all atomics.
 *  - Direct-mapped hash: bucket = hash(addr_without_port) & MASK.
 *  - An address colliding with a live bucket shares its response budget
 *    until the window expires; it does not replace the current tag or
 *    receive a fresh allowance.
 *  - No global mutex, no list scan, no UAF surface: the address never
 *    appears as a pointer, only as a tag.
 *
 * Caveats:
 *  - Hash collisions cause two unrelated addresses to share a bucket;
 *    this can suppress a colliding legitimate source when the shared
 *    budget is exhausted, but cannot expand reflection output.
 *  - The port is stripped from the key, so attackers cannot evade by
 *    rotating the source port.
 */

/* Reset the rate-limit table. Called once at server startup. Safe to
 * call multiple times; safe to skip (the table is zero-initialized at
 * load time). */
void ratelimit_init(void);

/* Atomic bump. `max_requests_per_sec` is the allowed number of responses
 * per source per second (the rate limit operates on a fixed 1-second
 * window). Returns true if THIS request is OVER the limit, i.e. the caller
 * should suppress the unauthorized response. The out parameter `first_drop`
 * is set to true exactly once per (bucket, window) pair. `first_collision`
 * is set to true exactly once when a live bucket is first shared by a
 * colliding address during a window. Either may be NULL. */
bool ratelimit_consume_address(const ioa_addr *address, uint32_t max_requests_per_sec, bool *first_drop,
                               bool *first_collision);

/* Telemetry accessors. All are cheap, read-only, and meant to be polled by the
 * metrics exporter at scrape time — never from the data path.
 *
 * ratelimit_get_collisions(): monotonic count of hash-bucket collisions since
 *   startup (wraps at 2^32; recover the increment with unsigned subtraction).
 * ratelimit_get_capacity(): the fixed number of buckets in the table.
 * ratelimit_count_occupied(): number of buckets currently holding a live,
 *   non-expired (1-second) window. Scans the whole table, so call it at most
 *   once per scrape. */
uint32_t ratelimit_get_collisions(void);
uint32_t ratelimit_get_capacity(void);
uint32_t ratelimit_count_occupied(void);

#ifdef __cplusplus
}
#endif

#endif //__TURN_RATE_LIMIT__
