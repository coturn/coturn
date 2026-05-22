/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2024 Wire Swiss GmbH
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

#ifndef __TURN_ATOMIC__
#define __TURN_ATOMIC__

/*
 * Portable atomic primitives.
 *
 * The TURN/STUN sources need a handful of lock-free counters and flags that
 * must compile on both POSIX toolchains (GCC/Clang, including MinGW) and
 * MSVC. C11 <stdatomic.h> covers the former, but MSVC has no usable C11
 * atomics on the toolsets we still build against: VS2019 (v142) lacks the
 * header entirely, and VS2022 (v143) gates it behind /experimental:c11atomics.
 *
 * This header is the single home for that compatibility split:
 *   - On MSVC, the operations lower onto the Interlocked intrinsics. Those
 *     carry full (sequentially-consistent) barriers.
 *   - Everywhere else, they map onto the non-explicit C11 atomic functions,
 *     which are likewise sequentially consistent.
 * Both sides therefore present the same ordering guarantee, so callers never
 * have to reason about per-platform memory-order differences.
 *
 * Gating is on _MSC_VER (the compiler), not the project's WINDOWS macro: only
 * MSVC lacks C11 atomics. MinGW is a GCC toolchain and uses the C11 path even
 * though WINDOWS is defined for it.
 *
 * Only the widths/operations that current callers need are provided (32-bit
 * load/store/fetch_add/compare-exchange). Add more here when a caller needs
 * them rather than reintroducing a per-file shim.
 */

#include <stdbool.h>
#include <stdint.h>

#if defined(_MSC_VER)

#include <intrin.h>

/* unsigned 32-bit atomic; LONG-compatible storage for the Interlocked ops. */
typedef volatile long turn_atomic_u32;

static inline uint32_t turn_atomic_load_u32(turn_atomic_u32 *p) {
  /* CAS against 0->0 is a full-barrier atomic read of the current value. */
  return (uint32_t)_InterlockedCompareExchange(p, 0, 0);
}
static inline void turn_atomic_store_u32(turn_atomic_u32 *p, uint32_t v) { _InterlockedExchange(p, (long)v); }
static inline uint32_t turn_atomic_fetch_add_u32(turn_atomic_u32 *p, uint32_t v) {
  return (uint32_t)_InterlockedExchangeAdd(p, (long)v);
}
/* Strong compare-exchange: if *p == expected, set *p = desired and return
 * true; otherwise leave *p unchanged and return false. */
static inline bool turn_atomic_cas_u32(turn_atomic_u32 *p, uint32_t expected, uint32_t desired) {
  return (uint32_t)_InterlockedCompareExchange(p, (long)desired, (long)expected) == expected;
}

#else

#include <stdatomic.h>

typedef _Atomic uint32_t turn_atomic_u32;

static inline uint32_t turn_atomic_load_u32(turn_atomic_u32 *p) { return atomic_load(p); }
static inline void turn_atomic_store_u32(turn_atomic_u32 *p, uint32_t v) { atomic_store(p, v); }
static inline uint32_t turn_atomic_fetch_add_u32(turn_atomic_u32 *p, uint32_t v) { return atomic_fetch_add(p, v); }
static inline bool turn_atomic_cas_u32(turn_atomic_u32 *p, uint32_t expected, uint32_t desired) {
  return atomic_compare_exchange_strong(p, &expected, desired);
}

#endif

#endif //__TURN_ATOMIC__
