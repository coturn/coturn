/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2011, 2012, 2013, 2014 Citrix Systems
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

#include "mp_peer_table.h"

#include "ns_turn_utils.h"

/* An ioa_addr is 128 bytes, and the common allocation registers its peer's
 * RTP and RTCP endpoints and nothing else. */
#define MP_SESSION_PEERS_INITIAL_CAPACITY (2)

/* The demux-table endpoints one session owns. */
typedef struct {
  ioa_addr *keys;
  size_t n;
  size_t capacity;
  bool limit_logged;
} mp_session_peers;

static size_t mp_limit(const mp_peer_table *t) {
  return t->max_per_session ? t->max_per_session : TURN_MP_PEERS_PER_SESSION_DEFAULT;
}

static ur_map_key_type mp_session_key(void *session) { return (ur_map_key_type)(uintptr_t)session; }

static void mp_session_peers_free(ur_map_value_type value) {
  mp_session_peers *sp = (mp_session_peers *)value;
  if (!sp) {
    return;
  }
  free(sp->keys);
  free(sp);
}

static mp_session_peers *mp_session_peers_get(mp_peer_table *t, void *session, bool create) {
  if (!t->sessions) {
    if (!create) {
      return NULL;
    }
    t->sessions = ur_map_create();
  }

  ur_map_value_type value = NULL;
  if (ur_map_get(t->sessions, mp_session_key(session), &value) && value) {
    return (mp_session_peers *)value;
  }

  if (!create) {
    return NULL;
  }

  mp_session_peers *sp = (mp_session_peers *)turn_calloc(1, sizeof(mp_session_peers));
  ur_map_put(t->sessions, mp_session_key(session), (ur_map_value_type)sp);
  return sp;
}

static void mp_session_peers_drop_if_empty(mp_peer_table *t, void *session, mp_session_peers *sp) {
  if (sp->n == 0) {
    ur_map_del(t->sessions, mp_session_key(session), mp_session_peers_free);
  }
}

/* Removes index slot i without preserving order; the caller owns the map entry. */
static void mp_session_peers_remove_at(mp_session_peers *sp, size_t i) {
  if (i + 1 < sp->n) {
    addr_cpy(&(sp->keys[i]), &(sp->keys[sp->n - 1]));
  }
  sp->n -= 1;
}

static void mp_session_peers_append(mp_session_peers *sp, const ioa_addr *key, size_t limit) {
  if (sp->n == sp->capacity) {
    size_t capacity = sp->capacity ? sp->capacity * 2 : MP_SESSION_PEERS_INITIAL_CAPACITY;
    if (capacity > limit) {
      capacity = limit;
    }
    sp->keys = (ioa_addr *)turn_realloc(sp->keys, capacity * sizeof(ioa_addr));
    sp->capacity = capacity;
  }
  addr_cpy(&(sp->keys[sp->n]), key);
  sp->n += 1;
}

void mp_peer_table_init(mp_peer_table *t, size_t max_per_session) {
  if (!t) {
    return;
  }
  memset(t, 0, sizeof(mp_peer_table));
  ur_addr_map_init(&(t->map));
  t->max_per_session = max_per_session;
}

/* ur_map_free() does not touch values, so the indexes are freed first. */
static bool mp_session_peers_free_cb(ur_map_key_type key, ur_map_value_type value, void *arg) {
  UNUSED_ARG(key);
  UNUSED_ARG(arg);
  mp_session_peers_free(value);
  return false;
}

void mp_peer_table_clean(mp_peer_table *t) {
  if (!t) {
    return;
  }
  if (t->sessions) {
    ur_map_foreach_arg(t->sessions, mp_session_peers_free_cb, NULL);
    ur_map_free(&(t->sessions));
  }
  ur_addr_map_clean(&(t->map));
  t->count = 0;
}

int mp_peer_table_register(mp_peer_table *t, const ioa_addr *peer_addr, void *session) {
  if (!t || !peer_addr || !session) {
    return MP_REGISTER_CONFLICT;
  }

  ioa_addr key = {0};
  addr_cpy(&key, peer_addr);

  ur_addr_map_value_type existing = NULL;
  if (ur_addr_map_get(&(t->map), &key, &existing) && existing) {
    return (existing == (ur_addr_map_value_type)session) ? MP_REGISTER_OK : MP_REGISTER_CONFLICT;
  }

  const size_t limit = mp_limit(t);
  mp_session_peers *sp = mp_session_peers_get(t, session, true);
  if (sp->n >= limit) {
    if (!sp->limit_logged) {
      sp->limit_logged = true;
      char saddr[MAX_IOA_ADDR_STRING] = {0};
      addr_to_string(peer_addr, saddr);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                    "multiplex-peer: allocation reached its %lu peer-endpoint limit (at %s); "
                    "further endpoints are rejected\n",
                    (unsigned long)limit, saddr);
    }
    return MP_REGISTER_LIMIT;
  }

  if (!ur_addr_map_put(&(t->map), &key, (ur_addr_map_value_type)session)) {
    mp_session_peers_drop_if_empty(t, session, sp);
    return MP_REGISTER_CONFLICT;
  }

  mp_session_peers_append(sp, &key, limit);
  t->count += 1;
  return MP_REGISTER_OK;
}

void *mp_peer_table_lookup(mp_peer_table *t, const ioa_addr *peer_addr) {
  if (!t || !peer_addr) {
    return NULL;
  }
  ioa_addr key = {0};
  addr_cpy(&key, peer_addr);
  ur_addr_map_value_type value = NULL;
  if (!ur_addr_map_get(&(t->map), &key, &value)) {
    return NULL;
  }
  return (void *)value;
}

void mp_peer_table_deregister(mp_peer_table *t, const ioa_addr *peer_addr, void *session) {
  if (!t || !peer_addr || !session) {
    return;
  }

  mp_session_peers *sp = mp_session_peers_get(t, session, false);
  if (!sp) {
    return;
  }

  for (size_t i = 0; i < sp->n; ++i) {
    t->deregister_ops += 1;
    if (!addr_eq(&(sp->keys[i]), peer_addr)) {
      continue;
    }
    ioa_addr key = {0};
    addr_cpy(&key, &(sp->keys[i]));
    ur_addr_map_del(&(t->map), &key, NULL);
    mp_session_peers_remove_at(sp, i);
    t->count -= 1;
    break;
  }

  mp_session_peers_drop_if_empty(t, session, sp);
}

/* peer_addr NULL matches every endpoint of the session, otherwise every
 * endpoint on that peer IP. */
static void mp_peer_table_deregister_matching(mp_peer_table *t, void *session, const ioa_addr *peer_addr,
                                              int address_family) {
  mp_session_peers *sp = mp_session_peers_get(t, session, false);
  if (!sp) {
    return;
  }

  size_t i = 0;
  while (i < sp->n) {
    t->deregister_ops += 1;
    const ioa_addr *key = &(sp->keys[i]);
    if ((address_family && key->ss.sa_family != address_family) || (peer_addr && !addr_eq_no_port(key, peer_addr))) {
      ++i;
      continue;
    }
    ioa_addr key_copy = {0};
    addr_cpy(&key_copy, key);
    ur_addr_map_del(&(t->map), &key_copy, NULL);
    mp_session_peers_remove_at(sp, i);
    t->count -= 1;
  }

  mp_session_peers_drop_if_empty(t, session, sp);
}

void mp_peer_table_deregister_ip(mp_peer_table *t, const ioa_addr *peer_addr, void *session) {
  if (!t || !peer_addr || !session) {
    return;
  }
  mp_peer_table_deregister_matching(t, session, peer_addr, 0);
}

void mp_peer_table_deregister_session(mp_peer_table *t, void *session, int address_family) {
  if (!t || !session) {
    return;
  }
  mp_peer_table_deregister_matching(t, session, NULL, address_family);
}

size_t mp_peer_table_count(const mp_peer_table *t) { return t ? t->count : 0; }

size_t mp_peer_table_session_count(mp_peer_table *t, void *session) {
  if (!t || !session) {
    return 0;
  }
  mp_session_peers *sp = mp_session_peers_get(t, session, false);
  return sp ? sp->n : 0;
}
