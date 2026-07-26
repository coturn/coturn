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

#ifndef __TURN_MP_PEER_TABLE__
#define __TURN_MP_PEER_TABLE__

#include "ns_turn_ioaddr.h"
#include "ns_turn_maps.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////

/* Distinct peer endpoints one allocation may keep in the demux table. */
#define TURN_MP_PEERS_PER_SESSION_DEFAULT (256)
#define TURN_MP_PEERS_PER_SESSION_MAX (65535)

/* mp_peer_table_register() results. */
#define MP_REGISTER_OK (0)
#define MP_REGISTER_CONFLICT (-1) /* endpoint already owned by another session */
#define MP_REGISTER_LIMIT (-2)    /* per-session endpoint limit reached */

//////////////////////////////////////////////////

/* One table per relay thread, shared by every session on it. The reverse index
 * keeps deregistration proportional to one session's endpoints. */
typedef struct {
  ur_addr_map map;         /* peer IP:port -> session */
  ur_map *sessions;        /* session -> mp_session_peers */
  size_t max_per_session;  /* 0 means TURN_MP_PEERS_PER_SESSION_DEFAULT */
  size_t count;            /* endpoints currently registered */
  uint64_t deregister_ops; /* index entries examined by deregistration; asserted by tests */
} mp_peer_table;

//////////////////////////////////////////////////

void mp_peer_table_init(mp_peer_table *t, size_t max_per_session);
void mp_peer_table_clean(mp_peer_table *t);

/* Returns MP_REGISTER_OK, MP_REGISTER_CONFLICT or MP_REGISTER_LIMIT. */
int mp_peer_table_register(mp_peer_table *t, const ioa_addr *peer_addr, void *session);

void *mp_peer_table_lookup(mp_peer_table *t, const ioa_addr *peer_addr);

void mp_peer_table_deregister(mp_peer_table *t, const ioa_addr *peer_addr, void *session);
/* Drops every endpoint of `session` on `peer_addr`'s IP, any port. */
void mp_peer_table_deregister_ip(mp_peer_table *t, const ioa_addr *peer_addr, void *session);
/* Drops every endpoint of `session`; address_family 0 means all families. */
void mp_peer_table_deregister_session(mp_peer_table *t, void *session, int address_family);

size_t mp_peer_table_count(const mp_peer_table *t);
size_t mp_peer_table_session_count(mp_peer_table *t, void *session);

//////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_MP_PEER_TABLE__
