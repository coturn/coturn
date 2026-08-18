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

#ifndef __TURN_SESSION__
#define __TURN_SESSION__

#include "ns_turn_allocation.h"
#include "ns_turn_ioalib.h"
#include "ns_turn_maps.h"
#include "ns_turn_utils.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

////////// REALM ////////////

typedef struct _perf_options_t {

  volatile band_limit_t max_bps;
  vint total_quota;
  vint user_quota;

} perf_options_t;

struct _realm_options_t {

  char name[STUN_MAX_REALM_SIZE + 1];

  perf_options_t perf_options;
};

//////////////// session info //////////////////////

typedef uint64_t turnsession_id;

/* The legacy random challenge nonce: 16 lowercase hex chars. */
#define TURN_RANDOM_NONCE_LENGTH (NONCE_LENGTH_32BITS * 4)
#define TURN_RANDOM_NONCE_SIZE (TURN_RANDOM_NONCE_LENGTH + 1)

/* Big enough for both nonce formats the server can issue: the legacy random
 * nonce (TURN_RANDOM_NONCE_LENGTH = 16 chars) and the stateless
 * timestamp||MAC nonce (TURN_STATELESS_NONCE_LENGTH = 24 chars). The two
 * differ in length, so emitters must use strlen(), not NONCE_MAX_SIZE - 1, and
 * a generator must bound itself with its own format's size - bounding the
 * random nonce with NONCE_MAX_SIZE widens it to 24 chars. */
#define NONCE_MAX_SIZE (TURN_STATELESS_NONCE_SIZE)

typedef uint64_t mobile_id_t;

/* Outcome of a user-key lookup, reported through get_username_resume_cb so the
 * 401 log line can name the actual cause instead of a generic "not found". */
typedef enum {
  TURN_KEY_LOOKUP_NOT_FOUND = 0,
  TURN_KEY_LOOKUP_OK,
  /* Time-limited username timestamp has passed; rejected before integrity verification. */
  TURN_KEY_LOOKUP_EXPIRED,
  /* Time-limited credentials matched no configured auth secret. */
  TURN_KEY_LOOKUP_INTEGRITY_MISMATCH,
} turn_key_lookup_result;

struct _ts_ur_super_session {
  void *server;
  turnsession_id id;
  turn_time_t start_time;
  ioa_socket_handle client_socket;
  allocation alloc;
  ioa_timer_handle to_be_allocated_timeout_ev;
  bool enforce_fingerprints;
  bool is_tcp_relay;
  bool to_be_closed;
  /* Stateless-nonce mode: this UDP session only exists to carry an auth
   * challenge (401/438) whose nonce can be recomputed later, so it is torn
   * down as soon as the challenge response has been written (issue #1999). */
  bool close_after_auth_challenge;
  /* Auth */
  uint8_t nonce[NONCE_MAX_SIZE];
  turn_time_t nonce_expiration_time;
  uint8_t username[STUN_MAX_USERNAME_SIZE + 1];
  hmackey_t hmackey;
  int hmackey_set;
  /* Why the last user-key lookup failed; consumed by the 401 log message. */
  turn_key_lookup_result key_lookup_result;
  password_t pwd;
  int quota_used;
  int oauth;
  turn_time_t max_session_time_auth;
  /* Realm */
  realm_options_t realm_options;
  int origin_set;
  char origin[STUN_MAX_ORIGIN_SIZE + 1];
  /* Stats */
  uint32_t received_packets;
  uint32_t sent_packets;
  uint32_t received_bytes;
  uint32_t sent_bytes;
  uint64_t t_received_packets;
  uint64_t t_sent_packets;
  uint64_t t_received_bytes;
  uint64_t t_sent_bytes;
  uint64_t received_rate;
  size_t sent_rate;
  size_t total_rate;
  uint32_t peer_received_packets;
  uint32_t peer_sent_packets;
  uint32_t peer_received_bytes;
  uint32_t peer_sent_bytes;
  uint32_t t_peer_received_packets;
  uint32_t t_peer_sent_packets;
  uint32_t t_peer_received_bytes;
  uint32_t t_peer_sent_bytes;
  uint64_t peer_received_rate;
  size_t peer_sent_rate;
  size_t peer_total_rate;
  /* Mobile */
  int is_mobile;
  mobile_id_t mobile_id;
  mobile_id_t old_mobile_id;
  char s_mobile_id[33];
  /* RFC 8016 mobility graceful handoff (dual-5-tuple transition state).
   * During a resume the allocation stays on the original session while the
   * resuming session (new client path) is kept alive and linked, so peer->client
   * traffic keeps flowing on the old 5-tuple until the client sends on the new
   * one (or a bounded deadline elapses). See docs/mobility-rfc8016.md. */
  turnsession_id mobile_resume_target;    /* resuming session -> allocation session id being resumed */
  turnsession_id mobile_pending_resume;   /* allocation session -> resuming session id */
  turn_time_t mobile_transition_deadline; /* allocation session: promote/abort by this time */
  /* Bandwidth */
  band_limit_t bps;
};

////// Session info for statistics //////

#define TURN_ADDR_STR_SIZE (64)
#define TURN_MAIN_PEERS_ARRAY_SIZE (5)

typedef struct _addr_data {
  ioa_addr addr;
  char saddr[TURN_ADDR_STR_SIZE];
} addr_data;

struct turn_session_info {
  turnsession_id id;
  int valid;
  turn_time_t start_time;
  turn_time_t expiration_time;
  SOCKET_TYPE client_protocol;
  SOCKET_TYPE peer_protocol;
  char tls_method[17];
  char tls_cipher[65];
  addr_data local_addr_data;
  addr_data remote_addr_data;
  addr_data relay_addr_data_ipv4;
  addr_data relay_addr_data_ipv6;
  uint8_t username[STUN_MAX_USERNAME_SIZE + 1];
  bool enforce_fingerprints;
  /* Stats */
  uint64_t received_packets;
  uint64_t sent_packets;
  uint64_t received_bytes;
  uint64_t sent_bytes;
  uint32_t received_rate;
  uint32_t sent_rate;
  uint32_t total_rate;
  uint64_t peer_received_packets;
  uint64_t peer_sent_packets;
  uint64_t peer_received_bytes;
  uint64_t peer_sent_bytes;
  uint32_t peer_received_rate;
  uint32_t peer_sent_rate;
  uint32_t peer_total_rate;
  /* Mobile */
  int is_mobile;
  /* Peers */
  addr_data main_peers_data[TURN_MAIN_PEERS_ARRAY_SIZE];
  size_t main_peers_size;
  addr_data *extra_peers_data;
  size_t extra_peers_size;
  /* Realm */
  char realm[STUN_MAX_REALM_SIZE + 1];
  char origin[STUN_MAX_ORIGIN_SIZE + 1];
  /* Bandwidth */
  band_limit_t bps;
};

void turn_session_info_clean(struct turn_session_info *tsi);
void turn_session_info_add_peer(struct turn_session_info *tsi, ioa_addr *peer);

int turn_session_info_copy_from(struct turn_session_info *tsi, ts_ur_super_session *ss);

////////////// ss /////////////////////

allocation *get_allocation_ss(ts_ur_super_session *ss);

///////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_SESSION__
