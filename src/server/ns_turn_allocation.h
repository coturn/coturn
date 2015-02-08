/*
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

#ifndef __TURN_TURN_A_LIB__
#define __TURN_TURN_A_LIB__

#include "ns_turn_utils.h"
#include "ns_turn_msg.h"
#include "ns_turn_ioalib.h"
#include "ns_turn_maps.h"

#ifdef __cplusplus
extern "C" {
#endif

///////// Defines //////////

#define TCP_PEER_CONN_TIMEOUT (30)
#define TCP_CONN_BIND_TIMEOUT (30)

////////////// Network session ////////////////

typedef struct
{
	ioa_socket_handle s;
	turn_time_t expiration_time;
	ioa_timer_handle lifetime_ev;
} relay_endpoint_session;

static inline void clear_relay_endpoint_session_data(relay_endpoint_session* cdi)
{
	if (cdi)
		IOA_CLOSE_SOCKET(cdi->s);
}

////////// RFC 6062 TCP connection ////////

#define MAX_UNSENT_BUFFER_SIZE (0x10)

enum _TC_STATE {
	TC_STATE_UNKNOWN=0,
	TC_STATE_CLIENT_TO_PEER_CONNECTING,
	TC_STATE_PEER_CONNECTING,
	TC_STATE_PEER_CONNECTED,
	TC_STATE_READY,
	TC_STATE_FAILED
};

typedef enum _TC_STATE TC_STATE;

typedef u32bits tcp_connection_id;

typedef struct {
	size_t sz;
	ioa_network_buffer_handle *bufs;
} unsent_buffer;

struct _tcp_connection
{
	TC_STATE state;
	tcp_connection_id id;
	ioa_addr peer_addr;
	ioa_socket_handle client_s;
	ioa_socket_handle peer_s;
	ioa_timer_handle peer_conn_timeout;
	ioa_timer_handle conn_bind_timeout;
	stun_tid tid;
	void *owner; //a
	int done;
	unsent_buffer ub_to_client;
};

typedef struct _tcp_connection_list {
	size_t sz;
	tcp_connection **elems;
} tcp_connection_list;

////////////////////////////////

#define TURN_PERMISSION_HASHTABLE_SIZE (0x8)
#define TURN_PERMISSION_ARRAY_SIZE (0x3)

struct _allocation;

typedef struct _ch_info {
  u16bits chnum;
  int allocated;
  u16bits port;
  ioa_addr peer_addr;
  turn_time_t expiration_time;
  ioa_timer_handle lifetime_ev;
  void *owner; //perm
  TURN_CHANNEL_HANDLER_KERNEL kernel_channel;
} ch_info;

///////////// "channel" map /////////////////////

#define CH_MAP_HASH_SIZE (0x8)
#define CH_MAP_ARRAY_SIZE (0x3)

typedef struct _chn_map_array {
	ch_info main_chns[CH_MAP_ARRAY_SIZE];
	size_t extra_sz;
	ch_info **extra_chns;
} ch_map_array;

typedef struct _ch_map {
	ch_map_array table[CH_MAP_HASH_SIZE];
} ch_map;

ch_info *ch_map_get(ch_map* map, u16bits chnum, int new_chn);
void ch_map_clean(ch_map* map);

////////////////////////////

typedef struct _turn_permission_info {
	int allocated;
	lm_map chns;
	ioa_addr addr;
	turn_time_t expiration_time;
	ioa_timer_handle lifetime_ev;
	void* owner; //a
	int verbose;
	unsigned long long session_id;
} turn_permission_info;

typedef struct _turn_permission_slot {
	turn_permission_info info;
} turn_permission_slot;

typedef struct _turn_permission_array {
	turn_permission_slot main_slots[TURN_PERMISSION_ARRAY_SIZE];
	size_t extra_sz;
	turn_permission_slot **extra_slots;
} turn_permission_array;

typedef struct _turn_permission_hashtable {
	turn_permission_array table[TURN_PERMISSION_HASHTABLE_SIZE];
} turn_permission_hashtable;

//////////////// ALLOCATION //////////////////////

#define ALLOC_IPV4_INDEX (0)
#define ALLOC_IPV6_INDEX (1)
#define ALLOC_PROTOCOLS_NUMBER (2)
#define ALLOC_INDEX(family) ((((family)==AF_INET6)) ? ALLOC_IPV6_INDEX : ALLOC_IPV4_INDEX )
#define ALLOC_INDEX_ADDR(addr) ALLOC_INDEX(((addr)->ss).sa_family)

typedef struct _allocation {
  int is_valid;
  stun_tid tid;
  turn_permission_hashtable addr_to_perm;
  relay_endpoint_session relay_sessions[ALLOC_PROTOCOLS_NUMBER];
  int relay_sessions_failure[ALLOC_PROTOCOLS_NUMBER];
  ch_map chns; /* chnum-to-ch_info* */
  void *owner; //ss
  ur_map *tcp_connections; //global (per turn server) reference
  tcp_connection_list tcs; //local reference
} allocation;

//////////// CHANNELS ////////////////////

u16bits get_turn_channel_number(turn_permission_info* tinfo, ioa_addr *addr);
ch_info *get_turn_channel(turn_permission_info* tinfo, ioa_addr *addr);

void turn_channel_delete(ch_info* chn);

/////////// ALLOCATION ////////////

void init_allocation(void *owner, allocation* a, ur_map *tcp_connections);
void clear_allocation(allocation *a);

void turn_permission_clean(turn_permission_info* tinfo);

void set_allocation_lifetime_ev(allocation *a, turn_time_t exp_time, ioa_timer_handle ev, int family);
int is_allocation_valid(const allocation* a);
void set_allocation_valid(allocation* a, int value);
turn_permission_info* allocation_get_permission(allocation* a, const ioa_addr *addr);
turn_permission_hashtable* allocation_get_turn_permission_hashtable(allocation *a);
turn_permission_info* allocation_add_permission(allocation *a, const ioa_addr* addr);

ch_info* allocation_get_new_ch_info(allocation* a, u16bits chnum, ioa_addr* peer_addr);
ch_info* allocation_get_ch_info(allocation* a, u16bits chnum);
ch_info* allocation_get_ch_info_by_peer_addr(allocation* a, ioa_addr* peer_addr);

relay_endpoint_session *get_relay_session(allocation *a, int family);
int get_relay_session_failure(allocation *a, int family);
void set_relay_session_failure(allocation *a, int family);
ioa_socket_handle get_relay_socket(allocation *a, int family);
void set_allocation_family_invalid(allocation *a, int family);

tcp_connection *get_and_clean_tcp_connection_by_id(ur_map *map, tcp_connection_id id);
tcp_connection *get_tcp_connection_by_id(ur_map *map, tcp_connection_id id);
tcp_connection *get_tcp_connection_by_peer(allocation *a, ioa_addr *peer_addr);
int can_accept_tcp_connection_from_peer(allocation *a, ioa_addr *peer_addr, int server_relay);
tcp_connection *create_tcp_connection(u08bits server_id, allocation *a, stun_tid *tid, ioa_addr *peer_addr, int *err_code);
void delete_tcp_connection(tcp_connection *tc);

void clear_unsent_buffer(unsent_buffer *ub);
void add_unsent_buffer(unsent_buffer *ub, ioa_network_buffer_handle nbh);
ioa_network_buffer_handle top_unsent_buffer(unsent_buffer *ub);
void pop_unsent_buffer(unsent_buffer *ub);

///////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_TURN_A_LIB__
