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

#ifndef __TURN_SERVER__
#define __TURN_SERVER__

#include "ns_turn_utils.h"
#include "ns_turn_session.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////// defines //////////////

#define TURN_SESSION_ID_FACTOR (1000000000000000LL)

//////////// ALTERNATE-SERVER /////////////

struct _turn_server_addrs_list {
	ioa_addr *addrs;
	volatile size_t size;
	turn_mutex m;
};

typedef struct _turn_server_addrs_list turn_server_addrs_list_t;

void init_turn_server_addrs_list(turn_server_addrs_list_t *l);

////////// RFC 5780 ///////////////////////

typedef int (*get_alt_addr_cb)(ioa_addr *addr, ioa_addr *alt_addr);
typedef int (*send_message_cb)(ioa_engine_handle e, ioa_network_buffer_handle nbh, ioa_addr *origin, ioa_addr *destination);

//////////////////////////////////////////

extern int TURN_MAX_ALLOCATE_TIMEOUT;
extern int TURN_MAX_ALLOCATE_TIMEOUT_STUN_ONLY;

typedef u08bits turnserver_id;

enum _MESSAGE_TO_RELAY_TYPE {
	RMT_UNKNOWN = 0,
	RMT_SOCKET,
	RMT_CB_SOCKET,
	RMT_MOBILE_SOCKET,
	RMT_CANCEL_SESSION
};
typedef enum _MESSAGE_TO_RELAY_TYPE MESSAGE_TO_RELAY_TYPE;

struct socket_message {
	ioa_socket_handle s;
	ioa_net_data nd;
	int can_resume;
};

typedef enum {
	DONT_FRAGMENT_UNSUPPORTED=0,
	DONT_FRAGMENT_SUPPORTED,
	DONT_FRAGMENT_SUPPORT_EMULATED
} dont_fragment_option_t;

struct _turn_turnserver;
typedef struct _turn_turnserver turn_turnserver;

typedef void (*get_username_resume_cb)(int success, int oauth, int max_session_time, hmackey_t hmackey, password_t pwd, turn_turnserver *server, u64bits ctxkey, ioa_net_data *in_buffer, u08bits* realm);
typedef u08bits *(*get_user_key_cb)(turnserver_id id, turn_credential_type ct, int in_oauth, int *out_oauth, u08bits *uname, u08bits *realm, get_username_resume_cb resume, ioa_net_data *in_buffer, u64bits ctxkey, int *postpone_reply);
typedef int (*check_new_allocation_quota_cb)(u08bits *username, int oauth, u08bits *realm);
typedef void (*release_allocation_quota_cb)(u08bits *username, int oauth, u08bits *realm);
typedef int (*send_socket_to_relay_cb)(turnserver_id id, u64bits cid, stun_tid *tid, ioa_socket_handle s, int message_integrity, MESSAGE_TO_RELAY_TYPE rmt, ioa_net_data *nd, int can_resume);
typedef int (*send_turn_session_info_cb)(struct turn_session_info *tsi);
typedef void (*send_https_socket_cb)(ioa_socket_handle s);

typedef band_limit_t (*allocate_bps_cb)(band_limit_t bps, int positive);

struct _turn_turnserver {

	turnserver_id id;

	turnsession_id session_id_counter;
	ur_map *sessions_map;

	turn_time_t ctime;

	ioa_engine_handle e;
	int verbose;
	int fingerprint;
	int rfc5780;
	vintp check_origin;
	vintp stale_nonce;
	vintp stun_only;
	vintp no_stun;
	vintp secure_stun;
	turn_credential_type ct;
	get_alt_addr_cb alt_addr_cb;
	send_message_cb sm_cb;
	dont_fragment_option_t dont_fragment;
	int (*disconnect)(ts_ur_super_session*);
	get_user_key_cb userkeycb;
	check_new_allocation_quota_cb chquotacb;
	release_allocation_quota_cb raqcb;
	int external_ip_set;
	ioa_addr external_ip;
	vintp no_loopback_peers;
	vintp no_multicast_peers;
	send_turn_session_info_cb send_turn_session_info;
	send_https_socket_cb send_https_socket;

	/* RFC 6062 ==>> */
	vintp no_udp_relay;
	vintp no_tcp_relay;
	ur_map *tcp_relay_connections;
	send_socket_to_relay_cb send_socket_to_relay;
	/* <<== RFC 6062 */

	/* Alternate servers ==>> */
	turn_server_addrs_list_t *alternate_servers_list;
	size_t as_counter;
	turn_server_addrs_list_t *tls_alternate_servers_list;
	size_t tls_as_counter;
	turn_server_addrs_list_t *aux_servers_list;
	int self_udp_balance;

	/* White/black listing of address ranges */
	ip_range_list_t* ip_whitelist;
	ip_range_list_t* ip_blacklist;

	/* Mobility */
	vintp mobility;
	ur_map *mobile_connections_map;

	/* Server relay */
	int server_relay;

	/* Bandwidth draft: */
	allocate_bps_cb allocate_bps_func;

	/* oAuth: */
	int oauth;
	const char* oauth_server_name;
};

///////////////////////////////////////////

void init_turn_server(turn_turnserver* server,
					turnserver_id id, int verbose,
				    ioa_engine_handle e,
				    turn_credential_type ct,
				    int stun_port,
				    int fingerprint,
				    dont_fragment_option_t dont_fragment,
				    get_user_key_cb userkeycb,
				    check_new_allocation_quota_cb chquotacb,
				    release_allocation_quota_cb raqcb,
				    ioa_addr *external_addr,
				    vintp check_origin,
				    vintp no_tcp_relay,
				    vintp no_udp_relay,
				    vintp stale_nonce,
				    vintp stun_only,
				    vintp no_stun,
				    turn_server_addrs_list_t *alternate_servers_list,
				    turn_server_addrs_list_t *tls_alternate_servers_list,
				    turn_server_addrs_list_t *aux_servers_list,
				    int self_udp_balance,
				    vintp no_multicast_peers,
				    vintp no_loopback_peers,
				    ip_range_list_t* ip_whitelist,
				    ip_range_list_t* ip_blacklist,
				    send_socket_to_relay_cb send_socket_to_relay,
				    vintp secure_stun,
				    vintp mobility,
				    int server_relay,
				    send_turn_session_info_cb send_turn_session_info,
				    send_https_socket_cb send_https_socket,
				    allocate_bps_cb allocate_bps_func,
				    int oauth,
				    const char* oauth_server_name);

ioa_engine_handle turn_server_get_engine(turn_turnserver *s);

////////// RFC 5780 ///////////////////////

void set_rfc5780(turn_turnserver *server, get_alt_addr_cb cb, send_message_cb smcb);

///////////////////////////////////////////

int open_client_connection_session(turn_turnserver* server, struct socket_message *sm);
int shutdown_client_connection(turn_turnserver *server, ts_ur_super_session *ss, int force, const char* reason);
void set_disconnect_cb(turn_turnserver* server, int (*disconnect)(ts_ur_super_session*));

int turnserver_accept_tcp_client_data_connection(turn_turnserver *server, tcp_connection_id tcid, stun_tid *tid, ioa_socket_handle s, int message_integrity, ioa_net_data *nd, int can_resume);

int report_turn_session_info(turn_turnserver *server, ts_ur_super_session *ss, int force_invalid);

turn_time_t get_turn_server_time(turn_turnserver *server);

void turn_cancel_session(turn_turnserver *server, turnsession_id sid);

///////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_SERVER__
