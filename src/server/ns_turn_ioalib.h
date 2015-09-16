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

/*
 * IO Abstraction library
 */

#ifndef __IOA_LIB__
#define __IOA_LIB__

#include "ns_turn_ioaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

////////////// forward declarations ////////

struct _ts_ur_super_session;
typedef struct _ts_ur_super_session ts_ur_super_session;

struct _tcp_connection;
typedef struct _tcp_connection tcp_connection;


////////////// Mutexes /////////////////////

struct _turn_mutex {
  u32bits data;
  void* mutex;
};

typedef struct _turn_mutex turn_mutex;

int turn_mutex_init(turn_mutex* mutex);
int turn_mutex_init_recursive(turn_mutex* mutex);

int turn_mutex_lock(const turn_mutex *mutex);
int turn_mutex_unlock(const turn_mutex *mutex);

int turn_mutex_destroy(turn_mutex* mutex);

#define TURN_MUTEX_DECLARE(mutex) turn_mutex mutex;
#define TURN_MUTEX_INIT(mutex) turn_mutex_init(mutex)
#define TURN_MUTEX_INIT_RECURSIVE(mutex) turn_mutex_init_recursive(mutex)
#define TURN_MUTEX_LOCK(mutex) turn_mutex_lock(mutex)
#define TURN_MUTEX_UNLOCK(mutex) turn_mutex_unlock(mutex)
#define TURN_MUTEX_DESTROY(mutex) turn_mutex_destroy(mutex)

/////// Sockets //////////////////////////////

#define IOA_EV_TIMEOUT	0x01
#define IOA_EV_READ		0x02
#define IOA_EV_WRITE	0x04
#define IOA_EV_SIGNAL	0x08
#define IOA_EV_CLOSE	0x10

enum _SOCKET_TYPE {
	UNKNOWN_SOCKET=0,
	TCP_SOCKET=6,
	UDP_SOCKET=17,
	TLS_SOCKET=56,
	SCTP_SOCKET=132,
	TLS_SCTP_SOCKET=133,
	DTLS_SOCKET=250,
	TENTATIVE_SCTP_SOCKET=254,
	TENTATIVE_TCP_SOCKET=255
};

typedef enum _SOCKET_TYPE SOCKET_TYPE;

enum _SOCKET_APP_TYPE {
	UNKNOWN_APP_SOCKET,
	CLIENT_SOCKET,
	HTTP_CLIENT_SOCKET,
	HTTPS_CLIENT_SOCKET,
	RELAY_SOCKET,
	RELAY_RTCP_SOCKET,
	TCP_CLIENT_DATA_SOCKET,
	TCP_RELAY_DATA_SOCKET,
	LISTENER_SOCKET
};

typedef enum _SOCKET_APP_TYPE SOCKET_APP_TYPE;

struct _ioa_socket;
typedef struct _ioa_socket ioa_socket;
typedef ioa_socket *ioa_socket_handle;

struct _ioa_engine;
typedef struct _ioa_engine ioa_engine;
typedef ioa_engine *ioa_engine_handle;

typedef void *ioa_timer_handle;

typedef void *ioa_network_buffer_handle;

/* event data for net event */
typedef struct _ioa_net_data {
	ioa_addr			src_addr;
	ioa_network_buffer_handle	nbh;
	int				recv_ttl;
	int				recv_tos;
} ioa_net_data;

/* Callback on TCP connection completion */
typedef void (*connect_cb)(int success, void *arg);
/* Callback on accepted socket from TCP relay endpoint */
typedef void (*accept_cb)(ioa_socket_handle s, void *arg);

////////// REALM ////////////

struct _realm_options_t;
typedef struct _realm_options_t realm_options_t;

//////// IP White/black listing ///////////

struct _ip_range {
	char str[257];
	char realm[513];
	ioa_addr_range enc;
};

typedef struct _ip_range ip_range_t;

struct _ip_range_list {
	ip_range_t *rs;
	size_t ranges_number;
};

typedef struct _ip_range_list ip_range_list_t;

void ioa_lock_whitelist(ioa_engine_handle e);
void ioa_unlock_whitelist(ioa_engine_handle e);
const ip_range_list_t* ioa_get_whitelist(ioa_engine_handle e);

void ioa_lock_blacklist(ioa_engine_handle e);
void ioa_unlock_blacklist(ioa_engine_handle e);
const ip_range_list_t* ioa_get_blacklist(ioa_engine_handle e);

////////////////////////////////////////////

/*
 * Network buffer functions
 */
ioa_network_buffer_handle ioa_network_buffer_allocate(ioa_engine_handle e);
void ioa_network_buffer_header_init(ioa_network_buffer_handle nbh);
u08bits *ioa_network_buffer_data(ioa_network_buffer_handle nbh);
size_t ioa_network_buffer_get_size(ioa_network_buffer_handle nbh);
size_t ioa_network_buffer_get_capacity(ioa_network_buffer_handle nbh);
size_t ioa_network_buffer_get_capacity_udp(void);
void ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len);
void ioa_network_buffer_add_offset_size(ioa_network_buffer_handle nbh, u16bits offset, u08bits coffset, size_t len);
u16bits ioa_network_buffer_get_offset(ioa_network_buffer_handle nbh);
u08bits ioa_network_buffer_get_coffset(ioa_network_buffer_handle nbh);
void ioa_network_buffer_delete(ioa_engine_handle e, ioa_network_buffer_handle nbh);

/*
 * Status reporting functions
 */
void turn_report_allocation_set(void *a, turn_time_t lifetime, int refresh);
void turn_report_allocation_delete(void *a);
void turn_report_session_usage(void *session);

/*
 * Network event handler callback
 * chnum parameter is just an optimisation hint -
 * the function must work correctly when chnum=0
 * (when no hint information is available).
 */
typedef void (*ioa_net_event_handler)(ioa_socket_handle s, int event_type, ioa_net_data *data, void *ctx, int can_resume);

/*
 * Timer callback
 */
typedef void (*ioa_timer_event_handler)(ioa_engine_handle e, void *ctx);

/* timers */

ioa_timer_handle set_ioa_timer(ioa_engine_handle e, int secs, int ms, ioa_timer_event_handler cb, void *ctx, int persist, const s08bits *txt);
void stop_ioa_timer(ioa_timer_handle th);
void delete_ioa_timer(ioa_timer_handle th);
#define IOA_EVENT_DEL(E) do { if(E) { delete_ioa_timer(E); E = NULL; } } while(0)

ioa_socket_handle create_unbound_relay_ioa_socket(ioa_engine_handle e, int family, SOCKET_TYPE st, SOCKET_APP_TYPE sat);

void inc_ioa_socket_ref_counter(ioa_socket_handle s);

/* Relay socket handling */
/*
 * event_port == -1: no rtcp;
 * event_port == 0: reserve rtcp;
 * even_port == +1: reserve and bind rtcp.
 */
int create_relay_ioa_sockets(ioa_engine_handle e, ioa_socket_handle client_s,
				int address_family, u08bits transport,
				int even_port, ioa_socket_handle *rtp_s, ioa_socket_handle *rtcp_s,
				u64bits *out_reservation_token, int *err_code, const u08bits **reason,
				accept_cb acb, void *acbarg);

ioa_socket_handle  ioa_create_connecting_tcp_relay_socket(ioa_socket_handle s, ioa_addr *peer_addr, connect_cb cb, void *arg);

int get_ioa_socket_from_reservation(ioa_engine_handle e, u64bits in_reservation_token, ioa_socket_handle *s);

int get_ioa_socket_address_family(ioa_socket_handle s);
int is_stream_socket(int st);
int is_tcp_socket(int st);
int is_sctp_socket(int st);
const char* socket_type_name(SOCKET_TYPE st);
const char* get_ioa_socket_cipher(ioa_socket_handle s);
const char* get_ioa_socket_ssl_method(ioa_socket_handle s);
SOCKET_TYPE get_ioa_socket_type(ioa_socket_handle s);
SOCKET_APP_TYPE get_ioa_socket_app_type(ioa_socket_handle s);
const char* get_ioa_socket_tls_method(ioa_socket_handle s);
const char* get_ioa_socket_tls_cipher(ioa_socket_handle s);
void set_ioa_socket_app_type(ioa_socket_handle s, SOCKET_APP_TYPE sat);
ioa_addr* get_local_addr_from_ioa_socket(ioa_socket_handle s);
ioa_addr* get_remote_addr_from_ioa_socket(ioa_socket_handle s);
int get_local_mtu_ioa_socket(ioa_socket_handle s);
ts_ur_super_session *get_ioa_socket_session(ioa_socket_handle s);
void set_ioa_socket_session(ioa_socket_handle s, ts_ur_super_session *ss);
void clear_ioa_socket_session_if(ioa_socket_handle s, void *ss);
tcp_connection *get_ioa_socket_sub_session(ioa_socket_handle s);
void set_ioa_socket_sub_session(ioa_socket_handle s, tcp_connection *tc);
int register_callback_on_ioa_socket(ioa_engine_handle e, ioa_socket_handle s, int event_type, ioa_net_event_handler cb, void *ctx, int clean_preexisting);
int send_data_from_ioa_socket_nbh(ioa_socket_handle s, ioa_addr* dest_addr, ioa_network_buffer_handle nbh, int ttl, int tos, int *skip);
void close_ioa_socket(ioa_socket_handle s);
#define IOA_CLOSE_SOCKET(S) do { if(S) { close_ioa_socket(S); S = NULL; } } while(0)
ioa_socket_handle detach_ioa_socket(ioa_socket_handle s);
void detach_socket_net_data(ioa_socket_handle s);
int set_df_on_ioa_socket(ioa_socket_handle s, int value);
void set_do_not_use_df(ioa_socket_handle s);
int ioa_socket_tobeclosed(ioa_socket_handle s);
void set_ioa_socket_tobeclosed(ioa_socket_handle s);
void close_ioa_socket_after_processing_if_necessary(ioa_socket_handle s);

////////////////// Base64 /////////////////////////////

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

void build_base64_decoding_table(void);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

///////////// Realm ///////////////////

void get_default_realm_options(realm_options_t* ro);
int get_realm_options_by_origin(char *origin, realm_options_t* ro);
void get_realm_options_by_name(char *realm, realm_options_t* ro);
int get_canonic_origin(const char* o, char *co, int sz);
int get_default_protocol_port(const char* scheme, size_t slen);

///////////// HTTP ////////////////////

void handle_http_echo(ioa_socket_handle s);

///////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif /* __IOA_LIB__ */
