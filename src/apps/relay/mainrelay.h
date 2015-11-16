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

#if !defined(__MAIN_RELAY__)
#define __MAIN_RELAY__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>

#include <pthread.h>
#include <sched.h>

#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>

#include <pwd.h>
#include <grp.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

#include "ns_turn_utils.h"
#include "ns_turn_khash.h"

#include "userdb.h"
#include "turn_admin_server.h"

#include "tls_listener.h"
#include "dtls_listener.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

#include "ns_ioalib_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

////////////// DEFINES ////////////////////////////

#define DEFAULT_CONFIG_FILE "turnserver.conf"

#define DEFAULT_CIPHER_LIST "DEFAULT"
/* "ALL:eNULL:aNULL:NULL" */

#define DEFAULT_EC_CURVE_NAME "prime256v1"

#define MAX_NUMBER_OF_GENERAL_RELAY_SERVERS ((u08bits)(0x80))

#define TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP MAX_NUMBER_OF_GENERAL_RELAY_SERVERS
#define TURNSERVER_ID_BOUNDARY_BETWEEN_UDP_AND_TCP TURNSERVER_ID_BOUNDARY_BETWEEN_TCP_AND_UDP

#define DEFAULT_CPUS_NUMBER (2)

/////////// TYPES ///////////////////////////////////

enum _DH_KEY_SIZE {
	DH_566,
	DH_1066,
	DH_2066,
	DH_CUSTOM
};

typedef enum _DH_KEY_SIZE DH_KEY_SIZE;

///////// LISTENER SERVER TYPES /////////////////////

struct message_to_listener_to_client {
	ioa_addr origin;
	ioa_addr destination;
	ioa_network_buffer_handle nbh;
};

enum _MESSAGE_TO_LISTENER_TYPE {
	LMT_UNKNOWN,
	LMT_TO_CLIENT
};
typedef enum _MESSAGE_TO_LISTENER_TYPE MESSAGE_TO_LISTENER_TYPE;

struct message_to_listener {
	MESSAGE_TO_LISTENER_TYPE t;
	union {
		struct message_to_listener_to_client tc;
	} m;
};

struct listener_server {
	rtcp_map* rtcpmap;
	turnipports* tp;
	struct event_base* event_base;
	ioa_engine_handle ioa_eng;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
	char **addrs;
	ioa_addr **encaddrs;
	size_t addrs_number;
	size_t services_number;
	dtls_listener_relay_server_type ***udp_services;
	dtls_listener_relay_server_type ***dtls_services;
	dtls_listener_relay_server_type ***aux_udp_services;
};

enum _NET_ENG_VERSION {
	NEV_UNKNOWN=0,
	NEV_MIN,
	NEV_UDP_SOCKET_PER_SESSION=NEV_MIN,
	NEV_UDP_SOCKET_PER_ENDPOINT,
	NEV_UDP_SOCKET_PER_THREAD,
	NEV_MAX=NEV_UDP_SOCKET_PER_THREAD,
	NEV_TOTAL
};

typedef enum _NET_ENG_VERSION NET_ENG_VERSION;

/////////// PARAMS //////////////////////////////////

typedef struct _turn_params_ {

//////////////// OpenSSL group //////////////////////

  SSL_CTX *tls_ctx_ssl23;
  
  SSL_CTX *tls_ctx_v1_0;
  
#if TLSv1_1_SUPPORTED
  SSL_CTX *tls_ctx_v1_1;
#if TLSv1_2_SUPPORTED
  SSL_CTX *tls_ctx_v1_2;
#endif
#endif
  
#if DTLS_SUPPORTED
  SSL_CTX *dtls_ctx;
#if DTLSv1_2_SUPPORTED
  SSL_CTX *dtls_ctx_v1_2;
#endif
#endif
  
  DH_KEY_SIZE dh_key_size;
  
  char cipher_list[1025];
  char ec_curve_name[33];
  
  char ca_cert_file[1025];
  char cert_file[1025];
  char pkey_file[1025];
  char tls_password[513];
  char dh_file[1025];

  int no_tlsv1;
  int no_tlsv1_1;
  int no_tlsv1_2;
  int no_tls;
  int no_dtls;

//////////////// Common params ////////////////////

  int verbose;
  int turn_daemon;

  int do_not_use_config_file;

  char pidfile[1025];

  ////////////////  Listener server /////////////////

  int listener_port;
  int tls_listener_port;
  int alt_listener_port;
  int alt_tls_listener_port;
  int rfc5780;

  int no_udp;
  int no_tcp;
  
  vint no_tcp_relay;
  vint no_udp_relay;

  char listener_ifname[1025];

  char redis_statsdb[1025];
  int use_redis_statsdb;

  struct listener_server listener;

  ip_range_list_t ip_whitelist;
  ip_range_list_t ip_blacklist;

  NET_ENG_VERSION net_engine_version;
  const char* net_engine_version_txt[NEV_TOTAL];

//////////////// Relay servers /////////////

  u16bits min_port;
  u16bits max_port;

  vint check_origin;

  vint no_multicast_peers;
  vint no_loopback_peers;

  char relay_ifname[1025];

  size_t relays_number;
  char **relay_addrs;
  int default_relays;

  // Single global public IP.
  // If multiple public IPs are used
  // then ioa_addr mapping must be used.
  ioa_addr *external_ip;

  turnserver_id general_relay_servers_number;
  turnserver_id udp_relay_servers_number;

////////////// Auth server ////////////////

  char oauth_server_name[1025];
  char domain[1025];
  int oauth;

/////////////// AUX SERVERS ////////////////

  turn_server_addrs_list_t aux_servers_list;
  int udp_self_balance;

/////////////// ALTERNATE SERVERS ////////////////

  turn_server_addrs_list_t alternate_servers_list;
  turn_server_addrs_list_t tls_alternate_servers_list;

  int stop_turn_server;

////////////// MISC PARAMS ////////////////

  vint stun_only;
  vint no_stun;
  vint secure_stun;
  int server_relay;
  int fingerprint;
  char rest_api_separator;
  vint stale_nonce;
  vint mobility;
  turn_credential_type ct;
  int use_auth_secret_with_timestamp;
  band_limit_t max_bps;
  band_limit_t bps_capacity;
  band_limit_t bps_capacity_allocated;
  vint total_quota;
  vint user_quota;

/////// Users DB ///////////

  default_users_db_t default_users_db;

/////// CPUs //////////////

  unsigned long cpus;

} turn_params_t;

extern turn_params_t turn_params;

////////////////  Listener server /////////////////

static inline int get_alt_listener_port(void) {
	if(turn_params.alt_listener_port<1)
		return turn_params.listener_port + 1;
	return turn_params.alt_listener_port;
}

static inline int get_alt_tls_listener_port(void) {
	if(turn_params.alt_tls_listener_port<1)
		return turn_params.tls_listener_port + 1;
	return turn_params.alt_tls_listener_port;
}

void add_aux_server(const char *saddr);

void add_alternate_server(const char *saddr);
void del_alternate_server(const char *saddr);
void add_tls_alternate_server(const char *saddr);
void del_tls_alternate_server(const char *saddr);

////////// Addrs ////////////////////

void add_listener_addr(const char* addr);
int add_relay_addr(const char* addr);

///////// Auth ////////////////

void send_auth_message_to_auth_server(struct auth_message *am);

/////////// Setup server ////////

void init_listener(void);
void setup_server(void);
void run_listener_server(struct listener_server *ls);

////////// BPS ////////////////

band_limit_t get_bps_capacity_allocated(void);
band_limit_t get_bps_capacity(void);
void set_bps_capacity(band_limit_t value);
band_limit_t get_max_bps(void);
void set_max_bps(band_limit_t value);

///////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__MAIN_RELAY__
