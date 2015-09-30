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

#ifndef __APP_LIB__
#define __APP_LIB__

#include <event2/event.h>

#include <openssl/ssl.h>

#include "ns_turn_ioaddr.h"
#include "ns_turn_msg_defs.h"
#include "ns_turn_ioalib.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////// Common defines ///////////////////////////

#define PEER_DEFAULT_PORT (3480)

#define DTLS_MAX_RECV_TIMEOUT (5)

#define UR_CLIENT_SOCK_BUF_SIZE (65536)
#define UR_SERVER_SOCK_BUF_SIZE (UR_CLIENT_SOCK_BUF_SIZE * 32)

extern int IS_TURN_SERVER;

/* ALPN */

#define OPENSSL_FIRST_ALPN_VERSION (0x10002003L)

#if OPENSSL_VERSION_NUMBER >= OPENSSL_FIRST_ALPN_VERSION
#define ALPN_SUPPORTED 1
#else
#define ALPN_SUPPORTED 0
#endif

/* TLS */

#if defined(TURN_NO_TLS)

	#define TLS_SUPPORTED 0
	#define TLSv1_1_SUPPORTED 0
	#define TLSv1_2_SUPPORTED 0

#else

	#define TLS_SUPPORTED 1

	#if defined(SSL_OP_NO_TLSv1_1)
		#define TLSv1_1_SUPPORTED 1
	#else
		#define TLSv1_1_SUPPORTED 0
	#endif

	#if defined(SSL_OP_NO_TLSv1_2)
		#define TLSv1_2_SUPPORTED 1
	#else
		#define TLSv1_2_SUPPORTED 0
	#endif

#endif

#if defined(TURN_NO_DTLS) || !defined(DTLS_CTRL_LISTEN)

	#define DTLS_SUPPORTED 0
	#define DTLSv1_2_SUPPORTED 0

#else

	#define DTLS_SUPPORTED 1

#if defined(SSL_OP_NO_DTLSv1_2)
		#define DTLSv1_2_SUPPORTED 1
	#else
		#define DTLSv1_2_SUPPORTED 0
	#endif

#endif

#if OPENSSL_VERSION_NUMBER >= OPENSSL_FIRST_ALPN_VERSION
#define SSL_SESSION_ECDH_AUTO_SUPPORTED 1
#else
#define SSL_SESSION_ECDH_AUTO_SUPPORTED 0
#endif

/////////// SSL //////////////////////////

enum _TURN_TLS_TYPE {
	TURN_TLS_NO=0,
	TURN_TLS_SSL23,
	TURN_TLS_v1_0,
#if TLSv1_1_SUPPORTED
	TURN_TLS_v1_1,
#if TLSv1_2_SUPPORTED
	TURN_TLS_v1_2,
#endif
#endif
	TURN_TLS_TOTAL
};

typedef enum _TURN_TLS_TYPE TURN_TLS_TYPE;

////////////////////////////////////////////

struct _oauth_key_data_raw {
	char kid[OAUTH_KID_SIZE+1];
	char ikm_key[OAUTH_KEY_SIZE+1];
	u64bits timestamp;
	u32bits lifetime;
	char as_rs_alg[OAUTH_ALG_SIZE+1];
	char realm[STUN_MAX_REALM_SIZE+1];
};

typedef struct _oauth_key_data_raw oauth_key_data_raw;

//////////////////////////////////////////

#define EVENT_DEL(ev) if(ev) { event_del(ev); event_free(ev); ev=NULL; }

//////////////////////////////////////////

#define ioa_socket_raw int

///////////////////////// Sockets ///////////////////////////////

#if defined(WIN32)
/** Do the platform-specific call needed to close a socket returned from
    socket() or accept(). */
#define socket_closesocket(s) closesocket(s)
#else
/** Do the platform-specific call needed to close a socket returned from
    socket() or accept(). */
#define socket_closesocket(s) close(s)
#endif

void read_spare_buffer(evutil_socket_t fd);

int set_sock_buf_size(evutil_socket_t fd, int sz);

int socket_set_reusable(evutil_socket_t fd, int reusable, SOCKET_TYPE st);
int sock_bind_to_device(evutil_socket_t fd, const unsigned char* ifname);
int socket_set_nonblocking(evutil_socket_t fd);
int socket_tcp_set_keepalive(evutil_socket_t fd, SOCKET_TYPE st);

int addr_connect(evutil_socket_t fd, const ioa_addr* addr, int *out_errno);

int addr_bind(evutil_socket_t fd, const ioa_addr* addr, int reusable, int debug, SOCKET_TYPE st);

int addr_get_from_sock(evutil_socket_t fd, ioa_addr *addr);

int handle_socket_error(void);

#define CORRECT_RAW_TTL(ttl) do { if(ttl<0 || ttl>255) ttl=TTL_DEFAULT; } while(0)
#define CORRECT_RAW_TOS(tos) do { if(tos<0 || tos>255) tos=TOS_DEFAULT; } while(0)

int set_raw_socket_tos(evutil_socket_t fd, int family, int tos);
int set_raw_socket_ttl(evutil_socket_t fd, int family, int ttl);
int get_raw_socket_tos(evutil_socket_t fd, int family);
int get_raw_socket_ttl(evutil_socket_t fd, int family);

/////////////////////// SYS /////////////////////

void ignore_sigpipe(void);
unsigned long set_system_parameters(int max_resources);

///////////////////////// MTU //////////////////////////

#define MAX_MTU (1500 - 20 - 8)
#define MIN_MTU (576 - 20 - 8)
#define SOSO_MTU (1300)

#define MTU_STEP (68)

int set_socket_df(evutil_socket_t fd, int family, int value);
int set_mtu_df(SSL* ssl, evutil_socket_t fd, int family, int mtu, int df_value, int verbose);
int decrease_mtu(SSL* ssl, int mtu, int verbose);
int get_socket_mtu(evutil_socket_t fd, int family, int verbose);

////////////////// Misc utils /////////////////////////

char *skip_blanks(char* s);

////////////////// File search ////////////////////////

char* find_config_file(const char *config_file, int print_file_name);
void set_execdir(void);
void print_abs_file_name(const char *msg1, const char *msg2, const char *fn);

////////////////// Base64 /////////////////////////////

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

void build_base64_decoding_table(void);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

///////////// SSL ////////////////

const char* turn_get_ssl_method(SSL *ssl, const char* mdefault);

////////////// OAUTH UTILS ////////////////

void convert_oauth_key_data_raw(const oauth_key_data_raw *raw, oauth_key_data *oakd);

//////////// Event Base /////////////////////

struct event_base *turn_event_base_new(void);

///////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__APP_LIB__
