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

#ifndef __UCLIENT_ECHO__
#define __UCLIENT_ECHO__

#include "ns_turn_utils.h"
#include "stun_buffer.h"
#include "session.h"

#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////

#define STOPPING_TIME (10)
#define STARTING_TCP_RELAY_TIME (30)

extern int clmessage_length;
extern int do_not_use_channel;
extern int clnet_verbose;
extern int use_tcp;
extern int use_sctp;
extern int use_secure;
extern char cert_file[1025];
extern char pkey_file[1025];
extern int hang_on;
extern int c2c;
extern ioa_addr peer_addr;
extern int no_rtcp;
extern int default_address_family;
extern int dont_fragment;
extern u08bits g_uname[STUN_MAX_USERNAME_SIZE+1];
extern password_t g_upwd;
extern char g_auth_secret[1025];
extern int g_use_auth_secret_with_timestamp;
extern int use_fingerprints;
extern SSL_CTX *root_tls_ctx[32];
extern int root_tls_ctx_num;
extern int RTP_PACKET_INTERVAL;
extern u08bits relay_transport;
extern unsigned char client_ifname[1025];
extern struct event_base* client_event_base;
extern int passive_tcp;
extern int mandatory_channel_padding;
extern int negative_test;
extern int negative_protocol_test;
extern int dos;
extern int random_disconnect;
extern SHATYPE shatype;
extern int mobility;
extern int no_permissions;
extern int extra_requests;
extern band_limit_t bps;
extern int dual_allocation;

extern char origin[STUN_MAX_ORIGIN_SIZE+1];

extern int oauth;
extern oauth_key okey_array[3];

#define UCLIENT_SESSION_LIFETIME (777)
#define OAUTH_SESSION_LIFETIME (555)

#define is_TCP_relay() (relay_transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE)

void start_mclient(const char *remote_address, int port,
		   const unsigned char* ifname, const char *local_address,
		   int messagenumber, int mclient);

int send_buffer(app_ur_conn_info *clnet_info, stun_buffer* message, int data_connection, app_tcp_conn_info *atc);
int recv_buffer(app_ur_conn_info *clnet_info, stun_buffer* message, int sync, int data_connection, app_tcp_conn_info *atc, stun_buffer* request_message);

void client_input_handler(evutil_socket_t fd, short what, void* arg);

turn_credential_type get_turn_credentials_type(void);

int add_integrity(app_ur_conn_info *clnet_info, stun_buffer *message);
int check_integrity(app_ur_conn_info *clnet_info, stun_buffer *message);

SOCKET_TYPE get_socket_type(void);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__UCLIENT_ECHO__

