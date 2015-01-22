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

#ifndef __TURN_ADMIN_SERVER__
#define __TURN_ADMIN_SERVER__

#include <stdlib.h>
#include <stdio.h>

#include <pthread.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "ns_turn_utils.h"
#include "ns_turn_maps.h"
#include "ns_turn_server.h"

#include "apputils.h"

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////

#define ADMIN_USER_MAX_LENGTH (32)

struct admin_session {
	int as_ok;
	char as_login[ADMIN_USER_MAX_LENGTH + 1];
	char as_realm[STUN_MAX_REALM_SIZE + 1];
	char as_eff_realm[STUN_MAX_REALM_SIZE + 1];
	size_t number_of_user_sessions;
};

struct admin_server {
	evutil_socket_t listen_fd;
	struct event_base* event_base;
	ioa_engine_handle e;
	int verbose;
	struct evconnlistener *l;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
	struct bufferevent *https_in_buf;
	struct bufferevent *https_out_buf;
	ur_map *sessions;
	pthread_t thr;
};

///////////////////////////////////////////

extern struct admin_server adminserver;

extern int use_cli;

#define CLI_DEFAULT_IP ("127.0.0.1")
extern ioa_addr cli_addr;
extern int cli_addr_set;

#define CLI_DEFAULT_PORT (5766)
extern int cli_port;

#define CLI_PASSWORD_LENGTH (129)
extern char cli_password[CLI_PASSWORD_LENGTH];

#define DEFAULT_CLI_MAX_OUTPUT_SESSIONS (256)
extern int cli_max_output_sessions;

////////////////////////////////////////////

void setup_admin_thread(void);

void admin_server_receive_message(struct bufferevent *bev, void *ptr);
void https_admin_server_receive_message(struct bufferevent *bev, void *ptr);

int send_turn_session_info(struct turn_session_info* tsi);
void send_https_socket(ioa_socket_handle s);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif
/// __TURN_ADMIN_SERVER__///

