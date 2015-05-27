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

#ifndef __SESSION__
#define __SESSION__

#include <event2/event.h>
#include <event2/bufferevent.h>

#include "ns_turn_ioaddr.h"
#include "ns_turn_utils.h"

#include "stun_buffer.h"
#include "apputils.h"

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

///////// types ////////////

enum _UR_STATE {
  UR_STATE_UNKNOWN=0,
  UR_STATE_READY,
  UR_STATE_DONE
};

typedef enum _UR_STATE UR_STATE;

//////////////// session info //////////////////////

typedef struct
{
	/* RFC 6062 */
	u32bits cid;
	ioa_addr tcp_data_local_addr;
	ioa_socket_raw tcp_data_fd;
	SSL *tcp_data_ssl;
	int tcp_data_bound;
} app_tcp_conn_info;

typedef struct {
  ioa_addr local_addr;
  char	lsaddr[129];
  ioa_addr remote_addr;
  char rsaddr[129];
  char ifname[129];
  ioa_addr peer_addr;
  ioa_addr relay_addr;
  ioa_socket_raw fd;
  SSL *ssl;
  int broken;
  u08bits nonce[STUN_MAX_NONCE_SIZE+1];
  u08bits realm[STUN_MAX_REALM_SIZE+1];
  /* oAuth */
  int oauth;
  u08bits server_name[STUN_MAX_SERVER_NAME_SIZE+1];
  hmackey_t key;
  int key_set;
  int cok;
  /* RFC 6062 */
  app_tcp_conn_info **tcp_conn;
  size_t tcp_conn_number;
  int is_peer;
  char s_mobile_id[33];
} app_ur_conn_info;

typedef struct {
  app_ur_conn_info pinfo;
  UR_STATE state;
  unsigned int ctime;
  uint16_t chnum;
  int wait_cycles;
  int timer_cycle;
  int completed;
  struct event *input_ev;
  struct event *input_tcp_data_ev;
  stun_buffer in_buffer;
  stun_buffer out_buffer;
  u32bits refresh_time;
  u32bits finished_time;
  //Msg counters:
  int tot_msgnum;
  int wmsgnum;
  int rmsgnum;
  int recvmsgnum;
  u32bits recvtimems;
  u32bits to_send_timems;
  //Statistics:
  size_t loss;
  u64bits latency;
  u64bits jitter;
} app_ur_session;

///////////////////////////////////////////////////////

typedef struct _message_info {
	int msgnum;
	u64bits mstime;
} message_info;

///////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__SESSION__
