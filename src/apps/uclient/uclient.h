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

#ifndef __UCLIENT_ECHO__
#define __UCLIENT_ECHO__

#include "session.h"
#include "stun_buffer.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////

typedef enum {
  UCLIENT_LOAD_MODE_NONE = 0,
  UCLIENT_LOAD_MODE_PACKET_FLOOD,
  UCLIENT_LOAD_MODE_ALLOC_FLOOD,
  UCLIENT_LOAD_MODE_INVALID_FLOOD
} uclient_load_mode;

#define STOPPING_TIME (10)
#define STARTING_TCP_RELAY_TIME (30)

/* Per-socket SO_RCVBUF/SO_SNDBUF for uclient. The default
 * UR_CLIENT_SOCK_BUF_SIZE (64 KB) is a poor fit for load-test runs:
 * with many concurrent sessions or short scheduling stalls the kernel
 * receive queue overflows and uclient reports phantom "lost packets".
 * 4 MB is large enough to survive typical jitter at 10k pps per socket;
 * set_sock_buf_size() halves on EPERM/EINVAL until the kernel
 * net.core.rmem_max ceiling is satisfied. */
#define UCLIENT_SOCK_BUF_SIZE (4 * 1024 * 1024)

/* Multi-threaded listener (recv) pool. The main thread keeps owning the
 * sender timer, the lifecycle, and the control plane; receive events for
 * each session are sharded across N listener threads, each with its own
 * libevent base. Default 0 (= legacy single-event-base, no worker
 * thread): a real-Linux bench on a c-4 loadgen showed K=0 winning at
 * -m {1,2} (4.6k / 6.2k pps vs ~3.2k for K=1), so the cheap default is
 * also the right one for short smoke tests. Auto-scales to K=1 once
 * concurrency reaches UCLIENT_AUTO_LISTENERS_THRESHOLD, where the
 * bench shows K=1 winning decisively (-m 4: 6.5k vs K=0's 5.1k; -m 8:
 * 7.9k vs 4.0k).
 *
 * Capped at UCLIENT_MAX_LISTENER_THREADS. The bench shows K=2 and K=4
 * regressing severely on a 4-vCPU loadgen (-m 4: 344/309 pps vs K=1's
 * 6557 -- 19x worse) due to cross-thread cache-line bouncing on the
 * shared atomic counters when each worker only owns 1-2 sessions. The
 * cap stays available for explicit -K on hardware where it might help,
 * but the auto rule never crosses it. */
#define UCLIENT_MAX_LISTENER_THREADS (4)
extern int num_listener_threads;
/* Set to true by mainuclient.c when -K / --listener-threads is given on
 * the command line; consumed by start_mclient() to decide whether to
 * auto-scale the pool based on -m (see UCLIENT_AUTO_LISTENERS_THRESHOLD). */
extern bool num_listener_threads_explicit;
/* Concurrency at/above which uclient auto-bumps the listener pool from
 * the K=0 default (lowest-overhead) to UCLIENT_AUTO_LISTENERS_TARGET.
 * Only applied when the user did not pass -K. Threshold lowered to 2
 * after per-listener counter slabs removed the K>=2 regression that
 * originally made the threshold conservative; with the slabs in place
 * the worker thread is a small loss at m=2 but a clear win from m=4
 * upward and the always-on shape is friendlier for downstream tooling
 * that expects a consistent thread topology. */
#define UCLIENT_AUTO_LISTENERS_THRESHOLD (2)
#define UCLIENT_AUTO_LISTENERS_TARGET (1)

/* ============================================================
 * Sender thread pool — mirror of the listener pool above, for
 * the send-burst side of the load generator. Without it the
 * timer_handler iteration runs on a single thread and caps
 * loadgen pps at ~1 core's worth of send() overhead.
 * Capped at UCLIENT_MAX_SENDER_THREADS. Auto-bumped from -m >=
 * UCLIENT_AUTO_SENDERS_THRESHOLD when --sender-threads is not
 * explicitly set. ============================================ */
#define UCLIENT_MAX_SENDER_THREADS (4)
extern int num_sender_threads;
extern bool num_sender_threads_explicit;
#define UCLIENT_AUTO_SENDERS_THRESHOLD (4)
#define UCLIENT_AUTO_SENDERS_TARGET (2)

extern int clmessage_length;
extern bool do_not_use_channel;
extern int clnet_verbose;
extern bool use_tcp;
extern bool use_sctp;
extern bool use_secure;
extern char cert_file[1025];
extern char pkey_file[1025];
extern bool hang_on;
extern bool c2c;
extern ioa_addr peer_addr;
extern bool no_rtcp;
extern int default_address_family;
extern bool dont_fragment;
extern uint8_t g_uname[STUN_MAX_USERNAME_SIZE + 1];
extern password_t g_upwd;
extern char g_auth_secret[1025];
extern bool g_use_auth_secret_with_timestamp;
extern bool use_fingerprints;
extern SSL_CTX *root_tls_ctx[32];
extern int root_tls_ctx_num;
extern int RTP_PACKET_INTERVAL;
extern uint8_t relay_transport;
extern unsigned char client_ifname[1025];
extern struct event_base *client_event_base;
extern bool passive_tcp;
extern bool mandatory_channel_padding;
extern bool negative_test;
extern bool negative_protocol_test;
extern bool dos;
extern bool random_disconnect;
extern SHATYPE shatype;
extern bool mobility;
extern bool no_permissions;
extern bool extra_requests;
extern band_limit_t bps;
extern bool dual_allocation;
extern bool unique_client_ports;
extern uclient_load_mode load_mode;

extern char origin[STUN_MAX_ORIGIN_SIZE + 1];

extern int oauth;
extern oauth_key okey_array[3];

#define UCLIENT_SESSION_LIFETIME (777)
#define OAUTH_SESSION_LIFETIME (555)

#define is_TCP_relay() (relay_transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE)
#define is_packet_flood_mode() (load_mode == UCLIENT_LOAD_MODE_PACKET_FLOOD)
#define is_alloc_flood_mode() (load_mode == UCLIENT_LOAD_MODE_ALLOC_FLOOD)
#define is_invalid_flood_mode() (load_mode == UCLIENT_LOAD_MODE_INVALID_FLOOD)
#define is_load_generator_mode() (load_mode != UCLIENT_LOAD_MODE_NONE)

void start_mclient(const char *remote_address, uint16_t port, const unsigned char *ifname, const char *local_address,
                   int messagenumber, int mclient);

int send_buffer(app_ur_conn_info *clnet_info, stun_buffer *message, bool data_connection, app_tcp_conn_info *atc);
int recv_buffer(app_ur_conn_info *clnet_info, stun_buffer *message, bool sync, bool data_connection,
                app_tcp_conn_info *atc, stun_buffer *request_message);

void client_input_handler(evutil_socket_t fd, short what, void *arg);

turn_credential_type get_turn_credentials_type(void);

int add_integrity(app_ur_conn_info *clnet_info, stun_buffer *message);
int check_integrity(app_ur_conn_info *clnet_info, stun_buffer *message);

SOCKET_TYPE get_socket_type(void);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__UCLIENT_ECHO__
