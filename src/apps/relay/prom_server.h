/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2020 Miquel Ortega
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

#ifndef __PROM_SERVER_H__
#define __PROM_SERVER_H__

#include "ns_turn_ioalib.h"
#include <stdbool.h>
#include <stdlib.h>

#if !defined(_MSC_VER)
#include <unistd.h>
#endif

#define DEFAULT_PROM_SERVER_PORT (9641)
#define TURN_ALLOC_STR_MAX_SIZE (20)

#if !defined(TURN_NO_PROMETHEUS)

#ifdef __cplusplus
extern "C" {
#endif

#include <microhttpd.h>

/* Vendored, self-contained Prometheus client (src/prometheus). */
#include "prom.h"

#ifdef __cplusplus
}
#endif /* __clplusplus */

extern prom_counter_t *packet_processed;
extern prom_counter_t *packet_dropped;

extern prom_counter_t *stun_binding_request;
extern prom_counter_t *stun_binding_response;
extern prom_counter_t *stun_binding_error;

extern prom_counter_t *turn_new_allocation;
extern prom_counter_t *turn_refreshed_allocation;
extern prom_counter_t *turn_deleted_allocation;

extern prom_counter_t *turn_traffic_rcvp;
extern prom_counter_t *turn_traffic_rcvb;
extern prom_counter_t *turn_traffic_sentp;
extern prom_counter_t *turn_traffic_sentb;

extern prom_counter_t *turn_traffic_peer_rcvp;
extern prom_counter_t *turn_traffic_peer_rcvb;
extern prom_counter_t *turn_traffic_peer_sentp;
extern prom_counter_t *turn_traffic_peer_sentb;

extern prom_counter_t *turn_total_traffic_rcvp;
extern prom_counter_t *turn_total_traffic_rcvb;
extern prom_counter_t *turn_total_traffic_sentp;
extern prom_counter_t *turn_total_traffic_sentb;

extern prom_counter_t *turn_total_traffic_peer_rcvp;
extern prom_counter_t *turn_total_traffic_peer_rcvb;
extern prom_counter_t *turn_total_traffic_peer_sentp;
extern prom_counter_t *turn_total_traffic_peer_sentb;

extern prom_gauge_t *turn_total_allocations_number;

/* Linux UDP recvmmsg/sendmmsg batching. Counters are bumped once per syscall
 * (not per datagram), so average batch size is rate(packets)/rate(calls) and
 * rate(datagrams)/rate(flushes) in PromQL — cheap to expose, cheap to scrape. */
extern prom_counter_t *turn_udp_recvmmsg_calls;
extern prom_counter_t *turn_udp_recvmmsg_packets;
extern prom_counter_t *turn_udp_sendmmsg_flushes;
extern prom_counter_t *turn_udp_sendmmsg_datagrams;
extern prom_counter_t *turn_udp_sendmmsg_gso_datagrams;

int is_ipv6_enabled(void);

void prom_inc_stun_binding_request(void);
void prom_inc_stun_binding_response(void);
void prom_inc_stun_binding_error(void);

#endif /* !defined(TURN_NO_PROMETHEUS) */

void start_prometheus_server(void);

void prom_set_finished_traffic(const char *realm, const char *user, unsigned long rsvp, unsigned long rsvb,
                               unsigned long sentp, unsigned long sentb, bool peer);

void prom_inc_allocation(SOCKET_TYPE type);
void prom_dec_allocation(SOCKET_TYPE type);

/* Per-engine deltas accumulated lock-free on the relay hot path and flushed
 * into the shared prometheus counters once per second (see timer_handler).
 * Defined unconditionally so callers compile regardless of TURN_NO_PROMETHEUS. */
struct prom_udp_counter_deltas {
  uint64_t packets_processed;
  uint64_t packets_dropped;
  uint64_t recvmmsg_calls;
  uint64_t recvmmsg_packets;
  uint64_t sendmmsg_flushes;
  uint64_t sendmmsg_datagrams;
  uint64_t sendmmsg_gso_datagrams;
};

/* Add the given non-zero deltas to the shared prometheus counters.
 * No-op when prometheus is disabled or compiled out. */
void prom_flush_udp_counters(const struct prom_udp_counter_deltas *d);

#endif /* __PROM_SERVER_H__ */
