
#ifndef __PROM_SERVER_H__
#define __PROM_SERVER_H__

#include "ns_turn_ioalib.h"
#include <stdbool.h>

#define DEFAULT_PROM_SERVER_PORT (9641)
#define TURN_ALLOC_STR_MAX_SIZE (20)

#if !defined(TURN_NO_PROMETHEUS)

#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <microhttpd.h>
#include <prom.h>
#ifdef __cplusplus
}
#endif /* __clplusplus */

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

#ifdef __cplusplus
extern "C" {
#endif

void start_prometheus_server(void);

void prom_set_finished_traffic(const char *realm, const char *user, unsigned long rsvp, unsigned long rsvb,
                               unsigned long sentp, unsigned long sentb, bool peer);

void prom_inc_allocation(SOCKET_TYPE type);
void prom_dec_allocation(SOCKET_TYPE type);

int is_ipv6_enabled(void);

void prom_inc_stun_binding_request(void);
void prom_inc_stun_binding_response(void);
void prom_inc_stun_binding_error(void);

#else

void start_prometheus_server(void);

void prom_set_finished_traffic(const char *realm, const char *user, unsigned long rsvp, unsigned long rsvb,
                               unsigned long sentp, unsigned long sentb, bool peer);

void prom_inc_allocation(SOCKET_TYPE type);
void prom_dec_allocation(SOCKET_TYPE type);

#endif /* TURN_NO_PROMETHEUS */

#ifdef __cplusplus
}
#endif /* __clplusplus */

#endif /* __PROM_SERVER_H__ */
