
#ifndef __PROM_SERVER_H__
#define __PROM_SERVER_H__

#if !defined(TURN_NO_PROMETHEUS)

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <microhttpd.h>
#include <prom.h>
#include <promhttp.h>
#ifdef __cplusplus
}
#endif /* __clplusplus */

#define DEFAULT_PROM_SERVER_PORT (9641)

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

#define TURN_ALLOC_STR_MAX_SIZE (20)

#ifdef __cplusplus
extern "C" {
#endif


int start_prometheus_server(void);

void prom_set_finished_traffic(const char* realm, const char* user, unsigned long rsvp, unsigned long rsvb, unsigned long sentp, unsigned long sentb, bool peer);

#endif /* TURN_NO_PROMETHEUS */

#ifdef __cplusplus
}
#endif /* __clplusplus */

#endif /* __PROM_SERVER_H__ */