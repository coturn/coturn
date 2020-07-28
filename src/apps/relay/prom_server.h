
#ifndef __PROM_SERVER_H__
#define __PROM_SERVER_H__

#if !defined(TURN_NO_PROMETHEUS)

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include <microhttpd.h>
#include <prom.h>
#include <promhttp.h>

#define DEFAULT_PROM_SERVER_PORT (9641)

prom_gauge_t *turn_status;

prom_gauge_t *turn_traffic_rcvp;
prom_gauge_t *turn_traffic_rcvb;
prom_gauge_t *turn_traffic_sentp;
prom_gauge_t *turn_traffic_sentb;

prom_gauge_t *turn_total_traffic_rcvp;
prom_gauge_t *turn_total_traffic_rcvb;
prom_gauge_t *turn_total_traffic_sentp;
prom_gauge_t *turn_total_traffic_sentb;

prom_gauge_t *turn_traffic_peer_rcvp;
prom_gauge_t *turn_traffic_peer_rcvb;
prom_gauge_t *turn_traffic_peer_sentp;
prom_gauge_t *turn_traffic_peer_sentb;

prom_gauge_t *turn_total_traffic_peer_rcvp;
prom_gauge_t *turn_total_traffic_peer_rcvb;
prom_gauge_t *turn_total_traffic_peer_sentp;
prom_gauge_t *turn_total_traffic_peer_sentb;

#ifdef __cplusplus
extern "C" {
#endif


int start_prometheus_server(void);

void prom_set_status(const char* realm, const char* user, unsigned long long allocation, const char* status, unsigned long lifetime);
void prom_del_status(const char* realm, const char* user, unsigned long long allocation, const char* status);
void prom_set_traffic(const char* realm, const char* user, unsigned long long allocation, unsigned long rsvp, unsigned long rsvb, unsigned long sentp, unsigned long sentb, bool peer);
void prom_set_total_traffic(const char* realm, const char* user, unsigned long long allocation, unsigned long rsvp, unsigned long rsvb, unsigned long sentp, unsigned long sentb, bool peer);

#endif /* TURN_NO_PROMETHEUS */

#ifdef __cplusplus
}
#endif /* __clplusplus */

#endif /* __PROM_SERVER_H__ */