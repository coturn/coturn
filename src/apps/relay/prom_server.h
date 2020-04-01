
#ifndef __PROM_SERVER_H__
#define __PROM_SERVER_H__

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <microhttpd.h>
#include <prom.h>
#include <promhttp.h>

#define DEFAULT_PROM_SERVER_PORT (9121)

prom_gauge_t *turn_status;
prom_gauge_t *turn_traffic_rcvp;
prom_gauge_t *turn_traffic_rcvb;
prom_gauge_t *turn_traffic_sentp;
prom_gauge_t *turn_traffic_sentb;
prom_gauge_t *turn_traffic_peer_rcvp;
prom_gauge_t *turn_traffic_peer_rcvb;
prom_gauge_t *turn_traffic_peer_sentp;
prom_gauge_t *turn_traffic_peer_sentb;

#ifdef __cplusplus
extern "C" {
#endif

int start_prometheus_server(void);

void prom_set_status(const char* realm, const char* user, unsigned long long allocation, const char* status, unsigned long lifetime);
void prom_del_status(const char* realm, const char* user, unsigned long long allocation, const char* status);
void prom_set_rcvp(const char* realm, const char* user, unsigned long long allocation, unsigned long rsvp);
void prom_set_rcvb(const char* realm, const char* user, unsigned long long allocation, unsigned long rsvb);
void prom_set_sentp(const char* realm, const char* user, unsigned long long allocation, unsigned long sentp);
void prom_set_sentb(const char* realm, const char* user, unsigned long long allocation, unsigned long sentb);
void prom_set_peer_rcvp(const char* realm, const char* user, unsigned long long allocation, unsigned long rsvp);
void prom_set_peer_rcvb(const char* realm, const char* user, unsigned long long allocation, unsigned long rsvb);
void prom_set_peer_sentp(const char* realm, const char* user, unsigned long long allocation, unsigned long sentp);
void prom_set_peer_sentb(const char* realm, const char* user, unsigned long long allocation, unsigned long sentb);



#ifdef __cplusplus
}
#endif /* __clplusplus */

#endif /* __PROM_SERVER_H__ */