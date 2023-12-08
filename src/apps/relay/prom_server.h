
#ifndef __PROM_SERVER_H__
#define __PROM_SERVER_H__

#include "ns_turn_ioalib.h"
#include <stdbool.h>

#define DEFAULT_PROM_SERVER_PORT 9641
#define DEFAULT_PROM_SID_RETAIN 60
#define TURN_ALLOC_STR_MAX_SIZE (20)

#if !defined(TURN_NO_PROMETHEUS)

#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <libprom/prom.h>
#include <libprom/promhttp.h>
#ifdef __cplusplus
}
#endif /* __clplusplus */

extern prom_counter_t *stun_binding_request;
extern prom_counter_t *stun_binding_response;
extern prom_counter_t *stun_binding_error;

extern prom_counter_t *turn_rx_msgs;
extern prom_counter_t *turn_rx_bytes;
extern prom_counter_t *turn_tx_msgs;
extern prom_counter_t *turn_tx_bytes;
extern prom_gauge_t *turn_lifetime;
extern prom_gauge_t *turn_allocations;

typedef enum {
  METRIC_RX_MSGS,
  METRIC_TX_MSGS,
  METRIC_RX_BYTES,
  METRIC_TX_BYTES,
  METRIC_LIFETIME,
  METRIC_ALLOCATIONS_RUNNING,
  METRIC_ALLOCATIONS_CREATED,
  METRIC_STUN_REQUEST,
  METRIC_STUN_RESPONSE,
  METRIC_STUN_ERROR,
  METRIC_MAX
} session_metric_t;

#ifdef __cplusplus
extern "C" {
#endif

void start_prometheus_server(void);

pms_t *get_state_sample(int32_t tid, int32_t sid, uint64_t usid, char *realm, char *user);
pms_t *get_session_sample(session_metric_t type, bool peer, int32_t tid, int32_t sid, uint64_t usid);

void prom_binding_error(int32_t tid, int32_t sid, uint64_t usid, int error);

#else

void start_prometheus_server(void);

#endif /* TURN_NO_PROMETHEUS */

bool prom_disabled(void);
bool prom_rsids(void);

#ifdef __cplusplus
}
#endif /* __clplusplus */

#endif /* __PROM_SERVER_H__ */
