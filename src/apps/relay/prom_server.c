#include <microhttpd.h>

#include "prom_server.h"
#include "mainrelay.h"
#include "ns_turn_utils.h"

#if !defined(TURN_NO_PROMETHEUS)

prom_counter_t *stun_binding_request;
prom_counter_t *stun_binding_response;
prom_counter_t *stun_binding_error;

prom_counter_t *turn_traffic_rcvp;
prom_counter_t *turn_traffic_rcvb;
prom_counter_t *turn_traffic_sentp;
prom_counter_t *turn_traffic_sentb;

prom_counter_t *turn_traffic_peer_rcvp;
prom_counter_t *turn_traffic_peer_rcvb;
prom_counter_t *turn_traffic_peer_sentp;
prom_counter_t *turn_traffic_peer_sentb;

prom_gauge_t *turn_total_allocations;

void start_prometheus_server(void) {
	PROM_INIT_FLAGS features = PROM_PROCESS|PROM_SCRAPETIME_ALL;
  if (turn_params.prometheus == 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "prometheus collector disabled, not started\n");
    return;
  }
  if (turn_params.prometheus_compact)
	features |= PROM_COMPACT;
  if (pcr_init(features, "coturn_")) {
	TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "prometheus collector disabled - init failed.\n");
	turn_params.prometheus = 0;
	return;
  }

  const char *label[] = {"realm", NULL};
  size_t nlabels = 1;

  if (turn_params.prometheus_username_labels) {
    label[1] = "user";
    nlabels++;
  }

  // Create STUN counters
  stun_binding_request = pcr_must_register_metric(prom_counter_new(
	"bind_requests","Incoming STUN Binding requests", 0, NULL));
  stun_binding_response = pcr_must_register_metric(prom_counter_new(
	"bind_responses","Outgoing STUN Binding responses", 0, NULL));
  stun_binding_error = pcr_must_register_metric(prom_counter_new(
	"bind_errors","STUN Binding errors", 0, NULL));

  // Create TURN traffic counter metrics
  // see tcp_client_input_handler_rfc6062data()
  turn_traffic_rcvp = pcr_must_register_metric(prom_counter_new(
	"rx_msgs","Messages received in a session from the turn client.", nlabels, label));
  turn_traffic_peer_sentp = pcr_must_register_metric(prom_counter_new(
	"peer_tx_msgs","Messages sent in a session to the turn client.", nlabels, label));
  turn_traffic_rcvb = pcr_must_register_metric(prom_counter_new(
	"rx_bytes","Bytes received in a session from the turn client.", nlabels, label));
  turn_traffic_peer_sentb = pcr_must_register_metric(prom_counter_new(
	"peer_tx_bytes","Bytes sent in a session to the turn client.", nlabels, label));

  // Create finished sessions traffic for peers counter metrics
  // see tcp_peer_input_handler()
  turn_traffic_peer_rcvp = pcr_must_register_metric(prom_counter_new(
	"peer_rx_pkts","Messages received in a session from the peer.", nlabels, label));
  turn_traffic_sentp = pcr_must_register_metric(prom_counter_new(
	"tx_msgs","Messages sent in a session to the peer.", nlabels, label));
  turn_traffic_peer_rcvb = pcr_must_register_metric(prom_counter_new(
	"peer_rx_bytes","Bytes received in a session from peer.", nlabels, label));
  turn_traffic_sentb = pcr_must_register_metric(prom_counter_new(
	"tx_bytes","Bytes sent in a session to the peer.", nlabels, label));

  // Create total allocations number gauge metric
  const char *typeLabel[] = {"type"};
  turn_total_allocations = pcr_must_register_metric(prom_gauge_new(
	"allocations", "Current allocations", 1, typeLabel));

  promhttp_set_active_collector_registry(NULL);

  // some flags appeared first in microhttpd v0.9.53
  unsigned int flags;
#ifdef MHD_USE_AUTO
	flags = MHD_USE_AUTO;
	// EITHER
#	ifdef MHD_USE_INTERNAL_POLLING_THREAD
		flags |= MHD_USE_INTERNAL_POLLING_THREAD;   // EPOLL if avail or POLL
#	endif
	/* OR
#	ifdef MHD_USE_THREAD_PER_CONNECTION
		flags |= MHD_USE_THREAD_PER_CONNECTION;		// implies POLL
#	endif
	*/
#else
	flags = MHD_USE_POLL_INTERNALLY;				// internal polling thread
	/* OR
	flags = MHD_USE_THREAD_PER_CONNECTION;			// implies POLL
	*/
#endif
#ifdef MHD_USE_DEBUG
	flags |= MHD_USE_DEBUG;							// same as MHD_USE_ERROR_LOG
#endif

  struct MHD_Daemon *daemon = promhttp_start_daemon(flags, turn_params.prometheus_port, NULL, NULL);
  if (daemon == NULL) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "could not start prometheus collector\n");
    return;
  }

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "prometheus collector started successfully\n");

  return;
}

// This is total non-sense right now, because called at the end of a session,
// only. So would only appear as a tiny spike in a timeseries visualization.
void prom_set_finished_traffic(const char *realm, const char *user, unsigned long rsvp, unsigned long rsvb,
                               unsigned long sentp, unsigned long sentb, bool peer) {
  if (turn_params.prometheus == 1) {

    const char *label[] = {realm, NULL};
    if (turn_params.prometheus_username_labels) {
      label[1] = user;
    }

    if (peer) {
      prom_counter_add(turn_traffic_peer_rcvp, rsvp, label);
      prom_counter_add(turn_traffic_peer_rcvb, rsvb, label);
      prom_counter_add(turn_traffic_peer_sentp, sentp, label);
      prom_counter_add(turn_traffic_peer_sentb, sentb, label);
    } else {
      prom_counter_add(turn_traffic_rcvp, rsvp, label);
      prom_counter_add(turn_traffic_rcvb, rsvb, label);
      prom_counter_add(turn_traffic_sentp, sentp, label);
      prom_counter_add(turn_traffic_sentb, sentb, label);
    }
  }
}

void prom_inc_allocation(SOCKET_TYPE type) {
  if (turn_params.prometheus == 1) {
    const char *label[] = {socket_type_name(type)};
    prom_gauge_inc(turn_total_allocations, label);
  }
}

void prom_dec_allocation(SOCKET_TYPE type) {
  if (turn_params.prometheus == 1) {
    const char *label[] = {socket_type_name(type)};
    prom_gauge_dec(turn_total_allocations, label);
  }
}

void prom_inc_stun_binding_request(void) {
  if (turn_params.prometheus == 1) {
    prom_counter_add(stun_binding_request, 1, NULL);
  }
}

void prom_inc_stun_binding_response(void) {
  if (turn_params.prometheus == 1) {
    prom_counter_add(stun_binding_response, 1, NULL);
  }
}

void prom_inc_stun_binding_error(void) {
  if (turn_params.prometheus == 1) {
    prom_counter_add(stun_binding_error, 1, NULL);
  }
}

#else

void start_prometheus_server(void) {
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "turnserver compiled without prometheus support\n");
  return;
}

void prom_set_finished_traffic(const char *realm, const char *user, unsigned long rsvp, unsigned long rsvb,
                               unsigned long sentp, unsigned long sentb, bool peer) {
  UNUSED_ARG(realm);
  UNUSED_ARG(user);
  UNUSED_ARG(rsvp);
  UNUSED_ARG(rsvb);
  UNUSED_ARG(sentp);
  UNUSED_ARG(sentb);
  UNUSED_ARG(peer);
}

void prom_inc_allocation(SOCKET_TYPE type) { UNUSED_ARG(type); }

void prom_dec_allocation(SOCKET_TYPE type) { UNUSED_ARG(type); }

#endif /* TURN_NO_PROMETHEUS */
