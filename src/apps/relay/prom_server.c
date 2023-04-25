#include "prom_server.h"
#include "mainrelay.h"
#include "ns_turn_utils.h"

#if !defined(TURN_NO_PROMETHEUS)

int prometheus_port = DEFAULT_PROM_SERVER_PORT;
ioa_addr prometheus_addr;

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

prom_counter_t *turn_total_traffic_rcvp;
prom_counter_t *turn_total_traffic_rcvb;
prom_counter_t *turn_total_traffic_sentp;
prom_counter_t *turn_total_traffic_sentb;

prom_counter_t *turn_total_traffic_peer_rcvp;
prom_counter_t *turn_total_traffic_peer_rcvb;
prom_counter_t *turn_total_traffic_peer_sentp;
prom_counter_t *turn_total_traffic_peer_sentb;

prom_gauge_t *turn_total_allocations;

void start_prometheus_server(void) {
  if (turn_params.prometheus == PROM_DISABLED) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "prometheus collector disabled, not started\n");
    return;
  }
  prom_collector_registry_default_init();

  const char *label[] = {"realm", NULL};
  size_t nlabels = 1;

  if (turn_params.prometheus_username_labels) {
    label[1] = "user";
    nlabels++;
  }

  // Create STUN counters
  stun_binding_request = prom_collector_registry_must_register_metric(
      prom_counter_new("stun_binding_request", "Incoming STUN Binding requests", 0, NULL));
  stun_binding_response = prom_collector_registry_must_register_metric(
      prom_counter_new("stun_binding_response", "Outgoing STUN Binding responses", 0, NULL));
  stun_binding_error = prom_collector_registry_must_register_metric(
      prom_counter_new("stun_binding_error", "STUN Binding errors", 0, NULL));

  // Create TURN traffic counter metrics
  turn_traffic_rcvp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_rcvp", "Represents finished sessions received packets", nlabels, label));
  turn_traffic_rcvb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_rcvb", "Represents finished sessions received bytes", nlabels, label));
  turn_traffic_sentp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_sentp", "Represents finished sessions sent packets", nlabels, label));
  turn_traffic_sentb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_sentb", "Represents finished sessions sent bytes", nlabels, label));

  // Create finished sessions traffic for peers counter metrics
  turn_traffic_peer_rcvp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_peer_rcvp", "Represents finished sessions peer received packets", nlabels, label));
  turn_traffic_peer_rcvb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_peer_rcvb", "Represents finished sessions peer received bytes", nlabels, label));
  turn_traffic_peer_sentp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_peer_sentp", "Represents finished sessions peer sent packets", nlabels, label));
  turn_traffic_peer_sentb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_traffic_peer_sentb", "Represents finished sessions peer sent bytes", nlabels, label));

  // Create total finished traffic counter metrics
  turn_total_traffic_rcvp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_rcvp", "Represents total finished sessions received packets", 0, NULL));
  turn_total_traffic_rcvb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_rcvb", "Represents total finished sessions received bytes", 0, NULL));
  turn_total_traffic_sentp = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_sentp", "Represents total finished sessions sent packets", 0, NULL));
  turn_total_traffic_sentb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_sentb", "Represents total finished sessions sent bytes", 0, NULL));

  // Create total finished sessions traffic for peers counter metrics
  turn_total_traffic_peer_rcvp = prom_collector_registry_must_register_metric(prom_counter_new(
      "turn_total_traffic_peer_rcvp", "Represents total finished sessions peer received packets", 0, NULL));
  turn_total_traffic_peer_rcvb = prom_collector_registry_must_register_metric(prom_counter_new(
      "turn_total_traffic_peer_rcvb", "Represents total finished sessions peer received bytes", 0, NULL));
  turn_total_traffic_peer_sentp = prom_collector_registry_must_register_metric(prom_counter_new(
      "turn_total_traffic_peer_sentp", "Represents total finished sessions peer sent packets", 0, NULL));
  turn_total_traffic_peer_sentb = prom_collector_registry_must_register_metric(
      prom_counter_new("turn_total_traffic_peer_sentb", "Represents total finished sessions peer sent bytes", 0, NULL));

  // Create total allocations number gauge metric
  const char *typeLabel[] = {"type"};
  turn_total_allocations = prom_collector_registry_must_register_metric(
      prom_gauge_new("turn_total_allocations", "Represents current allocations number", 1, typeLabel));

  promhttp_set_active_collector_registry(NULL);

  // some flags appeared first in microhttpd v0.9.53
  unsigned int flags = 0;
#if MHD_VERSION >= 0x00095300
  flags |= MHD_USE_ERROR_LOG;
#endif

  if (MHD_is_feature_supported(MHD_FEATURE_EPOLL)) {
#if MHD_VERSION >= 0x00095300
    flags |= MHD_USE_EPOLL_INTERNAL_THREAD;
#else
    flags |= MHD_USE_EPOLL_INTERNALLY_LINUX_ONLY; // old versions of microhttpd
#endif
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "prometheus exporter server will start using EPOLL\n");
  } else {
    flags |= MHD_USE_SELECT_INTERNALLY;
    // Select() will not work if all 1024 first file-descriptors are used.
    // In this case the prometheus server will be unreachable
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "prometheus exporter server will start using SELECT. "
                                          "The exporter might be unreachable on highly used servers\n");
  }
  
  struct MHD_Daemon *daemon;
  void *arg;

  if (turn_params.prometheus == PROM_ENABLED) {
    flags |= MHD_USE_DUAL_STACK;
    daemon = promhttp_start_daemon(flags, prometheus_port, NULL, NULL);
  } else {
    // turn_params.prometheus == PROM_ENABLED_WITH_IP

    addr_set_port(&prometheus_addr, prometheus_port);

    if (prometheus_addr.ss.sa_family == AF_INET6) {
      flags |= MHD_USE_IPv6;
      arg = &prometheus_addr.s6;
    } else {
      arg = &prometheus_addr.s4;
    }

    daemon = promhttp_start_daemon_with_options(flags, 0, NULL, NULL, MHD_OPTION_SOCK_ADDR, arg, MHD_OPTION_END);
  }  

  if (daemon == NULL) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "could not start prometheus collector\n");
    return;
  }

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "prometheus collector started successfully\n");

  return;
}

void prom_set_finished_traffic(const char* realm, const char* user, unsigned long rsvp, unsigned long rsvb,
                               unsigned long sentp, unsigned long sentb, bool peer) {
  if (turn_params.prometheus > PROM_DISABLED) {

    const char *label[] = {realm, NULL};
    if (turn_params.prometheus_username_labels) {
      label[1] = user;
    }

    if (peer) {
      prom_counter_add(turn_traffic_peer_rcvp, rsvp, label);
      prom_counter_add(turn_traffic_peer_rcvb, rsvb, label);
      prom_counter_add(turn_traffic_peer_sentp, sentp, label);
      prom_counter_add(turn_traffic_peer_sentb, sentb, label);

      prom_counter_add(turn_total_traffic_peer_rcvp, rsvp, NULL);
      prom_counter_add(turn_total_traffic_peer_rcvb, rsvb, NULL);
      prom_counter_add(turn_total_traffic_peer_sentp, sentp, NULL);
      prom_counter_add(turn_total_traffic_peer_sentb, sentb, NULL);
    } else {
      prom_counter_add(turn_traffic_rcvp, rsvp, label);
      prom_counter_add(turn_traffic_rcvb, rsvb, label);
      prom_counter_add(turn_traffic_sentp, sentp, label);
      prom_counter_add(turn_traffic_sentb, sentb, label);

      prom_counter_add(turn_total_traffic_rcvp, rsvp, NULL);
      prom_counter_add(turn_total_traffic_rcvb, rsvb, NULL);
      prom_counter_add(turn_total_traffic_sentp, sentp, NULL);
      prom_counter_add(turn_total_traffic_sentb, sentb, NULL);
    }
  }
}

void prom_inc_allocation(SOCKET_TYPE type) {
  if (turn_params.prometheus > PROM_DISABLED) {
    const char *label[] = {socket_type_name(type)};
    prom_gauge_inc(turn_total_allocations, label);
  }
}

void prom_dec_allocation(SOCKET_TYPE type) {
  if (turn_params.prometheus > PROM_DISABLED) {
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
  if (turn_params.prometheus > PROM_DISABLED) {
    prom_counter_add(stun_binding_response, 1, NULL);
  }
}

void prom_inc_stun_binding_error(void) {
  if (turn_params.prometheus > PROM_DISABLED) {
    prom_counter_add(stun_binding_error, 1, NULL);
  }
}

#else

void start_prometheus_server(void) {
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "turnserver compiled without prometheus support\n");
  return;
}

#endif /* TURN_NO_PROMETHEUS */
