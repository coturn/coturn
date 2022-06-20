#if !defined(TURN_NO_PROMETHEUS)

#include "mainrelay.h"
#include "prom_server.h"

int prometheus_port = DEFAULT_PROM_SERVER_PORT;
ioa_addr prometheus_addr;

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

prom_gauge_t *turn_active_allocations;

int start_prometheus_server(void){
  if (turn_params.prometheus == PROM_DISABLED){
    return 1;
  }
  prom_collector_registry_default_init();

  const char *label[] = {"realm", NULL};
  size_t nlabels = 1;

  if (turn_params.prometheus_username_labels) {
    label[1] = "user";
    nlabels++;
  }

  // Create traffic counter metrics
  turn_traffic_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_rcvp", "Represents finished sessions received packets", nlabels, label));
  turn_traffic_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_rcvb", "Represents finished sessions received bytes", nlabels, label));
  turn_traffic_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_sentp", "Represents finished sessions sent packets", nlabels, label));
  turn_traffic_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_sentb", "Represents finished sessions sent bytes", nlabels, label));

  // Create finished sessions traffic for peers counter metrics
  turn_traffic_peer_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_rcvp", "Represents finished sessions peer received packets", nlabels, label));
  turn_traffic_peer_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_rcvb", "Represents finished sessions peer received bytes", nlabels, label));
  turn_traffic_peer_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_sentp", "Represents finished sessions peer sent packets", nlabels, label));
  turn_traffic_peer_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_sentb", "Represents finished sessions peer sent bytes", nlabels, label));

  // Create total finished traffic counter metrics
  turn_total_traffic_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_rcvp", "Represents total finished sessions received packets", 0, NULL));
  turn_total_traffic_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_rcvb", "Represents total finished sessions received bytes", 0, NULL));
  turn_total_traffic_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_sentp", "Represents total finished sessions sent packets", 0, NULL));
  turn_total_traffic_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_sentb", "Represents total finished sessions sent bytes", 0, NULL));

  // Create total finished sessions traffic for peers counter metrics
  turn_total_traffic_peer_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_rcvp", "Represents total finished sessions peer received packets", 0, NULL));
  turn_total_traffic_peer_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_rcvb", "Represents total finished sessions peer received bytes", 0, NULL));
  turn_total_traffic_peer_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_sentp", "Represents total finished sessions peer sent packets", 0, NULL));
  turn_total_traffic_peer_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_sentb", "Represents total finished sessions peer sent bytes", 0, NULL));

  // Create total active allocations gauge
  turn_active_allocations = prom_collector_registry_must_register_metric(prom_gauge_new("turn_active_allocations", "Number of currently active allocations", 0, NULL));

  promhttp_set_active_collector_registry(NULL);

  struct MHD_Daemon *daemon;
  int flags = MHD_USE_SELECT_INTERNALLY;
  void *arg;

  if (turn_params.prometheus == PROM_ENABLED) {
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
    return -1;
  }
  return 0;
}

void prom_set_finished_traffic(const char* realm, const char* user, unsigned long rsvp, unsigned long rsvb, unsigned long sentp, unsigned long sentb, bool peer){

  if (turn_params.prometheus > PROM_DISABLED){
    const char *label[] = {realm, NULL};
    if (turn_params.prometheus_username_labels){
      label[1] = user;
    }

    if (peer){
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

void prom_report_allocation_start(){
  if (turn_params.prometheus > PROM_DISABLED){
    prom_gauge_inc(turn_active_allocations, NULL);
  }
}

void prom_report_allocation_finish(){
  if (turn_params.prometheus > PROM_DISABLED){
    prom_gauge_dec(turn_active_allocations, NULL);
  }
}

#endif /* TURN_NO_PROMETHEUS */
