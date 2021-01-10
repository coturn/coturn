#if !defined(TURN_NO_PROMETHEUS)

#include "mainrelay.h"
#include "prom_server.h"


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


int start_prometheus_server(void){
  if (turn_params.prometheus == 0){
    return 1;
  }
  prom_collector_registry_default_init();
  
  const char *label[] = {"realm", "user"};

  // Create traffic counter metrics
  turn_traffic_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_rcvp", "Represents finsihed sessions received packets", 2, label));
  turn_traffic_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_rcvb", "Represents finsihed sessions received bytes", 2, label));
  turn_traffic_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_sentp", "Represents finsihed sessions sent packets", 2, label));
  turn_traffic_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_sentb", "Represents finsihed sessions sent bytes", 2, label));

  // Create finsihed sessions traffic for peers counter metrics
  turn_traffic_peer_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_rcvp", "Represents finsihed sessions peer received packets", 2, label));
  turn_traffic_peer_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_rcvb", "Represents finsihed sessions peer received bytes", 2, label));
  turn_traffic_peer_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_sentp", "Represents finsihed sessions peer sent packets", 2, label));
  turn_traffic_peer_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_sentb", "Represents finsihed sessions peer sent bytes", 2, label));

  // Create total finished traffic counter metrics
  turn_total_traffic_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_rcvp", "Represents total finsihed sessions received packets", 0, NULL));
  turn_total_traffic_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_rcvb", "Represents total finsihed sessions received bytes", 0, NULL));
  turn_total_traffic_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_sentp", "Represents total finsihed sessions sent packets", 0, NULL));
  turn_total_traffic_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_sentb", "Represents total finsihed sessions sent bytes", 0, NULL));

  // Create total finsihed sessions traffic for peers counter metrics
  turn_total_traffic_peer_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_rcvp", "Represents total finsihed sessions peer received packets", 0, NULL));
  turn_total_traffic_peer_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_rcvb", "Represents total finsihed sessions peer received bytes", 0, NULL));
  turn_total_traffic_peer_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_sentp", "Represents total finsihed sessions peer sent packets", 0, NULL));
  turn_total_traffic_peer_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_sentb", "Represents total finsihed sessions peer sent bytes", 0, NULL));

  promhttp_set_active_collector_registry(NULL);


  struct MHD_Daemon *daemon = promhttp_start_daemon(MHD_USE_SELECT_INTERNALLY, DEFAULT_PROM_SERVER_PORT, NULL, NULL);
  if (daemon == NULL) {
    return 1;
  }
  return 0;
}

void prom_set_finished_traffic(const char* realm, const char* user, unsigned long rsvp, unsigned long rsvb, unsigned long sentp, unsigned long sentb, bool peer){
  if (turn_params.prometheus == 1){

    const char *label[] = {realm, user};

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

#endif /* TURN_NO_PROMETHEUS */
