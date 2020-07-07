#if !defined(TURN_NO_PROMETHEUS)

#include "mainrelay.h"
#include "prom_server.h"

int start_prometheus_server(void){
  if (turn_params.prometheus == 0){
    return 0;
  }
  prom_collector_registry_default_init();
  // Create status gauge metric
  turn_status = prom_collector_registry_must_register_metric(prom_gauge_new("turn_status", "Represents status", 5, (const char *[]) {"realm", "user", "allocation", "status", "lifetime" }));

  // Create traffic gauge metrics
  turn_traffic_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_rcvp", "Represents received packets", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_traffic_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_rcvb", "Represents received bytes", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_traffic_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_sentp", "Represents sent packets", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_traffic_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_sentb", "Represents sent bytes", 3, (const char *[]) {"realm", "user", "allocation" }));

  // Create traffic for peers gauge metrics
  turn_traffic_peer_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_rcvp", "Represents peer received packets", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_traffic_peer_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_rcvb", "Represents peer received bytes", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_traffic_peer_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_sentp", "Represents peer sent packets", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_traffic_peer_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_traffic_peer_sentb", "Represents peer sent bytes", 3, (const char *[]) {"realm", "user", "allocation" }));

  // Create total traffic gauge metrics
  turn_total_traffic_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_rcvp", "Represents total received packets", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_total_traffic_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_rcvb", "Represents total received bytes", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_total_traffic_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_sentp", "Represents total sent packets", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_total_traffic_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_sentb", "Represents total sent bytes", 3, (const char *[]) {"realm", "user", "allocation" }));

  // Create tota traffic for peers gauge metrics
  turn_total_traffic_peer_rcvp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_rcvp", "Represents total peer received packets", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_total_traffic_peer_rcvb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_rcvb", "Represents total peer received bytes", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_total_traffic_peer_sentp = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_sentp", "Represents total peer sent packets", 3, (const char *[]) {"realm", "user", "allocation" }));
  turn_total_traffic_peer_sentb = prom_collector_registry_must_register_metric(prom_counter_new("turn_total_traffic_peer_sentb", "Represents total peer sent bytes", 3, (const char *[]) {"realm", "user", "allocation" }));

  promhttp_set_active_collector_registry(NULL);


  struct MHD_Daemon *daemon = promhttp_start_daemon(MHD_USE_SELECT_INTERNALLY, DEFAULT_PROM_SERVER_PORT, NULL, NULL);
  if (daemon == NULL) {
    return 1;
  }
  return 0;
}

void prom_set_status(const char* realm, const char* user, unsigned long long allocation, const char* status, unsigned long lifetime){
  if (turn_params.prometheus == 1){
    char allocation_chars[1024];
    char lifetime_chars[1024];

    snprintf(allocation_chars, sizeof(allocation_chars), "%018llu", allocation);
    snprintf(lifetime_chars, sizeof(lifetime_chars), "%lu", lifetime);

    prom_gauge_add(turn_status, 1, (const char *[]) { realm , user, allocation_chars, status, lifetime_chars });
  }
}

void prom_del_status(const char* realm, const char* user, unsigned long long allocation, const char* status){
  if (turn_params.prometheus == 0){
    char allocation_chars[1024];
    snprintf(allocation_chars, sizeof(allocation_chars), "%018llu", allocation);

    prom_gauge_sub(turn_status, 1, (const char *[]) { realm , user, allocation_chars, (char *)"new", (char *)"600" });
    prom_gauge_add(turn_status, 1, (const char *[]) { realm , user, allocation_chars, status, NULL });
  }
}
void prom_set_traffic(const char* realm, const char* user, unsigned long long allocation, unsigned long rsvp, unsigned long rsvb, unsigned long sentp, unsigned long sentb, bool peer){
  if (turn_params.prometheus == 1){
    char allocation_chars[1024];
    snprintf(allocation_chars, sizeof(allocation_chars), "%018llu", allocation);

    if (peer){
      prom_counter_add(turn_traffic_peer_rcvp, rsvp, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_traffic_peer_rcvb, rsvb, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_traffic_peer_sentp, sentp, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_traffic_peer_sentb, sentb, (const char *[]) { realm , user, allocation_chars });
    } else {
      prom_counter_add(turn_traffic_rcvp, rsvp, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_traffic_rcvb, rsvb, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_traffic_sentp, sentp, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_traffic_sentb, sentb, (const char *[]) { realm , user, allocation_chars });
    }
  }
}

void prom_set_total_traffic(const char* realm, const char* user, unsigned long long allocation, unsigned long rsvp, unsigned long rsvb, unsigned long sentp, unsigned long sentb, bool peer){
  if (turn_params.prometheus == 1){
    char allocation_chars[1024];
    snprintf(allocation_chars, sizeof(allocation_chars), "%018llu", allocation);

    if (peer){
      prom_counter_add(turn_total_traffic_peer_rcvp, rsvp, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_total_traffic_peer_rcvb, rsvb, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_total_traffic_peer_sentp, sentp, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_total_traffic_peer_sentb, sentb, (const char *[]) { realm , user, allocation_chars });
    } else {
      prom_counter_add(turn_total_traffic_rcvp, rsvp, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_total_traffic_rcvb, rsvb, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_total_traffic_sentp, sentp, (const char *[]) { realm , user, allocation_chars });
      prom_counter_add(turn_total_traffic_sentb, sentb, (const char *[]) { realm , user, allocation_chars });
    }
  }
}

#endif /* TURN_NO_PROMETHEUS */
