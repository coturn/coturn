#include <microhttpd.h>

#include "prom_server.h"
#include "mainrelay.h"
#include "ns_turn_utils.h"

#if !defined(TURN_NO_PROMETHEUS)

prom_counter_t *stun_binding_request = NULL;
prom_counter_t *stun_binding_response = NULL;
prom_counter_t *stun_binding_error = NULL;

prom_counter_t *turn_rx_msgs = NULL;
prom_counter_t *turn_rx_bytes = NULL;
prom_counter_t *turn_tx_msgs = NULL;
prom_counter_t *turn_tx_bytes = NULL;

prom_gauge_t *turn_lifetime = NULL;	// -1 .. closed, otherwise lifetime [s]
prom_gauge_t *turn_allocations = NULL;
prom_gauge_t *turn_state = NULL;

static bool is_prom_enabled = false;
bool prom_disabled(void) { return !is_prom_enabled; }

static bool use_rsids = false;
bool prom_rsids(void) { return use_rsids; }

// metrics need to have the same labels over their whole lifetime, which means
// here, over the lifetime of the app. Therefore labels get calculated once
// on server startup an d reused as needed.
#define LABEL_PEER "peer"
#define LABEL_REALM "realm"
#define LABEL_USER "user"
#define LABEL_TURNSERVER_ID "tid"
#define LABEL_SESSION_ID "sid"
#define LABEL_STUN_ERR "code"
#define LABEL_ALLOCATIONS "created"

static const char **state_labels;
static size_t state_label_count;
static bool use_sid_labels = true;

static const char *session_labels[] =
	{ LABEL_TURNSERVER_ID, LABEL_SESSION_ID, LABEL_PEER };
static size_t session_label_count = 3;

static bool
init_state_labels(void) {
	size_t n;

	if (turn_params.prom_usid && turn_params.prom_rsid) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "prom-sid takes precedence "
		"over prom-usid. Metrics get tagged with dynamic session IDs to save"
		"resources and hopefully keep your timeseries DB happy.\n");
		turn_params.prom_usid = 0;
	}
	if (!turn_params.prom_rsid && !turn_params.prom_usid) {
		use_sid_labels = false;
		if (!turn_params.prom_usernames) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Neither prom-usid nor "
			"prom-sid nor prom-usernames is given (makes your server safe "
			"wrt. too many metrics attacks): session_state and lifetime "
			"metrics get not enabled.\n");
		}
		state_label_count = 0; // use as indicator for state n/a
		return false;
	}

	state_label_count = turn_params.prom_realm + turn_params.prom_usernames
      + (use_sid_labels ? 2 : 1);

	state_labels = (const char **)
		malloc(state_label_count * sizeof(const char *));
	if (state_labels == NULL) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
			"Memory problem - metric collector disabled - init failed.\n");
		state_label_count = 0;
		turn_params.prom = 0;
		return false;
	}
    n = 0;
	state_labels[n++] = LABEL_TURNSERVER_ID;
	if (use_sid_labels)
		state_labels[n++] = LABEL_SESSION_ID;
	if (turn_params.prom_realm)
		state_labels[n++] = LABEL_REALM;
	if (turn_params.prom_usernames)
		state_labels[n++] = LABEL_USER;
	return true;
}

static void
init_metrics(void) {
  const char *str;

  prom_metric_t *version = pcr_must_register_metric(prom_gauge_new(
	"version","TURN server version.", 2,(const char *[]) {"name", "release"}));
  prom_gauge_set(version, 1, (const char *[]) {"Coturn",TURN_SERVER_VERSION});

  if (init_state_labels()) {
    turn_state = pcr_must_register_metric(prom_gauge_new(
      "session_state", "The state of a client or peer session. "
      "0 .. closed, 1 .. allocation deleted, 2 .. closing, 3 .. open, "
	  "4 .. allocation created, 5 .. allocation refresh seen.",
      state_label_count, state_labels));
  }

  if (!use_sid_labels) {
    session_labels[--session_label_count] = NULL;
    session_labels[session_label_count - 1] = LABEL_PEER;
  } else if (turn_params.prom_rsid) {
	use_rsids = true;
  }

  // Create TURN traffic counter metrics
  turn_rx_msgs = pcr_must_register_metric(prom_counter_new(
	"rx_msgs","Messages received from the turn client or peer.",
	session_label_count, session_labels));
  turn_tx_msgs = pcr_must_register_metric(prom_counter_new(
	"tx_msgs","Messages sent to the turn client or peer.",
	session_label_count, session_labels));
  turn_rx_bytes = pcr_must_register_metric(prom_counter_new(
	"rx_bytes","Bytes received from the turn client or peer.",
	session_label_count, session_labels));
  turn_tx_bytes = pcr_must_register_metric(prom_counter_new(
	"tx_bytes","Bytes sent to the turn client or peer.",
	session_label_count, session_labels));

  // Create total allocations number gauge metric
  // use peer as total label
  str = session_labels[session_label_count - 1];
  session_labels[session_label_count - 1] = LABEL_ALLOCATIONS;
  turn_allocations = pcr_must_register_metric(prom_gauge_new(
	"allocations", "Current allocations",
	session_label_count, session_labels));
  session_labels[session_label_count - 1] = str;

  if (use_sid_labels)
	turn_lifetime = pcr_must_register_metric(prom_gauge_new(
	"lifetime", "The life time of a client's allocation.",
	session_label_count - 1, session_labels));

  // Create STUN counters
  if (!turn_params.no_stun) {
    stun_binding_request = pcr_must_register_metric(prom_counter_new(
      "bind_requests","Valid STUN Binding requests received.",
      session_label_count - 1, session_labels));
    stun_binding_response = pcr_must_register_metric(prom_counter_new(
      "bind_responses","STUN Binding responses sent.",
      session_label_count - 1, session_labels));

    // use peer as error label
    str = session_labels[session_label_count - 1];
    session_labels[session_label_count - 1] = LABEL_STUN_ERR;
    stun_binding_error = pcr_must_register_metric(prom_counter_new(
      "bind_errors","STUN Binding errors",
      session_label_count, session_labels));
    session_labels[session_label_count - 1] = str;
  }

  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Metrics initialized.\n");
}

void start_prometheus_server(void) {
  PROM_INIT_FLAGS features = PROM_PROCESS|PROM_SCRAPETIME_ALL;
  if (turn_params.prom == 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Metric collector disabled, not started.\n");
    return;
  }

  if (turn_params.prom_compact)
	features |= PROM_COMPACT;
  if (pcr_init(features, "coturn_")) {
	TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Metric collector disabled - init failed.\n");
	turn_params.prom = 0;
	return;
  }

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

  struct MHD_Daemon *daemon = promhttp_start_daemon(flags, turn_params.prom_port, NULL, NULL);
  if (daemon == NULL) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Could not start metric exporter.\n");
    return;
  }
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Metric exporter started successfully.\n");

  init_metrics();
  is_prom_enabled = true;
  return;
}

	//bool peer, int32_t tid, int32_t sid, uint64_t usid)
#define PREPARE_TID_SID_PEER_LABELS(DST, TID, SID, USID, PEER) \
	char tidstr[12]; \
	char sidstr[12]; \
	int n = 0; \
 \
	sprintf(tidstr, "%d", TID); \
	DST[n++] = tidstr; \
	if (use_sid_labels) { \
		if (turn_params.prom_rsid) { \
			sprintf(sidstr, "%d", SID); \
		} else if (turn_params.prom_usid) { \
			/* uint64_t l = USID/TURN_SESSION_ID_FACTOR; sprintf(tidstr,"%ld",l);*/ \
			/* sprintf(sidstr, "%lld", USID - (l * TURN_SESSION_ID_FACTOR)); */ \
			sprintf(sidstr, "%lld", USID - (TID * TURN_SESSION_ID_FACTOR)); \
		} \
		DST[n++] = sidstr; \
	} \
	DST[n++] = PEER ? "1" : "0"; \

pms_t *
get_state_sample(int32_t tid, int32_t sid, uint64_t usid,
	char *realm, char *user)
{
	const char *vals[state_label_count + 1]; // + dummy for peer
	pms_t *res = NULL;

	if (state_label_count == 0 || prom_disabled())
		return NULL;

	PREPARE_TID_SID_PEER_LABELS(vals, tid, sid, usid, false);
	if (turn_params.prom_realm)
		vals[state_label_count-2] = realm;
	if (turn_params.prom_usernames)
		vals[state_label_count-1] = user;

	res = pms_from_labels(turn_state, vals);
	return res;
}

pms_t *
get_session_sample(session_metric_t type, bool peer,
	int32_t tid, int32_t sid, uint64_t usid)
{
	const char *vals[session_label_count];

	if (prom_disabled())
		return NULL;

	PREPARE_TID_SID_PEER_LABELS(vals, tid, sid, usid, peer);

	switch (type) {
		case METRIC_RX_MSGS:
			return pms_from_labels(turn_rx_msgs, vals);
		case METRIC_TX_MSGS:
			return pms_from_labels(turn_tx_msgs, vals);
		case METRIC_RX_BYTES:
			return pms_from_labels(turn_rx_bytes, vals);
		case METRIC_TX_BYTES:
			return pms_from_labels(turn_tx_bytes, vals);
		case METRIC_LIFETIME:
			return turn_lifetime ? pms_from_labels(turn_lifetime, vals) : NULL;
		case METRIC_ALLOCATIONS_RUNNING:
			vals[session_label_count-1] = "0";
			return pms_from_labels(turn_allocations, vals);
		case METRIC_ALLOCATIONS_CREATED:
			vals[session_label_count-1] = "1";
			return pms_from_labels(turn_allocations, vals);
		case METRIC_STUN_REQUEST:
			vals[session_label_count-1] = NULL;
			return stun_binding_request
				? pms_from_labels(stun_binding_request, vals)
				: NULL;
		case METRIC_STUN_RESPONSE:
			vals[session_label_count-1] = NULL;
			return stun_binding_response
				? pms_from_labels(stun_binding_response, vals)
				: NULL;
		case METRIC_STUN_ERROR:
			vals[session_label_count-1] = NULL;
			// we do not know all errors, don't want to maintain the list.
			// So on error the little bit slower way via
			// prom_binding_error(...) and the metric will be used.
			break;
		default: TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
			"Session metric %d is not yet supported.\n", type);
	}
	return NULL;
}

void prom_binding_error(int32_t tid, int32_t sid, uint64_t usid,
	int err)
{
	const char *vals[session_label_count];
	char buf[12];

	if (!stun_binding_error)
		return;

	PREPARE_TID_SID_PEER_LABELS(vals, tid, sid, usid, false);
	sprintf(buf, "%d", err);
	vals[session_label_count - 1] = buf;
	prom_counter_add(stun_binding_error, 1, vals);
}

#else

bool prom_disabled(void) { return true; }
bool prom_rsids(void) { return false; }

void start_prometheus_server(void) {
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "turnserver compiled without metric support.\n");
  return;
}

#endif /* TURN_NO_PROMETHEUS */
