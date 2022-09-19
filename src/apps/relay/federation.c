/*
 * Copyright (C) 2022 Wire Swiss GmbH
 */

#include "mainrelay.h"

#include "federation.h"
#include "ns_ioalib_impl.h"
#include "hostcheck.h"

#include <openssl/x509v3.h>
#include <pthread.h>

///////////////////////////////////////////////////

// Whitelist data
static char** whitelist_hostnames = NULL;
static char** whitelist_issuers = NULL;
static size_t whitelist_count = 0;

///////////// federation singleton data ////////
typedef struct _federation_data {
	ur_addr_map* federation_client_tuple_to_fed_connection;
	lm_map federation_cid_to_fed_connection;
	int federation_initalized; // set to 1 if federation is configured and initialized
	int use_mutex;    // set to 1 if mutex should be used, otherwise 0
	turn_mutex mutex; // only initialized if use_mutex is 1
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;	
} federation_data;

federation_data federation_data_singleton = { 0 };  // singleton instance
#define FED_LOCK() if(federation_data_singleton.use_mutex) turn_mutex_lock(&federation_data_singleton.mutex)
#define FED_UNLOCK() if(federation_data_singleton.use_mutex) turn_mutex_unlock(&federation_data_singleton.mutex)

typedef struct _federation_connection {
	uint16_t connection_id;  // channel number
	ioa_addr client_addr;
	turn_turnserver *server;
	turnsession_id sid;
} federation_connection;

#define DTLS_CLIENT_CONNECTION_MAX_TIME_SECS       10

#define FEDERATION_HEARTBEAT_TIME_SECS              5  // Send a client ping (\r\n\r\n) every 5 seconds after DTLS handshake
#define FEDERATION_CLIENT_HEARTBEAT_MAX_OUTSTANDING 1  // Client side: We are allowed to have up to 1 ping that doesn't get ponged - max detection time is 15s
#define FEDERATION_SERVER_MAX_MISSING_HEARTBEATS    2  // Server side: We are allowed to have up to 2 5 second intervals with no pings - max detection time is 15s

uint16_t federation_add_connection_imp(federation_data* fed_data, allocation* fed_allocation);
int federation_remove_connection_imp(federation_data* fed_data, uint16_t connection_id);
federation_connection* federation_get_connection_by_connection_id(uint16_t connection_id);
federation_connection* federation_get_connection_by_allocation(allocation* client_allocation);
int federation_get_connection_info_by_connection_id(uint16_t connection_id, turn_turnserver** turn_server, turnsession_id* turn_session_id);
SSL_CTX* federation_setup_dtls_client_ctx(void);
int federation_send_data_imp(dtls_listener_relay_server_type* server, ioa_addr* dest_addr,
				ioa_network_buffer_handle nbh,
				int ttl, int tos, int* skip);

// WARNING:  make sure this is always called under lock
federation_connection* federation_get_connection_by_connection_id(uint16_t connection_id) {
	federation_connection* fed_con = 0;
	ur_map_value_type mvt = 0;
	if(lm_map_get(&federation_data_singleton.federation_cid_to_fed_connection, connection_id, &mvt)) {
		fed_con = (federation_connection*)mvt;
	}
	return fed_con;
}

// WARNING:  make sure this is always called under lock
federation_connection* federation_get_connection_by_allocation(allocation* client_allocation) {
	federation_connection* fed_con = 0;
	ur_addr_map_value_type mvt = 0;
	ioa_addr* client_addr = &(((ts_ur_super_session*)client_allocation->owner)->client_socket->remote_addr);
	if(ur_addr_map_get(federation_data_singleton.federation_client_tuple_to_fed_connection, client_addr, &mvt)) {
		fed_con = (federation_connection*)mvt;
	}
	return fed_con;
}

// returns 1 for success, 0 otherwise
int federation_get_connection_info_by_connection_id(uint16_t connection_id, turn_turnserver** turn_server, turnsession_id* turn_session_id) {
	int ret = 0;

	FED_LOCK();
	
	federation_connection* fed_con = federation_get_connection_by_connection_id(connection_id);
	if(fed_con) {
		ret = 1;
		if(turn_server) *turn_server = fed_con->server;
		if(turn_session_id) *turn_session_id = fed_con->sid;
	}

	FED_UNLOCK();

	return ret;
}

uint16_t federation_add_connection(allocation* client_allocation) {

	uint16_t connection_id = 0;

	FED_LOCK();

	// Create ur_addr_map if not created yet
	if(federation_data_singleton.federation_client_tuple_to_fed_connection == 0) {
		federation_data_singleton.federation_client_tuple_to_fed_connection = (ur_addr_map*)malloc(sizeof(ur_addr_map));
		ur_addr_map_init(federation_data_singleton.federation_client_tuple_to_fed_connection);
	}

	if(!client_allocation) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: allocation was NULL\n",__FUNCTION__);
		goto done;
	}
	if(!client_allocation->owner) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: allocation has no owner\n",__FUNCTION__);
		goto done;
	}

	// Check if connection for client_addr already exists, if so return it
	federation_connection* fed_con = federation_get_connection_by_allocation(client_allocation);
	if(fed_con) {
		connection_id = fed_con->connection_id;
		goto done;
	}
	
	// Generate Random connection_id and ensure doesn't exist
	do {
		// Ensure randomly generated number is in range of a valid RFC TURN channel numbers,
		// since it is more friendly for the client to demux and for display in wireshark.
		connection_id = (uint16_t)rand() % 0x3FFF + 0x4000;  // Move to valid TURN channel number range
		/* Ensure cid is unique, by looking it up */
		if (connection_id) {			
			if (federation_get_connection_by_connection_id(connection_id)) {
				connection_id = 0;
			}
		}
	} while(connection_id == 0);

    // Create new federation_connection
	fed_con = (federation_connection*)malloc(sizeof(federation_connection));

	// Assign info from allocation
	fed_con->connection_id = connection_id;
	ts_ur_super_session* ss = (ts_ur_super_session*)client_allocation->owner;
	memcpy(&fed_con->client_addr, &(ss->client_socket->remote_addr), sizeof(ioa_addr));
	fed_con->sid = ss->id;
	fed_con->server = (turn_turnserver*)ss->server;

	// We have a unique connection_id now - add to both maps
	ur_addr_map_put(federation_data_singleton.federation_client_tuple_to_fed_connection, &fed_con->client_addr, (ur_addr_map_value_type)fed_con);
	lm_map_put(&federation_data_singleton.federation_cid_to_fed_connection, fed_con->connection_id, (ur_map_value_type)fed_con);

	if(fed_con->server->verbose) {
		char log_buf[128];
		sprintf(log_buf, "%s: added cid=%u, sid=%018llu, client_addr", __FUNCTION__, fed_con->connection_id, (unsigned long long)fed_con->sid);
		addr_debug_print(1, &fed_con->client_addr, log_buf);
	}

	done:

	FED_UNLOCK();

	return connection_id;
}

int federation_remove_connection(uint16_t connection_id) {
	int ret = EINVAL;
	
	FED_LOCK();

	// Get item first, then remove from both maps
	federation_connection* fed_con = federation_get_connection_by_connection_id(connection_id);
	if(fed_con != 0) {
		ur_addr_map_del(federation_data_singleton.federation_client_tuple_to_fed_connection, &fed_con->client_addr, NULL);
		lm_map_del(&federation_data_singleton.federation_cid_to_fed_connection, connection_id, NULL);

		// Release federation_connection memory
		free(fed_con);

		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: removed cid=%u\n", __FUNCTION__, connection_id);

		ret = 0;
	}

	FED_UNLOCK();

	return ret;
}

#if DTLSv1_2_SUPPORTED

// returns -1 if not found, otherwise position in whitelist
static int hostname_whitelist_match(char* cert_hostname) {
	// Look through all whitelist entries for a match
	for(size_t i = 0; i < whitelist_count; i++) {

		if(wildcard_hostcheck(whitelist_hostnames[i], cert_hostname) == 1) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: config_hostname=%s, cert_hostname=%s - MATCHED!\n", __FUNCTION__, whitelist_hostnames[i], cert_hostname);
			return i;
		}
	}
	return -1;
}

static int federation_cert_verify(X509_STORE_CTX *x509_ctx, void *arg) {
	UNUSED_ARG(arg);

	char cSubjectNameString[257];
	char cIssuerNameString[257];

	// Do the normal builtin certification validation by openssl
    int preverify_ok = X509_verify_cert(x509_ctx);
	int postverify_ok = 0;

	X509 *pCurCert = X509_STORE_CTX_get_current_cert(x509_ctx);

	if (NULL != pCurCert) {
		X509_NAME_oneline(X509_get_subject_name(pCurCert),cSubjectNameString,256);
		X509_NAME_oneline(X509_get_issuer_name(pCurCert),cIssuerNameString,256);
	} else {
		cSubjectNameString[0] = 0;
		cIssuerNameString[0] = 0;
	}

	if(!preverify_ok) {
		int iErr = X509_STORE_CTX_get_error(x509_ctx);
		int iDepth = X509_STORE_CTX_get_error_depth(x509_ctx);

		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Error when verifying peer's chain of certificates: %s, iErr='%s' depth=%d %s %s\n",
			__FUNCTION__, X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)),
			X509_verify_cert_error_string(iErr), iDepth, cSubjectNameString, cIssuerNameString);
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: SSL preverify OK: %s %s\n",__FUNCTION__, cSubjectNameString, cIssuerNameString);

		if(whitelist_count > 0) {
			int bSubjectAltNamePresent = 0;
			int whitelistMatchPosition = -1;

			// Subject Alt Name Check
			STACK_OF(GENERAL_NAME)* pSubjectAltNames = NULL;
			pSubjectAltNames = X509_get_ext_d2i((X509*)pCurCert, NID_subject_alt_name, NULL, NULL);
			if(pSubjectAltNames != NULL) {
				bSubjectAltNamePresent = 1;
				int numNames = sk_GENERAL_NAME_num(pSubjectAltNames);
				for(int i = 0; i < numNames; i++) {
					const GENERAL_NAME* pSubjectAltName = sk_GENERAL_NAME_value(pSubjectAltNames, i);
					if(pSubjectAltName->type == GEN_DNS) {
						char* cDNSName = (char*)ASN1_STRING_data(pSubjectAltName->d.dNSName);
						whitelistMatchPosition = hostname_whitelist_match(cDNSName);
						if(whitelistMatchPosition == -1) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Found non-matching Subject Alt Name: %s\n",__FUNCTION__, cDNSName);
						} else {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Found matching Subject Alt Name: %s\n",__FUNCTION__, cDNSName);
							break;
						}
					}
				}
			}
			sk_GENERAL_NAME_pop_free(pSubjectAltNames, GENERAL_NAME_free);

			// Check Common Name - maybe don't check if subject alt names are present?
			if(!bSubjectAltNamePresent) {
				int commonNameIndex = X509_NAME_get_index_by_NID(X509_get_subject_name((X509*) pCurCert), NID_commonName, -1);
				if(commonNameIndex >= 0) {
					X509_NAME_ENTRY* pCommonNameEntry = X509_NAME_get_entry(X509_get_subject_name((X509*)pCurCert), commonNameIndex);
					if(pCommonNameEntry != NULL) {
						ASN1_STRING* pCommonNameASN1 = X509_NAME_ENTRY_get_data(pCommonNameEntry);
						if(pCommonNameASN1 != NULL) {
							char* cCommonName = (char*)ASN1_STRING_data(pCommonNameASN1);
							whitelistMatchPosition = hostname_whitelist_match(cCommonName);
							if(whitelistMatchPosition == -1) {
								TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Found non-matching Common Name: %s\n",__FUNCTION__, cCommonName);
							} else {
								TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Found matching Common Name: %s\n",__FUNCTION__, cCommonName);
							}
						}
					}
				}
			}

			// Check Issuer, if we found a hostname match, and issuer is specified
			if(whitelistMatchPosition != -1) {
				if(whitelist_issuers[whitelistMatchPosition][0] != 0) {
					STACK_OF(X509)* pChain = X509_STORE_CTX_get1_chain(x509_ctx);
					int numCertsInChain = sk_X509_num(pChain);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: %d certs in chain\n",__FUNCTION__, numCertsInChain);
					for(int i = 0; i < numCertsInChain; i++) {
						X509* pCert = sk_X509_value(pChain, i);

						// Check Issuer Name
						int issuerNameIndex = X509_NAME_get_index_by_NID(X509_get_issuer_name((X509*)pCert), NID_commonName, -1);
						if(issuerNameIndex >= 0) {
							X509_NAME_ENTRY* pIssuerNameEntry = X509_NAME_get_entry(X509_get_issuer_name((X509*)pCert), issuerNameIndex);
							if(pIssuerNameEntry != NULL) {
								ASN1_STRING* pIssuerNameASN1 = X509_NAME_ENTRY_get_data(pIssuerNameEntry);
								if(pIssuerNameASN1 != NULL) {
									char* cIssuerName = (char*)ASN1_STRING_data(pIssuerNameASN1);
									if(strcmp(whitelist_issuers[whitelistMatchPosition], cIssuerName) == 0) {
										TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Found matching Issuer Name: %s\n",__FUNCTION__, cIssuerName);
										postverify_ok = 1;
										break;
									} else { 
										TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Found non-matching Issuer Name: %s\n",__FUNCTION__, cIssuerName);
									}
								}
							}
						}
					}
					sk_X509_pop_free(pChain, X509_free);
				} else {
					// No issuer specified, accept all
					postverify_ok = 1;
				}
			}
		} else {
			// No whitelist provided, accept all
			postverify_ok = 1;
		}
	}

	if(preverify_ok && postverify_ok && x509_ctx) return 1;
	return -1;
}

#if ALPN_SUPPORTED
static const unsigned char kALPNProtos[] = "\x08http/1.1\x09stun.turn\x12stun.nat-discovery";
static const size_t kALPNProtosLen = sizeof(kALPNProtos) - 1;
#endif

static const char *cipherlist = 
	"ECDHE-RSA-AES128-GCM-SHA256:"
	"ECDHE-ECDSA-AES128-GCM-SHA256:"
	"ECDHE-RSA-AES256-GCM-SHA384:"
	"ECDHE-ECDSA-AES256-GCM-SHA384:"
	"DHE-RSA-AES128-GCM-SHA256:"
	"DHE-DSS-AES128-GCM-SHA256:"
	"ECDHE-RSA-AES128-SHA256:"
	"ECDHE-ECDSA-AES128-SHA256:"
	"ECDHE-RSA-AES128-SHA:"
	"ECDHE-ECDSA-AES128-SHA:"
	"ECDHE-RSA-AES256-SHA384:"
	"ECDHE-ECDSA-AES256-SHA384:"
	"ECDHE-RSA-AES256-SHA:"
	"ECDHE-ECDSA-AES256-SHA:"
	"DHE-RSA-AES128-SHA256:"
	"DHE-RSA-AES128-SHA:"
	"DHE-DSS-AES128-SHA256:"
	"DHE-RSA-AES256-SHA256:"
	"DHE-DSS-AES256-SHA:"
	"DHE-RSA-AES256-SHA:"
	"ECDHE-RSA-AES128-CBC-SHA";

static SSL_CTX* federation_setup_dtls_ctx(const SSL_METHOD* method) {
	SSL_CTX* ssl_ctx = NULL;
	set_ctx_ex(&ssl_ctx,"DTLS1.2", method, turn_params.federation_cert_file, turn_params.federation_pkey_file, turn_params.federation_pkey_pwd);
	SSL_CTX_set_cipher_list(ssl_ctx, cipherlist);
	
	if(turn_params.ca_cert_file[0]) {
		// Note:  this call is overriding what was set in set_ctx (mainrelay.c)
		// Note2: Instead of providing a callback to SSL_CTX_set_verify, we instead call SSL_CTX_set_cert_verify_callback.
		//        Why you ask?  Well..  If the peer provided multiple certs then the callback set via 
		//        SSL_CTX_set_verify would get called once for each certificate in the chain.  When we do it this way
		//        our callback is only called once.  We want to validate the domain/commonname/subject_alt_name and the issuer
		//        and we only want to do this against the top level certificate, so this setup works out much better, 
		//        otherwise we don't know which callback (when there are multiple) to run the domain/issuer checks in.
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, NULL);
		SSL_CTX_set_cert_verify_callback(ssl_ctx, federation_cert_verify, NULL);
	}
	
	SSL_CTX_set_read_ahead(ssl_ctx, 1);

	SSL_CTX_set_cookie_generate_cb(ssl_ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ssl_ctx, verify_cookie);	
	
	return ssl_ctx;
}

#endif

static void cleanup_connection(ur_addr_map_value_type connectionvt) {
  	ioa_socket_handle connection = (ioa_socket_handle)connectionvt;
	close_ioa_socket(connection);
}
static void signal_callback_handler(evutil_socket_t sock, short events, void *args)
{
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Terminating server, ending all federated connections..\n");

    ur_addr_map* connectionsmap = turn_params.listener.federation_service->children_ss;

    ur_addr_map_foreach(connectionsmap, cleanup_connection);

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Terminating server, ended all federated connections\n");

	exit(0);

	UNUSED_ARG(sock);
	UNUSED_ARG(events);
	UNUSED_ARG(args);
}

enum _MESSAGE_TO_FEDERATION_TYPE {
	FMT_UNKNOWN = 0,
	FMT_SEND_DATA
};
typedef enum _MESSAGE_TO_FEDERATION_TYPE MESSAGE_TO_FEDERATION_TYPE;

struct federation_send_data_message {
	dtls_listener_relay_server_type* listen_server;
	ioa_addr dest_addr;
	int ttl;
	int tos;
	ioa_network_buffer_handle nbh;
};

struct message_to_federation {
	MESSAGE_TO_FEDERATION_TYPE t;
	union {
		struct federation_send_data_message send_data;
	} m;
};

static void federation_receive_message(struct bufferevent *bev, void *ptr)
{
	struct message_to_federation msg;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	//struct relay_server *rs = (struct relay_server *)ptr;
	UNUSED_ARG(ptr);

	while ((n = evbuffer_remove(input, &msg, sizeof(struct message_to_federation))) > 0) {

		if (n != sizeof(struct message_to_federation)) {
			perror("Weird buffer error\n");
			continue;
		}

		switch(msg.t) {
			case FMT_SEND_DATA:
				federation_send_data_imp(msg.m.send_data.listen_server, &msg.m.send_data.dest_addr, msg.m.send_data.nbh, msg.m.send_data.ttl, msg.m.send_data.tos, NULL);
			break;

			default:
			break;
		}
	}
}

void federation_load_certificates(void) {
#if DTLSv1_2_SUPPORTED
	if(!turn_params.federation_no_dtls && federation_data_singleton.federation_initalized) {
		// Store old ctx's so we can free them - at startup these are nulls
		SSL_CTX* old_client_ctx = turn_params.federation_dtls_client_ctx_v1_2;
		SSL_CTX* old_server_ctx = turn_params.federation_dtls_server_ctx_v1_2;

		// Create and assign new ctx's.  Pointer set's are atomic so no need for locking.
		turn_params.federation_dtls_client_ctx_v1_2 = federation_setup_dtls_ctx(DTLSv1_2_client_method());
		turn_params.federation_dtls_server_ctx_v1_2 = federation_setup_dtls_ctx(DTLSv1_2_server_method());

		// Free old ctx's if defined - only needed for when SIG_USR2 is fired and we are reloading after startup
		if(old_client_ctx) {
			SSL_CTX_free(old_client_ctx);
		}
		if(old_server_ctx) {
			SSL_CTX_free(old_server_ctx);
		}
	}
#endif
}

void federation_init(ioa_engine_handle e) {
	//run_wildcard_hostcheck_unit_tests(); // uncomment to test wildcard_hostcheck code
	
	// Install signal handlers so that we can terminate federated DTLS connections on program exit
	struct event *ev = evsignal_new(turn_params.listener.event_base, SIGINT, signal_callback_handler, NULL);
	event_add(ev, NULL);
	struct event *ev2 = evsignal_new(turn_params.listener.event_base, SIGTERM, signal_callback_handler, NULL);
	event_add(ev2, NULL);
	struct event *ev3 = evsignal_new(turn_params.listener.event_base, SIGQUIT, signal_callback_handler, NULL);
	event_add(ev3, NULL);

	// Initialize Mutex - if needed
	if(turn_params.general_relay_servers_number > 1) {
		turn_mutex_init(&federation_data_singleton.mutex);
		federation_data_singleton.use_mutex = 1;
	} else {
		federation_data_singleton.use_mutex = 0;
	}

	// Create in/out buffer pair for messaging to the federation thread.  Senders use out_buf to send.  Data arrives
	// on in_buff via registered callback.
	struct bufferevent* pair[2];
	bufferevent_pair_new(e->event_base, TURN_BUFFEREVENTS_OPTIONS, pair);
	federation_data_singleton.in_buf = pair[0];
	federation_data_singleton.out_buf = pair[1];
	bufferevent_setcb(federation_data_singleton.in_buf, federation_receive_message, NULL, NULL, NULL);
	bufferevent_enable(federation_data_singleton.in_buf, EV_READ);

	federation_data_singleton.federation_initalized = 1;

	// Load federation certificates and setup federation DTLS contexts
	federation_load_certificates();
}

#if DTLSv1_2_SUPPORTED
static void federation_client_connect_timeout_handler(ioa_engine_handle e, void* arg) {

	UNUSED_ARG(e);

	if (!arg) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s: empty federation_client_connection to be cleaned\n",__FUNCTION__);
		return;
	}

	ioa_socket_handle s = (ioa_socket_handle) arg;

	if(s->ssl && !SSL_is_init_finished(s->ssl)) {
		addr_debug_print(1, &s->remote_addr, "DTLS client connection failed to ");
		// Note: when you close a socket it removes itself from it's containing map as well
		IOA_CLOSE_SOCKET(s);
	}
}
#endif

int federation_send_data_imp(dtls_listener_relay_server_type* server, ioa_addr* dest_addr,
				ioa_network_buffer_handle nbh, int ttl, int tos, int* skip) {
#if DTLSv1_2_SUPPORTED
	int fd = server->udp_listen_s->fd;
	if(server->federation_listener && !turn_params.federation_no_dtls) {
		// See if we already have a DTLS connection to the destination
		ur_addr_map_value_type mvt = 0;
		if(!(server->children_ss)) {
			// addr map isn't initalized yet, initialize it now
			server->children_ss = (ur_addr_map*)allocate_super_memory_engine(server->e, sizeof(ur_addr_map));
			ur_addr_map_init(server->children_ss);
		}
		ur_addr_map *amap = server->children_ss;

		// Lookup dest_addr in map
		ioa_socket_handle chs = NULL;
		if ((ur_addr_map_get(amap, dest_addr, &mvt) > 0) && mvt) {
			chs = (ioa_socket_handle) mvt;
		}

		if(chs == NULL) {			
			// No connection yet, DTLS connect to dest_addr
			SSL* ssl = SSL_new(turn_params.federation_dtls_client_ctx_v1_2);
			SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

#if ALPN_SUPPORTED
			SSL_set_alpn_protos(ssl, kALPNProtos, kALPNProtosLen);
#endif

			/* Create BIO, connect and set the peer as the destination */
			BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);   // should we use close or noclose?
			BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &dest_addr->ss);

			SSL_set_bio(ssl, bio, bio);

			/* Set and activate timeouts */
			struct timeval timeout;
			timeout.tv_sec = DTLS_MAX_RECV_TIMEOUT;
			timeout.tv_usec = 0;
			BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

			set_mtu_df(ssl, fd, dest_addr->ss.sa_family, SOSO_MTU, 1, server->verbose);

			SSL_set_max_cert_list(ssl, 655350);

			SSL_set_connect_state(ssl);

			addr_debug_print(server->verbose, dest_addr, "Starting DTLS handshake to ");

			chs = create_ioa_socket_from_ssl(server->e, server->udp_listen_s, ssl, DTLS_SOCKET, CLIENT_SOCKET, dest_addr, &(server->addr));
			if(chs == NULL) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create ioa_socket from SSL\n");
				return -1;
			}

			// start a client connection timer
			IOA_EVENT_DEL(chs->ssl_client_conn_tmr);
			chs->ssl_client_conn_tmr = set_ioa_timer(server->e, DTLS_CLIENT_CONNECTION_MAX_TIME_SECS, 0,
							federation_client_connect_timeout_handler, chs, 0,
							"federation_client_connect_timeout_handler");

			add_socket_to_map(chs, server->children_ss);

			if(register_callback_on_ioa_socket(server->e, chs, IOA_EV_READ, federation_input_handler, server /* ctx */, 0)<0) {
				return -1;
			}	
		}

		addr_debug_print(eve(server->verbose), dest_addr, "Federation: relaying data from SendInd to");

		return send_data_from_ioa_socket_nbh(chs, dest_addr, nbh, ttl, tos, skip);
	}
	else
#endif
	{
		addr_debug_print(eve(server->verbose), dest_addr, "Federation: relaying data from SendInd to");

		// Relay UDP data
		return send_data_from_ioa_socket_nbh(server->udp_listen_s, dest_addr, nbh, ttl, tos, skip);
	}
}

void federation_send_data(dtls_listener_relay_server_type* server, ioa_addr* dest_addr,
				ioa_network_buffer_handle nbh, int ttl, int tos, int* skip) {

	if(turn_params.general_relay_servers_number > 1) {
		// If muti-threaded, then send info federation thread for sending
		struct message_to_federation msg;
		msg.t = FMT_SEND_DATA;
		msg.m.send_data.listen_server = server;
		memcpy(&msg.m.send_data.dest_addr, dest_addr, sizeof(ioa_addr));
		msg.m.send_data.ttl = ttl;
		msg.m.send_data.tos = tos;
		msg.m.send_data.nbh = nbh;

		struct evbuffer *output = bufferevent_get_output(federation_data_singleton.out_buf);
		if(evbuffer_add(output,&msg,sizeof(struct message_to_federation))<0) {
			fprintf(stderr,"%s: Weird buffer error\n",__FUNCTION__);
			ioa_network_buffer_delete(server->e, nbh);
		}

		return;
	}

	// If single threaded then just send immediately
	federation_send_data_imp(server, dest_addr, nbh, ttl, tos, skip);
}

// Note:  No need to call ioa_network_buffer_delete on errors below, since caller will delete buffer
//        as long as we don't null it out, ie: in_buffer->nbh = NULL;
void federation_input_handler(ioa_socket_handle s, int event_type,
		ioa_net_data *in_buffer, void *arg, int can_resume) {

	UNUSED_ARG(can_resume);

	if (!(event_type & IOA_EV_READ) || !arg) {
		return;
	}

	if(in_buffer->recv_ttl==0) {
		return;
	}

	if(!s || ioa_socket_tobeclosed(s)) {
		return;
	}

	dtls_listener_relay_server_type * dtls_listener = (dtls_listener_relay_server_type *) arg;

	if(!(dtls_listener->udp_listen_s) || ioa_socket_tobeclosed(dtls_listener->udp_listen_s)) {
		return;
	}

	// Check if packet is a heartbeat "ping"
	uint8_t *data = ioa_network_buffer_data(in_buffer->nbh);
	if(ioa_network_buffer_get_size(in_buffer->nbh) == 4 && memcmp("\r\n\r\n", data, 4) == 0) {
		//addr_debug_print(1, &in_buffer->src_addr, "Federation: received heartbeat ping from");
		// Send pong back to sender - use same buffer, just change size to 2
		ioa_network_buffer_handle nbh = in_buffer->nbh;
		// We are reusing the inbound buffer for outbound sending, NULL it out so caller doesn't free
		in_buffer->nbh = NULL;
		ioa_network_buffer_set_size(nbh, 2);
		send_data_from_ioa_socket_nbh(s, &in_buffer->src_addr, nbh, TTL_IGNORE, TOS_IGNORE, NULL /* skip/ret */);

		s->federation_heartbeat_pings_outstanding = 0;  // We have a ping, reset pings outstanding counter

		// Don't process packet any further
		return;
	}

	// Check if packet is a hearbeat "pong"
	if(ioa_network_buffer_get_size(in_buffer->nbh) == 2 && memcmp("\r\n", data, 2) == 0) {
		//addr_debug_print(1, &in_buffer->src_addr, "Federation: received heartbeat pong from");
		s->federation_heartbeat_pings_outstanding = 0;  // We have a pong, reset pings outstanding counter
		// Don't process packet any further
		return;
	}

	// Extract the first two bytes to get the federation cid from the message.  We use this to lookup the mapped allocation
	// so that we can send this data to the client address.
	uint16_t cid = ntohs(((const uint16_t*)data)[0]);
    // We enforce cids to be in valid RFC TURN channel numbers. It is more friendly for the client to demux and for display in wireshark.	
	if (!STUN_VALID_CHANNEL(cid)) { 
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "%s: Federation listener received data for invalid channel range cid=%hd ignoring\n", __FUNCTION__, cid);
		return;
	}

	turn_turnserver* turn_server = 0;
	turnsession_id sid = 0;
	if(!federation_get_connection_info_by_connection_id(cid, &turn_server, &sid)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "%s: Federation listener received data for invalid cid=%hd ignoring\n", __FUNCTION__, cid);
		return;
	}

    // We are reusing the inbound buffer for outbound sending, NULL it out so caller doesn't free
	ioa_network_buffer_handle nbh = in_buffer->nbh;
	in_buffer->nbh = NULL;

	if(turn_params.general_relay_servers_number > 1) {
		if(eve(turn_server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Federation listener received data cid=%hd, relaying data via relay thread...\n",__FUNCTION__, cid);
	    send_federation_data_message_to_relay(sid, nbh, in_buffer->recv_ttl-1, in_buffer->recv_tos);
	}
	else {
		if(eve(turn_server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Federation listener received data cid=%hd, relaying data directly...\n",__FUNCTION__, cid);
		turn_send_federation_data(turn_server, sid, nbh, in_buffer->recv_ttl-1, in_buffer->recv_tos);
	}
}

void federation_whitelist_add(char* hostname, char* issuer) {
	size_t new_size = (whitelist_count+1) * sizeof(char*);
	whitelist_hostnames = (char**)realloc(whitelist_hostnames, new_size);
	whitelist_issuers = (char**)realloc(whitelist_issuers, new_size);
	whitelist_hostnames[whitelist_count]=strdup(hostname);
	whitelist_issuers[whitelist_count]=strdup(issuer);
	whitelist_count++;
}

static void federation_client_heartbeat_timeout_handler(ioa_engine_handle e, void* arg) {

	UNUSED_ARG(e);
	
	if (!arg) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s: empty socket handle to heartbeat\n",__FUNCTION__);
		return;
	}

	ioa_socket_handle s = (ioa_socket_handle) arg;

	if(ioa_socket_tobeclosed(s)) {
		return;
	}

	if(s->federation_heartbeat_pings_outstanding <= FEDERATION_CLIENT_HEARTBEAT_MAX_OUTSTANDING) {
		//addr_debug_print(1, &s->remote_addr, "Federation: sending heartbeat ping to");

		// Build double CRLF as heartbeat ping, expecting keepalive ping (single CRLF) to be returned
		ioa_network_buffer_handle nbh = ioa_network_buffer_allocate(s->e);
		uint8_t *data = ioa_network_buffer_data(nbh);
		bcopy("\r\n\r\n", data, 4);
		ioa_network_buffer_set_size(nbh, 4);
		send_data_from_ioa_socket_nbh(s, NULL /* dest_addr */, nbh, TTL_IGNORE, TOS_IGNORE, NULL /* skip/ret */);

		s->federation_heartbeat_pings_outstanding  = s->federation_heartbeat_pings_outstanding + 1;

		// Restart timer
		federation_start_client_heartbeat_timer(s);
	} else {
		addr_debug_print(1, &s->remote_addr, "Federation: keepalive pong not received after pings, terminating connection to");
		// Previous ping(s), didn't have a pong response.  Mapping is likely dead.  Close socket.
		close_ioa_socket(s);
	}
}

void federation_start_client_heartbeat_timer(ioa_socket_handle s) {
	IOA_EVENT_DEL(s->federation_heartbeat_tmr);
	s->federation_heartbeat_tmr = set_ioa_timer(s->e, FEDERATION_HEARTBEAT_TIME_SECS, 0,
				federation_client_heartbeat_timeout_handler, s, 0,
			 	"federation_client_heartbeat_timeout_handler");
}

static void federation_server_heartbeat_timeout_handler(ioa_engine_handle e, void* arg) {

	UNUSED_ARG(e);
	
	if (!arg) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s: empty socket handle to heartbeat\n",__FUNCTION__);
		return;
	}

	ioa_socket_handle s = (ioa_socket_handle) arg;

	if(ioa_socket_tobeclosed(s)) {
		return;
	}

	if(s->federation_heartbeat_pings_outstanding <= FEDERATION_SERVER_MAX_MISSING_HEARTBEATS) {
		s->federation_heartbeat_pings_outstanding  = s->federation_heartbeat_pings_outstanding + 1;

		// Restart timer
		federation_start_server_heartbeat_timer(s);
	} else {
		addr_debug_print(1, &s->remote_addr, "Federation: keepalive pings not received, terminating connection to");
		close_ioa_socket(s);
	}
}

void federation_start_server_heartbeat_timer(ioa_socket_handle s) {
	IOA_EVENT_DEL(s->federation_heartbeat_tmr);
	s->federation_heartbeat_tmr = set_ioa_timer(s->e, FEDERATION_HEARTBEAT_TIME_SECS, 0,
				federation_server_heartbeat_timeout_handler, s, 0,
			 	"federation_server_heartbeat_timeout_handler");
}