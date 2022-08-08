// TODO SLG - do we want a copyright block here?

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
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;	
} federation_data;

federation_data federation_data_singleton = { 0 };  // singleton instance
typedef struct _federation_connection {
	uint16_t connection_id;  // channel number
	allocation* fed_allocation;
} federation_connection;


uint16_t federation_add_connection_imp(federation_data* fed_data, allocation* fed_allocation);
int federation_remove_connection_imp(federation_data* fed_data, uint16_t connection_id);
federation_connection* federation_get_connection_by_connection_id(uint16_t connection_id);
federation_connection* federation_get_connection_by_allocation(allocation* client_allocation);
SSL_CTX* federation_setup_dtls_client_ctx(void);

// TODO SLG - add locking for multi-threaded use
federation_connection* federation_get_connection_by_connection_id(uint16_t connection_id) {
	federation_connection* fed_con = 0;
	ur_map_value_type mvt = 0;
	if(lm_map_get(&federation_data_singleton.federation_cid_to_fed_connection, connection_id, &mvt)) {
		fed_con = (federation_connection*)mvt;
	}
	return fed_con;
}

federation_connection* federation_get_connection_by_allocation(allocation* client_allocation) {
	federation_connection* fed_con = 0;
	ur_addr_map_value_type mvt = 0;
	ioa_addr* client_addr = &(((ts_ur_super_session*)client_allocation->owner)->client_socket->remote_addr);
	if(ur_addr_map_get(federation_data_singleton.federation_client_tuple_to_fed_connection, client_addr, &mvt)) {
		fed_con = (federation_connection*)mvt;
	}
	return fed_con;
}

uint16_t federation_add_connection(allocation* client_allocation) {
	// Create ur_addr_map if not created yet
	if(federation_data_singleton.federation_client_tuple_to_fed_connection == 0) {
		federation_data_singleton.federation_client_tuple_to_fed_connection = (ur_addr_map*)malloc(sizeof(ur_addr_map));
		ur_addr_map_init(federation_data_singleton.federation_client_tuple_to_fed_connection);
	}

	// Check if connection for client_addr already exists, if so return it
	federation_connection* fed_con = federation_get_connection_by_allocation(client_allocation);
	if(fed_con) {
		return fed_con->connection_id;
	}

    // Create new federation_connection
	fed_con = (federation_connection*)malloc(sizeof(federation_connection));
	
	// Generate Random connection_id and ensure doesn't exist
	do {
		// Ensure randomly generated number is in range of a valid RFC TURN channel numbers,
		// since it is more friendly for the client to demux and for display in wireshark.
		fed_con->connection_id = (uint16_t)rand() % 0x3FFF + 0x4000;  // Move to valid TURN channel number range
		/* Ensure cid is unique, by looking it up */
		if (fed_con->connection_id) {			
			if (federation_get_connection_by_connection_id(fed_con->connection_id)) {
				fed_con->connection_id = 0;
			}
		}
	} while(fed_con->connection_id == 0);

	// Assign allocation
	fed_con->fed_allocation = client_allocation;

	// We have a unique connection_id now - add to both maps
	ioa_addr* client_addr = &(((ts_ur_super_session*)client_allocation->owner)->client_socket->remote_addr);
	ur_addr_map_put(federation_data_singleton.federation_client_tuple_to_fed_connection, client_addr, (ur_addr_map_value_type)fed_con);
	lm_map_put(&federation_data_singleton.federation_cid_to_fed_connection, fed_con->connection_id, (ur_map_value_type)fed_con);

	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: added cid=%u\n", __FUNCTION__, fed_con->connection_id);

	return fed_con->connection_id;
}

int federation_remove_connection(uint16_t connection_id) {
	// Get item first, then remove from both maps
	federation_connection* fed_con = federation_get_connection_by_connection_id(connection_id);
	if(fed_con != 0) {
		ioa_addr* client_addr = &(((ts_ur_super_session*)fed_con->fed_allocation->owner)->client_socket->remote_addr);
		ur_addr_map_del(federation_data_singleton.federation_client_tuple_to_fed_connection, client_addr, NULL);
		lm_map_del(&federation_data_singleton.federation_cid_to_fed_connection, connection_id, NULL);

		// Release federation_connection memory
		free(fed_con);

		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: removed cid=%u\n", __FUNCTION__, connection_id);

		return 0;
	}
	return EINVAL;
}

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

struct message_to_federation {
	MESSAGE_TO_FEDERATION_TYPE t;
	union {
//		struct socket_message sm;
//		struct cb_socket_message cb_sm;
//		struct cancelled_session_message csm;
	} m;
};

static void federation_receive_message(struct bufferevent *bev, void *ptr)
{
	struct message_to_relay sm;
	int n = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	//struct relay_server *rs = (struct relay_server *)ptr;
	UNUSED_ARG(ptr);

	while ((n = evbuffer_remove(input, &sm, sizeof(struct message_to_federation))) > 0) {

		if (n != sizeof(struct message_to_federation)) {
			perror("Weird buffer error\n");
			continue;
		}

		//handle_federation_message(rs, &sm);
	}
}

void federation_init(ioa_engine_handle e) {
	// Install signal handlers so that we can terminate federated DTLS connections on program exit
	struct event *ev = evsignal_new(turn_params.listener.event_base, SIGINT, signal_callback_handler, NULL);
	event_add(ev, NULL);
	struct event *ev2 = evsignal_new(turn_params.listener.event_base, SIGTERM, signal_callback_handler, NULL);
	event_add(ev2, NULL);
	struct event *ev3 = evsignal_new(turn_params.listener.event_base, SIGQUIT, signal_callback_handler, NULL);
	event_add(ev3, NULL);

	// Create in/out buffer pair for messaging to the federation thread.  Senders use out_buf to send.  Data arrives
	// on in_buff via registered callback.
	struct bufferevent* pair[2];
	bufferevent_pair_new(e->event_base, TURN_BUFFEREVENTS_OPTIONS, pair);
	federation_data_singleton.in_buf = pair[0];
	federation_data_singleton.out_buf = pair[1];
	bufferevent_setcb(federation_data_singleton.in_buf, federation_receive_message, NULL, NULL, NULL);
	bufferevent_enable(federation_data_singleton.in_buf, EV_READ);

	if(turn_params.federation_use_dtls) {
		// Initialize the DTLS client CTX
		// Note: the DTLS server CTX is part of the dtls_listener storage
		turn_params.federation_dtls_client_ctx_v1_2 = federation_setup_dtls_ctx(DTLSv1_2_client_method());
		turn_params.federation_dtls_server_ctx_v1_2 = federation_setup_dtls_ctx(DTLSv1_2_server_method());
	}
}

static void federation_client_connect_timeout_handler(ioa_engine_handle e, void* arg) {

	UNUSED_ARG(e);

	if (!arg) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "!!! %s: empty federation_client_connection to be cleaned\n",__FUNCTION__);
		return;
	}

	ioa_socket_handle s = (ioa_socket_handle) arg;
	addr_debug_print(1, &s->remote_addr, "DTLS client connection failed to ");
	// Note: when you close a socket it removes itself from it's containing map as well
	IOA_CLOSE_SOCKET(s);
}

int federation_send_data(dtls_listener_relay_server_type* server, ioa_addr* dest_addr,
				ioa_network_buffer_handle nbh,
				int ttl, int tos, int* skip) {

	int fd = server->udp_listen_s->fd;
	if(server->federation_listener && turn_params.federation_use_dtls) {
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

            // TODO SLG - what is ALPN, do we need it?
//#if ALPN_SUPPORTED
//		SSL_set_alpn_protos(ssl, kALPNProtos, kALPNProtosLen);
//#endif

			/* Create BIO, connect and set the peer as the destination */
			BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);   // should we use close or noclose?
			BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &dest_addr->ss);

			SSL_set_bio(ssl, bio, bio);

			/* Set and activate timeouts */
			struct timeval timeout;
			timeout.tv_sec = DTLS_MAX_RECV_TIMEOUT;
			timeout.tv_usec = 0;
			BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

			set_mtu_df(ssl, fd, dest_addr->ss.sa_family, SOSO_MTU, 1, server->verbose);  // TODO SLG - should we be changing MTU and DF on federation listen socket here?  maybe not

			SSL_set_max_cert_list(ssl, 655350);

			SSL_set_connect_state(ssl);

			addr_debug_print(server->verbose, dest_addr, "Starting DTLS handshake to ");

			chs = create_ioa_socket_from_ssl(server->e, server->udp_listen_s, ssl, DTLS_SOCKET, CLIENT_SOCKET, dest_addr, &(server->addr));
			if(chs == NULL) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create ioa_socket from SSL\n");
				return -1;
			}

			// start a connection timer
			IOA_EVENT_DEL(chs->ssl_client_conn_tmr);
			chs->ssl_client_conn_tmr = set_ioa_timer(server->e, 10 /* TODO Define constant */, 0,
							federation_client_connect_timeout_handler, chs, 0,
							"federation_client_connect_timeout_handler");

			add_socket_to_map(chs, server->children_ss);

			if(register_callback_on_ioa_socket(server->e, chs, IOA_EV_READ, federation_input_handler, server /* ctx */, 0)<0) {
				return -1;
			}	
		}

		return send_data_from_ioa_socket_nbh(chs, dest_addr, nbh, ttl, tos, skip);
	}
	else
	{
		// Relay UDP data
		return send_data_from_ioa_socket_nbh(server->udp_listen_s, dest_addr, nbh, ttl, tos, skip);
	}
}

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

	// Extract the first two bytes to get the federation cid from the message.  We use this to lookup the mapped allocation
	// so that we can send this data to the client address.
	uint16_t cid = ntohs(((const uint16_t*)(ioa_network_buffer_data(in_buffer->nbh)))[0]);
    // We enforce cids to be in valid RFC TURN channel numbers. It is more friendly for the client to demux and for display in wireshark.	
	if (!STUN_VALID_CHANNEL(cid)) { 
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "%s: Federation listener received data for invalid channel range cid=%hd ignoring\n", __FUNCTION__, cid);
		return;
	}

	federation_connection* fed_con = federation_get_connection_by_connection_id(cid);
	if(!fed_con) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "%s: Federation listener received data for invalid cid=%hd ignoring\n", __FUNCTION__, cid);
		return;
	}

	allocation* a = fed_con->fed_allocation;
	if(!is_allocation_valid(a)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: Federation listener received data for valid cid=%hd, but allocation was not valid\n",__FUNCTION__, cid);
		return;
	}

	if(!a->owner) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: Federation listener received data for valid cid=%hd, but allocation has no owner\n",__FUNCTION__, cid);
		return;
	}

	ts_ur_super_session* ss = (ts_ur_super_session*)a->owner;
	if(!ss->client_socket)
	{
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"%s: Federation listener received data for valid cid=%hd, but allocation owner has no client_socket\n",__FUNCTION__, cid);
		return;
	}
	
    // We are reusing the inbound buffer for outbound sending, NULL it out so caller doesn't free
	ioa_network_buffer_handle nbh = in_buffer->nbh;
	in_buffer->nbh = NULL;

	// TODO SLG - eventually comment out
	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: Federation listener received data for valid cid=%hd and found mapped allocation, relaying data...\n",__FUNCTION__, cid);

	send_data_from_ioa_socket_nbh(ss->client_socket, NULL /* dest_addr */, nbh, in_buffer->recv_ttl-1, in_buffer->recv_tos, NULL /* skip/ret */);
}

void federation_whitelist_add(char* hostname, char* issuer)
{
	size_t new_size = (whitelist_count+1) * sizeof(char*);
	whitelist_hostnames = (char**)realloc(whitelist_hostnames, new_size);
	whitelist_issuers = (char**)realloc(whitelist_issuers, new_size);
	whitelist_hostnames[whitelist_count]=strdup(hostname);
	whitelist_issuers[whitelist_count]=strdup(issuer);
	whitelist_count++;
}
