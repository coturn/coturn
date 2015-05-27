/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <unistd.h>

#include "apputils.h"
#include "ns_turn_utils.h"
#include "startuclient.h"
#include "ns_turn_msg.h"
#include "uclient.h"
#include "session.h"

#include <openssl/err.h>

/////////////////////////////////////////

#define MAX_CONNECT_EFFORTS (77)
#define DTLS_MAX_CONNECT_TIMEOUT (30)
#define MAX_TLS_CYCLES (32)
#define EXTRA_CREATE_PERMS (25)

static uint64_t current_reservation_token = 0;
static int allocate_rtcp = 0;
static const int never_allocate_rtcp = 0;

#if ALPN_SUPPORTED
static const unsigned char kALPNProtos[] = "\x08http/1.1\x09stun.turn\x12stun.nat-discovery";
static const size_t kALPNProtosLen = sizeof(kALPNProtos) - 1;
#endif

/////////////////////////////////////////

int rare_event(void)
{
	if(dos)
		return (((unsigned long)random()) %1000 == 777);
	return 0;
}

int not_rare_event(void)
{
	if(dos)
		return ((((unsigned long)random()) %1000) < 200);
	return 0;
}

static int get_allocate_address_family(ioa_addr *relay_addr) {
	if(relay_addr->ss.sa_family == AF_INET)
		return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
	else if(relay_addr->ss.sa_family == AF_INET6)
		return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
	else
		return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_INVALID;
}

/////////////////////////////////////////

static SSL* tls_connect(ioa_socket_raw fd, ioa_addr *remote_addr, int *try_again, int connect_cycle)
{

	int ctxtype = (int)(((unsigned long)random())%root_tls_ctx_num);

	SSL *ssl;

	ssl = SSL_NEW(root_tls_ctx[ctxtype]);

#if ALPN_SUPPORTED
	SSL_set_alpn_protos(ssl, kALPNProtos, kALPNProtosLen);
#endif

	if(use_tcp) {
		SSL_set_fd(ssl, fd);
	} else {
#if !DTLS_SUPPORTED
	  UNUSED_ARG(remote_addr);
	  fprintf(stderr,"ERROR: DTLS is not supported.\n");
	  exit(-1);
#else
		/* Create BIO, connect and set to already connected */
		BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
		//bio = BIO_new_socket(fd, BIO_CLOSE);

		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr->ss);

		SSL_set_bio(ssl, bio, bio);

		{
			struct timeval timeout;
			/* Set and activate timeouts */
			timeout.tv_sec = DTLS_MAX_CONNECT_TIMEOUT;
			timeout.tv_usec = 0;
			BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
		}

		set_mtu_df(ssl, fd, remote_addr->ss.sa_family, SOSO_MTU, !use_tcp, clnet_verbose);
#endif
	}

	SSL_set_max_cert_list(ssl, 655350);

	if (clnet_verbose)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "call SSL_connect...\n");

	int rc = 0;

	do {
		do {
			rc = SSL_connect(ssl);
		} while (rc < 0 && errno == EINTR);
		int orig_errno = errno;
		if (rc > 0) {
		  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: client session connected with cipher %s, method=%s\n",__FUNCTION__,
				  SSL_get_cipher(ssl),turn_get_ssl_method(ssl,NULL));
		  if(clnet_verbose && SSL_get_peer_certificate(ssl)) {
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "------------------------------------------------------------\n");
		  	X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)), 1,
		  						XN_FLAG_MULTILINE);
		  	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n\n Cipher: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		  	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n------------------------------------------------------------\n\n");
		  }
		  break;
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cannot connect: rc=%d, ctx=%d\n",
					__FUNCTION__,rc,ctxtype);

			switch (SSL_get_error(ssl, rc)) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				if(!dos) usleep(1000);
				continue;
			default: {
				char buf[1025];
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "errno=%d, err=%d, %s (%d)\n",orig_errno,
								(int)ERR_get_error(), ERR_error_string(ERR_get_error(), buf), (int)SSL_get_error(ssl, rc));
				if(connect_cycle<MAX_TLS_CYCLES) {
					if(try_again) {
						SSL_FREE(ssl);
						*try_again = 1;
						return NULL;
					}
				}
				exit(-1);
			}
			};
		}
	} while (1);

	if (clnet_verbose && SSL_get_peer_certificate(ssl)) {
		if(use_tcp) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"------TLS---------------------------------------------------\n");
		} else {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"------DTLS---------------------------------------------------\n");
		}
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(
				SSL_get_peer_certificate(ssl)), 1, XN_FLAG_MULTILINE);
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n\n Cipher: %s\n",
				SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"\n------------------------------------------------------------\n\n");
	}

	return ssl;
}

int socket_connect(evutil_socket_t clnet_fd, ioa_addr *remote_addr, int *connect_err)
{
	if (addr_connect(clnet_fd, remote_addr, connect_err) < 0) {
		if(*connect_err == EINPROGRESS)
			return 0;
		if (*connect_err == EADDRINUSE)
			return +1;
		perror("connect");
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cannot connect to remote addr: %d\n", __FUNCTION__,*connect_err);
		exit(-1);
	}

	return 0;
}

static int clnet_connect(uint16_t clnet_remote_port, const char *remote_address,
		const unsigned char* ifname, const char *local_address, int verbose,
		app_ur_conn_info *clnet_info) {

	ioa_addr local_addr;
	evutil_socket_t clnet_fd;
	int connect_err;
	int connect_cycle = 0;

	ioa_addr remote_addr;

 start_socket:

	clnet_fd = -1;
	connect_err = 0;

	ns_bzero(&remote_addr, sizeof(ioa_addr));
	if (make_ioa_addr((const u08bits*) remote_address, clnet_remote_port,
			&remote_addr) < 0)
		return -1;

	ns_bzero(&local_addr, sizeof(ioa_addr));

	clnet_fd = socket(remote_addr.ss.sa_family,
			use_sctp ? SCTP_CLIENT_STREAM_SOCKET_TYPE : (use_tcp ? CLIENT_STREAM_SOCKET_TYPE : CLIENT_DGRAM_SOCKET_TYPE),
			use_sctp ? SCTP_CLIENT_STREAM_SOCKET_PROTOCOL : (use_tcp ? CLIENT_STREAM_SOCKET_PROTOCOL : CLIENT_DGRAM_SOCKET_PROTOCOL));
	if (clnet_fd < 0) {
		perror("socket");
		exit(-1);
	}

	if (sock_bind_to_device(clnet_fd, ifname) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"Cannot bind client socket to device %s\n", ifname);
	}

	set_sock_buf_size(clnet_fd, UR_CLIENT_SOCK_BUF_SIZE);

	set_raw_socket_tos(clnet_fd, remote_addr.ss.sa_family, 0x22);
	set_raw_socket_ttl(clnet_fd, remote_addr.ss.sa_family, 47);

	if(clnet_info->is_peer && (*local_address==0)) {

		if(remote_addr.ss.sa_family == AF_INET6) {
			if (make_ioa_addr((const u08bits*) "::1", 0, &local_addr) < 0) {
			    return -1;
			}
		} else {
			if (make_ioa_addr((const u08bits*) "127.0.0.1", 0, &local_addr) < 0) {
			    return -1;
			}
		}

		addr_bind(clnet_fd, &local_addr, 0, 1, get_socket_type());

	} else if (strlen(local_address) > 0) {

		if (make_ioa_addr((const u08bits*) local_address, 0,
			    &local_addr) < 0)
			return -1;

		addr_bind(clnet_fd, &local_addr,0,1,get_socket_type());
	}

	if(clnet_info->is_peer) {
		;
	} else if(socket_connect(clnet_fd, &remote_addr, &connect_err)>0)
		goto start_socket;

	if (clnet_info) {
		addr_cpy(&(clnet_info->remote_addr), &remote_addr);
		addr_cpy(&(clnet_info->local_addr), &local_addr);
		clnet_info->fd = clnet_fd;
		addr_get_from_sock(clnet_fd, &(clnet_info->local_addr));
		STRCPY(clnet_info->lsaddr,local_address);
		STRCPY(clnet_info->rsaddr,remote_address);
		STRCPY(clnet_info->ifname,(const char*)ifname);
	}

	if (use_secure) {
		int try_again = 0;
		clnet_info->ssl = tls_connect(clnet_info->fd, &remote_addr,&try_again,connect_cycle++);
		if (!clnet_info->ssl) {
			if(try_again) {
				goto start_socket;
			}
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cannot SSL connect to remote addr\n", __FUNCTION__);
			exit(-1);
		}
	}

	if(verbose && clnet_info) {
		addr_debug_print(verbose, &(clnet_info->local_addr), "Connected from");
		addr_debug_print(verbose, &remote_addr, "Connected to");
	}

	if(!dos) usleep(500);

	return 0;
}

int read_mobility_ticket(app_ur_conn_info *clnet_info, stun_buffer *message)
{
	int ret = 0;
	if(clnet_info && message) {
		stun_attr_ref s_mobile_id_sar = stun_attr_get_first_by_type(message, STUN_ATTRIBUTE_MOBILITY_TICKET);
		if(s_mobile_id_sar) {
			int smid_len = stun_attr_get_len(s_mobile_id_sar);
			if(smid_len>0 && (((size_t)smid_len)<sizeof(clnet_info->s_mobile_id))) {
				const u08bits* smid_val = stun_attr_get_value(s_mobile_id_sar);
				if(smid_val) {
					ns_bcopy(smid_val, clnet_info->s_mobile_id, (size_t)smid_len);
					clnet_info->s_mobile_id[smid_len] = 0;
					if (clnet_verbose)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"%s: smid=%s\n", __FUNCTION__, clnet_info->s_mobile_id);
				}
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
							"%s: ERROR: smid_len=%d\n", __FUNCTION__, smid_len);
				ret = -1;
			}
		}
	}
	return ret;
}

void add_origin(stun_buffer *message)
{
	if(message && origin[0]) {
		const char* some_origin = "https://carleon.gov:443";
		stun_attr_add(message, STUN_ATTRIBUTE_ORIGIN, some_origin, strlen(some_origin));
		stun_attr_add(message, STUN_ATTRIBUTE_ORIGIN, origin, strlen(origin));
		some_origin = "ftp://uffrith.net";
		stun_attr_add(message, STUN_ATTRIBUTE_ORIGIN, some_origin, strlen(some_origin));
	}
}

static int clnet_allocate(int verbose,
		app_ur_conn_info *clnet_info,
		ioa_addr *relay_addr,
		int af,
		char *turn_addr, u16bits *turn_port) {

	int af_cycle = 0;
	int reopen_socket = 0;

	int allocate_finished;

	stun_buffer request_message, response_message;

	beg_allocate:

	allocate_finished=0;

	while (!allocate_finished && af_cycle++ < 32) {

		int allocate_sent = 0;

		if(reopen_socket && !use_tcp) {
			socket_closesocket(clnet_info->fd);
			clnet_info->fd = -1;
			if (clnet_connect(addr_get_port(&(clnet_info->remote_addr)), clnet_info->rsaddr, (u08bits*)clnet_info->ifname, clnet_info->lsaddr,
					verbose, clnet_info) < 0) {
				exit(-1);
			}
			reopen_socket = 0;
		}

		int af4 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4);
		int af6 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6);

		uint64_t reservation_token = 0;
		char* rt = NULL;
		int ep = !no_rtcp && !dual_allocation;

		if(!no_rtcp) {
			if (!never_allocate_rtcp && allocate_rtcp) {
				reservation_token = ioa_ntoh64(current_reservation_token);
				rt = (char*) (&reservation_token);
			}
		}

		if(is_TCP_relay()) {
			ep = -1;
		} else if(rt) {
			ep = -1;
		} else if(!ep) {
			ep = (((u08bits)random()) % 2);
			ep = ep-1;
		}

		if(!dos)
			stun_set_allocate_request(&request_message, UCLIENT_SESSION_LIFETIME, af4, af6, relay_transport, mobility, rt, ep);
		else
			stun_set_allocate_request(&request_message, UCLIENT_SESSION_LIFETIME/3, af4, af6, relay_transport, mobility, rt, ep);

		if(bps)
			stun_attr_add_bandwidth_str(request_message.buf, (size_t*)(&(request_message.len)), bps);

		if(dont_fragment)
			stun_attr_add(&request_message, STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);

		add_origin(&request_message);

		if(add_integrity(clnet_info, &request_message)<0) return -1;

		stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));

		while (!allocate_sent) {

			int len = send_buffer(clnet_info, &request_message,0,0);

			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "allocate sent\n");
				}
				allocate_sent = 1;
			} else {
				perror("send");
				exit(1);
			}
		}

		////////////<<==allocate send

		if(not_rare_event()) return 0;

		////////allocate response==>>
		{
			int allocate_received = 0;
			while (!allocate_received) {

				int len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);

				if (len > 0) {
					if (verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
								"allocate response received: \n");
					}
					response_message.len = len;
					int err_code = 0;
					u08bits err_msg[129];
					if (stun_is_success_response(&response_message)) {
						allocate_received = 1;
						allocate_finished = 1;

						if(clnet_info->nonce[0]) {
							if(check_integrity(clnet_info, &response_message)<0)
								return -1;
						}

						if (verbose) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
						}
						{
							int found = 0;

							stun_attr_ref sar = stun_attr_get_first(&response_message);
							while (sar) {

								int attr_type = stun_attr_get_type(sar);
								if(attr_type == STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS) {

									if (stun_attr_get_addr(&response_message, sar, relay_addr, NULL) < 0) {
										TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
											"%s: !!!: relay addr cannot be received (1)\n",
											__FUNCTION__);
										return -1;
									} else {
										if (verbose) {
											ioa_addr raddr;
											memcpy(&raddr, relay_addr,sizeof(ioa_addr));
											addr_debug_print(verbose, &raddr,"Received relay addr");
										}

										if(!addr_any(relay_addr)) {
											if(relay_addr->ss.sa_family == AF_INET) {
												if(default_address_family != STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6) {
													found = 1;
													addr_cpy(&(clnet_info->relay_addr),relay_addr);
													break;
												}
											}
											if(relay_addr->ss.sa_family == AF_INET6) {
												if(default_address_family == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6) {
													found = 1;
													addr_cpy(&(clnet_info->relay_addr),relay_addr);
													break;
												}
											}
										}
									}
								}

								sar = stun_attr_get_next(&response_message,sar);
							}

							if(!found) {
								TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: !!!: relay addr cannot be received (2)\n",
										__FUNCTION__);
								return -1;
							}
						}

						stun_attr_ref rt_sar = stun_attr_get_first_by_type(
								&response_message, STUN_ATTRIBUTE_RESERVATION_TOKEN);
						uint64_t rtv = stun_attr_get_reservation_token_value(rt_sar);
						current_reservation_token = rtv;
						if (verbose)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
								      "%s: rtv=%llu\n", __FUNCTION__, (long long unsigned int)rtv);

						read_mobility_ticket(clnet_info, &response_message);

					} else if (stun_is_challenge_response_str(response_message.buf, (size_t)response_message.len,
									&err_code,err_msg,sizeof(err_msg),
									clnet_info->realm,clnet_info->nonce,
									clnet_info->server_name, &(clnet_info->oauth))) {
						goto beg_allocate;
					} else if (stun_is_error_response(&response_message, &err_code,err_msg,sizeof(err_msg))) {

						allocate_received = 1;

						if(err_code == 300) {

							if(clnet_info->nonce[0]) {
								if(check_integrity(clnet_info, &response_message)<0)
									return -1;
							}

							ioa_addr alternate_server;
							if(stun_attr_get_first_addr(&response_message, STUN_ATTRIBUTE_ALTERNATE_SERVER, &alternate_server, NULL)==-1) {
								//error
							} else if(turn_addr && turn_port){
								addr_to_string_no_port(&alternate_server, (u08bits*)turn_addr);
								*turn_port = (u16bits)addr_get_port(&alternate_server);
							}

						}

						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "error %d (%s)\n",
								      err_code,(char*)err_msg);
						if (err_code != 437) {
							allocate_finished = 1;
							current_reservation_token = 0;
							return -1;
						} else {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"trying allocate again %d...\n", err_code);
							sleep(1);
							reopen_socket = 1;
						}
					} else {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"unknown allocate response\n");
						/* Try again ? */
					}
				} else {
					perror("recv");
					exit(-1);
					break;
				}
			}
		}
	}
	////////////<<== allocate response received

	if(rare_event()) return 0;

	if(!allocate_finished) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
			"Cannot complete Allocation\n");
	  exit(-1);
	}

	allocate_rtcp = !allocate_rtcp;

	if (1) {

	  af_cycle = 0;

	  if(clnet_info->s_mobile_id[0]) {

		  int fd = clnet_info->fd;
		  SSL* ssl = clnet_info->ssl;

		  int close_now = (int)(random()%2);

		  if(close_now) {
			  int close_socket = (int)(random()%2);
			  if(ssl && !close_socket) {
				  SSL_shutdown(ssl);
				  SSL_FREE(ssl);
				  fd = -1;
			  } else if(fd>=0) {
				  close(fd);
				  fd = -1;
				  ssl = NULL;
			  }
		  }

		  app_ur_conn_info ci;
		  ns_bcopy(clnet_info,&ci,sizeof(ci));
		  ci.fd = -1;
		  ci.ssl = NULL;
		  clnet_info->fd = -1;
		  clnet_info->ssl = NULL;
		  //Reopen:
		  if(clnet_connect(addr_get_port(&(ci.remote_addr)), ci.rsaddr,
		  		(unsigned char*)ci.ifname, ci.lsaddr, clnet_verbose,
		  		clnet_info)<0) {
			  exit(-1);
		  }

		  if(ssl) {
			  SSL_shutdown(ssl);
		  	  SSL_FREE(ssl);
		  } else if(fd>=0) {
		  	  close(fd);
		  }
	  }

		beg_refresh:

	  if(af_cycle++>32) {
	    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
			  "Cannot complete Refresh\n");
	    exit(-1);
	  }

		//==>>refresh request, for an example only:
		{
			int refresh_sent = 0;

			stun_init_request(STUN_METHOD_REFRESH, &request_message);
			uint32_t lt = htonl(UCLIENT_SESSION_LIFETIME);
			stun_attr_add(&request_message, STUN_ATTRIBUTE_LIFETIME, (const char*) &lt, 4);

			if(clnet_info->s_mobile_id[0]) {
				stun_attr_add(&request_message, STUN_ATTRIBUTE_MOBILITY_TICKET, (const char*)clnet_info->s_mobile_id, strlen(clnet_info->s_mobile_id));
			}

			if(dual_allocation && !mobility) {
				int t = ((u08bits)random())%3;
				if(t) {
					u08bits field[4];
					field[0] = (t==1) ? (u08bits)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4 : (u08bits)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
					field[1]=0;
					field[2]=0;
					field[3]=0;
					stun_attr_add(&request_message, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY, (const char*) field, 4);
				}
			}

			add_origin(&request_message);

			if(add_integrity(clnet_info, &request_message)<0) return -1;

			stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));

			while (!refresh_sent) {

				int len = send_buffer(clnet_info, &request_message, 0,0);

				if (len > 0) {
					if (verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "refresh sent\n");
					}
					refresh_sent = 1;

					if(clnet_info->s_mobile_id[0]) {
						usleep(10000);
						send_buffer(clnet_info, &request_message, 0,0);
					}
				} else {
					perror("send");
					exit(1);
				}
			}
		}

		if(not_rare_event()) return 0;

		////////refresh response==>>
		{
			int refresh_received = 0;
			while (!refresh_received) {

				int len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);

				if(clnet_info->s_mobile_id[0]) {
					len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);
				}

				if (len > 0) {
					if (verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
								"refresh response received: \n");
					}
					response_message.len = len;
					int err_code = 0;
					u08bits err_msg[129];
					if (stun_is_success_response(&response_message)) {
						read_mobility_ticket(clnet_info, &response_message);
						refresh_received = 1;
						if (verbose) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
						}
					} else if (stun_is_challenge_response_str(response_message.buf, (size_t)response_message.len,
										&err_code,err_msg,sizeof(err_msg),
										clnet_info->realm,clnet_info->nonce,
										clnet_info->server_name, &(clnet_info->oauth))) {
						goto beg_refresh;
					} else if (stun_is_error_response(&response_message, &err_code,err_msg,sizeof(err_msg))) {
						refresh_received = 1;
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "error %d (%s)\n",
								      err_code,(char*)err_msg);
						return -1;
					} else {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown refresh response\n");
						/* Try again ? */
					}
				} else {
					perror("recv");
					exit(-1);
					break;
				}
			}
		}
	}

	return 0;
}

static int turn_channel_bind(int verbose, uint16_t *chn,
		app_ur_conn_info *clnet_info, ioa_addr *peer_addr) {

	stun_buffer request_message, response_message;

	beg_bind:

	{
		int cb_sent = 0;

		if(negative_test) {
			*chn = stun_set_channel_bind_request(&request_message, peer_addr, (u16bits)random());
		} else {
			*chn = stun_set_channel_bind_request(&request_message, peer_addr, *chn);
		}

		add_origin(&request_message);

		if(add_integrity(clnet_info, &request_message)<0) return -1;

		stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));

		while (!cb_sent) {

			int len = send_buffer(clnet_info, &request_message, 0,0);
			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "channel bind sent\n");
				}
				cb_sent = 1;
			} else {
				perror("send");
				exit(1);
			}
		}
	}

	////////////<<==channel bind send

	if(not_rare_event()) return 0;

	////////channel bind response==>>

	{
		int cb_received = 0;
		while (!cb_received) {

			int len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);
			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"cb response received: \n");
				}
				int err_code = 0;
				u08bits err_msg[129];
				if (stun_is_success_response(&response_message)) {

					cb_received = 1;

					if(clnet_info->nonce[0]) {
						if(check_integrity(clnet_info, &response_message)<0)
							return -1;
					}

					if (verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success: 0x%x\n",
								(int) (*chn));
					}
				} else if (stun_is_challenge_response_str(response_message.buf, (size_t)response_message.len,
										&err_code,err_msg,sizeof(err_msg),
										clnet_info->realm,clnet_info->nonce,
										clnet_info->server_name, &(clnet_info->oauth))) {
					goto beg_bind;
				} else if (stun_is_error_response(&response_message, &err_code,err_msg,sizeof(err_msg))) {
					cb_received = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "channel bind: error %d (%s)\n",
							      err_code,(char*)err_msg);
					return -1;
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown channel bind response\n");
					/* Try again ? */
				}
			} else {
				perror("recv");
				exit(-1);
				break;
			}
		}
	}

	return 0;
}

static int turn_create_permission(int verbose, app_ur_conn_info *clnet_info,
		ioa_addr *peer_addr, int addrnum)
{

	if(no_permissions || (addrnum<1))
		return 0;

	char saddr[129]="\0";
	if (verbose) {
		addr_to_string(peer_addr,(u08bits*)saddr);
	}

	stun_buffer request_message, response_message;

	beg_cp:

	{
		int cp_sent = 0;

		stun_init_request(STUN_METHOD_CREATE_PERMISSION, &request_message);
		{
			int addrindex;
			for(addrindex=0;addrindex<addrnum;++addrindex) {
				stun_attr_add_addr(&request_message, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer_addr+addrindex);
			}
		}

		add_origin(&request_message);

		if(add_integrity(clnet_info, &request_message)<0) return -1;

		stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));

		while (!cp_sent) {

			int len = send_buffer(clnet_info, &request_message, 0,0);

			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "create perm sent: %s\n",saddr);
				}
				cp_sent = 1;
			} else {
				perror("send");
				exit(1);
			}
		}
	}

	////////////<<==create permission send

	if(not_rare_event()) return 0;

	////////create permission response==>>

	{
		int cp_received = 0;
		while (!cp_received) {

			int len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);
			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"cp response received: \n");
				}
				int err_code = 0;
				u08bits err_msg[129];
				if (stun_is_success_response(&response_message)) {

					cp_received = 1;

					if(clnet_info->nonce[0]) {
						if(check_integrity(clnet_info, &response_message)<0)
							return -1;
					}

					if (verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
					}
				} else if (stun_is_challenge_response_str(response_message.buf, (size_t)response_message.len,
									&err_code,err_msg,sizeof(err_msg),
									clnet_info->realm,clnet_info->nonce,
									clnet_info->server_name, &(clnet_info->oauth))) {
					goto beg_cp;
				} else if (stun_is_error_response(&response_message, &err_code,err_msg,sizeof(err_msg))) {
					cp_received = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "create permission error %d (%s)\n",
							      err_code,(char*)err_msg);
					return -1;
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown create permission response\n");
					/* Try again ? */
				}
			} else {
				perror("recv");
				exit(-1);
			}
		}
	}

	return 0;
}

int start_connection(uint16_t clnet_remote_port0,
		     const char *remote_address0,
		     const unsigned char* ifname, const char *local_address,
		     int verbose,
		     app_ur_conn_info *clnet_info_probe,
		     app_ur_conn_info *clnet_info,
		     uint16_t *chn,
		     app_ur_conn_info *clnet_info_rtcp,
		     uint16_t *chn_rtcp) {

	ioa_addr relay_addr;
	ioa_addr relay_addr_rtcp;
	ioa_addr peer_addr_rtcp;

	addr_cpy(&peer_addr_rtcp,&peer_addr);
	addr_set_port(&peer_addr_rtcp,addr_get_port(&peer_addr_rtcp)+1);

	/* Probe: */

	if (clnet_connect(clnet_remote_port0, remote_address0, ifname, local_address,
			verbose, clnet_info_probe) < 0) {
		exit(-1);
	}

	uint16_t clnet_remote_port = clnet_remote_port0;
	char remote_address[1025];
	STRCPY(remote_address,remote_address0);

	clnet_allocate(verbose, clnet_info_probe, &relay_addr, default_address_family, remote_address, &clnet_remote_port);

	/* Real: */

	*chn = 0;
	if(chn_rtcp) *chn_rtcp=0;

	if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address,
			verbose, clnet_info) < 0) {
	  exit(-1);
	}

	if(!no_rtcp) {
	  if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address,
			  verbose, clnet_info_rtcp) < 0) {
	    exit(-1);
	  }
	}

	int af = default_address_family ? default_address_family : get_allocate_address_family(&peer_addr);
	if (clnet_allocate(verbose, clnet_info, &relay_addr, af, NULL,NULL) < 0) {
	  exit(-1);
	}

	if(rare_event()) return 0;

	if(!no_rtcp) {
		af = default_address_family ? default_address_family : get_allocate_address_family(&peer_addr_rtcp);
	  if (clnet_allocate(verbose, clnet_info_rtcp, &relay_addr_rtcp, af,NULL,NULL) < 0) {
	    exit(-1);
	  }
	  if(rare_event()) return 0;
	}

	if (!dos) {
		if (!do_not_use_channel) {
			/* These multiple "channel bind" requests are here only because
			 * we are playing with the TURN server trying to screw it */
			if (turn_channel_bind(verbose, chn, clnet_info, &peer_addr_rtcp)
					< 0) {
				exit(-1);
			}
			if(rare_event()) return 0;

			if (turn_channel_bind(verbose, chn, clnet_info, &peer_addr_rtcp)
					< 0) {
				exit(-1);
			}
			if(rare_event()) return 0;
			*chn = 0;
			if (turn_channel_bind(verbose, chn, clnet_info, &peer_addr) < 0) {
				exit(-1);
			}

			if(rare_event()) return 0;
			if (turn_channel_bind(verbose, chn, clnet_info, &peer_addr) < 0) {
				exit(-1);
			}
			if(rare_event()) return 0;

			if(extra_requests) {
				const char *sarbaddr = "164.156.178.190";
				if(random() % 2 == 0)
					sarbaddr = "2001::172";
				ioa_addr arbaddr;
				make_ioa_addr((const u08bits*)sarbaddr, 333, &arbaddr);
				int i;
				int maxi = (unsigned short)random() % EXTRA_CREATE_PERMS;
				for(i=0;i<maxi;i++) {
					u16bits chni=0;
					int port = (unsigned short)random();
					if(port<1024) port += 1024;
					addr_set_port(&arbaddr, port);
					u08bits *u=(u08bits*)&(arbaddr.s4.sin_addr);
					u[(unsigned short)random()%4] = u[(unsigned short)random()%4] + 1;
					//char sss[128];
					//addr_to_string(&arbaddr,(u08bits*)sss);
					//printf("%s: 111.111: %s\n",__FUNCTION__,sss);
					turn_channel_bind(verbose, &chni, clnet_info, &arbaddr);
				}
			}

			if (!no_rtcp) {
				if (turn_channel_bind(verbose, chn_rtcp, clnet_info_rtcp,
						&peer_addr_rtcp) < 0) {
					exit(-1);
				}
			}
			if(rare_event()) return 0;

			if(extra_requests) {
				const char *sarbaddr = "64.56.78.90";
				if(random() % 2 == 0)
					sarbaddr = "2001::172";
				ioa_addr arbaddr[EXTRA_CREATE_PERMS];
				make_ioa_addr((const u08bits*)sarbaddr, 333, &arbaddr[0]);
				int i;
				int maxi = (unsigned short)random() % EXTRA_CREATE_PERMS;
				for(i=0;i<maxi;i++) {
					if(i>0)
						addr_cpy(&arbaddr[i],&arbaddr[0]);
					addr_set_port(&arbaddr[i], (unsigned short)random());
					u08bits *u=(u08bits*)&(arbaddr[i].s4.sin_addr);
					u[(unsigned short)random()%4] = u[(unsigned short)random()%4] + 1;
					//char sss[128];
					//addr_to_string(&arbaddr[i],(u08bits*)sss);
					//printf("%s: 111.111: %s\n",__FUNCTION__,sss);
				}
				turn_create_permission(verbose, clnet_info, arbaddr, maxi);
			}
		} else {

			int before=(random()%2 == 0);

			if(before) {
				if (turn_create_permission(verbose, clnet_info, &peer_addr, 1) < 0) {
					exit(-1);
				}
				if(rare_event()) return 0;
				if (turn_create_permission(verbose, clnet_info, &peer_addr_rtcp, 1)
						< 0) {
					exit(-1);
				}
				if(rare_event()) return 0;
			}

			if(extra_requests) {
				const char *sarbaddr = "64.56.78.90";
				if(random() % 2 == 0)
					sarbaddr = "2001::172";
				ioa_addr arbaddr[EXTRA_CREATE_PERMS];
				make_ioa_addr((const u08bits*)sarbaddr, 333, &arbaddr[0]);
				int i;
				int maxi = (unsigned short)random() % EXTRA_CREATE_PERMS;
				for(i=0;i<maxi;i++) {
					if(i>0)
						addr_cpy(&arbaddr[i],&arbaddr[0]);
					addr_set_port(&arbaddr[i], (unsigned short)random());
					u08bits *u=(u08bits*)&(arbaddr[i].s4.sin_addr);
					u[(unsigned short)random()%4] = u[(unsigned short)random()%4] + 1;
					//char sss[128];
					//addr_to_string(&arbaddr,(u08bits*)sss);
					//printf("%s: 111.111: %s\n",__FUNCTION__,sss);
				}
				turn_create_permission(verbose, clnet_info, arbaddr, maxi);
			}

			if(!before) {
				if (turn_create_permission(verbose, clnet_info, &peer_addr, 1) < 0) {
					exit(-1);
				}
				if(rare_event()) return 0;
				if (turn_create_permission(verbose, clnet_info, &peer_addr_rtcp, 1)
					< 0) {
					exit(-1);
				}
				if(rare_event()) return 0;
			}

			if (!no_rtcp) {
				if (turn_create_permission(verbose, clnet_info_rtcp,
						&peer_addr_rtcp, 1) < 0) {
					exit(-1);
				}
				if(rare_event()) return 0;
				if (turn_create_permission(verbose, clnet_info_rtcp, &peer_addr, 1)
						< 0) {
					exit(-1);
				}
				if(rare_event()) return 0;
			}
		}
	}

	addr_cpy(&(clnet_info->peer_addr), &peer_addr);
	if(!no_rtcp) 
	  addr_cpy(&(clnet_info_rtcp->peer_addr), &peer_addr_rtcp);

	return 0;
}


int start_c2c_connection(uint16_t clnet_remote_port0,
		const char *remote_address0, const unsigned char* ifname,
		const char *local_address, int verbose,
		app_ur_conn_info *clnet_info_probe,
		app_ur_conn_info *clnet_info1,
		uint16_t *chn1, app_ur_conn_info *clnet_info1_rtcp,
		uint16_t *chn1_rtcp,
		app_ur_conn_info *clnet_info2, uint16_t *chn2,
		app_ur_conn_info *clnet_info2_rtcp,
		uint16_t *chn2_rtcp) {

	ioa_addr relay_addr1;
	ioa_addr relay_addr1_rtcp;

	ioa_addr relay_addr2;
	ioa_addr relay_addr2_rtcp;

	*chn1 = 0;
	*chn2 = 0;
	if(chn1_rtcp) *chn1_rtcp=0;
	if(chn2_rtcp) *chn2_rtcp=0;

	/* Probe: */

	if (clnet_connect(clnet_remote_port0, remote_address0, ifname, local_address,
			verbose, clnet_info_probe) < 0) {
		exit(-1);
	}

	uint16_t clnet_remote_port = clnet_remote_port0;
	char remote_address[1025];
	STRCPY(remote_address,remote_address0);

	clnet_allocate(verbose, clnet_info_probe, &relay_addr1, default_address_family, remote_address, &clnet_remote_port);

	if(rare_event()) return 0;

	/* Real: */

	if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address,
			verbose, clnet_info1) < 0) {
		exit(-1);
	}

	if(!no_rtcp) 
	  if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address,
			  verbose, clnet_info1_rtcp) < 0) {
	    exit(-1);
	  }

	if(passive_tcp)
		clnet_info2->is_peer = 1;

	if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address,
			verbose, clnet_info2) < 0) {
		exit(-1);
	}

	if(!no_rtcp) 
	  if (clnet_connect(clnet_remote_port, remote_address, ifname, local_address,
			  verbose, clnet_info2_rtcp) < 0) {
	    exit(-1);
	  }

	if(!no_rtcp) {

	  if (clnet_allocate(verbose, clnet_info1, &relay_addr1, default_address_family,NULL,NULL)
	      < 0) {
	    exit(-1);
	  }
	  
	  if(rare_event()) return 0;

	  if (clnet_allocate(verbose, clnet_info1_rtcp,
			   &relay_addr1_rtcp, default_address_family,NULL,NULL) < 0) {
	    exit(-1);
	  }
	  
	  if(rare_event()) return 0;

	  if (clnet_allocate(verbose, clnet_info2, &relay_addr2, default_address_family,NULL,NULL)
	      < 0) {
	    exit(-1);
	  }
	  
	  if(rare_event()) return 0;

	  if (clnet_allocate(verbose, clnet_info2_rtcp,
			   &relay_addr2_rtcp, default_address_family,NULL,NULL) < 0) {
	    exit(-1);
	  }

	  if(rare_event()) return 0;
	} else {

	  if (clnet_allocate(verbose, clnet_info1, &relay_addr1, default_address_family,NULL,NULL)
	      < 0) {
	    exit(-1);
	  }
	  if(rare_event()) return 0;
	  if(!(clnet_info2->is_peer)) {
		  if (clnet_allocate(verbose, clnet_info2, &relay_addr2, default_address_family,NULL,NULL) < 0) {
			  exit(-1);
		  }
		  if(rare_event()) return 0;
	  } else {
		  addr_cpy(&(clnet_info2->remote_addr),&relay_addr1);
		  addr_cpy(&relay_addr2,&(clnet_info2->local_addr));
	  }
	}

	if (!do_not_use_channel) {
		if (turn_channel_bind(verbose, chn1, clnet_info1, &relay_addr2) < 0) {
			exit(-1);
		}

		if(extra_requests) {
			const char *sarbaddr = "164.156.178.190";
			if(random() % 2 == 0)
				sarbaddr = "2001::172";
			ioa_addr arbaddr;
			make_ioa_addr((const u08bits*)sarbaddr, 333, &arbaddr);
			int i;
			int maxi = (unsigned short)random() % EXTRA_CREATE_PERMS;
			for(i=0;i<maxi;i++) {
				u16bits chni=0;
				int port = (unsigned short)random();
				if(port<1024) port += 1024;
				addr_set_port(&arbaddr, port);
				u08bits *u=(u08bits*)&(arbaddr.s4.sin_addr);
				u[(unsigned short)random()%4] = u[(unsigned short)random()%4] + 1;
				//char sss[128];
				//addr_to_string(&arbaddr,(u08bits*)sss);
				//printf("%s: 111.111: %s\n",__FUNCTION__,sss);
				turn_channel_bind(verbose, &chni, clnet_info1, &arbaddr);
			}
		}

		if(rare_event()) return 0;

		if(extra_requests) {
			const char *sarbaddr = "64.56.78.90";
			if(random() % 2 == 0)
				sarbaddr = "2001::172";
			ioa_addr arbaddr[EXTRA_CREATE_PERMS];
			make_ioa_addr((const u08bits*)sarbaddr, 333, &arbaddr[0]);
			int i;
			int maxi = (unsigned short)random() % EXTRA_CREATE_PERMS;
			for(i=0;i<maxi;i++) {
				if(i>0)
					addr_cpy(&arbaddr[i],&arbaddr[0]);
				addr_set_port(&arbaddr[i], (unsigned short)random());
				u08bits *u=(u08bits*)&(arbaddr[i].s4.sin_addr);
				u[(unsigned short)random()%4] = u[(unsigned short)random()%4] + 1;
				//char sss[128];
				//addr_to_string(&arbaddr[i],(u08bits*)sss);
				//printf("%s: 111.111: %s\n",__FUNCTION__,sss);
			}
			turn_create_permission(verbose, clnet_info1, arbaddr, maxi);
		}

		if(!no_rtcp)
		  if (turn_channel_bind(verbose, chn1_rtcp, clnet_info1_rtcp,
					&relay_addr2_rtcp) < 0) {
		    exit(-1);
		  }
		if(rare_event()) return 0;
		if (turn_channel_bind(verbose, chn2, clnet_info2, &relay_addr1) < 0) {
			exit(-1);
		}
		if(rare_event()) return 0;
		if(!no_rtcp)
		  if (turn_channel_bind(verbose, chn2_rtcp, clnet_info2_rtcp,
					&relay_addr1_rtcp) < 0) {
		    exit(-1);
		  }
		if(rare_event()) return 0;
	} else {

		if (turn_create_permission(verbose, clnet_info1, &relay_addr2, 1) < 0) {
			exit(-1);
		}

		if(extra_requests) {
			const char *sarbaddr = "64.56.78.90";
			if(random() % 2 == 0)
				sarbaddr = "2001::172";
			ioa_addr arbaddr;
			make_ioa_addr((const u08bits*)sarbaddr, 333, &arbaddr);
			int i;
			int maxi = (unsigned short)random() % EXTRA_CREATE_PERMS;
			for(i=0;i<maxi;i++) {
				addr_set_port(&arbaddr, (unsigned short)random());
				u08bits *u=(u08bits*)&(arbaddr.s4.sin_addr);
				u[(unsigned short)random()%4] = u[(unsigned short)random()%4] + 1;
				//char sss[128];
				//addr_to_string(&arbaddr,(u08bits*)sss);
				//printf("%s: 111.111: %s\n",__FUNCTION__,sss);
				turn_create_permission(verbose, clnet_info1, &arbaddr, 1);
			}
		}

		if(rare_event()) return 0;
		if (!no_rtcp)
			if (turn_create_permission(verbose, clnet_info1_rtcp, &relay_addr2_rtcp, 1) < 0) {
				exit(-1);
			}
		if(rare_event()) return 0;
		if(!(clnet_info2->is_peer)) {
			if (turn_create_permission(verbose, clnet_info2, &relay_addr1, 1) < 0) {
				exit(-1);
			}
			if(rare_event()) return 0;
		}
		if (!no_rtcp)
			if (turn_create_permission(verbose, clnet_info2_rtcp, &relay_addr1_rtcp, 1) < 0) {
				exit(-1);
			}
		if(rare_event()) return 0;
	}

	addr_cpy(&(clnet_info1->peer_addr), &relay_addr2);
	if(!no_rtcp)
	  addr_cpy(&(clnet_info1_rtcp->peer_addr), &relay_addr2_rtcp);
	addr_cpy(&(clnet_info2->peer_addr), &relay_addr1);
	if(!no_rtcp)
	  addr_cpy(&(clnet_info2_rtcp->peer_addr), &relay_addr1_rtcp);

	return 0;
}

//////////// RFC 6062 ///////////////

int turn_tcp_connect(int verbose, app_ur_conn_info *clnet_info, ioa_addr *peer_addr) {

	{
		int cp_sent = 0;

		stun_buffer message;

		stun_init_request(STUN_METHOD_CONNECT, &message);
		stun_attr_add_addr(&message, STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer_addr);

		add_origin(&message);

		if(add_integrity(clnet_info, &message)<0) return -1;

		stun_attr_add_fingerprint_str(message.buf,(size_t*)&(message.len));

		while (!cp_sent) {

			int len = send_buffer(clnet_info, &message, 0,0);

			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "tcp connect sent\n");
				}
				cp_sent = 1;
			} else {
				perror("send");
				exit(1);
			}
		}
	}

	////////////<<==connect send

	return 0;
}

static int turn_tcp_connection_bind(int verbose, app_ur_conn_info *clnet_info, app_tcp_conn_info *atc, int errorOK) {

	stun_buffer request_message, response_message;

	beg_cb:

	{
		int cb_sent = 0;

		u32bits cid = atc->cid;

		stun_init_request(STUN_METHOD_CONNECTION_BIND, &request_message);

		stun_attr_add(&request_message, STUN_ATTRIBUTE_CONNECTION_ID, (const s08bits*)&cid,4);

		add_origin(&request_message);

		if(add_integrity(clnet_info, &request_message)<0) return -1;

		stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));

		while (!cb_sent) {

			int len = send_buffer(clnet_info, &request_message, 1, atc);

			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "connection bind sent\n");
				}
				cb_sent = 1;
			} else {
				if(errorOK)
					return 0;
				perror("send");
				exit(1);
			}
		}
	}

	////////////<<==connection bind send

	if(not_rare_event()) return 0;

	////////connection bind response==>>

	{
		int cb_received = 0;
		while (!cb_received) {

			int len = recv_buffer(clnet_info, &response_message, 1, 1, atc, &request_message);
			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"connect bind response received: \n");
				}
				int err_code = 0;
				u08bits err_msg[129];
				if (stun_is_success_response(&response_message)) {

					if(clnet_info->nonce[0]) {
						if(check_integrity(clnet_info, &response_message)<0)
							return -1;
					}

					if(stun_get_method(&response_message)!=STUN_METHOD_CONNECTION_BIND)
						continue;
					cb_received = 1;
					if (verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
					}
					atc->tcp_data_bound = 1;
				} else if (stun_is_challenge_response_str(response_message.buf, (size_t)response_message.len,
										&err_code,err_msg,sizeof(err_msg),
										clnet_info->realm,clnet_info->nonce,
										clnet_info->server_name, &(clnet_info->oauth))) {
					goto beg_cb;
				} else if (stun_is_error_response(&response_message, &err_code,err_msg,sizeof(err_msg))) {
					cb_received = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "connection bind error %d (%s)\n",
							      err_code,(char*)err_msg);
					return -1;
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown connection bind response\n");
					/* Try again ? */
				}
			} else {
				if(errorOK)
					return 0;
				perror("recv");
				exit(-1);
			}
		}
	}

	return 0;
}

void tcp_data_connect(app_ur_session *elem, u32bits cid)
{
	int clnet_fd;
	int connect_cycle = 0;

	again:

	clnet_fd = socket(elem->pinfo.remote_addr.ss.sa_family, CLIENT_STREAM_SOCKET_TYPE, CLIENT_STREAM_SOCKET_PROTOCOL);
	if (clnet_fd < 0) {
		perror("socket");
		exit(-1);
	}

	if (sock_bind_to_device(clnet_fd, client_ifname) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
						"Cannot bind client socket to device %s\n", client_ifname);
	}
	set_sock_buf_size(clnet_fd, (UR_CLIENT_SOCK_BUF_SIZE<<2));

	++elem->pinfo.tcp_conn_number;
	int i = (int)(elem->pinfo.tcp_conn_number-1);
	elem->pinfo.tcp_conn=(app_tcp_conn_info**)turn_realloc(elem->pinfo.tcp_conn,0,elem->pinfo.tcp_conn_number*sizeof(app_tcp_conn_info*));
	elem->pinfo.tcp_conn[i]=(app_tcp_conn_info*)turn_malloc(sizeof(app_tcp_conn_info));
	ns_bzero(elem->pinfo.tcp_conn[i],sizeof(app_tcp_conn_info));

	elem->pinfo.tcp_conn[i]->tcp_data_fd = clnet_fd;
	elem->pinfo.tcp_conn[i]->cid = cid;

	addr_cpy(&(elem->pinfo.tcp_conn[i]->tcp_data_local_addr),&(elem->pinfo.local_addr));

	addr_set_port(&(elem->pinfo.tcp_conn[i]->tcp_data_local_addr),0);

	addr_bind(clnet_fd, &(elem->pinfo.tcp_conn[i]->tcp_data_local_addr), 1, 1, TCP_SOCKET);

	addr_get_from_sock(clnet_fd,&(elem->pinfo.tcp_conn[i]->tcp_data_local_addr));

	{
	  int cycle = 0;
	  while(cycle++<1024) {
	    int err = 0;
	    if (addr_connect(clnet_fd, &(elem->pinfo.remote_addr),&err) < 0) {
	      if(err == EADDRINUSE) {
	    	  socket_closesocket(clnet_fd);
	    	  clnet_fd = socket(elem->pinfo.remote_addr.ss.sa_family, CLIENT_STREAM_SOCKET_TYPE, CLIENT_STREAM_SOCKET_PROTOCOL);
	    	  if (clnet_fd < 0) {
	    		  perror("socket");
	    		  exit(-1);
	    	  }
	    	  if (sock_bind_to_device(clnet_fd, client_ifname) < 0) {
	    		  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
	    				  "Cannot bind client socket to device %s\n", client_ifname);
	    	  }
	    	  set_sock_buf_size(clnet_fd, UR_CLIENT_SOCK_BUF_SIZE<<2);

	    	  elem->pinfo.tcp_conn[i]->tcp_data_fd = clnet_fd;

	    	  addr_cpy(&(elem->pinfo.tcp_conn[i]->tcp_data_local_addr),&(elem->pinfo.local_addr));

	    	  addr_set_port(&(elem->pinfo.tcp_conn[i]->tcp_data_local_addr),0);

	    	  addr_bind(clnet_fd, &(elem->pinfo.tcp_conn[i]->tcp_data_local_addr),1,1,TCP_SOCKET);

	    	  addr_get_from_sock(clnet_fd,&(elem->pinfo.tcp_conn[i]->tcp_data_local_addr));

	    	  continue;

	      } else {
	    	  perror("connect");
	    	  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
			      "%s: cannot connect to remote addr\n", __FUNCTION__);
	    	  exit(-1);
	      }
	    } else {
	      break;
	    }
	  }
	}

	if(use_secure) {
		int try_again = 0;
		elem->pinfo.tcp_conn[i]->tcp_data_ssl = tls_connect(elem->pinfo.tcp_conn[i]->tcp_data_fd, &(elem->pinfo.remote_addr),&try_again, connect_cycle++);
		if(!(elem->pinfo.tcp_conn[i]->tcp_data_ssl)) {
			if(try_again) {
				--elem->pinfo.tcp_conn_number;
				goto again;
			}
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					"%s: cannot SSL connect to remote addr\n", __FUNCTION__);
			exit(-1);
		}
	}

	if(turn_tcp_connection_bind(clnet_verbose, &(elem->pinfo), elem->pinfo.tcp_conn[i],0)<0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"%s: cannot BIND to tcp connection\n", __FUNCTION__);
	} else {

		socket_set_nonblocking(clnet_fd);

		struct event* ev = event_new(client_event_base,clnet_fd,
					EV_READ|EV_PERSIST,client_input_handler,
					elem);

		event_add(ev,NULL);

		elem->input_tcp_data_ev = ev;

		addr_debug_print(clnet_verbose, &(elem->pinfo.remote_addr), "TCP data network connected to");
	}
}

/////////////////////////////////////////////////
