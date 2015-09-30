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

#include "apputils.h"
#include "mainrelay.h"

#include "dtls_listener.h"
#include "ns_ioalib_impl.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <pthread.h>

/* #define REQUEST_CLIENT_CERT */

///////////////////////////////////////////////////

#define FUNCSTART if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:start\n",__FUNCTION__,__LINE__)
#define FUNCEND if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:end\n",__FUNCTION__,__LINE__)

#define COOKIE_SECRET_LENGTH (32)

#define MAX_SINGLE_UDP_BATCH (16)

struct dtls_listener_relay_server_info {
  char ifname[1025];
  ioa_addr addr;
  ioa_engine_handle e;
  turn_turnserver *ts;
  int verbose;
#if DTLS_SUPPORTED
  SSL_CTX *dtls_ctx;
#if DTLSv1_2_SUPPORTED
  SSL_CTX *dtls_ctx_v1_2;
#endif
#endif
  struct event *udp_listen_ev;
  ioa_socket_handle udp_listen_s;
  ur_addr_map *children_ss; /* map of socket children on remote addr */
  struct message_to_relay sm;
  int slen0;
  ioa_engine_new_connection_event_handler connect_cb;
};

///////////// forward declarations ////////

static int create_server_socket(dtls_listener_relay_server_type* server, int report_creation);
static int clean_server(dtls_listener_relay_server_type* server);
static int reopen_server_socket(dtls_listener_relay_server_type* server, evutil_socket_t fd);

///////////// dtls message types //////////

int is_dtls_handshake_message(const unsigned char* buf, int len);
int is_dtls_data_message(const unsigned char* buf, int len);
int is_dtls_alert_message(const unsigned char* buf, int len);
int is_dtls_cipher_change_message(const unsigned char* buf, int len);
int get_dtls_version(const unsigned char* buf, int len);

int is_dtls_message(const unsigned char* buf, int len);

int is_dtls_handshake_message(const unsigned char* buf, int len) {
  return (buf && len>3 && buf[0]==0x16 && buf[1]==0xfe && ((buf[2]==0xff)||(buf[2]==0xfd)));
}

int is_dtls_data_message(const unsigned char* buf, int len) {
  return (buf && len>3 && buf[0]==0x17 && buf[1]==0xfe && ((buf[2]==0xff)||(buf[2]==0xfd)));
}

int is_dtls_alert_message(const unsigned char* buf, int len) {
  return (buf && len>3 && buf[0]==0x15 && buf[1]==0xfe && ((buf[2]==0xff)||(buf[2]==0xfd)));
}

int is_dtls_cipher_change_message(const unsigned char* buf, int len) {
  return (buf && len>3 && buf[0]==0x14 && buf[1]==0xfe && ((buf[2]==0xff)||(buf[2]==0xfd)));
}

int is_dtls_message(const unsigned char* buf, int len) {
  if(buf && (len>3) && (buf[1])==0xfe && ((buf[2]==0xff)||(buf[2]==0xfd))) {
	  switch (buf[0]) {
	  case 0x14:
	  case 0x15:
	  case 0x16:
	  case 0x17:
		  return 1;
	  default:
		  ;
	  }
  }
  return 0;
}

/* 0 - 1.0, 1 - 1.2 */
int get_dtls_version(const unsigned char* buf, int len) {
	if(buf && (len>3) && (buf[2] == 0xfd))
		return 1;
	return 0;
}

///////////// utils /////////////////////

#if DTLS_SUPPORTED

static void calculate_cookie(SSL* ssl, unsigned char *cookie_secret, unsigned int cookie_length) {
  long rv=(long)ssl;
  long inum=(cookie_length-(((long)cookie_secret)%sizeof(long)))/sizeof(long);
  long i=0;
  long *ip=(long*)cookie_secret;
  for(i=0;i<inum;++i,++ip) *ip=rv;
}

static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned int length = 0, resultlength;
  ioa_addr peer;

  unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
  calculate_cookie(ssl, cookie_secret, sizeof(cookie_secret));
  
  /* Read peer information */
  (void) BIO_dgram_get_peer(SSL_get_wbio(ssl), &peer);
  
  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.sa_family) {
  case AF_INET:
    length += sizeof(struct in_addr);
    break;
  case AF_INET6:
    length += sizeof(struct in6_addr);
    break;
  default:
    OPENSSL_assert(0);
    break;
  }
  length += sizeof(in_port_t);
  buffer = (unsigned char*) OPENSSL_malloc(length);
  
  if (buffer == NULL) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"out of memory\n");
    return 0;
  }
  
  switch (peer.ss.sa_family) {
  case AF_INET:
    memcpy(buffer,
	   &peer.s4.sin_port,
	   sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.s4.sin_port),
	   &peer.s4.sin_addr,
	   sizeof(struct in_addr));
    break;
  case AF_INET6:
    memcpy(buffer,
	   &peer.s6.sin6_port,
	   sizeof(in_port_t));
    memcpy(buffer + sizeof(in_port_t),
	   &peer.s6.sin6_addr,
	   sizeof(struct in6_addr));
    break;
  default:
    OPENSSL_assert(0);
    break;
  }
  
  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
       (const unsigned char*) buffer, length, result, &resultlength);
  OPENSSL_free(buffer);
  
  memcpy(cookie, result, resultlength);
  *cookie_len = resultlength;
  
  return 1;
}

static int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
  unsigned int resultlength=0;
  unsigned char result[COOKIE_SECRET_LENGTH];

  generate_cookie(ssl, result, &resultlength);
  
  if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0) {
    //TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: cookies are OK, length=%u\n",__FUNCTION__,cookie_len);
    return 1;
  }
  
  return 0;
}

/////////////// io handlers ///////////////////

static ioa_socket_handle dtls_accept_client_connection(
				dtls_listener_relay_server_type* server,
				ioa_socket_handle sock,
				SSL *ssl,
				ioa_addr *remote_addr, ioa_addr *local_addr,
				ioa_network_buffer_handle nbh)
{
	FUNCSTART;

	if (!ssl)
		return NULL;

	int rc = ssl_read(sock->fd, ssl, nbh, server->verbose);

	if (rc < 0)
		return NULL;

	addr_debug_print(server->verbose, remote_addr, "Accepted connection from");

	ioa_socket_handle ioas = create_ioa_socket_from_ssl(server->e, sock, ssl, DTLS_SOCKET, CLIENT_SOCKET, remote_addr, local_addr);
	if(ioas) {
		addr_cpy(&(server->sm.m.sm.nd.src_addr),remote_addr);
		server->sm.m.sm.nd.recv_ttl = TTL_IGNORE;
		server->sm.m.sm.nd.recv_tos = TOS_IGNORE;
		server->sm.m.sm.s = ioas;
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot create ioa_socket from SSL\n");
	}

	FUNCEND	;

	return ioas;
}

static ioa_socket_handle dtls_server_input_handler(dtls_listener_relay_server_type* server,
				ioa_socket_handle s,
				ioa_network_buffer_handle nbh)
{
	FUNCSTART;

	if (!server || !nbh) {
		return NULL;
	}

	SSL* connecting_ssl = NULL;

	BIO *wbio = NULL;
	struct timeval timeout;

	/* Create BIO */
	wbio = BIO_new_dgram(s->fd, BIO_NOCLOSE);
	(void)BIO_dgram_set_peer(wbio, (struct sockaddr*) &(server->sm.m.sm.nd.src_addr));

	/* Set and activate timeouts */
	timeout.tv_sec = DTLS_MAX_RECV_TIMEOUT;
	timeout.tv_usec = 0;
	BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

#if DTLSv1_2_SUPPORTED
	if(get_dtls_version(ioa_network_buffer_data(nbh),
							(int)ioa_network_buffer_get_size(nbh)) == 1) {
		connecting_ssl = SSL_NEW(server->dtls_ctx_v1_2);
	} else {
		connecting_ssl = SSL_NEW(server->dtls_ctx);
	}
#else
	{
		connecting_ssl = SSL_NEW(server->dtls_ctx);
	}
#endif

	SSL_set_accept_state(connecting_ssl);

	SSL_set_bio(connecting_ssl, NULL, wbio);
	SSL_set_options(connecting_ssl, SSL_OP_COOKIE_EXCHANGE);

	SSL_set_max_cert_list(connecting_ssl, 655350);

	ioa_socket_handle rc = dtls_accept_client_connection(server, s, connecting_ssl,
					&(server->sm.m.sm.nd.src_addr),
					&(server->addr),
					nbh);

	if (!rc) {
		if (!(SSL_get_shutdown(connecting_ssl) & SSL_SENT_SHUTDOWN)) {
			SSL_set_shutdown(connecting_ssl, SSL_RECEIVED_SHUTDOWN);
			SSL_shutdown(connecting_ssl);
		}
		SSL_FREE(connecting_ssl);
	}

	return rc;
}

#endif

static int handle_udp_packet(dtls_listener_relay_server_type *server,
				struct message_to_relay *sm,
				ioa_engine_handle ioa_eng, turn_turnserver *ts)
{
	int verbose = ioa_eng->verbose;
	ioa_socket_handle s = sm->m.sm.s;

	ur_addr_map_value_type mvt = 0;
	if(!(server->children_ss)) {
		server->children_ss = (ur_addr_map*)allocate_super_memory_engine(server->e, sizeof(ur_addr_map));
		ur_addr_map_init(server->children_ss);
	}
	ur_addr_map *amap = server->children_ss;

	ioa_socket_handle chs = NULL;
	if ((ur_addr_map_get(amap, &(sm->m.sm.nd.src_addr), &mvt) > 0) && mvt) {
		chs = (ioa_socket_handle) mvt;
	}

	if (chs && !ioa_socket_tobeclosed(chs)
			&& (chs->sockets_container == amap)
			&& (chs->magic == SOCKET_MAGIC)) {
		s = chs;
		sm->m.sm.s = s;
		if(s->ssl) {
			int sslret = ssl_read(s->fd, s->ssl, sm->m.sm.nd.nbh, verbose);
			if(sslret < 0) {
				ioa_network_buffer_delete(ioa_eng, sm->m.sm.nd.nbh);
				sm->m.sm.nd.nbh = NULL;
				ts_ur_super_session *ss = (ts_ur_super_session *) s->session;
				if (ss) {
					turn_turnserver *server = (turn_turnserver *) ss->server;
					if (server) {
						shutdown_client_connection(server, ss, 0, "SSL read error");
					}
				} else {
					close_ioa_socket(s);
				}
				ur_addr_map_del(amap, &(sm->m.sm.nd.src_addr), NULL);
				sm->m.sm.s = NULL;
				s = NULL;
				chs = NULL;
			} else if(ioa_network_buffer_get_size(sm->m.sm.nd.nbh)>0) {
				;
			} else {
				ioa_network_buffer_delete(ioa_eng, sm->m.sm.nd.nbh);
				sm->m.sm.nd.nbh = NULL;
			}
		}

		if(s && ioa_socket_check_bandwidth(s,sm->m.sm.nd.nbh,1)) {
			s->e = ioa_eng;
			if (s && s->read_cb && sm->m.sm.nd.nbh) {
				s->read_cb(s, IOA_EV_READ, &(sm->m.sm.nd), s->read_ctx, 1);
				ioa_network_buffer_delete(ioa_eng, sm->m.sm.nd.nbh);
				sm->m.sm.nd.nbh = NULL;

				if (ioa_socket_tobeclosed(s)) {
					ts_ur_super_session *ss = (ts_ur_super_session *) s->session;
					if (ss) {
						turn_turnserver *server = (turn_turnserver *) ss->server;
						if (server) {
							shutdown_client_connection(server, ss, 0, "UDP packet processing error");
						}
					}
				}
			}
		}
	} else {
		if (chs && ioa_socket_tobeclosed(chs)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"%s: socket to be closed\n", __FUNCTION__);
			{
				u08bits saddr[129];
				u08bits rsaddr[129];
				long thrid = (long) pthread_self();
				addr_to_string(get_local_addr_from_ioa_socket(chs),saddr);
				addr_to_string(get_remote_addr_from_ioa_socket(chs),rsaddr);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					"%s: 111.111: thrid=0x%lx: Amap = 0x%lx, socket container=0x%lx, local addr %s, remote addr %s, s=0x%lx, done=%d, tbc=%d\n",
					__FUNCTION__, thrid, (long) amap,
					(long) (chs->sockets_container), (char*) saddr,
					(char*) rsaddr, (long) s, (int) (chs->done),
					(int) (chs->tobeclosed));
			}
		}

		if (chs && (chs->magic != SOCKET_MAGIC)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"%s: wrong socket magic\n", __FUNCTION__);
		}

		if (chs && (chs->sockets_container != amap)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"%s: wrong socket container\n", __FUNCTION__);
			{
				u08bits saddr[129];
				u08bits rsaddr[129];
				long thrid = (long) pthread_self();
				addr_to_string(get_local_addr_from_ioa_socket(chs),saddr);
				addr_to_string(get_remote_addr_from_ioa_socket(chs),rsaddr);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					"%s: 111.222: thrid=0x%lx: Amap = 0x%lx, socket container=0x%lx, local addr %s, remote addr %s, s=0x%lx, done=%d, tbc=%d, st=%d, sat=%d\n",
					__FUNCTION__, thrid, (long) amap,
					(long) (chs->sockets_container), (char*) saddr,
					(char*) rsaddr, (long) chs, (int) (chs->done),
					(int) (chs->tobeclosed), (int) (chs->st),
					(int) (chs->sat));
			}
		}

		chs = NULL;

#if DTLS_SUPPORTED
		if (!turn_params.no_dtls &&
			is_dtls_handshake_message(ioa_network_buffer_data(sm->m.sm.nd.nbh),
			(int)ioa_network_buffer_get_size(sm->m.sm.nd.nbh))) {
			chs = dtls_server_input_handler(server,s, sm->m.sm.nd.nbh);
			ioa_network_buffer_delete(server->e, sm->m.sm.nd.nbh);
			sm->m.sm.nd.nbh = NULL;
		}
#endif

		if(!chs) {
			chs = create_ioa_socket_from_fd(ioa_eng, s->fd, s,
				UDP_SOCKET, CLIENT_SOCKET, &(sm->m.sm.nd.src_addr),
				get_local_addr_from_ioa_socket(s));
		}

		s = chs;
		sm->m.sm.s = s;

		if (s) {
			if(verbose) {
				u08bits saddr[129];
				u08bits rsaddr[129];
				addr_to_string(get_local_addr_from_ioa_socket(s),saddr);
				addr_to_string(get_remote_addr_from_ioa_socket(s),rsaddr);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
					"%s: New UDP endpoint: local addr %s, remote addr %s\n",
					__FUNCTION__, (char*) saddr,(char*) rsaddr);
			}
			s->e = ioa_eng;
			add_socket_to_map(s, amap);
			if(open_client_connection_session(ts, &(sm->m.sm))<0) {
				return -1;
			}
		}
	}

	return 0;
}

static int create_new_connected_udp_socket(
		dtls_listener_relay_server_type* server, ioa_socket_handle s)
{

	evutil_socket_t udp_fd = socket(s->local_addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
	if (udp_fd < 0) {
		perror("socket");
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot allocate new socket\n",
				__FUNCTION__);
		return -1;
	}

	if (sock_bind_to_device(udp_fd, (unsigned char*) (s->e->relay_ifname))
			< 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"Cannot bind udp server socket to device %s\n",
				(char*) (s->e->relay_ifname));
	}

	ioa_socket_handle ret = (ioa_socket*) turn_malloc(sizeof(ioa_socket));
	if (!ret) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"%s: Cannot allocate new socket structure\n", __FUNCTION__);
		close(udp_fd);
		return -1;
	}

	ns_bzero(ret, sizeof(ioa_socket));

	ret->magic = SOCKET_MAGIC;

	ret->fd = udp_fd;

	ret->family = s->family;
	ret->st = s->st;
	ret->sat = CLIENT_SOCKET;
	ret->local_addr_known = 1;
	addr_cpy(&(ret->local_addr), &(s->local_addr));

	if (addr_bind(udp_fd,&(s->local_addr),1,1,UDP_SOCKET) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"Cannot bind new detached udp server socket to local addr\n");
		IOA_CLOSE_SOCKET(ret);
		return -1;
	}
	ret->bound = 1;

	{
		int connect_err = 0;
		if (addr_connect(udp_fd, &(server->sm.m.sm.nd.src_addr), &connect_err) < 0) {
			char sl[129];
			char sr[129];
			addr_to_string(&(ret->local_addr),(u08bits*)sl);
			addr_to_string(&(server->sm.m.sm.nd.src_addr),(u08bits*)sr);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"Cannot connect new detached udp client socket from local addr %s to remote addr %s\n",sl,sr);
			IOA_CLOSE_SOCKET(ret);
			return -1;
		}
	}
	ret->connected = 1;
	addr_cpy(&(ret->remote_addr), &(server->sm.m.sm.nd.src_addr));

	set_socket_options(ret);

	ret->current_ttl = s->current_ttl;
	ret->default_ttl = s->default_ttl;

	ret->current_tos = s->current_tos;
	ret->default_tos = s->default_tos;

#if DTLS_SUPPORTED
	if (!turn_params.no_dtls
			&& is_dtls_handshake_message(
					ioa_network_buffer_data(server->sm.m.sm.nd.nbh),
					(int) ioa_network_buffer_get_size(
							server->sm.m.sm.nd.nbh))) {

		SSL* connecting_ssl = NULL;

		BIO *wbio = NULL;
		struct timeval timeout;

		/* Create BIO */
		wbio = BIO_new_dgram(ret->fd, BIO_NOCLOSE);
		(void) BIO_dgram_set_peer(wbio, (struct sockaddr*) &(server->sm.m.sm.nd.src_addr));

		BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &(server->sm.m.sm.nd.src_addr));

		/* Set and activate timeouts */
		timeout.tv_sec = DTLS_MAX_RECV_TIMEOUT;
		timeout.tv_usec = 0;
		BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

#if DTLSv1_2_SUPPORTED
		if(get_dtls_version(ioa_network_buffer_data(server->sm.m.sm.nd.nbh),
							(int)ioa_network_buffer_get_size(server->sm.m.sm.nd.nbh)) == 1) {
			connecting_ssl = SSL_NEW(server->dtls_ctx_v1_2);
		} else {
			connecting_ssl = SSL_NEW(server->dtls_ctx);
		}
#else
		{
			connecting_ssl = SSL_NEW(server->dtls_ctx);
		}
#endif

		SSL_set_accept_state(connecting_ssl);

		SSL_set_bio(connecting_ssl, NULL, wbio);

		SSL_set_options(connecting_ssl, SSL_OP_COOKIE_EXCHANGE);
		SSL_set_max_cert_list(connecting_ssl, 655350);
		int rc = ssl_read(ret->fd, connecting_ssl, server->sm.m.sm.nd.nbh,
				server->verbose);

		if (rc < 0) {
			if (!(SSL_get_shutdown(connecting_ssl) & SSL_SENT_SHUTDOWN)) {
				SSL_set_shutdown(connecting_ssl, SSL_RECEIVED_SHUTDOWN);
				SSL_shutdown(connecting_ssl);
			}
			SSL_FREE(connecting_ssl);
			IOA_CLOSE_SOCKET(ret);
			return -1;
		}

		addr_debug_print(server->verbose, &(server->sm.m.sm.nd.src_addr),
				"Accepted DTLS connection from");

		ret->ssl = connecting_ssl;

		ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
		server->sm.m.sm.nd.nbh = NULL;

		ret->st = DTLS_SOCKET;
	}
#endif

	server->sm.m.sm.s = ret;
	return server->connect_cb(server->e, &(server->sm));
}

static void udp_server_input_handler(evutil_socket_t fd, short what, void* arg)
{
	int cycle = 0;

	dtls_listener_relay_server_type* server = (dtls_listener_relay_server_type*)arg;
	ioa_socket_handle s = server->udp_listen_s;

	FUNCSTART;

	if (!(what & EV_READ)) {
		return;
	}

	//printf_server_socket(server, fd);

	ioa_network_buffer_handle *elem = NULL;

	start_udp_cycle:

	elem = (ioa_network_buffer_handle *)ioa_network_buffer_allocate(server->e);

	server->sm.m.sm.nd.nbh = elem;
	server->sm.m.sm.nd.recv_ttl = TTL_IGNORE;
	server->sm.m.sm.nd.recv_tos = TOS_IGNORE;
	server->sm.m.sm.can_resume = 1;

	addr_set_any(&(server->sm.m.sm.nd.src_addr));

	ssize_t bsize = 0;

	int flags = MSG_DONTWAIT;

	bsize = udp_recvfrom(fd, &(server->sm.m.sm.nd.src_addr), &(server->addr),
			(s08bits*)ioa_network_buffer_data(elem), (int)ioa_network_buffer_get_capacity_udp(),
			&(server->sm.m.sm.nd.recv_ttl), &(server->sm.m.sm.nd.recv_tos),
			server->e->cmsg, flags, NULL);

	int conn_reset = is_connreset();
	int to_block = would_block();

	if (bsize < 0) {

		if(to_block) {
			ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
			server->sm.m.sm.nd.nbh = NULL;
			FUNCEND;
			return;
		}

	#if defined(MSG_ERRQUEUE)

		//Linux
		int eflags = MSG_ERRQUEUE | MSG_DONTWAIT;
		static s08bits buffer[65535];
		u32bits errcode = 0;
		ioa_addr orig_addr;
		int ttl = 0;
		int tos = 0;
		int slen = server->slen0;
		udp_recvfrom(fd, &orig_addr, &(server->addr), buffer,
					(int) sizeof(buffer), &ttl, &tos, server->e->cmsg, eflags,
					&errcode);
		//try again...
		do {
			bsize = recvfrom(fd, ioa_network_buffer_data(elem), ioa_network_buffer_get_capacity_udp(), flags, (struct sockaddr*) &(server->sm.m.sm.nd.src_addr), (socklen_t*) &slen);
		} while (bsize < 0 && (errno == EINTR));

		conn_reset = is_connreset();
		to_block = would_block();

	#endif

		if(conn_reset) {
			ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
			server->sm.m.sm.nd.nbh = NULL;
			reopen_server_socket(server,fd);
			FUNCEND;
			return;
		}
	}

	if(bsize<0) {
		if(!to_block && !conn_reset) {
			int ern=errno;
			perror(__FUNCTION__);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: recvfrom error %d\n",__FUNCTION__,ern);
		}
		ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
		server->sm.m.sm.nd.nbh = NULL;
		FUNCEND;
		return;
	}

	if (bsize > 0) {

		int rc = 0;
		ioa_network_buffer_set_size(elem, (size_t)bsize);

		if(server->connect_cb) {

			rc = create_new_connected_udp_socket(server, s);
			if(rc<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot handle UDP packet, size %d\n",(int)bsize);
			}

		} else {
			server->sm.m.sm.s = s;
			rc = handle_udp_packet(server, &(server->sm), server->e, server->ts);
		}

		if(rc < 0) {
			if(eve(server->e->verbose)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot handle UDP event\n");
			}
		}
	}

	ioa_network_buffer_delete(server->e, server->sm.m.sm.nd.nbh);
	server->sm.m.sm.nd.nbh = NULL;

	if((bsize>0) && (cycle++<MAX_SINGLE_UDP_BATCH))
		goto start_udp_cycle;

	FUNCEND;
}

///////////////////// operations //////////////////////////

static int create_server_socket(dtls_listener_relay_server_type* server, int report_creation) {

  FUNCSTART;

  if(!server) return -1;

  clean_server(server);

  {
	  ioa_socket_raw udp_listen_fd = -1;

	  udp_listen_fd = socket(server->addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
	  if (udp_listen_fd < 0) {
		  perror("socket");
		  return -1;
	  }

	  server->udp_listen_s = create_ioa_socket_from_fd(server->e, udp_listen_fd, NULL, UDP_SOCKET, LISTENER_SOCKET, NULL, &(server->addr));

	  set_sock_buf_size(udp_listen_fd,UR_SERVER_SOCK_BUF_SIZE);

	  if(sock_bind_to_device(udp_listen_fd, (unsigned char*)server->ifname)<0) {
		  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind listener socket to device %s\n",server->ifname);
	  }

	  set_raw_socket_ttl_options(udp_listen_fd, server->addr.ss.sa_family);
	  set_raw_socket_tos_options(udp_listen_fd, server->addr.ss.sa_family);

	  {
		  const int max_binding_time = 60;
		  int addr_bind_cycle = 0;
		  retry_addr_bind:

		  if(addr_bind(udp_listen_fd,&server->addr,1,1,UDP_SOCKET)<0) {
			  perror("Cannot bind local socket to addr");
			  char saddr[129];
			  addr_to_string(&server->addr,(u08bits*)saddr);
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,"Cannot bind DTLS/UDP listener socket to addr %s\n",saddr);
			  if(addr_bind_cycle++<max_binding_time) {
				  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Trying to bind DTLS/UDP listener socket to addr %s, again...\n",saddr);
				  sleep(1);
				  goto retry_addr_bind;
			  }
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Fatal final failure: cannot bind DTLS/UDP listener socket to addr %s\n",saddr);
			  exit(-1);
		  }
	  }

	  server->udp_listen_ev = event_new(server->e->event_base,udp_listen_fd,
				    EV_READ|EV_PERSIST,udp_server_input_handler,
				    server);

	  event_add(server->udp_listen_ev,NULL);
  }

  if(report_creation) {
	  if(!turn_params.no_udp && !turn_params.no_dtls)
		  addr_debug_print(server->verbose, &server->addr,"DTLS/UDP listener opened on");
	  else if(!turn_params.no_dtls)
		  addr_debug_print(server->verbose, &server->addr,"DTLS listener opened on");
	  else if(!turn_params.no_udp)
		  addr_debug_print(server->verbose, &server->addr,"UDP listener opened on");
  }

  FUNCEND;
  
  return 0;
}

static int reopen_server_socket(dtls_listener_relay_server_type* server, evutil_socket_t fd)
{
	UNUSED_ARG(fd);

	if(!server)
		return 0;

	FUNCSTART;

	{
		EVENT_DEL(server->udp_listen_ev);

		if(server->udp_listen_s->fd>=0) {
			socket_closesocket(server->udp_listen_s->fd);
			server->udp_listen_s->fd = -1;
		}

		if (!(server->udp_listen_s)) {
			return create_server_socket(server,1);
		}

		ioa_socket_raw udp_listen_fd = socket(server->addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
		if (udp_listen_fd < 0) {
			perror("socket");
			FUNCEND;
			return -1;
		}

		server->udp_listen_s->fd = udp_listen_fd;

		/* some UDP sessions may fail due to the race condition here */

		set_socket_options(server->udp_listen_s);

		set_sock_buf_size(udp_listen_fd, UR_SERVER_SOCK_BUF_SIZE);

		if (sock_bind_to_device(udp_listen_fd, (unsigned char*) server->ifname) < 0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"Cannot bind listener socket to device %s\n",
				server->ifname);
		}

		if(addr_bind(udp_listen_fd,&server->addr,1,1,UDP_SOCKET)<0) {
			perror("Cannot bind local socket to addr");
			char saddr[129];
			addr_to_string(&server->addr,(u08bits*)saddr);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind listener socket to addr %s\n",saddr);
			return -1;
		}

		server->udp_listen_ev = event_new(server->e->event_base, udp_listen_fd,
				EV_READ | EV_PERSIST, udp_server_input_handler,
				server);

		event_add(server->udp_listen_ev, NULL );
	}

	if (!turn_params.no_udp && !turn_params.no_dtls)
		addr_debug_print(server->verbose, &server->addr,
					"DTLS/UDP listener opened on ");
	else if (!turn_params.no_dtls)
		addr_debug_print(server->verbose, &server->addr,
					"DTLS listener opened on ");
	else if (!turn_params.no_udp)
		addr_debug_print(server->verbose, &server->addr,
				"UDP listener opened on ");

	FUNCEND;

	return 0;
}

#if defined(REQUEST_CLIENT_CERT)

static int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
  /* This function should ask the user
   * if he trusts the received certificate.
   * Here we always trust.
   */
  if(ok && ctx) return 1;
  return -1;
}

#endif

static int init_server(dtls_listener_relay_server_type* server,
		       const char* ifname,
		       const char *local_address, 
		       int port, 
		       int verbose,
		       ioa_engine_handle e,
		       turn_turnserver *ts,
		       int report_creation,
		       ioa_engine_new_connection_event_handler send_socket) {

  if(!server) return -1;

#if DTLS_SUPPORTED
  server->dtls_ctx = e->dtls_ctx;

#if DTLSv1_2_SUPPORTED
  server->dtls_ctx_v1_2 = e->dtls_ctx_v1_2;
#endif
#endif

  server->ts = ts;
  server->connect_cb = send_socket;

  if(ifname) STRCPY(server->ifname,ifname);

  if(make_ioa_addr((const u08bits*)local_address, port, &server->addr)<0) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot create a DTLS/UDP listener for address: %s\n",local_address);
	  return -1;
  }

  server->slen0 = get_ioa_addr_len(&(server->addr));

  server->verbose=verbose;
  
  server->e = e;
  
#if DTLS_SUPPORTED
  if(server->dtls_ctx) {

#if defined(REQUEST_CLIENT_CERT)
	  /* If client has to authenticate, then  */
	  SSL_CTX_set_verify(server->dtls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
#endif
  
	  SSL_CTX_set_read_ahead(server->dtls_ctx, 1);

	  SSL_CTX_set_cookie_generate_cb(server->dtls_ctx, generate_cookie);
	  SSL_CTX_set_cookie_verify_cb(server->dtls_ctx, verify_cookie);
  }

#if DTLSv1_2_SUPPORTED
  if(server->dtls_ctx_v1_2) {

  #if defined(REQUEST_CLIENT_CERT)
  	  /* If client has to authenticate, then  */
  	  SSL_CTX_set_verify(server->dtls_ctx_v1_2, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
  #endif

  	  SSL_CTX_set_read_ahead(server->dtls_ctx_v1_2, 1);

  	  SSL_CTX_set_cookie_generate_cb(server->dtls_ctx_v1_2, generate_cookie);
  	  SSL_CTX_set_cookie_verify_cb(server->dtls_ctx_v1_2, verify_cookie);
    }
#endif
#endif

  return create_server_socket(server, report_creation);
}

static int clean_server(dtls_listener_relay_server_type* server) {
  if(server) {
	  EVENT_DEL(server->udp_listen_ev);
	  close_ioa_socket(server->udp_listen_s);
	  server->udp_listen_s = NULL;
  }
  return 0;
}

///////////////////////////////////////////////////////////

dtls_listener_relay_server_type* create_dtls_listener_server(const char* ifname,
							     const char *local_address, 
							     int port, 
							     int verbose,
							     ioa_engine_handle e,
							     turn_turnserver *ts,
							     int report_creation,
							     ioa_engine_new_connection_event_handler send_socket) {
  
  dtls_listener_relay_server_type* server=(dtls_listener_relay_server_type*)
		allocate_super_memory_engine(e,sizeof(dtls_listener_relay_server_type));

  if(init_server(server,
		 ifname, local_address, port,
		 verbose,
		 e, ts, report_creation, send_socket)<0) {
    return NULL;
  } else {
    return server;
  }
}

ioa_engine_handle get_engine(dtls_listener_relay_server_type* server)
{
	if(server)
		return server->e;
	return NULL;
}

//////////// UDP send ////////////////

void udp_send_message(dtls_listener_relay_server_type *server, ioa_network_buffer_handle nbh, ioa_addr *dest)
{
	if(server && dest && nbh && (server->udp_listen_s))
		udp_send(server->udp_listen_s, dest, (s08bits*)ioa_network_buffer_data(nbh), (int)ioa_network_buffer_get_size(nbh));
}

//////////////////////////////////////////////////////////////////
