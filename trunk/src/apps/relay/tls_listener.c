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

#include "ns_turn_utils.h"

#include "tls_listener.h"
#include "ns_ioalib_impl.h"

#include <event2/listener.h>

///////////////////////////////////////////////////

#define FUNCSTART if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:start\n",__FUNCTION__,__LINE__)
#define FUNCEND if(server && eve(server->verbose)) TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s:%d:end\n",__FUNCTION__,__LINE__)

struct tls_listener_relay_server_info
{
	char ifname[1025];
	ioa_addr addr;
	ioa_engine_handle e;
	int verbose;
	struct evconnlistener *l;
	struct evconnlistener *sctp_l;
	struct message_to_relay sm;
	ioa_engine_new_connection_event_handler connect_cb;
	struct relay_server *relay_server;
};

/////////////// io handlers ///////////////////

static void server_input_handler(struct evconnlistener *l, evutil_socket_t fd,
				struct sockaddr *sa, int socklen, void *arg)
{

	UNUSED_ARG(l);

	tls_listener_relay_server_type * server = (tls_listener_relay_server_type*) arg;

	if(!(server->connect_cb)) {
		socket_closesocket(fd);
		return;
	}

	FUNCSTART;

	if (!server)
		return;

	ns_bcopy(sa,&(server->sm.m.sm.nd.src_addr),socklen);

	addr_debug_print(server->verbose, &(server->sm.m.sm.nd.src_addr),"tcp or tls connected to");

	SOCKET_TYPE st = TENTATIVE_TCP_SOCKET;

	if(turn_params.no_tls)
		st = TCP_SOCKET;
	else if(turn_params.no_tcp)
		st = TLS_SOCKET;

	ioa_socket_handle ioas =
				create_ioa_socket_from_fd(
							server->e,
							fd,
							NULL,
							st,
							CLIENT_SOCKET,
							&(server->sm.m.sm.nd.src_addr),
							&(server->addr));

	if (ioas) {

		server->sm.m.sm.nd.recv_ttl = TTL_IGNORE;
		server->sm.m.sm.nd.recv_tos = TOS_IGNORE;
		server->sm.m.sm.nd.nbh = NULL;
		server->sm.m.sm.s = ioas;
		server->sm.m.sm.can_resume = 1;
		server->sm.relay_server = server->relay_server;

		int rc = server->connect_cb(server->e, &(server->sm));

		if (rc < 0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"Cannot create tcp or tls session\n");
		}
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"Cannot create ioa_socket from FD\n");
		socket_closesocket(fd);
	}

	FUNCEND	;
}

#if !defined(TURN_NO_SCTP)

static void sctp_server_input_handler(struct evconnlistener *l, evutil_socket_t fd,
				struct sockaddr *sa, int socklen, void *arg)
{

	UNUSED_ARG(l);

	tls_listener_relay_server_type * server = (tls_listener_relay_server_type*) arg;

	if(!(server->connect_cb)) {
		socket_closesocket(fd);
		return;
	}

	FUNCSTART;

	if (!server)
		return;

	ns_bcopy(sa,&(server->sm.m.sm.nd.src_addr),socklen);

	addr_debug_print(server->verbose, &(server->sm.m.sm.nd.src_addr),"sctp or tls/sctp connected to");

	SOCKET_TYPE st = TENTATIVE_SCTP_SOCKET;

	if(turn_params.no_tls)
		st = SCTP_SOCKET;
	else if(turn_params.no_tcp)
		st = TLS_SCTP_SOCKET;

	ioa_socket_handle ioas =
				create_ioa_socket_from_fd(
							server->e,
							fd,
							NULL,
							st,
							CLIENT_SOCKET,
							&(server->sm.m.sm.nd.src_addr),
							&(server->addr));

	if (ioas) {

		server->sm.m.sm.nd.recv_ttl = TTL_IGNORE;
		server->sm.m.sm.nd.recv_tos = TOS_IGNORE;
		server->sm.m.sm.nd.nbh = NULL;
		server->sm.m.sm.s = ioas;
		server->sm.m.sm.can_resume = 1;
		server->sm.relay_server = server->relay_server;

		int rc = server->connect_cb(server->e, &(server->sm));

		if (rc < 0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
					"Cannot create sctp or tls/sctp session\n");
		}
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
				"Cannot create ioa_socket from FD\n");
		socket_closesocket(fd);
	}

	FUNCEND	;
}

#endif

///////////////////// operations //////////////////////////

static int create_server_listener(tls_listener_relay_server_type* server) {

  FUNCSTART;

  if(!server) return -1;

  evutil_socket_t tls_listen_fd = -1;

  tls_listen_fd = socket(server->addr.ss.sa_family, CLIENT_STREAM_SOCKET_TYPE, CLIENT_STREAM_SOCKET_PROTOCOL);
  if (tls_listen_fd < 0) {
      perror("socket");
      return -1;
  }

  if(sock_bind_to_device(tls_listen_fd, (unsigned char*)server->ifname)<0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind listener socket to device %s\n",server->ifname);
  }

  {
  	 const int max_binding_time = 60;
  	 int addr_bind_cycle = 0;
  	 retry_addr_bind:

  	 if(addr_bind(tls_listen_fd,&server->addr,1,1,TCP_SOCKET)<0) {
  		perror("Cannot bind local socket to addr");
  		char saddr[129];
  		addr_to_string(&server->addr,(u08bits*)saddr);
  		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,"Cannot bind TLS/TCP listener socket to addr %s\n",saddr);
  		if(addr_bind_cycle++<max_binding_time) {
  		  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Trying to bind TLS/TCP listener socket to addr %s, again...\n",saddr);
  		  sleep(1);
  		  goto retry_addr_bind;
  		}
  		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Fatal final failure: cannot bind TLS/TCP listener socket to addr %s\n",saddr);
  		exit(-1);
  	 }
   }

  socket_tcp_set_keepalive(tls_listen_fd,TCP_SOCKET);

  socket_set_nonblocking(tls_listen_fd);

  server->l = evconnlistener_new(server->e->event_base,
		  server_input_handler, server,
		  LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
		  1024, tls_listen_fd);

  if(!(server->l)) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot create TLS listener\n");
	  socket_closesocket(tls_listen_fd);
	  return -1;
  }

  if(!turn_params.no_tcp && !turn_params.no_tls)
	  addr_debug_print(server->verbose, &server->addr,"TLS/TCP listener opened on ");
  else if(!turn_params.no_tls)
	  addr_debug_print(server->verbose, &server->addr,"TLS listener opened on ");
  else if(!turn_params.no_tcp)
	  addr_debug_print(server->verbose, &server->addr,"TCP listener opened on ");

  FUNCEND;
  
  return 0;
}

#if !defined(TURN_NO_SCTP)

static int sctp_create_server_listener(tls_listener_relay_server_type* server) {

  FUNCSTART;

  if(!server) return -1;

  evutil_socket_t tls_listen_fd = -1;

  tls_listen_fd = socket(server->addr.ss.sa_family, SCTP_CLIENT_STREAM_SOCKET_TYPE, SCTP_CLIENT_STREAM_SOCKET_PROTOCOL);
  if (tls_listen_fd < 0) {
    perror("socket");
    return -1;
  }

  if(sock_bind_to_device(tls_listen_fd, (unsigned char*)server->ifname)<0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"Cannot bind listener socket to device %s\n",server->ifname);
  }

  if(addr_bind(tls_listen_fd,&server->addr,1,0,SCTP_SOCKET)<0) {
	  close(tls_listen_fd);
	  return -1;
  }

  socket_tcp_set_keepalive(tls_listen_fd,SCTP_SOCKET);

  socket_set_nonblocking(tls_listen_fd);

  server->sctp_l = evconnlistener_new(server->e->event_base,
		  sctp_server_input_handler, server,
		  LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
		  1024, tls_listen_fd);

  if(!(server->sctp_l)) {
	  socket_closesocket(tls_listen_fd);
	  return -1;
  }

  if (!turn_params.no_tls)
	addr_debug_print(server->verbose, &server->addr, "TLS/SCTP listener opened on ");
  else
	addr_debug_print(server->verbose, &server->addr, "SCTP listener opened on ");

  FUNCEND;

  return 0;
}

#endif

static int init_server(tls_listener_relay_server_type* server,
		       const char* ifname,
		       const char *local_address, 
		       int port, 
		       int verbose,
		       ioa_engine_handle e,
		       ioa_engine_new_connection_event_handler send_socket,
		       struct relay_server *relay_server) {

  if(!server) return -1;

  server->connect_cb = send_socket;
  server->relay_server = relay_server;

  if(ifname) STRCPY(server->ifname,ifname);

  if(make_ioa_addr((const u08bits*)local_address, port, &server->addr)<0) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,"Cannot create a TCP/TLS listener for address: %s\n",local_address);
	  return -1;
  }

  server->verbose=verbose;
  
  server->e = e;

#if !defined(TURN_NO_SCTP)
  sctp_create_server_listener(server);
#endif

  return create_server_listener(server);
}

///////////////////////////////////////////////////////////


tls_listener_relay_server_type* create_tls_listener_server(const char* ifname,
				const char *local_address, int port, int verbose,
				ioa_engine_handle e,
				ioa_engine_new_connection_event_handler send_socket,
				struct relay_server *relay_server)
{

	tls_listener_relay_server_type* server =
			(tls_listener_relay_server_type*) allocate_super_memory_engine(e,sizeof(tls_listener_relay_server_type));

	if (init_server(server, ifname, local_address, port, verbose, e,
			send_socket, relay_server) < 0) {
		return NULL ;
	} else {
		return server;
	}
}

//////////////////////////////////////////////////////////////////
