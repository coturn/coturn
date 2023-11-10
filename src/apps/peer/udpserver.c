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

#include "udpserver.h"
#include "apputils.h"
#include "stun_buffer.h"

struct listen_info {
  ioa_addr addr;
  int received;
  int verbose;
  struct listen_info *next;
};

/////////////// io handlers ///////////////////

static void udp_server_input_handler(evutil_socket_t fd, short what, void *arg) {

  if (!(what & EV_READ))
    return;

  struct listen_info *listen = (struct listen_info *)arg;

  int len = 0;
  int slen = get_ioa_addr_len(&listen->addr);
  stun_buffer *buffer = (stun_buffer *)malloc(sizeof(stun_buffer));
  ioa_addr remote_addr = {0};
  if (!buffer)
    return;

  do {
    len = recvfrom(fd, buffer->buf, sizeof(buffer->buf) - 1, 0, (struct sockaddr *)&remote_addr, (socklen_t *)&slen);
  } while (len < 0 && socket_eintr());

  buffer->len = len;

  if (len >= 0) {
    listen->received += len;
    if (listen->verbose) {
      uint8_t ra[64] = {0}, la[64] = {0};
      addr_to_string(&listen->addr, la);
      addr_to_string(&remote_addr, ra);
      TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "Received %d bytes data %s from %s. total received: %d bytes\n", len, la, ra,
                    listen->received);
    }

    do {
      len = sendto(fd, buffer->buf, buffer->len, 0, (const struct sockaddr *)&remote_addr, (socklen_t)slen);
    } while (len < 0 && (socket_eintr() || socket_enobufs() || socket_eagain()));
  }

  free(buffer);
}

///////////////////// operations //////////////////////////

static struct listen_info *udp_create_server_socket(server_type *server, const char *ifname, const char *local_address,
                                                    int port) {
  if (!server) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "server is null\n");
    return NULL;
  }

  struct listen_info *listen = (struct listen_info *)calloc(sizeof(struct listen_info), 1);
  if (!listen)
    return NULL;

  do {
    evutil_socket_t udp_fd = -1;
    listen->verbose = server->verbose;
    ioa_addr *server_addr = &listen->addr;

    STRCPY(server->ifname, ifname);

    if (make_ioa_addr((const uint8_t *)local_address, port, server_addr) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "make_ioa_addr fail %s:%d\n", local_address, port);
      break;
    }

    udp_fd = socket(server_addr->ss.sa_family, RELAY_DGRAM_SOCKET_TYPE, RELAY_DGRAM_SOCKET_PROTOCOL);
    if (udp_fd < 0) {
#if WINDOWS
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Create socket fail: %d\n", WSAGetLastError());
#else
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Create socket fail: %s\n", strerror(errno));
#endif
      break;
    }

    if (sock_bind_to_device(udp_fd, (unsigned char *)server->ifname) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot bind udp server socket to device %s\n", server->ifname);
      break;
    }

    set_sock_buf_size(udp_fd, UR_SERVER_SOCK_BUF_SIZE);

    if (addr_bind(udp_fd, server_addr, 1, 1, UDP_SOCKET) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot bind udp server socket to %s:%d\n", local_address, port);
      break;
    }

    socket_set_nonblocking(udp_fd);

    struct event *udp_ev =
        event_new(server->event_base, udp_fd, EV_READ | EV_PERSIST, udp_server_input_handler, listen);
    if (udp_ev)
      event_add(udp_ev, NULL);

    if (server && server->verbose)
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s:%d start\n", local_address, port);

    return listen;
  } while (0);

  free(listen);
  return NULL;
}

static server_type *init_server(int verbose, const char *ifname, char **local_addresses, size_t las, int port) {

  server_type *server = (server_type *)malloc(sizeof(server_type));

  if (!server)
    return NULL;

  memset(server, 0, sizeof(server_type));

  server->verbose = verbose;

  server->event_base = turn_event_base_new();

  while (las) {
    struct listen_info *listen = NULL;
    listen = udp_create_server_socket(server, ifname, local_addresses[--las], port);
    if (listen) {
      listen->next = server->listen;
      server->listen = listen;
    }
    listen = udp_create_server_socket(server, ifname, local_addresses[las], port + 1);
    if (listen) {
      listen->next = server->listen;
      server->listen = listen;
    }
  }

  return server;
}

static int clean_server(server_type *server) {
  if (server) {
    if (server->event_base)
      event_base_free(server->event_base);

    struct listen_info *l = server->listen;
    while (l) {
      struct listen_info *n = l->next;
      free(l);
      l = n;
    }

    free(server);
  }
  return 0;
}

///////////////////////////////////////////////////////////

static void run_events(server_type *server) {

  if (!server)
    return;

  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = 100000;

  event_base_loopexit(server->event_base, &timeout);
  event_base_dispatch(server->event_base);
}

/////////////////////////////////////////////////////////////

server_type *start_udp_server(int verbose, const char *ifname, char **local_addresses, size_t las, int port) {
  return init_server(verbose, ifname, local_addresses, las, port);
}

void run_udp_server(server_type *server) {

  if (server) {

    unsigned int cycle = 0;

    while (1) {

      cycle++;

      run_events(server);
    }
  }
}

void clean_udp_server(server_type *server) {
  if (server)
    clean_server(server);
}

//////////////////////////////////////////////////////////////////
