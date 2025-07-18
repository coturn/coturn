/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
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

#include <limits.h> // for USHRT_MAX

/////////////// io handlers ///////////////////

static void udp_server_input_handler(evutil_socket_t fd, short what, void *arg) {

  if (!(what & EV_READ)) {
    return;
  }

  ioa_addr *addr = (ioa_addr *)arg;

  stun_buffer buffer;
  ioa_addr remote_addr;
  uint32_t slen = get_ioa_addr_len(addr);
  ssize_t len = 0;

  do {
    len = recvfrom(fd, buffer.buf, sizeof(buffer.buf) - 1, 0, (struct sockaddr *)&remote_addr, (socklen_t *)&slen);
  } while (len < 0 && socket_eintr());

  buffer.len = len;

  if (len >= 0) {
    do {
      len = sendto(fd, buffer.buf, buffer.len, 0, (const struct sockaddr *)&remote_addr, (socklen_t)slen);
    } while (len < 0 && (socket_eintr() || socket_enobufs() || socket_eagain()));
  }
}

///////////////////// operations //////////////////////////

static int udp_create_server_socket(server_type *const server, const char *const ifname,
                                    const char *const local_address, int const port) {

  if (!server) {
    return -1;
  }

  if (server->verbose) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Start\n");
  }

  ioa_addr *server_addr = (ioa_addr *)malloc(sizeof(ioa_addr));
  if (!server_addr) {
    return -1;
  }

  STRCPY(server->ifname, ifname);

  if (make_ioa_addr((const uint8_t *)local_address, port, server_addr) < 0) {
    free(server_addr);
    return -1;
  }

  evutil_socket_t udp_fd = socket(server_addr->ss.sa_family, RELAY_DGRAM_SOCKET_TYPE, RELAY_DGRAM_SOCKET_PROTOCOL);
  if (udp_fd < 0) {
    perror("socket");
    free(server_addr);
    return -1;
  }

  if (sock_bind_to_device(udp_fd, (unsigned char *)server->ifname) < 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Cannot bind udp server socket to device %s\n", server->ifname);
  }

  set_sock_buf_size(udp_fd, UR_SERVER_SOCK_BUF_SIZE);

  if (addr_bind(udp_fd, server_addr, 1, 1, UDP_SOCKET) < 0) {
    goto cleanup;
  }

  socket_set_nonblocking(udp_fd);

  struct event *udp_ev =
      event_new(server->event_base, udp_fd, EV_READ | EV_PERSIST, udp_server_input_handler, server_addr);

  if (udp_ev == NULL) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Failed to create new event in udp_create_server_socket\n");
    goto cleanup;
  }

  if (event_add(udp_ev, NULL) < 0) {
    event_free(udp_ev);
    goto cleanup;
  }

  if (server->verbose) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "End\n");
  }

  return 0;

cleanup:
  socket_closesocket(udp_fd);
  free(server_addr);
  return -1;
}

static server_type *init_server(int verbose, const char *ifname, char **local_addresses, size_t las, int port) {
  // Ports cannot be larger than unsigned 16 bits
  // and since this function creates two ports next to each other
  // the provided port must be smaller than max unsigned 16.
  if ((uint16_t)port >= USHRT_MAX) {
    return NULL;
  }
  server_type *server = (server_type *)calloc(1, sizeof(server_type));
  if (!server) {
    return NULL;
  }

  server->verbose = verbose;
  server->event_base = turn_event_base_new();

  while (las) {
    udp_create_server_socket(server, ifname, local_addresses[--las], port);
    udp_create_server_socket(server, ifname, local_addresses[las], port + 1);
  }

  return server;
}

static int clean_server(server_type *server) {
  if (server) {
    if (server->event_base) {
      event_base_free(server->event_base);
    }
    free(server);
  }
  return 0;
}

///////////////////////////////////////////////////////////

static void run_events(server_type *server) {

  if (!server) {
    return;
  }

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
    while (1) {
      run_events(server);
    }
  }
}

void clean_udp_server(server_type *server) {
  if (server) {
    clean_server(server);
  }
}

//////////////////////////////////////////////////////////////////
