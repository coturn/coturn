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

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "udpserver.h"
#include "apputils.h"
#include "stun_buffer.h"
#include <errno.h>
#include <string.h>

#include <limits.h> // for USHRT_MAX

#if defined(__linux__)
#include <netinet/udp.h>
#include <sys/socket.h>
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#endif

/////////////// io handlers ///////////////////

#if defined(__linux__)

/* Per-callback batch state. The peer is single-threaded (one libevent
 * event_base, all sockets dispatched serially), so module-static buffers
 * are race-free and avoid per-callback allocation. */
#define PEER_BATCH 32
/* Max bytes we are willing to echo per datagram. STUN packets are small;
 * 4 KiB covers anything that fits in a Path-MTU UDP datagram with comfortable
 * headroom and keeps the static state at PEER_BATCH * 4 KiB = 128 KiB. */
#define PEER_DGRAM_MAX 4096
/* Bound the drain loop so a packet flood can't starve the rest of the event
 * loop. PEER_BATCH * MAX_DRAIN_ROUNDS sets the upper bound on packets handled
 * per readiness event. */
#define MAX_DRAIN_ROUNDS 8
/* UDP-GSO: a single sendmsg can describe many segments of gso_size bytes.
 * We only enable it when batch entries share source AND size — a deliberately
 * conservative predicate that matches the synthetic packet-flood pattern
 * without misbehaving on heterogeneous traffic. */
#define PEER_GSO_MAX_SEGSZ 1472

static struct mmsghdr g_msgs[PEER_BATCH];
static struct iovec g_iovs[PEER_BATCH];
static ioa_addr g_srcs[PEER_BATCH];
static uint8_t g_bufs[PEER_BATCH][PEER_DGRAM_MAX];

static int try_gso_echo(evutil_socket_t fd, int n) {
  if (n < 2) {
    return 0;
  }

  const uint32_t s0 = (uint32_t)g_msgs[0].msg_len;
  if (s0 == 0 || s0 > PEER_GSO_MAX_SEGSZ) {
    return 0;
  }

  const socklen_t namelen0 = g_msgs[0].msg_hdr.msg_namelen;
  for (int i = 1; i < n; ++i) {
    if (g_msgs[i].msg_len != s0) {
      return 0;
    }
    if (g_msgs[i].msg_hdr.msg_namelen != namelen0) {
      return 0;
    }
    if (memcmp(&g_srcs[i], &g_srcs[0], namelen0) != 0) {
      return 0;
    }
  }

  struct iovec sendiov[PEER_BATCH];
  for (int i = 0; i < n; ++i) {
    sendiov[i].iov_base = g_bufs[i];
    sendiov[i].iov_len = (size_t)s0;
  }

  union {
    struct cmsghdr align;
    char buf[CMSG_SPACE(sizeof(uint16_t))];
  } cmsg_buf = {0};

  struct msghdr mh = {0};
  mh.msg_iov = sendiov;
  mh.msg_iovlen = (size_t)n;
  mh.msg_name = &g_srcs[0];
  mh.msg_namelen = namelen0;
  mh.msg_control = cmsg_buf.buf;
  mh.msg_controllen = sizeof(cmsg_buf.buf);

  struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
  cm->cmsg_level = SOL_UDP;
  cm->cmsg_type = UDP_SEGMENT;
  cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
  uint16_t seg = (uint16_t)s0;
  memcpy(CMSG_DATA(cm), &seg, sizeof(seg));

  ssize_t rc;
  do {
    rc = sendmsg(fd, &mh, 0);
  } while (rc < 0 && errno == EINTR);

  if (rc < 0) {
    return 0;
  }
  return n;
}

static void udp_server_input_handler(evutil_socket_t fd, short what, void *arg) {
  if (!(what & EV_READ)) {
    return;
  }
  (void)arg; /* bind addr unused — recvmmsg fills msg_name with the actual
                source for each datagram, which is also the echo destination. */

  for (int round = 0; round < MAX_DRAIN_ROUNDS; ++round) {
    for (int i = 0; i < PEER_BATCH; ++i) {
      g_iovs[i].iov_base = g_bufs[i];
      g_iovs[i].iov_len = sizeof(g_bufs[i]);
      memset(&g_msgs[i].msg_hdr, 0, sizeof(g_msgs[i].msg_hdr));
      g_msgs[i].msg_hdr.msg_iov = &g_iovs[i];
      g_msgs[i].msg_hdr.msg_iovlen = 1;
      g_msgs[i].msg_hdr.msg_name = &g_srcs[i];
      g_msgs[i].msg_hdr.msg_namelen = sizeof(g_srcs[i]);
      g_msgs[i].msg_len = 0;
    }

    int n;
    do {
      n = recvmmsg(fd, g_msgs, PEER_BATCH, MSG_DONTWAIT, NULL);
    } while (n < 0 && errno == EINTR);

    if (n <= 0) {
      return;
    }

    int sent = try_gso_echo(fd, n);
    if (!sent) {
      /* Reuse the same mmsghdr array for sendmmsg: each entry already has
       * msg_name pointing at the source (which is the echo destination) and
       * the iovec pointing at the received bytes. Shrink iov_len to the
       * actual recv'd size and fire. No userspace copy. */
      for (int i = 0; i < n; ++i) {
        g_iovs[i].iov_len = (size_t)g_msgs[i].msg_len;
      }
      int s = 0;
      while (s < n) {
        int r;
        do {
          r = sendmmsg(fd, &g_msgs[s], (unsigned int)(n - s), 0);
        } while (r < 0 && errno == EINTR);
        if (r <= 0) {
          break;
        }
        s += r;
      }
    }

    if (n < PEER_BATCH) {
      /* recvmmsg returned a partial batch — kernel queue is drained. */
      return;
    }
  }
}

#else /* !__linux__ */

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

#endif /* __linux__ */

///////////////////// operations //////////////////////////

static int udp_create_server_socket(server_type *const server, const char *const ifname,
                                    const char *const local_address, const uint16_t port) {

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
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "socket: %s\n", strerror(errno));
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

static server_type *init_server(int verbose, const char *ifname, char **local_addresses, size_t las, uint16_t port) {
  // Ports cannot be larger than unsigned 16 bits
  // and since this function creates two ports next to each other
  // the provided port must be smaller than max unsigned 16.
  if (port == USHRT_MAX) {
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

server_type *start_udp_server(int verbose, const char *ifname, char **local_addresses, size_t las, uint16_t port) {
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
