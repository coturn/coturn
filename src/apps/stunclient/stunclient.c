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

#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(_MSC_VER)
#include <getopt.h>
#else
#include <unistd.h>
#if !defined(WINDOWS)
#include <err.h>
#endif
#endif

#include "apputils.h"
#include "ns_turn_utils.h"
#include "stun_buffer.h"

#ifdef __cplusplus
#include "TurnMsgLib.h"
#endif

////////////////////////////////////////////////////

static int udp_fd = -1;
static ioa_addr real_local_addr;
static int counter = 0;
static volatile sig_atomic_t stop_continuous = 0;

static void stop_continuous_handler(int signo) {
  (void)signo;
  stop_continuous = 1;
}

static double monotonic_time_ms(void) {
#if defined(_MSC_VER)
  struct timeval tv = {0, 0};
  clock_gettime(CLOCK_REALTIME, &tv);
  return ((double)tv.tv_sec * 1000.0) + ((double)tv.tv_usec / 1000.0);
#else
  struct timespec ts = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((double)ts.tv_sec * 1000.0) + ((double)ts.tv_nsec / 1000000.0);
#endif
}

static void sleep_ms(unsigned int milliseconds) {
#if defined(WINDOWS)
  Sleep(milliseconds);
#else
  struct timespec requested = {(time_t)(milliseconds / 1000), (long)(milliseconds % 1000) * 1000000L};
  struct timespec remaining;

  while (!stop_continuous && nanosleep(&requested, &remaining) < 0 && errno == EINTR) {
    requested = remaining;
  }
#endif
}

static void set_receive_timeout(int fd, unsigned int timeout_ms) {
#if defined(WINDOWS)
  DWORD timeout = timeout_ms;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
#else
  struct timeval timeout = {(time_t)(timeout_ms / 1000), (suseconds_t)(timeout_ms % 1000) * 1000};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
#endif
}

#ifdef __cplusplus

static int run_stunclient(const char *rip, uint16_t rport, uint16_t *port, bool *rfc5780, int response_port,
                          bool change_ip, bool change_port, int padding, unsigned int timeout_ms, bool print_details) {

  ioa_addr remote_addr;

  memset((void *)&remote_addr, 0, sizeof(ioa_addr));
  if (make_ioa_addr((const uint8_t *)rip, rport, &remote_addr) < 0) {
    err(-1, nullptr);
  }

  if (udp_fd < 0) {
    udp_fd = socket(remote_addr.ss.sa_family, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
      err(-1, nullptr);
    }

    if (!addr_any(&real_local_addr)) {
      if (addr_bind(udp_fd, &real_local_addr, 0, 1, UDP_SOCKET) < 0) {
        err(-1, nullptr);
      }
    }
  }

  int new_udp_fd = -1;
  if (response_port >= 0 && response_port <= USHRT_MAX) {
    new_udp_fd = socket(remote_addr.ss.sa_family, SOCK_DGRAM, 0);
    if (new_udp_fd < 0) {
      err(-1, nullptr);
    }

    addr_set_port(&real_local_addr, (uint16_t)response_port);

    if (addr_bind(new_udp_fd, &real_local_addr, 0, 1, UDP_SOCKET) < 0) {
      err(-1, nullptr);
    }
  }

  turn::StunMsgRequest req(STUN_METHOD_BINDING);

  req.constructBindingRequest();

  if (response_port >= 0 && response_port <= USHRT_MAX) {
    turn::StunAttrResponsePort rpa;
    rpa.setResponsePort((uint16_t)response_port);
    try {
      req.addAttr(rpa);
    } catch (const turn::WrongStunAttrFormatException &ex1) {
      printf("Wrong rp attr format\n");
      exit(-1);
    } catch (const turn::WrongStunBufferFormatException &ex2) {
      printf("Wrong stun buffer format (1)\n");
      exit(-1);
    } catch (...) {
      printf("Wrong something (1)\n");
      exit(-1);
    }
  }
  if (change_ip || change_port) {
    turn::StunAttrChangeRequest cra;
    cra.setChangeIp(change_ip);
    cra.setChangePort(change_port);
    try {
      req.addAttr(cra);
    } catch (const turn::WrongStunAttrFormatException &ex1) {
      printf("Wrong cr attr format\n");
      exit(-1);
    } catch (const turn::WrongStunBufferFormatException &ex2) {
      printf("Wrong stun buffer format (2)\n");
      exit(-1);
    } catch (...) {
      printf("Wrong something (2)\n");
      exit(-1);
    }
  }
  if (padding) {
    turn::StunAttrPadding pa;
    pa.setPadding(1500);
    try {
      req.addAttr(pa);
    } catch (const turn::WrongStunAttrFormatException &ex1) {
      printf("Wrong p attr format\n");
      exit(-1);
    } catch (const turn::WrongStunBufferFormatException &ex2) {
      printf("Wrong stun buffer format (3)\n");
      exit(-1);
    } catch (...) {
      printf("Wrong something (3)\n");
      exit(-1);
    }
  }

  {
    const int len = 0;
    const ssize_t slen = get_ioa_addr_len(&remote_addr);

    do {
      len = sendto(udp_fd, req.getRawBuffer(), req.getSize(), 0, (struct sockaddr *)&remote_addr, (socklen_t)slen);
    } while (len < 0 && (socket_eintr() || socket_enobufs() || socket_eagain()));

    if (len < 0) {
      err(-1, NULL);
    }
  }

  if (addr_get_from_sock(udp_fd, &real_local_addr) < 0) {
    printf("%s: Cannot get address from local socket\n", __FUNCTION__);
  } else {
    *port = addr_get_port(&real_local_addr);
  }

  if (new_udp_fd >= 0) {
    socket_closesocket(udp_fd);
    udp_fd = new_udp_fd;
  }

  set_receive_timeout(udp_fd, timeout_ms);

  {
    ssize_t len = 0;
    stun_buffer buf;
    int recvd = 0;
    const int to_recv = sizeof(buf.buf);

    do {
      len = recv(udp_fd, buf.buf, to_recv - recvd, 0);
      if (len > 0) {
        recvd += len;
        break;
      }
    } while (len < 0 && socket_eintr());

    if (recvd > 0) {
      len = recvd;
    } else {
      if (socket_eagain() || socket_ewouldblock()) {
        return 1;
      }
      return -1;
    }
    buf.len = len;

    try {
      turn::StunMsgResponse res(buf.buf, sizeof(buf.buf), (size_t)buf.len, true);

      if (res.isCommand()) {

        if (res.isSuccess()) {

          if (res.isBindingResponse()) {

            ioa_addr reflexive_addr;
            addr_set_any(&reflexive_addr);
            turn::StunAttrIterator iter(res, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS);
            if (!iter.eof()) {

              turn::StunAttrAddr addr(iter);
              addr.getAddr(reflexive_addr);

              turn::StunAttrIterator iter1(res, STUN_ATTRIBUTE_OTHER_ADDRESS);
              if (!iter1.eof()) {
                *rfc5780 = 1;
                if (print_details) {
                  printf("\n========================================\n");
                  printf("RFC 5780 response %d\n", ++counter);
                }
                const ioa_addr other_addr;
                turn::StunAttrAddr addr1(iter1);
                addr1.getAddr(other_addr);
                turn::StunAttrIterator iter2(res, STUN_ATTRIBUTE_RESPONSE_ORIGIN);
                if (!iter2.eof()) {
                  const ioa_addr response_origin;
                  turn::StunAttrAddr addr2(iter2);
                  addr2.getAddr(response_origin);
                  if (print_details) {
                    addr_debug_print(1, &response_origin, "Response origin: ");
                  }
                }
                if (print_details) {
                  addr_debug_print(1, &other_addr, "Other addr: ");
                }
              }
              if (print_details) {
                addr_debug_print(1, &reflexive_addr, "UDP reflexive addr");
              }

            } else {
              printf("Cannot read the response\n");
            }
          } else {
            printf("Wrong type of response\n");
          }
        } else {
          int err_code = res.getError();
          std::string reason = res.getReason();

          printf("The response is an error %d (%s)\n", err_code, reason.c_str());
        }
      } else {
        printf("The response is not a response message\n");
      }
    } catch (...) {
      printf("The response is not a well formed STUN message\n");
    }
  }

  return 0;
}

#else  // ifdef __cplusplus

static int run_stunclient(const char *rip, uint16_t rport, uint16_t *port, bool *rfc5780, int response_port,
                          bool change_ip, bool change_port, int padding, unsigned int timeout_ms, bool print_details) {

  ioa_addr remote_addr;
  stun_buffer buf;

  memset(&remote_addr, 0, sizeof(remote_addr));
  if (make_ioa_addr((const uint8_t *)rip, rport, &remote_addr) < 0) {
    err(-1, NULL);
  }

  int new_udp_fd = -1;
  if (udp_fd < 0) {
    udp_fd = socket(remote_addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
    if (udp_fd < 0) {
      err(-1, NULL);
    }

    if (!addr_any(&real_local_addr)) {
      if (addr_bind(udp_fd, &real_local_addr, 0, 1, UDP_SOCKET) < 0) {
        err(-1, NULL);
      }
    }
  }

  if (response_port >= 0 && response_port < USHRT_MAX) {

    new_udp_fd = socket(remote_addr.ss.sa_family, CLIENT_DGRAM_SOCKET_TYPE, CLIENT_DGRAM_SOCKET_PROTOCOL);
    if (new_udp_fd < 0) {
      err(-1, NULL);
    }

    addr_set_port(&real_local_addr, (uint16_t)response_port);

    if (addr_bind(new_udp_fd, &real_local_addr, 0, 1, UDP_SOCKET) < 0) {
      err(-1, NULL);
    }
  }

  stun_prepare_binding_request(&buf);

  if (response_port >= 0 && response_port <= USHRT_MAX) {
    stun_attr_add_response_port_str((uint8_t *)(buf.buf), (size_t *)&(buf.len), (uint16_t)response_port);
  }
  if (change_ip || change_port) {
    stun_attr_add_change_request_str((uint8_t *)buf.buf, (size_t *)&(buf.len), change_ip, change_port);
  }

  if (padding && !stun_attr_add_padding_str((uint8_t *)buf.buf, (size_t *)&(buf.len), 1500)) {
    printf("%s: ERROR: Cannot add padding\n", __FUNCTION__);
  }

  {
    ssize_t len = 0;
    uint32_t slen = get_ioa_addr_len(&remote_addr);

    do {
      len = sendto(udp_fd, buf.buf, buf.len, 0, (struct sockaddr *)&remote_addr, (socklen_t)slen);
    } while (len < 0 && (socket_eintr() || socket_enobufs() || socket_eagain()));

    if (len < 0) {
      err(-1, NULL);
    }
  }

  if (addr_get_from_sock(udp_fd, &real_local_addr) < 0) {
    printf("%s: Cannot get address from local socket\n", __FUNCTION__);
  } else {
    *port = addr_get_port(&real_local_addr);
  }

  if (new_udp_fd >= 0) {
    socket_closesocket(udp_fd);
    udp_fd = new_udp_fd;
  }

  set_receive_timeout(udp_fd, timeout_ms);

  {
    ssize_t len = 0;
    int recvd = 0;
    const int to_recv = sizeof(buf.buf);

    do {
      len = recv(udp_fd, buf.buf, to_recv - recvd, 0);
      if (len > 0) {
        recvd += len;
        break;
      }
    } while (len < 0 && socket_eintr());

    if (recvd > 0) {
      len = recvd;
    } else {
      if (socket_eagain() || socket_ewouldblock()) {
        return 1;
      }
      return -1;
    }
    buf.len = len;

    if (stun_is_command_message(&buf)) {

      if (stun_is_response(&buf)) {

        if (stun_is_success_response(&buf)) {

          if (stun_is_binding_response(&buf)) {

            ioa_addr reflexive_addr;
            addr_set_any(&reflexive_addr);
            if (stun_attr_get_first_addr(&buf, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &reflexive_addr, NULL)) {

              stun_attr_ref sar = stun_attr_get_first_by_type_str(buf.buf, buf.len, STUN_ATTRIBUTE_OTHER_ADDRESS);
              if (sar) {
                *rfc5780 = 1;
                if (print_details) {
                  printf("\n========================================\n");
                  printf("RFC 5780 response %d\n", ++counter);
                }
                ioa_addr other_addr;
                stun_attr_get_addr_str((uint8_t *)buf.buf, (size_t)buf.len, sar, &other_addr, NULL);
                sar = stun_attr_get_first_by_type_str(buf.buf, buf.len, STUN_ATTRIBUTE_RESPONSE_ORIGIN);
                if (sar) {
                  ioa_addr response_origin;
                  stun_attr_get_addr_str((uint8_t *)buf.buf, (size_t)buf.len, sar, &response_origin, NULL);
                  if (print_details) {
                    addr_debug_print(1, &response_origin, "Response origin: ");
                  }
                }
                if (print_details) {
                  addr_debug_print(1, &other_addr, "Other addr: ");
                }
              }
              if (print_details) {
                addr_debug_print(1, &reflexive_addr, "UDP reflexive addr");
              }

            } else {
              printf("Cannot read the response\n");
            }
          } else {
            printf("Wrong type of response\n");
          }
        } else {
          int err_code = 0;
          uint8_t err_msg[1025] = "\0";
          size_t err_msg_size = sizeof(err_msg);
          if (stun_is_error_response(&buf, &err_code, err_msg, err_msg_size)) {
            printf("The response is an error %d (%s)\n", err_code, (char *)err_msg);
          } else {
            printf("The response is an unrecognized error\n");
          }
        }
      } else {
        printf("The response is not a response message\n");
      }
    } else {
      printf("The response is not a STUN message\n");
    }
  }

  return 0;
}
#endif // ifdef __cplusplus

//////////////// local definitions /////////////////

static char Usage[] = "Usage: stunclient [options] address\n"
                      "Options:\n"
                      "        -p      STUN server port (Default: 3478)\n"
                      "        -L      Local address to use (optional)\n"
                      "        -f      Force RFC 5780 processing\n"
                      "        -c      Continuously send binding requests and report latency\n"
                      "        -i      Interval between continuous requests in milliseconds (Default: 1000)\n"
                      "        -t      Response timeout in milliseconds (Default: 3000)\n";

//////////////////////////////////////////////////

int main(int argc, char **argv) {
  uint16_t port = DEFAULT_STUN_PORT;
  char local_addr[256] = "\0";
  int c = 0;
  bool forceRfc5780 = false;
  bool continuous = false;
  unsigned int interval_ms = 1000;
  unsigned int timeout_ms = 3000;

  if (socket_init()) {
    return -1;
  }

  set_logfile("stdout");
  set_no_stdout_log(1);
  set_system_parameters(0);

  memset(local_addr, 0, sizeof(local_addr));

  while ((c = getopt(argc, argv, "p:L:fci:t:")) != -1) {
    switch (c) {
    case 'c':
      continuous = true;
      break;
    case 'f':
      forceRfc5780 = 1;
      break;
    case 'i': {
      char *end = NULL;
      unsigned long value = strtoul(optarg, &end, 10);
      if (!optarg[0] || *end || value > UINT_MAX) {
        fprintf(stderr, "Invalid interval: %s\n", optarg);
        exit(1);
      }
      interval_ms = (unsigned int)value;
      break;
    }
    case 'p':
      port = atoi(optarg);
      break;
    case 't': {
      char *end = NULL;
      unsigned long value = strtoul(optarg, &end, 10);
      if (!optarg[0] || *end || value == 0 || value > UINT_MAX) {
        fprintf(stderr, "Invalid timeout: %s\n", optarg);
        exit(1);
      }
      timeout_ms = (unsigned int)value;
      break;
    }
    case 'L':
      STRCPY(local_addr, optarg);
      break;
    default:
      fprintf(stderr, "%s\n", Usage);
      exit(1);
    }
  }

  if (optind >= argc) {
    fprintf(stderr, "%s\n", Usage);
    exit(-1);
  }

  addr_set_any(&real_local_addr);

  if (local_addr[0]) {
    if (make_ioa_addr((const uint8_t *)local_addr, 0, &real_local_addr) < 0) {
      err(-1, NULL);
    }
  }

  uint16_t local_port = 0;
  bool rfc5780 = false;

  if (continuous) {
    unsigned long sent = 0;
    unsigned long received = 0;
    double total_ms = 0.0;
    double min_ms = 0.0;
    double max_ms = 0.0;

    signal(SIGINT, stop_continuous_handler);
    printf("Continuous STUN binding requests to %s:%u, interval %u ms, timeout %u ms\n", argv[optind], port,
           interval_ms, timeout_ms);

    while (!stop_continuous) {
      const double started_ms = monotonic_time_ms();
      int result;
      double elapsed_ms;

      ++sent;
      result = run_stunclient(argv[optind], port, &local_port, &rfc5780, -1, 0, 0, 0, timeout_ms, false);
      elapsed_ms = monotonic_time_ms() - started_ms;

      if (result == 0) {
        ++received;
        total_ms += elapsed_ms;
        if (received == 1 || elapsed_ms < min_ms) {
          min_ms = elapsed_ms;
        }
        if (received == 1 || elapsed_ms > max_ms) {
          max_ms = elapsed_ms;
        }
        printf("%lu: time=%.3f ms\n", sent, elapsed_ms);
      } else if (result == 1) {
        printf("%lu: timeout after %u ms\n", sent, timeout_ms);
      } else {
        printf("%lu: receive error\n", sent);
      }
      fflush(stdout);

      if (!stop_continuous && interval_ms > elapsed_ms) {
        sleep_ms((unsigned int)((double)interval_ms - elapsed_ms));
      }
    }

    printf("\n--- %s STUN latency statistics ---\n", argv[optind]);
    printf("%lu requests sent, %lu responses received, %.1f%% packet loss\n", sent, received,
           sent ? ((double)(sent - received) * 100.0 / (double)sent) : 0.0);
    if (received > 0) {
      printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n", min_ms, total_ms / (double)received, max_ms);
    }
  } else {
    int result = run_stunclient(argv[optind], port, &local_port, &rfc5780, -1, 0, 0, 0, timeout_ms, true);
    if (result == 1) {
      fprintf(stderr, "STUN receive timeout after %u ms\n", timeout_ms);
      socket_closesocket(udp_fd);
      return 1;
    }
    if (result < 0) {
      fprintf(stderr, "STUN receive error\n");
      socket_closesocket(udp_fd);
      return 1;
    }

    if (rfc5780 || forceRfc5780) {
      run_stunclient(argv[optind], port, &local_port, &rfc5780, local_port + 1, 1, 1, 0, timeout_ms, true);
      run_stunclient(argv[optind], port, &local_port, &rfc5780, -1, 1, 1, 1, timeout_ms, true);
    }
  }

  socket_closesocket(udp_fd);

  return 0;
}
