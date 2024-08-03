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

#include "ns_turn_msg.h"
#include "ns_turn_utils.h"

#include "apputils.h"

#include <event2/event.h>

#if defined(__unix__) || defined(unix) || defined(__APPLE__)
#include <getopt.h>
#include <ifaddrs.h>
#endif

#if defined(__unix__) || defined(unix) || defined(__APPLE__) || defined(__MINGW32__)
#include <libgen.h>
#endif

#if defined(__unix__) || defined(unix)
#include <pthread.h>
#include <sys/resource.h>
#include <sys/time.h>
#endif

#if defined(WINDOWS)
#include <dsrole.h>
#endif

#if defined(_MSC_VER)
#include <direct.h>
#else
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>

#if !defined(TURN_NO_SCTP) && defined(TURN_SCTP_INCLUDE)
#include TURN_SCTP_INCLUDE
#endif

/************************/

int IS_TURN_SERVER = 0;

/*********************** Sockets *********************************/

int socket_set_nonblocking(evutil_socket_t fd) {
#if defined(WINDOWS)
  unsigned long nonblocking = 1;
  ioctlsocket(fd, FIONBIO, (unsigned long *)&nonblocking);
#else
  if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
    perror("O_NONBLOCK");
    return -1;
  }
#endif
  return 0;
}

void read_spare_buffer(evutil_socket_t fd) {
  if (fd >= 0) {
    static char buffer[65536];
#if defined(WINDOWS)
    // TODO: add set no-block? by Kang Lin <kl222@126.com>
    recv(fd, buffer, sizeof(buffer), 0);
#else
    recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
#endif
  }
}

int set_sock_buf_size(evutil_socket_t fd, int sz0) {
  int sz;

  sz = sz0;
  while (sz > 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const void *)&sz, (socklen_t)sizeof(sz)) < 0) {
      sz = sz / 2;
    } else {
      break;
    }
  }

  if (sz < 1) {
    perror("Cannot set socket rcv size");
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Cannot set rcv sock size %d on fd %d\n", sz0, fd);
  }

  sz = sz0;
  while (sz > 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const void *)&sz, (socklen_t)sizeof(sz)) < 0) {
      sz = sz / 2;
    } else {
      break;
    }
  }

  if (sz < 1) {
    perror("Cannot set socket snd size");
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Cannot set snd sock size %d on fd %d\n", sz0, fd);
  }

  return 0;
}

int socket_init(void) {
#if defined(WINDOWS)
  {
    WORD wVersionRequested;
    WSADATA wsaData;
    int e;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    e = WSAStartup(wVersionRequested, &wsaData);
    if (e != 0) {
      /* Tell the user that we could not find a usable */
      /* Winsock DLL.                                  */
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "WSAStartup failed with error: %d\n", e);
      return 1;
    }
  }
#endif
  return 0;
}

int socket_tcp_set_keepalive(evutil_socket_t fd, SOCKET_TYPE st) {
  UNUSED_ARG(st);

#ifdef SO_KEEPALIVE
  /* Set the keepalive option active */
  {
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const void *)&on, (socklen_t)sizeof(on));
  }
#else
  UNUSED_ARG(fd);
#endif

#ifdef SO_NOSIGPIPE
  {
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (const void *)&on, (socklen_t)sizeof(on));
  }
#endif

  return 0;
}

int socket_set_reusable(evutil_socket_t fd, int flag, SOCKET_TYPE st) {
  UNUSED_ARG(st);

  if (fd < 0) {
    return -1;
  } else {

#if defined(WINDOWS)
    int use_reuseaddr = IS_TURN_SERVER;
#else
    int use_reuseaddr = 1;
#endif

#if defined(SO_REUSEADDR)
    if (use_reuseaddr) {
      int on = flag;
      int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, (socklen_t)sizeof(on));
      if (ret < 0) {
        perror("SO_REUSEADDR");
      }
    }
#endif

#if !defined(TURN_NO_SCTP)
#if defined(SCTP_REUSE_PORT)
    if (use_reuseaddr) {
      if (is_sctp_socket(st)) {
        int on = flag;
        int ret = setsockopt(fd, IPPROTO_SCTP, SCTP_REUSE_PORT, (const void *)&on, (socklen_t)sizeof(on));
        if (ret < 0) {
          perror("SCTP_REUSE_PORT");
        }
      }
    }
#endif
#endif

#if defined(SO_REUSEPORT)
    if (use_reuseaddr) {
      int on = flag;
      setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void *)&on, (socklen_t)sizeof(on));
    }
#endif

    return 0;
  }
}

int sock_bind_to_device(evutil_socket_t fd, const unsigned char *ifname) {

  if (fd >= 0 && ifname && ifname[0]) {

#if defined(SO_BINDTODEVICE)

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, (const char *)ifname, sizeof(ifr.ifr_name));

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (const void *)&ifr, sizeof(ifr)) < 0) {
      if (socket_eperm()) {
        perror("You must obtain superuser privileges to bind a socket to device");
      } else {
        perror("Cannot bind socket to device");
      }

      return -1;
    }

    return 0;

#endif
  }

  return 0;
}

int addr_connect(evutil_socket_t fd, const ioa_addr *addr, int *out_errno) {
  if (!addr || fd < 0) {
    return -1;
  } else {
    int err = 0;
    do {
      if (addr->ss.sa_family == AF_INET) {
        err = connect(fd, (const struct sockaddr *)addr, sizeof(struct sockaddr_in));
      } else if (addr->ss.sa_family == AF_INET6) {
        err = connect(fd, (const struct sockaddr *)addr, sizeof(struct sockaddr_in6));
      } else {
        return -1;
      }
    } while (err < 0 && socket_eintr());

    if (out_errno) {
      *out_errno = socket_errno();
    }

    if (err < 0 && !socket_einprogress()) {
      perror("Connect");
    }

    return err;
  }
}

int addr_bind(evutil_socket_t fd, const ioa_addr *addr, int reusable, int debug, SOCKET_TYPE st) {
  if (!addr || fd < 0) {

    return -1;

  } else {

    int ret = -1;

    socket_set_reusable(fd, reusable, st);

    if (addr->ss.sa_family == AF_INET) {
      do {
        ret = bind(fd, (const struct sockaddr *)addr, sizeof(struct sockaddr_in));
      } while (ret < 0 && socket_eintr());
    } else if (addr->ss.sa_family == AF_INET6) {
      const int off = 0;
      setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&off, sizeof(off));
      do {
        ret = bind(fd, (const struct sockaddr *)addr, sizeof(struct sockaddr_in6));
      } while (ret < 0 && socket_eintr());
    } else {
      return -1;
    }
    if (ret < 0) {
      if (debug) {
        int err = socket_errno();
        perror("bind");
        char str[129];
        addr_to_string(addr, (uint8_t *)str);
        TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "Trying to bind fd %d to <%s>: errno=%d\n", fd, str, err);
      }
    }
    return ret;
  }
}

int addr_get_from_sock(evutil_socket_t fd, ioa_addr *addr) {

  if (fd < 0 || !addr) {
    return -1;
  } else {

    ioa_addr a;
    a.ss.sa_family = AF_INET6;
    socklen_t socklen = get_ioa_addr_len(&a);
    if (getsockname(fd, (struct sockaddr *)&a, &socklen) < 0) {
      a.ss.sa_family = AF_INET;
      socklen = get_ioa_addr_len(&a);
      if (getsockname(fd, (struct sockaddr *)&a, &socklen) < 0) {
        return -1;
      }
    }

    addr_cpy(addr, &a);

    return 0;
  }
}

int get_raw_socket_ttl(evutil_socket_t fd, int family) {
  int ttl = 0;

  if (family == AF_INET6) {
#if !defined(IPV6_UNICAST_HOPS)
    UNUSED_ARG(fd);
    do {
      return TTL_IGNORE;
    } while (0);
#else
    socklen_t slen = (socklen_t)sizeof(ttl);
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (void *)&ttl, &slen) < 0) {
      perror("get HOPLIMIT on socket");
      return TTL_IGNORE;
    }
#endif
  } else {
#if !defined(IP_TTL)
    UNUSED_ARG(fd);
    do {
      return TTL_IGNORE;
    } while (0);
#else
    socklen_t slen = (socklen_t)sizeof(ttl);
    if (getsockopt(fd, IPPROTO_IP, IP_TTL, (void *)&ttl, &slen) < 0) {
      perror("get TTL on socket");
      return TTL_IGNORE;
    }
#endif
  }

  CORRECT_RAW_TTL(ttl);

  return ttl;
}

int get_raw_socket_tos(evutil_socket_t fd, int family) {
  int tos = 0;

  if (family == AF_INET6) {
#if !defined(IPV6_TCLASS)
    UNUSED_ARG(fd);
    do {
      return TOS_IGNORE;
    } while (0);
#else
    socklen_t slen = (socklen_t)sizeof(tos);
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, (void *)&tos, &slen) < 0) {
      perror("get TCLASS on socket");
      return -1;
    }
#endif
  } else {
#if !defined(IP_TOS)
    UNUSED_ARG(fd);
    do {
      return TOS_IGNORE;
    } while (0);
#else
    socklen_t slen = (socklen_t)sizeof(tos);
    if (getsockopt(fd, IPPROTO_IP, IP_TOS, (void *)&tos, &slen) < 0) {
      perror("get TOS on socket");
      return -1;
    }
#endif
  }

  CORRECT_RAW_TOS(tos);

  return tos;
}

int set_raw_socket_ttl(evutil_socket_t fd, int family, int ttl) {

  if (family == AF_INET6) {
#if !defined(IPV6_UNICAST_HOPS)
    UNUSED_ARG(fd);
    UNUSED_ARG(ttl);
#else
    CORRECT_RAW_TTL(ttl);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (const void *)&ttl, sizeof(ttl)) < 0) {
      perror("set HOPLIMIT on socket");
      return -1;
    }
#endif
  } else {
#if !defined(IP_TTL)
    UNUSED_ARG(fd);
    UNUSED_ARG(ttl);
#else
    CORRECT_RAW_TTL(ttl);
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, (const void *)&ttl, sizeof(ttl)) < 0) {
      perror("set TTL on socket");
      return -1;
    }
#endif
  }

  return 0;
}

int set_raw_socket_tos(evutil_socket_t fd, int family, int tos) {

  if (family == AF_INET6) {
#if !defined(IPV6_TCLASS)
    UNUSED_ARG(fd);
    UNUSED_ARG(tos);
#else
    CORRECT_RAW_TOS(tos);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, (const void *)&tos, sizeof(tos)) < 0) {
      perror("set TCLASS on socket");
      return -1;
    }
#endif
  } else {
#if !defined(IP_TOS)
    UNUSED_ARG(fd);
    UNUSED_ARG(tos);
#else
    if (setsockopt(fd, IPPROTO_IP, IP_TOS, (const void *)&tos, sizeof(tos)) < 0) {
      perror("set TOS on socket");
      return -1;
    }
#endif
  }

  return 0;
}

int is_stream_socket(int st) {
  switch (st) {
  case TCP_SOCKET:
  case TCP_SOCKET_PROXY:
  case TLS_SOCKET:
  case TENTATIVE_TCP_SOCKET:
  case SCTP_SOCKET:
  case TLS_SCTP_SOCKET:
  case TENTATIVE_SCTP_SOCKET:
    return 1;
  default:;
  }
  return 0;
}

int is_tcp_socket(int st) {
  switch (st) {
  case TCP_SOCKET:
  case TLS_SOCKET:
  case TENTATIVE_TCP_SOCKET:
    return 1;
  default:;
  }
  return 0;
}

int is_sctp_socket(int st) {
  switch (st) {
  case SCTP_SOCKET:
  case TLS_SCTP_SOCKET:
  case TENTATIVE_SCTP_SOCKET:
    return 1;
  default:;
  }
  return 0;
}

const char *socket_type_name(SOCKET_TYPE st) {
  switch (st) {
  case TCP_SOCKET:
    return "TCP";
  case SCTP_SOCKET:
    return "SCTP";
  case UDP_SOCKET:
    return "UDP";
  case TLS_SOCKET:
    return "TLS/TCP";
  case TLS_SCTP_SOCKET:
    return "TLS/SCTP";
  case DTLS_SOCKET:
    return "DTLS";
  case TENTATIVE_TCP_SOCKET:
    return "TLS/TCP ?";
  case TENTATIVE_SCTP_SOCKET:
    return "TLS/SCTP ?";
  default:;
  };
  return "UNKNOWN";
}

/////////////////// MTU /////////////////////////////////////////

int set_socket_df(evutil_socket_t fd, int family, int value) {

  int ret = 0;

#if defined(IP_DONTFRAG) && defined(IPPROTO_IP) // BSD
  {
    const int val = value;
    /* kernel sets DF bit on outgoing IP packets */
    if (family == AF_INET) {
      ret = setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, (const void *)&val, sizeof(val));
    } else {
#if defined(IPV6_DONTFRAG) && defined(IPPROTO_IPV6)
      ret = setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, (const void *)&val, sizeof(val));
#else
#error CANNOT SET IPV6 SOCKET DF FLAG (1)
#endif
    }
    if (ret < 0) {
      int err = socket_errno();
      perror("set socket df:");
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: set sockopt failed: fd=%d, err=%d, family=%d\n", __FUNCTION__, fd, err,
                    family);
    }
  }
#elif defined(IPPROTO_IP) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO) && defined(IP_PMTUDISC_DONT) // LINUX
  {
    /* kernel sets DF bit on outgoing IP packets */
    if (family == AF_INET) {
      int val = IP_PMTUDISC_DO;
      if (!value) {
        val = IP_PMTUDISC_DONT;
      }
      ret = setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, (const void *)&val, sizeof(val));
    } else {
#if defined(IPPROTO_IPV6) && defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO) && defined(IPV6_PMTUDISC_DONT)
      int val = IPV6_PMTUDISC_DO;
      if (!value) {
        val = IPV6_PMTUDISC_DONT;
      }
      ret = setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, (const void *)&val, sizeof(val));
#else
#error CANNOT SET IPV6 SOCKET DF FLAG (2)
#endif
    }
    if (ret < 0) {
      perror("set DF");
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: set sockopt failed\n", __FUNCTION__);
    }
  }
#else
  // CANNOT SET SOCKET DF FLAG (3) : UNKNOWN PLATFORM
  UNUSED_ARG(fd);
  UNUSED_ARG(family);
  UNUSED_ARG(value);
#endif

  return ret;
}

static int get_mtu_from_ssl(SSL *ssl) {
  int ret = SOSO_MTU;
#if DTLS_SUPPORTED
  if (ssl) {
    ret = BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_QUERY_MTU, 0, NULL);
  }
#else
  UNUSED_ARG(ssl);
#endif
  return ret;
}

static void set_query_mtu(SSL *ssl) {
  if (ssl) {
#if defined(SSL_OP_NO_QUERY_MTU)
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
#else
    ;
#endif
  }
}

int decrease_mtu(SSL *ssl, int mtu, int verbose) {

  if (!ssl) {
    return mtu;
  }

  int new_mtu = get_mtu_from_ssl(ssl);

  if (new_mtu < 1) {
    new_mtu = mtu;
  }

  if (new_mtu > MAX_MTU) {
    mtu = MAX_MTU;
  }
  if (new_mtu > 0 && new_mtu < MIN_MTU) {
    mtu = MIN_MTU;
  } else if (new_mtu < mtu) {
    mtu = new_mtu;
  } else {
    mtu -= MTU_STEP;
  }

  if (mtu < MIN_MTU) {
    mtu = MIN_MTU;
  }

  set_query_mtu(ssl);
  if (verbose) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "1. mtu to use: %d\n", mtu);
  }

#if DTLS_SUPPORTED
  SSL_set_mtu(ssl, mtu);
  BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_SET_MTU, mtu, NULL);
#endif

  return mtu;
}

int set_mtu_df(SSL *ssl, evutil_socket_t fd, int family, int mtu, int df_value, int verbose) {

  if (!ssl || fd < 0) {
    return 0;
  }

  int ret = set_socket_df(fd, family, df_value);

  if (!mtu) {
    mtu = SOSO_MTU;
  } else if (mtu < MIN_MTU) {
    mtu = MIN_MTU;
  } else if (mtu > MAX_MTU) {
    mtu = MAX_MTU;
  }

  set_query_mtu(ssl);
  if (verbose) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "3. mtu to use: %d\n", mtu);
  }

#if DTLS_SUPPORTED

  SSL_set_mtu(ssl, mtu);

  BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_SET_MTU, mtu, NULL);

#endif

  if (verbose) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "4. new mtu: %d\n", get_mtu_from_ssl(ssl));
  }

  return ret;
}

int get_socket_mtu(evutil_socket_t fd, int family, int verbose) {

  int ret = 0;

  UNUSED_ARG(fd);
  UNUSED_ARG(family);
  UNUSED_ARG(verbose);

#if defined(IP_MTU)
  int val = 0;
  socklen_t slen = sizeof(val);
  if (family == AF_INET) {
    ret = getsockopt(fd, IPPROTO_IP, IP_MTU, (void *)&val, &slen);
  } else {
#if defined(IPPROTO_IPV6) && defined(IPV6_MTU)
    ret = getsockopt(fd, IPPROTO_IPV6, IPV6_MTU, (void *)&val, &slen);
#endif
    ;
  }

  ret = val;
#endif

  if (verbose) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: final=%d\n", __FUNCTION__, ret);
  }

  return ret;
}

//////////////////// socket error handle ////////////////////

int handle_socket_error(void) {
  if (socket_eintr()) {
    /* Interrupted system call.
     * Just ignore.
     */
    return 1;
  }
  if (socket_enobufs()) {
    /* Interrupted system call.
     * Just ignore.
     */
    return 1;
  }
  if (socket_ewouldblock() || socket_eagain()) {
    return 1;
  }
  if (socket_ebadf()) {
    /* Invalid socket.
     * Must close connection.
     */
    return 0;
  }
  if (socket_ehostdown()) {
    /* Host is down.
     * Just ignore, might be an attacker
     * sending fake ICMP messages.
     */
    return 1;
  }
  if (socket_econnreset() || socket_econnrefused()) {
    /* Connection reset by peer. */
    return 0;
  }
  if (socket_enomem()) {
    /* Out of memory.
     * Must close connection.
     */
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Out of memory!\n");
    return 0;
  }
  if (socket_eacces()) {
    /* Permission denied.
     * Just ignore, we might be blocked
     * by some firewall policy. Try again
     * and hope for the best.
     */
    return 1;
  }

  /* Something unexpected happened */
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unexpected error! (errno = %d)\n", socket_errno());
  return 0;
}

//////////////////// Misc utils //////////////////////////////

char *skip_blanks(char *s) {
  while (*s == ' ' || *s == '\t' || *s == '\n') {
    ++s;
  }

  return s;
}

#if defined(_MSC_VER)

LARGE_INTEGER getFILETIMEoffset() {
  SYSTEMTIME s;
  FILETIME f;
  LARGE_INTEGER t;

  s.wYear = 1970;
  s.wMonth = 1;
  s.wDay = 1;
  s.wHour = 0;
  s.wMinute = 0;
  s.wSecond = 0;
  s.wMilliseconds = 0;
  SystemTimeToFileTime(&s, &f);
  t.QuadPart = f.dwHighDateTime;
  t.QuadPart <<= 32;
  t.QuadPart |= f.dwLowDateTime;
  return (t);
}

int clock_gettime(int X, struct timeval *tv) {
  LARGE_INTEGER t;
  FILETIME f;
  double microseconds;
  static LARGE_INTEGER offset;
  static double frequencyToMicroseconds;
  static int initialized = 0;
  static BOOL usePerformanceCounter = FALSE;

  if (!initialized) {
    LARGE_INTEGER performanceFrequency;
    initialized = 1;
    usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
    if (usePerformanceCounter) {
      QueryPerformanceCounter(&offset);
      frequencyToMicroseconds = (double)performanceFrequency.QuadPart / 1000000.;
    } else {
      offset = getFILETIMEoffset();
      frequencyToMicroseconds = 10.;
    }
  }
  if (usePerformanceCounter) {
    QueryPerformanceCounter(&t);
  } else {
    GetSystemTimeAsFileTime(&f);
    t.QuadPart = f.dwHighDateTime;
    t.QuadPart <<= 32;
    t.QuadPart |= f.dwLowDateTime;
  }

  t.QuadPart -= offset.QuadPart;
  microseconds = (double)t.QuadPart / frequencyToMicroseconds;
  t.QuadPart = microseconds;
  tv->tv_sec = t.QuadPart / 1000000;
  tv->tv_usec = t.QuadPart % 1000000;
  return 0;
}

int gettimeofday(struct timeval *tp, void *tzp) {
  time_t clock;
  struct tm tm;
  SYSTEMTIME wtm;

  GetLocalTime(&wtm);
  tm.tm_year = wtm.wYear - 1900;
  tm.tm_mon = wtm.wMonth - 1;
  tm.tm_mday = wtm.wDay;
  tm.tm_hour = wtm.wHour;
  tm.tm_min = wtm.wMinute;
  tm.tm_sec = wtm.wSecond;
  tm.tm_isdst = -1;
  clock = mktime(&tm);
  tp->tv_sec = clock;
  tp->tv_usec = wtm.wMilliseconds * 1000;

  return (0);
}

char *dirname(char *path) {
  char drive[_MAX_DRIVE];
  char dir[_MAX_DIR];

  errno_t err = _splitpath_s(path, drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
  if (err) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "split path fail: %d", err);
    return NULL;
  }

  int n = strlen(drive) + strlen(dir);
  if (n > 0) {
    path[n] = 0;
  } else {
    return NULL;
  }
  return path;
}
#endif

#if defined(WINDOWS)

/*!
 * \brief convert wchar to char
 *
 * \param pszInBuf: input buffer of wchar_t
 * \param nInSize: size of input wchar_t buffer
 * \param pszOutBuf: output buffer of char
 * \param pnOutSize: size of output char buffer
 * \return
 */
static char *_WTA(__in wchar_t *pszInBuf, __in int nInSize, __out char **pszOutBuf, __out int *pnOutSize) {
  if (!pszInBuf || !pszOutBuf || !*pszOutBuf || !pnOutSize || nInSize <= 0) {
    return NULL;
  }
  *pnOutSize = WideCharToMultiByte((UINT)0, (DWORD)0, pszInBuf, nInSize, NULL, 0, NULL, NULL);
  if (*pnOutSize == 0) {
    return NULL;
  }
  // add 1 for explicit nul-terminator at end.
  // if MultiByteToWideChar is provided a length for the input, it does not add space for a nul-terminator
  // and we have to add space to the allocation ourselves.
  (*pnOutSize)++;
  *pszOutBuf = malloc(*pnOutSize * sizeof(char));
  if (WideCharToMultiByte((UINT)0, (DWORD)0, pszInBuf, nInSize, *pszOutBuf, *pnOutSize, NULL, NULL) == 0) {
    free(*pszOutBuf);
    return NULL;
  } else {
    (*pszOutBuf)[*pnOutSize - 1] = '\0';
    return *pszOutBuf;
  }
}

int getdomainname(char *name, size_t len) {
  DSROLE_PRIMARY_DOMAIN_INFO_BASIC *info;
  DWORD dw;

  dw = DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE *)&info);
  if (dw != ERROR_SUCCESS) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "DsRoleGetPrimaryDomainInformation: %u\n", dw);
    return -1;
  }

  do {
    if (info->DomainForestName) {
      char *pszOut = NULL;
      int nOutSize = 0;
      if (_WTA(info->DomainForestName, wcslen(info->DomainForestName), &pszOut, &nOutSize)) {
        int n = nOutSize - 1;
        if (nOutSize > len - 1) {
          n = len - 1;
        }
        strncpy(name, pszOut, n);
        name[n] = 0;
        TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "DomainForestName: %s\n", pszOut);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "wchar convert to char fail");
      }

      free(pszOut);
      break;
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "DomainForestName is NULL\n");
    }

    if (info->DomainNameDns) {
      char *pszOut = NULL;
      int nOutSize = 0;
      if (_WTA(info->DomainNameDns, wcslen(info->DomainNameDns), &pszOut, &nOutSize)) {
        int n = nOutSize - 1;
        if (nOutSize > len - 1) {
          n = len - 1;
        }
        strncpy(name, pszOut, n);
        name[n] = 0;
        TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "DomainNameDns: %s\n", pszOut);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "wchar convert to char fail");
      }

      free(pszOut);
      break;
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "DomainNameDns is NULL\n");
    }

    if (info->DomainNameFlat) {
      char *pszOut = NULL;
      int nOutSize = 0;
      if (_WTA(info->DomainNameFlat, wcslen(info->DomainNameFlat), &pszOut, &nOutSize)) {
        int n = nOutSize - 1;
        if (nOutSize > len - 1) {
          n = len - 1;
        }
        strncpy(name, pszOut, n);
        name[n] = 0;
        TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "DomainNameFlat: %s\n", pszOut);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "wchar convert to char fail");
      }

      free(pszOut);
    } else {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "DomainNameFlat is NULL\n");
      return -2;
    }
  } while (0);

  DsRoleFreeMemory(info);
  return 0;
}

#endif

//////////////////// Config file search //////////////////////

#define Q(x) #x
#define QUOTE(x) Q(x)

#define ETCDIR INSTALL_PREFIX / etc /
#define QETCDIR QUOTE(ETCDIR)

#define ETCDIR1 INSTALL_PREFIX / etc / turnserver /
#define QETCDIR1 QUOTE(ETCDIR1)

#define ETCDIR2 INSTALL_PREFIX / etc / coturn /
#define QETCDIR2 QUOTE(ETCDIR2)

static const char *config_file_search_dirs[] = {"./",
                                                "./turnserver/",
                                                "./coturn/",
                                                "./etc/",
                                                "./etc/turnserver/",
                                                "./etc/coturn/",
                                                "../etc/",
                                                "../etc/turnserver/",
                                                "../etc/coturn/",
                                                "/etc/",
                                                "/etc/turnserver/",
                                                "/etc/coturn/",
                                                "/usr/local/etc/",
                                                "/usr/local/etc/turnserver/",
                                                "/usr/local/etc/coturn/",
                                                QETCDIR,
                                                QETCDIR1,
                                                QETCDIR2,
                                                NULL};
static char *c_execdir = NULL;

void set_execdir(void) {
  /* On some systems, this may give us the execution path */
  char *_var = NULL;
#if defined(_MSC_VER)
  char szPath[MAX_PATH];
  if (!GetModuleFileNameA(NULL, szPath, MAX_PATH)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "GetModuleFileName failed(%d)\n", GetLastError());
    return;
  }
  _var = szPath;
#elif defined(__unix__)
  _var = getenv("_");
#endif
  if (_var && *_var) {
    _var = strdup(_var);
    char *edir = _var;
    if (edir[0] != '.') {
      edir = strstr(edir, "/");
    }
    if (edir && *edir) {
      edir = dirname(edir);
    } else {
      edir = dirname(_var);
    }
    if (c_execdir) {
      free(c_execdir);
    }
    c_execdir = strdup(edir);
    free(_var);
  }
}

void print_abs_file_name(const char *msg1, const char *msg2, const char *fn) {
  char absfn[1025];
  absfn[0] = 0;

  if (fn) {
    while (fn[0] && fn[0] == ' ') {
      ++fn;
    }
    if (fn[0]) {
      if (fn[0] == '/') {
        STRCPY(absfn, fn);
      } else {
        if (fn[0] == '.' && fn[1] && fn[1] == '/') {
          fn += 2;
        }
        if (!getcwd(absfn, sizeof(absfn) - 1)) {
          absfn[0] = 0;
        }
        size_t blen = strlen(absfn);
        if (blen < sizeof(absfn) - 1) {
          strncpy(absfn + blen, "/", sizeof(absfn) - blen);
          strncpy(absfn + blen + 1, fn, sizeof(absfn) - blen - 1);
        } else {
          STRCPY(absfn, fn);
        }
        absfn[sizeof(absfn) - 1] = 0;
      }
    }
  }
  if (absfn[0]) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s%s file found: %s\n", msg1, msg2, absfn);
  }
}

char *find_config_file(const char *config_file) {
  char *full_path_to_config_file = NULL;

  if (config_file && config_file[0]) {
    if ((config_file[0] == '/') || (config_file[0] == '~')) {
      FILE *f = fopen(config_file, "r");
      if (f) {
        fclose(f);
        full_path_to_config_file = strdup(config_file);
      }
    } else {
      int i = 0;
      size_t cflen = strlen(config_file);

      while (config_file_search_dirs[i]) {
        size_t dirlen = strlen(config_file_search_dirs[i]);
        size_t fnsz = sizeof(char) * (dirlen + cflen + 10);
        char *fn = (char *)malloc(fnsz + 1);
        strncpy(fn, config_file_search_dirs[i], fnsz);
        strncpy(fn + dirlen, config_file, fnsz - dirlen);
        fn[fnsz] = 0;
        FILE *f = fopen(fn, "r");
        if (f) {
          fclose(f);
          full_path_to_config_file = fn;
          break;
        }
        free(fn);
        if (config_file_search_dirs[i][0] != '/' && config_file_search_dirs[i][0] != '.' && c_execdir && c_execdir[0]) {
          size_t celen = strlen(c_execdir);
          fnsz = sizeof(char) * (dirlen + cflen + celen + 10);
          fn = (char *)malloc(fnsz + 1);
          strncpy(fn, c_execdir, fnsz);
          size_t fnlen = strlen(fn);
          if (fnlen < fnsz) {
            strncpy(fn + fnlen, "/", fnsz - fnlen);
            fnlen = strlen(fn);
            if (fnlen < fnsz) {
              strncpy(fn + fnlen, config_file_search_dirs[i], fnsz - fnlen);
              fnlen = strlen(fn);
              if (fnlen < fnsz) {
                strncpy(fn + fnlen, config_file, fnsz - fnlen);
              }
            }
          }
          fn[fnsz] = 0;
          if (strstr(fn, "//") != fn) {
            f = fopen(fn, "r");
            if (f) {
              fclose(f);
              full_path_to_config_file = fn;
              break;
            }
          }
          free(fn);
        }
        ++i;
      }
    }

    if (!full_path_to_config_file) {
      if (strstr(config_file, "etc/") == config_file) {
        return find_config_file(config_file + 4);
      }
    }
  }

  return full_path_to_config_file;
}

/////////////////// SYS SETTINGS ///////////////////////

void ignore_sigpipe(void) {
#if defined(__linux__) || defined(__APPLE__)
  /* Ignore SIGPIPE from TCP sockets */
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    perror("Cannot set SIGPIPE handler");
  }
#endif
}

static uint64_t turn_getRandTime(void) {
  struct timespec tp = {0, 0};
#if defined(CLOCK_REALTIME)
  clock_gettime(CLOCK_REALTIME, &tp);
#else
  tp.tv_sec = time(NULL);
#endif
  uint64_t current_time = (uint64_t)(tp.tv_sec);
  uint64_t current_mstime = (uint64_t)(current_time + (tp.tv_nsec));

  return current_mstime;
}

void turn_srandom(void) {
#if defined(WINDOWS)
  srand((unsigned int)(turn_getRandTime() + (unsigned int)((long)(&turn_getRandTime))));
#else
  srandom((unsigned int)(turn_getRandTime() + (unsigned int)((long)(&turn_getRandTime))));
#endif
}

long turn_random(void) {
#if defined(WINDOWS)
  return rand();
#else
  return random();
#endif
}

unsigned long set_system_parameters(int max_resources) {
  turn_srandom();

  setlocale(LC_ALL, "C");

  build_base64_decoding_table();

  ignore_sigpipe();

  if (max_resources) {
#if defined(WINDOWS)
    int num = 0;
    // TODO: get max socket? by KangLin <kl222@126.com>

    num = _getmaxstdio();
    return num;
#elif defined(__linux__) || defined(__APPLE__)

    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
      perror("Cannot get system limit");
    } else {
      rlim.rlim_cur = rlim.rlim_max;
      while ((setrlimit(RLIMIT_NOFILE, &rlim) < 0) && (rlim.rlim_cur > 0)) {
        rlim.rlim_cur = rlim.rlim_cur >> 1;
      }
      return (unsigned long)rlim.rlim_cur;
    }

#endif
  }

  return 0;
}

unsigned long get_system_number_of_cpus(void) {
#if defined(WINDOWS)
  SYSTEM_INFO sysInfo;
  GetSystemInfo(&sysInfo);
  // TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "System cpu num is %d\n", sysInfo.dwNumberOfProcessors);
  return sysInfo.dwNumberOfProcessors;
#else
#if defined(_SC_NPROCESSORS_ONLN)
  // TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "System cpu num is %ld \n", sysconf(_SC_NPROCESSORS_CONF));
  return sysconf(_SC_NPROCESSORS_CONF);
#else
  // GNU way
  // TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "System cpu num is %d\n", get_nprocs_conf());
  return get_nprocs_conf();
#endif
#endif
}

unsigned long get_system_active_number_of_cpus(void) {
#if defined(WINDOWS)
  SYSTEM_INFO sysInfo;
  GetSystemInfo(&sysInfo);
  // TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "System enable num is 0x%X\n", sysInfo.dwActiveProcessorMask);
  return sysInfo.dwActiveProcessorMask;
#else
#if defined(_SC_NPROCESSORS_ONLN)
  // TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "System enable num is %ld\n", sysconf(_SC_NPROCESSORS_ONLN));
  return sysconf(_SC_NPROCESSORS_ONLN);
#else
  // GNU way
  // TURN_LOG_FUNC(TURN_LOG_LEVEL_DEBUG, "System enable num is %d\n", get_nprocs());
  return get_nprocs();
#endif
#endif
}

////////////////////// Base 64 ////////////////////////////

static const size_t mod_table[] = {0, 2, 1};
static const char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                      'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                      'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
static const char *decoding_table = NULL;

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {

  *output_length = 4 * ((input_length + 2) / 3);

  char *encoded_data = (char *)malloc(*output_length + 1);
  if (encoded_data == NULL) {
    return NULL;
  }

  for (size_t i = 0, j = 0; i < input_length;) {

    uint32_t octet_a = i < input_length ? data[i++] : 0;
    uint32_t octet_b = i < input_length ? data[i++] : 0;
    uint32_t octet_c = i < input_length ? data[i++] : 0;

    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

    encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
  }

  for (size_t i = 0; i < mod_table[input_length % 3]; i++) {
    encoded_data[*output_length - 1 - i] = '=';
  }

  encoded_data[*output_length] = 0;

  return encoded_data;
}

void build_base64_decoding_table(void) {

  char *table = (char *)calloc(256, sizeof(char));

  for (char i = 0; i < 64; i++) {
    table[(unsigned char)encoding_table[i]] = i;
  }
  decoding_table = table;
}

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {

  if (decoding_table == NULL) {
    build_base64_decoding_table();
  }

  if (input_length % 4 != 0) {
    return NULL;
  }

  *output_length = input_length / 4 * 3;
  if (data[input_length - 1] == '=') {
    (*output_length)--;
  }
  if (data[input_length - 2] == '=') {
    (*output_length)--;
  }

  unsigned char *decoded_data = (unsigned char *)malloc(*output_length);
  if (decoded_data == NULL) {
    return NULL;
  }

  int i;
  size_t j;
  for (i = 0, j = 0; i < (int)input_length;) {

    uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
    uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
    uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];
    uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[(int)data[i++]];

    uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

    if (j < *output_length) {
      decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
    }
    if (j < *output_length) {
      decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
    }
    if (j < *output_length) {
      decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
  }

  return decoded_data;
}

////////////////// SSL /////////////////////

const char *turn_get_ssl_method(SSL *ssl, const char *mdefault) {
  const char *ret = "unknown";
  if (!ssl) {
    ret = mdefault;
  } else {
    ret = SSL_get_version(ssl);
  }

  return ret;
}

//////////// EVENT BASE ///////////////

struct event_base *turn_event_base_new(void) {
  struct event_config *cfg = event_config_new();

  event_config_set_flag(cfg, EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);

  return event_base_new_with_config(cfg);
}

/////////// OAUTH /////////////////

void convert_oauth_key_data_raw(const oauth_key_data_raw *raw, oauth_key_data *oakd) {
  if (raw && oakd) {

    memset(oakd, 0, sizeof(oauth_key_data));

    oakd->timestamp = (turn_time_t)raw->timestamp;
    oakd->lifetime = raw->lifetime;

    memcpy(oakd->as_rs_alg, raw->as_rs_alg, sizeof(oakd->as_rs_alg));
    memcpy(oakd->kid, raw->kid, sizeof(oakd->kid));

    if (raw->ikm_key[0]) {
      size_t ikm_key_size = 0;
      char *ikm_key = (char *)base64_decode(raw->ikm_key, strlen(raw->ikm_key), &ikm_key_size);
      if (ikm_key) {
        memcpy(oakd->ikm_key, ikm_key, ikm_key_size);
        oakd->ikm_key_size = ikm_key_size;
        free(ikm_key);
      }
    }
  }
}

//////////////////////////////////////////////////////////////
