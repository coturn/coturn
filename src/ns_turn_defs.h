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

#ifndef __IOADEFS__
#define __IOADEFS__

#define TURN_SERVER_VERSION "4.5.0.3"
#define TURN_SERVER_VERSION_NAME "dan Eider"
#define TURN_SOFTWARE "Coturn-" TURN_SERVER_VERSION " '" TURN_SERVER_VERSION_NAME "'"

#if (defined(__unix__) || defined(unix)) && !defined(USG)
#include <sys/param.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NS types: */

#define	s08bits	char
#define	s16bits	int16_t
#define	s32bits	int32_t
#define	s64bits	int64_t

#define	u08bits	unsigned char
#define	u16bits uint16_t
#define	u32bits	uint32_t
#define	u64bits	uint64_t

#define ns_bcopy(src,dst,sz) bcopy((src),(dst),(sz))
#define ns_bzero(ptr,sz) bzero((ptr),(sz))
#define ns_bcmp(ptr1,ptr2,sz) bcmp((ptr1),(ptr2),(sz))

#define nswap16(s) ntohs(s)
#define nswap32(ul) ntohl(ul)
#define nswap64(ull) ioa_ntoh64(ull)

static inline u64bits _ioa_ntoh64(u64bits v)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	u08bits *src = (u08bits*) &v;
	u08bits* dst = src + 7;
	while (src < dst) {
		u08bits vdst = *dst;
		*(dst--) = *src;
		*(src++) = vdst;
	}
#elif BYTE_ORDER == BIG_ENDIAN
	/* OK */
#else
#error WRONG BYTE_ORDER SETTING
#endif
	return v;
}

/* TTL */
#define TTL_IGNORE ((int)(-1))
#define TTL_DEFAULT (64)

/* TOS */
#define TOS_IGNORE ((int)(-1))
#define TOS_DEFAULT (0)

#define ioa_ntoh64 _ioa_ntoh64
#define ioa_hton64 _ioa_ntoh64

#if defined(TURN_MEMORY_DEBUG)

#if defined(TURN_LOG_FUNC)
#undef TURN_LOG_FUNC
#endif

#define TURN_LOG_FUNC(level, ...) printf (__VA_ARGS__)

  void tm_print_func(void);
  void *turn_malloc_func(size_t sz, const char* function, int line);
  void *turn_realloc_func(void *ptr, size_t old_sz, size_t new_sz, const char* function, int line);
  void turn_free_func(void *ptr, size_t sz, const char* function, int line);
  void turn_free_simple(void *ptr);
  void *turn_calloc_func(size_t number, size_t size, const char* function, int line);
  char *turn_strdup_func(const char* s, const char* function, int line);
  void* debug_ptr_add_func(void *ptr, const char* function, int line);
  void debug_ptr_del_func(void *ptr, const char* function, int line);

#define debug_ptr_add(ptr) debug_ptr_add_func((ptr),__FUNCTION__,__LINE__)
#define debug_ptr_del(ptr) debug_ptr_del_func((ptr),__FUNCTION__,__LINE__)
#define tm_print() tm_print_func()
#define turn_malloc(sz) turn_malloc_func((size_t)(sz),__FUNCTION__,__LINE__)
#define turn_free(ptr,sz) turn_free_func((ptr),(size_t)(sz),__FUNCTION__,__LINE__)
#define turn_realloc(ptr, old_sz, new_sz) turn_realloc_func((ptr),(size_t)(old_sz),(size_t)(new_sz),__FUNCTION__,__LINE__)
#define turn_calloc(number, sz) turn_calloc_func((number),(size_t)(sz),__FUNCTION__,__LINE__)
#define turn_strdup(s) turn_strdup_func((s),__FUNCTION__,__LINE__)

#define SSL_NEW(ctx) ((SSL*)debug_ptr_add(SSL_new(ctx)))

#else

#define debug_ptr_add(ptr)
#define debug_ptr_del(ptr)
#define tm_print() 
#define turn_malloc(sz) malloc((size_t)(sz))
#define turn_free(ptr,sz) free((ptr))
#define turn_realloc(ptr, old_sz, new_sz) realloc((ptr),(size_t)(new_sz))
#define turn_calloc(number, sz) calloc((number),(size_t)(sz))
#define turn_strdup(s) strdup((s))
#define turn_free_simple free

#define SSL_NEW(ctx) SSL_new(ctx)

#endif

#define SSL_FREE(ssl) do { debug_ptr_del(ssl); SSL_free(ssl); ssl = NULL; } while(0)
#define BUFFEREVENT_FREE(be) do { if(be) { debug_ptr_del(be); bufferevent_flush(be,EV_READ|EV_WRITE,BEV_FLUSH); bufferevent_disable(be,EV_READ|EV_WRITE); bufferevent_free(be); be = NULL;} } while(0)

#define turn_time() ((turn_time_t)time(NULL))

typedef int vint;
typedef vint* vintp;

typedef u32bits turn_time_t;

#define turn_time_before(t1,t2) ((((s32bits)(t1))-((s32bits)(t2))) < 0)

#if !defined(UNUSED_ARG)
#define UNUSED_ARG(A) do { A=A; } while(0)
#endif

#define MAX_STUN_MESSAGE_SIZE (65507)
#define STUN_BUFFER_SIZE (MAX_STUN_MESSAGE_SIZE)
#define UDP_STUN_BUFFER_SIZE (1024<<4)

#define NONCE_LENGTH_32BITS (4)

#define DEFAULT_STUN_PORT (3478)
#define DEFAULT_STUN_TLS_PORT (5349)

#if BYTE_ORDER == LITTLE_ENDIAN
#define DEFAULT_STUN_PORT_NBO (0x960D)
#elif BYTE_ORDER == BIG_ENDIAN
#define DEFAULT_STUN_PORT_NBO (0x0D96)
#else
#error WRONG BYTE_ORDER SETTING
#endif

#define STRCPY(dst,src) \
	do { if((const char*)(dst) != (const char*)(src)) { \
		if(sizeof(dst)==sizeof(char*))\
			strcpy(((char*)(dst)),(const char*)(src));\
		else {\
			size_t szdst = sizeof((dst));\
			strncpy((char*)(dst),(const char*)(src),szdst);\
			((char*)(dst))[szdst-1] = 0;\
		}\
	} } while(0)

//////////////// Bufferevents /////////////////////

#define TURN_BUFFEREVENTS_OPTIONS (BEV_OPT_DEFER_CALLBACKS | BEV_OPT_THREADSAFE | BEV_OPT_UNLOCK_CALLBACKS)

//////////////// KERNEL-LEVEL CHANNEL HANDLERS /////////

#if !defined(TURN_CHANNEL_HANDLER_KERNEL)
#define TURN_CHANNEL_HANDLER_KERNEL void*
#endif

#if !defined(CREATE_TURN_CHANNEL_KERNEL)
#define CREATE_TURN_CHANNEL_KERNEL(channel_number, address_family_client, address_family_peer, protocol_client, client_addr, local_addr, local_relay_addr, peer_addr) ((TURN_CHANNEL_HANDLER_KERNEL)(1))
#endif

#if !defined(DELETE_TURN_CHANNEL_KERNEL)
#define DELETE_TURN_CHANNEL_KERNEL(handler)
#endif

////////////////////////////////////////////////////////

#if !defined(IPPROTO_SCTP)
#define TURN_NO_SCTP
#endif

#define CLIENT_DGRAM_SOCKET_TYPE SOCK_DGRAM
#define CLIENT_DGRAM_SOCKET_PROTOCOL IPPROTO_IP

#define CLIENT_STREAM_SOCKET_TYPE SOCK_STREAM
#define CLIENT_STREAM_SOCKET_PROTOCOL IPPROTO_IP

#define SCTP_CLIENT_STREAM_SOCKET_TYPE SOCK_STREAM

#if !defined(TURN_NO_SCTP)
#define SCTP_CLIENT_STREAM_SOCKET_PROTOCOL IPPROTO_SCTP
#else
#define SCTP_CLIENT_STREAM_SOCKET_PROTOCOL IPPROTO_IP
#endif

#define RELAY_DGRAM_SOCKET_TYPE SOCK_DGRAM
#define RELAY_DGRAM_SOCKET_PROTOCOL IPPROTO_IP
#define RELAY_STREAM_SOCKET_TYPE SOCK_STREAM
#define RELAY_STREAM_SOCKET_PROTOCOL IPPROTO_IP

#define ADMIN_STREAM_SOCKET_TYPE SOCK_STREAM
#define ADMIN_STREAM_SOCKET_PROTOCOL IPPROTO_IP

////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif 
/* __IODEFS__ */
