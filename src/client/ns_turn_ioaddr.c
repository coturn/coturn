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

#include "ns_turn_ioaddr.h"
#include <netdb.h>
#include <string.h>

//////////////////////////////////////////////////////////////

u32bits get_ioa_addr_len(const ioa_addr* addr) {
  if(addr->ss.sa_family == AF_INET) return sizeof(struct sockaddr_in);
  else if(addr->ss.sa_family == AF_INET6) return sizeof(struct sockaddr_in6);
  return 0;
}

///////////////////////////////////////////////////////////////

void addr_set_any(ioa_addr *addr) {
	if(addr)
		ns_bzero(addr,sizeof(ioa_addr));
}

int addr_any(const ioa_addr* addr) {

	if(!addr)
		return 1;

  if(addr->ss.sa_family == AF_INET) {
    return ((addr->s4.sin_addr.s_addr==0)&&(addr->s4.sin_port==0));
  } else if(addr->ss.sa_family == AF_INET6) {
    if(addr->s6.sin6_port!=0) return 0;
    else {
      size_t i;
      for(i=0;i<sizeof(addr->s6.sin6_addr);i++) 
	if(((const s08bits*)&(addr->s6.sin6_addr))[i]) return 0;
    }
  }

  return 1;
}

int addr_any_no_port(const ioa_addr* addr) {
	if(!addr)
		return 1;

  if(addr->ss.sa_family == AF_INET) {
    return (addr->s4.sin_addr.s_addr==0);
  } else if(addr->ss.sa_family == AF_INET6) {
    size_t i;
    for(i=0;i<sizeof(addr->s6.sin6_addr);i++) 
      if(((const s08bits*)(&(addr->s6.sin6_addr)))[i]) return 0;
  }

  return 1;
}

u32bits hash_int32(u32bits a)
{
	a = a ^ (a>>4);
	a = (a^0xdeadbeef) + (a<<5);
	a = a ^ (a>>11);
	return a;
}

u64bits hash_int64(u64bits a)
{
	a = a ^ (a>>4);
	a = (a^0xdeadbeefdeadbeefLL) + (a<<5);
	a = a ^ (a>>11);
	return a;
}

u32bits addr_hash(const ioa_addr *addr)
{
	if(!addr)
		return 0;

	u32bits ret = 0;
	if (addr->ss.sa_family == AF_INET) {
		ret = hash_int32(addr->s4.sin_addr.s_addr + addr->s4.sin_port);
	} else {
		const u64bits *a = (const u64bits *) (&(addr->s6.sin6_addr));
		ret = (u32bits)((hash_int64(a[0])<<3) + (hash_int64(a[1] + addr->s6.sin6_port)));
	}
	return ret;
}

u32bits addr_hash_no_port(const ioa_addr *addr)
{
	if(!addr)
		return 0;

	u32bits ret = 0;
	if (addr->ss.sa_family == AF_INET) {
		ret = hash_int32(addr->s4.sin_addr.s_addr);
	} else {
		const u64bits *a = (const u64bits *) (&(addr->s6.sin6_addr));
		ret = (u32bits)((hash_int64(a[0])<<3) + (hash_int64(a[1])));
	}
	return ret;
}

void addr_cpy(ioa_addr* dst, const ioa_addr* src) {
	if(dst && src)
		ns_bcopy(src,dst,sizeof(ioa_addr));
}

void addr_cpy4(ioa_addr* dst, const struct sockaddr_in* src) {
	if(src && dst)
		ns_bcopy(src,dst,sizeof(struct sockaddr_in));
}

void addr_cpy6(ioa_addr* dst, const struct sockaddr_in6* src) {
	if(src && dst)
		ns_bcopy(src,dst,sizeof(struct sockaddr_in6));
}

int addr_eq(const ioa_addr* a1, const ioa_addr *a2) {

  if(!a1) return (!a2);
  else if(!a2) return (!a1);

  if(a1->ss.sa_family == a2->ss.sa_family) {
    if(a1->ss.sa_family == AF_INET && a1->s4.sin_port == a2->s4.sin_port) {
      if((int)a1->s4.sin_addr.s_addr == (int)a2->s4.sin_addr.s_addr) {
	return 1;
      }
    } else if(a1->ss.sa_family == AF_INET6 && a1->s6.sin6_port == a2->s6.sin6_port) {
      const u64bits *p1=(const u64bits *)(&(a1->s6.sin6_addr));
      const u64bits *p2=(const u64bits *)(&(a2->s6.sin6_addr));
      if(p1[0]==p2[0] && p1[1]==p2[1]) {
	return 1;
      }
    }
  }

  return 0;
}

int addr_eq_no_port(const ioa_addr* a1, const ioa_addr *a2) {

  if(!a1) return (!a2);
  else if(!a2) return (!a1);
  
  if(a1->ss.sa_family == a2->ss.sa_family) {
    if(a1->ss.sa_family == AF_INET) {
      if((int)a1->s4.sin_addr.s_addr == (int)a2->s4.sin_addr.s_addr) {
	return 1;
      }
    } else if(a1->ss.sa_family == AF_INET6) {
	const u64bits *p1=(const u64bits *)(&(a1->s6.sin6_addr));
	const u64bits *p2=(const u64bits *)(&(a2->s6.sin6_addr));
	if(p1[0]==p2[0] && p1[1]==p2[1]) {
	  return 1;
	}
    }
  }
  return 0;
}

int make_ioa_addr(const u08bits* saddr0, int port, ioa_addr *addr) {

  if(!saddr0 || !addr) return -1;

  char ssaddr[257];
  STRCPY(ssaddr,saddr0);

  char* saddr=ssaddr;
  while(*saddr == ' ') ++saddr;

  size_t len=strlen(saddr);
  while(len>0) {
	  if(saddr[len-1]==' ') {
		  saddr[len-1]=0;
		  --len;
	  } else {
		  break;
	  }
  }

  ns_bzero(addr, sizeof(ioa_addr));
  if((len == 0)||
     (inet_pton(AF_INET, saddr, &addr->s4.sin_addr) == 1)) {
    addr->s4.sin_family = AF_INET;
#if defined(TURN_HAS_SIN_LEN) /* tested when configured */
    addr->s4.sin_len = sizeof(struct sockaddr_in);
#endif
    addr->s4.sin_port = nswap16(port);
  } else if (inet_pton(AF_INET6, saddr, &addr->s6.sin6_addr) == 1) {
    addr->s6.sin6_family = AF_INET6;
#if defined(SIN6_LEN) /* this define is required by IPv6 if used */
    addr->s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
    addr->s6.sin6_port = nswap16(port);
  } else {
    struct addrinfo addr_hints;
    struct addrinfo *addr_result = NULL;
    int err;

    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    addr_hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    addr_hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    addr_hints.ai_protocol = 0;          /* Any protocol */
    addr_hints.ai_canonname = NULL;
    addr_hints.ai_addr = NULL;
    addr_hints.ai_next = NULL;

    err = getaddrinfo(saddr, NULL, &addr_hints, &addr_result);
    if ((err != 0)||(!addr_result)) {
      fprintf(stderr,"error resolving '%s' hostname: %s\n",saddr,gai_strerror(err));
      return -1;
    }
    
    int family = AF_INET;
    struct addrinfo *addr_result_orig = addr_result;
    int found = 0;

    beg_af:

    while(addr_result) {

    	if(addr_result->ai_family == family) {
    		if (addr_result->ai_family == AF_INET) {
    			ns_bcopy(addr_result->ai_addr, addr, addr_result->ai_addrlen);
    			addr->s4.sin_port = nswap16(port);
#if defined(TURN_HAS_SIN_LEN) /* tested when configured */
    			addr->s4.sin_len = sizeof(struct sockaddr_in);
#endif
    			found = 1;
    			break;
    		} else if (addr_result->ai_family == AF_INET6) {
    			ns_bcopy(addr_result->ai_addr, addr, addr_result->ai_addrlen);
    			addr->s6.sin6_port = nswap16(port);
#if defined(SIN6_LEN) /* this define is required by IPv6 if used */
    			addr->s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
    			found = 1;
    			break;
    		}
    	}

    	addr_result = addr_result->ai_next;
    }

    if(!found && family == AF_INET) {
    	family = AF_INET6;
    	addr_result = addr_result_orig;
    	goto beg_af;
    }
    
    freeaddrinfo(addr_result_orig);
  }

  return 0;
}

static char* get_addr_string_and_port(char* s0, int *port)
{
	char *s = s0;
	while(*s && (*s==' ')) ++s;
	if(*s == '[') {
		++s;
		char *tail = strstr(s,"]");
		if(tail) {
			*tail=0;
			++tail;
			while(*tail && (*tail==' ')) ++tail;
			if(*tail==':') {
				++tail;
				*port = atoi(tail);
				return s;
			} else if(*tail == 0) {
				*port = 0;
				return s;
			}
		}
	} else {
		char *tail = strstr(s,":");
		if(tail) {
			*tail = 0;
			++tail;
			*port = atoi(tail);
			return s;
		} else {
			*port = 0;
			return s;
		}
	}
	return NULL;
}

int make_ioa_addr_from_full_string(const u08bits* saddr, int default_port, ioa_addr *addr)
{
	if(!addr)
		return -1;

	int ret = -1;
	int port = 0;
	char* s = turn_strdup((const char*)saddr);
	char *sa = get_addr_string_and_port(s,&port);
	if(sa) {
		if(port<1)
			port = default_port;
		ret = make_ioa_addr((u08bits*)sa,port,addr);
	}
	turn_free(s,strlen(s)+1);
	return ret;
}

int addr_to_string(const ioa_addr* addr, u08bits* saddr)
{

	if (addr && saddr) {

		s08bits addrtmp[MAX_IOA_ADDR_STRING];

		if (addr->ss.sa_family == AF_INET) {
			inet_ntop(AF_INET, &addr->s4.sin_addr, addrtmp, INET_ADDRSTRLEN);
			if(addr_get_port(addr)>0)
			  snprintf((s08bits*)saddr, MAX_IOA_ADDR_STRING, "%s:%d", addrtmp, addr_get_port(addr));
			else
			  strncpy((s08bits*)saddr, addrtmp, MAX_IOA_ADDR_STRING);
		} else if (addr->ss.sa_family == AF_INET6) {
			inet_ntop(AF_INET6, &addr->s6.sin6_addr, addrtmp, INET6_ADDRSTRLEN);
			if(addr_get_port(addr)>0)
			  snprintf((s08bits*)saddr, MAX_IOA_ADDR_STRING, "[%s]:%d", addrtmp, addr_get_port(addr));
			else
			  strncpy((s08bits*)saddr, addrtmp, MAX_IOA_ADDR_STRING);
		} else {
			return -1;
		}

		return 0;
	}

	return -1;
}

int addr_to_string_no_port(const ioa_addr* addr, u08bits* saddr)
{

	if (addr && saddr) {

		s08bits addrtmp[MAX_IOA_ADDR_STRING];

		if (addr->ss.sa_family == AF_INET) {
			inet_ntop(AF_INET, &addr->s4.sin_addr, addrtmp, INET_ADDRSTRLEN);
			strncpy((s08bits*)saddr, addrtmp, MAX_IOA_ADDR_STRING);
		} else if (addr->ss.sa_family == AF_INET6) {
			inet_ntop(AF_INET6, &addr->s6.sin6_addr, addrtmp, INET6_ADDRSTRLEN);
			strncpy((s08bits*)saddr, addrtmp, MAX_IOA_ADDR_STRING);
		} else {
			return -1;
		}

		return 0;
	}

	return -1;
}

void addr_set_port(ioa_addr* addr, int port) {
  if(addr) {
    if(addr->s4.sin_family == AF_INET) {
      addr->s4.sin_port = nswap16(port);
    } else if(addr->s6.sin6_family == AF_INET6) {
      addr->s6.sin6_port = nswap16(port);
    }
  }
}

int addr_get_port(const ioa_addr* addr) {
	if(!addr)
		return 0;

  if(addr->s4.sin_family == AF_INET) {
    return nswap16(addr->s4.sin_port);
  } else if(addr->s6.sin6_family == AF_INET6) {
    return nswap16(addr->s6.sin6_port);
  }
  return 0;
}

/////////////////////////////////////////////////////////////////////////////

void ioa_addr_range_set(ioa_addr_range* range, const ioa_addr* addr_min, const ioa_addr* addr_max) {
  if(range) {
    if(addr_min) addr_cpy(&(range->min),addr_min);
    else addr_set_any(&(range->min));
    if(addr_max) addr_cpy(&(range->max),addr_max);
    else addr_set_any(&(range->max));
  }
}

int addr_less_eq(const ioa_addr* addr1, const ioa_addr* addr2) {

  if(!addr1) return 1;
  else if(!addr2) return 0;
  else {
    if(addr1->ss.sa_family != addr2->ss.sa_family) return (addr1->ss.sa_family < addr2->ss.sa_family);
    else if(addr1->ss.sa_family == AF_INET) {
      return ((u32bits)nswap32(addr1->s4.sin_addr.s_addr) <= (u32bits)nswap32(addr2->s4.sin_addr.s_addr));
    } else if(addr1->ss.sa_family == AF_INET6) {
      int i;
      for(i=0;i<16;i++) {
	if((u08bits)(((const s08bits*)&(addr1->s6.sin6_addr))[i]) > (u08bits)(((const s08bits*)&(addr2->s6.sin6_addr))[i])) 
	  return 0;
      }
      return 1;
    } else return 1;
  }
}

int ioa_addr_in_range(const ioa_addr_range* range, const ioa_addr* addr) {

  if(range && addr) {
    if(addr_any(&(range->min)) || addr_less_eq(&(range->min),addr)) {
      if(addr_any(&(range->max))) {
	return 1;
      } else {
	return addr_less_eq(addr,&(range->max));
      }
    }
  }

  return 0;
}

void ioa_addr_range_cpy(ioa_addr_range* dest, const ioa_addr_range* src) {
  if(dest && src) {
    addr_cpy(&(dest->min),&(src->min));
    addr_cpy(&(dest->max),&(src->max));
  }
}

/////// Check whether this is a good address //////////////

int ioa_addr_is_multicast(ioa_addr *addr)
{
	if(addr) {
		if(addr->ss.sa_family == AF_INET) {
			const u08bits *u = ((const u08bits*)&(addr->s4.sin_addr));
			return (u[0] > 223);
		} else if(addr->ss.sa_family == AF_INET6) {
			u08bits u = ((const u08bits*)&(addr->s6.sin6_addr))[0];
			return (u == 255);
		}
	}
	return 0;
}

int ioa_addr_is_loopback(ioa_addr *addr)
{
	if(addr) {
		if(addr->ss.sa_family == AF_INET) {
			const u08bits *u = ((const u08bits*)&(addr->s4.sin_addr));
			return (u[0] == 127);
		} else if(addr->ss.sa_family == AF_INET6) {
			const u08bits *u = ((const u08bits*)&(addr->s6.sin6_addr));
			if(u[7] == 1) {
				int i;
				for(i=0;i<7;++i) {
					if(u[i])
						return 0;
				}
				return 1;
			}
		}
	}
	return 0;
}

/////// Map "public" address to "private" address //////////////

// Must be called only in a single-threaded context,
// before the program starts spawning threads:

static ioa_addr **public_addrs = NULL;
static ioa_addr **private_addrs = NULL;
static size_t mcount = 0;
static size_t msz = 0;

void ioa_addr_add_mapping(ioa_addr *apub, ioa_addr *apriv)
{
	size_t new_size = msz + sizeof(ioa_addr*);
	public_addrs = (ioa_addr**)turn_realloc(public_addrs, msz, new_size);
	private_addrs = (ioa_addr**)turn_realloc(private_addrs, msz, new_size);
	public_addrs[mcount]=(ioa_addr*)turn_malloc(sizeof(ioa_addr));
	private_addrs[mcount]=(ioa_addr*)turn_malloc(sizeof(ioa_addr));
	addr_cpy(public_addrs[mcount],apub);
	addr_cpy(private_addrs[mcount],apriv);
	++mcount;
	msz += sizeof(ioa_addr*);
}

void map_addr_from_public_to_private(const ioa_addr *public_addr, ioa_addr *private_addr)
{
	size_t i;
	for(i=0;i<mcount;++i) {
		if(addr_eq_no_port(public_addr,public_addrs[i])) {
			addr_cpy(private_addr,private_addrs[i]);
			addr_set_port(private_addr,addr_get_port(public_addr));
			return;
		}
	}
	addr_cpy(private_addr,public_addr);
}

void map_addr_from_private_to_public(const ioa_addr *private_addr, ioa_addr *public_addr)
{
	size_t i;
	for(i=0;i<mcount;++i) {
		if(addr_eq_no_port(private_addr,private_addrs[i])) {
			addr_cpy(public_addr,public_addrs[i]);
			addr_set_port(public_addr,addr_get_port(private_addr));
			return;
		}
	}
	addr_cpy(public_addr,private_addr);
}

//////////////////////////////////////////////////////////////////////////////

