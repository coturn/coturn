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

#ifndef __IOADDR__
#define __IOADDR__

#include "ns_turn_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/////////////////////////////////////////////////////

#define MAX_IOA_ADDR_STRING (65)

typedef union {
  struct sockaddr ss;
  struct sockaddr_in s4;
  struct sockaddr_in6 s6;
} ioa_addr;

typedef struct {
  ioa_addr min;
  ioa_addr max;
} ioa_addr_range;

////////////////////////////

u32bits get_ioa_addr_len(const ioa_addr* addr);

////////////////////////////

void addr_set_any(ioa_addr *addr);
int addr_any(const ioa_addr* addr);
int addr_any_no_port(const ioa_addr* addr);
u32bits addr_hash(const ioa_addr *addr);
u32bits addr_hash_no_port(const ioa_addr *addr);
void addr_cpy(ioa_addr* dst, const ioa_addr* src);
void addr_cpy4(ioa_addr* dst, const struct sockaddr_in* src);
void addr_cpy6(ioa_addr* dst, const struct sockaddr_in6* src);
int addr_eq(const ioa_addr* a1, const ioa_addr *a2);
int addr_eq_no_port(const ioa_addr* a1, const ioa_addr *a2);
int make_ioa_addr(const u08bits* saddr, int port, ioa_addr *addr);
int make_ioa_addr_from_full_string(const u08bits* saddr, int default_port, ioa_addr *addr);
void addr_set_port(ioa_addr* addr, int port);
int addr_get_port(const ioa_addr* addr);
int addr_to_string(const ioa_addr* addr, u08bits* saddr);
int addr_to_string_no_port(const ioa_addr* addr, u08bits* saddr);

u32bits hash_int32(u32bits a);
u64bits hash_int64(u64bits a);

///////////////////////////////////////////

void ioa_addr_range_set(ioa_addr_range* range, const ioa_addr* addr_min, const ioa_addr* addr_max);
int addr_less_eq(const ioa_addr* addr1, const ioa_addr* addr2);
int ioa_addr_in_range(const ioa_addr_range* range, const ioa_addr* addr);
void ioa_addr_range_cpy(ioa_addr_range* dest, const ioa_addr_range* src);

/////// Check whether this is a good address //////////////

int ioa_addr_is_multicast(ioa_addr *a);
int ioa_addr_is_loopback(ioa_addr *addr);

/////// Map "public" address to "private" address //////////////

// Must be called only in a single-threaded context,
// before the program starts spawning threads:

void ioa_addr_add_mapping(ioa_addr *apub, ioa_addr *apriv);
void map_addr_from_public_to_private(const ioa_addr *public_addr, ioa_addr *private_addr);
void map_addr_from_private_to_public(const ioa_addr *private_addr, ioa_addr *public_addr);

///////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__IOADDR__
