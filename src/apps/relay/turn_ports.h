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

#ifndef __TURN_PORTS__
#define __TURN_PORTS__

#include "ns_turn_ioaddr.h"

#include "ns_sm.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////

#define LOW_DEFAULT_PORTS_BOUNDARY (49152)
#define HIGH_DEFAULT_PORTS_BOUNDARY (65535)

//////////////////////////////////////////////////

struct _turnipports;
typedef struct _turnipports turnipports;

//////////////////////////////////////////////////

turnipports* turnipports_create(super_memory_t *sm, u16bits start, u16bits end);

void turnipports_add_ip(u08bits transport, const ioa_addr *backend_addr);

int turnipports_allocate(turnipports* tp, u08bits transport, const ioa_addr *backend_addr);
int turnipports_allocate_even(turnipports* tp, const ioa_addr *backend_addr, 
			      int allocate_rtcp, u64bits *reservation_token);

void turnipports_release(turnipports* tp, u08bits transport, const ioa_addr *socket_addr);

int turnipports_is_allocated(turnipports* tp, u08bits transport, const ioa_addr *backend_addr, u16bits port);
int turnipports_is_available(turnipports* tp, u08bits transport, const ioa_addr *backend_addr, u16bits port);

//////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_PORTS__
