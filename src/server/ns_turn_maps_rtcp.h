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

#ifndef __TURN_RTCP_MAP__
#define __TURN_RTCP_MAP__

#include "ns_turn_maps.h"
#include "ns_turn_ioalib.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////////// RTCP MAP //////////////////

typedef ur_map_key_type rtcp_token_type;

struct _rtcp_map;
typedef struct _rtcp_map rtcp_map;

////////////////////////////////////////////////

rtcp_map* rtcp_map_create(ioa_engine_handle e);

/**
 * @ret:
 * 0 - success
 * -1 - error
 */
int rtcp_map_put(rtcp_map* map, rtcp_token_type key, ioa_socket_handle s);

/**
 * @ret:
 * >=0 - success
 * <0 - not found
 */
ioa_socket_handle rtcp_map_get(rtcp_map* map, rtcp_token_type token);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
void rtcp_map_free(rtcp_map** map);

size_t rtcp_map_size(const rtcp_map* map);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_RTCP_MAP__
