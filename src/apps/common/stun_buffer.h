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

#ifndef __TURN_STUN_BUF__
#define __TURN_STUN_BUF__

#include "ns_turn_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////

typedef struct _stun_buffer {
  uint8_t	channel[STUN_CHANNEL_HEADER_LENGTH];
  uint8_t	buf[STUN_BUFFER_SIZE];
  size_t	len;
  uint16_t	offset;
  uint8_t	coffset;
} stun_buffer;

//////////////////////////////////////////////////////////////

int stun_init_buffer(stun_buffer *buf);
int stun_get_size(const stun_buffer *buf);

//////////////////////////////////////////////////////////////

void stun_tid_generate_in_message(stun_buffer* buf, stun_tid* id);
void stun_tid_from_message(const stun_buffer *buf, stun_tid* id);

///////////////////////////////////////////////////////////////

int stun_is_command_message(const stun_buffer* buf);
int stun_is_request(const stun_buffer* buf);
int stun_is_response(const stun_buffer* buf);
int stun_is_success_response(const stun_buffer* buf);
int stun_is_error_response(const stun_buffer* buf, int *err_code, uint8_t *err_msg, size_t err_msg_size);
int stun_is_indication(const stun_buffer* buf);
uint16_t stun_get_method(const stun_buffer* buf);
uint16_t stun_get_msg_type(const stun_buffer* buf);

///////////////////////////////////////////////////////////////

void stun_init_request(uint16_t method, stun_buffer* buf);
void stun_init_indication(uint16_t method, stun_buffer* buf);
void stun_init_success_response(uint16_t method, stun_buffer* buf, stun_tid* id);
void stun_init_error_response(uint16_t method, stun_buffer* buf, uint16_t error_code, const uint8_t *reason, stun_tid* id);

///////////////////////////////////////////////////////////////

int stun_attr_add(stun_buffer* buf, uint16_t attr, const char* avalue, int alen);
int stun_attr_add_channel_number(stun_buffer* buf, uint16_t chnumber);
int stun_attr_add_addr(stun_buffer *buf,uint16_t attr_type, const ioa_addr* ca);

stun_attr_ref stun_attr_get_first(const stun_buffer* buf);
stun_attr_ref stun_attr_get_first_by_type(const stun_buffer* buf, uint16_t attr_type);
stun_attr_ref stun_attr_get_next(const stun_buffer* buf, stun_attr_ref prev);
int stun_attr_get_addr(const stun_buffer *buf, stun_attr_ref attr, ioa_addr* ca, const ioa_addr *default_addr);
int stun_attr_add_even_port(stun_buffer* buf, uint8_t value);

int stun_attr_get_first_addr(const stun_buffer *buf, uint16_t attr_type, ioa_addr* ca, const ioa_addr *default_addr);
uint16_t stun_attr_get_first_channel_number(const stun_buffer *buf);

///////////////////////////////////////////////////////////////

int stun_get_command_message_len(const stun_buffer* buf);

///////////////////////////////////////////////////////////////

int stun_init_channel_message(uint16_t chnumber, stun_buffer* buf, int length, int do_padding);
int stun_is_channel_message(stun_buffer* buf, uint16_t* chnumber, int is_padding_madatory);

///////////////////////////////////////////////////////////////

int stun_set_allocate_request(stun_buffer* buf, uint32_t lifetime, int af4, int af6, uint8_t transport, int mobile, const char* rt, int ep);
int stun_set_allocate_response(stun_buffer* buf, stun_tid* tid, 
			       const ioa_addr *relayed_addr1, const ioa_addr *relayed_addr2,
			       const ioa_addr *reflexive_addr,
			       uint32_t lifetime, uint32_t max_lifetime,
			       int error_code, const uint8_t *reason,
			       uint64_t reservation_token, char *mobile_id);

///////////////////////////////////////////////////////////////

void stun_set_binding_request(stun_buffer* buf);
int stun_set_binding_response(stun_buffer* buf, stun_tid* tid, 
			      const ioa_addr *reflexive_addr, int error_code, const uint8_t *reason);

void stun_prepare_binding_request(stun_buffer* buf);
int stun_is_binding_response(const stun_buffer* buf);

///////////////////////////////////////////////////////////////

uint16_t stun_set_channel_bind_request(stun_buffer* buf, const ioa_addr* peer_addr, uint16_t channel_number);
void stun_set_channel_bind_response(stun_buffer* buf, stun_tid* tid, int error_code, const uint8_t *reason);

///////////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_STUN_BUF__
