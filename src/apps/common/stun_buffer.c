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

#include "stun_buffer.h"

#include <string.h> // for memset

////////////////////// BUFFERS ///////////////////////////

int stun_init_buffer(stun_buffer *buf) {
  if (!buf) {
    return -1;
  }
  memset(buf->buf, 0, sizeof(buf->buf));
  buf->len = 0;
  buf->offset = 0;
  buf->coffset = 0;
  return 0;
}

int stun_get_size(const stun_buffer *buf) {
  if (!buf) {
    return 0;
  }
  return sizeof(buf->buf);
}

////////////////////////////////////////////////////////////

void stun_tid_from_message(const stun_buffer *buf, stun_tid *id) {
  stun_tid_from_message_str(buf->buf, (size_t)(buf->len), id);
}

void stun_tid_generate_in_message(stun_buffer *buf, stun_tid *id) {
  if (buf) {
    stun_tid_generate_in_message_str(buf->buf, id);
  }
}

////////////////////////////////////////////////////////

static inline bool is_channel_msg(const stun_buffer *buf) {
  if (buf && buf->len > 0) {
    return is_channel_msg_str(buf->buf, (size_t)(buf->len));
  }
  return false;
}

bool stun_is_command_message(const stun_buffer *buf) {
  if (!buf || buf->len <= 0) {
    return false;
  } else {
    return stun_is_command_message_str(buf->buf, (size_t)(buf->len));
  }
}

bool stun_is_request(const stun_buffer *buf) { return stun_is_request_str(buf->buf, (size_t)buf->len); }

bool stun_is_success_response(const stun_buffer *buf) {
  return stun_is_success_response_str(buf->buf, (size_t)(buf->len));
}

bool stun_is_error_response(const stun_buffer *buf, int *err_code, uint8_t *err_msg, size_t err_msg_size) {
  return stun_is_error_response_str(buf->buf, (size_t)(buf->len), err_code, err_msg, err_msg_size);
}

bool stun_is_response(const stun_buffer *buf) { return stun_is_response_str(buf->buf, (size_t)(buf->len)); }

bool stun_is_indication(const stun_buffer *buf) {
  if (is_channel_msg(buf)) {
    return false;
  }
  return IS_STUN_INDICATION(stun_get_msg_type(buf));
}

uint16_t stun_get_method(const stun_buffer *buf) { return stun_get_method_str(buf->buf, (size_t)(buf->len)); }

uint16_t stun_get_msg_type(const stun_buffer *buf) {
  if (!buf) {
    return (uint16_t)-1;
  }
  return stun_get_msg_type_str(buf->buf, (size_t)buf->len);
}

////////////////////////////////////////////////////////////

static void stun_init_command(uint16_t message_type, stun_buffer *buf) {
  buf->len = stun_get_size(buf);
  stun_init_command_str(message_type, buf->buf, &(buf->len));
}

void stun_init_request(uint16_t method, stun_buffer *buf) { stun_init_command(stun_make_request(method), buf); }

void stun_init_indication(uint16_t method, stun_buffer *buf) { stun_init_command(stun_make_indication(method), buf); }

void stun_init_success_response(uint16_t method, stun_buffer *buf, stun_tid *id) {
  buf->len = stun_get_size(buf);
  stun_init_success_response_str(method, buf->buf, &(buf->len), id);
}

void stun_init_error_response(uint16_t method, stun_buffer *buf, uint16_t error_code, const uint8_t *reason,
                              stun_tid *id) {
  buf->len = stun_get_size(buf);
  stun_init_error_response_str(method, buf->buf, &(buf->len), error_code, reason, id);
}

///////////////////////////////////////////////////////////////////////////////

int stun_get_command_message_len(const stun_buffer *buf) {
  return stun_get_command_message_len_str(buf->buf, buf->len);
}

///////////////////////////////////////////////////////////////////////////////

bool stun_init_channel_message(uint16_t chnumber, stun_buffer *buf, int length, bool do_padding) {
  return stun_init_channel_message_str(chnumber, buf->buf, &(buf->len), length, do_padding);
}

bool stun_is_channel_message(stun_buffer *buf, uint16_t *chnumber, bool is_padding_mandatory) {
  if (!buf) {
    return false;
  }
  size_t blen = buf->len;
  bool ret = stun_is_channel_message_str(buf->buf, &blen, chnumber, is_padding_mandatory);
  if (ret) {
    buf->len = blen;
  }
  return ret;
}

///////////////////////////////////////////////////////////////////////////////

bool stun_set_allocate_request(stun_buffer *buf, uint32_t lifetime, bool af4, bool af6, uint8_t transport, bool mobile,
                               const char *rt, int ep) {
  return stun_set_allocate_request_str(buf->buf, &(buf->len), lifetime, af4, af6, transport, mobile, rt, ep);
}

bool stun_set_allocate_response(stun_buffer *buf, stun_tid *tid, const ioa_addr *relayed_addr1,
                                const ioa_addr *relayed_addr2, const ioa_addr *reflexive_addr, uint32_t lifetime,
                                uint32_t max_lifetime, int error_code, const uint8_t *reason,
                                uint64_t reservation_token, char *mobile_id) {

  return stun_set_allocate_response_str(buf->buf, &(buf->len), tid, relayed_addr1, relayed_addr2, reflexive_addr,
                                        lifetime, max_lifetime, error_code, reason, reservation_token, mobile_id);
}

///////////////////////////////////////////////////////////////////////////////

uint16_t stun_set_channel_bind_request(stun_buffer *buf, const ioa_addr *peer_addr, uint16_t channel_number) {

  return stun_set_channel_bind_request_str(buf->buf, &(buf->len), peer_addr, channel_number);
}

void stun_set_channel_bind_response(stun_buffer *buf, stun_tid *tid, int error_code, const uint8_t *reason) {
  stun_set_channel_bind_response_str(buf->buf, &(buf->len), tid, error_code, reason);
}

////////////////////////////////////////////////////////////////

stun_attr_ref stun_attr_get_first(const stun_buffer *buf) { return stun_attr_get_first_str(buf->buf, buf->len); }

stun_attr_ref stun_attr_get_next(const stun_buffer *buf, stun_attr_ref prev) {
  return stun_attr_get_next_str(buf->buf, buf->len, prev);
}

bool stun_attr_add(stun_buffer *buf, uint16_t attr, const char *avalue, int alen) {
  return stun_attr_add_str(buf->buf, &(buf->len), attr, (const uint8_t *)avalue, alen);
}

bool stun_attr_add_channel_number(stun_buffer *buf, uint16_t chnumber) {
  return stun_attr_add_channel_number_str(buf->buf, &(buf->len), chnumber);
}

bool stun_attr_add_addr(stun_buffer *buf, uint16_t attr_type, const ioa_addr *ca) {
  return stun_attr_add_addr_str(buf->buf, &(buf->len), attr_type, ca);
}

bool stun_attr_get_addr(const stun_buffer *buf, stun_attr_ref attr, ioa_addr *ca, const ioa_addr *default_addr) {
  return stun_attr_get_addr_str(buf->buf, buf->len, attr, ca, default_addr);
}

bool stun_attr_get_first_addr(const stun_buffer *buf, uint16_t attr_type, ioa_addr *ca, const ioa_addr *default_addr) {
  return stun_attr_get_first_addr_str(buf->buf, buf->len, attr_type, ca, default_addr);
}

bool stun_attr_add_even_port(stun_buffer *buf, uint8_t value) {
  if (value) {
    value = 0x80;
  }
  return stun_attr_add(buf, STUN_ATTRIBUTE_EVEN_PORT, (const char *)&value, 1);
}

uint16_t stun_attr_get_first_channel_number(const stun_buffer *buf) {
  return stun_attr_get_first_channel_number_str(buf->buf, buf->len);
}

stun_attr_ref stun_attr_get_first_by_type(const stun_buffer *buf, uint16_t attr_type) {
  return stun_attr_get_first_by_type_str(buf->buf, buf->len, attr_type);
}

///////////////////////////////////////////////////////////////////////////////

void stun_set_binding_request(stun_buffer *buf) { stun_set_binding_request_str(buf->buf, (size_t *)(&(buf->len))); }

bool stun_set_binding_response(stun_buffer *buf, stun_tid *tid, const ioa_addr *reflexive_addr, int error_code,
                               const uint8_t *reason) {
  return stun_set_binding_response_str(buf->buf, &(buf->len), tid, reflexive_addr, error_code, reason, 0, false, true);
}

void stun_prepare_binding_request(stun_buffer *buf) { stun_set_binding_request_str(buf->buf, (size_t *)(&(buf->len))); }

bool stun_is_binding_response(const stun_buffer *buf) { return stun_is_binding_response_str(buf->buf, buf->len); }

///////////////////////////////////////////////////////
