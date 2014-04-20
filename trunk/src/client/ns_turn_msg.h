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

#ifndef __LIB_TURN_MSG__
#define __LIB_TURN_MSG__

#include "ns_turn_ioaddr.h"
#include "ns_turn_msg_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////

/**
 * Structure holding the STUN message Transaction ID
 */
#define STUN_TID_SIZE (12)
typedef struct {
	/**
	 * Binary array
	 */
  uint8_t tsx_id[STUN_TID_SIZE];
} stun_tid;

typedef enum {
	TURN_CREDENTIALS_NONE = 0,
	TURN_CREDENTIALS_LONG_TERM,
	TURN_CREDENTIALS_SHORT_TERM,
	TURN_CREDENTIALS_UNDEFINED
} turn_credential_type;

/**
 * HMAC key
 */
typedef u08bits hmackey_t[64];

/**
 * Short-term credentials password
 */
#define SHORT_TERM_PASSWORD_SIZE (512)
typedef u08bits st_password_t[SHORT_TERM_PASSWORD_SIZE+1];

///////////////////////////////////

typedef const void* stun_attr_ref;

//////////////////////////////////////////////////////////////

int stun_tid_equals(const stun_tid *id1, const stun_tid *id2);
void stun_tid_cpy(stun_tid *id_dst, const stun_tid *id_src);
void stun_tid_generate(stun_tid* id);

///////////////////////////////////////////////////////////////

u16bits stun_make_type(u16bits method);
u16bits stun_make_request(u16bits method);
u16bits stun_make_indication(u16bits method);
u16bits stun_make_success_response(u16bits method);
u16bits stun_make_error_response(u16bits method);

///////////////////////////////////////////////////////////////

u32bits stun_adjust_allocate_lifetime(u32bits lifetime);

///////////// STR ////////////////////////////////////////////////

int stun_get_message_len_str(u08bits *buf, size_t len, int padding, size_t *app_len);

void stun_init_buffer_str(u08bits *buf, size_t *len);
void stun_init_command_str(u16bits message_type, u08bits* buf, size_t *len);
void old_stun_init_command_str(u16bits message_type, u08bits* buf, size_t *len, u32bits cookie);
void stun_init_request_str(u16bits method, u08bits* buf, size_t *len);
void stun_init_indication_str(u16bits method, u08bits* buf, size_t *len);
void stun_init_success_response_str(u16bits method, u08bits* buf, size_t *len, stun_tid* id);
void old_stun_init_success_response_str(u16bits method, u08bits* buf, size_t *len, stun_tid* id, u32bits cookie);
void stun_init_error_response_str(u16bits method, u08bits* buf, size_t *len, u16bits error_code, const u08bits *reason, stun_tid* id);
void old_stun_init_error_response_str(u16bits method, u08bits* buf, size_t *len, u16bits error_code, const u08bits *reason, stun_tid* id, u32bits cookie);
int stun_init_channel_message_str(u16bits chnumber, u08bits* buf, size_t *len, int length, int do_padding);

int stun_is_command_message_str(const u08bits* buf, size_t blen);
int old_stun_is_command_message_str(const u08bits* buf, size_t blen, u32bits *cookie);
int stun_is_command_message_full_check_str(const u08bits* buf, size_t blen, int must_check_fingerprint, int *fingerprint_present);
int stun_is_command_message_offset_str(const u08bits* buf, size_t blen, int offset);
int stun_is_request_str(const u08bits* buf, size_t len);
int stun_is_success_response_str(const u08bits* buf, size_t len);
int stun_is_error_response_str(const u08bits* buf, size_t len, int *err_code, u08bits *err_msg, size_t err_msg_size);
int stun_is_challenge_response_str(const u08bits* buf, size_t len, int *err_code, u08bits *err_msg, size_t err_msg_size, u08bits *realm, u08bits *nonce);
int stun_is_response_str(const u08bits* buf, size_t len);
int stun_is_indication_str(const u08bits* buf, size_t len);
u16bits stun_get_method_str(const u08bits *buf, size_t len);
u16bits stun_get_msg_type_str(const u08bits *buf, size_t len);
int stun_is_channel_message_str(const u08bits *buf, size_t *blen, u16bits* chnumber, int mandatory_padding);
int is_channel_msg_str(const u08bits* buf, size_t blen);

void stun_set_binding_request_str(u08bits* buf, size_t *len);
int stun_set_binding_response_str(u08bits* buf, size_t *len, stun_tid* tid, 
				  const ioa_addr *reflexive_addr, int error_code,
				  const u08bits *reason,
				  u32bits cookie, int old_stun);
int stun_is_binding_request_str(const u08bits* buf, size_t len, size_t offset);
int stun_is_binding_response_str(const u08bits* buf, size_t len);

void stun_tid_from_message_str(const u08bits* buf, size_t len, stun_tid* id);
void stun_tid_message_cpy(u08bits *buf, const stun_tid* id);
void stun_tid_generate_in_message_str(u08bits* buf, stun_tid* id);

int stun_get_command_message_len_str(const u08bits* buf, size_t len);

int stun_attr_is_addr(stun_attr_ref attr);
int stun_attr_get_type(stun_attr_ref attr);
int stun_attr_get_len(stun_attr_ref attr);
const u08bits* stun_attr_get_value(stun_attr_ref attr);
u16bits stun_attr_get_channel_number(stun_attr_ref attr);
u08bits stun_attr_get_even_port(stun_attr_ref attr);
u64bits stun_attr_get_reservation_token_value(stun_attr_ref attr);
stun_attr_ref stun_attr_get_first_by_type_str(const u08bits* buf, size_t len, u16bits attr_type);
stun_attr_ref stun_attr_get_first_str(const u08bits* buf, size_t len);
stun_attr_ref stun_attr_get_next_str(const u08bits* buf, size_t len, stun_attr_ref prev);
int stun_attr_add_str(u08bits* buf, size_t *len, u16bits attr, const u08bits* avalue, int alen);
int stun_attr_add_addr_str(u08bits *buf, size_t *len, u16bits attr_type, const ioa_addr* ca);
int stun_attr_get_addr_str(const u08bits *buf, size_t len, stun_attr_ref attr, ioa_addr* ca, const ioa_addr *default_addr);
int stun_attr_get_first_addr_str(const u08bits *buf, size_t len, u16bits attr_type, ioa_addr* ca, const ioa_addr *default_addr);
int stun_attr_add_channel_number_str(u08bits* buf, size_t *len, u16bits chnumber);
u16bits stun_attr_get_first_channel_number_str(const u08bits *buf, size_t len);

int stun_set_allocate_request_str(u08bits* buf, size_t *len, u32bits lifetime, int address_family, u08bits transport, int mobile);
int stun_set_allocate_response_str(u08bits* buf, size_t *len, stun_tid* tid, 
				   const ioa_addr *relayed_addr,
				   const ioa_addr *reflexive_addr,
				   u32bits lifetime, int error_code, const u08bits *reason,
				   u64bits reservation_token, char *mobile_id);

u16bits stun_set_channel_bind_request_str(u08bits* buf, size_t *len,
					  const ioa_addr* peer_addr, u16bits channel_number);
void stun_set_channel_bind_response_str(u08bits* buf, size_t *len, stun_tid* tid, int error_code, const u08bits *reason);

int stun_get_requested_address_family(stun_attr_ref attr);

int stun_attr_add_fingerprint_str(u08bits *buf, size_t *len);

int SASLprep(u08bits *s);

#define print_bin(str, len, field) print_bin_func(str,len,field,__FUNCTION__)
void print_bin_func(const char *name, size_t len, const void *s, const char *func);

/*
 * Return -1 if failure, 0 if the integrity is not correct, 1 if OK
 */
int stun_check_message_integrity_by_key_str(turn_credential_type ct, u08bits *buf, size_t len, hmackey_t key, st_password_t pwd, SHATYPE shatype, int *too_weak);
int stun_check_message_integrity_str(turn_credential_type ct, u08bits *buf, size_t len, u08bits *uname, u08bits *realm, u08bits *upwd, SHATYPE shatype);
int stun_attr_add_integrity_str(turn_credential_type ct, u08bits *buf, size_t *len, hmackey_t key, st_password_t pwd, SHATYPE shatype);
int stun_attr_add_integrity_by_user_str(u08bits *buf, size_t *len, u08bits *uname, u08bits *realm, u08bits *upwd, u08bits *nonce, SHATYPE shatype);
int stun_attr_add_integrity_by_user_short_term_str(u08bits *buf, size_t *len, u08bits *uname, st_password_t pwd, SHATYPE shatype);
size_t get_hmackey_size(SHATYPE shatype);

/*
 * To be implemented with openssl
 */

#define TURN_RANDOM_SIZE (sizeof(long))
long turn_random(void);
void turn_random32_size(u32bits *ar, size_t sz);

int stun_produce_integrity_key_str(u08bits *uname, u08bits *realm, u08bits *upwd, hmackey_t key, SHATYPE shatype);
int stun_calculate_hmac(const u08bits *buf, size_t len, const u08bits *key, size_t sz, u08bits *hmac, unsigned int *hmac_len, SHATYPE shatype);

/* RFC 5780 */
int stun_attr_get_change_request_str(stun_attr_ref attr, int *change_ip, int *change_port);
int stun_attr_add_change_request_str(u08bits *buf, size_t *len, int change_ip, int change_port);
int stun_attr_get_response_port_str(stun_attr_ref attr);
int stun_attr_add_response_port_str(u08bits *buf, size_t *len, u16bits port);
int stun_attr_get_padding_len_str(stun_attr_ref attr);
int stun_attr_add_padding_str(u08bits *buf, size_t *len, u16bits padding_len);

/* HTTP */
int is_http_get(const char *s, size_t blen);

///////////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__LIB_TURN_MSG__
