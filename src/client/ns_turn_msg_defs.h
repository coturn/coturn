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

#ifndef __LIB_TURN_MSG_DEFS__
#define __LIB_TURN_MSG_DEFS__

#include "ns_turn_msg_defs_experimental.h"

///////////////////////////////////////////
// http://www.iana.org/assignments/stun-parameters/stun-parameters.xhtml
///////////////////////////////////////////

#define STUN_HEADER_LENGTH (20)
#define STUN_CHANNEL_HEADER_LENGTH (4)

#define STUN_MAX_USERNAME_SIZE (512)
#define STUN_MAX_REALM_SIZE (127)
#define STUN_MAX_NONCE_SIZE (127)
#define STUN_MAX_SERVER_NAME_SIZE (1025)
#define STUN_MAX_PWD_SIZE (256)
#define AUTH_SECRET_SIZE STUN_MAX_PWD_SIZE

#define STUN_MAGIC_COOKIE (0x2112A442)

#define IS_STUN_REQUEST(msg_type)       (((msg_type) & 0x0110) == 0x0000)
#define IS_STUN_INDICATION(msg_type)    (((msg_type) & 0x0110) == 0x0010)
#define IS_STUN_SUCCESS_RESP(msg_type)  (((msg_type) & 0x0110) == 0x0100)
#define IS_STUN_ERR_RESP(msg_type)      (((msg_type) & 0x0110) == 0x0110)

#define GET_STUN_REQUEST(msg_type)      (msg_type & 0xFEEF)
#define GET_STUN_INDICATION(msg_type)   ((msg_type & 0xFEEF)|0x0010)
#define GET_STUN_SUCCESS_RESP(msg_type)  ((msg_type & 0xFEEF)|0x0100)
#define GET_STUN_ERR_RESP(msg_type)      (msg_type | 0x0110)

/* Lifetimes: */
#define STUN_DEFAULT_ALLOCATE_LIFETIME (600)
#define STUN_MIN_ALLOCATE_LIFETIME STUN_DEFAULT_ALLOCATE_LIFETIME
#define STUN_MAX_ALLOCATE_LIFETIME (3600)
#define STUN_CHANNEL_LIFETIME (600)
#define STUN_PERMISSION_LIFETIME (300)
#define STUN_NONCE_EXPIRATION_TIME (600)
/**/

#define STUN_METHOD_BINDING (0x0001)
#define STUN_METHOD_ALLOCATE (0x0003)
#define STUN_METHOD_REFRESH (0x0004)
#define STUN_METHOD_SEND (0x0006)
#define STUN_METHOD_DATA (0x0007)
#define STUN_METHOD_CREATE_PERMISSION (0x0008)
#define STUN_METHOD_CHANNEL_BIND (0x0009)

/* RFC 6062 ==>>*/
#define STUN_METHOD_CONNECT (0x000a)
#define STUN_METHOD_CONNECTION_BIND (0x000b)
#define STUN_METHOD_CONNECTION_ATTEMPT (0x000c)
/* <<== RFC 6062 */

#define STUN_ATTRIBUTE_MAPPED_ADDRESS (0x0001)
#define OLD_STUN_ATTRIBUTE_RESPONSE_ADDRESS (0x0002)
#define STUN_ATTRIBUTE_CHANGE_REQUEST (0x0003)
#define OLD_STUN_ATTRIBUTE_SOURCE_ADDRESS (0x0004)
#define OLD_STUN_ATTRIBUTE_CHANGED_ADDRESS (0x0005)
#define STUN_ATTRIBUTE_USERNAME (0x0006)
#define OLD_STUN_ATTRIBUTE_PASSWORD (0x0007)
#define STUN_ATTRIBUTE_MESSAGE_INTEGRITY (0x0008)
#define STUN_ATTRIBUTE_ERROR_CODE (0x0009)
#define STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES (0x000A)
#define OLD_STUN_ATTRIBUTE_REFLECTED_FROM (0x000B)
#define STUN_ATTRIBUTE_REALM (0x0014)
#define STUN_ATTRIBUTE_NONCE (0x0015)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY (0x0017)
#define STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS (0x0020)
#define OLD_STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS (0x8020)

#define STUN_ATTRIBUTE_SOFTWARE (0x8022)
#define OLD_STUN_ATTRIBUTE_SERVER STUN_ATTRIBUTE_SOFTWARE
#define STUN_ATTRIBUTE_ALTERNATE_SERVER (0x8023)
#define STUN_ATTRIBUTE_FINGERPRINT (0x8028)

#define STUN_ATTRIBUTE_CHANNEL_NUMBER (0x000C)
#define STUN_ATTRIBUTE_LIFETIME (0x000D)
#define STUN_ATTRIBUTE_BANDWIDTH (0x0010)
#define STUN_ATTRIBUTE_XOR_PEER_ADDRESS (0x0012)
#define STUN_ATTRIBUTE_DATA (0x0013)
#define STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS (0x0016)
#define STUN_ATTRIBUTE_EVEN_PORT (0x0018)
#define STUN_ATTRIBUTE_REQUESTED_TRANSPORT (0x0019)
#define STUN_ATTRIBUTE_DONT_FRAGMENT (0x001A)
#define STUN_ATTRIBUTE_TIMER_VAL (0x0021)
#define STUN_ATTRIBUTE_RESERVATION_TOKEN (0x0022)

/* ICE */
#define STUN_ATTRIBUTE_PRIORITY (0x0024)
#define STUN_ATTRIBUTE_ICE_CONTROLLED (0x8029)

/* RFC 5780 */
#define STUN_ATTRIBUTE_PADDING (0x0026)
#define STUN_ATTRIBUTE_RESPONSE_PORT (0x0027)
#define STUN_ATTRIBUTE_RESPONSE_ORIGIN (0x802B)
#define STUN_ATTRIBUTE_OTHER_ADDRESS (0x802C)

/* RFC 6062 ==>> */
#define STUN_ATTRIBUTE_CONNECTION_ID (0x002A)
/* <<== RFC 6062 */

#define STUN_VALID_CHANNEL(chn) ((chn)>=0x4000 && (chn)<=0x7FFF)

///////// extra values //////////////////

/* RFC 6156 ==>> */
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4 (0x01)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6 (0x02)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT (0x00)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_INVALID (-1)
/* <<== RFC 6156 */

/* RFC 6062 ==>> */
#define STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE (6)
#define STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE (17)
#define STUN_ATTRIBUTE_TRANSPORT_TLS_VALUE (56)
#define STUN_ATTRIBUTE_TRANSPORT_DTLS_VALUE (250)
/* <<== RFC 6062 */

/* SHA ==>> */

#define SHA1SIZEBYTES (20)
#define SHA256SIZEBYTES (32)
#define SHA384SIZEBYTES (48)
#define SHA512SIZEBYTES (64)

#define MAXSHASIZE (128)

enum _SHATYPE {
	SHATYPE_ERROR = -1,
	SHATYPE_DEFAULT=0,
	SHATYPE_SHA1=SHATYPE_DEFAULT,
	SHATYPE_SHA256,
	SHATYPE_SHA384,
	SHATYPE_SHA512
};

typedef enum _SHATYPE SHATYPE;

#define shatype_name(sht) ((sht == SHATYPE_SHA1) ? "SHA1" : ((sht == SHATYPE_SHA256) ? "SHA256" : ((sht == SHATYPE_SHA384) ? "SHA384" : "SHA512")))

/* <<== SHA */

/* OAUTH TOKEN ENC ALG ==> */

enum _ENC_ALG {
	ENC_ALG_ERROR=-1,
#if !defined(TURN_NO_GCM)
	ENC_ALG_DEFAULT=0,
	A256GCM=ENC_ALG_DEFAULT,
	A128GCM,
#endif
	ENC_ALG_NUM
};

typedef enum _ENC_ALG ENC_ALG;

/* <<== OAUTH TOKEN ENC ALG */

/**
 * oAuth struct
 */

#define STUN_ATTRIBUTE_THIRD_PARTY_AUTHORIZATION (0x802E)
#define STUN_ATTRIBUTE_OAUTH_ACCESS_TOKEN (0x001B)

#define OAUTH_KID_SIZE (128)
#define OAUTH_HASH_FUNC_SIZE (64)
#define OAUTH_ALG_SIZE (64)
#define OAUTH_KEY_SIZE (256)
#define OAUTH_GCM_NONCE_SIZE (12)
#define OAUTH_MAX_NONCE_SIZE (256)
#define OAUTH_GCM_TAG_SIZE (16)
#define OAUTH_ENC_ALG_BLOCK_SIZE (16)

#define OAUTH_DEFAULT_LIFETIME (0)
#define OAUTH_DEFAULT_TIMESTAMP (turn_time())

#define OAUTH_TIME_DELTA (5)

struct _oauth_key_data {
	char kid[OAUTH_KID_SIZE+1];
	char ikm_key[OAUTH_KEY_SIZE+1];
	size_t ikm_key_size;
	turn_time_t timestamp;
	turn_time_t lifetime;
	char as_rs_alg[OAUTH_ALG_SIZE+1];
};

typedef struct _oauth_key_data oauth_key_data;

struct _oauth_key {
	char kid[OAUTH_KID_SIZE+1];
	char ikm_key[OAUTH_KEY_SIZE+1];
	size_t ikm_key_size;
	turn_time_t timestamp;
	turn_time_t lifetime;
	ENC_ALG as_rs_alg;
	char as_rs_key[OAUTH_KEY_SIZE+1];
	size_t as_rs_key_size;
	char auth_key[OAUTH_KEY_SIZE+1];
	size_t auth_key_size;
};

typedef struct _oauth_key oauth_key;

struct _oauth_encrypted_block {
	uint16_t nonce_length;
	uint8_t nonce[OAUTH_MAX_NONCE_SIZE];
	uint16_t key_length;
	uint8_t mac_key[MAXSHASIZE];
	uint64_t timestamp;
	uint32_t lifetime;
};

typedef struct _oauth_encrypted_block oauth_encrypted_block;

struct _oauth_token {
	oauth_encrypted_block enc_block;
};

typedef struct _oauth_token oauth_token;

#define MAX_ENCODED_OAUTH_TOKEN_SIZE (1024)

struct _encoded_oauth_token {
	char token[MAX_ENCODED_OAUTH_TOKEN_SIZE];
	size_t size;
};

typedef struct _encoded_oauth_token encoded_oauth_token;

////////////////////////////////////////////////

#endif //__LIB_TURN_MSG_DEFS__
