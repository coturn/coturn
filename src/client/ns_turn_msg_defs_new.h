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

#ifndef __LIB_TURN_MSG_DEFS_NEW__
#define __LIB_TURN_MSG_DEFS_NEW__

/***** POST-RFC5766 FRESH SPECS ***********/

/* Origin ==>> */
#define STUN_MAX_ORIGIN_SIZE (127)
#define STUN_ATTRIBUTE_ORIGIN (0x802F)
/* <<== Origin */

/* Bandwidth */

#define STUN_ATTRIBUTE_NEW_BANDWIDTH (0x8000 + STUN_ATTRIBUTE_BANDWIDTH)

/* <<== Bandwidth */

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
	ENC_ALG_DEFAULT=0,
	AES_256_CBC=ENC_ALG_DEFAULT,
	AES_128_CBC,
	AEAD_AES_128_GCM,
	AEAD_AES_256_GCM,
	ENG_ALG_NUM
};

typedef enum _ENC_ALG ENC_ALG;

/* <<== OAUTH TOKEN ENC ALG */

/* OAUTH TOKEN AUTH ALG ==> */

enum _AUTH_ALG {
	AUTH_ALG_ERROR = -1,
	AUTH_ALG_UNDEFINED = 0,
	AUTH_ALG_DEFAULT = 1,
	AUTH_ALG_HMAC_SHA_256_128 = AUTH_ALG_DEFAULT,
	AUTH_ALG_HMAC_SHA_1,
	AUTH_ALG_HMAC_SHA_256,
	AUTH_ALG_HMAC_SHA_384,
	AUTH_ALG_HMAC_SHA_512
};

typedef enum _AUTH_ALG AUTH_ALG;

/* <<== OAUTH TOKEN AUTH ALG */

/**
 * oAuth struct
 */

#define STUN_ATTRIBUTE_THIRD_PARTY_AUTHORIZATION (0x8031)
#define STUN_ATTRIBUTE_OAUTH_ACCESS_TOKEN (0x0031)

#define OAUTH_KID_SIZE (128)
#define OAUTH_HASH_FUNC_SIZE (64)
#define OAUTH_ALG_SIZE (64)
#define OAUTH_KEY_SIZE (256)
#define OAUTH_AEAD_NONCE_SIZE (12)
#define OAUTH_AEAD_TAG_SIZE (16)
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
	char hkdf_hash_func[OAUTH_HASH_FUNC_SIZE+1];
	char as_rs_alg[OAUTH_ALG_SIZE+1];
	char as_rs_key[OAUTH_KEY_SIZE+1];
	size_t as_rs_key_size;
	char auth_alg[OAUTH_ALG_SIZE+1];
	char auth_key[OAUTH_KEY_SIZE+1];
	size_t auth_key_size;
};

typedef struct _oauth_key_data oauth_key_data;

struct _oauth_key {
	char kid[OAUTH_KID_SIZE+1];
	char ikm_key[OAUTH_KEY_SIZE+1];
	size_t ikm_key_size;
	turn_time_t timestamp;
	turn_time_t lifetime;
	SHATYPE hkdf_hash_func;
	ENC_ALG as_rs_alg;
	char as_rs_key[OAUTH_KEY_SIZE+1];
	size_t as_rs_key_size;
	AUTH_ALG auth_alg;
	char auth_key[OAUTH_KEY_SIZE+1];
	size_t auth_key_size;
};

typedef struct _oauth_key oauth_key;

struct _oauth_encrypted_block {
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

////////////// SSODA ///////////////////

#define STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY (0x8032)
#define STUN_ATTRIBUTE_ADDRESS_ERROR_CODE (0x8033)

#endif //__LIB_TURN_MSG_DEFS_NEW__
