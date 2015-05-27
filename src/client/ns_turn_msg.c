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

#include "ns_turn_msg.h"
#include "ns_turn_msg_addr.h"

///////////// Security functions implementation from ns_turn_msg.h ///////////

#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

///////////

#include <stdlib.h>

///////////

static void generate_random_nonce(unsigned char *nonce, size_t sz);

///////////

int stun_method_str(u16bits method, char *smethod)
{
	int ret = 0;

	const char* s = "UNKNOWN";

	switch(method) {
	case STUN_METHOD_BINDING:
		s = "BINDING";
		break;
	case STUN_METHOD_ALLOCATE:
		s = "ALLOCATE";
		break;
	case STUN_METHOD_REFRESH:
		s = "REFRESH";
		break;
	case STUN_METHOD_SEND:
		s = "SEND";
		break;
	case STUN_METHOD_DATA:
		s = "DATA";
		break;
	case STUN_METHOD_CREATE_PERMISSION:
		s = "CREATE_PERMISSION";
		break;
	case STUN_METHOD_CHANNEL_BIND:
		s = "CHANNEL_BIND";
		break;
	case STUN_METHOD_CONNECT:
		s = "CONNECT";
		break;
	case STUN_METHOD_CONNECTION_BIND:
		s = "CONNECTION_BIND";
		break;
	case STUN_METHOD_CONNECTION_ATTEMPT:
		s = "CONNECTION_ATTEMPT";
		break;
	default:
		ret = -1;
	};

	if(smethod) {
		ns_bcopy(s,smethod,strlen(s)+1);
	}

	return ret;
}

long turn_random(void)
{
	long ret = 0;
	if(!RAND_bytes((unsigned char *)&ret,sizeof(ret)))
		ret = random();
	return ret;
}

static void turn_random_tid_size(void *id)
{
	u32bits *ar=(u32bits*)id;
	if(!RAND_pseudo_bytes((unsigned char *)ar,12)) {
		size_t i;
		for(i=0;i<3;++i) {
			ar[i] = (u32bits)random();
		}
	}
}

int stun_calculate_hmac(const u08bits *buf, size_t len, const u08bits *key, size_t keylen, u08bits *hmac, unsigned int *hmac_len, SHATYPE shatype)
{
	ERR_clear_error();
	UNUSED_ARG(shatype);

	if(shatype == SHATYPE_SHA256) {
#if !defined(OPENSSL_NO_SHA256) && defined(SHA256_DIGEST_LENGTH)
	  if (!HMAC(EVP_sha256(), key, keylen, buf, len, hmac, hmac_len)) {
	    return -1;
	  }
#else
	  fprintf(stderr,"SHA256 is not supported\n");
	  return -1;
#endif
	} else if(shatype == SHATYPE_SHA384) {
#if !defined(OPENSSL_NO_SHA384) && defined(SHA384_DIGEST_LENGTH)
	  if (!HMAC(EVP_sha384(), key, keylen, buf, len, hmac, hmac_len)) {
	    return -1;
	  }
#else
	  fprintf(stderr,"SHA384 is not supported\n");
	  return -1;
#endif
	} else if(shatype == SHATYPE_SHA512) {
#if !defined(OPENSSL_NO_SHA512) && defined(SHA512_DIGEST_LENGTH)
	  if (!HMAC(EVP_sha512(), key, keylen, buf, len, hmac, hmac_len)) {
	    return -1;
	  }
#else
	  fprintf(stderr,"SHA512 is not supported\n");
	  return -1;
#endif
	} else
	  if (!HMAC(EVP_sha1(), key, keylen, buf, len, hmac, hmac_len)) {
	    return -1;
	  }

	return 0;
}

int stun_produce_integrity_key_str(u08bits *uname, u08bits *realm, u08bits *upwd, hmackey_t key, SHATYPE shatype)
{
	ERR_clear_error();
	UNUSED_ARG(shatype);

	size_t ulen = strlen((s08bits*)uname);
	size_t rlen = strlen((s08bits*)realm);
	size_t plen = strlen((s08bits*)upwd);
	size_t sz = ulen+1+rlen+1+plen+1+10;
	size_t strl = ulen+1+rlen+1+plen;
	u08bits *str = (u08bits*)turn_malloc(sz+1);

	strncpy((s08bits*)str,(s08bits*)uname,sz);
	str[ulen]=':';
	strncpy((s08bits*)str+ulen+1,(s08bits*)realm,sz-ulen-1);
	str[ulen+1+rlen]=':';
	strncpy((s08bits*)str+ulen+1+rlen+1,(s08bits*)upwd,sz-ulen-1-rlen-1);
	str[strl]=0;

	if(shatype == SHATYPE_SHA256) {
#if !defined(OPENSSL_NO_SHA256) && defined(SHA256_DIGEST_LENGTH)
		unsigned int keylen = 0;
		EVP_MD_CTX ctx;
		EVP_DigestInit(&ctx,EVP_sha256());
		EVP_DigestUpdate(&ctx,str,strl);
		EVP_DigestFinal(&ctx,key,&keylen);
		EVP_MD_CTX_cleanup(&ctx);
#else
		fprintf(stderr,"SHA256 is not supported\n");
		return -1;
#endif
	} else if(shatype == SHATYPE_SHA384) {
#if !defined(OPENSSL_NO_SHA384) && defined(SHA384_DIGEST_LENGTH)
		unsigned int keylen = 0;
		EVP_MD_CTX ctx;
		EVP_DigestInit(&ctx,EVP_sha384());
		EVP_DigestUpdate(&ctx,str,strl);
		EVP_DigestFinal(&ctx,key,&keylen);
		EVP_MD_CTX_cleanup(&ctx);
#else
		fprintf(stderr,"SHA384 is not supported\n");
		return -1;
#endif
	} else if(shatype == SHATYPE_SHA512) {
#if !defined(OPENSSL_NO_SHA512) && defined(SHA512_DIGEST_LENGTH)
		unsigned int keylen = 0;
		EVP_MD_CTX ctx;
		EVP_DigestInit(&ctx,EVP_sha512());
		EVP_DigestUpdate(&ctx,str,strl);
		EVP_DigestFinal(&ctx,key,&keylen);
		EVP_MD_CTX_cleanup(&ctx);
#else
		fprintf(stderr,"SHA512 is not supported\n");
		return -1;
#endif
	} else {
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx,str,strl);
		MD5_Final(key,&ctx);
	}

	turn_free(str,sz+1);

	return 0;
}

#define PWD_SALT_SIZE (8)

static void readable_string(unsigned char *orig, unsigned char *out, size_t sz)
{
    size_t i = 0;
    out[0]=0;

    for(i = 0; i < sz; ++i) {
      snprintf((char*)(out + (i * 2)), 4, "%02x", (unsigned int)orig[i]);
    }
}

static void generate_enc_password(const char* pwd, char *result, const unsigned char *orig_salt)
{
	unsigned char salt[PWD_SALT_SIZE+1];
	if(!orig_salt) {
		generate_random_nonce(salt, PWD_SALT_SIZE);
	} else {
		ns_bcopy(orig_salt,salt,PWD_SALT_SIZE);
		salt[PWD_SALT_SIZE]=0;
	}
	unsigned char rsalt[PWD_SALT_SIZE*2+1];
	readable_string(salt,rsalt,PWD_SALT_SIZE);
	result[0]='$';
	result[1]='5';
	result[2]='$';
	ns_bcopy((char*)rsalt,result+3,PWD_SALT_SIZE+PWD_SALT_SIZE);
	result[3+PWD_SALT_SIZE+PWD_SALT_SIZE]='$';
	unsigned char* out = (unsigned char*)(result+3+PWD_SALT_SIZE+PWD_SALT_SIZE+1);
	{
		EVP_MD_CTX ctx;
#if !defined(OPENSSL_NO_SHA256) && defined(SHA256_DIGEST_LENGTH)
		EVP_DigestInit(&ctx,EVP_sha256());
#else
		EVP_DigestInit(&ctx,EVP_sha1());
#endif
		EVP_DigestUpdate(&ctx,salt,PWD_SALT_SIZE);
		EVP_DigestUpdate(&ctx,pwd,strlen(pwd));
		{
			unsigned char hash[129];
			unsigned int keylen = 0;
			EVP_DigestFinal(&ctx,hash,&keylen);
			readable_string(hash,out,keylen);
		}
		EVP_MD_CTX_cleanup(&ctx);
	}
}

void generate_new_enc_password(const char* pwd, char *result)
{
	generate_enc_password(pwd, result, NULL);
}

static int encrypted_password(const char* pin, unsigned char* salt)
{
	size_t min_len = 3+PWD_SALT_SIZE+PWD_SALT_SIZE+1+32;
	if(strlen(pin)>=min_len) {
		if((pin[0]=='$') && (pin[1]=='5') && (pin[2]=='$') && (pin[3+PWD_SALT_SIZE+PWD_SALT_SIZE]=='$')) {
			size_t i = 0;
			for(i=0;i<PWD_SALT_SIZE;++i) {
				const char* c = pin+3+i+i;
				char sc[3];
				sc[0]=c[0];
				sc[1]=c[1];
				sc[2]=0;
				salt[i] = (unsigned char)strtoul(sc,NULL,16);
			}
			return 1;
		}
	}
	return 0;
}

int check_password(const char* pin, const char* pwd)
{
	unsigned char salt[PWD_SALT_SIZE];
	if(!encrypted_password(pwd,salt)) {
		return strcmp(pin,pwd);
	}
	char enc_pin[257];
	generate_enc_password(pin, enc_pin, salt);
	return strcmp(enc_pin,pwd);
}

/////////////////////////////////////////////////////////////////

static u32bits ns_crc32(const u08bits *buffer, u32bits len);

void print_hmac(const char *name, const void *s, size_t len);

/////////////////////////////////////////////////////////////////

int stun_get_command_message_len_str(const u08bits* buf, size_t len)
{
	if (len < STUN_HEADER_LENGTH)
		return -1;
	return (int) (nswap16(((const u16bits*)(buf))[1]) + STUN_HEADER_LENGTH);
}

static int stun_set_command_message_len_str(u08bits* buf, int len) {
  if(len<STUN_HEADER_LENGTH) return -1;
  ((u16bits*)buf)[1]=nswap16((u16bits)(len-STUN_HEADER_LENGTH));
  return 0;
}

///////////  Low-level binary //////////////////////////////////////////////

u16bits stun_make_type(u16bits method) {
  method = method & 0x0FFF;
  return ((method & 0x000F) | ((method & 0x0070)<<1) | 
	  ((method & 0x0380)<<2) | ((method & 0x0C00)<<2));
}

u16bits stun_get_method_str(const u08bits *buf, size_t len) {
  if(!buf || len<2) return (u16bits)-1;

  u16bits tt = nswap16(((const u16bits*)buf)[0]);
  
  return (tt & 0x000F) | ((tt & 0x00E0)>>1) | 
    ((tt & 0x0E00)>>2) | ((tt & 0x3000)>>2);
}

u16bits stun_get_msg_type_str(const u08bits *buf, size_t len) {
  if(!buf || len<2) return (u16bits)-1;
  return ((nswap16(((const u16bits*)buf)[0])) & 0x3FFF);
}

int is_channel_msg_str(const u08bits* buf, size_t blen) {
  return (buf && blen>=4 && STUN_VALID_CHANNEL(nswap16(((const u16bits*)buf)[0])));
}

/////////////// message types /////////////////////////////////

int stun_is_command_message_str(const u08bits* buf, size_t blen)
{
	if (buf && blen >= STUN_HEADER_LENGTH) {
		if (!STUN_VALID_CHANNEL(nswap16(((const u16bits*)buf)[0]))) {
			if ((((u08bits) buf[0]) & ((u08bits) (0xC0))) == 0) {
				if (nswap32(((const u32bits*)(buf))[1])
						== STUN_MAGIC_COOKIE) {
					u16bits len = nswap16(((const u16bits*)(buf))[1]);
					if ((len & 0x0003) == 0) {
						if ((size_t) (len + STUN_HEADER_LENGTH) == blen) {
							return 1;
						}
					}
				}
			}
		}
	}
	return 0;
}

int old_stun_is_command_message_str(const u08bits* buf, size_t blen, u32bits *cookie)
{
	if (buf && blen >= STUN_HEADER_LENGTH) {
		if (!STUN_VALID_CHANNEL(nswap16(((const u16bits*)buf)[0]))) {
			if ((((u08bits) buf[0]) & ((u08bits) (0xC0))) == 0) {
				if (nswap32(((const u32bits*)(buf))[1])
						!= STUN_MAGIC_COOKIE) {
					u16bits len = nswap16(((const u16bits*)(buf))[1]);
					if ((len & 0x0003) == 0) {
						if ((size_t) (len + STUN_HEADER_LENGTH) == blen) {
							*cookie = nswap32(((const u32bits*)(buf))[1]);
							return 1;
						}
					}
				}
			}
		}
	}
	return 0;
}

int stun_is_command_message_full_check_str(const u08bits* buf, size_t blen, int must_check_fingerprint, int *fingerprint_present) {
	if(!stun_is_command_message_str(buf,blen))
		return 0;
	stun_attr_ref sar = stun_attr_get_first_by_type_str(buf, blen, STUN_ATTRIBUTE_FINGERPRINT);
	if(!sar) {
		if(fingerprint_present)
			*fingerprint_present = 0;
		if(stun_get_method_str(buf,blen) == STUN_METHOD_BINDING) {
			return 1;
		}
		return !must_check_fingerprint;
	}
	if(stun_attr_get_len(sar) != 4)
		return 0;
	const u32bits* fingerprint = (const u32bits*)stun_attr_get_value(sar);
	if(!fingerprint)
		return !must_check_fingerprint;
	u32bits crc32len = (u32bits)((((const u08bits*)fingerprint)-buf)-4);
	int ret = (*fingerprint == nswap32(ns_crc32(buf,crc32len) ^ ((u32bits)0x5354554e)));
	if(ret && fingerprint_present)
		*fingerprint_present = ret;
	return ret;
}

int stun_is_command_message_offset_str(const u08bits* buf, size_t blen, int offset) {
  return stun_is_command_message_str(buf + offset, blen);
}

int stun_is_request_str(const u08bits* buf, size_t len) {
  if(is_channel_msg_str(buf,len)) return 0;
  return IS_STUN_REQUEST(stun_get_msg_type_str(buf,len));
}

int stun_is_success_response_str(const u08bits* buf, size_t len) {
  if(is_channel_msg_str(buf,len)) return 0;
  return IS_STUN_SUCCESS_RESP(stun_get_msg_type_str(buf,len));
}

int stun_is_error_response_str(const u08bits* buf, size_t len, int *err_code, u08bits *err_msg, size_t err_msg_size) {
  if(is_channel_msg_str(buf,len)) return 0;
  if(IS_STUN_ERR_RESP(stun_get_msg_type_str(buf,len))) {
    if(err_code) {
      stun_attr_ref sar = stun_attr_get_first_by_type_str(buf, len, STUN_ATTRIBUTE_ERROR_CODE);
      if(sar) {
    	  if(stun_attr_get_len(sar)>=4) {
    		  const u08bits* val = (const u08bits*)stun_attr_get_value(sar);
    		  *err_code=(int)(val[2]*100 + val[3]);
    		  if(err_msg && err_msg_size>0) {
    			  err_msg[0]=0;
    			  if(stun_attr_get_len(sar)>4) {
    				  size_t msg_len = stun_attr_get_len(sar) - 4;
    				  if(msg_len>(err_msg_size-1))
    					  msg_len=err_msg_size - 1;
    				  ns_bcopy(val+4, err_msg, msg_len);
    				  err_msg[msg_len]=0;
    			  }
    		  }
    	  }
      }
    }
    return 1;
  }
  return 0;
}

int stun_is_challenge_response_str(const u08bits* buf, size_t len, int *err_code, u08bits *err_msg, size_t err_msg_size,
				u08bits *realm, u08bits *nonce, u08bits *server_name, int *oauth)
{
	int ret = stun_is_error_response_str(buf, len, err_code, err_msg, err_msg_size);

	if(ret && (((*err_code) == 401) || ((*err_code) == 438) )) {

		stun_attr_ref sar = stun_attr_get_first_by_type_str(buf,len,STUN_ATTRIBUTE_REALM);
		if(sar) {

			int found_oauth = 0;

			const u08bits *value = stun_attr_get_value(sar);
			if(value) {
				size_t vlen = (size_t)stun_attr_get_len(sar);
				ns_bcopy(value,realm,vlen);
				realm[vlen]=0;

				{
					stun_attr_ref sar = stun_attr_get_first_by_type_str(buf,len,STUN_ATTRIBUTE_THIRD_PARTY_AUTHORIZATION);
					if(sar) {
						const u08bits *value = stun_attr_get_value(sar);
						if(value) {
							size_t vlen = (size_t)stun_attr_get_len(sar);
							if(vlen>0) {
								if(server_name) {
									ns_bcopy(value,server_name,vlen);
								}
								found_oauth = 1;
							}
						}
					}
				}

				sar = stun_attr_get_first_by_type_str(buf,len,STUN_ATTRIBUTE_NONCE);
				if(sar) {
					value = stun_attr_get_value(sar);
					if(value) {
						vlen = (size_t)stun_attr_get_len(sar);
						ns_bcopy(value,nonce,vlen);
						nonce[vlen]=0;
						if(oauth) {
							*oauth = found_oauth;
						}
						return 1;
					}
				}
			}
		}
	}

	return 0;
}

int stun_is_response_str(const u08bits* buf, size_t len) {
  if(is_channel_msg_str(buf,len)) return 0;
  if(IS_STUN_SUCCESS_RESP(stun_get_msg_type_str(buf,len))) return 1;
  if(IS_STUN_ERR_RESP(stun_get_msg_type_str(buf,len))) return 1;
  return 0;
}

int stun_is_indication_str(const u08bits* buf, size_t len) {
  if(is_channel_msg_str(buf,len)) return 0;
  return IS_STUN_INDICATION(stun_get_msg_type_str(buf,len));
}

u16bits stun_make_request(u16bits method) {
  return GET_STUN_REQUEST(stun_make_type(method));
}

u16bits stun_make_indication(u16bits method) {
  return GET_STUN_INDICATION(stun_make_type(method));
}

u16bits stun_make_success_response(u16bits method) {
  return GET_STUN_SUCCESS_RESP(stun_make_type(method));
}

u16bits stun_make_error_response(u16bits method) {
  return GET_STUN_ERR_RESP(stun_make_type(method));
}

//////////////// INIT ////////////////////////////////////////////

void stun_init_buffer_str(u08bits *buf, size_t *len) {
  *len=STUN_HEADER_LENGTH;
  ns_bzero(buf,*len);
}

void stun_init_command_str(u16bits message_type, u08bits* buf, size_t *len) {
  stun_init_buffer_str(buf,len);
  message_type &= (u16bits)(0x3FFF);
  ((u16bits*)buf)[0]=nswap16(message_type);
  ((u16bits*)buf)[1]=0;
  ((u32bits*)buf)[1]=nswap32(STUN_MAGIC_COOKIE);
  stun_tid_generate_in_message_str(buf,NULL);
}

void old_stun_init_command_str(u16bits message_type, u08bits* buf, size_t *len, u32bits cookie) {
  stun_init_buffer_str(buf,len);
  message_type &= (u16bits)(0x3FFF);
  ((u16bits*)buf)[0]=nswap16(message_type);
  ((u16bits*)buf)[1]=0;
  ((u32bits*)buf)[1]=nswap32(cookie);
  stun_tid_generate_in_message_str(buf,NULL);
}

void stun_init_request_str(u16bits method, u08bits* buf, size_t *len) {
  stun_init_command_str(stun_make_request(method), buf, len);
}

void stun_init_indication_str(u16bits method, u08bits* buf, size_t *len) {
  stun_init_command_str(stun_make_indication(method), buf, len);
}

void stun_init_success_response_str(u16bits method, u08bits* buf, size_t *len, stun_tid* id) {
  stun_init_command_str(stun_make_success_response(method), buf, len);
  if(id) {
    stun_tid_message_cpy(buf, id);
  }
}

void old_stun_init_success_response_str(u16bits method, u08bits* buf, size_t *len, stun_tid* id, u32bits cookie) {
  old_stun_init_command_str(stun_make_success_response(method), buf, len, cookie);
  if(id) {
    stun_tid_message_cpy(buf, id);
  }
}

const u08bits* get_default_reason(int error_code)
{
	const u08bits* reason = (const u08bits *) "Unknown error";

	switch (error_code){
	case 300:
		reason = (const u08bits *) "Try Alternate";
		break;
	case 400:
		reason = (const u08bits *) "Bad Request";
		break;
	case 401:
		reason = (const u08bits *) "Unauthorized";
		break;
	case 403:
		reason = (const u08bits *) "Forbidden";
		break;
	case 404:
		reason = (const u08bits *) "Not Found";
		break;
	case 420:
		reason = (const u08bits *) "Unknown Attribute";
		break;
	case 437:
		reason = (const u08bits *) "Allocation Mismatch";
		break;
	case 438:
		reason = (const u08bits *) "Stale Nonce";
		break;
	case 440:
		reason = (const u08bits *) "Address Family not Supported";
		break;
	case 441:
		reason = (const u08bits *) "Wrong Credentials";
		break;
	case 442:
		reason = (const u08bits *) "Unsupported Transport Protocol";
		break;
	case 443:
		reason = (const u08bits *) "Peer Address Family Mismatch";
		break;
	case 446:
		reason = (const u08bits *) "Connection Already Exists";
		break;
	case 447:
		reason = (const u08bits *) "Connection Timeout or Failure";
		break;
	case 486:
		reason = (const u08bits *) "Allocation Quota Reached";
		break;
	case 487:
		reason = (const u08bits *) "Role Conflict";
		break;
	case 500:
		reason = (const u08bits *) "Server Error";
		break;
	case 508:
		reason = (const u08bits *) "Insufficient Capacity";
		break;
	default:
		;
	};

	return reason;
}

static void stun_init_error_response_common_str(u08bits* buf, size_t *len,
				u16bits error_code, const u08bits *reason,
				stun_tid* id)
{

	if (!reason || !strcmp((const char*)reason,"Unknown error")) {
		reason = get_default_reason(error_code);
	}

	u08bits avalue[513];
	avalue[0] = 0;
	avalue[1] = 0;
	avalue[2] = (u08bits) (error_code / 100);
	avalue[3] = (u08bits) (error_code % 100);
	strncpy((s08bits*) (avalue + 4), (const s08bits*) reason, sizeof(avalue)-4);
	avalue[sizeof(avalue)-1]=0;
	int alen = 4 + strlen((const s08bits*) (avalue+4));

	//"Manual" padding for compatibility with classic old stun:
	{
		int rem = alen % 4;
		if(rem) {
			alen +=(4-rem);
		}
	}

	stun_attr_add_str(buf, len, STUN_ATTRIBUTE_ERROR_CODE, (u08bits*) avalue, alen);
	if (id) {
		stun_tid_message_cpy(buf, id);
	}
}

void old_stun_init_error_response_str(u16bits method, u08bits* buf, size_t *len,
				u16bits error_code, const u08bits *reason,
				stun_tid* id, u32bits cookie)
{

	old_stun_init_command_str(stun_make_error_response(method), buf, len, cookie);

	stun_init_error_response_common_str(buf, len,
					error_code, reason,
					id);
}

void stun_init_error_response_str(u16bits method, u08bits* buf, size_t *len,
				u16bits error_code, const u08bits *reason,
				stun_tid* id)
{

	stun_init_command_str(stun_make_error_response(method), buf, len);

	stun_init_error_response_common_str(buf, len,
					error_code, reason,
					id);
}

/////////// CHANNEL ////////////////////////////////////////////////

int stun_init_channel_message_str(u16bits chnumber, u08bits* buf, size_t *len, int length, int do_padding)
{
	u16bits rlen = (u16bits)length;

	if(length<0 || (MAX_STUN_MESSAGE_SIZE<(4+length))) return -1;
	((u16bits*)(buf))[0]=nswap16(chnumber);
	((u16bits*)(buf))[1]=nswap16((u16bits)length);

	if(do_padding && (rlen & 0x0003))
		rlen = ((rlen>>2)+1)<<2;

	*len=4+rlen;

	return 0;
}

int stun_is_channel_message_str(const u08bits *buf, size_t *blen, u16bits* chnumber, int mandatory_padding)
{
	u16bits datalen_header;
	u16bits datalen_actual;

	if (!blen || (*blen < 4))
		return 0;

	u16bits chn = nswap16(((const u16bits*)(buf))[0]);
	if (!STUN_VALID_CHANNEL(chn))
		return 0;

	if(*blen>(u16bits)-1)
		*blen=(u16bits)-1;

	datalen_actual = (u16bits)(*blen) - 4;
	datalen_header = ((const u16bits*)buf)[1];
	datalen_header = nswap16(datalen_header);

	if (datalen_header > datalen_actual)
		return 0;

	if (datalen_header != datalen_actual) {

		/* maybe there are padding bytes for 32-bit alignment. Mandatory for TCP. Optional for UDP */

		if(datalen_actual & 0x0003) {

			if(mandatory_padding) {
				return 0;
			} else if ((datalen_actual < datalen_header) || (datalen_header == 0)) {
				return 0;
			} else {
				u16bits diff = datalen_actual - datalen_header;
				if (diff > 3)
					return 0;
			}
		}
	}

	*blen = datalen_header + 4;

	if (chnumber)
		*chnumber = chn;

	return 1;
}

////////// STUN message ///////////////////////////////

static inline int sheadof(const char *head, const char* full, int ignore_case)
{
	while(*head) {
		if(*head != *full) {
		  if(ignore_case && (tolower((int)*head)==tolower((int)*full))) {
				//OK
			} else {
				return 0;
			}
		}
		++head;++full;
	}
	return 1;
}

static inline const char* findstr(const char *hay, size_t slen, const char *needle, int ignore_case)
{
	const char *ret = NULL;

	if(hay && slen && needle) {
		size_t nlen=strlen(needle);
		if(nlen<=slen) {
			size_t smax = slen-nlen+1;
			size_t i;
			const char *sp = hay;
			for(i=0;i<smax;++i) {
				if(sheadof(needle,sp+i,ignore_case)) {
					ret = sp+i;
					break;
				}
			}
		}
	}

	return ret;
}

static inline int is_http_inline(const char *s, size_t blen) {
	if(s && blen>=12) {
		if((strstr(s,"GET ")==s) ||(strstr(s,"POST ")==s) || (strstr(s,"DELETE ")==s) || (strstr(s,"PUT ")==s)) {
			const char *sp=findstr(s+4,blen-4," HTTP/",0);
			if(sp) {
				sp += 6;
				size_t diff_blen = sp-s;
				if(diff_blen+4 <= blen) {
					sp=findstr(sp,blen-diff_blen,"\r\n\r\n",0);
					if(sp) {
						int ret_len = (int)(sp-s+4);
						const char* clheader = "content-length: ";
						const char* cl = findstr(s,sp-s,clheader,1);
						if(cl) {
							unsigned long clen = strtoul(cl+strlen(clheader),NULL,10);
							if(clen>0 && clen<(0x0FFFFFFF)) {
								ret_len += (int)clen;
							}
						}
						return ret_len;
					}
				}
			}
		}
	}
	return 0;
}

int is_http(const char *s, size_t blen) {
	return is_http_inline(s, blen);
}

int stun_get_message_len_str(u08bits *buf, size_t blen, int padding, size_t *app_len) {
	if (buf && blen) {
		/* STUN request/response ? */
		if (buf && blen >= STUN_HEADER_LENGTH) {
			if (!STUN_VALID_CHANNEL(nswap16(((const u16bits*)buf)[0]))) {
				if ((((u08bits) buf[0]) & ((u08bits) (0xC0))) == 0) {
					if (nswap32(((const u32bits*)(buf))[1])
							== STUN_MAGIC_COOKIE) {
						u16bits len = nswap16(((const u16bits*)(buf))[1]);
						if ((len & 0x0003) == 0) {
							len += STUN_HEADER_LENGTH;
							if ((size_t) len <= blen) {
								*app_len = (size_t)len;
								return (int)len;
							}
						}
					}
				}
			}
		}

		//HTTP request ?
		{
			int http_len = is_http_inline(((char*)buf), blen);
			if((http_len>0) && ((size_t)http_len<=blen)) {
				*app_len = (size_t)http_len;
				return http_len;
			}
		}

		/* STUN channel ? */
		if(blen>=4) {
			u16bits chn=nswap16(((const u16bits*)(buf))[0]);
			if(STUN_VALID_CHANNEL(chn)) {

				u16bits bret = (4+(nswap16(((const u16bits*)(buf))[1])));

				*app_len = bret;

				if(padding && (bret & 0x0003)) {
					bret = ((bret>>2)+1)<<2;
				}

				if(bret<=blen) {
					return bret;
				}
			}
		}

	}

	return -1;
}

////////// ALLOCATE ///////////////////////////////////

int stun_set_allocate_request_str(u08bits* buf, size_t *len, u32bits lifetime, int af4, int af6,
				u08bits transport, int mobile, const char* rt, int ep) {

  stun_init_request_str(STUN_METHOD_ALLOCATE, buf, len);

  //REQUESTED-TRANSPORT
  {
    u08bits field[4];
    field[0]=transport;
    field[1]=0;
    field[2]=0;
    field[3]=0;
    if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_REQUESTED_TRANSPORT,field,sizeof(field))<0) return -1;
  }

  //LIFETIME
  {
    if(lifetime<1) lifetime=STUN_DEFAULT_ALLOCATE_LIFETIME;
    u32bits field=nswap32(lifetime);
    if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_LIFETIME,(u08bits*)(&field),sizeof(field))<0) return -1;
  }

  //MICE
  if(mobile) {
	  if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_MOBILITY_TICKET,(const u08bits*)"",0)<0) return -1;
  }

  if(ep>-1) {
	  uint8_t value = ep ? 0x80 : 0x00;
	  if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_EVEN_PORT,(const u08bits*)&value,1)<0) return -1;
  }

  //RESERVATION-TOKEN, EVEN-PORT and DUAL-ALLOCATION are mutually exclusive:
  if(rt) {

	  stun_attr_add_str(buf,len, STUN_ATTRIBUTE_RESERVATION_TOKEN, (const u08bits*) rt, 8);

  } else {

	  //ADRESS-FAMILY
	  if (af4 && !af6) {
		  u08bits field[4];
		  field[0] = (u08bits)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4;
		  field[1]=0;
		  field[2]=0;
		  field[3]=0;
		  if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY,field,sizeof(field))<0) return -1;
	  }

	  if (af6 && !af4) {
		  u08bits field[4];
		  field[0] = (u08bits)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
		  field[1]=0;
		  field[2]=0;
		  field[3]=0;
		  if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY,field,sizeof(field))<0) return -1;
	  }

	  if (af4 && af6) {
	  	u08bits field[4];
	  	field[0] = (u08bits)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
	  	field[1]=0;
	  	field[2]=0;
	  	field[3]=0;
	  	if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY,field,sizeof(field))<0) return -1;
	  }
  }

  return 0;
}

int stun_set_allocate_response_str(u08bits* buf, size_t *len, stun_tid* tid, 
				   const ioa_addr *relayed_addr1, const ioa_addr *relayed_addr2,
				   const ioa_addr *reflexive_addr,
				   u32bits lifetime, int error_code, const u08bits *reason,
				   u64bits reservation_token, char* mobile_id) {

  if(!error_code) {

    stun_init_success_response_str(STUN_METHOD_ALLOCATE, buf, len, tid);
    
    if(relayed_addr1) {
      if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,relayed_addr1)<0) return -1;
    }

    if(relayed_addr2) {
      if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,relayed_addr2)<0) return -1;
    }
    
    if(reflexive_addr) {
      if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,reflexive_addr)<0) return -1;
    }

    if(reservation_token) {
      reservation_token=nswap64(reservation_token);
      stun_attr_add_str(buf,len,STUN_ATTRIBUTE_RESERVATION_TOKEN,(u08bits*)(&reservation_token),8);
    }

    {
      if(lifetime<1) lifetime=STUN_DEFAULT_ALLOCATE_LIFETIME;
      else if(lifetime>STUN_MAX_ALLOCATE_LIFETIME) lifetime = STUN_MAX_ALLOCATE_LIFETIME;

      u32bits field=nswap32(lifetime);
      if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_LIFETIME,(u08bits*)(&field),sizeof(field))<0) return -1;
    }

    if(mobile_id && *mobile_id) {
	    if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_MOBILITY_TICKET,(u08bits*)mobile_id,strlen(mobile_id))<0) return -1;
    }

  } else {
    stun_init_error_response_str(STUN_METHOD_ALLOCATE, buf, len, error_code, reason, tid);
  }

  return 0;
}

/////////////// CHANNEL BIND ///////////////////////////////////////

u16bits stun_set_channel_bind_request_str(u08bits* buf, size_t *len,
					   const ioa_addr* peer_addr, u16bits channel_number) {

  if(!STUN_VALID_CHANNEL(channel_number)) {
    channel_number = 0x4000 + ((u16bits)(((u32bits)turn_random())%(0x7FFF-0x4000+1)));
  }
  
  stun_init_request_str(STUN_METHOD_CHANNEL_BIND, buf, len);
  
  if(stun_attr_add_channel_number_str(buf, len, channel_number)<0) return 0;
  
  if(!peer_addr) {
    ioa_addr ca;
    ns_bzero(&ca,sizeof(ioa_addr));
    
    if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &ca)<0) return 0;
  } else {
    if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_PEER_ADDRESS, peer_addr)<0) return 0;
  }

  return channel_number;
}

void stun_set_channel_bind_response_str(u08bits* buf, size_t *len, stun_tid* tid, int error_code, const u08bits *reason) {
  if(!error_code) {
    stun_init_success_response_str(STUN_METHOD_CHANNEL_BIND, buf, len, tid);
  } else {
    stun_init_error_response_str(STUN_METHOD_CHANNEL_BIND, buf, len, error_code, reason, tid);
  }
}

/////////////// BINDING ///////////////////////////////////////

void stun_set_binding_request_str(u08bits* buf, size_t *len) {
  stun_init_request_str(STUN_METHOD_BINDING, buf, len);
}

int stun_set_binding_response_str(u08bits* buf, size_t *len, stun_tid* tid, 
				  const ioa_addr *reflexive_addr, int error_code, const u08bits *reason,
				  u32bits cookie, int old_stun)

{
	if (!error_code) {
		if (!old_stun) {
			stun_init_success_response_str(STUN_METHOD_BINDING, buf, len, tid);
		} else {
			old_stun_init_success_response_str(STUN_METHOD_BINDING, buf, len, tid, cookie);
		}
		if(!old_stun && reflexive_addr) {
			if (stun_attr_add_addr_str(buf, len, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, reflexive_addr) < 0)
				return -1;
		}
		if(reflexive_addr) {
			if (stun_attr_add_addr_str(buf, len, STUN_ATTRIBUTE_MAPPED_ADDRESS, reflexive_addr) < 0)
				return -1;
		}
	} else if (!old_stun) {
		stun_init_error_response_str(STUN_METHOD_BINDING, buf, len, error_code, reason, tid);
	} else {
		old_stun_init_error_response_str(STUN_METHOD_BINDING, buf, len, error_code, reason, tid, cookie);
	}

	return 0;
}

int stun_is_binding_request_str(const u08bits* buf, size_t len, size_t offset)
{
  if(offset < len) {
    buf += offset;
    len -= offset;
    if (stun_is_command_message_str(buf, len)) {
      if (stun_is_request_str(buf, len) && (stun_get_method_str(buf, len) == STUN_METHOD_BINDING)) {
	return 1;
      }
    }
  }
  return 0;
}

int stun_is_binding_response_str(const u08bits* buf, size_t len) {
  if(stun_is_command_message_str(buf,len) &&
     (stun_get_method_str(buf,len)==STUN_METHOD_BINDING)) {
    if(stun_is_response_str(buf,len)) {
      return 1;
    }
  }
  return 0;
}

/////////////////////////////// TID ///////////////////////////////


int stun_tid_equals(const stun_tid *id1, const stun_tid *id2) {
  if(id1==id2) return 1;
  if(!id1) return 0;
  if(!id2) return 0;
  {
    unsigned int i=0;
    for(i=0;i<STUN_TID_SIZE;++i) {
      if(id1->tsx_id[i]!=id2->tsx_id[i]) return 0;
    }
  }
  return 1;
}

void stun_tid_cpy(stun_tid *id1, const stun_tid *id2) {
  if(!id1) return;
  if(!id2) return;
  ns_bcopy((const void*)(id2->tsx_id),(void*)(id1->tsx_id),STUN_TID_SIZE);
}

static void stun_tid_string_cpy(u08bits* s, const stun_tid* id) {
  if(s && id) {
    ns_bcopy((const void*)(id->tsx_id),s,STUN_TID_SIZE);
  }
}

static void stun_tid_from_string(const u08bits* s, stun_tid* id) {
  if(s && id) {
    ns_bcopy(s,(void*)(id->tsx_id),STUN_TID_SIZE);
  }
}

void stun_tid_from_message_str(const u08bits* buf, size_t len, stun_tid* id) {
	UNUSED_ARG(len);
	stun_tid_from_string(buf+8, id);
}

void stun_tid_message_cpy(u08bits* buf, const stun_tid* id) {
  if(buf && id) {
    stun_tid_string_cpy(buf+8, id);
  }
}

void stun_tid_generate(stun_tid* id) {
  if(id) {
    turn_random_tid_size(id->tsx_id);
  }
}

void stun_tid_generate_in_message_str(u08bits* buf, stun_tid* id) {
  stun_tid tmp;
  if(!id) id=&tmp;
  stun_tid_generate(id);
  stun_tid_message_cpy(buf, id);
}

/////////////////// TIME ////////////////////////////////////////////////////////

turn_time_t stun_adjust_allocate_lifetime(turn_time_t lifetime, turn_time_t max_lifetime) {

  if(!lifetime) lifetime = STUN_DEFAULT_ALLOCATE_LIFETIME;
  else if(lifetime<STUN_MIN_ALLOCATE_LIFETIME) lifetime = STUN_MIN_ALLOCATE_LIFETIME;
  else if(lifetime>STUN_MAX_ALLOCATE_LIFETIME) lifetime = STUN_MAX_ALLOCATE_LIFETIME;

  if(max_lifetime && (max_lifetime < lifetime)) {
  	lifetime = max_lifetime;
  }

  return lifetime;
}

////////////// ATTR /////////////////////////////////////////////////////////////

int stun_attr_get_type(stun_attr_ref attr) {
  if(attr)
    return (int)(nswap16(((const u16bits*)attr)[0]));
  return -1;
}

int stun_attr_get_len(stun_attr_ref attr) {
  if(attr)
    return (int)(nswap16(((const u16bits*)attr)[1]));
  return -1;
}

const u08bits* stun_attr_get_value(stun_attr_ref attr) {
  if(attr) {
    int len = (int)(nswap16(((const u16bits*)attr)[1]));
    if(len<1) return NULL;
    return ((const u08bits*)attr)+4;
  }
  return NULL;
}

int stun_get_requested_address_family(stun_attr_ref attr)
{
	if (attr) {
		int len = (int) (nswap16(((const u16bits*)attr)[1]));
		if (len != 4)
			return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_INVALID;
		int val = ((const u08bits*) attr)[4];
		switch (val){
		case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
			return val;
		case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
			return val;
		default:
			return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_INVALID;
		};
	}
	return STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
}

u16bits stun_attr_get_channel_number(stun_attr_ref attr) {
  if(attr) {
    const u08bits* value = stun_attr_get_value(attr);
    if(value && (stun_attr_get_len(attr) >= 2)) {
      u16bits cn=nswap16(((const u16bits*)value)[0]);
      if(STUN_VALID_CHANNEL(cn)) return cn;
    }
  }
  return 0;
}

band_limit_t stun_attr_get_bandwidth(stun_attr_ref attr) {
  if(attr) {
    const u08bits* value = stun_attr_get_value(attr);
    if(value && (stun_attr_get_len(attr) >= 4)) {
      u32bits bps=nswap32(((const u32bits*)value)[0]);
      return (band_limit_t)(bps << 7);
    }
  }
  return 0;
}

u64bits stun_attr_get_reservation_token_value(stun_attr_ref attr)  {
  if(attr) {
    const u08bits* value = stun_attr_get_value(attr);
    if(value && (stun_attr_get_len(attr) == 8)) {
      return nswap64(((const u64bits*)value)[0]);
    }
  }
  return 0;
}

int stun_attr_is_addr(stun_attr_ref attr) {

  if(attr) {
    switch(stun_attr_get_type(attr)) {
    case STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
    case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
    case STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS:
    case STUN_ATTRIBUTE_MAPPED_ADDRESS:
    case STUN_ATTRIBUTE_ALTERNATE_SERVER:
    case OLD_STUN_ATTRIBUTE_RESPONSE_ADDRESS:
    case OLD_STUN_ATTRIBUTE_SOURCE_ADDRESS:
    case OLD_STUN_ATTRIBUTE_CHANGED_ADDRESS:
    case OLD_STUN_ATTRIBUTE_REFLECTED_FROM:
    case STUN_ATTRIBUTE_RESPONSE_ORIGIN:
    case STUN_ATTRIBUTE_OTHER_ADDRESS:
      return 1;
      break;
    default:
      ;
    };
  }
  return 0;
}

u08bits stun_attr_get_even_port(stun_attr_ref attr) {
  if(attr) {
    const u08bits* value=stun_attr_get_value(attr);
    if(value) {
      if((u08bits)(value[0]) > 0x7F) return 1;
    }
  }
  return 0;
}

stun_attr_ref stun_attr_get_first_by_type_str(const u08bits* buf, size_t len, u16bits attr_type) {

  stun_attr_ref attr=stun_attr_get_first_str(buf,len);
  while(attr) {
    if(stun_attr_get_type(attr) == attr_type) {
      return attr;
    }
    attr=stun_attr_get_next_str(buf,len,attr);
  }

  return NULL;
}

stun_attr_ref stun_attr_get_first_str(const u08bits* buf, size_t len) {

  if(stun_get_command_message_len_str(buf,len)>STUN_HEADER_LENGTH) {
    return (stun_attr_ref)(buf+STUN_HEADER_LENGTH);
  }

  return NULL;
}

stun_attr_ref stun_attr_get_next_str(const u08bits* buf, size_t len, stun_attr_ref prev) {

  if(!prev) return stun_attr_get_first_str(buf,len);
  else {
    const u08bits* end = buf + stun_get_command_message_len_str(buf,len);
    int attrlen=stun_attr_get_len(prev);
    u16bits rem4 = ((u16bits)attrlen) & 0x0003;
    if(rem4) {
      attrlen = attrlen+4-(int)rem4;
    }
    const u08bits* attr_end=(const u08bits*)prev+4+attrlen;
    if(attr_end<end) return attr_end;
    return NULL;
  }
}

int stun_attr_add_str(u08bits* buf, size_t *len, u16bits attr, const u08bits* avalue, int alen) {
  if(alen<0) alen=0;
  u08bits tmp[1];
  if(!avalue) {
    alen=0;
    avalue=tmp;
  }
  int clen = stun_get_command_message_len_str(buf,*len);
  int newlen = clen + 4 + alen;
  int newlenrem4=newlen & 0x00000003;
  if(newlenrem4) {
    newlen=newlen+(4-newlenrem4);
  }
  if(newlen>=MAX_STUN_MESSAGE_SIZE) return -1;
  else {
    u08bits* attr_start=buf+clen;
    
    u16bits *attr_start_16t=(u16bits*)attr_start;
    
    stun_set_command_message_len_str(buf,newlen);
    *len = newlen;
    
    attr_start_16t[0]=nswap16(attr);
    attr_start_16t[1]=nswap16(alen);
    if(alen>0) ns_bcopy(avalue,attr_start+4,alen);
    return 0;
  }
}

int stun_attr_add_addr_str(u08bits *buf, size_t *len, u16bits attr_type, const ioa_addr* ca) {

  stun_tid tid;
  stun_tid_from_message_str(buf, *len, &tid);

  int xor_ed=0;
  switch(attr_type) {
  case STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
  case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
  case STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS:
    xor_ed=1;
    break;
  default:
    ;
  };

  ioa_addr public_addr;
  map_addr_from_private_to_public(ca,&public_addr);

  u08bits cfield[64];
  int clen=0;
  if(stun_addr_encode(&public_addr, cfield, &clen, xor_ed, STUN_MAGIC_COOKIE, tid.tsx_id)<0) {
    return -1;
  }

  if(stun_attr_add_str(buf,len,attr_type,(u08bits*)(&cfield),clen)<0) return -1;

  return 0;
}

int stun_attr_get_addr_str(const u08bits *buf, size_t len, stun_attr_ref attr, ioa_addr* ca, const ioa_addr *default_addr) {

  stun_tid tid;
  stun_tid_from_message_str(buf, len, &tid);
  ioa_addr public_addr;

  ns_bzero(ca,sizeof(ioa_addr));

  int attr_type = stun_attr_get_type(attr);
  if(attr_type<0) return -1;

  int xor_ed=0;
  switch(attr_type) {
  case STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
  case STUN_ATTRIBUTE_XOR_PEER_ADDRESS:
  case STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS:
    xor_ed=1;
    break;
  default:
    ;
  };

  const u08bits *cfield=stun_attr_get_value(attr);
  if(!cfield) return -1;

  if(stun_addr_decode(&public_addr, cfield, stun_attr_get_len(attr), xor_ed, STUN_MAGIC_COOKIE, tid.tsx_id)<0) {
    return -1;
  }

  map_addr_from_public_to_private(&public_addr, ca);

  if(default_addr && addr_any_no_port(ca) && !addr_any_no_port(default_addr)) {
    int port = addr_get_port(ca);
    addr_cpy(ca,default_addr);
    addr_set_port(ca,port);
  }

  return 0;
}

int stun_attr_get_first_addr_str(const u08bits *buf, size_t len, u16bits attr_type, ioa_addr* ca, const ioa_addr *default_addr) {

  stun_attr_ref attr=stun_attr_get_first_str(buf,len);

  while(attr) {
    if(stun_attr_is_addr(attr) && (attr_type == stun_attr_get_type(attr))) {
      if(stun_attr_get_addr_str(buf,len,attr,ca,default_addr)==0) {
    	  return 0;
      }
    }
    attr=stun_attr_get_next_str(buf,len,attr);
  }

  return -1;
}

int stun_attr_add_channel_number_str(u08bits* buf, size_t *len, u16bits chnumber) {

  u16bits field[2];
  field[0]=nswap16(chnumber);
  field[1]=0;
  
  return stun_attr_add_str(buf,len,STUN_ATTRIBUTE_CHANNEL_NUMBER,(u08bits*)(field),sizeof(field));
}

int stun_attr_add_bandwidth_str(u08bits* buf, size_t *len, band_limit_t bps0) {

	u32bits bps = (band_limit_t)(bps0 >> 7);

	u32bits field=nswap32(bps);

	return stun_attr_add_str(buf,len,STUN_ATTRIBUTE_NEW_BANDWIDTH,(u08bits*)(&field),sizeof(field));
}

int stun_attr_add_address_error_code(u08bits* buf, size_t *len, int requested_address_family, int error_code)
{
	const u08bits *reason = get_default_reason(error_code);

	u08bits avalue[513];
	avalue[0] = (u08bits)requested_address_family;
	avalue[1] = 0;
	avalue[2] = (u08bits) (error_code / 100);
	avalue[3] = (u08bits) (error_code % 100);
	strncpy((s08bits*) (avalue + 4), (const s08bits*) reason, sizeof(avalue)-4);
	avalue[sizeof(avalue)-1]=0;
	int alen = 4 + strlen((const s08bits*) (avalue+4));

	//"Manual" padding for compatibility with classic old stun:
	{
		int rem = alen % 4;
		if(rem) {
			alen +=(4-rem);
		}
	}

	stun_attr_add_str(buf, len, STUN_ATTRIBUTE_ADDRESS_ERROR_CODE, (u08bits*) avalue, alen);

	return 0;
}

int stun_attr_get_address_error_code(u08bits* buf, size_t len, int *requested_address_family, int *error_code)
{
	if(requested_address_family) {
		*requested_address_family = 0;
	}
	if(error_code) {
		*error_code = 0;
	}
	if(buf && len) {
		stun_attr_ref sar = stun_attr_get_first_by_type_str(buf, len, STUN_ATTRIBUTE_ADDRESS_ERROR_CODE);
		if(sar) {
			const u08bits* value = stun_attr_get_value(sar);
			if(!value) {
				return -1;
			} else {
				int alen = stun_attr_get_len(sar);
				if(alen != 4) {
					return -1;
				}
				if(requested_address_family) {
					*requested_address_family = value[0];
				}
				if(error_code) {
					*error_code = (int)(value[2]*100+value[3]);
				}
				return 0;
			}
		}
	}
	return 0;
}

u16bits stun_attr_get_first_channel_number_str(const u08bits *buf, size_t len) {

  stun_attr_ref attr=stun_attr_get_first_str(buf,len);
  while(attr) {
    if(stun_attr_get_type(attr) == STUN_ATTRIBUTE_CHANNEL_NUMBER) {
      u16bits ret = stun_attr_get_channel_number(attr);
      if(STUN_VALID_CHANNEL(ret)) {
    	  return ret;
      }
    }
    attr=stun_attr_get_next_str(buf,len,attr);
  }

  return 0;
}

////////////// FINGERPRINT ////////////////////////////

int stun_attr_add_fingerprint_str(u08bits *buf, size_t *len)
{
	u32bits crc32 = 0;
	stun_attr_add_str(buf, len, STUN_ATTRIBUTE_FINGERPRINT, (u08bits*)&crc32, 4);
	crc32 = ns_crc32(buf,*len-8);
	*((u32bits*)(buf+*len-4)) = nswap32(crc32 ^ ((u32bits)0x5354554e));
	return 0;
}
////////////// CRC ///////////////////////////////////////////////

#define CRC_MASK    0xFFFFFFFFUL

#define UPDATE_CRC(crc, c)  crc = crctable[(u08bits)crc ^ (u08bits)(c)] ^ (crc >> 8)

static const u32bits crctable[256] = {
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
  0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
  0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
  0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
  0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
  0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
  0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
  0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
  0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
  0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
  0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
  0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
  0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
  0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
  0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
  0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
  0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
  0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
  0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
  0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
  0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
  0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
  0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
  0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
  0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
  0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
  0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
  0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
  0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
  0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
  0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
  0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
  0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
  0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
  0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
  0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
  0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
  0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
  0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
  0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
  0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
  0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
  0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

/*

#define CRCPOLY     0xEDB88320UL
reversed 0x04C11DB7
1110 1101 1001 1000 1000 0011 0010 0000

static void make_crctable(void)
{
	uint i, j;
	u32bits r;

	for (i = 0; i < 256; ++i) {
		r = i;
		for (j = 8; j > 0; --j) {
			if (r & 1)
				r = (r >> 1) ^ CRCPOLY;
			else
				r >>= 1;
		}
		crctable[i] = r;
	}
}
*/

static u32bits ns_crc32(const u08bits *buffer, u32bits len)
{
	u32bits crc = CRC_MASK;
	while ( len-- ) UPDATE_CRC( crc, *buffer++ );
	return (~crc);
}

//////////// SASLprep RFC 4013 /////////////////////////////////////////

/* We support only basic ASCII table */

int SASLprep(u08bits *s)
{
	if(s) {
		u08bits *strin = s;
		u08bits *strout = s;
		for(;;) {
			u08bits c = *strin;
			if(!c) {
				*strout=0;
				break;
			}

			switch(c) {
			case 0xAD:
				++strin;
				break;
			case 0xA0:
			case 0x20:
				*strout=0x20;
				++strout;
				++strin;
				break;
			case 0x7F:
				return -1;
			default:
				if(c<0x1F)
					return -1;
				if(c>=0x80 && c<=0x9F)
					return -1;
				*strout=c;
				++strout;
				++strin;
			};
		}
	}

	return 0;
}

//////////////// Message Integrity ////////////////////////////

size_t get_hmackey_size(SHATYPE shatype)
{
	if(shatype == SHATYPE_SHA256)
		return 32;
	if(shatype == SHATYPE_SHA384)
		return 48;
	if(shatype == SHATYPE_SHA512)
		return 64;
	return 16;
}

void print_bin_func(const char *name, size_t len, const void *s, const char *func)
{
	printf("<%s>:<%s>:len=%d:[",func,name,(int)len);
	size_t i;
	for(i=0;i<len;i++) {
		printf("%02x",(int)((const u08bits*)s)[i]);
	}
	printf("]\n");
}

int stun_attr_add_integrity_str(turn_credential_type ct, u08bits *buf, size_t *len, hmackey_t key, password_t pwd, SHATYPE shatype)
{
	u08bits hmac[MAXSHASIZE];

	unsigned int shasize;

	switch(shatype) {
	case SHATYPE_SHA256:
		shasize = SHA256SIZEBYTES;
		break;
	case SHATYPE_SHA384:
		shasize = SHA384SIZEBYTES;
		break;
	case SHATYPE_SHA512:
		shasize = SHA512SIZEBYTES;
		break;
	default:
		shasize = SHA1SIZEBYTES;
	};

	if(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_MESSAGE_INTEGRITY, hmac, shasize)<0)
		return -1;

	if(ct == TURN_CREDENTIALS_SHORT_TERM) {
		if(stun_calculate_hmac(buf, *len-4-shasize, pwd, strlen((char*)pwd), buf+*len-shasize, &shasize, shatype)<0)
				return -1;
	} else {
		if(stun_calculate_hmac(buf, *len-4-shasize, key, get_hmackey_size(shatype), buf+*len-shasize, &shasize, shatype)<0)
			return -1;
	}

	return 0;
}

int stun_attr_add_integrity_by_key_str(u08bits *buf, size_t *len, u08bits *uname, u08bits *realm, hmackey_t key, u08bits *nonce, SHATYPE shatype)
{
	if(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_USERNAME, uname, strlen((s08bits*)uname))<0)
			return -1;

	if(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_NONCE, nonce, strlen((s08bits*)nonce))<0)
		return -1;

	if(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_REALM, realm, strlen((s08bits*)realm))<0)
			return -1;

	password_t p;
	return stun_attr_add_integrity_str(TURN_CREDENTIALS_LONG_TERM, buf, len, key, p, shatype);
}

int stun_attr_add_integrity_by_user_str(u08bits *buf, size_t *len, u08bits *uname, u08bits *realm, u08bits *upwd, u08bits *nonce, SHATYPE shatype)
{
	hmackey_t key;

	if(stun_produce_integrity_key_str(uname, realm, upwd, key, shatype)<0)
		return -1;

	return stun_attr_add_integrity_by_key_str(buf, len, uname, realm, key, nonce, shatype);
}

int stun_attr_add_integrity_by_user_short_term_str(u08bits *buf, size_t *len, u08bits *uname, password_t pwd, SHATYPE shatype)
{
	if(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_USERNAME, uname, strlen((s08bits*)uname))<0)
			return -1;

	hmackey_t key;
	return stun_attr_add_integrity_str(TURN_CREDENTIALS_SHORT_TERM, buf, len, key, pwd, shatype);
}

void print_hmac(const char *name, const void *s, size_t len)
{
	printf("%s:len=%d:[",name,(int)len);
	size_t i;
	for(i=0;i<len;i++) {
		printf("%02x",(int)((const u08bits*)s)[i]);
	}
	printf("]\n");
}

/*
 * Return -1 if failure, 0 if the integrity is not correct, 1 if OK
 */
int stun_check_message_integrity_by_key_str(turn_credential_type ct, u08bits *buf, size_t len, hmackey_t key, password_t pwd, SHATYPE shatype)
{
	int res = 0;
	u08bits new_hmac[MAXSHASIZE];
	unsigned int shasize;
	const u08bits *old_hmac = NULL;

	stun_attr_ref sar = stun_attr_get_first_by_type_str(buf, len, STUN_ATTRIBUTE_MESSAGE_INTEGRITY);
	if (!sar)
		return -1;

	int sarlen = stun_attr_get_len(sar);

	switch(sarlen) {
	case SHA256SIZEBYTES:
		shasize = SHA256SIZEBYTES;
		if(shatype != SHATYPE_SHA256)
			return -1;
		break;
	case SHA384SIZEBYTES:
		shasize = SHA384SIZEBYTES;
		if(shatype != SHATYPE_SHA384)
			return -1;
		break;
	case SHA512SIZEBYTES:
		shasize = SHA512SIZEBYTES;
		if(shatype != SHATYPE_SHA512)
			return -1;
		break;
	case SHA1SIZEBYTES:
		shasize = SHA1SIZEBYTES;
		if(shatype != SHATYPE_SHA1)
			return -1;
		break;
	default:
		return -1;
	};

	int orig_len = stun_get_command_message_len_str(buf, len);
	if (orig_len < 0)
		return -1;

	int new_len = ((const u08bits*) sar - buf) + 4 + shasize;
	if (new_len > orig_len)
		return -1;

	if (stun_set_command_message_len_str(buf, new_len) < 0)
		return -1;

	if(ct == TURN_CREDENTIALS_SHORT_TERM) {
		res = stun_calculate_hmac(buf, (size_t) new_len - 4 - shasize, pwd, strlen((char*)pwd), new_hmac, &shasize, shatype);
	} else {
		res = stun_calculate_hmac(buf, (size_t) new_len - 4 - shasize, key, get_hmackey_size(shatype), new_hmac, &shasize, shatype);
	}

	stun_set_command_message_len_str(buf, orig_len);
	if(res<0)
		return -1;

	old_hmac = stun_attr_get_value(sar);
	if(!old_hmac)
		return -1;

	if(bcmp(old_hmac,new_hmac,shasize))
		return 0;

	return +1;
}

/*
 * Return -1 if failure, 0 if the integrity is not correct, 1 if OK
 */
int stun_check_message_integrity_str(turn_credential_type ct, u08bits *buf, size_t len, u08bits *uname, u08bits *realm, u08bits *upwd, SHATYPE shatype)
{
	hmackey_t key;
	password_t pwd;

	if(ct == TURN_CREDENTIALS_SHORT_TERM)
		strncpy((char*)pwd,(char*)upwd,sizeof(password_t));
	else if (stun_produce_integrity_key_str(uname, realm, upwd, key, shatype) < 0)
		return -1;

	return stun_check_message_integrity_by_key_str(ct, buf, len, key, pwd, shatype);
}

/* RFC 5780 */

int stun_attr_get_change_request_str(stun_attr_ref attr, int *change_ip, int *change_port)
{
	if(stun_attr_get_len(attr) == 4) {
		const u08bits* value = stun_attr_get_value(attr);
		if(value) {
			*change_ip = (value[3] & (u08bits)0x04);
			*change_port = (value[3] & (u08bits)0x02);
			return 0;
		}
	}
	return -1;
}

int stun_attr_add_change_request_str(u08bits *buf, size_t *len, int change_ip, int change_port)
{
	u08bits avalue[4]={0,0,0,0};

	if(change_ip) {
		if(change_port) {
			avalue[3] = 0x06;
		} else {
			avalue[3] = 0x04;
		}
	} else if(change_port) {
		avalue[3]=0x02;
	}

	return stun_attr_add_str(buf, len, STUN_ATTRIBUTE_CHANGE_REQUEST, avalue, 4);
}

int stun_attr_get_response_port_str(stun_attr_ref attr)
{
	if(stun_attr_get_len(attr) >= 2) {
		const u08bits* value = stun_attr_get_value(attr);
		if(value) {
			return nswap16(((const u16bits*)value)[0]);
		}
	}
	return -1;
}

int stun_attr_add_response_port_str(u08bits *buf, size_t *len, u16bits port)
{
	u08bits avalue[4]={0,0,0,0};
	u16bits *port_ptr = (u16bits*)avalue;

	*port_ptr = nswap16(port);

	return stun_attr_add_str(buf, len, STUN_ATTRIBUTE_RESPONSE_PORT, avalue, 4);
}

int stun_attr_get_padding_len_str(stun_attr_ref attr) {
	int len = stun_attr_get_len(attr);
	if(len<0)
		return -1;
	return (u16bits)len;
}

int stun_attr_add_padding_str(u08bits *buf, size_t *len, u16bits padding_len)
{
	u08bits avalue[0xFFFF];
	ns_bzero(avalue,padding_len);

	return stun_attr_add_str(buf, len, STUN_ATTRIBUTE_PADDING, avalue, padding_len);
}

/* OAUTH */

#define OAUTH_ERROR(...) fprintf(stderr,__VA_ARGS__)

static void remove_spaces(char *s)
{
	char *sfns = s;
	while(*sfns) {
		if(*sfns != ' ')
			break;
		++sfns;
	}
	if(*sfns) {
		if(sfns != s) {
			while(*sfns && (*sfns != ' ')) {
				*s = *sfns;
				++s;
				++sfns;
			};
			*s = 0;
		} else {
			while(*s) {
				if(*s == ' ') {
					*s = 0;
					break;
				}
				++s;
			}
		}
	}
}

static void normalize_algorithm(char *s)
{
	char c = *s;
	while(c) {
		if(c=='_') *s='-';
		else if((c>='a')&&(c<='z')) {
			*s = c - 'a' + 'A';
		}
		++s;
		c = *s;
	}
}

size_t calculate_enc_key_length(ENC_ALG a);
size_t calculate_enc_key_length(ENC_ALG a)
{
	switch(a) {
#if !defined(TURN_NO_GCM)
	case A128GCM:
		return 16;
#endif
	default:
		break;
	};

	return 32;
}

size_t calculate_auth_key_length(ENC_ALG a);
size_t calculate_auth_key_length(ENC_ALG a)
{
	switch(a) {
#if !defined(TURN_NO_GCM)
	case A256GCM:
	case A128GCM:
		return 0;
#endif
	default:
		break;
	};

	return 0;
}

int calculate_key(char *key, size_t key_size,
		char *new_key, size_t new_key_size);
int calculate_key(char *key, size_t key_size,
		char *new_key, size_t new_key_size)
{
	UNUSED_ARG(key_size);

	ns_bcopy(key,new_key,new_key_size);

	return 0;
}

int convert_oauth_key_data(const oauth_key_data *oakd0, oauth_key *key, char *err_msg, size_t err_msg_size)
{
	if(oakd0 && key) {

		oauth_key_data oakd_obj;
		ns_bcopy(oakd0,&oakd_obj,sizeof(oauth_key_data));
		oauth_key_data *oakd = &oakd_obj;

		if(!(oakd->ikm_key_size)) {
			if(err_msg) {
				snprintf(err_msg,err_msg_size,"key is not defined");
			}
		}

		remove_spaces(oakd->kid);

		remove_spaces(oakd->as_rs_alg);

		normalize_algorithm(oakd->as_rs_alg);

		if(!(oakd->kid[0])) {
			if(err_msg) {
				snprintf(err_msg,err_msg_size,"KID is not defined");
			}
			OAUTH_ERROR("KID is not defined\n");
			return -1;
		}

		ns_bzero(key,sizeof(oauth_key));

		STRCPY(key->kid,oakd->kid);

		ns_bcopy(oakd->ikm_key,key->ikm_key,sizeof(key->ikm_key));
		key->ikm_key_size = oakd->ikm_key_size;

		key->timestamp = oakd->timestamp;
		key->lifetime = oakd->lifetime;

		if(!(key->timestamp)) key->timestamp = OAUTH_DEFAULT_TIMESTAMP;
		if(!(key->lifetime)) key->lifetime = OAUTH_DEFAULT_LIFETIME;

		key->as_rs_alg = ENC_ALG_ERROR;
#if !defined(TURN_NO_GCM)
		key->as_rs_alg = ENC_ALG_DEFAULT;
		if(!strcmp(oakd->as_rs_alg,"A128GCM")) {
			key->as_rs_alg = A128GCM;
			key->auth_key_size = 0;
			key->auth_key[0] = 0;
		} else if(!strcmp(oakd->as_rs_alg,"A256GCM")) {
			key->as_rs_alg = A256GCM;
			key->auth_key_size = 0;
			key->auth_key[0] = 0;
		} else 
#endif
		{
			if(err_msg) {
				snprintf(err_msg,err_msg_size,"Wrong oAuth token encryption algorithm: %s (2)\n",oakd->as_rs_alg);
			}
			OAUTH_ERROR("Wrong oAuth token encryption algorithm: %s (3)\n",oakd->as_rs_alg);
			return -1;
		}

#if !defined(TURN_NO_GCM)

		key->auth_key_size = calculate_auth_key_length(key->as_rs_alg);
		if(key->auth_key_size) {
			if(calculate_key(key->ikm_key,key->ikm_key_size,key->auth_key,key->auth_key_size)<0) {
				return -1;
			}
		}

		key->as_rs_key_size = calculate_enc_key_length(key->as_rs_alg);
		if(calculate_key(key->ikm_key,key->ikm_key_size,key->as_rs_key,key->as_rs_key_size)<0) {
			return -1;
		}
#endif
	}

	return 0;
}

const EVP_CIPHER *get_cipher_type(ENC_ALG enc_alg);
const EVP_CIPHER *get_cipher_type(ENC_ALG enc_alg)
{
	switch(enc_alg) {
#if !defined(TURN_NO_GCM)
	case A128GCM:
		return EVP_aes_128_gcm();
	case A256GCM:
		return EVP_aes_256_gcm();
#endif
	default:
		break;
	}
	OAUTH_ERROR("%s: Unsupported enc algorithm: %d\n",__FUNCTION__,(int)enc_alg);
	return NULL;
}

int my_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
			 int *outl, const unsigned char *in, int inl);
int my_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
		int *outl, const unsigned char *in, int inl)
{
	int cycle = 0;
	int out_len = 0;
	while((out_len<inl)&&(++cycle<128)) {
		int tmp_outl=0;
		unsigned char *ptr = NULL;
		if(out)
			ptr = out+out_len;
		int ret = EVP_EncryptUpdate(ctx, ptr, &tmp_outl, in+out_len, inl-out_len);
		out_len += tmp_outl;
		if(ret<1)
			return ret;
	}
	*outl = out_len;
	return 1;
}

int my_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
			 int *outl, const unsigned char *in, int inl);
int my_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
		int *outl, const unsigned char *in, int inl)
{
	int cycle = 0;
	int out_len = 0;
	while((out_len<inl)&&(++cycle<128)) {
		int tmp_outl=0;
		unsigned char *ptr = NULL;
		if(out)
			ptr = out+out_len;
		int ret = EVP_DecryptUpdate(ctx, ptr, &tmp_outl, in+out_len, inl-out_len);
		out_len += tmp_outl;
		if(ret<1)
			return ret;
	}
	*outl = out_len;
	return 1;
}

void print_field(const char* name, const unsigned char* f, size_t len);
void print_field(const char* name, const unsigned char* f, size_t len) {
	printf("\nfield %s==>>\n",name);
	size_t i;
	for(i = 0;i<len;++i) {
		printf("<0x%x>",(unsigned int)f[i]);
	}
	printf("\n<<==field %s\n",name);
}

int encode_oauth_token_normal(const u08bits *server_name, encoded_oauth_token *etoken, const oauth_key *key, const oauth_token *dtoken);
int encode_oauth_token_normal(const u08bits *server_name, encoded_oauth_token *etoken, const oauth_key *key, const oauth_token *dtoken)
{
	UNUSED_ARG(server_name);
	UNUSED_ARG(etoken);
	UNUSED_ARG(key);
	UNUSED_ARG(dtoken);

	/*
	if(server_name && etoken && key && dtoken && (dtoken->enc_block.key_length<=128)) {

		unsigned char orig_field[MAX_ENCODED_OAUTH_TOKEN_SIZE];
		ns_bzero(orig_field,sizeof(orig_field));

		size_t len = 0;
		*((uint16_t*)(orig_field+len)) = nswap16(dtoken->enc_block.key_length);
		len +=2;

		ns_bcopy(dtoken->enc_block.mac_key,orig_field+len,dtoken->enc_block.key_length);
		len += dtoken->enc_block.key_length;

		*((uint64_t*)(orig_field+len)) = nswap64(dtoken->enc_block.timestamp);
		len += 8;

		*((uint32_t*)(orig_field+len)) = nswap32(dtoken->enc_block.lifetime);
		len += 4;

		const EVP_CIPHER * cipher = get_cipher_type(key->as_rs_alg);
		if(!cipher)
			return -1;

		unsigned char *encoded_field = (unsigned char*)etoken->token;

		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		EVP_EncryptInit_ex(&ctx, cipher, NULL, (const unsigned char *)key->as_rs_key, NULL);
		EVP_CIPHER_CTX_set_padding(&ctx,1);
		int outl=0;
		my_EVP_EncryptUpdate(&ctx, encoded_field, &outl, orig_field, (int)len);
		if(outl % OAUTH_ENC_ALG_BLOCK_SIZE) {
			int tmp_outl = 0;
			EVP_EncryptFinal_ex(&ctx, encoded_field + outl, &tmp_outl);
			outl += tmp_outl;
		}

		EVP_CIPHER_CTX_cleanup(&ctx);

		size_t sn_len = strlen((const char*)server_name);
		ns_bcopy(server_name,encoded_field+outl,sn_len);
		outl += sn_len;

		const EVP_MD *md = get_auth_type(key->auth_alg);
		if(!md)
			return -1;

		unsigned int hmac_len = EVP_MD_size(md);
		if (!HMAC(md, key->auth_key, key->auth_key_size, encoded_field, outl, encoded_field + outl, &hmac_len)) {
		    return -1;
		}

		update_hmac_len(key->auth_alg, &hmac_len);

		ns_bcopy(encoded_field + outl, encoded_field + outl - sn_len, hmac_len);
		outl -= sn_len;
		outl += hmac_len; //encoded+hmac

		etoken->size = outl;

		return 0;
	}
	*/
	return -1;
}

int decode_oauth_token_normal(const u08bits *server_name, const encoded_oauth_token *etoken, const oauth_key *key, oauth_token *dtoken);
int decode_oauth_token_normal(const u08bits *server_name, const encoded_oauth_token *etoken, const oauth_key *key, oauth_token *dtoken)
{
	UNUSED_ARG(server_name);
	UNUSED_ARG(etoken);
	UNUSED_ARG(key);
	UNUSED_ARG(dtoken);

	/*
	if(server_name && etoken && key && dtoken) {

		size_t mac_size = calculate_auth_output_length(key->auth_alg);
		size_t min_encoded_field_size = 2+4+8+1;
		if(etoken->size < mac_size+min_encoded_field_size) {
			OAUTH_ERROR("%s: token size too small: %d, mac_size=%d, min_encoded_field_size=%d\n",__FUNCTION__,(int)etoken->size,(int)mac_size,(int)min_encoded_field_size);
			return -1;
		}

		const unsigned char* encoded_field = (const unsigned char*)etoken->token;
		unsigned int encoded_field_size = (unsigned int)etoken->size-mac_size;
		const unsigned char* mac = ((const unsigned char*)etoken->token) + etoken->size - mac_size;

		{
			const EVP_MD *md = get_auth_type(key->auth_alg);
			if(!md)
				return -1;
       		unsigned int hmac_len = EVP_MD_size(md);
       		update_hmac_len(key->auth_alg,&hmac_len);
       		if(hmac_len != mac_size) {
       			OAUTH_ERROR("%s: mac size is wrong: %d, must be %d\n",__FUNCTION__,(int)mac_size,(int)hmac_len);
       			return -1;
       		}
       		unsigned char efield[MAX_ENCODED_OAUTH_TOKEN_SIZE];
       		unsigned char check_mac[MAXSHASIZE];
       		ns_bcopy(encoded_field,efield,encoded_field_size);
       		size_t sn_len = strlen((const char*)server_name);
       		ns_bcopy(server_name,efield+encoded_field_size,sn_len);
		    if (!HMAC(md, key->auth_key, key->auth_key_size, efield, encoded_field_size+sn_len, check_mac, &hmac_len)) {
		    	return -1;
		    }

		    if(ns_bcmp(check_mac,mac,mac_size)) {
		    	OAUTH_ERROR("%s: token integrity check failed\n",__FUNCTION__);
		    	return -1;
		    }
		}

		unsigned char decoded_field[MAX_ENCODED_OAUTH_TOKEN_SIZE];

		const EVP_CIPHER * cipher = get_cipher_type(key->as_rs_alg);
		if(!cipher)
			return -1;

		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		EVP_DecryptInit_ex(&ctx, cipher, NULL, (const unsigned char *)key->as_rs_key, NULL);
		EVP_CIPHER_CTX_set_padding(&ctx,1);
		int outl=0;
		my_EVP_DecryptUpdate(&ctx, decoded_field, &outl, encoded_field, (int)encoded_field_size);

		int tmp_outl = 0;
		EVP_DecryptFinal_ex(&ctx, decoded_field + outl, &tmp_outl);
		outl += tmp_outl;

		EVP_CIPHER_CTX_cleanup(&ctx);

		size_t len = 0;

		dtoken->enc_block.key_length = nswap16(*((uint16_t*)(decoded_field+len)));
		len += 2;

		ns_bcopy(decoded_field+len,dtoken->enc_block.mac_key,dtoken->enc_block.key_length);
		len += dtoken->enc_block.key_length;

		dtoken->enc_block.timestamp = nswap64(*((uint64_t*)(decoded_field+len)));
		len += 8;

		dtoken->enc_block.lifetime = nswap32(*((uint32_t*)(decoded_field+len)));
		len += 4;

		return 0;
	}
	*/
	return -1;
}

static void generate_random_nonce(unsigned char *nonce, size_t sz) {
	if(!RAND_bytes(nonce, sz)) {
		size_t i;
		for(i=0;i<sz;++i) {
			nonce[i] = (unsigned char)random();
		}
	}
}

#if !defined(TURN_NO_GCM)

static int encode_oauth_token_gcm(const u08bits *server_name, encoded_oauth_token *etoken, const oauth_key *key, const oauth_token *dtoken, const u08bits* nonce0) {
	if(server_name && etoken && key && dtoken && (dtoken->enc_block.key_length<=MAXSHASIZE)) {

		unsigned char orig_field[MAX_ENCODED_OAUTH_TOKEN_SIZE];
		ns_bzero(orig_field,sizeof(orig_field));

		unsigned char nonce[OAUTH_GCM_NONCE_SIZE];
		if(nonce0) {
			ns_bcopy(nonce0,nonce,sizeof(nonce));
		} else {
			generate_random_nonce(nonce, sizeof(nonce));
		}

		size_t len = 0;

		*((uint16_t*)(orig_field+len)) = nswap16(OAUTH_GCM_NONCE_SIZE);
		len +=2;

		ns_bcopy(nonce,orig_field+len,OAUTH_GCM_NONCE_SIZE);
		len += OAUTH_GCM_NONCE_SIZE;

		*((uint16_t*)(orig_field+len)) = nswap16(dtoken->enc_block.key_length);
		len +=2;

		ns_bcopy(dtoken->enc_block.mac_key,orig_field+len,dtoken->enc_block.key_length);
		len += dtoken->enc_block.key_length;

		*((uint64_t*)(orig_field+len)) = nswap64(dtoken->enc_block.timestamp);
		len += 8;

		*((uint32_t*)(orig_field+len)) = nswap32(dtoken->enc_block.lifetime);
		len += 4;

		const EVP_CIPHER * cipher = get_cipher_type(key->as_rs_alg);
		if(!cipher)
			return -1;

		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);

		/* Initialize the encryption operation. */
		if(1 != EVP_EncryptInit_ex(&ctx, cipher, NULL, NULL, NULL))
			return -1;

		EVP_CIPHER_CTX_set_padding(&ctx,1);

		/* Set IV length if default 12 bytes (96 bits) is not appropriate */
		if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, OAUTH_GCM_NONCE_SIZE, NULL))
			return -1;

		/* Initialize key and IV */
		if(1 != EVP_EncryptInit_ex(&ctx, NULL, NULL, (const unsigned char *)key->as_rs_key, nonce))
			return -1;

		int outl=0;
		size_t sn_len = strlen((const char*)server_name);

		/* Provide any AAD data. This can be called zero or more times as
		 * required
		 */
		if(1 != my_EVP_EncryptUpdate(&ctx, NULL, &outl, server_name, (int)sn_len))
			return -1;

		outl=0;
		unsigned char *encoded_field = (unsigned char*)etoken->token;
		ns_bcopy(orig_field,encoded_field,OAUTH_GCM_NONCE_SIZE + 2);
		encoded_field += OAUTH_GCM_NONCE_SIZE + 2;
		unsigned char *start_field = orig_field + OAUTH_GCM_NONCE_SIZE + 2;
		len -= OAUTH_GCM_NONCE_SIZE + 2;

		if(1 != my_EVP_EncryptUpdate(&ctx, encoded_field, &outl, start_field, (int)len))
			return -1;

		int tmp_outl = 0;
		EVP_EncryptFinal_ex(&ctx, encoded_field + outl, &tmp_outl);
		outl += tmp_outl;

		EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, OAUTH_GCM_TAG_SIZE, encoded_field + outl);
		outl += OAUTH_GCM_TAG_SIZE;

		etoken->size = 2 + OAUTH_GCM_NONCE_SIZE + outl;

		EVP_CIPHER_CTX_cleanup(&ctx);

		return 0;
	}
	return -1;
}

static int decode_oauth_token_gcm(const u08bits *server_name, const encoded_oauth_token *etoken, const oauth_key *key, oauth_token *dtoken)
{
	if(server_name && etoken && key && dtoken) {

		unsigned char snl[2];
		ns_bcopy((const unsigned char*)(etoken->token),snl,2);
		const unsigned char *csnl = snl;

		uint16_t nonce_len = nswap16(*((const uint16_t*)csnl));

		size_t min_encoded_field_size = 2+4+8+nonce_len+2+OAUTH_GCM_TAG_SIZE+1;
		if(etoken->size < min_encoded_field_size) {
			OAUTH_ERROR("%s: token size too small: %d\n",__FUNCTION__,(int)etoken->size);
			return -1;
		}

		const unsigned char* encoded_field = (const unsigned char*)(etoken->token + nonce_len + 2);
		unsigned int encoded_field_size = (unsigned int)etoken->size - nonce_len - 2 - OAUTH_GCM_TAG_SIZE;
		const unsigned char* nonce = ((const unsigned char*)etoken->token + 2);

		unsigned char tag[OAUTH_GCM_TAG_SIZE];
		ns_bcopy(((const unsigned char*)etoken->token) + nonce_len + 2 + encoded_field_size, tag ,sizeof(tag));

		unsigned char decoded_field[MAX_ENCODED_OAUTH_TOKEN_SIZE];

		const EVP_CIPHER * cipher = get_cipher_type(key->as_rs_alg);
		if(!cipher) {
			OAUTH_ERROR("%s: Cannot find cipher for algorithm: %d\n",__FUNCTION__,(int)key->as_rs_alg);
			return -1;
		}

		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		/* Initialize the decryption operation. */
		if(1 != EVP_DecryptInit_ex(&ctx, cipher, NULL, NULL, NULL)) {
			OAUTH_ERROR("%s: Cannot initialize decryption\n",__FUNCTION__);
			return -1;
		}

		//EVP_CIPHER_CTX_set_padding(&ctx,1);

		/* Set IV length if default 12 bytes (96 bits) is not appropriate */
		if(1 != EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL)) {
			OAUTH_ERROR("%s: Cannot set nonce length\n",__FUNCTION__);
			return -1;
		}

		/* Initialize key and IV */
		if(1 != EVP_DecryptInit_ex(&ctx, NULL, NULL, (const unsigned char *)key->as_rs_key, nonce)) {
			OAUTH_ERROR("%s: Cannot set nonce\n",__FUNCTION__);
			return -1;
		}

		/* Set expected tag value. A restriction in OpenSSL 1.0.1c and earlier
		  +         * required the tag before any AAD or ciphertext */
		EVP_CIPHER_CTX_ctrl (&ctx, EVP_CTRL_GCM_SET_TAG, OAUTH_GCM_TAG_SIZE, tag);

		int outl=0;
		size_t sn_len = strlen((const char*)server_name);

		/* Provide any AAD data. This can be called zero or more times as
		 * required
		 */
		if(1 != my_EVP_DecryptUpdate(&ctx, NULL, &outl, server_name, (int)sn_len)) {
			OAUTH_ERROR("%s: Cannot decrypt update server_name: %s, len=%d\n",__FUNCTION__,server_name,(int)sn_len);
			return -1;
		}
		if(1 != my_EVP_DecryptUpdate(&ctx, decoded_field, &outl, encoded_field, (int)encoded_field_size)) {
			OAUTH_ERROR("%s: Cannot decrypt update\n",__FUNCTION__);
			return -1;
		}

		int tmp_outl = 0;
		if(EVP_DecryptFinal_ex(&ctx, decoded_field + outl, &tmp_outl)<1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			OAUTH_ERROR("%s: token integrity check failed\n",__FUNCTION__);
			return -1;
		}
		outl += tmp_outl;

		EVP_CIPHER_CTX_cleanup(&ctx);

		size_t len = 0;

		dtoken->enc_block.key_length = nswap16(*((uint16_t*)(decoded_field+len)));
		len += 2;

		ns_bcopy(decoded_field+len,dtoken->enc_block.mac_key,dtoken->enc_block.key_length);
		len += dtoken->enc_block.key_length;

		dtoken->enc_block.timestamp = nswap64(*((uint64_t*)(decoded_field+len)));
		len += 8;

		dtoken->enc_block.lifetime = nswap32(*((uint32_t*)(decoded_field+len)));
		len += 4;

		return 0;
	}
	return -1;
}

#endif

int encode_oauth_token(const u08bits *server_name, encoded_oauth_token *etoken, const oauth_key *key, const oauth_token *dtoken, const u08bits *nonce)
{
	UNUSED_ARG(nonce);
	if(server_name && etoken && key && dtoken) {
		switch(key->as_rs_alg) {
#if !defined(TURN_NO_GCM)
		case A256GCM:
		case A128GCM:
			return encode_oauth_token_gcm(server_name, etoken,key,dtoken,nonce);
#endif
		default:
			fprintf(stderr,"Unsupported AS_RS algorithm: %d\n",(int)key->as_rs_alg);
			break;
		};
	}
	return -1;
}

int decode_oauth_token(const u08bits *server_name, const encoded_oauth_token *etoken, const oauth_key *key, oauth_token *dtoken)
{
	if(server_name && etoken && key && dtoken) {
		switch(key->as_rs_alg) {
#if !defined(TURN_NO_GCM)
		case A256GCM:
		case A128GCM:
			return decode_oauth_token_gcm(server_name, etoken,key,dtoken);
#endif
		default:
			fprintf(stderr,"Unsupported AS_RS algorithm: %d\n",(int)key->as_rs_alg);
			break;
		};
	}
	return -1;
}

///////////////////////////////////////////////////////////////
