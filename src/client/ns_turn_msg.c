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

#include <stdlib.h>

///////////

long turn_random(void)
{
	long ret = 0;
	if(!RAND_bytes((unsigned char *)&ret,sizeof(ret)))
		ret = random();
	return ret;
}

void turn_random32_size(u32bits *ar, size_t sz)
{
	if(!RAND_bytes((unsigned char *)ar, sz<<2)<0) {
		size_t i;
		for(i=0;i<sz;++i) {
			ar[i] = (u32bits)random();
		}
	}
}

int stun_calculate_hmac(const u08bits *buf, size_t len, const u08bits *key, size_t keylen, u08bits *hmac, unsigned int *hmac_len, SHATYPE shatype)
{
	ERR_clear_error();
	UNUSED_ARG(shatype);

#if !defined(OPENSSL_NO_SHA256) && defined(SSL_TXT_SHA256)
	if(shatype == SHATYPE_SHA256) {
	  if (!HMAC(EVP_sha256(), key, keylen, buf, len, hmac, hmac_len)) {
	    return -1;
	  }
	} else
#endif

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
	u08bits *str = (u08bits*)malloc(sz+1);

	strncpy((s08bits*)str,(s08bits*)uname,sz);
	str[ulen]=':';
	strncpy((s08bits*)str+ulen+1,(s08bits*)realm,sz-ulen-1);
	str[ulen+1+rlen]=':';
	strncpy((s08bits*)str+ulen+1+rlen+1,(s08bits*)upwd,sz-ulen-1-rlen-1);
	str[strl]=0;

#if !defined(OPENSSL_NO_SHA256) && defined(SSL_TXT_SHA256)
	if(shatype == SHATYPE_SHA256) {
		unsigned int keylen = 0;
		EVP_MD_CTX ctx;
		EVP_DigestInit(&ctx,EVP_sha256());
		EVP_DigestUpdate(&ctx,str,strl);
		EVP_DigestFinal(&ctx,key,&keylen);
	} else
#endif
	{
		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx,str,strl);
		MD5_Final(key,&ctx);
	}

	free(str);

	return 0;
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
				u08bits *realm, u08bits *nonce)
{
	int ret = stun_is_error_response_str(buf, len, err_code, err_msg, err_msg_size);

	if(ret && (((*err_code) == 401) || ((*err_code) == 438) || ((*err_code) == SHA_TOO_WEAK))) {

		stun_attr_ref sar = stun_attr_get_first_by_type_str(buf,len,STUN_ATTRIBUTE_REALM);
		if(sar) {
			const u08bits *value = stun_attr_get_value(sar);
			if(value) {
				size_t vlen = (size_t)stun_attr_get_len(sar);
				ns_bcopy(value,realm,vlen);
				realm[vlen]=0;
				sar = stun_attr_get_first_by_type_str(buf,len,STUN_ATTRIBUTE_NONCE);
				if(sar) {
					value = stun_attr_get_value(sar);
					if(value) {
						vlen = (size_t)stun_attr_get_len(sar);
						ns_bcopy(value,nonce,vlen);
						nonce[vlen]=0;
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

static void stun_init_error_response_common_str(u08bits* buf, size_t *len,
				u16bits error_code, const u08bits *reason,
				stun_tid* id)
{

	if (!reason) {

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
		case 404:
			reason = (const u08bits *) "Not Found";
			break;
		case 420:
			reason = (const u08bits *) "Unknown Attribute";
			break;
		case 438:
			reason = (const u08bits *) "Stale Nonce";
			break;
		case 500:
			reason = (const u08bits *) "Server Error";
			break;
		default:
			reason = (const u08bits *) "Unknown Error";
			break;
		};
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

static inline int sheadof(const char *head, const char* full)
{
	while(*head) {
		if(*head != *full)
			return 0;
		++head;++full;
	}
	return 1;
}

static inline const char* findstr(const char *hay, size_t slen, const char *needle)
{
	const char *ret = NULL;

	if(hay && slen && needle) {
		size_t nlen=strlen(needle);
		if(nlen<=slen) {
			size_t smax = slen-nlen+1;
			size_t i;
			const char *sp = hay;
			for(i=0;i<smax;++i) {
				if(sheadof(needle,sp+i)) {
					ret = sp+i;
					break;
				}
			}
		}
	}

	return ret;
}

static inline int is_http_get_inline(const char *s, size_t blen) {
	if(s && blen>=12) {
		if((s[0]=='G')&&(s[1]=='E')&&(s[2]=='T')&&(s[3]==' ')) {
			const char *sp=findstr(s+4,blen-4,"HTTP");
			if(sp) {
				sp += 4;
				size_t diff_blen = sp-s;
				if(diff_blen+4 <= blen) {
					sp=findstr(sp,blen-diff_blen,"\r\n\r\n");
					if(sp) {
						return (int)(sp-s+4);
					}
				}
			}

		}
	}
	return 0;
}

int is_http_get(const char *s, size_t blen) {
	return is_http_get_inline(s, blen);
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
			int http_len = is_http_get_inline(((char*)buf), blen);
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

int stun_set_allocate_request_str(u08bits* buf, size_t *len, u32bits lifetime, int address_family,
				u08bits transport, int mobile) {

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

  if(mobile) {
	  if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_MOBILITY_TICKET,(const u08bits*)"",0)<0) return -1;
  }

  //ADRESS-FAMILY
  switch (address_family) {
  case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4:
  case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6:
  {
	  u08bits field[4];
	  field[0] = (u08bits)address_family;
	  field[1]=0;
	  field[2]=0;
	  field[3]=0;
	  if(stun_attr_add_str(buf,len,STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY,field,sizeof(field))<0) return -1;
	  break;
  }
  case STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT:
	  /* ignore */
	  break;
  default:
	  return -1;
  };

  return 0;
}

int stun_set_allocate_response_str(u08bits* buf, size_t *len, stun_tid* tid, 
				   const ioa_addr *relayed_addr, const ioa_addr *reflexive_addr,
				   u32bits lifetime, int error_code, const u08bits *reason,
				   u64bits reservation_token, char* mobile_id) {

  if(!error_code) {

    stun_init_success_response_str(STUN_METHOD_ALLOCATE, buf, len, tid);
    
    if(relayed_addr) {
      if(stun_attr_add_addr_str(buf,len,STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,relayed_addr)<0) return -1;
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
		if(!old_stun) {
			if (stun_attr_add_addr_str(buf, len, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, reflexive_addr) < 0)
				return -1;
		}
		if (stun_attr_add_addr_str(buf, len, STUN_ATTRIBUTE_MAPPED_ADDRESS, reflexive_addr) < 0)
			return -1;
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
    u32bits *w=(u32bits*)(id->tsx_id);
    turn_random32_size(w,3);
  }
}

void stun_tid_generate_in_message_str(u08bits* buf, stun_tid* id) {
  stun_tid tmp;
  if(!id) id=&tmp;
  stun_tid_generate(id);
  stun_tid_message_cpy(buf, id);
}

/////////////////// TIME ////////////////////////////////////////////////////////

u32bits stun_adjust_allocate_lifetime(u32bits lifetime) {
  if(!lifetime) return STUN_DEFAULT_ALLOCATE_LIFETIME;
  else if(lifetime<STUN_MIN_ALLOCATE_LIFETIME) return STUN_MIN_ALLOCATE_LIFETIME;
  else if(lifetime>STUN_MAX_ALLOCATE_LIFETIME) return STUN_MAX_ALLOCATE_LIFETIME;
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

int stun_attr_add_integrity_str(turn_credential_type ct, u08bits *buf, size_t *len, hmackey_t key, st_password_t pwd, SHATYPE shatype)
{
	u08bits hmac[MAXSHASIZE];

	unsigned int shasize;

	switch(shatype) {
	case SHATYPE_SHA256:
		shasize = SHA256SIZEBYTES;
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

int stun_attr_add_integrity_by_user_str(u08bits *buf, size_t *len, u08bits *uname, u08bits *realm, u08bits *upwd, u08bits *nonce, SHATYPE shatype)
{
	hmackey_t key;

	if(stun_produce_integrity_key_str(uname, realm, upwd, key, shatype)<0)
		return -1;

	if(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_USERNAME, uname, strlen((s08bits*)uname))<0)
			return -1;

	if(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_NONCE, nonce, strlen((s08bits*)nonce))<0)
		return -1;

	if(stun_attr_add_str(buf, len, STUN_ATTRIBUTE_REALM, realm, strlen((s08bits*)realm))<0)
			return -1;

	st_password_t p;
	return stun_attr_add_integrity_str(TURN_CREDENTIALS_LONG_TERM, buf, len, key, p, shatype);
}

int stun_attr_add_integrity_by_user_short_term_str(u08bits *buf, size_t *len, u08bits *uname, st_password_t pwd, SHATYPE shatype)
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
int stun_check_message_integrity_by_key_str(turn_credential_type ct, u08bits *buf, size_t len, hmackey_t key, st_password_t pwd, SHATYPE shatype, int *too_weak)
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
	case SHA1SIZEBYTES:
		shasize = SHA1SIZEBYTES;
		if(shatype != SHATYPE_SHA1) {
			if(too_weak)
				*too_weak = 1;
			return -1;
		}
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

	return 1;
}

/*
 * Return -1 if failure, 0 if the integrity is not correct, 1 if OK
 */
int stun_check_message_integrity_str(turn_credential_type ct, u08bits *buf, size_t len, u08bits *uname, u08bits *realm, u08bits *upwd, SHATYPE shatype)
{
	hmackey_t key;
	st_password_t pwd;

	if(ct == TURN_CREDENTIALS_SHORT_TERM)
		strncpy((char*)pwd,(char*)upwd,sizeof(st_password_t));
	else if (stun_produce_integrity_key_str(uname, realm, upwd, key, shatype) < 0)
		return -1;

	return stun_check_message_integrity_by_key_str(ct, buf, len, key, pwd, shatype, NULL);
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

///////////////////////////////////////////////////////////////
