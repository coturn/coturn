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

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ns_turn_utils.h"
#include "apputils.h"
#include "stun_buffer.h"

//////////// OAUTH //////////////////

static const char* encs[]={
#if !defined(TURN_NO_GCM)
		"A128GCM", "A256GCM",
#endif
		NULL};

static int print_extra = 0;

void print_field5769(const char* name, const void* f0, size_t len);
void print_field5769(const char* name, const void* f0, size_t len) {
  const unsigned char* f = (const unsigned char*)f0;
  printf("\nfield %s %lu==>>\n",name,(unsigned long)len);
  size_t i;
  for(i = 0;i<len;++i) {
    printf("\\x%02x",(unsigned int)f[i]);
  }
  printf("\n<<==field %s\n",name);
}

static int check_oauth(void) {

	const char server_name[33] = "blackdow.carleon.gov";

	size_t i_encs;

	const char long_term_key[33] = "HGkj32KJGiuy098sdfaqbNjOiaz71923";

	size_t ltp_output_length=0;

	const char* base64encoded_ltp = base64_encode((const unsigned char *)long_term_key,
						      strlen(long_term_key),
						      &ltp_output_length);

	const char mac_key[33] = "ZksjpweoixXmvn67534m";
	const size_t mac_key_length=strlen(mac_key);
	const uint64_t token_timestamp = (uint64_t)(92470300704768LL);
	const uint32_t token_lifetime = 3600;

	const char kid[33] = "2783466234";
	const turn_time_t key_timestamp = 1234567890;
	const turn_time_t key_lifetime = 3600;

	const char gcm_nonce[OAUTH_GCM_NONCE_SIZE+1] = "h4j3k2l2n4b5";

	{
		{

			for (i_encs = 0; encs[i_encs]; ++i_encs) {

				printf("oauth token %s:",encs[i_encs]);

				if(print_extra)
					printf("\n");

				oauth_token ot;
				ns_bzero(&ot,sizeof(ot));
				ot.enc_block.key_length = (uint16_t)mac_key_length;
				STRCPY(ot.enc_block.mac_key,mac_key);
				ot.enc_block.timestamp = token_timestamp;
				ot.enc_block.lifetime = token_lifetime;

				oauth_token dot;
				ns_bzero((&dot),sizeof(dot));
				oauth_key key;
				ns_bzero(&key,sizeof(key));

				{
					oauth_key_data okd;
					ns_bzero(&okd,sizeof(okd));

					{
					  oauth_key_data_raw okdr;
					  ns_bzero(&okdr,sizeof(okdr));

						STRCPY(okdr.kid,kid);
						STRCPY(okdr.ikm_key,base64encoded_ltp);
						STRCPY(okdr.as_rs_alg, encs[i_encs]);
						okdr.timestamp = key_timestamp;
						okdr.lifetime = key_lifetime;

						convert_oauth_key_data_raw(&okdr, &okd);

						char err_msg[1025] = "\0";
						size_t err_msg_size = sizeof(err_msg) - 1;

						if (convert_oauth_key_data(&okd, &key, err_msg,
								err_msg_size) < 0) {
							fprintf(stderr, "%s\n", err_msg);
							return -1;
						}
					}
				}

				if(print_extra) {
					print_field5769("AS-RS",key.as_rs_key,key.as_rs_key_size);
					print_field5769("AUTH",key.auth_key,key.auth_key_size);
				}

				{
					encoded_oauth_token etoken;
					ns_bzero(&etoken,sizeof(etoken));

					if (encode_oauth_token((const u08bits *) server_name, &etoken,
							&key, &ot, (const u08bits*)gcm_nonce) < 0) {
						fprintf(stderr, "%s: cannot encode oauth token\n",
								__FUNCTION__);
						return -1;
					}

					if(print_extra) {
						print_field5769("encoded token",etoken.token,etoken.size);
					}

					if (decode_oauth_token((const u08bits *) server_name, &etoken,
							&key, &dot) < 0) {
						fprintf(stderr, "%s: cannot decode oauth token\n",
								__FUNCTION__);
						return -1;
					}
				}

				if (strcmp((char*) ot.enc_block.mac_key,
						(char*) dot.enc_block.mac_key)) {
					fprintf(stderr, "%s: wrong mac key: %s, must be %s\n",
							__FUNCTION__, (char*) dot.enc_block.mac_key,
							(char*) ot.enc_block.mac_key);
					return -1;
				}

				if (ot.enc_block.key_length != dot.enc_block.key_length) {
					fprintf(stderr, "%s: wrong key length: %d, must be %d\n",
							__FUNCTION__, (int) dot.enc_block.key_length,
							(int) ot.enc_block.key_length);
					return -1;
				}
				if (ot.enc_block.timestamp != dot.enc_block.timestamp) {
					fprintf(stderr, "%s: wrong timestamp: %llu, must be %llu\n",
							__FUNCTION__,
							(unsigned long long) dot.enc_block.timestamp,
							(unsigned long long) ot.enc_block.timestamp);
					return -1;
				}
				if (ot.enc_block.lifetime != dot.enc_block.lifetime) {
					fprintf(stderr, "%s: wrong lifetime: %lu, must be %lu\n",
							__FUNCTION__,
							(unsigned long) dot.enc_block.lifetime,
							(unsigned long) ot.enc_block.lifetime);
					return -1;
				}

				printf("OK\n");
			}
		}
	}

	return 0;
}

//////////////////////////////////////////////////

static SHATYPE shatype = SHATYPE_SHA1;

int main(int argc, const char **argv)
{
	int res = -1;

	UNUSED_ARG(argc);
	UNUSED_ARG(argv);

	if(argc>1)
		print_extra = 1;

	set_logfile("stdout");
	set_system_parameters(0);

	{
		const unsigned char reqstc[] =
					     "\x00\x01\x00\x58"
					     "\x21\x12\xa4\x42"
					     "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
					     "\x80\x22\x00\x10"
					       "STUN test client"
					     "\x00\x24\x00\x04"
					       "\x6e\x00\x01\xff"
					     "\x80\x29\x00\x08"
					       "\x93\x2f\xf9\xb1\x51\x26\x3b\x36"
					     "\x00\x06\x00\x09"
					       "\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20"
					     "\x00\x08\x00\x14"
					       "\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5"
					       "\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2"
					     "\x80\x28\x00\x04"
					       "\xe5\x7a\x3b\xcf";

		u08bits buf[sizeof(reqstc)];
		memcpy(buf, reqstc, sizeof(reqstc));

		{//fingerprintfs etc

			res = stun_is_command_message_full_check_str(buf, sizeof(reqstc) - 1, 1, NULL);
			printf("RFC 5769 message fingerprint test(0) result: ");

			if (res) {
				printf("success\n");
			} else if (res == 0) {
				printf("failure on fingerprint(0) check\n");
				exit(-1);
			}
		}

		{//short-term credentials
			u08bits uname[33];
			u08bits realm[33];
			u08bits upwd[33];
			strcpy((char*) upwd, "VOkJxbRl1RmTxUk/WvJxBt");

			res = stun_check_message_integrity_str(TURN_CREDENTIALS_SHORT_TERM, buf, sizeof(reqstc) - 1, uname, realm, upwd, shatype);
			printf("RFC 5769 simple request short-term credentials and integrity test result: ");

			if (res > 0) {
				printf("success\n");
			} else if (res == 0) {
				printf("failure on integrity check\n");
				exit(-1);
			} else {
				printf("failure on message structure check\n");
				exit(-1);
			}
		}

		{//negative fingerprint
			buf[27] = 23;

			res = stun_is_command_message_full_check_str(buf, sizeof(reqstc) - 1, 1, NULL);
			printf("RFC 5769 NEGATIVE fingerprint test(0) result: ");

			if (!res) {
				printf("success\n");
			} else if (res == 0) {
				printf("failure on NEGATIVE fingerprint check\n");
				exit(-1);
			}
		}
	}

	{
		const unsigned char reqltc[] = "\x00\x01\x00\x60"
			"\x21\x12\xa4\x42"
			"\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e"
			"\x00\x06\x00\x12"
			"\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83"
			"\xe3\x82\xaf\xe3\x82\xb9\x00\x00"
			"\x00\x15\x00\x1c"
			"\x66\x2f\x2f\x34\x39\x39\x6b\x39\x35\x34\x64\x36"
			"\x4f\x4c\x33\x34\x6f\x4c\x39\x46\x53\x54\x76\x79"
			"\x36\x34\x73\x41"
			"\x00\x14\x00\x0b"
			"\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x00"
			"\x00\x08\x00\x14"
			"\xf6\x70\x24\x65\x6d\xd6\x4a\x3e\x02\xb8\xe0\x71"
			"\x2e\x85\xc9\xa2\x8c\xa8\x96\x66";

		u08bits user[] = "\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83"
			"\xe3\x82\xaf\xe3\x82\xb9";

		u08bits realm[33];
		u08bits nonce[29];
		u08bits upwd[33];

		u08bits buf[sizeof(reqltc)];
		memcpy(buf, reqltc, sizeof(reqltc));

		u08bits uname[sizeof(user)];
		memcpy(uname, user, sizeof(user));

		strcpy((char*) realm, "example.org");
		strcpy((char*) upwd, "TheMatrIX");
		strcpy((char*)nonce,"f//499k954d6OL34oL9FSTvy64sA");

		res = stun_check_message_integrity_str(TURN_CREDENTIALS_LONG_TERM, buf, sizeof(reqltc) - 1, uname, realm,
						upwd, shatype);

		printf("RFC 5769 message structure, long-term credentials and integrity test result: ");

		if (res > 0) {
			printf("success\n");
		} else if (res == 0) {
			printf("failure on integrity check\n");
			exit(-1);
		} else {
			printf("failure on message structure check\n");
			exit(-1);
		}

		{ //encoding test
			printf("RFC 5769 message encoding test result: ");
			size_t len = 0;
			u16bits message_type = STUN_METHOD_BINDING;
			stun_tid tid;
			u16bits *buf16 = (u16bits*)buf;
			u32bits *buf32 = (u32bits*)buf;
			memcpy(tid.tsx_id,"\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e",12);
			stun_init_buffer_str(buf,&len);
			message_type &= (u16bits)(0x3FFF);
			buf16[0]=nswap16(message_type);
			buf16[1]=0;
			buf32[1]=nswap32(STUN_MAGIC_COOKIE);
			stun_tid_message_cpy(buf, &tid);
			stun_attr_add_integrity_by_user_str(buf, &len, uname, realm, upwd, nonce, shatype);
			if(len != (sizeof(reqltc)-1)) {
				printf("failure: length %d, must be %d\n",(int)len,(int)(sizeof(reqltc)-1));
				exit(-1);
			}
			if(memcmp(buf,reqltc,len)) {
				printf("failure: wrong message content\n");
				{
					int lines = 29;
					int line = 0;
					int col = 0;
					int cols = 4;
					for(line = 0;line<lines;line++) {
						for(col = 0; col<cols; col++) {
							u08bits c = buf[line*4+col];
							printf(" %2x",(int)c);
						}
						printf("\n");
					}
				}
				exit(-1);
			}
			printf("success\n");
		}

		//Negative test:
		buf[32] = 10;
		res = stun_check_message_integrity_str(TURN_CREDENTIALS_LONG_TERM, buf, sizeof(reqltc) - 1, uname, realm,
						upwd, shatype);

		printf("RFC 5769 NEGATIVE long-term credentials test result: ");

		if (res == 0) {
			printf("success\n");
		} else {
			printf("failure on NEGATIVE long-term credentials check\n");
			exit(-1);
		}
	}

	{
		const unsigned char respv4[] = "\x01\x01\x00\x3c"
			"\x21\x12\xa4\x42"
			"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
			"\x80\x22\x00\x0b"
			"\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20"
			"\x00\x20\x00\x08"
			"\x00\x01\xa1\x47\xe1\x12\xa6\x43"
			"\x00\x08\x00\x14"
			"\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9"
			"\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7"
			"\x80\x28\x00\x04"
			"\xc0\x7d\x4c\x96";

		u08bits buf[sizeof(respv4)];
		memcpy(buf, respv4, sizeof(respv4));

		{//fingerprintfs etc

			res = stun_is_command_message_full_check_str(buf, sizeof(respv4) - 1, 1, NULL);
			printf("RFC 5769 message fingerprint test(1) result: ");

			if (res) {
				printf("success\n");
			} else if (res == 0) {
				printf("failure on fingerprint(1) check\n");
				exit(-1);
			}
		}

		{//short-term credentials
			u08bits uname[33];
			u08bits realm[33];
			u08bits upwd[33];
			strcpy((char*) upwd, "VOkJxbRl1RmTxUk/WvJxBt");

			res = stun_check_message_integrity_str(TURN_CREDENTIALS_SHORT_TERM, buf, sizeof(respv4) - 1, uname, realm, upwd, shatype);
			printf("RFC 5769 IPv4 response short-term credentials and integrity test result: ");

			if (res > 0) {
				printf("success\n");
			} else if (res == 0) {
				printf("failure on integrity check\n");
				exit(-1);
			} else {
				printf("failure on message structure check\n");
				exit(-1);
			}
		}

		{//negative fingerprint
			buf[27] = 23;

			res = stun_is_command_message_full_check_str(buf, sizeof(respv4) - 1, 1, NULL);
			printf("RFC 5769 NEGATIVE fingerprint test(1) result: ");

			if (!res) {
				printf("success\n");
			} else if (res == 0) {
				printf("failure on NEGATIVE fingerprint check\n");
				exit(-1);
			}
		}

		{//IPv4 addr
			ioa_addr addr4;
			ioa_addr addr4_test;

			printf("RFC 5769 IPv4 encoding result: ");

			res = stun_attr_get_first_addr_str(buf, sizeof(respv4)-1, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &addr4, NULL);
			if(res < 0) {
				printf("failure on message structure check\n");
				exit(-1);
			}

			make_ioa_addr((const u08bits*)"192.0.2.1", 32853, &addr4_test);
			if(addr_eq(&addr4,&addr4_test)) {
				printf("success\n");
			} else {
				printf("failure on IPv4 deconding check\n");
				exit(-1);
			}
		}
	}

	{
		const unsigned char respv6[] = "\x01\x01\x00\x48"
						     "\x21\x12\xa4\x42"
						     "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"
						     "\x80\x22\x00\x0b"
						       "\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20"
						     "\x00\x20\x00\x14"
						       "\x00\x02\xa1\x47"
						       "\x01\x13\xa9\xfa\xa5\xd3\xf1\x79"
						       "\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9"
						     "\x00\x08\x00\x14"
						       "\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c"
						       "\x82\x92\xc2\x75\xbf\xe3\xed\x41"
						     "\x80\x28\x00\x04"
						       "\xc8\xfb\x0b\x4c";

		u08bits buf[sizeof(respv6)];

		{ //decoding test
			memcpy(buf, respv6, sizeof(respv6));

			res = stun_is_command_message_full_check_str(buf, sizeof(respv6) - 1, 1, NULL);
			printf("RFC 5769 message fingerprint test(2) result: ");

			if (res) {
				printf("success\n");
			} else if (res == 0) {
				printf("failure on fingerprint(2) check\n");
				exit(-1);
			}
		}

		{//short-term credentials test
			u08bits uname[33];
			u08bits realm[33];
			u08bits upwd[33];
			strcpy((char*) upwd, "VOkJxbRl1RmTxUk/WvJxBt");

			res = stun_check_message_integrity_str(TURN_CREDENTIALS_SHORT_TERM, buf, sizeof(respv6) - 1, uname, realm, upwd, shatype);
			printf("RFC 5769 IPv6 response short-term credentials and integrity test result: ");

			if (res > 0) {
				printf("success\n");
			} else if (res == 0) {
				printf("failure on integrity check\n");
				exit(-1);
			} else {
				printf("failure on message structure check\n");
				exit(-1);
			}
		}

		{//negative decoding test
			buf[27] = 23;

			res = stun_is_command_message_full_check_str(buf, sizeof(respv6) - 1, 1, NULL);
			printf("RFC 5769 NEGATIVE fingerprint test(2) result: ");

			if (!res) {
				printf("success\n");
			} else if (res == 0) {
				printf("failure on NEGATIVE fingerprint check\n");
				exit(-1);
			}
		}

		{//IPv6 deconding test
			ioa_addr addr6;
			ioa_addr addr6_test;

			printf("RFC 5769 IPv6 encoding result: ");

			res = stun_attr_get_first_addr_str(buf, sizeof(respv6) - 1,
							STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &addr6, NULL);
			if (res < 0) {
				printf("failure on message structure check\n");
				exit(-1);
			}

			make_ioa_addr((const u08bits*) "2001:db8:1234:5678:11:2233:4455:6677", 32853, &addr6_test);
			if (addr_eq(&addr6, &addr6_test)) {
				printf("success\n");
			} else {
				printf("failure on IPv6 deconding check\n");
				exit(-1);
			}
		}
	}

	{
		if(check_oauth()<0)
			exit(-1);
	}

	return 0;
}
