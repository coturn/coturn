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
#include <getopt.h>
#include <stddef.h>

#include "ns_turn_utils.h"
#include "apputils.h"
#include "stun_buffer.h"

////////////////////////////////////////////////////

#define OAUTH_TOKEN_SIZE 1000 //TODO: find insted of 1000 the real max of encoded token length 
#define OAUTH_MAC_KEY_SIZE 32
#define OAUTH_LTK_ID_SIZE 32
#define OAUTH_LTK_SIZE 32
#define OAUTH_LTK_BASE64ENCODED_SIZE 44
#define OAUTH_TOKEN_LIFETIME 3600
#define OAUTH_AS_RS_ALG_SIZE 7 
#define OAUTH_SERVER_NAME_SIZE 255 
#define OAUTH_GCM_NONCE_BASE64ENCODED_SIZE 16 
#define OAUTH_HMAC_ALG_SIZE 20


static int setup_ikm_key(const char *kid, 
                        const char *ikm_key, 
                        const turn_time_t key_timestamp, 
                        const turn_time_t key_lifetime, 
                        const char *as_rs_alg, 
                        oauth_key *key) { 

        bzero(key,sizeof(*key));

        oauth_key_data okd;
        bzero(&okd,sizeof(okd));

        {
                oauth_key_data_raw okdr;
                bzero(&okdr,sizeof(okdr));

                STRCPY(okdr.kid,kid);
                STRCPY(okdr.ikm_key,ikm_key);
                STRCPY(okdr.as_rs_alg,as_rs_alg);
                okdr.timestamp = key_timestamp;
                okdr.lifetime = key_lifetime;

                convert_oauth_key_data_raw(&okdr, &okd);
        }        

        char err_msg[1025] = "\0";
        size_t err_msg_size = sizeof(err_msg) - 1;

        if (convert_oauth_key_data(&okd, key, err_msg, err_msg_size) < 0) {
                        fprintf(stderr, "%s\n", err_msg);
                        return -1;
        }         

        return 0;
}



static int encode_token(const char* server_name,
                        const char* gcm_nonce,
                        const char* mac_key,
                        const uint64_t token_timestamp,
                        const uint32_t token_lifetime,
                        const oauth_key key,
                        char* base64encoded_etoken) {


        oauth_token ot;
        bzero(&ot,sizeof(ot));

        const size_t mac_key_length=strlen(mac_key);
        ot.enc_block.key_length = (uint16_t)mac_key_length;
        STRCPY(ot.enc_block.mac_key,mac_key);
        ot.enc_block.timestamp = token_timestamp;
        ot.enc_block.lifetime = token_lifetime;

        encoded_oauth_token etoken;
        bzero(&etoken,sizeof(etoken));

        // TODO: avoid this hack
        if (!*gcm_nonce) gcm_nonce=NULL;

        if (encode_oauth_token((const uint8_t *) server_name, &etoken, &key, &ot,(const uint8_t *) gcm_nonce) < 0) {
                fprintf(stderr, "%s: cannot encode oauth token\n",
                                __FUNCTION__);
                return -1;
        }

        size_t base64encoded_etoken_length;
        const char *tmp=base64_encode((unsigned char *)(etoken.token), etoken.size, &base64encoded_etoken_length);
        STRCPY(base64encoded_etoken,tmp);

        return 0;
}

static int validate_decode_token(const char* server_name, 
                        const oauth_key key,
                        const char* base64encoded_etoken, oauth_token* dot) {

        
        bzero((dot),sizeof(*dot));

        encoded_oauth_token etoken;
        bzero(&etoken,sizeof(etoken));

        const size_t base64encoded_etoken_length=strlen(base64encoded_etoken);
        const unsigned char *tmp = base64_decode(base64encoded_etoken,base64encoded_etoken_length,&etoken.size);
        memcpy(etoken.token,tmp,etoken.size);
                        
        if (decode_oauth_token((const uint8_t *) server_name, &etoken, &key, dot) < 0) {
                fprintf(stderr, "%s: cannot decode oauth token\n",
                                __FUNCTION__);
                return -1;
        } else {
                return 0;
        };
}

static void print_token_body(oauth_token* dot) {
        printf("\n");
        printf("Token non-encrpyted body:\n");
        printf("{\n");
        size_t base64encoded_nonce_length;
        const char *base64encoded_nonce = base64_encode((unsigned char *)dot->enc_block.nonce, dot->enc_block.nonce_length,&base64encoded_nonce_length); 
        printf("    nonce: %s\n", base64encoded_nonce);
        printf("    nonce length: %d\n", (int) dot->enc_block.nonce_length);
        printf("Token encrpyted body:\n");
        printf("{\n");
        printf("    mac key: %s\n", (char*) dot->enc_block.mac_key);
        printf("    mac key length: %d\n", (int) dot->enc_block.key_length);
        time_t time=dot->enc_block.timestamp>>16;
        unsigned msec=(dot->enc_block.timestamp & 0xFFFF)*64;
        printf("    timestamp:\n");
        printf("        unixtime: %u (localtime: %s )", (unsigned int)time, ctime(&time));
        printf("        msec:%u\n", msec);
        printf("    lifetime: %lu\n", (unsigned long) dot->enc_block.lifetime);
        printf("}\n");
}

//////////////// local definitions /////////////////

const char Usage[] =
  "Usage: oauth [ -e / -d ] [options]\n"
  "Options:\n"
  "\n"
  "        -h, --help                       usage\n\n"
  "        -v, --verbose                    verbose mode\n\n"
  "        -e, --encrypt                    encrypt token\n"
  "        -d, --decrypt                    decrypt validate token\n\n"
  "        -i, --server-name                server name (max. 255 char)\n"
  "        -j, --auth-key-id                Auth key id (max. 32 char)\n"
  "        -k, --auth-key                   base64 encoded Auth key\n"
  "        -l  --auth-key-timestamp         Auth key timestamp (sec since epoch)\n"
  "        -m, --auth-key-lifetime          Auth key lifetime in sec\n"
  "        -n, --auth-key-as-rs-alg         Authorization Server(AS) - Resource Server (RS) encryption algorithm\n"
  "        -o, --token-nonce                base64 encoded nonce base64(12 octet) = 16 char\n"
  "        -p, --token-mac-key              base64 encoded MAC key base64(32 octet) = 44 char\n"
  "        -q, --token-timestamp            timestamp in format 64 bit unsigned (Native format - Unix),\n" 
  "                                         so 48 bit for secs since epoch UTC + 16 bit for 1/64000 fractions of a second.\n" 
  "                                         e.g.: the actual unixtimestamp 16 bit left shifted. (Default: actual gmtime)\n"
  "        -r, --token-lifetime             lifetime in sec (Default: 3600)\n"
  "        -t, --token                      base64 encoded encrypted token for validation and decryption\n"
  "        -u, --hmac-alg                   stun client hmac algorithm\n";

//////////////////////////////////////////////////


int main(int argc, char **argv)
{

  oauth_key key;

  //init vars with default values
  char gcm_nonce[OAUTH_GCM_NONCE_SIZE+1]="";

  char mac_key[OAUTH_MAC_KEY_SIZE+1]="";

  time_t current_time = time(NULL);
  struct tm* gmt = gmtime(&current_time);
  uint64_t token_timestamp = (unsigned long long)mktime(gmt) << 16;
  uint32_t token_lifetime = OAUTH_TOKEN_LIFETIME;
 
  //oauth_key
  char kid[OAUTH_LTK_ID_SIZE+1] = "";
  char base64encoded_ltk[OAUTH_LTK_BASE64ENCODED_SIZE+1]="";
  turn_time_t key_timestamp = 0;
  turn_time_t key_lifetime = 0;
  char as_rs_alg[OAUTH_AS_RS_ALG_SIZE+1]="A256GCM";
  char server_name[OAUTH_SERVER_NAME_SIZE+1] = "";

  char base64encoded_etoken[OAUTH_TOKEN_SIZE]=""; 

  //TODO: replace SHA1 with an option. Actualy both big browser chrome and mozilla supports AFAIU implemented only SHA1.
  char hmac_alg[OAUTH_HMAC_ALG_SIZE+1]="HMAC-SHA1";

  static int verbose_flag=0;
  static int encrypt_flag=0;
  static int decrypt_flag=0;

  static struct option long_options[] =
   {
     /* These options set a flag. */
     {"verbose",                  no_argument,       &verbose_flag, 1},
     {"encrypt",                  no_argument,       &encrypt_flag, 1},
     {"decrypt",                  no_argument,       &decrypt_flag, 1},
     {"help",                     no_argument,       0, 'h'},
     {"server-name",              required_argument, 0, 'i'},
     {"auth-key-id",         required_argument, 0, 'j'},
     {"auth-key",            required_argument, 0, 'k'},
     {"auth-key-timestamp",  required_argument, 0, 'l'},
     {"auth-key-lifetime",   required_argument, 0, 'm'},
     {"auth-key-as-rs-alg",  required_argument, 0, 'n'},
     {"token-nonce",              required_argument, 0, 'o'},
     {"token-mac-key",            required_argument, 0, 'p'},
     {"token-timestamp",          required_argument, 0, 'q'},
     {"token-lifetime",           required_argument, 0, 'r'},
     {"token",                    required_argument, 0, 't'},
     {"hmac-alg",                 required_argument, 0, 'u'},
     {0, 0, 0, 0}
   };
  /* getopt_long stores the option index here. */
  int option_index = 0;

  //tmp vars
  size_t nonce_size=0;
  char *nonce_val;

  size_t mac_key_size;
  char *mac_key_val;


  int i;
  int c=0;

  set_logfile("stdout");
  set_system_parameters(0);

  while ((c = getopt_long(argc, argv, "hvedi:j:k:l:m:n:o:p:q:r:t:u:",long_options, &option_index)) != -1) {
    switch(c) {
    case 'h':
      fprintf(stderr, "%s\n", Usage);
      exit(1); 
      break;
    case 'v':
      verbose_flag=1;
      break;
    case 'e':
      encrypt_flag=1;
      break;
    case 'd':
      decrypt_flag=1;
      break;
    case 'i':
      //server-name
      if ( strlen(optarg) <= OAUTH_SERVER_NAME_SIZE ) {
        STRCPY(server_name,optarg);
      } else {
        fprintf(stderr,"Server-name must not exceed %d!\n", OAUTH_LTK_ID_SIZE );
        exit(1);
      }
      break;
   case 'j':
      //auth-key-id
      if ( strlen(optarg) <= OAUTH_LTK_ID_SIZE ) {
        STRCPY(kid,optarg);
      } else {
        fprintf(stderr,"Key ID must not exceed %d!\n", OAUTH_LTK_ID_SIZE );
        exit(1);
      }
      break;
    case 'k':
      //auth-key
      if ( strlen(optarg) <= OAUTH_LTK_BASE64ENCODED_SIZE ) {
        STRCPY(base64encoded_ltk,optarg);
      } else {
        fprintf(stderr,"Key must not exceed %d!\n", OAUTH_LTK_BASE64ENCODED_SIZE );
        exit(1);
      }
      break;
    case 'l':
      //auth-key-timestamp
      key_timestamp = atoi(optarg);
      break;
    case 'm':
      //auth-key-lifetime
      key_lifetime=atoi(optarg);
      break;
    case 'n':
      //auth-key-as-rs-alg
      if ( strlen(optarg) <= OAUTH_AS_RS_ALG_SIZE ) {
        STRCPY(as_rs_alg,optarg);
      } else {
        fprintf(stderr,"AS-RS Alg must not exceed %d!\n", OAUTH_AS_RS_ALG_SIZE );
        exit(1);
      }
      break;
    case 'o':
      //token-nonce
      nonce_val = (char*)base64_decode(optarg,strlen(optarg),&nonce_size);
      if (nonce_size > OAUTH_GCM_NONCE_SIZE){
        nonce_size=OAUTH_GCM_NONCE_SIZE;
      } 
      strncpy(gcm_nonce,nonce_val,nonce_size);
      gcm_nonce[ nonce_size + 1 ]='\0';
      break;
    case 'p':
      //token-mac-key
      mac_key_val = (char*)base64_decode(optarg,strlen(optarg),&mac_key_size);
      if (mac_key_size > OAUTH_MAC_KEY_SIZE){
        mac_key_size=OAUTH_MAC_KEY_SIZE;
      } 
      strncpy(mac_key,mac_key_val,mac_key_size);
      mac_key[mac_key_size+1]='\0';
      break;
    case 'q':
      //token-timestamp
      token_timestamp=strtoull(optarg,0,10);
      break;
    case 'r':
      //token-lifetime
      token_lifetime=atoi(optarg);
      break;
    case 't':
      if ( strlen(optarg) <= OAUTH_TOKEN_SIZE ) {
        STRCPY(base64encoded_etoken,optarg);
      } else {
        fprintf(stderr,"base64 encoded encrypted token must not exceed %d!\n", OAUTH_TOKEN_SIZE );
        exit(1);
      }
      break;
    case 'u':
      //hmac-alg
      if ( strlen(optarg) <= OAUTH_HMAC_ALG_SIZE ) {
        STRCPY(hmac_alg,optarg);
      } else {
        fprintf(stderr,"STUN client HMAC Alg must not exceed %d!\n", OAUTH_HMAC_ALG_SIZE );
        exit(1);
      }
      break;
    default:
      fprintf(stderr,"%s\n", Usage);
      exit(1);
      break;
    }
  }

  for (i = optind; i < argc; i++)
    printf ("Non-option argument %s\n", argv[i]);

  if(optind>argc) {
    fprintf(stderr, "%s\n", Usage);
    exit(-1);
  }

  if (!(encrypt_flag || decrypt_flag)){
        fprintf(stderr, "Use either encrypt or decrypt.\nPlease use -h or --help for the detailed help\n");
         exit(-1);
  }
 
  //check if we have required params 
  //TODO: more compact warnning handling
  if (encrypt_flag || decrypt_flag){
    if (strlen(server_name) == 0) { 
        fprintf(stderr, "For encode/decode  --server-name/-i is mandatory \n");
         exit(-1);
    }
    
    if (strlen(kid) == 0){
        fprintf(stderr, "For encode/decode  --auth-key-id/-j is mandatory \n");
        exit(-1);
    }
     if (strlen(base64encoded_ltk) == 0){
        fprintf(stderr, "For encode/decode  --auth-key/-k is mandatory \n");
        exit(-1);
    }
    if (key_timestamp == 0){
        fprintf(stderr, "For encode/decode  --auth-key-timestamp/-l is mandatory \n");
        exit(-1);
    }
    if (key_lifetime == 0){
        fprintf(stderr, "For encode/decode  --auth-key-lifetime/-m is mandatory \n");
        exit(-1);
    }

    if (encrypt_flag && strlen(mac_key) == 0) { 
        fprintf(stderr, "For encode --token-mac-key/-p is mandatory \n");
        exit(-1);
    }
    
    if (!encrypt_flag && decrypt_flag && strlen(base64encoded_etoken) == 0) { 
        fprintf(stderr, "For decode --token/-t is mandatory \n");
        exit(-1);
    }
    
    // Expiry warnings
    if ( (unsigned long long)key_timestamp<<16 > token_timestamp  +((unsigned long long)token_lifetime << 16)  ) {
        fprintf(stderr,"\nWARNING: Token expiry is earlear then Auth key life time start timestamp!!\n\n");
    } else {
        if( (unsigned long long)key_timestamp<<16 > token_timestamp) {
            fprintf(stderr,"\nWARNING: Token life time start timestamp is earlier then Auth key start timestamp!!\n\n");
        }
    }
    if( (unsigned long long)( key_timestamp + key_lifetime )<<16 < token_timestamp ) {
        fprintf(stderr,"\nWARNING: Auth key will expire before token lifetime start timestamp!!\n\n");
    } else {
        if( (unsigned long long)( key_timestamp + key_lifetime)<<16 < token_timestamp + ((unsigned long long)token_lifetime << 16) ) {
            fprintf(stderr,"\nWARNING: Auth key will expire before token expiry!!\n\n");
        }  
    }

    if ( setup_ikm_key(kid, base64encoded_ltk, key_timestamp, key_lifetime, as_rs_alg, &key) == 0 ) {
          if(encrypt_flag) {
          if (encode_token(server_name, gcm_nonce, mac_key, token_timestamp, token_lifetime, key, base64encoded_etoken) == 0 ) {
            printf("{\n");
            printf("    \"access_token\":\"%s\",\n",base64encoded_etoken);
            printf("    \"token_type\":\"pop\",\n");
            printf("    \"expires_in\":%d,\n",token_lifetime);
            printf("    \"kid\":\"%s\",\n",kid);
            printf("    \"key\":\"%s\",\n",mac_key);
            printf("    \"alg\":\"%s\"\n",hmac_alg);
            printf("}\n");
          } else {
            fprintf(stderr, "Error during token encode\n");
            exit(-1);
          }
        }
        if (decrypt_flag) {
          oauth_token dot;
          if ( validate_decode_token(server_name, key, base64encoded_etoken,&dot) == 0) {
            printf("-=Valid token!=-\n");
              if (verbose_flag) print_token_body(&dot);
          } else {
            fprintf(stderr, "Error during token validation and decoding\n");
            exit(-1);
          }
        }
     } else {
        fprintf(stderr, "Error during key setup\n");
         exit(-1);
    }

  }

  return 0;
}
