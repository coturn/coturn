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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <locale.h>
#include <libgen.h>

#include <pthread.h>

#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "userdb.h"
#include "dbdrivers/dbdriver.h"
#include "mainrelay.h"

#include "ns_turn_utils.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

//////////// REALM //////////////

static realm_params_t *default_realm_params_ptr = NULL;

static ur_string_map *realms = NULL;
static turn_mutex o_to_realm_mutex;
static ur_string_map *o_to_realm = NULL;
static secrets_list_t realms_list;

void lock_realms(void) {
	ur_string_map_lock(realms);
}

void unlock_realms(void) {
	ur_string_map_unlock(realms);
}

void update_o_to_realm(ur_string_map * o_to_realm_new) {
  TURN_MUTEX_LOCK(&o_to_realm_mutex);
  ur_string_map_free(&o_to_realm);
  o_to_realm = o_to_realm_new;
  TURN_MUTEX_UNLOCK(&o_to_realm_mutex);
}

void create_default_realm()
{
	if(default_realm_params_ptr) {
		return;
	}

	static realm_params_t _default_realm_params =
	{
	  1,
	  {
		"\0", /* name */
	    {0,0,0}
	  },
	  {0,NULL}
	};

	/* init everything: */
	TURN_MUTEX_INIT_RECURSIVE(&o_to_realm_mutex);
	init_secrets_list(&realms_list);
	o_to_realm = ur_string_map_create(turn_free_simple);
	default_realm_params_ptr = &_default_realm_params;
	realms = ur_string_map_create(NULL);
	lock_realms();
	default_realm_params_ptr->status.alloc_counters =  ur_string_map_create(NULL);
	unlock_realms();
}

void get_default_realm_options(realm_options_t* ro)
{
	if(ro) {
		lock_realms();
		ns_bcopy(&(default_realm_params_ptr->options),ro,sizeof(realm_options_t));
		unlock_realms();
	}
}

void set_default_realm_name(char *realm) {
	lock_realms();
	ur_string_map_value_type value = (ur_string_map_value_type)default_realm_params_ptr;
	STRCPY(default_realm_params_ptr->options.name,realm);
	ur_string_map_put(realms, (ur_string_map_key_type)default_realm_params_ptr->options.name, value);
	add_to_secrets_list(&realms_list, realm);
	unlock_realms();
}

realm_params_t* get_realm(char* name)
{
	if(name && name[0]) {
		lock_realms();
		ur_string_map_value_type value = 0;
		ur_string_map_key_type key = (ur_string_map_key_type)name;
		if (ur_string_map_get(realms, key, &value)) {
			unlock_realms();
			return (realm_params_t*)value;
		} else {
			realm_params_t *ret = (realm_params_t*)turn_malloc(sizeof(realm_params_t));
			ns_bcopy(default_realm_params_ptr,ret,sizeof(realm_params_t));
			STRCPY(ret->options.name,name);
			value = (ur_string_map_value_type)ret;
			ur_string_map_put(realms, key, value);
			ret->status.alloc_counters =  ur_string_map_create(NULL);
			add_to_secrets_list(&realms_list, name);
			unlock_realms();
			return ret;
		}
	}

	return default_realm_params_ptr;
}

int get_realm_data(char* name, realm_params_t* rp)
{
	lock_realms();
	ns_bcopy(get_realm(name),rp,sizeof(realm_params_t));
	unlock_realms();
	return 0;
}

int get_realm_options_by_origin(char *origin, realm_options_t* ro)
{
	ur_string_map_value_type value = 0;
	TURN_MUTEX_LOCK(&o_to_realm_mutex);
	if (ur_string_map_get(o_to_realm, (ur_string_map_key_type) origin, &value) && value) {
		char *realm = turn_strdup((char*)value);
		TURN_MUTEX_UNLOCK(&o_to_realm_mutex);
		realm_params_t rp;
		get_realm_data(realm, &rp);
		ns_bcopy(&(rp.options),ro,sizeof(realm_options_t));
		turn_free(realm,strlen(realm)+1);
		return 1;
	} else {
		TURN_MUTEX_UNLOCK(&o_to_realm_mutex);
		get_default_realm_options(ro);
		return 0;
	}
}

void get_realm_options_by_name(char *realm, realm_options_t* ro)
{
	realm_params_t rp;
	get_realm_data(realm, &rp);
	ns_bcopy(&(rp.options),ro,sizeof(realm_options_t));
}

int change_total_quota(char *realm, int value)
{
	int ret = value;
	lock_realms();
	realm_params_t* rp = get_realm(realm);
	rp->options.perf_options.total_quota = value;
	unlock_realms();
	return ret;
}

int change_user_quota(char *realm, int value)
{
	int ret = value;
	lock_realms();
	realm_params_t* rp = get_realm(realm);
	rp->options.perf_options.user_quota = value;
	unlock_realms();
	return ret;
}

static void must_set_admin_realm(void *realm0)
{
	char* realm = (char*)realm0;
	if(!realm || !realm[0]) {
		fprintf(stderr, "The operation cannot be completed: the realm must be set.\n");
		exit(-1);
	}
}

static void must_set_admin_user(void *user0)
{
	char* user = (char*)user0;
	if(!user || !user[0]) {
		fprintf(stderr, "The operation cannot be completed: the user must be set.\n");
		exit(-1);
	}
}

static void must_set_admin_pwd(void *pwd0)
{
	char* pwd = (char*)pwd0;
	if(!pwd || !pwd[0]) {
		fprintf(stderr, "The operation cannot be completed: the password must be set.\n");
		exit(-1);
	}
}

static void must_set_admin_origin(void *origin0)
{
	char* origin = (char*)origin0;
	if(!origin || !origin[0]) {
		fprintf(stderr, "The operation cannot be completed: the origin must be set.\n");
		exit(-1);
	}
}

/////////// SHARED SECRETS /////////////////

void init_secrets_list(secrets_list_t *sl)
{
	if(sl) {
		ns_bzero(sl,sizeof(secrets_list_t));
	}
}

void clean_secrets_list(secrets_list_t *sl)
{
	if(sl) {
		if(sl->secrets) {
			size_t i = 0;
			for(i = 0;i<sl->sz;++i) {
				if(sl->secrets[i]) {
					turn_free(sl->secrets[i], strlen(sl->secrets[i])+1);
				}
			}
			turn_free(sl->secrets,(sl->sz)*sizeof(char*));
			sl->secrets = NULL;
			sl->sz = 0;
		}
	}
}

size_t get_secrets_list_size(secrets_list_t *sl)
{
	if(sl && sl->secrets) {
		return sl->sz;
	}
	return 0;
}

const char* get_secrets_list_elem(secrets_list_t *sl, size_t i)
{
	if(get_secrets_list_size(sl)>i) {
		return sl->secrets[i];
	}
	return NULL;
}

void add_to_secrets_list(secrets_list_t *sl, const char* elem)
{
	if(sl && elem) {
	  sl->secrets = (char**)turn_realloc(sl->secrets,0,(sizeof(char*)*(sl->sz+1)));
	  sl->secrets[sl->sz] = turn_strdup(elem);
	  sl->sz += 1;
	}
}

////////////////////////////////////////////

static int get_auth_secrets(secrets_list_t *sl, u08bits *realm)
{
	int ret = -1;
  const turn_dbdriver_t * dbd = get_dbdriver();

	clean_secrets_list(sl);

	if(get_secrets_list_size(&turn_params.default_users_db.ram_db.static_auth_secrets)) {
		size_t i = 0;
		for(i=0;i<get_secrets_list_size(&turn_params.default_users_db.ram_db.static_auth_secrets);++i) {
			add_to_secrets_list(sl,get_secrets_list_elem(&turn_params.default_users_db.ram_db.static_auth_secrets,i));
		}
		ret=0;
	}
  
  if (dbd && dbd->get_auth_secrets) {
    ret = (*dbd->get_auth_secrets)(sl, realm);
  }

	return ret;
}

/*
 * Timestamp retrieval
 */
static turn_time_t get_rest_api_timestamp(char *usname)
{
	turn_time_t ts = 0;
	int ts_set = 0;

	char *col = strchr(usname,turn_params.rest_api_separator);

	if(col) {
		if(col == usname) {
			usname +=1;
		} else {
			char *ptr = usname;
			int found_non_figure = 0;
			while(ptr < col) {
				if(!(ptr[0]>='0' && ptr[0]<='9')) {
					found_non_figure=1;
					break;
				}
				++ptr;
			}
			if(found_non_figure) {
				ts = (turn_time_t)atol(col+1);
				ts_set = 1;
			} else {
				*col=0;
				ts = (turn_time_t)atol(usname);
				ts_set = 1;
				*col=turn_params.rest_api_separator;
			}
		}
	}

	if(!ts_set) {
		ts = (turn_time_t)atol(usname);
	}

	return ts;
}

static char *get_real_username(char *usname)
{
	if(usname[0] && turn_params.use_auth_secret_with_timestamp) {
		char *col=strchr(usname,turn_params.rest_api_separator);
		if(col) {
			if(col == usname) {
				usname +=1;
			} else {
				char *ptr = usname;
				int found_non_figure = 0;
				while(ptr < col) {
					if(!(ptr[0]>='0' && ptr[0]<='9')) {
						found_non_figure=1;
						break;
					}
					++ptr;
				}
				if(!found_non_figure) {
					usname = col+1;
				} else {
					*col=0;
					usname = turn_strdup(usname);
					*col=turn_params.rest_api_separator;
					return usname;
				}
			}
		}
	}

	return turn_strdup(usname);
}

/*
 * Password retrieval
 */
int get_user_key(int in_oauth, int *out_oauth, int *max_session_time, u08bits *usname, u08bits *realm, hmackey_t key, ioa_network_buffer_handle nbh)
{
	int ret = -1;

	if(max_session_time)
		*max_session_time = 0;

	if(in_oauth && out_oauth && usname && usname[0]) {

		stun_attr_ref sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(nbh),
								ioa_network_buffer_get_size(nbh),
								STUN_ATTRIBUTE_OAUTH_ACCESS_TOKEN);
		if(sar) {

			int len = stun_attr_get_len(sar);
			const u08bits *value = stun_attr_get_value(sar);

			*out_oauth = 1;

			if(len>0 && value) {

				const turn_dbdriver_t * dbd = get_dbdriver();

				if (dbd && dbd->get_oauth_key) {

					oauth_key_data_raw rawKey;
					ns_bzero(&rawKey,sizeof(rawKey));

					int gres = (*(dbd->get_oauth_key))(usname,&rawKey);
					if(gres<0)
						return ret;

					if(!rawKey.kid[0])
						return ret;

					if(rawKey.lifetime) {
						if(!turn_time_before(turn_time(),(turn_time_t)(rawKey.timestamp + rawKey.lifetime+OAUTH_TIME_DELTA))) {
							return ret;
						}
					}

					oauth_key_data okd;
					ns_bzero(&okd,sizeof(okd));

					convert_oauth_key_data_raw(&rawKey, &okd);

					char err_msg[1025] = "\0";
					size_t err_msg_size = sizeof(err_msg) - 1;

					oauth_key okey;
					ns_bzero(&okey,sizeof(okey));

					if (convert_oauth_key_data(&okd, &okey, err_msg, err_msg_size) < 0) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s\n", err_msg);
						return -1;
					}

					oauth_token dot;
					ns_bzero((&dot),sizeof(dot));

					encoded_oauth_token etoken;
					ns_bzero(&etoken,sizeof(etoken));

					if((size_t)len > sizeof(etoken.token)) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Encoded oAuth token is too large\n");
						return -1;
					}
					ns_bcopy(value,etoken.token,(size_t)len);
					etoken.size = (size_t)len;

					const char* server_name = (char*)turn_params.oauth_server_name;
					if(!(server_name && server_name[0])) {
						server_name = (char*)realm;
						if(!(server_name && server_name[0])) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot determine oAuth server name");
							return -1;
						}
					}

					if (decode_oauth_token((const u08bits *) server_name, &etoken,&okey, &dot) < 0) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot decode oauth token\n");
						return -1;
					}

					switch(dot.enc_block.key_length) {
					case SHA1SIZEBYTES:
						break;
					case SHA256SIZEBYTES:
					case SHA384SIZEBYTES:
					case SHA512SIZEBYTES:
					default:
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong size of the MAC key in oAuth token(3): %d\n",(int)dot.enc_block.key_length);
						return -1;
					};

					password_t pwdtmp;
					if(stun_check_message_integrity_by_key_str(TURN_CREDENTIALS_LONG_TERM,
								ioa_network_buffer_data(nbh),
								ioa_network_buffer_get_size(nbh),
								dot.enc_block.mac_key,
								pwdtmp,
								SHATYPE_DEFAULT)>0) {

						turn_time_t lifetime = (turn_time_t)(dot.enc_block.lifetime);
						if(lifetime) {
							turn_time_t ts = (turn_time_t)(dot.enc_block.timestamp >> 16);
							turn_time_t to = ts + lifetime + OAUTH_TIME_DELTA;
							turn_time_t ct = turn_time();
							if(!turn_time_before(ct,to)) {
								TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "oAuth token is too old\n");
								return -1;
							}
							if(max_session_time) {
								*max_session_time = to - ct;
							}
						}

						ns_bcopy(dot.enc_block.mac_key,key,dot.enc_block.key_length);

						if(rawKey.realm[0]) {
							ns_bcopy(rawKey.realm,realm,sizeof(rawKey.realm));
						}

						ret = 0;
					}
				}
			}
		}
	}

	if(out_oauth && *out_oauth) {
		return ret;
	}

	if(turn_params.use_auth_secret_with_timestamp) {

		turn_time_t ctime = (turn_time_t) time(NULL);
		turn_time_t ts = 0;
		secrets_list_t sl;
		size_t sll = 0;

		init_secrets_list(&sl);

		if(get_auth_secrets(&sl, realm)<0)
			return ret;

		ts = get_rest_api_timestamp((char*)usname);

		if(!turn_time_before(ts, ctime)) {

			u08bits hmac[MAXSHASIZE];
			unsigned int hmac_len;
			password_t pwdtmp;

			hmac[0] = 0;

			stun_attr_ref sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(nbh),
							ioa_network_buffer_get_size(nbh),
							STUN_ATTRIBUTE_MESSAGE_INTEGRITY);
			if (!sar)
				return -1;

			int sarlen = stun_attr_get_len(sar);
			switch(sarlen) {
			case SHA1SIZEBYTES:
				hmac_len = SHA1SIZEBYTES;
				break;
			case SHA256SIZEBYTES:
			case SHA384SIZEBYTES:
			case SHA512SIZEBYTES:
			default:
				return -1;
			};

			for(sll=0;sll<get_secrets_list_size(&sl);++sll) {

				const char* secret = get_secrets_list_elem(&sl,sll);

				if(secret) {
					if(stun_calculate_hmac(usname, strlen((char*)usname), (const u08bits*)secret, strlen(secret), hmac, &hmac_len, SHATYPE_DEFAULT)>=0) {
						size_t pwd_length = 0;
						char *pwd = base64_encode(hmac,hmac_len,&pwd_length);

						if(pwd) {
							if(pwd_length<1) {
								turn_free(pwd,strlen(pwd)+1);
							} else {
								if(stun_produce_integrity_key_str((u08bits*)usname, realm, (u08bits*)pwd, key, SHATYPE_DEFAULT)>=0) {

									if(stun_check_message_integrity_by_key_str(TURN_CREDENTIALS_LONG_TERM,
										ioa_network_buffer_data(nbh),
										ioa_network_buffer_get_size(nbh),
										key,
										pwdtmp,
										SHATYPE_DEFAULT)>0) {

										ret = 0;
									}
								}
								turn_free(pwd,pwd_length);

								if(ret==0)
									break;
							}
						}
					}
				}
			}
		}

		clean_secrets_list(&sl);

		return ret;
	}

	ur_string_map_value_type ukey = NULL;
	ur_string_map_lock(turn_params.default_users_db.ram_db.static_accounts);
	if(ur_string_map_get(turn_params.default_users_db.ram_db.static_accounts, (ur_string_map_key_type)usname, &ukey)) {
		ret = 0;
	}
	ur_string_map_unlock(turn_params.default_users_db.ram_db.static_accounts);

	if(ret==0) {
		size_t sz = get_hmackey_size(SHATYPE_DEFAULT);
		ns_bcopy(ukey,key,sz);
		return 0;
	}

	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->get_user_key) {
		ret = (*(dbd->get_user_key))(usname, realm, key);
	}

	return ret;
}

u08bits *start_user_check(turnserver_id id, turn_credential_type ct, int in_oauth, int *out_oauth, u08bits *usname, u08bits *realm, get_username_resume_cb resume, ioa_net_data *in_buffer, u64bits ctxkey, int *postpone_reply)
{
	*postpone_reply = 1;

	struct auth_message am;
	ns_bzero(&am,sizeof(struct auth_message));
	am.id = id;
	am.ct = ct;
	am.in_oauth = in_oauth;
	am.out_oauth = *out_oauth;
	STRCPY(am.username,usname);
	STRCPY(am.realm,realm);
	am.resume_func = resume;
	memcpy(&(am.in_buffer),in_buffer,sizeof(ioa_net_data));
	in_buffer->nbh = NULL;
	am.ctxkey = ctxkey;

	send_auth_message_to_auth_server(&am);

	return NULL;
}

int check_new_allocation_quota(u08bits *user, int oauth, u08bits *realm)
{
	int ret = 0;
	if (user || oauth) {
		u08bits *username = oauth ? (u08bits*)turn_strdup("") : (u08bits*)get_real_username((char*)user);
		realm_params_t *rp = get_realm((char*)realm);
		ur_string_map_lock(rp->status.alloc_counters);
		if (rp->options.perf_options.total_quota && (rp->status.total_current_allocs >= rp->options.perf_options.total_quota)) {
			ret = -1;
		} else if(username[0]){
			ur_string_map_value_type value = 0;
			if (!ur_string_map_get(rp->status.alloc_counters, (ur_string_map_key_type) username, &value)) {
				value = (ur_string_map_value_type) 1;
				ur_string_map_put(rp->status.alloc_counters, (ur_string_map_key_type) username, value);
				++(rp->status.total_current_allocs);
			} else {
				if ((rp->options.perf_options.user_quota) && ((size_t) value >= (size_t)(rp->options.perf_options.user_quota))) {
					ret = -1;
				} else {
					value = (ur_string_map_value_type)(((size_t)value) + 1);
					ur_string_map_put(rp->status.alloc_counters, (ur_string_map_key_type) username, value);
					++(rp->status.total_current_allocs);
				}
			}
		} else {
			++(rp->status.total_current_allocs);
		}
		turn_free(username,strlen((char*)username)+1);
		ur_string_map_unlock(rp->status.alloc_counters);
	}
	return ret;
}

void release_allocation_quota(u08bits *user, int oauth, u08bits *realm)
{
	if (user) {
		u08bits *username = oauth ? (u08bits*)turn_strdup("") : (u08bits*)get_real_username((char*)user);
		realm_params_t *rp = get_realm((char*)realm);
		ur_string_map_lock(rp->status.alloc_counters);
		if(username[0]) {
			ur_string_map_value_type value = 0;
			ur_string_map_get(rp->status.alloc_counters, (ur_string_map_key_type) username, &value);
			if (value) {
				value = (ur_string_map_value_type)(((size_t)value) - 1);
				ur_string_map_put(rp->status.alloc_counters, (ur_string_map_key_type) username, value);
			}
		}
		if (rp->status.total_current_allocs)
			--(rp->status.total_current_allocs);
		ur_string_map_unlock(rp->status.alloc_counters);
		turn_free(username, strlen((char*)username)+1);
	}
}

//////////////////////////////////

int add_static_user_account(char *user)
{
	/* Realm is either default or empty for users taken from file or command-line */
	if(user && !turn_params.use_auth_secret_with_timestamp) {
		char *s = strstr(user, ":");
		if(!s || (s==user) || (strlen(s)<2)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong user account: %s\n",user);
		} else {
			size_t ulen = s-user;
			char *usname = (char*)turn_malloc(sizeof(char)*(ulen+1));
			strncpy(usname,user,ulen);
			usname[ulen]=0;
			if(SASLprep((u08bits*)usname)<0) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong user name: %s\n",user);
				turn_free(usname,sizeof(char)*(ulen+1));
				return -1;
			}
			s = skip_blanks(s+1);
			hmackey_t *key = (hmackey_t*)turn_malloc(sizeof(hmackey_t));
			if(strstr(s,"0x")==s) {
				char *keysource = s + 2;
				size_t sz = get_hmackey_size(SHATYPE_DEFAULT);
				if(strlen(keysource)<sz*2) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key format: %s\n",s);
				} if(convert_string_key_to_binary(keysource, *key, sz)<0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key: %s\n",s);
					turn_free(usname,strlen(usname)+1);
					turn_free(key,sizeof(hmackey_t));
					return -1;
				}
			} else {
				//this is only for default realm
				stun_produce_integrity_key_str((u08bits*)usname, (u08bits*)get_realm(NULL)->options.name, (u08bits*)s, *key, SHATYPE_DEFAULT);
			}
			{
				ur_string_map_lock(turn_params.default_users_db.ram_db.static_accounts);
				ur_string_map_put(turn_params.default_users_db.ram_db.static_accounts, (ur_string_map_key_type)usname, (ur_string_map_value_type)*key);
				ur_string_map_unlock(turn_params.default_users_db.ram_db.static_accounts);
			}
			turn_params.default_users_db.ram_db.users_number++;
			turn_free(usname,strlen(usname)+1);
			return 0;
		}
	}

	return -1;
}

////////////////// Admin /////////////////////////

static int list_users(u08bits *realm, int is_admin)
{
  const turn_dbdriver_t * dbd = get_dbdriver();
  if (dbd) {
	  if(is_admin) {
		  if(dbd->list_admin_users) {
		  	(*dbd->list_admin_users)(0);
		  }
	  } else {
		  if(dbd->list_users) {
			  (*dbd->list_users)(realm,NULL,NULL);
		  }
	  }
  }

  return 0;
}

static int show_secret(u08bits *realm)
{
  const turn_dbdriver_t * dbd = get_dbdriver();
  if (dbd && dbd->list_secrets) {
    (*dbd->list_secrets)(realm,NULL,NULL);
  }

  return 0;
}

static int del_secret(u08bits *secret, u08bits *realm) {

	must_set_admin_realm(realm);

	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->del_secret) {
		(*dbd->del_secret)(secret, realm);
	}

	return 0;
}

static int set_secret(u08bits *secret, u08bits *realm) {

	if(!secret || (secret[0]==0))
		return 0;

	must_set_admin_realm(realm);

	del_secret(secret, realm);

	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->set_secret) {
		(*dbd->set_secret)(secret, realm);
	}

	return 0;
}

static int add_origin(u08bits *origin0, u08bits *realm)
{
	u08bits origin[STUN_MAX_ORIGIN_SIZE+1];

	get_canonic_origin((const char *)origin0, (char *)origin, sizeof(origin)-1);

	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->add_origin) {
		(*dbd->add_origin)(origin, realm);
	}

	return 0;
}

static int del_origin(u08bits *origin0)
{
	u08bits origin[STUN_MAX_ORIGIN_SIZE+1];

	get_canonic_origin((const char *)origin0, (char *)origin, sizeof(origin)-1);

	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->del_origin) {
		(*dbd->del_origin)(origin);
	}

	return 0;
}

static int list_origins(u08bits *realm)
{
  const turn_dbdriver_t * dbd = get_dbdriver();
  if (dbd && dbd->list_origins) {
    (*dbd->list_origins)(realm,NULL,NULL);
  }

  return 0;
}

static int set_realm_option_one(u08bits *realm, unsigned long value, const char* opt)
{
	if(value == (unsigned long)-1)
		return 0;

	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->set_realm_option_one) {
		(*dbd->set_realm_option_one)(realm, value, opt);
	}

	return 0;
}

static int set_realm_option(u08bits *realm, perf_options_t *po)
{
	set_realm_option_one(realm,(unsigned long)po->max_bps,"max-bps");
	set_realm_option_one(realm,(unsigned long)po->user_quota,"user-quota");
	set_realm_option_one(realm,(unsigned long)po->total_quota,"total-quota");
	return 0;
}

static int list_realm_options(u08bits *realm)
{
  const turn_dbdriver_t * dbd = get_dbdriver();
  if (dbd && dbd->list_realm_options) {
    (*dbd->list_realm_options)(realm);
	}

	return 0;
}

int adminuser(u08bits *user, u08bits *realm, u08bits *pwd, u08bits *secret, u08bits *origin, TURNADMIN_COMMAND_TYPE ct, perf_options_t *po, int is_admin)
{
	hmackey_t key;
	char skey[sizeof(hmackey_t) * 2 + 1];

	if (ct == TA_LIST_USERS) {
		return list_users(realm, is_admin);
	}

	if (ct == TA_LIST_ORIGINS) {
		return list_origins(realm);
	}

	if (ct == TA_SHOW_SECRET) {
		return show_secret(realm);
	}

	if (ct == TA_SET_SECRET) {
		return set_secret(secret, realm);
	}

	if (ct == TA_DEL_SECRET) {
		return del_secret(secret, realm);
	}

	if (ct == TA_ADD_ORIGIN) {
		must_set_admin_origin(origin);
		must_set_admin_realm(realm);
		return add_origin(origin, realm);
	}

	if (ct == TA_DEL_ORIGIN) {
		must_set_admin_origin(origin);
		return del_origin(origin);
	}

	if (ct == TA_SET_REALM_OPTION) {
		must_set_admin_realm(realm);
		if (!(po && (po->max_bps != ((band_limit_t) -1) || po->total_quota >= 0 || po->user_quota >= 0))) {
			fprintf(stderr, "The operation cannot be completed: a realm option must be set.\n");
			exit(-1);
		}
		return set_realm_option(realm, po);
	}

	if (ct == TA_LIST_REALM_OPTIONS) {
		return list_realm_options(realm);
	}

	must_set_admin_user(user);

	if (ct != TA_DELETE_USER && !is_admin) {

		must_set_admin_pwd(pwd);

		{
			stun_produce_integrity_key_str(user, realm, pwd, key, SHATYPE_DEFAULT);
			size_t i = 0;
			size_t sz = get_hmackey_size(SHATYPE_DEFAULT);
			int maxsz = (int) (sz * 2) + 1;
			char *s = skey;
			for (i = 0; (i < sz) && (maxsz > 2); i++) {
				snprintf(s, (size_t) (sz * 2), "%02x", (unsigned int) key[i]);
				maxsz -= 2;
				s += 2;
			}
			skey[sz * 2] = 0;
		}
	}

	const turn_dbdriver_t * dbd = get_dbdriver();

	if (ct == TA_PRINT_KEY) {

		printf("0x%s\n", skey);

	} else if (dbd) {

		if(!is_admin)
			must_set_admin_realm(realm);

		if (ct == TA_DELETE_USER) {
			if(is_admin) {
				if (dbd->del_admin_user)
					(*dbd->del_admin_user)(user);
			} else {
				if (dbd->del_user)
					(*dbd->del_user)(user, realm);
			}
		} else if (ct == TA_UPDATE_USER) {
			if(is_admin) {
				must_set_admin_pwd(pwd);
				if (dbd->set_admin_user) {
					password_t password;
					generate_new_enc_password((char*)pwd,(char*)password);
					(*dbd->set_admin_user)(user, realm, password);
				}
			} else {
				if (dbd->set_user_key)
					(*dbd->set_user_key)(user, realm, skey);
			}
		}

	}

	return 0;
}

/////////// PING //////////////

void auth_ping(redis_context_handle rch)
{
  const turn_dbdriver_t * dbd = get_dbdriver();
  if (dbd && dbd->auth_ping) {
    (*dbd->auth_ping)(rch);
  }
}

///////////////// TEST /////////////////

#if defined(DB_TEST)

void run_db_test(void)
{
	turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd) {

		printf("DB TEST 1:\n");
		dbd->list_oauth_keys();

		printf("DB TEST 2:\n");
		oauth_key_data_raw key_;
		oauth_key_data_raw *key=&key_;
		dbd->get_oauth_key((const u08bits*)"north",key);
		printf("  kid=%s, ikm_key=%s, timestamp=%llu, lifetime=%lu, as_rs_alg=%s\n",
		    		key->kid, key->ikm_key, (unsigned long long)key->timestamp, (unsigned long)key->lifetime, key->as_rs_alg);

		printf("DB TEST 3:\n");

		STRCPY(key->as_rs_alg,"as_rs_alg");
		STRCPY(key->ikm_key,"ikm_key");
		STRCPY(key->kid,"kid");
		key->timestamp = 123;
		key->lifetime = 456;
		dbd->del_oauth_key((const u08bits*)"kid");
		dbd->set_oauth_key(key);
		dbd->list_oauth_keys();

		printf("DB TEST 4:\n");
		dbd->get_oauth_key((const u08bits*)"kid",key);
		printf("  kid=%s, ikm_key=%s, timestamp=%llu, lifetime=%lu, as_rs_alg=%s\n",
		    		key->kid, key->ikm_key, (unsigned long long)key->timestamp, (unsigned long)key->lifetime, key->as_rs_alg);

		printf("DB TEST 5:\n");
		dbd->del_oauth_key((const u08bits*)"kid");
		dbd->list_oauth_keys();

		printf("DB TEST 6:\n");

		dbd->get_oauth_key((const u08bits*)"north",key);

		oauth_key_data oakd;
		convert_oauth_key_data_raw(key, &oakd);
		printf("  kid=%s, ikm_key=%s, timestamp=%llu, lifetime=%lu, as_rs_alg=%s\n",
				    		oakd.kid, oakd.ikm_key, (unsigned long long)oakd.timestamp, (unsigned long)oakd.lifetime, oakd.as_rs_alg);

		oauth_key oak;
		char err_msg[1025];
		err_msg[0]=0;
		if(convert_oauth_key_data(&oakd,&oak,err_msg,sizeof(err_msg)-1)<0) {
			printf("  ERROR: %s\n",err_msg);
		} else {
			printf("  OK!\n");
		}
		printf("DB TEST END\n");
	}
}

#endif

///////////////// WHITE/BLACK IP LISTS ///////////////////

#if !defined(TURN_NO_RWLOCK)
static pthread_rwlock_t* whitelist_rwlock = NULL;
static pthread_rwlock_t* blacklist_rwlock = NULL;
#else
static turn_mutex whitelist_mutex;
static turn_mutex blacklist_mutex;
#endif

static ip_range_list_t* ipwhitelist = NULL;
static ip_range_list_t* ipblacklist = NULL;

void init_dynamic_ip_lists(void)
{
#if !defined(TURN_NO_RWLOCK)
	whitelist_rwlock = (pthread_rwlock_t*) turn_malloc(sizeof(pthread_rwlock_t));
	pthread_rwlock_init(whitelist_rwlock, NULL);

	blacklist_rwlock = (pthread_rwlock_t*) turn_malloc(sizeof(pthread_rwlock_t));
	pthread_rwlock_init(blacklist_rwlock, NULL);
#else
	turn_mutex_init(&whitelist_mutex);
	turn_mutex_init(&blacklist_mutex);
#endif
}

void ioa_lock_whitelist(ioa_engine_handle e)
{
	UNUSED_ARG(e);
#if !defined(TURN_NO_RWLOCK)
	pthread_rwlock_rdlock(whitelist_rwlock);
#else
	turn_mutex_lock(&whitelist_mutex);
#endif
}
void ioa_unlock_whitelist(ioa_engine_handle e)
{
	UNUSED_ARG(e);
#if !defined(TURN_NO_RWLOCK)
	pthread_rwlock_unlock(whitelist_rwlock);
#else
	turn_mutex_unlock(&whitelist_mutex);
#endif
}
static void ioa_wrlock_whitelist(ioa_engine_handle e)
{
	UNUSED_ARG(e);
#if !defined(TURN_NO_RWLOCK)
	pthread_rwlock_wrlock(whitelist_rwlock);
#else
	turn_mutex_lock(&whitelist_mutex);
#endif
}
const ip_range_list_t* ioa_get_whitelist(ioa_engine_handle e)
{
	UNUSED_ARG(e);
	return ipwhitelist;
}

void ioa_lock_blacklist(ioa_engine_handle e)
{
	UNUSED_ARG(e);
#if !defined(TURN_NO_RWLOCK)
	pthread_rwlock_rdlock(blacklist_rwlock);
#else
	turn_mutex_lock(&blacklist_mutex);
#endif
}
void ioa_unlock_blacklist(ioa_engine_handle e)
{
	UNUSED_ARG(e);
#if !defined(TURN_NO_RWLOCK)
	pthread_rwlock_unlock(blacklist_rwlock);
#else
	turn_mutex_unlock(&blacklist_mutex);
#endif
}
static void ioa_wrlock_blacklist(ioa_engine_handle e)
{
	UNUSED_ARG(e);
#if !defined(TURN_NO_RWLOCK)
	pthread_rwlock_wrlock(blacklist_rwlock);
#else
	turn_mutex_lock(&blacklist_mutex);
#endif
}
const ip_range_list_t* ioa_get_blacklist(ioa_engine_handle e)
{
	UNUSED_ARG(e);
	return ipblacklist;
}

ip_range_list_t* get_ip_list(const char *kind)
{
	ip_range_list_t *ret = (ip_range_list_t*) turn_malloc(sizeof(ip_range_list_t));
	ns_bzero(ret,sizeof(ip_range_list_t));

	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->get_ip_list) {
		(*dbd->get_ip_list)(kind, ret);
	}

	return ret;
}

void ip_list_free(ip_range_list_t *l)
{
	if(l) {
		if(l->rs)
		  turn_free(l->rs,l->ranges_number * sizeof(ip_range_t));
		turn_free(l,sizeof(ip_range_list_t));
	}
}

void update_white_and_black_lists(void)
{
	{
		ip_range_list_t *wl = get_ip_list("allowed");
		ip_range_list_t *owl = NULL;
		ioa_wrlock_whitelist(NULL);
		owl = ipwhitelist;
		ipwhitelist = wl;
		ioa_unlock_whitelist(NULL);
		ip_list_free(owl);
	}
	{
		ip_range_list_t *bl = get_ip_list("denied");
		ip_range_list_t *obl = NULL;
		ioa_wrlock_blacklist(NULL);
		obl = ipblacklist;
		ipblacklist = bl;
		ioa_unlock_blacklist(NULL);
		ip_list_free(obl);
	}
}

/////////////// add ACL record ///////////////////

int add_ip_list_range(const char * range0, const char * realm, ip_range_list_t * list)
{
	char *range = turn_strdup(range0);

	char* separator = strchr(range, '-');

	if (separator) {
		*separator = '\0';
	}

	ioa_addr min, max;

	if (make_ioa_addr((const u08bits*) range, 0, &min) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong address format: %s\n", range);
		turn_free(range,0);
		return -1;
	}

	if (separator) {
		if (make_ioa_addr((const u08bits*) separator + 1, 0, &max) < 0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong address format: %s\n", separator + 1);
			turn_free(range,0);
			return -1;
		}
	} else {
		// Doesn't have a '-' character in it, so assume that this is a single address
		addr_cpy(&max, &min);
	}

	if (separator)
		*separator = '-';

	++(list->ranges_number);
	list->rs = (ip_range_t*) turn_realloc(list->rs, 0, sizeof(ip_range_t) * list->ranges_number);
	STRCPY(list->rs[list->ranges_number - 1].str,range);
	if(realm)
		STRCPY(list->rs[list->ranges_number - 1].realm,realm);
	else
		list->rs[list->ranges_number - 1].realm[0]=0;
	turn_free(range,0);
	ioa_addr_range_set(&(list->rs[list->ranges_number - 1].enc), &min, &max);

	return 0;
}

int check_ip_list_range(const char * range0)
{
	char *range = turn_strdup(range0);

	char* separator = strchr(range, '-');

	if (separator) {
		*separator = '\0';
	}

	ioa_addr min, max;

	if (make_ioa_addr((const u08bits*) range, 0, &min) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong address range format: %s\n", range);
		turn_free(range,0);
		return -1;
	}

	if (separator) {
		if (make_ioa_addr((const u08bits*) separator + 1, 0, &max) < 0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong address range format: %s\n", separator + 1);
			turn_free(range,0);
			return -1;
		}
	} else {
		// Doesn't have a '-' character in it, so assume that this is a single address
		addr_cpy(&max, &min);
	}

	if (separator)
		*separator = '-';

	turn_free(range,0);

	return 0;
}

/////////// REALM //////////////

void reread_realms(void)
{
	{
		realm_params_t* defrp = get_realm(NULL);
		lock_realms();
		defrp->options.perf_options.max_bps = turn_params.max_bps;
		defrp->options.perf_options.total_quota = turn_params.total_quota;
		defrp->options.perf_options.user_quota = turn_params.user_quota;
		unlock_realms();
	}

	const turn_dbdriver_t * dbd = get_dbdriver();
	if (dbd && dbd->reread_realms) {
		(*dbd->reread_realms)(&realms_list);
	}
}

///////////////////////////////
