/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 * Copyright (C) 2014 Vivocha S.p.A.
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

#include "../mainrelay.h"
#include "dbd_redis.h"

#if !defined(TURN_NO_HIREDIS)
#include "hiredis_libevent2.h"
#include <hiredis/hiredis.h>

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int donot_print_connection_success = 0;

static void turnFreeRedisReply(void *reply) {
	if(reply) {
		freeReplyObject(reply);
	}
}

struct _Ryconninfo {
	char *host;
	char *dbname;
	char *password;
	unsigned int connect_timeout;
	unsigned int port;
};

typedef struct _Ryconninfo Ryconninfo;

static void RyconninfoFree(Ryconninfo *co) {
	if(co) {
		if(co->host) turn_free(co->host, strlen(co->host)+1);
		if(co->dbname) turn_free(co->dbname, strlen(co->dbname)+1);
		if(co->password) turn_free(co->password, strlen(co->password)+1);
		ns_bzero(co,sizeof(Ryconninfo));
	}
}

static Ryconninfo *RyconninfoParse(const char *userdb, char **errmsg) {
	Ryconninfo *co = (Ryconninfo*) turn_malloc(sizeof(Ryconninfo));
	ns_bzero(co,sizeof(Ryconninfo));
	if (userdb) {
		char *s0 = turn_strdup(userdb);
		char *s = s0;

		while (s && *s) {

			while (*s && (*s == ' '))
				++s;
			char *snext = strstr(s, " ");
			if (snext) {
				*snext = 0;
				++snext;
			}

			char* seq = strstr(s, "=");
			if (!seq) {
				RyconninfoFree(co);
				co = NULL;
				if (errmsg) {
					*errmsg = turn_strdup(s);
				}
				break;
			}

			*seq = 0;
			if (!strcmp(s, "host"))
				co->host = turn_strdup(seq + 1);
			else if (!strcmp(s, "ip"))
				co->host = turn_strdup(seq + 1);
			else if (!strcmp(s, "addr"))
				co->host = turn_strdup(seq + 1);
			else if (!strcmp(s, "ipaddr"))
				co->host = turn_strdup(seq + 1);
			else if (!strcmp(s, "hostaddr"))
				co->host = turn_strdup(seq + 1);
			else if (!strcmp(s, "dbname"))
				co->dbname = turn_strdup(seq + 1);
			else if (!strcmp(s, "db"))
				co->dbname = turn_strdup(seq + 1);
			else if (!strcmp(s, "database"))
				co->dbname = turn_strdup(seq + 1);
			else if (!strcmp(s, "user"))
				;
			else if (!strcmp(s, "uname"))
				;
			else if (!strcmp(s, "name"))
				;
			else if (!strcmp(s, "username"))
				;
			else if (!strcmp(s, "password"))
				co->password = turn_strdup(seq + 1);
			else if (!strcmp(s, "pwd"))
				co->password = turn_strdup(seq + 1);
			else if (!strcmp(s, "passwd"))
				co->password = turn_strdup(seq + 1);
			else if (!strcmp(s, "secret"))
				co->password = turn_strdup(seq + 1);
			else if (!strcmp(s, "port"))
				co->port = (unsigned int) atoi(seq + 1);
			else if (!strcmp(s, "p"))
				co->port = (unsigned int) atoi(seq + 1);
			else if (!strcmp(s, "connect_timeout"))
				co->connect_timeout = (unsigned int) atoi(seq + 1);
			else if (!strcmp(s, "timeout"))
				co->connect_timeout = (unsigned int) atoi(seq + 1);
			else {
				RyconninfoFree(co);
				co = NULL;
				if (errmsg) {
					*errmsg = turn_strdup(s);
				}
				break;
			}

			s = snext;
		}

		turn_free(s0, strlen(s0)+1);
	}

	if(co) {
		if(!(co->dbname))
			co->dbname=turn_strdup("0");
		if(!(co->host))
			co->host=turn_strdup("127.0.0.1");
		if(!(co->password))
			co->password=turn_strdup("");
	}

	return co;
}

redis_context_handle get_redis_async_connection(struct event_base *base, const char* connection_string, int delete_keys) {

	redis_context_handle ret = NULL;

	char *errmsg = NULL;
	if(base  && connection_string  && connection_string[0]) {
		Ryconninfo *co = RyconninfoParse(connection_string, &errmsg);
		if (!co) {
			if (errmsg) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error: %s\n", connection_string, errmsg);
				turn_free(errmsg,strlen(errmsg)+1);
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error\n", connection_string);
			}
		} else if (errmsg) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error: %s\n", connection_string, errmsg);
			turn_free(errmsg,strlen(errmsg)+1);
			RyconninfoFree(co);
		} else {

			if(delete_keys) {

				redisContext *rc = NULL;

				char ip[256] = "\0";
				int port = DEFAULT_REDIS_PORT;
				if (co->host)
					STRCPY(ip,co->host);
				if (!ip[0])
					STRCPY(ip,"127.0.0.1");

				if (co->port)
					port = (int) (co->port);

				if (co->connect_timeout) {
					struct timeval tv;
					tv.tv_usec = 0;
					tv.tv_sec = (time_t) (co->connect_timeout);
					rc = redisConnectWithTimeout(ip, port, tv);
				} else {
					rc = redisConnect(ip, port);
				}

				if (!rc) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot initialize Redis DB async connection\n");
				} else {
					if (co->password) {
						turnFreeRedisReply(redisCommand(rc, "AUTH %s", co->password));
					}
					if (co->dbname) {
						turnFreeRedisReply(redisCommand(rc, "select %s", co->dbname));
					}
					{
						redisReply *reply = (redisReply*)redisCommand(rc, "keys turn/*/allocation/*/status");
						if(reply) {
							secrets_list_t keys;
							size_t isz = 0;
							char s[513];

							init_secrets_list(&keys);

							if (reply->type == REDIS_REPLY_ERROR) {
								TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
							} else if (reply->type != REDIS_REPLY_ARRAY) {
								if (reply->type != REDIS_REPLY_NIL)
									TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
							} else {
								size_t i;
								for (i = 0; i < reply->elements; ++i) {
									add_to_secrets_list(&keys,reply->element[i]->str);
								}
							}

							for(isz=0;isz<keys.sz;++isz) {

								snprintf(s,sizeof(s),"del %s", keys.secrets[isz]);
								turnFreeRedisReply(redisCommand(rc, s));
							}

							clean_secrets_list(&keys);

							turnFreeRedisReply(reply);
						}
					}
					redisFree(rc);
				}
			}

			ret = redisLibeventAttach(base, co->host, co->port, co->password, atoi(co->dbname));

			if (!ret) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot initialize Redis DB connection\n");
			} else if (is_redis_asyncconn_good(ret) && !donot_print_connection_success) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Redis DB async connection to be used: %s\n", connection_string);
				donot_print_connection_success = 1;
			}
			RyconninfoFree(co);
		}
	}

	return ret;
}

static redisContext *get_redis_connection(void) {
	persistent_users_db_t *pud = get_persistent_users_db();

	redisContext *redisconnection = (redisContext*)pthread_getspecific(connection_key);

	if(redisconnection) {
		if(redisconnection->err) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot connect to redis, err=%d, flags=0x%lx\n", __FUNCTION__,(int)redisconnection->err,(unsigned long)redisconnection->flags);
			redisFree(redisconnection);
			redisconnection = NULL;
			(void) pthread_setspecific(connection_key, redisconnection);
		}
	}

	if (!redisconnection) {

		char *errmsg = NULL;
		Ryconninfo *co = RyconninfoParse(pud->userdb, &errmsg);
		if (!co) {
			if (errmsg) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error: %s\n", pud->userdb, errmsg);
				turn_free(errmsg,strlen(errmsg)+1);
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error\n", pud->userdb);
			}
		} else if (errmsg) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error: %s\n", pud->userdb, errmsg);
			turn_free(errmsg,strlen(errmsg)+1);
			RyconninfoFree(co);
		} else {
			char ip[256] = "\0";
			int port = DEFAULT_REDIS_PORT;
			if (co->host)
				STRCPY(ip,co->host);
			if (!ip[0])
				STRCPY(ip,"127.0.0.1");

			if (co->port)
				port = (int) (co->port);

			if (co->connect_timeout) {
				struct timeval tv;
				tv.tv_usec = 0;
				tv.tv_sec = (time_t) (co->connect_timeout);
				redisconnection = redisConnectWithTimeout(ip, port, tv);
			} else {
				redisconnection = redisConnect(ip, port);
			}

			if (redisconnection) {
				if(redisconnection->err) {
					if(redisconnection->errstr[0]) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis: %s\n",redisconnection->errstr);
					}
					redisFree(redisconnection);
					redisconnection = NULL;
				} else if (co->password) {
					void *reply = redisCommand(redisconnection, "AUTH %s", co->password);
					if(!reply) {
						if(redisconnection->err && redisconnection->errstr[0]) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis: %s\n",redisconnection->errstr);
						}
						redisFree(redisconnection);
						redisconnection = NULL;
					} else {
						turnFreeRedisReply(reply);
						if (co->dbname) {
							reply = redisCommand(redisconnection, "select %s", co->dbname);
							if(!reply) {
								if(redisconnection->err && redisconnection->errstr[0]) {
									TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis: %s\n",redisconnection->errstr);
								}
								redisFree(redisconnection);
								redisconnection = NULL;
							} else {
								turnFreeRedisReply(reply);
							}
						}
					}
				}
			}

			if (!redisconnection) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot initialize Redis DB connection\n");
			} else if (!donot_print_connection_success) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Redis DB sync connection success: %s\n", pud->userdb);
				donot_print_connection_success = 1;
			}

			RyconninfoFree(co);
		}
		if(redisconnection) {
			(void) pthread_setspecific(connection_key, redisconnection);
		}
	}

	return redisconnection;
}

static int set_redis_realm_opt(char *realm, const char* key, unsigned long *value)
{
	int found = 0;

	redisContext *rc = get_redis_connection();

	if(rc) {
		redisReply *rget = NULL;

		char s[1025];

		snprintf(s, sizeof(s), "get turn/realm/%s/%s", realm, key);

		rget = (redisReply *) redisCommand(rc, s);
		if (rget) {
			if (rget->type == REDIS_REPLY_ERROR)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
			else if (rget->type != REDIS_REPLY_STRING) {
				if (rget->type != REDIS_REPLY_NIL)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
			} else {
				lock_realms();
				*value = (unsigned long)atol(rget->str);
				unlock_realms();
				found = 1;
			}
			turnFreeRedisReply(rget);
		}
	}

	return found;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int redis_get_auth_secrets(secrets_list_t *sl, u08bits *realm)
{
	int ret = -1;
	redisContext *rc = get_redis_connection();
	if (rc) {
		redisReply *reply = (redisReply*) redisCommand(rc, "smembers turn/realm/%s/secret", (char*) realm);
		if (reply) {

			if (reply->type == REDIS_REPLY_ERROR)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
			else if (reply->type != REDIS_REPLY_ARRAY) {
				if (reply->type != REDIS_REPLY_NIL)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
			} else {
				size_t i;
				for (i = 0; i < reply->elements; ++i) {
					add_to_secrets_list(sl, reply->element[i]->str);
				}
			}

			ret = 0;

			turnFreeRedisReply(reply);
		}
	}
	return ret;
}
  
static int redis_get_user_key(u08bits *usname, u08bits *realm, hmackey_t key) {
  int ret = -1;
	redisContext * rc = get_redis_connection();
	if(rc) {
		char s[TURN_LONG_STRING_SIZE];
		snprintf(s,sizeof(s),"get turn/realm/%s/user/%s/key", (char*)realm, usname);
		redisReply *rget = (redisReply *)redisCommand(rc, s);
		if(rget) {
			if (rget->type == REDIS_REPLY_ERROR)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
			else if (rget->type != REDIS_REPLY_STRING) {
				if (rget->type != REDIS_REPLY_NIL)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
			} else {
				size_t sz = get_hmackey_size(SHATYPE_DEFAULT);
				if(strlen(rget->str)<sz*2) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key format: %s, user %s\n",rget->str,usname);
				} else if(convert_string_key_to_binary(rget->str, key, sz)<0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key: %s, user %s\n",rget->str,usname);
				} else {
					ret = 0;
				}
			}
			turnFreeRedisReply(rget);
		}
	}
  return ret;
}

static int redis_get_oauth_key(const u08bits *kid, oauth_key_data_raw *key) {
  int ret = -1;
  redisContext * rc = get_redis_connection();
  if(rc) {
	char s[TURN_LONG_STRING_SIZE];
	ns_bzero(key,sizeof(oauth_key_data_raw));
	STRCPY(key->kid,kid);
	snprintf(s,sizeof(s),"hgetall turn/oauth/kid/%s", (const char*)kid);
	redisReply *reply = (redisReply *)redisCommand(rc, s);
	if(reply) {
		if (reply->type == REDIS_REPLY_ERROR)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
		else if (reply->type != REDIS_REPLY_ARRAY) {
			if (reply->type != REDIS_REPLY_NIL)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
		} else if(reply->elements > 1) {
			size_t i;
			for (i = 0; i < (reply->elements)/2; ++i) {
				char *kw = reply->element[2*i]->str;
				char *val = reply->element[2*i+1]->str;
				if(kw) {
					if(!strcmp(kw,"as_rs_alg")) {
						STRCPY(key->as_rs_alg,val);
					} else if(!strcmp(kw,"realm")) {
						STRCPY(key->realm,val);
					} else if(!strcmp(kw,"ikm_key")) {
						STRCPY(key->ikm_key,val);
					} else if(!strcmp(kw,"timestamp")) {
						key->timestamp = (u64bits)strtoull(val,NULL,10);
					} else if(!strcmp(kw,"lifetime")) {
						key->lifetime = (u32bits)strtoul(val,NULL,10);
					}
				}
			}
			ret = 0;
		}
		turnFreeRedisReply(reply);
	}
  }
  return ret;
}
  
static int redis_set_user_key(u08bits *usname, u08bits *realm, const char *key) {
  int ret = -1;
	redisContext *rc = get_redis_connection();
	if(rc) {
		char statement[TURN_LONG_STRING_SIZE];
		snprintf(statement,sizeof(statement),"set turn/realm/%s/user/%s/key %s",(char*)realm,usname,key);
		turnFreeRedisReply(redisCommand(rc, statement));
		turnFreeRedisReply(redisCommand(rc, "save"));
		ret = 0;
	}
  return ret;
}

static int redis_set_oauth_key(oauth_key_data_raw *key) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if(rc) {
	char statement[TURN_LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement),"hmset turn/oauth/kid/%s ikm_key %s as_rs_alg %s timestamp %llu lifetime %lu realm %s",
			key->kid,key->ikm_key,key->as_rs_alg,(unsigned long long)key->timestamp,(unsigned long)key->lifetime,key->realm);
	turnFreeRedisReply(redisCommand(rc, statement));
	turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}
  
static int redis_del_user(u08bits *usname, u08bits *realm) {
  int ret = -1;
	redisContext *rc = get_redis_connection();
	if(rc) {
		char statement[TURN_LONG_STRING_SIZE];
		{
		  snprintf(statement,sizeof(statement),"del turn/realm/%s/user/%s/key",(char*)realm,usname);
		  turnFreeRedisReply(redisCommand(rc, statement));
		}

		turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
	}
  return ret;
}

static int redis_del_oauth_key(const u08bits *kid) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if(rc) {
	char statement[TURN_LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement),"del turn/oauth/kid/%s",(const char*)kid);
	turnFreeRedisReply(redisCommand(rc, statement));
	turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}
  
static int redis_list_users(u08bits *realm, secrets_list_t *users, secrets_list_t *realms)
{
	int ret = -1;
	redisContext *rc = get_redis_connection();

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	if(rc) {
		secrets_list_t keys;
		size_t isz = 0;

		init_secrets_list(&keys);

		redisReply *reply = NULL;

		{
			if(realm && realm[0]) {
				reply = (redisReply*)redisCommand(rc, "keys turn/realm/%s/user/*/key", (char*)realm);
			} else {
				reply = (redisReply*)redisCommand(rc, "keys turn/realm/*/user/*/key");
			}

			if(reply) {

				if (reply->type == REDIS_REPLY_ERROR)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
				else if (reply->type != REDIS_REPLY_ARRAY) {
					if (reply->type != REDIS_REPLY_NIL)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
				} else {
					size_t i;
					for (i = 0; i < reply->elements; ++i) {
						add_to_secrets_list(&keys,reply->element[i]->str);
					}
				}
				turnFreeRedisReply(reply);
			}
		}

		size_t rhsz=strlen("turn/realm/");
		size_t uhsz = strlen("user/");

		for(isz=0;isz<keys.sz;++isz) {
			char *s = keys.secrets[isz];

			char *sh = strstr(s,"turn/realm/");
			if(sh != s) continue;
			sh += rhsz;
			char* st = strchr(sh,'/');
			if(!st) continue;
			*st=0;
			char *sr = sh;
			++st;

			sh = strstr(st,"user/");
			if(sh != st) continue;
			sh += uhsz;
			st = strchr(sh,'/');
			if(!st) continue;
			*st=0;
			char *su = sh;

			if(users) {
				add_to_secrets_list(users,su);
				if(realms) {
					add_to_secrets_list(realms,sr);
				}
			} else {
				printf("%s[%s]\n", su, sr);
			}
		}

		clean_secrets_list(&keys);
		ret = 0;
	}
	return ret;
}

static int redis_list_oauth_keys(secrets_list_t *kids,secrets_list_t *teas,secrets_list_t *tss,secrets_list_t *lts,secrets_list_t *realms) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  secrets_list_t keys;
  size_t isz = 0;
  init_secrets_list(&keys);

  if(rc) {

	  redisReply *reply = NULL;

	  reply = (redisReply*)redisCommand(rc, "keys turn/oauth/kid/*");
	  if(reply) {

		if (reply->type == REDIS_REPLY_ERROR) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
		} else if (reply->type != REDIS_REPLY_ARRAY) {
			if (reply->type != REDIS_REPLY_NIL) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
			}
		} else {
			size_t i;
			for (i = 0; i < reply->elements; ++i) {
				add_to_secrets_list(&keys,reply->element[i]->str);
			}
		}
		turnFreeRedisReply(reply);
	}
  }

  for(isz=0;isz<keys.sz;++isz) {
	char *s = keys.secrets[isz];
	s += strlen("turn/oauth/kid/");
	oauth_key_data_raw key_;
	oauth_key_data_raw *key=&key_;
	if(redis_get_oauth_key((const u08bits*)s,key) == 0) {
		if(kids) {
			add_to_secrets_list(kids,key->kid);
			add_to_secrets_list(teas,key->as_rs_alg);
			add_to_secrets_list(realms,key->realm);
			{
				char ts[256];
				snprintf(ts,sizeof(ts)-1,"%llu",(unsigned long long)key->timestamp);
				add_to_secrets_list(tss,ts);
			}
			{
				char lt[256];
				snprintf(lt,sizeof(lt)-1,"%lu",(unsigned long)key->lifetime);
				add_to_secrets_list(lts,lt);
			}
		} else {
			printf("  kid=%s, ikm_key=%s, timestamp=%llu, lifetime=%lu, as_rs_alg=%s, realm=%s\n",
							key->kid, key->ikm_key, (unsigned long long)key->timestamp, (unsigned long)key->lifetime,
							key->as_rs_alg,key->realm);
		}
	}
  }

  clean_secrets_list(&keys);
  ret = 0;

  return ret;
}
  

static int redis_list_secrets(u08bits *realm, secrets_list_t *secrets, secrets_list_t *realms)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	donot_print_connection_success = 1;
	redisContext *rc = get_redis_connection();
	if (rc) {
		redisReply *reply = NULL;
		if (realm && realm[0]) {
			reply = (redisReply*) redisCommand(rc, "keys turn/realm/%s/secret", (char*) realm);
		} else {
			reply = (redisReply*) redisCommand(rc, "keys turn/realm/*/secret");
		}
		if (reply) {
			secrets_list_t keys;
			size_t isz = 0;
			char s[257];

			init_secrets_list(&keys);

			if (reply->type == REDIS_REPLY_ERROR)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
			else if (reply->type != REDIS_REPLY_ARRAY) {
				if (reply->type != REDIS_REPLY_NIL)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
			} else {
				size_t i;
				for (i = 0; i < reply->elements; ++i) {
					add_to_secrets_list(&keys, reply->element[i]->str);
				}
			}

			size_t rhsz=strlen("turn/realm/");

			for (isz = 0; isz < keys.sz; ++isz) {
				snprintf(s, sizeof(s), "smembers %s", keys.secrets[isz]);
				redisReply *rget = (redisReply *) redisCommand(rc, s);
				if (rget) {
					if (rget->type == REDIS_REPLY_ERROR) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
					} else if (rget->type == REDIS_REPLY_STRING) {
						printf("%s\n", rget->str);
					} else if (rget->type != REDIS_REPLY_ARRAY) {
						if (rget->type != REDIS_REPLY_NIL)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
					} else {

						char *s = keys.secrets[isz];

						char *sh = strstr(s,"turn/realm/");
						if(sh != s) continue;
						sh += rhsz;
						char* st = strchr(sh,'/');
						if(!st) continue;
						*st=0;
						const char *rval = sh;

						size_t i;
						for (i = 0; i < rget->elements; ++i) {
							const char *kval = rget->element[i]->str;
							if(secrets) {
								add_to_secrets_list(secrets,kval);
								if(realms) {
									if(rval && *rval) {
								   		add_to_secrets_list(realms,rval);
									} else {
										add_to_secrets_list(realms,(char*)realm);
									}
								}
							} else {
								printf("%s[%s]\n", kval, rval);
							}
						}
					}
				}
				turnFreeRedisReply(rget);
			}

			clean_secrets_list(&keys);

			turnFreeRedisReply(reply);
			ret = 0;
		}
	}
	return ret;
}
  

static int redis_del_secret(u08bits *secret, u08bits *realm)
{
	int ret = -1;
	donot_print_connection_success = 1;
	redisContext *rc = get_redis_connection();
	if (rc) {
		turnFreeRedisReply(redisCommand(rc, "srem turn/realm/%s/secret %s", (char*) realm, (char*) secret));
		turnFreeRedisReply(redisCommand(rc, "save"));
		ret = 0;
	}
	return ret;
}
  

static int redis_set_secret(u08bits *secret, u08bits *realm)
{
	int ret = -1;
	donot_print_connection_success = 1;
	redisContext *rc = get_redis_connection();
	if (rc) {
		char s[TURN_LONG_STRING_SIZE];

		redis_del_secret(secret, realm);

		snprintf(s, sizeof(s), "sadd turn/realm/%s/secret %s", (char*) realm, secret);

		turnFreeRedisReply(redisCommand(rc, s));
		turnFreeRedisReply(redisCommand(rc, "save"));
		ret = 0;
	}
	return ret;
}

static int redis_set_permission_ip(const char *kind, u08bits *realm, const char* ip, int del)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	donot_print_connection_success = 1;

	redisContext *rc = get_redis_connection();
	if (rc) {
		char s[TURN_LONG_STRING_SIZE];

		if(del) {
			snprintf(s, sizeof(s), "srem turn/realm/%s/%s-peer-ip %s", (char*) realm, kind, ip);
		} else {
			snprintf(s, sizeof(s), "sadd turn/realm/%s/%s-peer-ip %s", (char*) realm, kind, ip);
		}

		turnFreeRedisReply(redisCommand(rc, s));
		turnFreeRedisReply(redisCommand(rc, "save"));
		ret = 0;
	}
	return ret;
}
  
static int redis_add_origin(u08bits *origin, u08bits *realm) {
  int ret = -1;
	redisContext *rc = get_redis_connection();
	if(rc) {
		char s[TURN_LONG_STRING_SIZE];

		snprintf(s,sizeof(s),"set turn/origin/%s %s", (char*)origin, (char*)realm);

		turnFreeRedisReply(redisCommand(rc, s));
		turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
	}
  return ret;
}
  
static int redis_del_origin(u08bits *origin) {
  int ret = -1;
	redisContext *rc = get_redis_connection();
	if(rc) {
		char s[TURN_LONG_STRING_SIZE];

		snprintf(s,sizeof(s),"del turn/origin/%s", (char*)origin);

		turnFreeRedisReply(redisCommand(rc, s));
		turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
	}
  return ret;
}
  
static int redis_list_origins(u08bits *realm, secrets_list_t *origins, secrets_list_t *realms)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	donot_print_connection_success = 1;

	redisContext *rc = get_redis_connection();
	if(rc) {
		secrets_list_t keys;
		size_t isz = 0;

		init_secrets_list(&keys);

		redisReply *reply = NULL;

		{
			reply = (redisReply*)redisCommand(rc, "keys turn/origin/*");
			if(reply) {

				if (reply->type == REDIS_REPLY_ERROR)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
				else if (reply->type != REDIS_REPLY_ARRAY) {
					if (reply->type != REDIS_REPLY_NIL)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
				} else {
					size_t i;
					size_t offset = strlen("turn/origin/");
					for (i = 0; i < reply->elements; ++i) {
						add_to_secrets_list(&keys,reply->element[i]->str+offset);
					}
				}
				turnFreeRedisReply(reply);
			}
		}

		for(isz=0;isz<keys.sz;++isz) {

			char *o = keys.secrets[isz];

			reply = (redisReply*)redisCommand(rc, "get turn/origin/%s",o);
			if(reply) {

				if (reply->type == REDIS_REPLY_ERROR)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
				else if (reply->type != REDIS_REPLY_STRING) {
					if (reply->type != REDIS_REPLY_NIL)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
				} else {
					if(!(realm && realm[0] && strcmp((char*)realm,reply->str))) {
						if(origins) {
							add_to_secrets_list(origins,o);
							if(realms) {
								add_to_secrets_list(realms,reply->str);
							}
						} else {
							printf("%s ==>> %s\n",o,reply->str);
						}
					}
				}
				turnFreeRedisReply(reply);
			}
		}

		clean_secrets_list(&keys);
		ret = 0;
	}
	return ret;
}
  
static int redis_set_realm_option_one(u08bits *realm, unsigned long value, const char* opt) {
  int ret = -1;
	redisContext *rc = get_redis_connection();
	if(rc) {
		char s[TURN_LONG_STRING_SIZE];

		if(value>0)
			snprintf(s,sizeof(s),"set turn/realm/%s/%s %lu", (char*)realm, opt, (unsigned long)value);
		else
			snprintf(s,sizeof(s),"del turn/realm/%s/%s", (char*)realm, opt);

		turnFreeRedisReply(redisCommand(rc, s));
		turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
	}
  return ret;
}
  
static int redis_list_realm_options(u08bits *realm) {
  int ret = -1;
	donot_print_connection_success = 1;
	redisContext *rc = get_redis_connection();
	if(rc) {
		secrets_list_t keys;
		size_t isz = 0;

		init_secrets_list(&keys);

		redisReply *reply = NULL;

		{
			if(realm && realm[0]) {
				reply = (redisReply*)redisCommand(rc, "keys turn/realm/%s/*",realm);
			} else {
				reply = (redisReply*)redisCommand(rc, "keys turn/realm/*");
			}
			if(reply) {

				if (reply->type == REDIS_REPLY_ERROR)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
				else if (reply->type != REDIS_REPLY_ARRAY) {
					if (reply->type != REDIS_REPLY_NIL)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
				} else {
					size_t i;
					for (i = 0; i < reply->elements; ++i) {
						if(strstr(reply->element[i]->str,"/max-bps")||
							strstr(reply->element[i]->str,"/total-quota")||
							strstr(reply->element[i]->str,"/user-quota")) {
							add_to_secrets_list(&keys,reply->element[i]->str);
						}
					}
				}
				turnFreeRedisReply(reply);
			}
		}

		size_t offset = strlen("turn/realm/");

		for(isz=0;isz<keys.sz;++isz) {
			char *o = keys.secrets[isz];

			reply = (redisReply*)redisCommand(rc, "get %s",o);
			if(reply) {

				if (reply->type == REDIS_REPLY_ERROR)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
				else if (reply->type != REDIS_REPLY_STRING) {
					if (reply->type != REDIS_REPLY_NIL)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
				} else {
					printf("%s = %s\n",o+offset,reply->str);
				}
				turnFreeRedisReply(reply);
			}
		}

		clean_secrets_list(&keys);
    ret = 0;
	}
  return ret;
}
  
static void redis_auth_ping(void * rch) {
	redisContext *rc = get_redis_connection();
	if(rc) {
		turnFreeRedisReply(redisCommand(rc, "keys turn/origin/*"));
	}
	if(rch)
		send_message_to_redis((redis_context_handle)rch, "publish", "__XXX__", "__YYY__");
}
  


static int redis_get_ip_list(const char *kind, ip_range_list_t * list)
{
	int ret = -1;
	redisContext *rc = get_redis_connection();
	if (rc) {
		char statement[TURN_LONG_STRING_SIZE];
		const char* header = "turn/realm/";
		size_t header_len = strlen(header);
		snprintf(statement, sizeof(statement), "keys %s*/%s-peer-ip", header,kind);
		redisReply *reply = (redisReply*) redisCommand(rc, statement);
		if (reply) {
			secrets_list_t keys;
			size_t isz = 0;
			char s[257];

			init_secrets_list(&keys);

			if (reply->type == REDIS_REPLY_ERROR)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
			else if (reply->type != REDIS_REPLY_ARRAY) {
				if (reply->type != REDIS_REPLY_NIL)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
			} else {
				size_t i;
				for (i = 0; i < reply->elements; ++i) {
					add_to_secrets_list(&keys, reply->element[i]->str);
				}
			}

			for (isz = 0; isz < keys.sz; ++isz) {

				char *realm = NULL;

				snprintf(s, sizeof(s), "smembers %s", keys.secrets[isz]);

				redisReply *rget = (redisReply *) redisCommand(rc, s);

				char *ptr = ((char*)keys.secrets[isz])+header_len;
				char *sep = strstr(ptr, "/");
				if (sep) {
					*sep = 0;
					realm = ptr;
				}

				if (rget) {
					if (rget->type == REDIS_REPLY_ERROR) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
					} else if (rget->type == REDIS_REPLY_STRING) {
						add_ip_list_range(rget->str, realm, list);
					} else if (rget->type != REDIS_REPLY_ARRAY) {
						if (rget->type != REDIS_REPLY_NIL)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
					} else {
						size_t i;
						for (i = 0; i < rget->elements; ++i) {
							add_ip_list_range(rget->element[i]->str, realm, list);
						}
					}
					turnFreeRedisReply(rget);
				}

				if(sep) {
					*sep='/';
				}
			}

			clean_secrets_list(&keys);

			turnFreeRedisReply(reply);
			ret = 0;
		}
	}
	return ret;
}
  
static void redis_reread_realms(secrets_list_t * realms_list) {
	redisContext *rc = get_redis_connection();
	if (rc) {

		redisReply *reply = (redisReply*) redisCommand(rc, "keys turn/origin/*");
		if (reply) {

			ur_string_map *o_to_realm_new = ur_string_map_create(turn_free_simple);

			secrets_list_t keys;

			init_secrets_list(&keys);

			size_t isz = 0;

			char s[1025];

			if (reply->type == REDIS_REPLY_ERROR)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
			else if (reply->type != REDIS_REPLY_ARRAY) {
				if (reply->type != REDIS_REPLY_NIL)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
			} else {
				size_t i;
				for (i = 0; i < reply->elements; ++i) {
					add_to_secrets_list(&keys, reply->element[i]->str);
				}
			}

			size_t offset = strlen("turn/origin/");

			for (isz = 0; isz < keys.sz; ++isz) {
				char *origin = keys.secrets[isz] + offset;
				snprintf(s, sizeof(s), "get %s", keys.secrets[isz]);
				redisReply *rget = (redisReply *) redisCommand(rc, s);
				if (rget) {
					if (rget->type == REDIS_REPLY_ERROR)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
					else if (rget->type != REDIS_REPLY_STRING) {
						if (rget->type != REDIS_REPLY_NIL)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
					} else {
						get_realm(rget->str);
						ur_string_map_value_type value = turn_strdup(rget->str);
						ur_string_map_put(o_to_realm_new, (const ur_string_map_key_type) origin, value);
					}
					turnFreeRedisReply(rget);
				}
			}

			clean_secrets_list(&keys);

			update_o_to_realm(o_to_realm_new);

			turnFreeRedisReply(reply);
		}

		{
			size_t i = 0;
			size_t rlsz = 0;

			lock_realms();
			rlsz = realms_list->sz;
			unlock_realms();

			for (i = 0; i<rlsz; ++i) {
				char *realm = realms_list->secrets[i];
				realm_params_t* rp = get_realm(realm);
				{
					unsigned long value = 0;
					if(!set_redis_realm_opt(realm,"max-bps",&value)) {
						lock_realms();
						rp->options.perf_options.max_bps = turn_params.max_bps;
						unlock_realms();
					} else {
						rp->options.perf_options.max_bps = (band_limit_t)value;
					}
				}
				{
					unsigned long value = 0;
					if(!set_redis_realm_opt(realm,"total-quota",&value)) {
						lock_realms();
						rp->options.perf_options.total_quota = turn_params.total_quota;
						unlock_realms();
					} else {
						rp->options.perf_options.total_quota = (vint)value;
					}
				}
				{
					unsigned long value = 0;
					if(!set_redis_realm_opt(realm,"user-quota",&value)) {
						lock_realms();
						rp->options.perf_options.user_quota = turn_params.user_quota;
						unlock_realms();
					} else {
						rp->options.perf_options.user_quota = (vint)value;
					}
				}
			}
		}
	}
}

/////////////////////////////////////////////////////

static int redis_get_admin_user(const u08bits *usname, u08bits *realm, password_t pwd)
{
	int ret = -1;
	redisContext * rc = get_redis_connection();
	if(rc) {
		char s[TURN_LONG_STRING_SIZE];
		realm[0]=0;
		pwd[0]=0;
		snprintf(s,sizeof(s),"hgetall turn/admin_user/%s", (const char*)usname);
		redisReply *reply = (redisReply *)redisCommand(rc, s);
		if(reply) {
			if (reply->type == REDIS_REPLY_ERROR)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
			else if (reply->type != REDIS_REPLY_ARRAY) {
				if (reply->type != REDIS_REPLY_NIL)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
			} else if(reply->elements > 1) {
				size_t i;
				for (i = 0; i < (reply->elements)/2; ++i) {
					char *kw = reply->element[2*i]->str;
					char *val = reply->element[2*i+1]->str;
					if(kw) {
						if(!strcmp(kw,"realm")) {
							strncpy((char*)realm,val,STUN_MAX_REALM_SIZE);
						} else if(!strcmp(kw,"password")) {
							strncpy((char*)pwd,val,STUN_MAX_PWD_SIZE);
							ret = 0;
						}
					}
				}
			}
			turnFreeRedisReply(reply);
		}
	  }
	  return ret;
}

static int redis_set_admin_user(const u08bits *usname, const u08bits *realm, const password_t pwd)
{
  int ret = -1;
  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  if(rc) {
	char statement[TURN_LONG_STRING_SIZE];
	if(realm[0]) {
		snprintf(statement,sizeof(statement),"hmset turn/admin_user/%s realm %s password %s",usname,realm,pwd);
	} else {
		snprintf(statement,sizeof(statement),"hmset turn/admin_user/%s password %s",usname,pwd);
	}
	turnFreeRedisReply(redisCommand(rc, statement));
	turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_del_admin_user(const u08bits *usname) {
  int ret = -1;
  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  if(rc) {
	char statement[TURN_LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement),"del turn/admin_user/%s",(const char*)usname);
	turnFreeRedisReply(redisCommand(rc, statement));
	turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_list_admin_users(int no_print)
{
  int ret = -1;
  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  secrets_list_t keys;
  size_t isz = 0;
  init_secrets_list(&keys);

  if(rc) {

	  redisReply *reply = NULL;

	  reply = (redisReply*)redisCommand(rc, "keys turn/admin_user/*");
	  if(reply) {

		if (reply->type == REDIS_REPLY_ERROR) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
		} else if (reply->type != REDIS_REPLY_ARRAY) {
			if (reply->type != REDIS_REPLY_NIL) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
			}
		} else {
			size_t i;
			for (i = 0; i < reply->elements; ++i) {
				add_to_secrets_list(&keys,reply->element[i]->str);
			}
		}
		turnFreeRedisReply(reply);
	}
  }

  ret = 0;
  for(isz=0;isz<keys.sz;++isz) {
	char *s = keys.secrets[isz];
	s += strlen("turn/admin_user/");
	u08bits realm[STUN_MAX_REALM_SIZE];
	password_t pwd;
	if(redis_get_admin_user((const u08bits*)s,realm,pwd) == 0) {
		++ret;
		if(!no_print) {
			if(realm[0]) {
				printf("%s[%s]\n",s,realm);
			} else {
				printf("%s\n",s);
			}
		}
	}
  }

  clean_secrets_list(&keys);

  return ret;
}

//////////////////////////////////////////////////////

static const turn_dbdriver_t driver = {
  &redis_get_auth_secrets,
  &redis_get_user_key,
  &redis_set_user_key,
  &redis_del_user,
  &redis_list_users,
  &redis_list_secrets,
  &redis_del_secret,
  &redis_set_secret,
  &redis_add_origin,
  &redis_del_origin,
  &redis_list_origins,
  &redis_set_realm_option_one,
  &redis_list_realm_options,
  &redis_auth_ping,
  &redis_get_ip_list,
  &redis_set_permission_ip,
  &redis_reread_realms,
  &redis_set_oauth_key,
  &redis_get_oauth_key,
  &redis_del_oauth_key,
  &redis_list_oauth_keys,
  &redis_get_admin_user,
  &redis_set_admin_user,
  &redis_del_admin_user,
  &redis_list_admin_users
};

const turn_dbdriver_t * get_redis_dbdriver(void) {
  return &driver;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

#else

const turn_dbdriver_t * get_redis_dbdriver(void) {
  return NULL;
}

#endif
