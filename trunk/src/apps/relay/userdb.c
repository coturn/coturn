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

#if !defined(TURN_NO_PQ)
#include <libpq-fe.h>
#endif

#if !defined(TURN_NO_MYSQL)
#include <mysql.h>
#endif

#if !defined(TURN_NO_HIREDIS)
#include "hiredis_libevent2.h"
#include <hiredis/hiredis.h>
#endif

#include <pthread.h>

#include <signal.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "userdb.h"
#include "mainrelay.h"

#include "ns_turn_utils.h"

#include "ns_turn_server.h"
#include "ns_turn_maps.h"

#include "apputils.h"

//////////// USER DB //////////////////////////////

#define LONG_STRING_SIZE (TURN_LONG_STRING_SIZE)

static int donot_print_connection_success=0;

//////////// REALM //////////////

static realm_params_t *default_realm_params_ptr = NULL;
static const realm_params_t _default_realm_params =
{
  1,
  {
	"\0", /* name */
    {0,0,0}
  },
  {0,NULL}
};

static ur_string_map *realms = NULL;
static turn_mutex o_to_realm_mutex;
static ur_string_map *o_to_realm = NULL;
static secrets_list_t realms_list;

void create_new_realm(char* name)
{
	realm_params_t *ret = NULL;

	if((name == NULL)||(name[0]==0)) {
		if(default_realm_params_ptr) {
			return;
		}
		/* init everything: */
		TURN_MUTEX_INIT_RECURSIVE(&o_to_realm_mutex);
		init_secrets_list(&realms_list);
		o_to_realm = ur_string_map_create(free);
		default_realm_params_ptr = (realm_params_t*)malloc(sizeof(realm_params_t));
		ns_bcopy(&_default_realm_params,default_realm_params_ptr,sizeof(realm_params_t));
		realms = ur_string_map_create(NULL);
		ur_string_map_lock(realms);
		ret = default_realm_params_ptr;
	} else {
		ur_string_map_value_type value = 0;
		ur_string_map_lock(realms);
		if (!ur_string_map_get(realms, (const ur_string_map_key_type) name, &value)) {
			ret = (realm_params_t*)turn_malloc(sizeof(realm_params_t));
			ns_bcopy(default_realm_params_ptr,ret,sizeof(realm_params_t));
			STRCPY(ret->options.name,name);
			value = (ur_string_map_value_type)ret;
			ur_string_map_put(realms, (const ur_string_map_key_type) name, value);
			add_to_secrets_list(&realms_list, name);
		} else {
			ur_string_map_unlock(realms);
			return;
		}
	}

	ret->status.alloc_counters =  ur_string_map_create(NULL);
	ur_string_map_unlock(realms);
}

void get_default_realm_options(realm_options_t* ro)
{
	if(ro) {
		ur_string_map_lock(realms);
		ns_bcopy(&(default_realm_params_ptr->options),ro,sizeof(realm_options_t));
		ur_string_map_unlock(realms);
	}
}

void set_default_realm_name(char *realm) {
	ur_string_map_lock(realms);
	ur_string_map_value_type value = (ur_string_map_value_type)default_realm_params_ptr;
	STRCPY(default_realm_params_ptr->options.name,realm);
	ur_string_map_put(realms, (ur_string_map_key_type)default_realm_params_ptr->options.name, value);
	add_to_secrets_list(&realms_list, realm);
	ur_string_map_unlock(realms);
}

realm_params_t* get_realm(char* name)
{
	if(name && name[0]) {
		ur_string_map_lock(realms);
		ur_string_map_value_type value = 0;
		ur_string_map_key_type key = (ur_string_map_key_type)name;
		if (ur_string_map_get(realms, key, &value)) {
			ur_string_map_unlock(realms);
			return (realm_params_t*)value;
		} else {
			realm_params_t *ret = (realm_params_t*)turn_malloc(sizeof(realm_params_t));
			ns_bcopy(default_realm_params_ptr,ret,sizeof(realm_params_t));
			STRCPY(ret->options.name,name);
			value = (ur_string_map_value_type)ret;
			ur_string_map_put(realms, key, value);
			ret->status.alloc_counters =  ur_string_map_create(NULL);
			add_to_secrets_list(&realms_list, name);
			ur_string_map_unlock(realms);
			return ret;
		}
	}

	return default_realm_params_ptr;
}

int get_realm_data(char* name, realm_params_t* rp)
{
	ur_string_map_lock(realms);
	ns_bcopy(get_realm(name),rp,sizeof(realm_params_t));
	ur_string_map_unlock(realms);
	return 0;
}

void get_realm_options_by_origin(char *origin, realm_options_t* ro)
{
	ur_string_map_value_type value = 0;
	TURN_MUTEX_LOCK(&o_to_realm_mutex);
	if (ur_string_map_get(o_to_realm, (ur_string_map_key_type) origin, &value) && value) {
		char *realm = strdup((char*)value);
		TURN_MUTEX_UNLOCK(&o_to_realm_mutex);
		realm_params_t rp;
		get_realm_data(realm, &rp);
		ns_bcopy(&(rp.options),ro,sizeof(realm_options_t));
		free(realm);
	} else {
		TURN_MUTEX_UNLOCK(&o_to_realm_mutex);
		get_default_realm_options(ro);
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
	ur_string_map_lock(realms);
	realm_params_t* rp = get_realm(realm);
	rp->options.perf_options.total_quota = value;
	ur_string_map_unlock(realms);
	return ret;
}

int change_user_quota(char *realm, int value)
{
	int ret = value;
	ur_string_map_lock(realms);
	realm_params_t* rp = get_realm(realm);
	rp->options.perf_options.user_quota = value;
	ur_string_map_unlock(realms);
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
		sl->secrets = (char**)realloc(sl->secrets,(sizeof(char*)*(sl->sz+1)));
		sl->secrets[sl->sz] = strdup(elem);
		sl->sz += 1;
	}
}

/////////// USER DB CHECK //////////////////

static persistent_users_db_t* get_persistent_users_db(void)
{
	return &(turn_params.default_users_db.persistent_users_db);
}

static int convert_string_key_to_binary(char* keysource, hmackey_t key, size_t sz) {
	{
		char is[3];
		size_t i;
		unsigned int v;
		is[2]=0;
		for(i=0;i<sz;i++) {
			is[0]=keysource[i*2];
			is[1]=keysource[i*2+1];
			sscanf(is,"%02x",&v);
			key[i]=(unsigned char)v;
		}
		return 0;
	}
}


static int is_pqsql_userdb(void)
{
#if !defined(TURN_NO_PQ)
	return (turn_params.default_users_db.userdb_type == TURN_USERDB_TYPE_PQ);
#else
	return 0;
#endif
}

static int is_mysql_userdb(void)
{
#if !defined(TURN_NO_MYSQL)
	return (turn_params.default_users_db.userdb_type == TURN_USERDB_TYPE_MYSQL);
#else
	return 0;
#endif
}

static int is_redis_userdb(void)
{
#if !defined(TURN_NO_HIREDIS)
	return (turn_params.default_users_db.userdb_type == TURN_USERDB_TYPE_REDIS);
#else
	return 0;
#endif
}

#if !defined(TURN_NO_PQ)
static PGconn *get_pqdb_connection(void)
{

	if(!is_pqsql_userdb())
		return NULL;

	persistent_users_db_t *pud = get_persistent_users_db();

	PGconn *pqdbconnection = (PGconn*)(pud->connection);
	if(pqdbconnection) {
		ConnStatusType status = PQstatus(pqdbconnection);
		if(status != CONNECTION_OK) {
			PQfinish(pqdbconnection);
			pqdbconnection = NULL;
		}
	}
	if(!pqdbconnection) {
		char *errmsg=NULL;
		PQconninfoOption *co = PQconninfoParse(pud->userdb, &errmsg);
		if(!co) {
			if(errmsg) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open PostgreSQL DB connection <%s>, connection string format error: %s\n",pud->userdb,errmsg);
				turn_free(errmsg,strlen(errmsg)+1);
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open PostgreSQL DB connection: <%s>, unknown connection string format error\n",pud->userdb);
			}
		} else {
			PQconninfoFree(co);
			if(errmsg)
				turn_free(errmsg,strlen(errmsg)+1);
			pqdbconnection = PQconnectdb(pud->userdb);
			if(!pqdbconnection) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open PostgreSQL DB connection: <%s>, runtime error\n",pud->userdb);
			} else {
				ConnStatusType status = PQstatus(pqdbconnection);
				if(status != CONNECTION_OK) {
					PQfinish(pqdbconnection);
					pqdbconnection = NULL;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open PostgreSQL DB connection: <%s>, runtime error\n",pud->userdb);
				} else if(!donot_print_connection_success){
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "PostgreSQL DB connection success: %s\n",pud->userdb);
				}
			}
		}
		pud->connection = pqdbconnection;
	}
	return pqdbconnection;
}

#endif

#if !defined(TURN_NO_MYSQL)

struct _Myconninfo {
	char *host;
	char *dbname;
	char *user;
	char *password;
	unsigned int port;
	unsigned int connect_timeout;
};

typedef struct _Myconninfo Myconninfo;

static void MyconninfoFree(Myconninfo *co) {
	if(co) {
		if(co->host) turn_free(co->host,strlen(co->host)+1);
		if(co->dbname) turn_free(co->dbname, strlen(co->dbname)+1);
		if(co->user) turn_free(co->user, strlen(co->user)+1);
		if(co->password) turn_free(co->password, strlen(co->password)+1);
		ns_bzero(co,sizeof(Myconninfo));
	}
}

static Myconninfo *MyconninfoParse(char *userdb, char **errmsg)
{
	Myconninfo *co = (Myconninfo*)turn_malloc(sizeof(Myconninfo));
	ns_bzero(co,sizeof(Myconninfo));
	if(userdb) {
		char *s0=strdup(userdb);
		char *s = s0;

		while(s && *s) {

			while(*s && (*s==' ')) ++s;
			char *snext = strstr(s," ");
			if(snext) {
				*snext = 0;
				++snext;
			}

			char* seq = strstr(s,"=");
			if(!seq) {
				MyconninfoFree(co);
				co = NULL;
				if(errmsg) {
					*errmsg = strdup(s);
				}
				break;
			}

			*seq = 0;
			if(!strcmp(s,"host"))
				co->host = strdup(seq+1);
			else if(!strcmp(s,"ip"))
				co->host = strdup(seq+1);
			else if(!strcmp(s,"addr"))
				co->host = strdup(seq+1);
			else if(!strcmp(s,"ipaddr"))
				co->host = strdup(seq+1);
			else if(!strcmp(s,"hostaddr"))
				co->host = strdup(seq+1);
			else if(!strcmp(s,"dbname"))
				co->dbname = strdup(seq+1);
			else if(!strcmp(s,"db"))
				co->dbname = strdup(seq+1);
			else if(!strcmp(s,"database"))
				co->dbname = strdup(seq+1);
			else if(!strcmp(s,"user"))
				co->user = strdup(seq+1);
			else if(!strcmp(s,"uname"))
				co->user = strdup(seq+1);
			else if(!strcmp(s,"name"))
				co->user = strdup(seq+1);
			else if(!strcmp(s,"username"))
				co->user = strdup(seq+1);
			else if(!strcmp(s,"password"))
				co->password = strdup(seq+1);
			else if(!strcmp(s,"pwd"))
				co->password = strdup(seq+1);
			else if(!strcmp(s,"passwd"))
				co->password = strdup(seq+1);
			else if(!strcmp(s,"secret"))
				co->password = strdup(seq+1);
			else if(!strcmp(s,"port"))
				co->port = (unsigned int)atoi(seq+1);
			else if(!strcmp(s,"p"))
				co->port = (unsigned int)atoi(seq+1);
			else if(!strcmp(s,"connect_timeout"))
				co->connect_timeout = (unsigned int)atoi(seq+1);
			else if(!strcmp(s,"timeout"))
				co->connect_timeout = (unsigned int)atoi(seq+1);
			else {
				MyconninfoFree(co);
				co = NULL;
				if(errmsg) {
					*errmsg = strdup(s);
				}
				break;
			}

			s = snext;
		}

		turn_free(s0, strlen(s0)+1);
	}

	if(!(co->dbname))
		co->dbname=strdup("0");
	if(!(co->host))
		co->host=strdup("127.0.0.1");
	if(!(co->user))
		co->user=strdup("");
	if(!(co->password))
		co->password=strdup("");

	return co;
}

static MYSQL *get_mydb_connection(void)
{

	if(!is_mysql_userdb())
		return NULL;

	persistent_users_db_t *pud = get_persistent_users_db();

	MYSQL *mydbconnection = (MYSQL*)(pud->connection);

	if(mydbconnection) {
		if(mysql_ping(mydbconnection)) {
			mysql_close(mydbconnection);
			mydbconnection=NULL;
		}
	}

	if(!mydbconnection) {
		char *errmsg=NULL;
		Myconninfo *co=MyconninfoParse(pud->userdb, &errmsg);
		if(!co) {
			if(errmsg) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open MySQL DB connection <%s>, connection string format error: %s\n",pud->userdb,errmsg);
				turn_free(errmsg,strlen(errmsg)+1);
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open MySQL DB connection <%s>, connection string format error\n",pud->userdb);
			}
		} else if(errmsg) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open MySQL DB connection <%s>, connection string format error: %s\n",pud->userdb,errmsg);
			turn_free(errmsg,strlen(errmsg)+1);
			MyconninfoFree(co);
		} else if(!(co->dbname)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL Database name is not provided: <%s>\n",pud->userdb);
			MyconninfoFree(co);
		} else {
			mydbconnection = mysql_init(NULL);
			if(!mydbconnection) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot initialize MySQL DB connection\n");
			} else {
				if(co->connect_timeout)
					mysql_options(mydbconnection,MYSQL_OPT_CONNECT_TIMEOUT,&(co->connect_timeout));
				MYSQL *conn = mysql_real_connect(mydbconnection, co->host, co->user, co->password, co->dbname, co->port, NULL, CLIENT_IGNORE_SIGPIPE);
				if(!conn) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open MySQL DB connection: <%s>, runtime error\n",pud->userdb);
					mysql_close(mydbconnection);
					mydbconnection=NULL;
				} else if(mysql_select_db(mydbconnection, co->dbname)) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot connect to MySQL DB: %s\n",co->dbname);
					mysql_close(mydbconnection);
					mydbconnection=NULL;
				} else if(!donot_print_connection_success) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "MySQL DB connection success: %s\n",pud->userdb);
				}
			}
			MyconninfoFree(co);
		}
		pud->connection = mydbconnection;
	}
	return mydbconnection;
}

#endif


#if !defined(TURN_NO_HIREDIS)

static void turnFreeRedisReply(void *reply)
{
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
		if(co->dbname) turn_free(co->dbname, strlen(co->username)+1);
		if(co->password) turn_free(co->password, strlen(co->password)+1);
		ns_bzero(co,sizeof(Ryconninfo));
	}
}

static Ryconninfo *RyconninfoParse(const char *userdb, char **errmsg)
{
	Ryconninfo *co = (Ryconninfo*) turn_malloc(sizeof(Ryconninfo));
	ns_bzero(co,sizeof(Ryconninfo));
	if (userdb) {
		char *s0 = strdup(userdb);
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
					*errmsg = strdup(s);
				}
				break;
			}

			*seq = 0;
			if (!strcmp(s, "host"))
				co->host = strdup(seq + 1);
			else if (!strcmp(s, "ip"))
				co->host = strdup(seq + 1);
			else if (!strcmp(s, "addr"))
				co->host = strdup(seq + 1);
			else if (!strcmp(s, "ipaddr"))
				co->host = strdup(seq + 1);
			else if (!strcmp(s, "hostaddr"))
				co->host = strdup(seq + 1);
			else if (!strcmp(s, "dbname"))
				co->dbname = strdup(seq + 1);
			else if (!strcmp(s, "db"))
				co->dbname = strdup(seq + 1);
			else if (!strcmp(s, "database"))
				co->dbname = strdup(seq + 1);
			else if (!strcmp(s, "user"))
				;
			else if (!strcmp(s, "uname"))
				;
			else if (!strcmp(s, "name"))
				;
			else if (!strcmp(s, "username"))
				;
			else if (!strcmp(s, "password"))
				co->password = strdup(seq + 1);
			else if (!strcmp(s, "pwd"))
				co->password = strdup(seq + 1);
			else if (!strcmp(s, "passwd"))
				co->password = strdup(seq + 1);
			else if (!strcmp(s, "secret"))
				co->password = strdup(seq + 1);
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
					*errmsg = strdup(s);
				}
				break;
			}

			s = snext;
		}

		turn_free(s0, strlen(s0)+1);
	}

	if(!(co->dbname))
		co->dbname=strdup("0");
	if(!(co->host))
		co->host=strdup("127.0.0.1");
	if(!(co->password))
		co->password=strdup("");

	return co;
}

redis_context_handle get_redis_async_connection(struct event_base *base, const char* connection_string, int delete_keys)
{
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
			}
			RyconninfoFree(co);
		}
	}

	return ret;
}

static redisContext *get_redis_connection(void)
{
	if(!is_redis_userdb())
		return NULL;

	persistent_users_db_t *pud = get_persistent_users_db();

	redisContext *redisconnection = (redisContext*)(pud->connection);

	if(redisconnection) {
		if(redisconnection->err) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot connect to redis, err=%d, flags=0x%x\n", __FUNCTION__,(int)redisconnection->err,(unsigned long)redisconnection->flags);
			redisFree(redisconnection);
			pud->connection = NULL;
			redisconnection = NULL;
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

			if (!redisconnection) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot initialize Redis DB connection\n");
			} else {
				if (co->password) {
					turnFreeRedisReply(redisCommand(redisconnection, "AUTH %s", co->password));
				}
				if (co->dbname) {
					turnFreeRedisReply(redisCommand(redisconnection, "select %s", co->dbname));
				}
				if (!donot_print_connection_success) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Redis DB sync connection success: %s\n", pud->userdb);
				}
			}
			RyconninfoFree(co);
		}
		pud->connection = redisconnection;

		pud = get_persistent_users_db();

		redisconnection = (redisContext*)(pud->connection);
	}

	return redisconnection;
}

#endif

static int get_auth_secrets(secrets_list_t *sl, u08bits *realm)
{
	int ret = -1;

	clean_secrets_list(sl);

	if(get_secrets_list_size(&turn_params.default_users_db.ram_db.static_auth_secrets)) {
		size_t i = 0;
		for(i=0;i<get_secrets_list_size(&turn_params.default_users_db.ram_db.static_auth_secrets);++i) {
			add_to_secrets_list(sl,get_secrets_list_elem(&turn_params.default_users_db.ram_db.static_auth_secrets,i));
		}
		ret=0;
	}

#if !defined(TURN_NO_PQ)
	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		char statement[LONG_STRING_SIZE];
		snprintf(statement,sizeof(statement)-1,"select value from turn_secret where realm='%s'",realm);
		PGresult *res = PQexec(pqc, statement);

		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		} else {
			int i = 0;
			for(i=0;i<PQntuples(res);i++) {
				char *kval = PQgetvalue(res,i,0);
				if(kval) {
					add_to_secrets_list(sl,kval);
				}
			}
			ret = 0;
		}

		if(res) {
			PQclear(res);
		}
	}
#endif

#if !defined(TURN_NO_MYSQL)
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[LONG_STRING_SIZE];
		snprintf(statement,sizeof(statement)-1,"select value from turn_secret where realm='%s'",realm);
		int res = mysql_query(myc, statement);
		if(res) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
		} else {
			MYSQL_RES *mres = mysql_store_result(myc);
			if(!mres) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else if(mysql_field_count(myc)==1) {
				for(;;) {
					MYSQL_ROW row = mysql_fetch_row(mres);
					if(!row) {
						break;
					} else {
						if(row[0]) {
							unsigned long *lengths = mysql_fetch_lengths(mres);
							if(lengths) {
								size_t sz = lengths[0];
								char auth_secret[LONG_STRING_SIZE];
								ns_bcopy(row[0],auth_secret,sz);
								auth_secret[sz]=0;
								add_to_secrets_list(sl,auth_secret);
							}
						}
					}
				}
				ret = 0;
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
#endif

#if !defined(TURN_NO_HIREDIS)
	redisContext *rc = get_redis_connection();
	if(rc) {
		redisReply *reply = (redisReply*)redisCommand(rc, "keys turn/realm/%s/secret/*", (char*)realm);
		if(reply) {

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
					add_to_secrets_list(&keys,reply->element[i]->str);
				}
			}

			for(isz=0;isz<keys.sz;++isz) {
				snprintf(s,sizeof(s),"get %s", keys.secrets[isz]);
				redisReply *rget = (redisReply *)redisCommand(rc, s);
				if(rget) {
					if (rget->type == REDIS_REPLY_ERROR)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
					else if (rget->type != REDIS_REPLY_STRING) {
						if (rget->type != REDIS_REPLY_NIL)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
					} else {
						add_to_secrets_list(sl,rget->str);
					}
					turnFreeRedisReply(rget);
				}
			}

			clean_secrets_list(&keys);

			ret = 0;

			turnFreeRedisReply(reply);
		}
	}
#endif

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
	if(turn_params.use_auth_secret_with_timestamp) {
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
					usname = strdup(usname);
					*col=turn_params.rest_api_separator;
					return usname;
				}
			}
		}
	}

	return strdup(usname);
}

/*
 * Long-term mechanism password retrieval
 */
int get_user_key(u08bits *usname, u08bits *realm, hmackey_t key, ioa_network_buffer_handle nbh)
{
	int ret = -1;

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
			st_password_t pwdtmp;

			hmac[0] = 0;

			stun_attr_ref sar = stun_attr_get_first_by_type_str(ioa_network_buffer_data(nbh),
							ioa_network_buffer_get_size(nbh),
							STUN_ATTRIBUTE_MESSAGE_INTEGRITY);
			if (!sar)
				return -1;

			int sarlen = stun_attr_get_len(sar);
			switch(sarlen) {
			case SHA1SIZEBYTES:
				if(turn_params.shatype != SHATYPE_SHA1)
					return -1;
				hmac_len = SHA1SIZEBYTES;
				break;
			case SHA256SIZEBYTES:
				if(turn_params.shatype != SHATYPE_SHA256)
					return -1;
				hmac_len = SHA256SIZEBYTES;
				break;
			default:
				return -1;
			};

			for(sll=0;sll<get_secrets_list_size(&sl);++sll) {

				const char* secret = get_secrets_list_elem(&sl,sll);

				if(secret) {
					if(stun_calculate_hmac(usname, strlen((char*)usname), (const u08bits*)secret, strlen(secret), hmac, &hmac_len, turn_params.shatype)>=0) {
						size_t pwd_length = 0;
						char *pwd = base64_encode(hmac,hmac_len,&pwd_length);

						if(pwd) {
							if(pwd_length<1) {
								turn_free(pwd,strlen(pwd)+1);
							} else {
								if(stun_produce_integrity_key_str((u08bits*)usname, realm, (u08bits*)pwd, key, turn_params.shatype)>=0) {

									if(stun_check_message_integrity_by_key_str(TURN_CREDENTIALS_LONG_TERM,
										ioa_network_buffer_data(nbh),
										ioa_network_buffer_get_size(nbh),
										key,
										pwdtmp,
										turn_params.shatype,NULL)>0) {

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
	} else {
		ur_string_map_lock(turn_params.default_users_db.ram_db.dynamic_accounts);
		if(ur_string_map_get(turn_params.default_users_db.ram_db.dynamic_accounts, (ur_string_map_key_type)usname, &ukey)) {
			ret = 0;
		}
		ur_string_map_unlock(turn_params.default_users_db.ram_db.dynamic_accounts);
	}
	ur_string_map_unlock(turn_params.default_users_db.ram_db.static_accounts);

	if(ret==0) {
		size_t sz = get_hmackey_size(turn_params.shatype);
		ns_bcopy(ukey,key,sz);
		return 0;
	}

#if !defined(TURN_NO_PQ)
	{
		PGconn * pqc = get_pqdb_connection();
		if(pqc) {
			char statement[LONG_STRING_SIZE];
			snprintf(statement,sizeof(statement),"select hmackey from turnusers_lt where name='%s' and realm='%s'",usname,realm);
			PGresult *res = PQexec(pqc, statement);

			if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK) || (PQntuples(res)!=1)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
			} else {
				char *kval = PQgetvalue(res,0,0);
				int len = PQgetlength(res,0,0);
				if(kval) {
					size_t sz = get_hmackey_size(turn_params.shatype);
					if(((size_t)len<sz*2)||(strlen(kval)<sz*2)) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key format: %s, user %s\n",kval,usname);
					} else if(convert_string_key_to_binary(kval, key, sz)<0) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key: %s, user %s\n",kval,usname);
					} else {
						ret = 0;
					}
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong hmackey data for user %s: NULL\n",usname);
				}
			}

			if(res)
				PQclear(res);

		}
	}
#endif

#if !defined(TURN_NO_MYSQL)
	{
		MYSQL * myc = get_mydb_connection();
		if(myc) {
			char statement[LONG_STRING_SIZE];
			snprintf(statement,sizeof(statement),"select hmackey from turnusers_lt where name='%s' and realm='%s'",usname,realm);
			int res = mysql_query(myc, statement);
			if(res) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else {
				MYSQL_RES *mres = mysql_store_result(myc);
				if(!mres) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
				} else if(mysql_field_count(myc)!=1) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown error retrieving MySQL DB information: %s\n",statement);
				} else {
					MYSQL_ROW row = mysql_fetch_row(mres);
					if(row && row[0]) {
						unsigned long *lengths = mysql_fetch_lengths(mres);
						if(lengths) {
							size_t sz = get_hmackey_size(turn_params.shatype)*2;
							if(lengths[0]<sz) {
								TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key format: string length=%d (must be %d): user %s\n",(int)lengths[0],(int)sz,usname);
							} else {
								char kval[sizeof(hmackey_t)+sizeof(hmackey_t)+1];
								ns_bcopy(row[0],kval,sz);
								kval[sz]=0;
								if(convert_string_key_to_binary(kval, key, sz/2)<0) {
									TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key: %s, user %s\n",kval,usname);
								} else {
									ret = 0;
								}
							}
						}
					}
				}

				if(mres)
					mysql_free_result(mres);
			}
		}
	}
#endif

#if !defined(TURN_NO_HIREDIS)
	{
		redisContext * rc = get_redis_connection();
		if(rc) {
			char s[LONG_STRING_SIZE];
			snprintf(s,sizeof(s),"get turn/realm/%s/user/%s/key", (char*)realm, usname);
			redisReply *rget = (redisReply *)redisCommand(rc, s);
			if(rget) {
				if (rget->type == REDIS_REPLY_ERROR)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
				else if (rget->type != REDIS_REPLY_STRING) {
					if (rget->type != REDIS_REPLY_NIL)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
				} else {
					size_t sz = get_hmackey_size(turn_params.shatype);
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
			if(ret != 0) {
				snprintf(s,sizeof(s),"get turn/realm/%s/user/%s/password", (char*)realm, usname);
				rget = (redisReply *)redisCommand(rc, s);
				if(rget) {
					if (rget->type == REDIS_REPLY_ERROR)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
					else if (rget->type != REDIS_REPLY_STRING) {
						if (rget->type != REDIS_REPLY_NIL)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
					} else {
						if(stun_produce_integrity_key_str((u08bits*)usname, realm, (u08bits*)rget->str, key, turn_params.shatype)>=0) {
							ret = 0;
						}
					}
					turnFreeRedisReply(rget);
				}
			}
		}
	}
#endif

	return ret;
}

/*
 * Short-term mechanism password retrieval
 */
int get_user_pwd(u08bits *usname, st_password_t pwd)
{
	int ret = -1;

	UNUSED_ARG(pwd);

	char statement[LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement),"select password from turnusers_st where name='%s'",usname);

	{
#if !defined(TURN_NO_PQ)
	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		PGresult *res = PQexec(pqc, statement);

		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK) || (PQntuples(res)!=1)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		} else {
			char *kval = PQgetvalue(res,0,0);
			if(kval) {
				strncpy((char*)pwd,kval,sizeof(st_password_t));
				ret = 0;
			} else {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong password data for user %s: NULL\n",usname);
			}
		}

		if(res) {
			PQclear(res);
		}
	}
#endif
#if !defined(TURN_NO_MYSQL)
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		int res = mysql_query(myc, statement);
		if(res) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
		} else {
			MYSQL_RES *mres = mysql_store_result(myc);
			if(!mres) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else if(mysql_field_count(myc)!=1) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown error retrieving MySQL DB information: %s\n",statement);
			} else {
				MYSQL_ROW row = mysql_fetch_row(mres);
				if(row && row[0]) {
					unsigned long *lengths = mysql_fetch_lengths(mres);
					if(lengths) {
						if(lengths[0]<1) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong password data for user %s, size in MySQL DB is zero(0)\n",usname);
						} else {
							ns_bcopy(row[0],pwd,lengths[0]);
							pwd[lengths[0]]=0;
							ret = 0;
						}
					}
				}
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
#endif
#if !defined(TURN_NO_HIREDIS)
	{
		redisContext * rc = get_redis_connection();
		if(rc) {
			char s[LONG_STRING_SIZE];
			snprintf(s,sizeof(s),"get turn/user/%s/password", usname);
			redisReply *rget = (redisReply *)redisCommand(rc, s);
			if(rget) {
				if (rget->type == REDIS_REPLY_ERROR)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
				else if (rget->type != REDIS_REPLY_STRING) {
					if (rget->type != REDIS_REPLY_NIL)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
				} else {
					strncpy((char*)pwd,rget->str,SHORT_TERM_PASSWORD_SIZE);
					pwd[SHORT_TERM_PASSWORD_SIZE]=0;
					ret = 0;
				}
				turnFreeRedisReply(rget);
			}
		}
	}
#endif
	}

	return ret;
}

u08bits *start_user_check(turnserver_id id, turn_credential_type ct, u08bits *usname, u08bits *realm, get_username_resume_cb resume, ioa_net_data *in_buffer, u64bits ctxkey, int *postpone_reply)
{
	*postpone_reply = 1;

	struct auth_message am;
	ns_bzero(&am,sizeof(struct auth_message));
	am.id = id;
	am.ct = ct;
	STRCPY(am.username,usname);
	STRCPY(am.realm,realm);
	am.resume_func = resume;
	memcpy(&(am.in_buffer),in_buffer,sizeof(ioa_net_data));
	in_buffer->nbh = NULL;
	am.ctxkey = ctxkey;

	send_auth_message_to_auth_server(&am);

	return NULL;
}

int check_new_allocation_quota(u08bits *user, u08bits *realm)
{
	int ret = 0;
	if (user) {
		u08bits *username = (u08bits*)get_real_username((char*)user);
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
		turn_free(username,strlen(username)+1);
		ur_string_map_unlock(rp->status.alloc_counters);
	}
	return ret;
}

void release_allocation_quota(u08bits *user, u08bits *realm)
{
	if (user) {
		u08bits *username = (u08bits*)get_real_username((char*)user);
		realm_params_t *rp = get_realm((char*)realm);
		ur_string_map_lock(rp->status.alloc_counters);
		ur_string_map_value_type value = 0;
		ur_string_map_get(rp->status.alloc_counters, (ur_string_map_key_type) username, &value);
		if (value) {
			value = (ur_string_map_value_type)(((size_t)value) - 1);
			ur_string_map_put(rp->status.alloc_counters, (ur_string_map_key_type) username, value);
		}
		if (rp->status.total_current_allocs)
			--(rp->status.total_current_allocs);
		ur_string_map_unlock(rp->status.alloc_counters);
		turn_free(username, strlen(username)+1);
	}
}

//////////////////////////////////

void read_userdb_file(int to_print)
{
	static char *full_path_to_userdb_file = NULL;
	static int first_read = 1;
	static turn_time_t mtime = 0;

	if(turn_params.default_users_db.userdb_type != TURN_USERDB_TYPE_FILE)
		return;
	if(turn_params.use_auth_secret_with_timestamp)
		return;

	FILE *f = NULL;

	persistent_users_db_t *pud = get_persistent_users_db();

	if(full_path_to_userdb_file) {
		struct stat sb;
		if(stat(full_path_to_userdb_file,&sb)<0) {
			perror("File statistics");
		} else {
			turn_time_t newmtime = (turn_time_t)(sb.st_mtime);
			if(mtime == newmtime)
				return;
			mtime = newmtime;

		}
	}

	if (!full_path_to_userdb_file)
		full_path_to_userdb_file = find_config_file(pud->userdb, first_read);

	if (full_path_to_userdb_file)
		f = fopen(full_path_to_userdb_file, "r");

	if (f) {

		char sbuf[LONG_STRING_SIZE];

		ur_string_map_lock(turn_params.default_users_db.ram_db.dynamic_accounts);

		ur_string_map_clean(turn_params.default_users_db.ram_db.dynamic_accounts);

		for (;;) {
			char *s = fgets(sbuf, sizeof(sbuf) - 1, f);
			if (!s)
				break;
			s = skip_blanks(s);
			if (s[0] == '#')
				continue;
			if (!s[0])
				continue;
			size_t slen = strlen(s);
			while (slen && (s[slen - 1] == 10 || s[slen - 1] == 13))
				s[--slen] = 0;
			if (slen) {
				if(to_print) {
					char* sc=strstr(s,":");
					if(sc)
						sc[0]=0;
					printf("%s\n",s);
				} else {
					add_user_account(s,1);
				}
			}
		}

		ur_string_map_unlock(turn_params.default_users_db.ram_db.dynamic_accounts);

		fclose(f);

	} else if (first_read) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: Cannot find userdb file: %s: going without flat file user database.\n", pud->userdb);
	} 

	first_read = 0;
}

int add_user_account(char *user, int dynamic)
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
				size_t sz = get_hmackey_size(turn_params.shatype);
				if(strlen(keysource)<sz*2) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key format: %s\n",s);
				} if(convert_string_key_to_binary(keysource, *key, sz)<0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key: %s\n",s);
					free(usname);
					free(key);
					return -1;
				}
			} else {
				//this is only for default realm
				stun_produce_integrity_key_str((u08bits*)usname, (u08bits*)get_realm(NULL)->options.name, (u08bits*)s, *key, turn_params.shatype);
			}
			if(dynamic) {
				ur_string_map_lock(turn_params.default_users_db.ram_db.dynamic_accounts);
				ur_string_map_put(turn_params.default_users_db.ram_db.dynamic_accounts, (ur_string_map_key_type)usname, (ur_string_map_value_type)*key);
				ur_string_map_unlock(turn_params.default_users_db.ram_db.dynamic_accounts);
			} else {
				ur_string_map_lock(turn_params.default_users_db.ram_db.static_accounts);
				ur_string_map_put(turn_params.default_users_db.ram_db.static_accounts, (ur_string_map_key_type)usname, (ur_string_map_value_type)*key);
				ur_string_map_unlock(turn_params.default_users_db.ram_db.static_accounts);
			}
			turn_params.default_users_db.ram_db.users_number++;
			free(usname);
			return 0;
		}
	}

	return -1;
}

////////////////// Admin /////////////////////////

static int list_users(int is_st, u08bits *realm)
{
	donot_print_connection_success = 1;

	if(is_pqsql_userdb()){
#if !defined(TURN_NO_PQ)
		char statement[LONG_STRING_SIZE];
		PGconn *pqc = get_pqdb_connection();
		if(pqc) {
			if(is_st) {
			  snprintf(statement,sizeof(statement),"select name from turnusers_st order by name");
			} else if(realm && realm[0]) {
			  snprintf(statement,sizeof(statement),"select name from turnusers_lt where realm='%s' order by name",realm);
			} else {
			  snprintf(statement,sizeof(statement),"select name from turnusers_lt order by name");
			}
			PGresult *res = PQexec(pqc, statement);
			if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
			} else {
				int i = 0;
				for(i=0;i<PQntuples(res);i++) {
					char *kval = PQgetvalue(res,i,0);
					if(kval) {
						printf("%s\n",kval);
					}
				}
			}
			if(res) {
				PQclear(res);
			}
		}
#endif
	} else if(is_mysql_userdb()){
#if !defined(TURN_NO_MYSQL)
		char statement[LONG_STRING_SIZE];
		MYSQL * myc = get_mydb_connection();
		if(myc) {
			if(is_st) {
			  snprintf(statement,sizeof(statement),"select name from turnusers_st order by name");
			} else if(realm && realm[0]) {
			  snprintf(statement,sizeof(statement),"select name from turnusers_lt where realm='%s' order by name",realm);
			} else {
			  snprintf(statement,sizeof(statement),"select name from turnusers_lt order by name");
			}
			int res = mysql_query(myc, statement);
			if(res) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else {
				MYSQL_RES *mres = mysql_store_result(myc);
				if(!mres) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
				} else if(mysql_field_count(myc)!=1) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown error retrieving MySQL DB information: %s\n",statement);
				} else {
					for(;;) {
						MYSQL_ROW row = mysql_fetch_row(mres);
						if(!row) {
							break;
						} else {
							if(row[0]) {
								printf("%s\n",row[0]);
							}
						}
					}
				}

				if(mres)
					mysql_free_result(mres);
			}
		}
#endif
	} else if(is_redis_userdb()) {
#if !defined(TURN_NO_HIREDIS)
		redisContext *rc = get_redis_connection();
		if(rc) {
			secrets_list_t keys;
			size_t isz = 0;

			init_secrets_list(&keys);

			redisReply *reply = NULL;

			if(!is_st) {

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

				if(realm && realm[0]) {
					reply = (redisReply*)redisCommand(rc, "keys turn/realm/%s/user/*/password", (char*)realm);
				} else {
					reply = (redisReply*)redisCommand(rc, "keys turn/realm/*/user/*/password");
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
			} else {

				reply = (redisReply*)redisCommand(rc, "keys turn/user/*/password");
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

			for(isz=0;isz<keys.sz;++isz) {
				char *s = keys.secrets[isz];
				char *sh = strstr(s,"/user/");
				if(sh) {
					sh += 6;
					char* st = strchr(sh,'/');
					if(st)
						*st=0;
					printf("%s\n",sh);
				}
			}

			clean_secrets_list(&keys);
		}
#endif
	} else if(!is_st) {

		read_userdb_file(1);

	}

	return 0;
}

static int show_secret(u08bits *realm)
{
	char statement[LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement)-1,"select value from turn_secret where realm='%s'",realm);

	donot_print_connection_success=1;

	must_set_admin_realm(realm);

	if(is_pqsql_userdb()){
#if !defined(TURN_NO_PQ)
		PGconn *pqc = get_pqdb_connection();
		if(pqc) {
			PGresult *res = PQexec(pqc, statement);
			if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
			} else {
				int i = 0;
				for(i=0;i<PQntuples(res);i++) {
					char *kval = PQgetvalue(res,i,0);
					if(kval) {
						printf("%s\n",kval);
					}
				}
			}
			if(res) {
				PQclear(res);
			}
		}
#endif
	} else if(is_mysql_userdb()){
#if !defined(TURN_NO_MYSQL)
		MYSQL * myc = get_mydb_connection();
		if(myc) {
			int res = mysql_query(myc, statement);
			if(res) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else {
				MYSQL_RES *mres = mysql_store_result(myc);
				if(!mres) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
				} else if(mysql_field_count(myc)!=1) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown error retrieving MySQL DB information: %s\n",statement);
				} else {
					for(;;) {
						MYSQL_ROW row = mysql_fetch_row(mres);
						if(!row) {
							break;
						} else {
							if(row[0]) {
								printf("%s\n",row[0]);
							}
						}
					}
				}

				if(mres)
					mysql_free_result(mres);
			}
		}
#endif
	} else if(is_redis_userdb()) {
#if !defined(TURN_NO_HIREDIS)
		redisContext *rc = get_redis_connection();
		if(rc) {
			redisReply *reply = NULL;
			if(realm && realm[0]) {
				reply = (redisReply*)redisCommand(rc, "keys turn/realm/%s/secret/*",(char*)realm);
			} else {
				reply = (redisReply*)redisCommand(rc, "keys turn/realm/*/secret/*");
			}
			if(reply) {
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
						add_to_secrets_list(&keys,reply->element[i]->str);
					}
				}

				for(isz=0;isz<keys.sz;++isz) {
					snprintf(s,sizeof(s),"get %s", keys.secrets[isz]);
					redisReply *rget = (redisReply *)redisCommand(rc, s);
					if(rget) {
						if (rget->type == REDIS_REPLY_ERROR)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
						else if (rget->type != REDIS_REPLY_STRING) {
							if (rget->type != REDIS_REPLY_NIL)
								TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
						} else {
							printf("%s\n",rget->str);
						}
					}
					turnFreeRedisReply(rget);
				}

				clean_secrets_list(&keys);

				turnFreeRedisReply(reply);
			}
		}
#endif
	}

	return 0;
}

static int del_secret(u08bits *secret, u08bits *realm) {

	UNUSED_ARG(secret);

	must_set_admin_realm(realm);

	donot_print_connection_success=1;

	if (is_pqsql_userdb()) {
#if !defined(TURN_NO_PQ)
		char statement[LONG_STRING_SIZE];
		PGconn *pqc = get_pqdb_connection();
		if (pqc) {
			if(!secret || (secret[0]==0))
			  snprintf(statement,sizeof(statement),"delete from turn_secret where realm='%s'",realm);
			else
			  snprintf(statement,sizeof(statement),"delete from turn_secret where value='%s' and realm='%s'",secret,realm);

			PGresult *res = PQexec(pqc, statement);
			if (res) {
				PQclear(res);
			}
		}
#endif
	} else if (is_mysql_userdb()) {
#if !defined(TURN_NO_MYSQL)
		char statement[LONG_STRING_SIZE];
		MYSQL * myc = get_mydb_connection();
		if (myc) {
			if(!secret || (secret[0]==0))
			  snprintf(statement,sizeof(statement),"delete from turn_secret where realm='%s'",realm);
			else
			  snprintf(statement,sizeof(statement),"delete from turn_secret where value='%s' and realm='%s'",secret,realm);
			mysql_query(myc, statement);
		}
#endif
	} else if(is_redis_userdb()) {
#if !defined(TURN_NO_HIREDIS)
		redisContext *rc = get_redis_connection();
		if(rc) {
			redisReply *reply = (redisReply*)redisCommand(rc, "keys turn/realm/%s/secret/*", (char*)realm);
			if(reply) {
				secrets_list_t keys;
				size_t isz = 0;
				char s[LONG_STRING_SIZE];

				init_secrets_list(&keys);

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

				for(isz=0;isz<keys.sz;++isz) {
					if(!secret || (secret[0]==0)) {
						snprintf(s,sizeof(s),"del %s", keys.secrets[isz]);
						turnFreeRedisReply(redisCommand(rc, s));
					} else {
						snprintf(s,sizeof(s),"get %s", keys.secrets[isz]);
						redisReply *rget = (redisReply *)redisCommand(rc, s);
						if(rget) {
							if (rget->type == REDIS_REPLY_ERROR)
								TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
							else if (rget->type != REDIS_REPLY_STRING) {
								if (rget->type != REDIS_REPLY_NIL)
									TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
							} else {
								if(!strcmp((char*)secret,rget->str)) {
									snprintf(s,sizeof(s),"del %s", keys.secrets[isz]);
									turnFreeRedisReply(redisCommand(rc, s));
								}
							}
							turnFreeRedisReply(rget);
						}
					}
				}

				turnFreeRedisReply(redisCommand(rc, "save"));

				clean_secrets_list(&keys);

				turnFreeRedisReply(reply);
			}
		}
#endif
	}

	return 0;
}

static int set_secret(u08bits *secret, u08bits *realm) {

	if(!secret || (secret[0]==0))
		return 0;

	must_set_admin_realm(realm);

	donot_print_connection_success = 1;

	del_secret(secret, realm);

	if (is_pqsql_userdb()) {
#if !defined(TURN_NO_PQ)
		char statement[LONG_STRING_SIZE];
		PGconn *pqc = get_pqdb_connection();
		if (pqc) {
		  snprintf(statement,sizeof(statement),"insert into turn_secret (realm,value) values('%s','%s')",realm,secret);
		  PGresult *res = PQexec(pqc, statement);
		  if (!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
		    TURN_LOG_FUNC(
				  TURN_LOG_LEVEL_ERROR,
				  "Error inserting/updating secret key information: %s\n",
				  PQerrorMessage(pqc));
		  }
		  if (res) {
		    PQclear(res);
		  }
		}
#endif
	} else if (is_mysql_userdb()) {
#if !defined(TURN_NO_MYSQL)
		char statement[LONG_STRING_SIZE];
		MYSQL * myc = get_mydb_connection();
		if (myc) {
		  snprintf(statement,sizeof(statement),"insert into turn_secret (realm,value) values('%s','%s')",realm,secret);
		  int res = mysql_query(myc, statement);
		  if (res) {
		    TURN_LOG_FUNC(
				  TURN_LOG_LEVEL_ERROR,
				  "Error inserting/updating secret key information: %s\n",
				  mysql_error(myc));
		  }
		}
#endif
	} else if(is_redis_userdb()) {
#if !defined(TURN_NO_HIREDIS)
		redisContext *rc = get_redis_connection();
		if(rc) {
			char s[LONG_STRING_SIZE];

			del_secret(secret, realm);

			snprintf(s,sizeof(s),"set turn/realm/%s/secret/%lu %s", (char*)realm, (unsigned long)turn_time(), secret);

			turnFreeRedisReply(redisCommand(rc, s));
			turnFreeRedisReply(redisCommand(rc, "save"));
		}
#endif
	}

	return 0;
}

static int add_origin(u08bits *origin0, u08bits *realm)
{
	UNUSED_ARG(realm);
	UNUSED_ARG(origin0);
	char origin[STUN_MAX_ORIGIN_SIZE+1];
	get_canonic_origin((char*)origin0, origin, sizeof(origin)-1);
#if !defined(TURN_NO_PQ)
	if(is_pqsql_userdb()) {
		char statement[LONG_STRING_SIZE];
		PGconn *pqc = get_pqdb_connection();
		if(pqc) {
			snprintf(statement,sizeof(statement),"insert into turn_origin_to_realm (origin,realm) values('%s','%s')",origin,realm);
			PGresult *res = PQexec(pqc, statement);
			if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting origin information: %s\n",PQerrorMessage(pqc));
			}
			if(res) {
				PQclear(res);
			}
		}
	}
#endif

#if !defined(TURN_NO_MYSQL)
	if (is_mysql_userdb()) {
		char statement[LONG_STRING_SIZE];
		MYSQL * myc = get_mydb_connection();
		if (myc) {
			snprintf(statement,sizeof(statement),"insert into turn_origin_to_realm (origin,realm) values('%s','%s')",origin,realm);
			int res = mysql_query(myc, statement);
			if (res) {
				TURN_LOG_FUNC(
				  TURN_LOG_LEVEL_ERROR,
				  "Error inserting origin information: %s\n",
				  mysql_error(myc));
			}
		}
	}
#endif

#if !defined(TURN_NO_HIREDIS)
	if(is_redis_userdb()) {
		redisContext *rc = get_redis_connection();
		if(rc) {
			char s[LONG_STRING_SIZE];

			snprintf(s,sizeof(s),"set turn/origin/%s %s", (char*)origin, (char*)realm);

			turnFreeRedisReply(redisCommand(rc, s));
			turnFreeRedisReply(redisCommand(rc, "save"));
		}
	}
#endif
	return 0;
}

static int del_origin(u08bits *origin0)
{
	UNUSED_ARG(origin0);
	char origin[STUN_MAX_ORIGIN_SIZE+1];
	get_canonic_origin((char*)origin0, origin, sizeof(origin)-1);
#if !defined(TURN_NO_PQ)
	if(is_pqsql_userdb()) {
		char statement[LONG_STRING_SIZE];
		PGconn *pqc = get_pqdb_connection();
		if(pqc) {
			snprintf(statement,sizeof(statement),"delete from turn_origin_to_realm where origin='%s'",origin);
			PGresult *res = PQexec(pqc, statement);
			if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error deleting origin information: %s\n",PQerrorMessage(pqc));
			}
			if(res) {
				PQclear(res);
			}
		}
	}
#endif

#if !defined(TURN_NO_MYSQL)
	if (is_mysql_userdb()) {
		char statement[LONG_STRING_SIZE];
		MYSQL * myc = get_mydb_connection();
		if (myc) {
			snprintf(statement,sizeof(statement),"delete from turn_origin_to_realm where origin='%s'",origin);
			int res = mysql_query(myc, statement);
			if (res) {
				TURN_LOG_FUNC(
				  TURN_LOG_LEVEL_ERROR,
				  "Error deleting origin information: %s\n",
				  mysql_error(myc));
			}
		}
	}
#endif

#if !defined(TURN_NO_HIREDIS)
	if(is_redis_userdb()) {
		redisContext *rc = get_redis_connection();
		if(rc) {
			char s[LONG_STRING_SIZE];

			snprintf(s,sizeof(s),"del turn/origin/%s", (char*)origin);

			turnFreeRedisReply(redisCommand(rc, s));
			turnFreeRedisReply(redisCommand(rc, "save"));
		}
	}
#endif
	return 0;
}

static int list_origins(u08bits *realm)
{
	donot_print_connection_success = 1;

	if(is_pqsql_userdb()){
#if !defined(TURN_NO_PQ)
		char statement[LONG_STRING_SIZE];
		PGconn *pqc = get_pqdb_connection();
		if(pqc) {
			if(realm && realm[0]) {
			  snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm where realm='%s' order by origin",realm);
			} else {
			  snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm order by origin,realm");
			}
			PGresult *res = PQexec(pqc, statement);
			if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
			} else {
				int i = 0;
				for(i=0;i<PQntuples(res);i++) {
					char *oval = PQgetvalue(res,i,0);
					if(oval) {
						char *rval = PQgetvalue(res,i,1);
						if(rval) {
							printf("%s ==>> %s\n",oval,rval);
						}
					}
				}
			}
			if(res) {
				PQclear(res);
			}
		}
#endif
	} else if(is_mysql_userdb()){
#if !defined(TURN_NO_MYSQL)
		char statement[LONG_STRING_SIZE];
		MYSQL * myc = get_mydb_connection();
		if(myc) {
			if(realm && realm[0]) {
				snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm where realm='%s' order by origin",realm);
			} else {
				snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm order by origin,realm");
			}
			int res = mysql_query(myc, statement);
			if(res) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else {
				MYSQL_RES *mres = mysql_store_result(myc);
				if(!mres) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
				} else if(mysql_field_count(myc)!=2) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown error retrieving MySQL DB information: %s\n",statement);
				} else {
					for(;;) {
						MYSQL_ROW row = mysql_fetch_row(mres);
						if(!row) {
							break;
						} else {
							if(row[0] && row[1]) {
								printf("%s ==>> %s\n",row[0],row[1]);
							}
						}
					}
				}

				if(mres)
					mysql_free_result(mres);
			}
		}
#endif
	} else if(is_redis_userdb()) {
#if !defined(TURN_NO_HIREDIS)
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
							printf("%s ==>> %s\n",o,reply->str);
						}
					}
					turnFreeRedisReply(reply);
				}
			}

			clean_secrets_list(&keys);
		}
#endif
	}

	return 0;
}

static int set_realm_option_one(u08bits *realm, vint value, const char* opt)
{
	UNUSED_ARG(realm);
	UNUSED_ARG(value);
	UNUSED_ARG(opt);
	if(value<0)
		return 0;
#if !defined(TURN_NO_PQ)
	if(is_pqsql_userdb()) {
		char statement[LONG_STRING_SIZE];
		PGconn *pqc = get_pqdb_connection();
		if(pqc) {
			{
				snprintf(statement,sizeof(statement),"delete from turn_realm_option where realm='%s' and opt='%s'",realm,opt);
				PGresult *res = PQexec(pqc, statement);
				if(res) {
					PQclear(res);
				}
			}
			if(value>0) {
				snprintf(statement,sizeof(statement),"insert into turn_realm_option (realm,opt,value) values('%s','%s','%d')",realm,opt,(int)value);
				PGresult *res = PQexec(pqc, statement);
				if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting realm option information: %s\n",PQerrorMessage(pqc));
				}
				if(res) {
					PQclear(res);
				}
			}
		}
	}
#endif

#if !defined(TURN_NO_MYSQL)
	if (is_mysql_userdb()) {
		char statement[LONG_STRING_SIZE];
		MYSQL * myc = get_mydb_connection();
		if (myc) {
			{
				snprintf(statement,sizeof(statement),"delete from turn_realm_option where realm='%s' and opt='%s'",realm,opt);
				mysql_query(myc, statement);
			}
			if(value>0) {
				snprintf(statement,sizeof(statement),"insert into turn_realm_option (realm,opt,value) values('%s','%s','%d')",realm,opt,(int)value);
				int res = mysql_query(myc, statement);
				if (res) {
					TURN_LOG_FUNC(
								TURN_LOG_LEVEL_ERROR,
								"Error inserting realm option information: %s\n",
								mysql_error(myc));
				}
			}
		}
	}
#endif

#if !defined(TURN_NO_HIREDIS)
	if(is_redis_userdb()) {
		redisContext *rc = get_redis_connection();
		if(rc) {
			char s[LONG_STRING_SIZE];

			if(value>0)
				snprintf(s,sizeof(s),"set turn/realm/%s/%s %d", (char*)realm, opt, (int)value);
			else
				snprintf(s,sizeof(s),"del turn/realm/%s/%s", (char*)realm, opt);

			turnFreeRedisReply(redisCommand(rc, s));
			turnFreeRedisReply(redisCommand(rc, "save"));
		}
	}
#endif
	return 0;
}

static int set_realm_option(u08bits *realm, perf_options_t *po)
{
	set_realm_option_one(realm,po->max_bps,"max-bps");
	set_realm_option_one(realm,po->user_quota,"user-quota");
	set_realm_option_one(realm,po->total_quota,"total-quota");
	return 0;
}

static int list_realm_options(u08bits *realm)
{
	donot_print_connection_success = 1;

	if(is_pqsql_userdb()){
#if !defined(TURN_NO_PQ)
		char statement[LONG_STRING_SIZE];
		PGconn *pqc = get_pqdb_connection();
		if(pqc) {
			if(realm && realm[0]) {
				snprintf(statement,sizeof(statement),"select realm,opt,value from turn_realm_option where realm='%s' order by realm,opt",realm);
			} else {
				snprintf(statement,sizeof(statement),"select realm,opt,value from turn_realm_option order by realm,opt");
			}
			PGresult *res = PQexec(pqc, statement);
			if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
			} else {
				int i = 0;
				for(i=0;i<PQntuples(res);i++) {
					char *rval = PQgetvalue(res,i,0);
					if(rval) {
						char *oval = PQgetvalue(res,i,1);
						if(oval) {
							char *vval = PQgetvalue(res,i,2);
							if(vval) {
								printf("%s[%s]=%s\n",oval,rval,vval);
							}
						}
					}
				}
			}
			if(res) {
				PQclear(res);
			}
		}
#endif
	} else if(is_mysql_userdb()){
#if !defined(TURN_NO_MYSQL)
		char statement[LONG_STRING_SIZE];
		MYSQL * myc = get_mydb_connection();
		if(myc) {
			if(realm && realm[0]) {
				snprintf(statement,sizeof(statement),"select realm,opt,value from turn_realm_option where realm='%s' order by realm,opt",realm);
			} else {
				snprintf(statement,sizeof(statement),"select realm,opt,value from turn_realm_option order by realm,opt");
			}
			int res = mysql_query(myc, statement);
			if(res) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else {
				MYSQL_RES *mres = mysql_store_result(myc);
				if(!mres) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
				} else if(mysql_field_count(myc)!=3) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown error retrieving MySQL DB information: %s\n",statement);
				} else {
					for(;;) {
						MYSQL_ROW row = mysql_fetch_row(mres);
						if(!row) {
							break;
						} else {
							if(row[0] && row[1] && row[2]) {
								printf("%s[%s]=%s\n",row[1],row[0],row[2]);
							}
						}
					}
				}

				if(mres)
					mysql_free_result(mres);
			}
		}
#endif
	} else if(is_redis_userdb()) {
#if !defined(TURN_NO_HIREDIS)
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
		}
#endif
	}

	return 0;
}

int adminuser(u08bits *user, u08bits *realm, u08bits *pwd, u08bits *secret, u08bits *origin,
				TURNADMIN_COMMAND_TYPE ct, int is_st,
				perf_options_t *po)
{
	hmackey_t key;
	char skey[sizeof(hmackey_t)*2+1];

	donot_print_connection_success = 1;

	st_password_t passwd;

	if(ct == TA_LIST_USERS) {
		return list_users(is_st, realm);
	}

	if(ct == TA_LIST_ORIGINS) {
		return list_origins(realm);
	}

	if(ct == TA_SHOW_SECRET) {
		return show_secret(realm);
	}

	if(ct == TA_SET_SECRET) {
		return set_secret(secret, realm);
	}

	if(ct == TA_DEL_SECRET) {
		return del_secret(secret, realm);
	}

	if(ct == TA_ADD_ORIGIN) {
		must_set_admin_origin(origin);
		must_set_admin_realm(realm);
		return add_origin(origin,realm);
	}

	if(ct == TA_DEL_ORIGIN) {
		must_set_admin_origin(origin);
		return del_origin(origin);
	}

	if(ct == TA_SET_REALM_OPTION) {
		must_set_admin_realm(realm);
		if(!(po && (po->max_bps>=0 || po->total_quota>=0 || po->user_quota>=0))) {
			fprintf(stderr, "The operation cannot be completed: a realm option must be set.\n");
			exit(-1);
		}
		return set_realm_option(realm,po);
	}

	if(ct == TA_LIST_REALM_OPTIONS) {
		return list_realm_options(realm);
	}

	must_set_admin_user(user);

	if(ct != TA_DELETE_USER) {

		must_set_admin_pwd(pwd);

		if(is_st) {
			strncpy((char*)passwd,(char*)pwd,sizeof(st_password_t));
		} else {
			stun_produce_integrity_key_str(user, realm, pwd, key, turn_params.shatype);
			size_t i = 0;
			size_t sz = get_hmackey_size(turn_params.shatype);
			int maxsz = (int)(sz*2)+1;
			char *s=skey;
			for(i=0;(i<sz) && (maxsz>2);i++) {
			  snprintf(s,(size_t)(sz*2),"%02x",(unsigned int)key[i]);
			  maxsz-=2;
			  s+=2;
			}
			skey[sz*2]=0;
		}
	}

	if(ct == TA_PRINT_KEY) {

		if(!is_st) {
			printf("0x%s\n",skey);
		}

	} else if(is_pqsql_userdb()){

#if !defined(TURN_NO_PQ)

		if(!is_st) {
			must_set_admin_realm(realm);
		}

		char statement[LONG_STRING_SIZE];
		PGconn *pqc = get_pqdb_connection();
		if(pqc) {
			if(ct == TA_DELETE_USER) {
				if(is_st) {
				  snprintf(statement,sizeof(statement),"delete from turnusers_st where name='%s'",user);
				} else {
				  snprintf(statement,sizeof(statement),"delete from turnusers_lt where name='%s' and realm='%s'",user,realm);
				}
				PGresult *res = PQexec(pqc, statement);
				if(res) {
					PQclear(res);
				}
			}

			if(ct == TA_UPDATE_USER) {
				if(is_st) {
				  snprintf(statement,sizeof(statement),"insert into turnusers_st values('%s','%s')",user,passwd);
				} else {
				  snprintf(statement,sizeof(statement),"insert into turnusers_lt (realm,name,hmackey) values('%s','%s','%s')",realm,user,skey);
				}
				PGresult *res = PQexec(pqc, statement);
				if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
					if(res) {
						PQclear(res);
					}
					if(is_st) {
					  snprintf(statement,sizeof(statement),"update turnusers_st set password='%s' where name='%s'",passwd,user);
					} else {
					  snprintf(statement,sizeof(statement),"update turnusers_lt set hmackey='%s' where name='%s' and realm='%s'",skey,user,realm);
					}
					res = PQexec(pqc, statement);
					if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating user information: %s\n",PQerrorMessage(pqc));
					}
				}
				if(res) {
					PQclear(res);
				}
			}
		}
#endif
	} else if(is_mysql_userdb()){

#if !defined(TURN_NO_MYSQL)

		if(!is_st) {
			must_set_admin_realm(realm);
		}

		char statement[LONG_STRING_SIZE];
		MYSQL * myc = get_mydb_connection();
		if(myc) {
			if(ct == TA_DELETE_USER) {
				if(is_st) {
				  snprintf(statement,sizeof(statement),"delete from turnusers_st where name='%s'",user);
				} else {
				  snprintf(statement,sizeof(statement),"delete from turnusers_lt where name='%s' and realm='%s'",user,realm);
				}
				int res = mysql_query(myc, statement);
				if(res) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error deleting user key information: %s\n",mysql_error(myc));
				}
			}

			if(ct == TA_UPDATE_USER) {
				if(is_st) {
				  snprintf(statement,sizeof(statement),"insert into turnusers_st values('%s','%s')",user,passwd);
				} else {
				  snprintf(statement,sizeof(statement),"insert into turnusers_lt (realm,name,hmackey) values('%s','%s','%s')",realm,user,skey);
				}
				int res = mysql_query(myc, statement);
				if(res) {
					if(is_st) {
					  snprintf(statement,sizeof(statement),"update turnusers_st set password='%s' where name='%s'",passwd,user);
					} else {
					  snprintf(statement,sizeof(statement),"update turnusers_lt set hmackey='%s' where name='%s' and realm='%s'",skey,user,realm);
					}
					res = mysql_query(myc, statement);
					if(res) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating user key information: %s\n",mysql_error(myc));
					}
				}
			}
		}
#endif
	} else if(is_redis_userdb()) {

#if !defined(TURN_NO_HIREDIS)

		if(!is_st) {
			must_set_admin_realm(realm);
		}

		redisContext *rc = get_redis_connection();
		if(rc) {
			char statement[LONG_STRING_SIZE];

			if(ct == TA_DELETE_USER) {
				if(is_st) {
				  snprintf(statement,sizeof(statement),"del turn/user/%s/password",user);
				  turnFreeRedisReply(redisCommand(rc, statement));
				} else {
				  snprintf(statement,sizeof(statement),"del turn/realm/%s/user/%s/key",(char*)realm,user);
				  turnFreeRedisReply(redisCommand(rc, statement));
				  snprintf(statement,sizeof(statement),"del turn/realm/%s/user/%s/password",(char*)realm,user);
				  turnFreeRedisReply(redisCommand(rc, statement));
				}
			}

			if(ct == TA_UPDATE_USER) {
				if(is_st) {
				  snprintf(statement,sizeof(statement),"set turn/user/%s/password %s",user,passwd);
				  turnFreeRedisReply(redisCommand(rc, statement));
				} else {
				  snprintf(statement,sizeof(statement),"set turn/realm/%s/user/%s/key %s",(char*)realm,user,skey);
				  turnFreeRedisReply(redisCommand(rc, statement));
				  snprintf(statement,sizeof(statement),"del turn/realm/%s/user/%s/password",(char*)realm,user);
				  turnFreeRedisReply(redisCommand(rc, statement));
				}
			}

			turnFreeRedisReply(redisCommand(rc, "save"));
		}
#endif
	} else if(!is_st) {

		persistent_users_db_t *pud = get_persistent_users_db();
		char *full_path_to_userdb_file = find_config_file(pud->userdb, 1);
		FILE *f = full_path_to_userdb_file ? fopen(full_path_to_userdb_file,"r") : NULL;
		int found = 0;
		char us[LONG_STRING_SIZE];
		size_t i = 0;
		char **content = NULL;
		size_t csz = 0;

		STRCPY(us, (char*) user);
		strncpy(us + strlen(us), ":", sizeof(us)-1-strlen(us));
		us[sizeof(us)-1]=0;

		if (!f) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "File %s not found, will be created.\n",pud->userdb);
		} else {

			char sarg[LONG_STRING_SIZE];
			char sbuf[LONG_STRING_SIZE];

			for (;;) {
				char *s0 = fgets(sbuf, sizeof(sbuf) - 1, f);
				if (!s0)
					break;

				size_t slen = strlen(s0);
				while (slen && (s0[slen - 1] == 10 || s0[slen - 1] == 13))
					s0[--slen] = 0;

				char *s = skip_blanks(s0);

				if (s[0] == '#')
					goto add_and_cont;
				if (!s[0])
					goto add_and_cont;

				STRCPY(sarg, s);
				if (strstr(sarg, us) == sarg) {
					if (ct == TA_DELETE_USER)
						continue;

					if (found)
						continue;
					found = 1;
					STRCPY(us, (char*) user);
					strncpy(us + strlen(us), ":0x", sizeof(us)-1-strlen(us));
					us[sizeof(us)-1]=0;
					size_t sz = get_hmackey_size(turn_params.shatype);
					for (i = 0; i < sz; i++) {
						snprintf(
							us + strlen(us),
							sizeof(us)-strlen(us),
							"%02x",
							(unsigned int) key[i]);
					}

					s0 = us;
				}

				add_and_cont:
				content = (char**)realloc(content, sizeof(char*) * (++csz));
				content[csz - 1] = strdup(s0);
			}

			fclose(f);
		}

		if(!found && (ct == TA_UPDATE_USER)) {
		  STRCPY(us,(char*)user);
		  strncpy(us+strlen(us),":0x",sizeof(us)-1-strlen(us));
		  us[sizeof(us)-1]=0;
		  size_t sz = get_hmackey_size(turn_params.shatype);
		  for(i=0;i<sz;i++) {
		    snprintf(us+strlen(us),sizeof(us)-strlen(us),"%02x",(unsigned int)key[i]);
		  }
		  content = (char**)realloc(content,sizeof(char*)*(++csz));
		  content[csz-1]=strdup(us);
		}

		if(!full_path_to_userdb_file)
			full_path_to_userdb_file=strdup(pud->userdb);

		size_t dirsz = strlen(full_path_to_userdb_file)+21;
		char *dir = (char*)turn_malloc(dirsz+1);
		strncpy(dir,full_path_to_userdb_file,dirsz);
		dir[dirsz]=0;
		size_t dlen = strlen(dir);
		while(dlen) {
			if(dir[dlen-1]=='/')
				break;
			dir[--dlen]=0;
		}
		strncpy(dir+strlen(dir),".tmp_userdb",dirsz-strlen(dir));

		f = fopen(dir,"w");
		if(!f) {
			perror("file open");
			exit(-1);
		}

		for(i=0;i<csz;i++)
			fprintf(f,"%s\n",content[i]);

		fclose(f);

		rename(dir,full_path_to_userdb_file);
		free(dir);
	}

	return 0;
}

/////////// PING //////////////

void auth_ping(redis_context_handle rch)
{
	donot_print_connection_success = 1;

#if !defined(TURN_NO_PQ)
	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		char statement[LONG_STRING_SIZE];
		STRCPY(statement,"select value from turn_secret");
		PGresult *res = PQexec(pqc, statement);

		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		}

		if(res) {
			PQclear(res);
		}
	}
#endif

#if !defined(TURN_NO_MYSQL)
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[LONG_STRING_SIZE];
		STRCPY(statement,"select value from turn_secret");
		int res = mysql_query(myc, statement);
		if(res) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
		} else {
			MYSQL_RES *mres = mysql_store_result(myc);
			if(!mres) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else {
				mysql_free_result(mres);
			}
		}
	}
#endif

#if !defined(TURN_NO_HIREDIS)
	redisContext *rc = get_redis_connection();
	if(rc) {
		turnFreeRedisReply(redisCommand(rc, "keys turn/origin/*"));
	}
	if(rch)
		send_message_to_redis(rch, "publish", "__XXX__", "__YYY__");
#endif

}

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

static ip_range_list_t* get_ip_list(const char *kind)
{
	UNUSED_ARG(kind);
	ip_range_list_t *ret = (ip_range_list_t*)turn_malloc(sizeof(ip_range_list_t));
	ns_bzero(ret,sizeof(ip_range_list_t));

#if !defined(TURN_NO_PQ)
	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		char statement[LONG_STRING_SIZE];
		snprintf(statement,sizeof(statement),"select ip_range from %s_peer_ip",kind);
		PGresult *res = PQexec(pqc, statement);

		if(res && (PQresultStatus(res) == PGRES_TUPLES_OK)) {
			int i = 0;
			for(i=0;i<PQntuples(res);i++) {
				char *kval = PQgetvalue(res,i,0);
				if(kval) {
					add_ip_list_range(kval,ret);
				}
			}
		}

		if(res) {
			PQclear(res);
		}
	}
#endif

#if !defined(TURN_NO_MYSQL)
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[LONG_STRING_SIZE];
		snprintf(statement,sizeof(statement),"select ip_range from %s_peer_ip",kind);
		int res = mysql_query(myc, statement);
		if(res == 0) {
			MYSQL_RES *mres = mysql_store_result(myc);
			if(mres && mysql_field_count(myc)==1) {
				for(;;) {
					MYSQL_ROW row = mysql_fetch_row(mres);
					if(!row) {
						break;
					} else {
						if(row[0]) {
							unsigned long *lengths = mysql_fetch_lengths(mres);
							if(lengths) {
								size_t sz = lengths[0];
								char kval[LONG_STRING_SIZE];
								ns_bcopy(row[0],kval,sz);
								kval[sz]=0;
								add_ip_list_range(kval,ret);
							}
						}
					}
				}
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
#endif

#if !defined(TURN_NO_HIREDIS)
	redisContext *rc = get_redis_connection();
	if(rc) {
		char statement[LONG_STRING_SIZE];
		snprintf(statement,sizeof(statement),"keys turn/%s-peer-ip/*", kind);
		redisReply *reply = (redisReply*)redisCommand(rc, statement);
		if(reply) {
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
					add_to_secrets_list(&keys,reply->element[i]->str);
				}
			}

			for(isz=0;isz<keys.sz;++isz) {
				snprintf(s,sizeof(s),"get %s", keys.secrets[isz]);
				redisReply *rget = (redisReply *)redisCommand(rc, s);
				if(rget) {
					if (rget->type == REDIS_REPLY_ERROR)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
					else if (rget->type != REDIS_REPLY_STRING) {
						if (rget->type != REDIS_REPLY_NIL)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
					} else {
						add_ip_list_range(rget->str,ret);
					}
					turnFreeRedisReply(rget);
				}
			}

			clean_secrets_list(&keys);

			turnFreeRedisReply(reply);
		}
	}
#endif

	return ret;
}

static void ip_list_free(ip_range_list_t *l)
{
	if(l) {
		size_t i;
		for(i=0;i<l->ranges_number;++i) {
			if(l->ranges && l->ranges[i])
				free(l->ranges[i]);
			if(l->encaddrsranges && l->encaddrsranges[i])
				free(l->encaddrsranges[i]);
		}
		if(l->ranges)
			free(l->ranges);
		if(l->encaddrsranges)
			free(l->encaddrsranges);
		free(l);
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

int add_ip_list_range(char* range, ip_range_list_t * list)
{
	char* separator = strchr(range, '-');

	if (separator) {
		*separator = '\0';
	}

	ioa_addr min, max;

	if (make_ioa_addr((const u08bits*) range, 0, &min) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong address format: %s\n", range);
		return -1;
	}

	if (separator) {
		if (make_ioa_addr((const u08bits*) separator + 1, 0, &max) < 0) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong address format: %s\n", separator + 1);
			return -1;
		}
	} else {
		// Doesn't have a '-' character in it, so assume that this is a single address
		addr_cpy(&max, &min);
	}

	if (separator)
		*separator = '-';

	++(list->ranges_number);
	list->ranges = (char**) realloc(list->ranges, sizeof(char*) * list->ranges_number);
	list->ranges[list->ranges_number - 1] = strdup(range);
	list->encaddrsranges = (ioa_addr_range**) realloc(list->encaddrsranges, sizeof(ioa_addr_range*) * list->ranges_number);

	list->encaddrsranges[list->ranges_number - 1] = (ioa_addr_range*) turn_malloc(sizeof(ioa_addr_range));

	ioa_addr_range_set(list->encaddrsranges[list->ranges_number - 1], &min, &max);

	return 0;
}

/////////// REALM //////////////

#if !defined(TURN_NO_HIREDIS)
static int set_redis_realm_opt(char *realm, const char* key, vint *value)
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
				ur_string_map_lock(realms);
				*value = atoi(rget->str);
				ur_string_map_unlock(realms);
				found = 1;
			}
			turnFreeRedisReply(rget);
		}
	}

	return found;
}
#endif

void reread_realms(void)
{
#if !defined(TURN_NO_PQ)
	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		char statement[LONG_STRING_SIZE];

		{
			snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm");
			PGresult *res = PQexec(pqc, statement);

			if(res && (PQresultStatus(res) == PGRES_TUPLES_OK)) {

				ur_string_map *o_to_realm_new = ur_string_map_create(free);

				int i = 0;
				for(i=0;i<PQntuples(res);i++) {
					char *oval = PQgetvalue(res,i,0);
					if(oval) {
						char *rval = PQgetvalue(res,i,1);
						if(rval) {
							get_realm(rval);
							ur_string_map_value_type value = strdup(rval);
							ur_string_map_put(o_to_realm_new, (const ur_string_map_key_type) oval, value);
						}
					}
				}

				TURN_MUTEX_LOCK(&o_to_realm_mutex);
				ur_string_map_free(&o_to_realm);
				o_to_realm = o_to_realm_new;
				TURN_MUTEX_UNLOCK(&o_to_realm_mutex);
			}

			if(res) {
				PQclear(res);
			}
		}

		{
			{
				size_t i = 0;
				size_t rlsz = 0;

				ur_string_map_lock(realms);
				rlsz = realms_list.sz;
				ur_string_map_unlock(realms);

				for (i = 0; i<rlsz; ++i) {

					char *realm = realms_list.secrets[i];

					realm_params_t* rp = get_realm(realm);

					ur_string_map_lock(realms);
					rp->options.perf_options.max_bps = turn_params.max_bps;
					ur_string_map_unlock(realms);

					ur_string_map_lock(realms);
					rp->options.perf_options.total_quota = turn_params.total_quota;
					ur_string_map_unlock(realms);

					ur_string_map_lock(realms);
					rp->options.perf_options.user_quota = turn_params.user_quota;
					ur_string_map_unlock(realms);

				}
			}

			snprintf(statement,sizeof(statement),"select realm,opt,value from turn_realm_option");
			PGresult *res = PQexec(pqc, statement);

			if(res && (PQresultStatus(res) == PGRES_TUPLES_OK)) {

				int i = 0;
				for(i=0;i<PQntuples(res);i++) {
					char *rval = PQgetvalue(res,i,0);
					char *oval = PQgetvalue(res,i,1);
					char *vval = PQgetvalue(res,i,2);
					if(rval && oval && vval) {
						realm_params_t* rp = get_realm(rval);
						if(!strcmp(oval,"max-bps"))
							rp->options.perf_options.max_bps = (vint)atoi(vval);
						else if(!strcmp(oval,"total-quota"))
							rp->options.perf_options.total_quota = (vint)atoi(vval);
						else if(!strcmp(oval,"user-quota"))
							rp->options.perf_options.user_quota = (vint)atoi(vval);
						else {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown realm option: %s\n", oval);
						}
					}
				}
			}

			if(res) {
				PQclear(res);
			}
		}
	}
#endif

#if !defined(TURN_NO_MYSQL)
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[LONG_STRING_SIZE];
		{
			snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm");
			int res = mysql_query(myc, statement);
			if(res == 0) {
				MYSQL_RES *mres = mysql_store_result(myc);
				if(mres && mysql_field_count(myc)==2) {

					ur_string_map *o_to_realm_new = ur_string_map_create(free);

					for(;;) {
						MYSQL_ROW row = mysql_fetch_row(mres);
						if(!row) {
							break;
						} else {
							if(row[0] && row[1]) {
								unsigned long *lengths = mysql_fetch_lengths(mres);
								if(lengths) {
									size_t sz = lengths[0];
									char oval[513];
									ns_bcopy(row[0],oval,sz);
									oval[sz]=0;
									char *rval=strdup(row[1]);
									get_realm(rval);
									ur_string_map_value_type value = strdup(rval);
									ur_string_map_put(o_to_realm_new, (const ur_string_map_key_type) oval, value);
								}
							}
						}
					}

					TURN_MUTEX_LOCK(&o_to_realm_mutex);
					ur_string_map_free(&o_to_realm);
					o_to_realm = o_to_realm_new;
					TURN_MUTEX_UNLOCK(&o_to_realm_mutex);
				}

				if(mres)
					mysql_free_result(mres);
			}
		}
		{
			size_t i = 0;
			size_t rlsz = 0;

			ur_string_map_lock(realms);
			rlsz = realms_list.sz;
			ur_string_map_unlock(realms);

			for (i = 0; i<rlsz; ++i) {

				char *realm = realms_list.secrets[i];

				realm_params_t* rp = get_realm(realm);

				ur_string_map_lock(realms);
				rp->options.perf_options.max_bps = turn_params.max_bps;
				ur_string_map_unlock(realms);

				ur_string_map_lock(realms);
				rp->options.perf_options.total_quota = turn_params.total_quota;
				ur_string_map_unlock(realms);

				ur_string_map_lock(realms);
				rp->options.perf_options.user_quota = turn_params.user_quota;
				ur_string_map_unlock(realms);

			}
		}

		snprintf(statement,sizeof(statement),"select realm,opt,value from turn_realm_option");
		int res = mysql_query(myc, statement);
		if(res == 0) {
			MYSQL_RES *mres = mysql_store_result(myc);
			if(mres && mysql_field_count(myc)==3) {

				for(;;) {
					MYSQL_ROW row = mysql_fetch_row(mres);
					if(!row) {
						break;
					} else {
						if(row[0] && row[1] && row[2]) {
							unsigned long *lengths = mysql_fetch_lengths(mres);
							if(lengths) {
								char rval[513];
								size_t sz = lengths[0];
								ns_bcopy(row[0],rval,sz);
								rval[sz]=0;
								char oval[513];
								sz = lengths[1];
								ns_bcopy(row[1],oval,sz);
								oval[sz]=0;
								char vval[513];
								sz = lengths[2];
								ns_bcopy(row[2],vval,sz);
								vval[sz]=0;
								realm_params_t* rp = get_realm(rval);
								if(!strcmp(oval,"max-bps"))
									rp->options.perf_options.max_bps = (vint)atoi(vval);
								else if(!strcmp(oval,"total-quota"))
									rp->options.perf_options.total_quota = (vint)atoi(vval);
								else if(!strcmp(oval,"user-quota"))
									rp->options.perf_options.user_quota = (vint)atoi(vval);
								else {
									TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown realm option: %s\n", oval);
								}
							}
						}
					}
				}
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
#endif

#if !defined(TURN_NO_HIREDIS)
	if (is_redis_userdb()) {
		redisContext *rc = get_redis_connection();
		if (rc) {

			redisReply *reply = (redisReply*) redisCommand(rc, "keys turn/origin/*");
			if (reply) {

				ur_string_map *o_to_realm_new = ur_string_map_create(free);

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
							ur_string_map_value_type value = strdup(rget->str);
							ur_string_map_put(o_to_realm_new, (const ur_string_map_key_type) origin, value);
						}
						turnFreeRedisReply(rget);
					}
				}

				clean_secrets_list(&keys);

				TURN_MUTEX_LOCK(&o_to_realm_mutex);
				ur_string_map_free(&o_to_realm);
				o_to_realm = o_to_realm_new;
				TURN_MUTEX_UNLOCK(&o_to_realm_mutex);

				turnFreeRedisReply(reply);
			}

			{
				size_t i = 0;
				size_t rlsz = 0;

				ur_string_map_lock(realms);
				rlsz = realms_list.sz;
				ur_string_map_unlock(realms);

				for (i = 0; i<rlsz; ++i) {
					char *realm = realms_list.secrets[i];
					realm_params_t* rp = get_realm(realm);
					if(!set_redis_realm_opt(realm,"max-bps",&(rp->options.perf_options.max_bps))) {
						ur_string_map_lock(realms);
						rp->options.perf_options.max_bps = turn_params.max_bps;
						ur_string_map_unlock(realms);
					}
					if(!set_redis_realm_opt(realm,"total-quota",&(rp->options.perf_options.total_quota))) {
						ur_string_map_lock(realms);
						rp->options.perf_options.total_quota = turn_params.total_quota;
						ur_string_map_unlock(realms);
					}
					if(!set_redis_realm_opt(realm,"user-quota",&(rp->options.perf_options.user_quota))) {
						ur_string_map_lock(realms);
						rp->options.perf_options.user_quota = turn_params.user_quota;
						ur_string_map_unlock(realms);
					}
				}
			}
		}
	}
#endif
}

///////////////////////////////
