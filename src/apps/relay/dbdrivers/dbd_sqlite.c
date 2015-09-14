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
#include "dbd_sqlite.h"

#if !defined(TURN_NO_SQLITE)

#include <sqlite3.h>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <pthread.h>

//////////////////////////////////////////////////

static pthread_mutex_t rc_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rc_cond = PTHREAD_COND_INITIALIZER;

static int read_threads = 0;
static int write_level = 0;
static pthread_t write_thread = 0;

static void sqlite_lock(int write)
{
	pthread_t pths = pthread_self();

	int can_move = 0;
	while (!can_move) {
		pthread_mutex_lock(&rc_mutex);
		if (write) {
			if (((write_thread == 0) && (read_threads < 1)) || (write_thread == pths)) {
				can_move = 1;
				++write_level;
				write_thread = pths;
			}
		} else {
			if ((!write_thread) || (write_thread == pths)) {
				can_move = 1;
				++read_threads;
			}
		}
		if (!can_move) {
			pthread_cond_wait(&rc_cond, &rc_mutex);
		}
		pthread_mutex_unlock(&rc_mutex);
	}
}

static void sqlite_unlock(int write)
{
	pthread_mutex_lock(&rc_mutex);
	if (write) {
		if (!(--write_level)) {
			write_thread = 0;
			pthread_cond_broadcast(&rc_cond);
		}
	} else {
		if (!(--read_threads)) {
			pthread_cond_broadcast(&rc_cond);
		}
	}
	pthread_mutex_unlock(&rc_mutex);
}

//////////////////////////////////////////////////

static int sqlite_init_multithreaded(void) {

#if defined(SQLITE_CONFIG_MULTITHREAD)

	sqlite3_shutdown();

	if (sqlite3_threadsafe() > 0) {
		int retCode = sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
		if (retCode != SQLITE_OK) {
			retCode = sqlite3_config(SQLITE_CONFIG_SERIALIZED);
			if (retCode != SQLITE_OK) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "setting sqlite thread safe mode to serialized failed!!! return code: %d\n", retCode);
				return -1;
			}
		}
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Your SQLite database is not compiled to be threadsafe.\n");
		return -1;
	}
#endif

	return 0;
}

static int donot_print_connection_success = 0;

static void fix_user_directory(char *dir0) {
	char *dir = dir0;
	while(*dir == ' ') ++dir;
	if(*dir == '~') {
		char *home=getenv("HOME");
		if(!home) {
			struct passwd	*pwd = getpwuid(getuid());
			if(!pwd) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot figure out the user's HOME directory (1)\n");
			} else {
				home = pwd->pw_dir;
				if(!home) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot figure out the user's HOME directory\n");
					return;
				}
			}
		}
		size_t szh = strlen(home);
		size_t sz = strlen(dir0)+1+szh;
		char* dir_fixed = (char*)turn_malloc(sz);
		strncpy(dir_fixed,home,szh);
		strncpy(dir_fixed+szh,dir+1,(sz-szh-1));
		strncpy(dir0,dir_fixed,sz);
		turn_free(dir_fixed,sz);
	}
}

static void init_sqlite_database(sqlite3 *sqliteconnection) {

	const char * statements[] = {
		"CREATE TABLE turnusers_lt ( realm varchar(127) default '', name varchar(512), hmackey char(128), PRIMARY KEY (realm,name))",
		"CREATE TABLE turn_secret (realm varchar(127) default '', value varchar(127), primary key (realm,value))",
		"CREATE TABLE allowed_peer_ip (realm varchar(127) default '', ip_range varchar(256), primary key (realm,ip_range))",
		"CREATE TABLE denied_peer_ip (realm varchar(127) default '', ip_range varchar(256), primary key (realm,ip_range))",
		"CREATE TABLE turn_origin_to_realm (origin varchar(127),realm varchar(127),primary key (origin))",
		"CREATE TABLE turn_realm_option (realm varchar(127) default '',	opt varchar(32),	value varchar(128),	primary key (realm,opt))",
		"CREATE TABLE oauth_key (kid varchar(128),ikm_key varchar(256),timestamp bigint default 0,lifetime integer default 0,as_rs_alg varchar(64) default '',realm varchar(127) default '',primary key (kid))",
		"CREATE TABLE admin_user (name varchar(32), realm varchar(127), password varchar(127), primary key (name))",
		NULL
	};

	int i = 0;
	while(statements[i]) {
		sqlite3_stmt *statement = NULL;
		int rc = 0;
		if ((rc = sqlite3_prepare(sqliteconnection, statements[i], -1, &statement, 0)) == SQLITE_OK) {
			sqlite3_step(statement);
		}
		sqlite3_finalize(statement);
		++i;
	}
}

static sqlite3 * get_sqlite_connection(void) {

	persistent_users_db_t *pud = get_persistent_users_db();

	sqlite3 *sqliteconnection = (sqlite3 *)pthread_getspecific(connection_key);
	if(!sqliteconnection) {
		fix_user_directory(pud->userdb);
		sqlite_init_multithreaded();
		int rc = sqlite3_open(pud->userdb, &sqliteconnection);
		if(!sqliteconnection || (rc != SQLITE_OK)) {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open SQLite DB connection: <%s>, runtime error:\n  %s\n  (If your intention is to use an SQLite database for the TURN server, then\n  check and fix, if necessary, the effective permissions of the TURN server\n  process and of the DB directory and then re-start the TURN server)\n",pud->userdb,errmsg);
			if(sqliteconnection) {
				sqlite3_close(sqliteconnection);
				sqliteconnection=NULL;
			}
			turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_UNKNOWN;
		} else {
			init_sqlite_database(sqliteconnection);
			if(!donot_print_connection_success){
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SQLite DB connection success: %s\n",pud->userdb);
				donot_print_connection_success = 1;
			}
		}
		if(sqliteconnection) {
			(void) pthread_setspecific(connection_key, sqliteconnection);
		}
	}
	return sqliteconnection;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int sqlite_get_auth_secrets(secrets_list_t *sl, u08bits *realm)
{
	int ret = -1;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		char statement[TURN_LONG_STRING_SIZE];
		sqlite3_stmt *st = NULL;
		int rc = 0;
		snprintf(statement, sizeof(statement) - 1, "select value from turn_secret where realm='%s'", realm);

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			int ctotal = sqlite3_column_count(st);
			ret = 0;

			while (ctotal > 0) {

				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					int type = sqlite3_column_type(st, 0);
					if (type != SQLITE_NULL)
						add_to_secrets_list(sl, (const char*) sqlite3_column_text(st, 0));

				} else if (res == SQLITE_DONE) {
					break;
				} else {
					const char* errmsg = sqlite3_errmsg(sqliteconnection);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
					ret = -1;
					break;
				}
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(0);
	}
	return ret;
}

static int sqlite_get_user_key(u08bits *usname, u08bits *realm, hmackey_t key)
{
	int ret = -1;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		char statement[TURN_LONG_STRING_SIZE];
		sqlite3_stmt *st = NULL;
		int rc = 0;
		/* direct user input eliminated - there is no SQL injection problem (since version 4.4.5.3) */
		snprintf(statement, sizeof(statement), "select hmackey from turnusers_lt where name='%s' and realm='%s'", usname, realm);

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			int res = sqlite3_step(st);
			if (res == SQLITE_ROW) {
				char *kval = turn_strdup((const char*) sqlite3_column_text(st, 0));
				size_t sz = get_hmackey_size(SHATYPE_DEFAULT);
				if (convert_string_key_to_binary(kval, key, sz) < 0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key: %s, user %s\n", kval, usname);
				} else {
					ret = 0;
				}
				turn_free(kval,strlen(kval)+1);
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}

		sqlite3_finalize(st);

		sqlite_unlock(0);
	}
	return ret;
}

static int sqlite_get_oauth_key(const u08bits *kid, oauth_key_data_raw *key) {

	int ret = -1;

	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	/* direct user input eliminated - there is no SQL injection problem (since version 4.4.5.3) */
	snprintf(statement,sizeof(statement),"select ikm_key,timestamp,lifetime,as_rs_alg,realm from oauth_key where kid='%s'",(const char*)kid);

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			int res = sqlite3_step(st);
			if (res == SQLITE_ROW) {

				STRCPY(key->ikm_key,sqlite3_column_text(st, 0));
				key->timestamp = (u64bits)strtoll((const char*)sqlite3_column_text(st, 1),NULL,10);
				key->lifetime = (u32bits)strtol((const char*)sqlite3_column_text(st, 2),NULL,10);
				STRCPY(key->as_rs_alg,sqlite3_column_text(st, 3));
				STRCPY(key->realm,sqlite3_column_text(st, 4));
				STRCPY(key->kid,kid);
				ret = 0;
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}

		sqlite3_finalize(st);

		sqlite_unlock(0);
	}

	return ret;
}

static int sqlite_list_oauth_keys(secrets_list_t *kids,secrets_list_t *teas,secrets_list_t *tss,secrets_list_t *lts,secrets_list_t *realms) {

	oauth_key_data_raw key_;
	oauth_key_data_raw *key=&key_;

	donot_print_connection_success=1;

	int ret = -1;

	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	snprintf(statement,sizeof(statement),"select ikm_key,timestamp,lifetime,as_rs_alg,realm,kid from oauth_key order by kid");

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			ret = 0;
			while (1) {
				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					STRCPY(key->ikm_key,sqlite3_column_text(st, 0));
					key->timestamp = (u64bits)strtoll((const char*)sqlite3_column_text(st, 1),NULL,10);
					key->lifetime = (u32bits)strtol((const char*)sqlite3_column_text(st, 2),NULL,10);
					STRCPY(key->as_rs_alg,sqlite3_column_text(st, 3));
					STRCPY(key->realm,sqlite3_column_text(st, 4));
					STRCPY(key->kid,sqlite3_column_text(st, 5));

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
						printf("  kid=%s, ikm_key=%s, timestamp=%llu, lifetime=%lu, as_rs_alg=%s\n",
										key->kid, key->ikm_key, (unsigned long long)key->timestamp, (unsigned long)key->lifetime,
										key->as_rs_alg);
					}

				} else if (res == SQLITE_DONE) {
					break;
				} else {
					const char* errmsg = sqlite3_errmsg(sqliteconnection);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
					ret = -1;
					break;
				}
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}

		sqlite3_finalize(st);

		sqlite_unlock(0);
	}

	return ret;
}

static int sqlite_set_user_key(u08bits *usname, u08bits *realm, const char *key)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {

		sqlite_lock(1);

		snprintf(statement, sizeof(statement), "insert or replace into turnusers_lt (realm,name,hmackey) values('%s','%s','%s')", realm, usname, key);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}

static int sqlite_set_oauth_key(oauth_key_data_raw *key)
{

	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		snprintf(
						statement,
						sizeof(statement),
						"insert or replace into oauth_key (kid,ikm_key,timestamp,lifetime,as_rs_alg,realm) values('%s','%s',%llu,%lu,'%s','%s')",
						key->kid, key->ikm_key, (unsigned long long) key->timestamp, (unsigned long) key->lifetime, key->as_rs_alg, key->realm);

		sqlite_lock(1);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error updating SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}

static int sqlite_del_user(u08bits *usname, u08bits *realm)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		snprintf(statement, sizeof(statement), "delete from turnusers_lt where name='%s' and realm='%s'", usname, realm);

		sqlite_lock(1);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}

static int sqlite_del_oauth_key(const u08bits *kid)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {

		snprintf(statement, sizeof(statement), "delete from oauth_key where kid = '%s'", (const char*) kid);

		sqlite_lock(1);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}


static int sqlite_list_users(u08bits *realm, secrets_list_t *users, secrets_list_t *realms)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		if (realm[0]) {
			snprintf(statement, sizeof(statement), "select name,realm from turnusers_lt where realm='%s' order by name", realm);
		} else {
			snprintf(statement, sizeof(statement), "select name,realm from turnusers_lt order by realm,name");
		}

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			ret = 0;
			while (1) {
				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					const char* kval = (const char*) sqlite3_column_text(st, 0);
					const char* rval = (const char*) sqlite3_column_text(st, 1);

					if(users) {
						add_to_secrets_list(users,kval);
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

				} else if (res == SQLITE_DONE) {
					break;
				} else {
					const char* errmsg = sqlite3_errmsg(sqliteconnection);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
					ret = -1;
					break;
				}
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(0);
	}
	return ret;
}

static int sqlite_list_secrets(u08bits *realm, secrets_list_t *secrets, secrets_list_t *realms)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	sqlite3_stmt *st = NULL;
	int rc = 0;

	if (realm[0]) {
		snprintf(statement, sizeof(statement), "select value,realm from turn_secret where realm='%s' order by value", realm);
	} else {
		snprintf(statement, sizeof(statement), "select value,realm from turn_secret order by realm,value");
	}

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			int res = 0;
			while(1) {
				res = sqlite3_step(st);
				if (res == SQLITE_ROW) {
					ret = 0;
					const char* kval = (const char*) sqlite3_column_text(st, 0);
					if(kval) {
						const char* rval = (const char*) sqlite3_column_text(st, 1);
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
							printf("%s[%s]\n",kval,rval);
						}
					}
				} else if (res == SQLITE_DONE) {
					break;
				} else {
					const char* errmsg = sqlite3_errmsg(sqliteconnection);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
					ret = -1;
					break;
				}
			}
		}
		sqlite3_finalize(st);

		sqlite_unlock(0);
	}
	return ret;
}
  
static int sqlite_del_secret(u08bits *secret, u08bits *realm)
{
	int ret = -1;
	donot_print_connection_success=1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		if(!secret || (secret[0]==0))
		  snprintf(statement,sizeof(statement),"delete from turn_secret where realm='%s'",realm);
		else
		  snprintf(statement,sizeof(statement),"delete from turn_secret where value='%s' and realm='%s'",secret,realm);

		sqlite_lock(1);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}
  
static int sqlite_set_secret(u08bits *secret, u08bits *realm)
{
	int ret = -1;
	donot_print_connection_success = 1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {

	  snprintf(statement,sizeof(statement),"insert or replace into turn_secret (realm,value) values('%s','%s')",realm,secret);

	  sqlite_lock(1);

	  if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}
  
static int sqlite_add_origin(u08bits *origin, u08bits *realm)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {
		snprintf(statement,sizeof(statement),"insert or replace into turn_origin_to_realm (origin,realm) values('%s','%s')",origin,realm);

		sqlite_lock(1);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}
  
static int sqlite_del_origin(u08bits *origin)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {
		snprintf(statement,sizeof(statement),"delete from turn_origin_to_realm where origin='%s'",origin);

		sqlite_lock(1);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}

static int sqlite_list_origins(u08bits *realm, secrets_list_t *origins, secrets_list_t *realms)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	donot_print_connection_success = 1;

	sqlite3_stmt *st = NULL;
	int rc = 0;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		char statement[TURN_LONG_STRING_SIZE];
		if (realm && realm[0]) {
			snprintf(statement, sizeof(statement), "select origin,realm from turn_origin_to_realm where realm='%s' order by origin", realm);
		} else {
			snprintf(statement, sizeof(statement), "select origin,realm from turn_origin_to_realm order by realm,origin");
		}

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			ret = 0;
			while (1) {
				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					const char* kval = (const char*) sqlite3_column_text(st, 0);
					const char* rval = (const char*) sqlite3_column_text(st, 1);

					if(origins) {
						add_to_secrets_list(origins,kval);
						if(realms) {
							if(rval && *rval) {
								add_to_secrets_list(realms,rval);
							} else {
								add_to_secrets_list(realms,(char*)realm);
							}
						}
					} else {
						printf("%s ==>> %s\n",kval,rval);
					}
				} else if (res == SQLITE_DONE) {
					break;
				} else {
					const char* errmsg = sqlite3_errmsg(sqliteconnection);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
					ret = -1;
					break;
				}
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(0);
	}
	return ret;
}
  
static int sqlite_set_realm_option_one(u08bits *realm, unsigned long value, const char* opt)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {
		if(value>0) {
			snprintf(statement,sizeof(statement),"insert or replace into turn_realm_option (realm,opt,value) values('%s','%s','%lu')",realm,opt,(unsigned long)value);

			sqlite_lock(1);

			if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
				sqlite3_step(st);
				ret = 0;
			} else {
				const char* errmsg = sqlite3_errmsg(sqliteconnection);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
			}
			sqlite3_finalize(st);

			sqlite_unlock(1);
		}
	}
	return ret;
}
  
static int sqlite_list_realm_options(u08bits *realm)
{
	int ret = -1;
	donot_print_connection_success = 1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		if (realm && realm[0]) {
			snprintf(statement, sizeof(statement), "select realm,opt,value from turn_realm_option where realm='%s' order by realm,opt", realm);
		} else {
			snprintf(statement, sizeof(statement), "select realm,opt,value from turn_realm_option order by realm,opt");
		}

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			ret = 0;

			while (1) {
				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					const char* rval = (const char*) sqlite3_column_text(st, 0);
					const char* oval = (const char*) sqlite3_column_text(st, 1);
					const char* vval = (const char*) sqlite3_column_text(st, 2);

					printf("%s[%s]=%s\n",oval,rval,vval);

				} else if (res == SQLITE_DONE) {
					break;
				} else {
					const char* errmsg = sqlite3_errmsg(sqliteconnection);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
					ret = -1;
					break;
				}
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(0);
	}
	return ret;
}
  
static void sqlite_auth_ping(void * rch)
{
	UNUSED_ARG(rch);
}

static int sqlite_get_ip_list(const char *kind, ip_range_list_t * list)
{
	int ret = -1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		char statement[TURN_LONG_STRING_SIZE];
		sqlite3_stmt *st = NULL;
		int rc = 0;
		snprintf(statement, sizeof(statement), "select ip_range,realm from %s_peer_ip", kind);

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			ret = 0;

			while (1) {
				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					const char* kval = (const char*) sqlite3_column_text(st, 0);
					const char* rval = (const char*) sqlite3_column_text(st, 1);

					add_ip_list_range(kval, rval, list);

				} else if (res == SQLITE_DONE) {
					break;
				} else {
					const char* errmsg = sqlite3_errmsg(sqliteconnection);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
					ret = -1;
					break;
				}
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(0);
	}
	return ret;
}

static int sqlite_set_permission_ip(const char *kind, u08bits *realm, const char* ip, int del)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	char statement[TURN_LONG_STRING_SIZE];

	sqlite3_stmt *st = NULL;
	int rc = 0;

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {

		sqlite_lock(1);

		if(del) {
			snprintf(statement, sizeof(statement), "delete from %s_peer_ip where realm = '%s'  and ip_range = '%s'", kind, (char*)realm, ip);
		} else {
			snprintf(statement, sizeof(statement), "insert or replace into %s_peer_ip (realm,ip_range) values('%s','%s')", kind, (char*)realm, ip);
		}

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error updating SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}

static void sqlite_reread_realms(secrets_list_t * realms_list)
{
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {
		char statement[TURN_LONG_STRING_SIZE];
		sqlite3_stmt *st = NULL;
		int rc = 0;
		{
			snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm");

			sqlite_lock(0);

			if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

				ur_string_map *o_to_realm_new = ur_string_map_create(turn_free_simple);

				while (1) {
					int res = sqlite3_step(st);
					if (res == SQLITE_ROW) {

						char* oval = turn_strdup((const char*) sqlite3_column_text(st, 0));
						char* rval = turn_strdup((const char*) sqlite3_column_text(st, 1));

						get_realm(rval);
						ur_string_map_value_type value = rval;
						ur_string_map_put(o_to_realm_new, (const ur_string_map_key_type) oval, value);

						turn_free(oval,strlen(oval)+1);

					} else if (res == SQLITE_DONE) {
						break;
					} else {
						const char* errmsg = sqlite3_errmsg(sqliteconnection);
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
						break;
					}
				}

				update_o_to_realm(o_to_realm_new);

			} else {
				const char* errmsg = sqlite3_errmsg(sqliteconnection);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
			}
			sqlite3_finalize(st);

			sqlite_unlock(0);
		}

		{
			{
				size_t i = 0;
				size_t rlsz = 0;

				lock_realms();
				rlsz = realms_list->sz;
				unlock_realms();

				for (i = 0; i<rlsz; ++i) {

					char *realm = realms_list->secrets[i];

					realm_params_t* rp = get_realm(realm);

					lock_realms();
					rp->options.perf_options.max_bps = turn_params.max_bps;
					unlock_realms();

					lock_realms();
					rp->options.perf_options.total_quota = turn_params.total_quota;
					unlock_realms();

					lock_realms();
					rp->options.perf_options.user_quota = turn_params.user_quota;
					unlock_realms();

				}
			}

			sqlite_lock(0);

			snprintf(statement,sizeof(statement),"select realm,opt,value from turn_realm_option");
			if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

				while (1) {
					int res = sqlite3_step(st);
					if (res == SQLITE_ROW) {

						char* rval = turn_strdup((const char*) sqlite3_column_text(st, 0));
						const char* oval = (const char*) sqlite3_column_text(st, 1);
						const char* vval = (const char*) sqlite3_column_text(st, 2);

						realm_params_t* rp = get_realm(rval);
						if(!strcmp(oval,"max-bps"))
							rp->options.perf_options.max_bps = (band_limit_t)strtoul(vval,NULL,10);
						else if(!strcmp(oval,"total-quota"))
							rp->options.perf_options.total_quota = (vint)atoi(vval);
						else if(!strcmp(oval,"user-quota"))
							rp->options.perf_options.user_quota = (vint)atoi(vval);
						else {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown realm option: %s\n", oval);
						}

						turn_free(rval,strlen(rval)+1);

					} else if (res == SQLITE_DONE) {
						break;
					} else {
						const char* errmsg = sqlite3_errmsg(sqliteconnection);
						TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
						break;
					}
				}
			} else {
				const char* errmsg = sqlite3_errmsg(sqliteconnection);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
			}
			sqlite3_finalize(st);

			sqlite_unlock(0);
		}
	}
}

////////////////////////////////////////////////////

static int sqlite_get_admin_user(const u08bits *usname, u08bits *realm, password_t pwd)
{
	int ret = -1;

	realm[0]=0;
	pwd[0]=0;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		char statement[TURN_LONG_STRING_SIZE];
		sqlite3_stmt *st = NULL;
		int rc = 0;
		snprintf(statement, sizeof(statement), "select realm,password from admin_user where name='%s'", usname);

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			int res = sqlite3_step(st);
			if (res == SQLITE_ROW) {
				const char *kval = (const char*) sqlite3_column_text(st, 0);
				if(kval) {
					strncpy((char*)realm,kval,STUN_MAX_REALM_SIZE);
				}
				kval = (const char*) sqlite3_column_text(st, 1);
				if(kval) {
					strncpy((char*)pwd,kval,STUN_MAX_PWD_SIZE);
				}
				ret = 0;
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}

		sqlite3_finalize(st);

		sqlite_unlock(0);
	}
	return ret;
}

static int sqlite_set_admin_user(const u08bits *usname, const u08bits *realm, const password_t pwd)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {

		sqlite_lock(1);

		snprintf(statement, sizeof(statement), "insert or replace into admin_user (realm,name,password) values('%s','%s','%s')", realm, usname, pwd);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}

static int sqlite_del_admin_user(const u08bits *usname)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		snprintf(statement, sizeof(statement), "delete from admin_user where name='%s'", usname);

		sqlite_lock(1);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(1);
	}
	return ret;
}

static int sqlite_list_admin_users(int no_print)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		snprintf(statement, sizeof(statement), "select name,realm from admin_user order by realm,name");

		sqlite_lock(0);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			ret = 0;
			while (1) {
				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					const char* kval = (const char*) sqlite3_column_text(st, 0);
					const char* rval = (const char*) sqlite3_column_text(st, 1);

					if(!no_print) {
						if (rval && *rval) {
							printf("%s[%s]\n", kval, rval);
						} else {
							printf("%s\n", kval);
						}
					}

					++ret;

				} else if (res == SQLITE_DONE) {
					break;
				} else {
					const char* errmsg = sqlite3_errmsg(sqliteconnection);
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
					ret = -1;
					break;
				}
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);

		sqlite_unlock(0);
	}
	return ret;
}

///////////////////////////////////////////////////////

static const turn_dbdriver_t driver = {
  &sqlite_get_auth_secrets,
  &sqlite_get_user_key,
  &sqlite_set_user_key,
  &sqlite_del_user,
  &sqlite_list_users,
  &sqlite_list_secrets,
  &sqlite_del_secret,
  &sqlite_set_secret,
  &sqlite_add_origin,
  &sqlite_del_origin,
  &sqlite_list_origins,
  &sqlite_set_realm_option_one,
  &sqlite_list_realm_options,
  &sqlite_auth_ping,
  &sqlite_get_ip_list,
  &sqlite_set_permission_ip,
  &sqlite_reread_realms,
  &sqlite_set_oauth_key,
  &sqlite_get_oauth_key,
  &sqlite_del_oauth_key,
  &sqlite_list_oauth_keys,
  &sqlite_get_admin_user,
  &sqlite_set_admin_user,
  &sqlite_del_admin_user,
  &sqlite_list_admin_users
};

//////////////////////////////////////////////////

const turn_dbdriver_t * get_sqlite_dbdriver(void) {
	return &driver;
}

//////////////////////////////////////////////////

#else

const turn_dbdriver_t * get_sqlite_dbdriver(void) {
	return NULL;
}

#endif
