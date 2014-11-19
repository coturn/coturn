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

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int sqlite_init_multithreaded(void) {

	sqlite3_shutdown();

	if (sqlite3_threadsafe() > 0) {
		int retCode = sqlite3_config(SQLITE_CONFIG_SERIALIZED);
		if (retCode != SQLITE_OK) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "setting sqlite thread safe mode to serialized failed!!! return code: %d\n", retCode);
			return -1;
		}
	} else {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Your SQLite database is not compiled to be threadsafe.\n");
		return -1;
	}

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
		"CREATE TABLE turnusers_lt ( realm varchar(512) default '', name varchar(512), hmackey char(128), PRIMARY KEY (realm,name))",
		"CREATE TABLE turnusers_st (name varchar(512) PRIMARY KEY, password varchar(512))",
		"CREATE TABLE turn_secret (realm varchar(512) default '', value varchar(512), primary key (realm,value))",
		"CREATE TABLE allowed_peer_ip (realm varchar(512) default '', ip_range varchar(256), primary key (realm,ip_range))",
		"CREATE TABLE denied_peer_ip (realm varchar(512) default '', ip_range varchar(256), primary key (realm,ip_range))",
		"CREATE TABLE turn_origin_to_realm (origin varchar(512),realm varchar(512),primary key (origin))",
		"CREATE TABLE turn_realm_option (realm varchar(512) default '',	opt varchar(32),	value varchar(128),	primary key (realm,opt))",
		"CREATE TABLE oauth_key (kid varchar(128),ikm_key varchar(256) default '',timestamp bigint default 0,lifetime integer default 0,hkdf_hash_func varchar(64) default '',as_rs_alg varchar(64) default '',as_rs_key varchar(256) default '',auth_alg varchar(64) default '',auth_key varchar(256) default '',primary key (kid))",
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

	sqlite3 *sqliteconnection = (sqlite3 *)(pud->connection);
	if(!sqliteconnection) {
		fix_user_directory(pud->userdb);
		sqlite_init_multithreaded();
		int rc = sqlite3_open(pud->userdb, &sqliteconnection);
		if(!sqliteconnection || (rc != SQLITE_OK)) {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open SQLite DB connection: <%s>, runtime error:\n  %s\n  (If your intention is to use a database for the TURN server, then\n  check the TURN server process / file / DB directory permissions and\n  re-start the TURN server)\n",pud->userdb,errmsg);
			if(sqliteconnection) {
				sqlite3_close(sqliteconnection);
				sqliteconnection=NULL;
			}
			turn_params.default_users_db.userdb_type = TURN_USERDB_TYPE_UNKNOWN;
		} else if(!donot_print_connection_success){
			init_sqlite_database(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "SQLite DB connection success: %s\n",pud->userdb);
		}
		pud->connection = sqliteconnection;
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
		snprintf(statement, sizeof(statement), "select hmackey from turnusers_lt where name='%s' and realm='%s'", usname, realm);
		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			int res = sqlite3_step(st);
			if (res == SQLITE_ROW) {
				char *kval = turn_strdup((const char*) sqlite3_column_text(st, 0));
				size_t sz = get_hmackey_size(turn_params.shatype);
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
	}
	return ret;
}

static int sqlite_get_user_pwd(u08bits *usname, st_password_t pwd)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	snprintf(statement, sizeof(statement), "select password from turnusers_st where name='%s'", usname);

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			int res = sqlite3_step(st);
			if (res == SQLITE_ROW) {
				const char *kval = (const char*) sqlite3_column_text(st, 0);
				if (kval) {
					strncpy((char*) pwd, kval, sizeof(st_password_t));
					ret = 0;
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong password data for user %s: NULL\n", usname);
				}
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}

		sqlite3_finalize(st);
	}
	return ret;
}

static int sqlite_get_oauth_key(const u08bits *kid, oauth_key_data_raw *key) {

	int ret = -1;

	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	snprintf(statement,sizeof(statement),"select ikm_key,timestamp,lifetime,hkdf_hash_func,as_rs_alg,as_rs_key,auth_alg,auth_key from oauth_key where kid='%s'",(const char*)kid);

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			int res = sqlite3_step(st);
			if (res == SQLITE_ROW) {

				STRCPY((char*)key->ikm_key,sqlite3_column_text(st, 0));
				key->timestamp = (u64bits)strtoll((const char*)sqlite3_column_text(st, 1),NULL,10);
				key->lifetime = (u32bits)strtol((const char*)sqlite3_column_text(st, 2),NULL,10);
				STRCPY((char*)key->hkdf_hash_func,sqlite3_column_text(st, 3));
				STRCPY((char*)key->as_rs_alg,sqlite3_column_text(st, 4));
				STRCPY((char*)key->as_rs_key,sqlite3_column_text(st, 5));
				STRCPY((char*)key->auth_alg,sqlite3_column_text(st, 6));
				STRCPY((char*)key->auth_key,sqlite3_column_text(st, 7));
				STRCPY((char*)key->kid,kid);
				ret = 0;
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}

		sqlite3_finalize(st);
	}

	return ret;
}

static int sqlite_list_oauth_keys(void) {

	oauth_key_data_raw key_;
	oauth_key_data_raw *key=&key_;

	int ret = -1;

	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	snprintf(statement,sizeof(statement),"select ikm_key,timestamp,lifetime,hkdf_hash_func,as_rs_alg,as_rs_key,auth_alg,auth_key,kid from oauth_key order by kid");

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			ret = 0;
			while (1) {
				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					STRCPY((char*)key->ikm_key,sqlite3_column_text(st, 0));
					key->timestamp = (u64bits)strtoll((const char*)sqlite3_column_text(st, 1),NULL,10);
					key->lifetime = (u32bits)strtol((const char*)sqlite3_column_text(st, 2),NULL,10);
					STRCPY((char*)key->hkdf_hash_func,sqlite3_column_text(st, 3));
					STRCPY((char*)key->as_rs_alg,sqlite3_column_text(st, 4));
					STRCPY((char*)key->as_rs_key,sqlite3_column_text(st, 5));
					STRCPY((char*)key->auth_alg,sqlite3_column_text(st, 6));
					STRCPY((char*)key->auth_key,sqlite3_column_text(st, 7));
					STRCPY((char*)key->kid,sqlite3_column_text(st, 7));

					printf("  kid=%s, ikm_key=%s, timestamp=%llu, lifetime=%lu, hkdf_hash_func=%s, as_rs_alg=%s, as_rs_key=%s, auth_alg=%s, auth_key=%s\n",
						key->kid, key->ikm_key, (unsigned long long)key->timestamp, (unsigned long)key->lifetime, key->hkdf_hash_func,
						key->as_rs_alg, key->as_rs_key, key->auth_alg, key->auth_key);

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
	}

	return ret;
}

static int sqlite_set_user_key(u08bits *usname, u08bits *realm, const char *key)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {

		snprintf(statement, sizeof(statement), "insert or replace into turnusers_lt (realm,name,hmackey) values('%s','%s','%s')", realm, usname, key);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
	}
	return ret;
}

static int sqlite_set_oauth_key(oauth_key_data_raw *key)
{

	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		snprintf(
						statement,
						sizeof(statement),
						"insert or replace into oauth_key (kid,ikm_key,timestamp,lifetime,hkdf_hash_func,as_rs_alg,as_rs_key,auth_alg,auth_key) values('%s','%s',%llu,%lu,'%s','%s','%s','%s','%s')",
						key->kid, key->ikm_key, (unsigned long long) key->timestamp, (unsigned long) key->lifetime, key->hkdf_hash_func, key->as_rs_alg, key->as_rs_key, key->auth_alg,
						key->auth_key);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
	}
	return ret;
}

static int sqlite_set_user_pwd(u08bits *usname, st_password_t pwd)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		snprintf(statement, sizeof(statement), "insert or replace into turnusers_st values('%s','%s')", usname, pwd);
		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
	}
	return ret;
}

static int sqlite_del_user(u08bits *usname, int is_st, u08bits *realm)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		if (is_st) {
			snprintf(statement, sizeof(statement), "delete from turnusers_st where name='%s'", usname);
		} else {
			snprintf(statement, sizeof(statement), "delete from turnusers_lt where name='%s' and realm='%s'", usname, realm);
		}
		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
	}
	return ret;
}

static int sqlite_del_oauth_key(const u08bits *kid)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		snprintf(statement, sizeof(statement), "delete from oauth_key where kid = '%s'", (const char*) kid);

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
	}
	return ret;
}


static int sqlite_list_users(int is_st, u08bits *realm)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		if (is_st) {
			snprintf(statement, sizeof(statement), "select name,'' from turnusers_st order by name");
		} else if (realm && realm[0]) {
			snprintf(statement, sizeof(statement), "select name,realm from turnusers_lt where realm='%s' order by name", realm);
		} else {
			snprintf(statement, sizeof(statement), "select name,realm from turnusers_lt order by name");
		}
		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			ret = 0;
			while (1) {
				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					const char* kval = (const char*) sqlite3_column_text(st, 0);
					const char* rval = (const char*) sqlite3_column_text(st, 1);

					if (rval && *rval) {
						printf("%s[%s]\n", kval, rval);
					} else {
						printf("%s\n", kval);
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
	}
	return ret;
}

static int sqlite_show_secret(u08bits *realm)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	snprintf(statement,sizeof(statement)-1,"select value from turn_secret where realm='%s'",realm);

	donot_print_connection_success=1;

	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {
		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			int res = sqlite3_step(st);
			if (res == SQLITE_ROW) {
				ret = 0;
				const char* kval = (const char*) sqlite3_column_text(st, 0);
				if(kval) {
					printf("%s\n",kval);
				}
			}
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
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

		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
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
	  if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
	}
	return ret;
}
  
static int sqlite_add_origin(u08bits *origin, u08bits *realm)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {
		snprintf(statement,sizeof(statement),"insert or replace into turn_origin_to_realm (origin,realm) values('%s','%s')",origin,realm);
		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
	}
	return ret;
}
  
static int sqlite_del_origin(u08bits *origin)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {
		snprintf(statement,sizeof(statement),"delete from turn_origin_to_realm where origin='%s'",origin);
		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
			sqlite3_step(st);
			ret = 0;
		} else {
			const char* errmsg = sqlite3_errmsg(sqliteconnection);
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
		}
		sqlite3_finalize(st);
	}
	return ret;
}

static int sqlite_list_origins(u08bits *realm)
{
	int ret = -1;
	donot_print_connection_success = 1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if (sqliteconnection) {
		if (realm && realm[0]) {
			snprintf(statement, sizeof(statement), "select origin,realm from turn_origin_to_realm where realm='%s' order by origin", realm);
		} else {
			snprintf(statement, sizeof(statement), "select origin,realm from turn_origin_to_realm order by origin,realm");
		}
		if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {

			ret = 0;
			while (1) {
				int res = sqlite3_step(st);
				if (res == SQLITE_ROW) {

					const char* kval = (const char*) sqlite3_column_text(st, 0);
					const char* rval = (const char*) sqlite3_column_text(st, 1);

					printf("%s ==>> %s\n",kval,rval);

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
	}
	return ret;
}
  
static int sqlite_set_realm_option_one(u08bits *realm, unsigned long value, const char* opt)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	sqlite3_stmt *st = NULL;
	int rc = 0;
	sqlite3 *sqliteconnection = get_sqlite_connection();
	if(sqliteconnection) {
		if(value>0) {
			snprintf(statement,sizeof(statement),"insert or replace into turn_realm_option (realm,opt,value) values('%s','%s','%lu')",realm,opt,(unsigned long)value);
			if ((rc = sqlite3_prepare(sqliteconnection, statement, -1, &st, 0)) == SQLITE_OK) {
				sqlite3_step(st);
				ret = 0;
			} else {
				const char* errmsg = sqlite3_errmsg(sqliteconnection);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving SQLite DB information: %s\n", errmsg);
			}
			sqlite3_finalize(st);
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
							rp->options.perf_options.max_bps = (band_limit_t)atol(vval);
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
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static turn_dbdriver_t driver = {
  &sqlite_get_auth_secrets,
  &sqlite_get_user_key,
  &sqlite_get_user_pwd,
  &sqlite_set_user_key,
  &sqlite_set_user_pwd,
  &sqlite_del_user,
  &sqlite_list_users,
  &sqlite_show_secret,
  &sqlite_del_secret,
  &sqlite_set_secret,
  &sqlite_add_origin,
  &sqlite_del_origin,
  &sqlite_list_origins,
  &sqlite_set_realm_option_one,
  &sqlite_list_realm_options,
  &sqlite_auth_ping,
  &sqlite_get_ip_list,
  &sqlite_reread_realms,
  &sqlite_set_oauth_key,
  &sqlite_get_oauth_key,
  &sqlite_del_oauth_key,
  &sqlite_list_oauth_keys
};

//////////////////////////////////////////////////

turn_dbdriver_t * get_sqlite_dbdriver(void) {
	return &driver;
}

//////////////////////////////////////////////////

#endif
