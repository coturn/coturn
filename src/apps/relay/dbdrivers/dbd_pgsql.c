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
#include "dbd_pgsql.h"

#if !defined(TURN_NO_PQ)
#include <libpq-fe.h>

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int donot_print_connection_success = 0;

static PGconn *get_pqdb_connection(void) {

	persistent_users_db_t *pud = get_persistent_users_db();

	PGconn *pqdbconnection = (PGconn*)pthread_getspecific(connection_key);
	if(pqdbconnection) {
		ConnStatusType status = PQstatus(pqdbconnection);
		if(status != CONNECTION_OK) {
			PQfinish(pqdbconnection);
			pqdbconnection = NULL;
			(void) pthread_setspecific(connection_key, pqdbconnection);
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
					donot_print_connection_success = 1;
				}
			}
		}

		if(pqdbconnection) {
			(void) pthread_setspecific(connection_key, pqdbconnection);
		}
	}
	return pqdbconnection;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int pgsql_get_auth_secrets(secrets_list_t *sl, u08bits *realm) {
  int ret = -1;
	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		char statement[TURN_LONG_STRING_SIZE];
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
  return ret;
}
  
static int pgsql_get_user_key(u08bits *usname, u08bits *realm, hmackey_t key) {
  int ret = -1;
	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		char statement[TURN_LONG_STRING_SIZE];
		/* direct user input eliminated - there is no SQL injection problem (since version 4.4.5.3) */
		snprintf(statement,sizeof(statement),"select hmackey from turnusers_lt where name='%s' and realm='%s'",usname,realm);
		PGresult *res = PQexec(pqc, statement);

		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK) || (PQntuples(res)!=1)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		} else {
			char *kval = PQgetvalue(res,0,0);
			int len = PQgetlength(res,0,0);
			if(kval) {
				size_t sz = get_hmackey_size(SHATYPE_DEFAULT);
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
  return ret;
}

static int pgsql_get_oauth_key(const u08bits *kid, oauth_key_data_raw *key) {

	int ret = -1;

	char statement[TURN_LONG_STRING_SIZE];
	/* direct user input eliminated - there is no SQL injection problem (since version 4.4.5.3) */
	snprintf(statement,sizeof(statement),"select ikm_key,timestamp,lifetime,as_rs_alg,realm from oauth_key where kid='%s'",(const char*)kid);

	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		PGresult *res = PQexec(pqc, statement);

		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK) || (PQntuples(res)!=1)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		} else {
			STRCPY(key->ikm_key,PQgetvalue(res,0,0));
			key->timestamp = (u64bits)strtoll(PQgetvalue(res,0,1),NULL,10);
			key->lifetime = (u32bits)strtol(PQgetvalue(res,0,2),NULL,10);
			STRCPY(key->as_rs_alg,PQgetvalue(res,0,3));
			STRCPY(key->realm,PQgetvalue(res,0,4));
			STRCPY(key->kid,kid);
			ret = 0;
		}

		if(res) {
			PQclear(res);
		}
	}

	return ret;
}

static int pgsql_list_oauth_keys(secrets_list_t *kids,secrets_list_t *teas,secrets_list_t *tss,secrets_list_t *lts,secrets_list_t *realms) {

	oauth_key_data_raw key_;
	oauth_key_data_raw *key=&key_;

	int ret = -1;

	char statement[TURN_LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement),"select ikm_key,timestamp,lifetime,as_rs_alg,realm,kid from oauth_key order by kid");

	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		PGresult *res = PQexec(pqc, statement);

		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		} else {
			int i = 0;
			for(i=0;i<PQntuples(res);i++) {

				STRCPY(key->ikm_key,PQgetvalue(res,i,0));
				key->timestamp = (u64bits)strtoll(PQgetvalue(res,i,1),NULL,10);
				key->lifetime = (u32bits)strtol(PQgetvalue(res,i,2),NULL,10);
				STRCPY(key->as_rs_alg,PQgetvalue(res,i,3));
				STRCPY(key->realm,PQgetvalue(res,i,4));
				STRCPY(key->kid,PQgetvalue(res,i,5));

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

				ret = 0;
			}
		}

		if(res) {
			PQclear(res);
		}
	}

	return ret;
}
  
static int pgsql_set_user_key(u08bits *usname, u08bits *realm, const char *key) {
  int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	PGconn *pqc = get_pqdb_connection();
	if(pqc) {
	  snprintf(statement,sizeof(statement),"insert into turnusers_lt (realm,name,hmackey) values('%s','%s','%s')",realm,usname,key);

		PGresult *res = PQexec(pqc, statement);
		if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
			if(res) {
				PQclear(res);
			}
			snprintf(statement,sizeof(statement),"update turnusers_lt set hmackey='%s' where name='%s' and realm='%s'",key,usname,realm);
			res = PQexec(pqc, statement);
			if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating user information: %s\n",PQerrorMessage(pqc));
			} else {
			  ret = 0;
			}
		}
		if(res) {
			PQclear(res);
		}
	}
  return ret;
}

static int pgsql_set_oauth_key(oauth_key_data_raw *key) {

  int ret = -1;
  char statement[TURN_LONG_STRING_SIZE];
  PGconn *pqc = get_pqdb_connection();
  if(pqc) {
	  snprintf(statement,sizeof(statement),"insert into oauth_key (kid,ikm_key,timestamp,lifetime,as_rs_alg,realm) values('%s','%s',%llu,%lu,'%s','%s')",
			  key->kid,key->ikm_key,(unsigned long long)key->timestamp,(unsigned long)key->lifetime,
			  key->as_rs_alg,key->realm);

	  PGresult *res = PQexec(pqc, statement);
	  if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
		  if(res) {
			PQclear(res);
		  }
		  snprintf(statement,sizeof(statement),"update oauth_key set ikm_key='%s',timestamp=%lu,lifetime=%lu, as_rs_alg='%s', realm='%s' where kid='%s'",key->ikm_key,(unsigned long)key->timestamp,(unsigned long)key->lifetime,
				  key->as_rs_alg,key->realm,key->kid);
		  res = PQexec(pqc, statement);
		  if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating oauth_key information: %s\n",PQerrorMessage(pqc));
		  } else {
			  ret = 0;
		  }
	  } else {
		  ret = 0;
	  }

	  if(res) {
		  PQclear(res);
	  }
  }
  return ret;
}
  
static int pgsql_del_user(u08bits *usname, u08bits *realm) {
  int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	PGconn *pqc = get_pqdb_connection();
	if(pqc) {
		snprintf(statement,sizeof(statement),"delete from turnusers_lt where name='%s' and realm='%s'",usname,realm);
		PGresult *res = PQexec(pqc, statement);
		if(res) {
			PQclear(res);
      ret = 0;
		}
	}
  return ret;
}

static int pgsql_del_oauth_key(const u08bits *kid) {

  int ret = -1;
  char statement[TURN_LONG_STRING_SIZE];
  PGconn *pqc = get_pqdb_connection();
  if(pqc) {
	  snprintf(statement,sizeof(statement),"delete from oauth_key where kid = '%s'",(const char*)kid);

	  PGresult *res = PQexec(pqc, statement);
	  if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
		  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error deleting oauth_key information: %s\n",PQerrorMessage(pqc));
	  } else {
		  ret = 0;
	  }
	  if(res) {
		  PQclear(res);
	  }
  }
  return ret;
}
  
static int pgsql_list_users(u08bits *realm, secrets_list_t *users, secrets_list_t *realms)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	PGconn *pqc = get_pqdb_connection();
	if(pqc) {
		if(realm[0]) {
		  snprintf(statement,sizeof(statement),"select name,realm from turnusers_lt where realm='%s' order by name",realm);
		} else {
		  snprintf(statement,sizeof(statement),"select name,realm from turnusers_lt order by realm,name");
		}
		PGresult *res = PQexec(pqc, statement);
		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		} else {
			int i = 0;
			for(i=0;i<PQntuples(res);i++) {
				char *kval = PQgetvalue(res,i,0);
				if(kval) {
					char *rval = PQgetvalue(res,i,1);
					if(rval) {
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
					}
				}
			}
			ret = 0;
		}
		if(res) {
			PQclear(res);
		}
	}
  return ret;
}
  
static int pgsql_list_secrets(u08bits *realm, secrets_list_t *secrets, secrets_list_t *realms)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	char statement[TURN_LONG_STRING_SIZE];
	if (realm[0]) {
		snprintf(statement, sizeof(statement), "select value,realm from turn_secret where realm='%s' order by value", realm);
	} else {
		snprintf(statement, sizeof(statement), "select value,realm from turn_secret order by realm,value");
	}

	donot_print_connection_success=1;

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
					char* rval = PQgetvalue(res,i,1);
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
			}
			ret = 0;
		}
		if(res) {
			PQclear(res);
		}
	}
	return ret;
}
  
static int pgsql_del_secret(u08bits *secret, u08bits *realm) {
  int ret = -1;
	donot_print_connection_success=1;
	char statement[TURN_LONG_STRING_SIZE];
	PGconn *pqc = get_pqdb_connection();
	if (pqc) {
		if(!secret || (secret[0]==0))
		  snprintf(statement,sizeof(statement),"delete from turn_secret where realm='%s'",realm);
		else
		  snprintf(statement,sizeof(statement),"delete from turn_secret where value='%s' and realm='%s'",secret,realm);

		PGresult *res = PQexec(pqc, statement);
		if (res) {
			PQclear(res);
      ret = 0;
		}
	}
  return ret;
}
  
static int pgsql_set_secret(u08bits *secret, u08bits *realm) {
  int ret = -1;
	donot_print_connection_success = 1;
	char statement[TURN_LONG_STRING_SIZE];
	PGconn *pqc = get_pqdb_connection();
	if (pqc) {
	  snprintf(statement,sizeof(statement),"insert into turn_secret (realm,value) values('%s','%s')",realm,secret);
	  PGresult *res = PQexec(pqc, statement);
	  if (!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
		  TURN_LOG_FUNC(
			  TURN_LOG_LEVEL_ERROR,
			  "Error inserting/updating secret key information: %s\n",
			  PQerrorMessage(pqc));
	  } else {
	    ret = 0;
	  }
	  if (res) {
	    PQclear(res);
	  }
	}

	return ret;
}

static int pgsql_set_permission_ip(const char *kind, u08bits *realm, const char* ip, int del)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	donot_print_connection_success = 1;

	char statement[TURN_LONG_STRING_SIZE];

	PGconn *pqc = get_pqdb_connection();

	if (pqc) {

		if(del) {
			snprintf(statement, sizeof(statement), "delete from %s_peer_ip where realm = '%s'  and ip_range = '%s'", kind, (char*)realm, ip);
		} else {
			snprintf(statement, sizeof(statement), "insert into %s_peer_ip (realm,ip_range) values('%s','%s')", kind, (char*)realm, ip);
		}

		PGresult *res = PQexec(pqc, statement);
		if (!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
			TURN_LOG_FUNC(
				TURN_LOG_LEVEL_ERROR,
				"Error inserting ip permission information: %s\n",
				PQerrorMessage(pqc));
	  } else {
	    ret = 0;
	  }
	  if (res) {
	    PQclear(res);
	  }
	}

	return ret;
}
  
static int pgsql_add_origin(u08bits *origin, u08bits *realm) {
  int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	PGconn *pqc = get_pqdb_connection();
	if(pqc) {
		snprintf(statement,sizeof(statement),"insert into turn_origin_to_realm (origin,realm) values('%s','%s')",origin,realm);
		PGresult *res = PQexec(pqc, statement);
		if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting origin information: %s\n",PQerrorMessage(pqc));
		} else {
		  ret = 0;
		}
		if(res) {
			PQclear(res);
		}
	}
  return ret;
}
  
static int pgsql_del_origin(u08bits *origin) {
  int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	PGconn *pqc = get_pqdb_connection();
	if(pqc) {
		snprintf(statement,sizeof(statement),"delete from turn_origin_to_realm where origin='%s'",origin);
		PGresult *res = PQexec(pqc, statement);
		if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error deleting origin information: %s\n",PQerrorMessage(pqc));
		} else {
		  ret = 0;
		}
		if(res) {
			PQclear(res);
		}
	}
  return ret;
}
  
static int pgsql_list_origins(u08bits *realm, secrets_list_t *origins, secrets_list_t *realms)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	donot_print_connection_success = 1;

	PGconn *pqc = get_pqdb_connection();

	if(pqc) {

		char statement[TURN_LONG_STRING_SIZE];

		if(realm && realm[0]) {
		  snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm where realm='%s' order by origin",realm);
		} else {
		  snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm order by realm,origin");
		}
		PGresult *res = PQexec(pqc, statement);
		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		} else {
			int i = 0;
			for(i=0;i<PQntuples(res);i++) {
				char *kval = PQgetvalue(res,i,0);
				if(kval) {
					char *rval = PQgetvalue(res,i,1);
					if(rval) {
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
					}
				}
			}
			ret = 0;
		}
		if(res) {
			PQclear(res);
		}
	}
	return ret;
}
  
static int pgsql_set_realm_option_one(u08bits *realm, unsigned long value, const char* opt) {
  int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
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
			snprintf(statement,sizeof(statement),"insert into turn_realm_option (realm,opt,value) values('%s','%s','%lu')",realm,opt,(unsigned long)value);
			PGresult *res = PQexec(pqc, statement);
			if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting realm option information: %s\n",PQerrorMessage(pqc));
			} else {
			  ret = 0;
			}
			if(res) {
				PQclear(res);
			}
		}
	}
  return ret;
}
  
static int pgsql_list_realm_options(u08bits *realm) {
  int ret = -1;
	donot_print_connection_success = 1;
	char statement[TURN_LONG_STRING_SIZE];
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
      ret = 0;
		}
		if(res) {
			PQclear(res);
		}
	}
  return ret;
}
  
static void pgsql_auth_ping(void * rch) {
	UNUSED_ARG(rch);
	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		char statement[TURN_LONG_STRING_SIZE];
		STRCPY(statement,"select value from turn_secret");
		PGresult *res = PQexec(pqc, statement);

		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		}

		if(res) {
			PQclear(res);
		}
	}
}
  

static int pgsql_get_ip_list(const char *kind, ip_range_list_t * list)
{
	int ret = -1;
	PGconn * pqc = get_pqdb_connection();
	if (pqc) {
		char statement[TURN_LONG_STRING_SIZE];
		snprintf(statement, sizeof(statement), "select ip_range,realm from %s_peer_ip", kind);
		PGresult *res = PQexec(pqc, statement);

		if (!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
			static int wrong_table_reported = 0;
			if(!wrong_table_reported) {
				wrong_table_reported = 1;
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s; probably, the tables 'allowed_peer_ip' and/or 'denied_peer_ip' have to be upgraded to include the realm column.\n",PQerrorMessage(pqc));
			}
			snprintf(statement, sizeof(statement), "select ip_range,'' from %s_peer_ip", kind);
			res = PQexec(pqc, statement);
		}

		if (res && (PQresultStatus(res) == PGRES_TUPLES_OK)) {
			int i = 0;
			for (i = 0; i < PQntuples(res); i++) {
				char *kval = PQgetvalue(res, i, 0);
				char *rval = PQgetvalue(res, i, 1);
				if (kval) {
					add_ip_list_range(kval, rval, list);
				}
			}
			ret = 0;
		}

		if (res) {
			PQclear(res);
		}
	}
	return ret;
}
  
static void pgsql_reread_realms(secrets_list_t * realms_list) {
	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		char statement[TURN_LONG_STRING_SIZE];

		{
			snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm");
			PGresult *res = PQexec(pqc, statement);

			if(res && (PQresultStatus(res) == PGRES_TUPLES_OK)) {

				ur_string_map *o_to_realm_new = ur_string_map_create(turn_free_simple);

				int i = 0;
				for(i=0;i<PQntuples(res);i++) {
					char *oval = PQgetvalue(res,i,0);
					if(oval) {
						char *rval = PQgetvalue(res,i,1);
						if(rval) {
							get_realm(rval);
							ur_string_map_value_type value = turn_strdup(rval);
							ur_string_map_put(o_to_realm_new, (const ur_string_map_key_type) oval, value);
						}
					}
				}

        update_o_to_realm(o_to_realm_new);
			}

			if(res) {
				PQclear(res);
			}
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
							rp->options.perf_options.max_bps = (band_limit_t)strtoul(vval,NULL,10);
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
}

//////////////////////////////////////////////

static int pgsql_get_admin_user(const u08bits *usname, u08bits *realm, password_t pwd)
{
	int ret = -1;

	realm[0]=0;
	pwd[0]=0;

	PGconn * pqc = get_pqdb_connection();
	if(pqc) {
		char statement[TURN_LONG_STRING_SIZE];
		snprintf(statement,sizeof(statement),"select realm,password from admin_user where name='%s'",usname);
		PGresult *res = PQexec(pqc, statement);

		if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK) || (PQntuples(res)!=1)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
		} else {
			const char *kval = PQgetvalue(res,0,0);
			if(kval) {
				strncpy((char*)realm,kval,STUN_MAX_REALM_SIZE);
			}
			kval = (const char*) PQgetvalue(res,0,1);
			if(kval) {
				strncpy((char*)pwd,kval,STUN_MAX_PWD_SIZE);
			}
			ret = 0;
		}

		if(res)
			PQclear(res);

	}
	return ret;
}

static int pgsql_set_admin_user(const u08bits *usname, const u08bits *realm, const password_t pwd)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	donot_print_connection_success=1;
	PGconn *pqc = get_pqdb_connection();
	if(pqc) {
	  snprintf(statement,sizeof(statement),"insert into admin_user (realm,name,password) values('%s','%s','%s')",realm,usname,pwd);

	  PGresult *res = PQexec(pqc, statement);
	  if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
		if(res) {
			PQclear(res);
		}
		snprintf(statement,sizeof(statement),"update admin_user set password='%s',realm='%s' where name='%s'",pwd,realm,usname);
		res = PQexec(pqc, statement);
		if(!res || (PQresultStatus(res) != PGRES_COMMAND_OK)) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating user information: %s\n",PQerrorMessage(pqc));
		} else {
		  ret = 0;
		}
	  }
	  if(res) {
		PQclear(res);
	  }
	}
	return ret;
}

static int pgsql_del_admin_user(const u08bits *usname)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	donot_print_connection_success=1;
	PGconn *pqc = get_pqdb_connection();
	if(pqc) {
		snprintf(statement,sizeof(statement),"delete from admin_user where name='%s'",usname);
		PGresult *res = PQexec(pqc, statement);
		if(res) {
			PQclear(res);
			ret = 0;
		}
	}
	return ret;
}

static int pgsql_list_admin_users(int no_print)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	donot_print_connection_success=1;
	PGconn *pqc = get_pqdb_connection();
	if(pqc) {
		snprintf(statement,sizeof(statement),"select name,realm,password from admin_user order by realm,name");
	}
	PGresult *res = PQexec(pqc, statement);
	if(!res || (PQresultStatus(res) != PGRES_TUPLES_OK)) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving PostgreSQL DB information: %s\n",PQerrorMessage(pqc));
	} else {
		int i = 0;
		ret = 0;
		for(i=0;i<PQntuples(res);i++) {
			char *kval = PQgetvalue(res,i,0);
			++ret;
			if(kval && !no_print) {
				char *rval = PQgetvalue(res,i,1);
				if(rval && *rval) {
					printf("%s[%s]\n",kval,rval);
				} else {
					printf("%s\n",kval);
				}
			}
		}
	}
	if(res) {
		PQclear(res);
	}
	return ret;
}

/////////////////////////////////////////////////////////////

static const turn_dbdriver_t driver = {
  &pgsql_get_auth_secrets,
  &pgsql_get_user_key,
  &pgsql_set_user_key,
  &pgsql_del_user,
  &pgsql_list_users,
  &pgsql_list_secrets,
  &pgsql_del_secret,
  &pgsql_set_secret,
  &pgsql_add_origin,
  &pgsql_del_origin,
  &pgsql_list_origins,
  &pgsql_set_realm_option_one,
  &pgsql_list_realm_options,
  &pgsql_auth_ping,
  &pgsql_get_ip_list,
  &pgsql_set_permission_ip,
  &pgsql_reread_realms,
  &pgsql_set_oauth_key,
  &pgsql_get_oauth_key,
  &pgsql_del_oauth_key,
  &pgsql_list_oauth_keys,
  &pgsql_get_admin_user,
  &pgsql_set_admin_user,
  &pgsql_del_admin_user,
  &pgsql_list_admin_users
};

const turn_dbdriver_t * get_pgsql_dbdriver(void) {
  return &driver;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

#else

const turn_dbdriver_t * get_pgsql_dbdriver(void) {
  return NULL;
}

#endif
