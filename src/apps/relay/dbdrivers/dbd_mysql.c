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
#include "dbd_mysql.h"

#if !defined(TURN_NO_MYSQL)
#include <mysql.h>

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int donot_print_connection_success = 0;

struct _Myconninfo {
	char *host;
	char *dbname;
	char *user;
	char *password;
	unsigned int port;
	unsigned int connect_timeout;
	/* SSL ==>> */
	char *key;
	char *ca;
	char *cert;
	char *capath;
	char *cipher;
	/* <<== SSL : see http://dev.mysql.com/doc/refman/5.0/en/mysql-ssl-set.html */
};

typedef struct _Myconninfo Myconninfo;

static void MyconninfoFree(Myconninfo *co) {
	if(co) {
		if(co->host) turn_free(co->host,strlen(co->host)+1);
		if(co->dbname) turn_free(co->dbname, strlen(co->dbname)+1);
		if(co->user) turn_free(co->user, strlen(co->user)+1);
		if(co->password) turn_free(co->password, strlen(co->password)+1);
		if(co->key) turn_free(co->key, strlen(co->key)+1);
		if(co->ca) turn_free(co->ca, strlen(co->ca)+1);
		if(co->cert) turn_free(co->cert, strlen(co->cert)+1);
		if(co->capath) turn_free(co->capath, strlen(co->capath)+1);
		if(co->cipher) turn_free(co->cipher, strlen(co->cipher)+1);
		ns_bzero(co,sizeof(Myconninfo));
	}
}

static Myconninfo *MyconninfoParse(char *userdb, char **errmsg) {
	Myconninfo *co = (Myconninfo*)turn_malloc(sizeof(Myconninfo));
	ns_bzero(co,sizeof(Myconninfo));
	if(userdb) {
		char *s0=turn_strdup(userdb);
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
					*errmsg = turn_strdup(s);
				}
				break;
			}

			*seq = 0;
			if(!strcmp(s,"host"))
				co->host = turn_strdup(seq+1);
			else if(!strcmp(s,"ip"))
				co->host = turn_strdup(seq+1);
			else if(!strcmp(s,"addr"))
				co->host = turn_strdup(seq+1);
			else if(!strcmp(s,"ipaddr"))
				co->host = turn_strdup(seq+1);
			else if(!strcmp(s,"hostaddr"))
				co->host = turn_strdup(seq+1);
			else if(!strcmp(s,"dbname"))
				co->dbname = turn_strdup(seq+1);
			else if(!strcmp(s,"db"))
				co->dbname = turn_strdup(seq+1);
			else if(!strcmp(s,"database"))
				co->dbname = turn_strdup(seq+1);
			else if(!strcmp(s,"user"))
				co->user = turn_strdup(seq+1);
			else if(!strcmp(s,"uname"))
				co->user = turn_strdup(seq+1);
			else if(!strcmp(s,"name"))
				co->user = turn_strdup(seq+1);
			else if(!strcmp(s,"username"))
				co->user = turn_strdup(seq+1);
			else if(!strcmp(s,"password"))
				co->password = turn_strdup(seq+1);
			else if(!strcmp(s,"pwd"))
				co->password = turn_strdup(seq+1);
			else if(!strcmp(s,"passwd"))
				co->password = turn_strdup(seq+1);
			else if(!strcmp(s,"secret"))
				co->password = turn_strdup(seq+1);
			else if(!strcmp(s,"port"))
				co->port = (unsigned int)atoi(seq+1);
			else if(!strcmp(s,"p"))
				co->port = (unsigned int)atoi(seq+1);
			else if(!strcmp(s,"connect_timeout"))
				co->connect_timeout = (unsigned int)atoi(seq+1);
			else if(!strcmp(s,"timeout"))
				co->connect_timeout = (unsigned int)atoi(seq+1);
			else if(!strcmp(s,"key"))
				co->key = turn_strdup(seq+1);
			else if(!strcmp(s,"ssl-key"))
				co->key = turn_strdup(seq+1);
			else if(!strcmp(s,"ca"))
				co->ca = turn_strdup(seq+1);
			else if(!strcmp(s,"ssl-ca"))
				co->ca = turn_strdup(seq+1);
			else if(!strcmp(s,"capath"))
				co->capath = turn_strdup(seq+1);
			else if(!strcmp(s,"ssl-capath"))
				co->capath = turn_strdup(seq+1);
			else if(!strcmp(s,"cert"))
				co->cert = turn_strdup(seq+1);
			else if(!strcmp(s,"ssl-cert"))
				co->cert = turn_strdup(seq+1);
			else if(!strcmp(s,"cipher"))
				co->cipher = turn_strdup(seq+1);
			else if(!strcmp(s,"ssl-cipher"))
				co->cipher = turn_strdup(seq+1);
			else {
				MyconninfoFree(co);
				co = NULL;
				if(errmsg) {
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
		if(!(co->user))
			co->user=turn_strdup("");
		if(!(co->password))
			co->password=turn_strdup("");
	}

	return co;
}

static MYSQL *get_mydb_connection(void) {

	persistent_users_db_t *pud = get_persistent_users_db();

	MYSQL *mydbconnection = (MYSQL*)pthread_getspecific(connection_key);

	if(mydbconnection) {
		if(mysql_ping(mydbconnection)) {
			mysql_close(mydbconnection);
			mydbconnection=NULL;
			(void) pthread_setspecific(connection_key, mydbconnection);
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
				if(co->ca || co->capath || co->cert || co->cipher || co->key) {
					mysql_ssl_set(mydbconnection, co->key, co->cert, co->ca, co->capath, co->cipher);
				}
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
					donot_print_connection_success = 1;
				}
			}
			MyconninfoFree(co);
		}
		if(mydbconnection) {
			(void) pthread_setspecific(connection_key, mydbconnection);
		}
	}
	return mydbconnection;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int mysql_get_auth_secrets(secrets_list_t *sl, u08bits *realm) {
  int ret = -1;
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[TURN_LONG_STRING_SIZE];
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
								char auth_secret[TURN_LONG_STRING_SIZE];
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
  return ret;
}
  
static int mysql_get_user_key(u08bits *usname, u08bits *realm, hmackey_t key) {
  int ret = -1;
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[TURN_LONG_STRING_SIZE];
		/* direct user input eliminated - there is no SQL injection problem (since version 4.4.5.3) */
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
						size_t sz = get_hmackey_size(SHATYPE_DEFAULT)*2;
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
  return ret;
}

static int mysql_get_oauth_key(const u08bits *kid, oauth_key_data_raw *key) {

	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	/* direct user input eliminated - there is no SQL injection problem (since version 4.4.5.3) */
	snprintf(statement,sizeof(statement),"select ikm_key,timestamp,lifetime,as_rs_alg,realm from oauth_key where kid='%s'",(const char*)kid);

	MYSQL * myc = get_mydb_connection();
	if(myc) {
		int res = mysql_query(myc, statement);
		if(res) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
		} else {
			MYSQL_RES *mres = mysql_store_result(myc);
			if(!mres) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else if(mysql_field_count(myc)!=5) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown error retrieving MySQL DB information: %s\n",statement);
			} else {
				MYSQL_ROW row = mysql_fetch_row(mres);
				if(row && row[0]) {
					unsigned long *lengths = mysql_fetch_lengths(mres);
					if(lengths) {
						STRCPY(key->kid,kid);
						ns_bcopy(row[0],key->ikm_key,lengths[0]);
						key->ikm_key[lengths[0]]=0;

						char stimestamp[128];
						ns_bcopy(row[1],stimestamp,lengths[1]);
						stimestamp[lengths[1]]=0;
						key->timestamp = (u64bits)strtoull(stimestamp,NULL,10);

						char slifetime[128];
						ns_bcopy(row[2],slifetime,lengths[2]);
						slifetime[lengths[2]]=0;
						key->lifetime = (u32bits)strtoul(slifetime,NULL,10);

						ns_bcopy(row[3],key->as_rs_alg,lengths[3]);
						key->as_rs_alg[lengths[3]]=0;

						ns_bcopy(row[4],key->realm,lengths[4]);
						key->realm[lengths[4]]=0;

						ret = 0;
					}
				}
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
	return ret;
}

static int mysql_list_oauth_keys(secrets_list_t *kids,secrets_list_t *teas,secrets_list_t *tss,secrets_list_t *lts,secrets_list_t *realms) {

	oauth_key_data_raw key_;
	oauth_key_data_raw *key=&key_;
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement),"select ikm_key,timestamp,lifetime,as_rs_alg,realm,kid from oauth_key order by kid");

	MYSQL * myc = get_mydb_connection();
	if(myc) {
		int res = mysql_query(myc, statement);
		if(res) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
		} else {
			MYSQL_RES *mres = mysql_store_result(myc);
			if(!mres) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information: %s\n",mysql_error(myc));
			} else if(mysql_field_count(myc)!=6) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown error retrieving MySQL DB information: %s\n",statement);
			} else {
				MYSQL_ROW row = mysql_fetch_row(mres);
				while(row) {
					unsigned long *lengths = mysql_fetch_lengths(mres);
					if(lengths) {

						ns_bcopy(row[0],key->ikm_key,lengths[0]);
						key->ikm_key[lengths[0]]=0;

						char stimestamp[128];
						ns_bcopy(row[1],stimestamp,lengths[1]);
						stimestamp[lengths[1]]=0;
						key->timestamp = (u64bits)strtoull(stimestamp,NULL,10);

						char slifetime[128];
						ns_bcopy(row[2],slifetime,lengths[2]);
						slifetime[lengths[2]]=0;
						key->lifetime = (u32bits)strtoul(slifetime,NULL,10);

						ns_bcopy(row[3],key->as_rs_alg,lengths[3]);
						key->as_rs_alg[lengths[3]]=0;

						ns_bcopy(row[4],key->realm,lengths[4]);
						key->realm[lengths[4]]=0;

						ns_bcopy(row[5],key->kid,lengths[5]);
						key->kid[lengths[5]]=0;

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
					row = mysql_fetch_row(mres);
				}
			}

			if(mres)
				mysql_free_result(mres);
		}
	}

	return ret;
}
  
static int mysql_set_user_key(u08bits *usname, u08bits *realm, const char *key)
{
  int ret = -1;
  char statement[TURN_LONG_STRING_SIZE];
  MYSQL * myc = get_mydb_connection();
  if(myc) {
	  snprintf(statement,sizeof(statement),"insert into turnusers_lt (realm,name,hmackey) values('%s','%s','%s')",realm,usname,key);
	  int res = mysql_query(myc, statement);
	  if(!res) {
		  ret = 0;
	  } else {
		  snprintf(statement,sizeof(statement),"update turnusers_lt set hmackey='%s' where name='%s' and realm='%s'",key,usname,realm);
		  res = mysql_query(myc, statement);
		  if(!res) {
			  ret = 0;
		  } else {
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating user key information: %s\n",mysql_error(myc));
		  }
	  }
  }
  return ret;
}

static int mysql_set_oauth_key(oauth_key_data_raw *key)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		snprintf(statement,sizeof(statement),"insert into oauth_key (kid,ikm_key,timestamp,lifetime,as_rs_alg,realm) values('%s','%s',%llu,%lu,'%s','%s')",
					  key->kid,key->ikm_key,(unsigned long long)key->timestamp,(unsigned long)key->lifetime,
					  key->as_rs_alg,key->realm);
		int res = mysql_query(myc, statement);
		if(res) {
			snprintf(statement,sizeof(statement),"update oauth_key set ikm_key='%s',timestamp=%lu,lifetime=%lu, as_rs_alg='%s', realm='%s' where kid='%s'",key->ikm_key,(unsigned long)key->timestamp,(unsigned long)key->lifetime,
							  key->as_rs_alg,key->realm,key->kid);
			res = mysql_query(myc, statement);
			if(res) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating oauth key information: %s\n",mysql_error(myc));
			} else {
				ret = 0;
			}
		} else {
			ret = 0;
		}
	}
	return ret;
}
  
static int mysql_del_user(u08bits *usname, u08bits *realm) {
  int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		snprintf(statement,sizeof(statement),"delete from turnusers_lt where name='%s' and realm='%s'",usname,realm);
		int res = mysql_query(myc, statement);
		if(res) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error deleting user key information: %s\n",mysql_error(myc));
		} else {
		  ret = 0;
		}
	}
  return ret;
}

static int mysql_del_oauth_key(const u08bits *kid) {
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		snprintf(statement,sizeof(statement),"delete from oauth_key where kid = '%s'",(const char*)kid);
		int res = mysql_query(myc, statement);
		if(res) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error deleting oauth key information: %s\n",mysql_error(myc));
		} else {
		  ret = 0;
		}
	}
	return ret;
}
  
static int mysql_list_users(u08bits *realm, secrets_list_t *users, secrets_list_t *realms)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	MYSQL * myc = get_mydb_connection();
	if(myc) {
		if(realm[0]) {
		  snprintf(statement,sizeof(statement),"select name, realm from turnusers_lt where realm='%s' order by name",realm);
		} else {
		  snprintf(statement,sizeof(statement),"select name, realm from turnusers_lt order by realm,name");
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
						if(row[0]) {
							if(users) {
								add_to_secrets_list(users,row[0]);
								if(realms) {
									if(row[1]) {
										add_to_secrets_list(realms,row[1]);
									} else {
										add_to_secrets_list(realms,(char*)realm);
									}
								}
							} else {
								printf("%s[%s]\n", row[0], row[1]);
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
  return ret;
}
  
static int mysql_list_secrets(u08bits *realm, secrets_list_t *secrets, secrets_list_t *realms)
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

	MYSQL * myc = get_mydb_connection();
	if(myc) {
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
						const char* kval = row[0];
						if(kval) {
							const char* rval = row[1];
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
				}
				ret = 0;
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
	return ret;
}
  
static int mysql_del_secret(u08bits *secret, u08bits *realm) {
  int ret = -1;
	donot_print_connection_success=1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if (myc) {
		if(!secret || (secret[0]==0))
		  snprintf(statement,sizeof(statement),"delete from turn_secret where realm='%s'",realm);
		else
		  snprintf(statement,sizeof(statement),"delete from turn_secret where value='%s' and realm='%s'",secret,realm);
		mysql_query(myc, statement);
    ret = 0;
	}
  return ret;
}
  
static int mysql_set_secret(u08bits *secret, u08bits *realm) {
  int ret = -1;
	donot_print_connection_success = 1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if (myc) {
	  snprintf(statement,sizeof(statement),"insert into turn_secret (realm,value) values('%s','%s')",realm,secret);
	  int res = mysql_query(myc, statement);
	  if (res) {
	    TURN_LOG_FUNC(
			  TURN_LOG_LEVEL_ERROR,
			  "Error inserting/updating secret key information: %s\n",
			  mysql_error(myc));
	  } else {
	    ret = 0;
	  }
	}
  return ret;
}

static int mysql_set_permission_ip(const char *kind, u08bits *realm, const char* ip, int del)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	donot_print_connection_success = 1;

	char statement[TURN_LONG_STRING_SIZE];

	MYSQL * myc = get_mydb_connection();
	if (myc) {
		if(del) {
			snprintf(statement, sizeof(statement), "delete from %s_peer_ip where realm = '%s'  and ip_range = '%s'", kind, (char*)realm, ip);
		} else {
			snprintf(statement, sizeof(statement), "insert into %s_peer_ip (realm,ip_range) values('%s','%s')", kind, (char*)realm, ip);
		}
		int res = mysql_query(myc, statement);
		if (res) {
			TURN_LOG_FUNC(
			  TURN_LOG_LEVEL_ERROR,
			  "Error inserting permission ip information: %s\n",
			  mysql_error(myc));
		} else {
			ret = 0;
		}
	}
	return ret;
}
  
static int mysql_add_origin(u08bits *origin, u08bits *realm) {
  int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if (myc) {
		snprintf(statement,sizeof(statement),"insert into turn_origin_to_realm (origin,realm) values('%s','%s')",origin,realm);
		int res = mysql_query(myc, statement);
		if (res) {
			TURN_LOG_FUNC(
			  TURN_LOG_LEVEL_ERROR,
			  "Error inserting origin information: %s\n",
			  mysql_error(myc));
		} else {
		  ret = 0;
		}
	}
  return ret;
}
  
static int mysql_del_origin(u08bits *origin) {
  int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if (myc) {
		snprintf(statement,sizeof(statement),"delete from turn_origin_to_realm where origin='%s'",origin);
		int res = mysql_query(myc, statement);
		if (res) {
			TURN_LOG_FUNC(
			  TURN_LOG_LEVEL_ERROR,
			  "Error deleting origin information: %s\n",
			  mysql_error(myc));
		} else {
		  ret = 0;
		}
	}
  return ret;
}
  
static int mysql_list_origins(u08bits *realm, secrets_list_t *origins, secrets_list_t *realms)
{
	int ret = -1;

	u08bits realm0[STUN_MAX_REALM_SIZE+1] = "\0";
	if(!realm) realm=realm0;

	donot_print_connection_success = 1;

	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[TURN_LONG_STRING_SIZE];
		if(realm && realm[0]) {
			snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm where realm='%s' order by origin",realm);
		} else {
			snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm order by realm,origin");
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
							const char* kval = row[0];
							const char* rval = row[1];
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

			if(mres)
				mysql_free_result(mres);
		}
	}
  return ret;
}
  
static int mysql_set_realm_option_one(u08bits *realm, unsigned long value, const char* opt) {
  int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if (myc) {
		{
			snprintf(statement,sizeof(statement),"delete from turn_realm_option where realm='%s' and opt='%s'",realm,opt);
			mysql_query(myc, statement);
		}
		if(value>0) {
			snprintf(statement,sizeof(statement),"insert into turn_realm_option (realm,opt,value) values('%s','%s','%lu')",realm,opt,(unsigned long)value);
			int res = mysql_query(myc, statement);
			if (res) {
				TURN_LOG_FUNC(
							TURN_LOG_LEVEL_ERROR,
							"Error inserting realm option information: %s\n",
							mysql_error(myc));
			} else {
			  ret = 0;
			}
		}
	}
  return ret;
}
  
static int mysql_list_realm_options(u08bits *realm) {
  int ret = -1;
	donot_print_connection_success = 1;
	char statement[TURN_LONG_STRING_SIZE];
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
        ret = 0;
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
  return ret;
}
  
static void mysql_auth_ping(void * rch) {
	UNUSED_ARG(rch);
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[TURN_LONG_STRING_SIZE];
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
}
  
static int mysql_get_ip_list(const char *kind, ip_range_list_t * list) {
  int ret = -1;
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[TURN_LONG_STRING_SIZE];
		snprintf(statement,sizeof(statement),"select ip_range,realm from %s_peer_ip",kind);
		int res = mysql_query(myc, statement);

		if(res) {
			static int wrong_table_reported = 0;
			if(!wrong_table_reported) {
				wrong_table_reported = 1;
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error retrieving MySQL DB information; probably, the tables 'allowed_peer_ip' and/or 'denied_peer_ip' have to be upgraded to include the realm column.\n");
			}
			snprintf(statement, sizeof(statement), "select ip_range,'' from %s_peer_ip", kind);
			res = mysql_query(myc, statement);
		}

		if(res == 0) {
			MYSQL_RES *mres = mysql_store_result(myc);
			if(mres && mysql_field_count(myc)==2) {
				for(;;) {
					MYSQL_ROW row = mysql_fetch_row(mres);
					if(!row) {
						break;
					} else {
						if(row[0]) {
							unsigned long *lengths = mysql_fetch_lengths(mres);
							if(lengths) {
								size_t sz = lengths[0];
								char kval[TURN_LONG_STRING_SIZE];
								ns_bcopy(row[0],kval,sz);
								kval[sz]=0;
								sz = lengths[1];
								char rval[TURN_LONG_STRING_SIZE];
								ns_bcopy(row[1],rval,sz);
								rval[sz]=0;
								add_ip_list_range(kval,rval,list);
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
  return ret;
}
  
static void mysql_reread_realms(secrets_list_t * realms_list) {
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[TURN_LONG_STRING_SIZE];
		{
			snprintf(statement,sizeof(statement),"select origin,realm from turn_origin_to_realm");
			int res = mysql_query(myc, statement);
			if(res == 0) {
				MYSQL_RES *mres = mysql_store_result(myc);
				if(mres && mysql_field_count(myc)==2) {

					ur_string_map *o_to_realm_new = ur_string_map_create(turn_free_simple);

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
									char *rval=turn_strdup(row[1]);
									get_realm(rval);
									ur_string_map_value_type value = (ur_string_map_value_type)rval;
									ur_string_map_put(o_to_realm_new, (const ur_string_map_key_type) oval, value);
								}
							}
						}
					}

					update_o_to_realm(o_to_realm_new);
				}

				if(mres)
					mysql_free_result(mres);
			}
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
				}
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
}

/////////////////////////////////////////////////////

static int mysql_get_admin_user(const u08bits *usname, u08bits *realm, password_t pwd)
{
  int ret = -1;

  realm[0]=0;
  pwd[0]=0;

  MYSQL * myc = get_mydb_connection();
  if(myc) {
	char statement[TURN_LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement),"select realm,password from admin_user where name='%s'",usname);
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
			MYSQL_ROW row = mysql_fetch_row(mres);
			if(row && row[0]) {
				strncpy((char*)realm,row[0],STUN_MAX_REALM_SIZE);
				strncpy((char*)pwd,row[1],STUN_MAX_PWD_SIZE);
				ret = 0;
			}
		}

		if(mres)
			mysql_free_result(mres);
	}
  }
  return ret;
}

static int mysql_set_admin_user(const u08bits *usname, const u08bits *realm, const password_t pwd)
{
  int ret = -1;
  char statement[TURN_LONG_STRING_SIZE];
  donot_print_connection_success=1;
  MYSQL * myc = get_mydb_connection();
  if(myc) {
	  snprintf(statement,sizeof(statement),"insert into admin_user (realm,name,password) values('%s','%s','%s')",realm,usname,pwd);
	  int res = mysql_query(myc, statement);
	  if(!res) {
		  ret = 0;
	  } else {
		  snprintf(statement,sizeof(statement),"update admin_user set realm='%s',password='%s' where name='%s'",realm,pwd,usname);
		  res = mysql_query(myc, statement);
		  if(!res) {
			  ret = 0;
		  } else {
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating user key information: %s\n",mysql_error(myc));
		  }
	  }
  }
  return ret;
}

static int mysql_del_admin_user(const u08bits *usname)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	donot_print_connection_success=1;
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		snprintf(statement,sizeof(statement),"delete from admin_user where name='%s'",usname);
		int res = mysql_query(myc, statement);
		if(res) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error deleting admin user information: %s\n",mysql_error(myc));
		} else {
		  ret = 0;
		}
	}
	return ret;
}

static int mysql_list_admin_users(int no_print)
{
	int ret = -1;
	char statement[TURN_LONG_STRING_SIZE];
	donot_print_connection_success=1;
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		snprintf(statement,sizeof(statement),"select name, realm from admin_user order by realm,name");
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
				ret = 0;
				for(;;) {
					MYSQL_ROW row = mysql_fetch_row(mres);
					if(!row) {
						break;
					} else {
						++ret;
						if(row[0] && !no_print) {
							if(row[1] && row[1][0]) {
								printf("%s[%s]\n",row[0],row[1]);
							} else {
								printf("%s\n",row[0]);
							}
						}
					}
				}
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
	return ret;
}

//////////////////////////////////////////////////////

static const turn_dbdriver_t driver = {
  &mysql_get_auth_secrets,
  &mysql_get_user_key,
  &mysql_set_user_key,
  &mysql_del_user,
  &mysql_list_users,
  &mysql_list_secrets,
  &mysql_del_secret,
  &mysql_set_secret,
  &mysql_add_origin,
  &mysql_del_origin,
  &mysql_list_origins,
  &mysql_set_realm_option_one,
  &mysql_list_realm_options,
  &mysql_auth_ping,
  &mysql_get_ip_list,
  &mysql_set_permission_ip,
  &mysql_reread_realms,
  &mysql_set_oauth_key,
  &mysql_get_oauth_key,
  &mysql_del_oauth_key,
  &mysql_list_oauth_keys,
  &mysql_get_admin_user,
  &mysql_set_admin_user,
  &mysql_del_admin_user,
  &mysql_list_admin_users
};

const turn_dbdriver_t * get_mysql_dbdriver(void) {
  return &driver;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

#else

const turn_dbdriver_t * get_mysql_dbdriver(void) {
  return NULL;
}

#endif
