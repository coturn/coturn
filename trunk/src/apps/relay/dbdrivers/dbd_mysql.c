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

static Myconninfo *MyconninfoParse(char *userdb, char **errmsg) {
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

static MYSQL *get_mydb_connection(void) {
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
  return ret;
}
  
static int mysql_get_user_pwd(u08bits *usname, st_password_t pwd) {
  int ret = 1;
	char statement[TURN_LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement),"select password from turnusers_st where name='%s'",usname);

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
  return ret;
}
  
static int mysql_set_user_key(u08bits *usname, u08bits *realm, const char *key) {
  int ret = 1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if(myc) {
	  snprintf(statement,sizeof(statement),"insert into turnusers_lt (realm,name,hmackey) values('%s','%s','%s')",realm,usname,key);
		int res = mysql_query(myc, statement);
		if(res) {
		  snprintf(statement,sizeof(statement),"update turnusers_lt set hmackey='%s' where name='%s' and realm='%s'",key,usname,realm);
			res = mysql_query(myc, statement);
			if(res) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating user key information: %s\n",mysql_error(myc));
			}
		}
	}
  return ret;
}
  
static int mysql_set_user_pwd(u08bits *usname, st_password_t pwd) {
  int ret = 1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if(myc) {
	  snprintf(statement,sizeof(statement),"insert into turnusers_st values('%s','%s')",usname,pwd);
		int res = mysql_query(myc, statement);
		if(res) {
		  snprintf(statement,sizeof(statement),"update turnusers_st set password='%s' where name='%s'",pwd,usname);
			res = mysql_query(myc, statement);
			if(res) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error inserting/updating user key information: %s\n",mysql_error(myc));
			} else {
			  ret = 0;
			}
		}
	}
  return ret;
}
  
static int mysql_del_user(u08bits *usname, int is_st, u08bits *realm) {
  int ret = 1;
	char statement[TURN_LONG_STRING_SIZE];
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		if(is_st) {
		  snprintf(statement,sizeof(statement),"delete from turnusers_st where name='%s'",usname);
		} else {
		  snprintf(statement,sizeof(statement),"delete from turnusers_lt where name='%s' and realm='%s'",usname,realm);
		}
		int res = mysql_query(myc, statement);
		if(res) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error deleting user key information: %s\n",mysql_error(myc));
		} else {
		  ret = 0;
		}
	}
  return ret;
}
  
static int mysql_list_users(int is_st, u08bits *realm) {
  int ret = 1;
	char statement[TURN_LONG_STRING_SIZE];
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
        ret = 0;
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
  return ret;
}
  
static int mysql_show_secret(u08bits *realm) {
  int ret = 1;
	char statement[TURN_LONG_STRING_SIZE];
	snprintf(statement,sizeof(statement)-1,"select value from turn_secret where realm='%s'",realm);

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
        ret = 0;
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
  return ret;
}
  
static int mysql_del_secret(u08bits *secret, u08bits *realm) {
  int ret = 1;
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
  int ret = 1;
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
  
static int mysql_add_origin(u08bits *origin, u08bits *realm) {
  int ret = 1;
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
  int ret = 1;
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
  
static int mysql_list_origins(u08bits *realm) {
  int ret = 1;
	donot_print_connection_success = 1;
	char statement[TURN_LONG_STRING_SIZE];
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
        ret = 0;
			}

			if(mres)
				mysql_free_result(mres);
		}
	}
  return ret;
}
  
static int mysql_set_realm_option_one(u08bits *realm, unsigned long value, const char* opt) {
  int ret = 1;
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
  int ret = 1;
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
	donot_print_connection_success = 1;
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
  int ret = 1;
	MYSQL * myc = get_mydb_connection();
	if(myc) {
		char statement[TURN_LONG_STRING_SIZE];
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
								char kval[TURN_LONG_STRING_SIZE];
								ns_bcopy(row[0],kval,sz);
								kval[sz]=0;
								add_ip_list_range(kval,list);
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
									rp->options.perf_options.max_bps = (band_limit_t)atol(vval);
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static turn_dbdriver_t driver = {
  &mysql_get_auth_secrets,
  &mysql_get_user_key,
  &mysql_get_user_pwd,
  &mysql_set_user_key,
  &mysql_set_user_pwd,
  &mysql_del_user,
  &mysql_list_users,
  &mysql_show_secret,
  &mysql_del_secret,
  &mysql_set_secret,
  &mysql_add_origin,
  &mysql_del_origin,
  &mysql_list_origins,
  &mysql_set_realm_option_one,
  &mysql_list_realm_options,
  &mysql_auth_ping,
  &mysql_get_ip_list,
  &mysql_reread_realms
};

turn_dbdriver_t * get_mysql_dbdriver(void) {
  return &driver;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

#else

turn_dbdriver_t * get_mysql_dbdriver(void) {
  return NULL;
}

#endif
