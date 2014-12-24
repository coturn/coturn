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

#include "apputils.h"

#include "dbdriver.h"
#include "dbd_sqlite.h"
#include "dbd_pgsql.h"
#include "dbd_mysql.h"
#include "dbd_mongo.h"
#include "dbd_redis.h"

static void make_connection_key(void)
{
    (void) pthread_key_create(&connection_key, NULL);
}


pthread_key_t connection_key;
pthread_once_t connection_key_once = PTHREAD_ONCE_INIT;

int convert_string_key_to_binary(char* keysource, hmackey_t key, size_t sz) {
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

persistent_users_db_t * get_persistent_users_db(void) {
	return &(turn_params.default_users_db.persistent_users_db);
}

const turn_dbdriver_t * get_dbdriver()
{
	if (turn_params.default_users_db.userdb_type == TURN_USERDB_TYPE_UNKNOWN)
		return NULL;

	(void) pthread_once(&connection_key_once, make_connection_key);

	static const turn_dbdriver_t * _driver = NULL;

	if (_driver == NULL) {

		switch (turn_params.default_users_db.userdb_type){
#if !defined(TURN_NO_SQLITE)
		case TURN_USERDB_TYPE_SQLITE:
			_driver = get_sqlite_dbdriver();
			break;
#endif
#if !defined(TURN_NO_PQ)
		case TURN_USERDB_TYPE_PQ:
			_driver = get_pgsql_dbdriver();
			break;
#endif
#if !defined(TURN_NO_MYSQL)
		case TURN_USERDB_TYPE_MYSQL:
			_driver = get_mysql_dbdriver();
			break;
#endif
#if !defined(TURN_NO_MONGO)
		case TURN_USERDB_TYPE_MONGO:
			_driver = get_mongo_dbdriver();
			break;
#endif
#if !defined(TURN_NO_HIREDIS)
		case TURN_USERDB_TYPE_REDIS:
			_driver = get_redis_dbdriver();
			break;
#endif
		default:
			break;
		}
	}
	return _driver;
}

