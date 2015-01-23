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

#ifndef __USERDB__
#define __USERDB__

#include <stdlib.h>
#include <stdio.h>

#include "hiredis_libevent2.h"

#include "ns_turn_utils.h"
#include "ns_turn_maps.h"
#include "ns_turn_server.h"

#include "apputils.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////// REALM //////////////

struct _realm_status_t;
typedef struct _realm_status_t realm_status_t;

struct _realm_params_t;
typedef struct _realm_params_t realm_params_t;

struct _realm_status_t {

	vint total_current_allocs;
	ur_string_map *alloc_counters;

};

struct _realm_params_t {

	int is_default_realm;

	realm_options_t options;

	realm_status_t status;

};

void lock_realms(void);
void unlock_realms(void);
void update_o_to_realm(ur_string_map * o_to_realm_new);

//////////// USER DB //////////////////////////////

struct auth_message {
	turnserver_id id;
	turn_credential_type ct;
	int in_oauth;
	int out_oauth;
	int max_session_time;
	u08bits username[STUN_MAX_USERNAME_SIZE + 1];
	u08bits realm[STUN_MAX_REALM_SIZE + 1];
	hmackey_t key;
	password_t pwd;
	get_username_resume_cb resume_func;
	ioa_net_data in_buffer;
	u64bits ctxkey;
	int success;
};

enum _TURN_USERDB_TYPE {
#if !defined(TURN_NO_SQLITE)
	TURN_USERDB_TYPE_UNKNOWN=-1,
	TURN_USERDB_TYPE_SQLITE=0
#else
	TURN_USERDB_TYPE_UNKNOWN=0
#endif
#if !defined(TURN_NO_PQ)
	,TURN_USERDB_TYPE_PQ
#endif
#if !defined(TURN_NO_MYSQL)
	,TURN_USERDB_TYPE_MYSQL
#endif
#if !defined(TURN_NO_MONGO)
	,TURN_USERDB_TYPE_MONGO
#endif
#if !defined(TURN_NO_HIREDIS)
	,TURN_USERDB_TYPE_REDIS
#endif
};

typedef enum _TURN_USERDB_TYPE TURN_USERDB_TYPE;

enum _TURNADMIN_COMMAND_TYPE {
	TA_COMMAND_UNKNOWN,
	TA_PRINT_KEY,
	TA_UPDATE_USER,
	TA_DELETE_USER,
	TA_LIST_USERS,
	TA_SET_SECRET,
	TA_SHOW_SECRET,
	TA_DEL_SECRET,
	TA_ADD_ORIGIN,
	TA_DEL_ORIGIN,
	TA_LIST_ORIGINS,
	TA_SET_REALM_OPTION,
	TA_LIST_REALM_OPTIONS
};

typedef enum _TURNADMIN_COMMAND_TYPE TURNADMIN_COMMAND_TYPE;

/////////// SHARED SECRETS //////////////////

struct _secrets_list {
	char **secrets;
	size_t sz;
};
typedef struct _secrets_list secrets_list_t;

/////////// USERS PARAM /////////////////////

#define TURN_LONG_STRING_SIZE (1025)

typedef struct _ram_users_db_t {
	size_t users_number;
	ur_string_map *static_accounts;
	secrets_list_t static_auth_secrets;
} ram_users_db_t;

typedef struct _persistent_users_db_t {
	char userdb[TURN_LONG_STRING_SIZE];
} persistent_users_db_t;

typedef struct _default_users_db_t
{
	TURN_USERDB_TYPE userdb_type;

	persistent_users_db_t persistent_users_db;

	ram_users_db_t ram_db;

} default_users_db_t;

/////////////////////////////////////////////

realm_params_t* get_realm(char* name);
void set_default_realm_name(char *realm);
int change_total_quota(char *realm, int value);
int change_user_quota(char *realm, int value);

/////////////////////////////////////////////

void init_secrets_list(secrets_list_t *sl);
void init_dynamic_ip_lists(void);
void update_white_and_black_lists(void);
void clean_secrets_list(secrets_list_t *sl);
size_t get_secrets_list_size(secrets_list_t *sl);
const char* get_secrets_list_elem(secrets_list_t *sl, size_t i);
void add_to_secrets_list(secrets_list_t *sl, const char* elem);

/////////// USER DB CHECK //////////////////

int get_user_key(int in_oauth, int *out_oauth, int *max_session_time, u08bits *uname, u08bits *realm, hmackey_t key, ioa_network_buffer_handle nbh);
u08bits *start_user_check(turnserver_id id, turn_credential_type ct, int in_oauth, int *out_oauth, u08bits *uname, u08bits *realm, get_username_resume_cb resume, ioa_net_data *in_buffer, u64bits ctxkey, int *postpone_reply);
int check_new_allocation_quota(u08bits *username, int oauth, u08bits *realm);
void release_allocation_quota(u08bits *username, int oauth, u08bits *realm);

/////////// Handle user DB /////////////////

#if defined(DB_TEST)
	void run_db_test(void);
#endif

void auth_ping(redis_context_handle rch);
void reread_realms(void);
int add_static_user_account(char *user);
int adminuser(u08bits *user, u08bits *realm, u08bits *pwd, u08bits *secret, u08bits *origin, TURNADMIN_COMMAND_TYPE ct, perf_options_t* po, int is_admin);

int add_ip_list_range(const char* range, const char* realm, ip_range_list_t * list);
int check_ip_list_range(const char* range);
ip_range_list_t* get_ip_list(const char *kind);
void ip_list_free(ip_range_list_t *l);

///////////// Redis //////////////////////

#if !defined(TURN_NO_HIREDIS)
redis_context_handle get_redis_async_connection(struct event_base *base, const char* connection_string, int delete_keys);
#endif

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif
/// __USERDB__///

