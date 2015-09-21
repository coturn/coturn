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

#ifndef __DBDRIVER__
#define __DBDRIVER__

#include "../userdb.h"

#include "ns_turn_msg_defs.h"

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////

extern pthread_key_t connection_key;
extern pthread_once_t connection_key_once;

typedef struct _turn_dbdriver_t {
  int (*get_auth_secrets)(secrets_list_t *sl, u08bits *realm);
  int (*get_user_key)(u08bits *usname, u08bits *realm, hmackey_t key);
  int (*set_user_key)(u08bits *usname, u08bits *realm, const char *key);
  int (*del_user)(u08bits *usname, u08bits *realm);
  int (*list_users)(u08bits *realm, secrets_list_t *users, secrets_list_t *realms);
  int (*list_secrets)(u08bits *realm, secrets_list_t *secrets, secrets_list_t *realms);
  int (*del_secret)(u08bits *secret, u08bits *realm);
  int (*set_secret)(u08bits *secret, u08bits *realm);
  int (*add_origin)(u08bits *origin, u08bits *realm);
  int (*del_origin)(u08bits *origin);
  int (*list_origins)(u08bits *realm, secrets_list_t *origins, secrets_list_t *realms);
  int (*set_realm_option_one)(u08bits *realm, unsigned long value, const char* opt);
  int (*list_realm_options)(u08bits *realm);
  void (*auth_ping)(void * rch);
  int (*get_ip_list)(const char *kind, ip_range_list_t * list);
  int (*set_permission_ip)(const char *kind, u08bits *realm, const char* ip, int del);
  void (*reread_realms)(secrets_list_t * realms_list);
  int (*set_oauth_key)(oauth_key_data_raw *key);
  int (*get_oauth_key)(const u08bits *kid, oauth_key_data_raw *key);
  int (*del_oauth_key)(const u08bits *kid);
  int (*list_oauth_keys)(secrets_list_t *kids,secrets_list_t *teas,secrets_list_t *tss,secrets_list_t *lts,secrets_list_t *realms);
  int (*get_admin_user)(const u08bits *usname, u08bits *realm, password_t pwd);
  int (*set_admin_user)(const u08bits *usname, const u08bits *realm, const password_t pwd);
  int (*del_admin_user)(const u08bits *usname);
  int (*list_admin_users)(int no_print);
} turn_dbdriver_t;

/////////// USER DB CHECK //////////////////

int convert_string_key_to_binary(char* keysource, hmackey_t key, size_t sz);
persistent_users_db_t * get_persistent_users_db(void);
const turn_dbdriver_t * get_dbdriver(void);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif
/// __DBDRIVER__///

