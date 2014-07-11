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

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////

typedef struct _turn_dbdriver_t {
  int (*get_auth_secrets)(secrets_list_t *sl, u08bits *realm);
  int (*get_user_key)(u08bits *usname, u08bits *realm, hmackey_t key);
  int (*get_user_pwd)(u08bits *usname, st_password_t pwd);
  int (*set_user_key)(u08bits *usname, u08bits *realm, const char *key);
  int (*set_user_pwd)(u08bits *usname, st_password_t pwd);
  int (*del_user)(u08bits *usname, int is_st, u08bits *realm);
  int (*list_users)(int is_st, u08bits *realm);
  int (*show_secret)(u08bits *realm);
  int (*del_secret)(u08bits *secret, u08bits *realm);
  int (*set_secret)(u08bits *secret, u08bits *realm);
  int (*add_origin)(u08bits *origin, u08bits *realm);
  int (*del_origin)(u08bits *origin);
  int (*list_origins)(u08bits *realm);
  int (*set_realm_option_one)(u08bits *realm, unsigned long value, const char* opt);
  int (*list_realm_options)(u08bits *realm);
  void (*auth_ping)(void * rch);
  int (*get_ip_list)(const char *kind, ip_range_list_t * list);
  void (*reread_realms)(secrets_list_t * realms_list);
} turn_dbdriver_t;

/////////// USER DB CHECK //////////////////

int convert_string_key_to_binary(char* keysource, hmackey_t key, size_t sz);
persistent_users_db_t * get_persistent_users_db(void);
turn_dbdriver_t * get_dbdriver(void);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif
/// __DBDRIVER__///

