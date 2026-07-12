/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
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

#include "dbd_redis_conninfo.h"

#include "ns_turn_utils.h" // for turn_malloc, turn_calloc, turn_realloc, turn_strdup

#include <stdlib.h>
#include <string.h>

void RyconninfoFree(Ryconninfo *co) {
  if (co) {
    free(co->host);
    free(co->dbname);
    free(co->user);
    free(co->password);
    free(co->tls_ca);
    free(co->tls_capath);
    free(co->tls_cert);
    free(co->tls_key);
    free(co->tls_sni);
    memset(co, 0, sizeof(Ryconninfo));
    free(co);
  }
}

/* Parse a boolean-ish connection-string value: 1/true/on/yes -> true. */
static int ry_parse_bool(const char *v) {
  return (!strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "on") || !strcmp(v, "yes"));
}

Ryconninfo *RyconninfoParse(const char *userdb, char **errmsg) {
  Ryconninfo *co = (Ryconninfo *)turn_calloc(1, sizeof(Ryconninfo));
  /* Tri-state: -1 means "not specified", so the secure default (peer
   * verification on) can be applied without clobbering an explicit
   * "tls-verify=none". */
  co->tls_verify = -1;

  if (userdb) {
    char *s0 = turn_strdup(userdb);
    char *s = s0;

    while (s && *s) {

      while (*s && (*s == ' ')) {
        ++s;
      }
      char *snext = strstr(s, " ");
      if (snext) {
        *snext = 0;
        ++snext;
      }

      char *seq = strstr(s, "=");
      if (!seq) {
        if (*s) {
          /* a non-empty token with no '=' is a syntax error */
          RyconninfoFree(co);
          co = NULL;
          if (errmsg) {
            *errmsg = turn_strdup(s);
          }
        }
        break;
      }

      *seq = 0;
      if (!strcmp(s, "host")) {
        free(co->host);
        co->host = turn_strdup(seq + 1);
      } else if (!strcmp(s, "ip")) {
        free(co->host);
        co->host = turn_strdup(seq + 1);
      } else if (!strcmp(s, "addr")) {
        free(co->host);
        co->host = turn_strdup(seq + 1);
      } else if (!strcmp(s, "ipaddr")) {
        free(co->host);
        co->host = turn_strdup(seq + 1);
      } else if (!strcmp(s, "hostaddr")) {
        free(co->host);
        co->host = turn_strdup(seq + 1);
      } else if (!strcmp(s, "dbname")) {
        free(co->dbname);
        co->dbname = turn_strdup(seq + 1);
      } else if (!strcmp(s, "db")) {
        free(co->dbname);
        co->dbname = turn_strdup(seq + 1);
      } else if (!strcmp(s, "database")) {
        free(co->dbname);
        co->dbname = turn_strdup(seq + 1);
      } else if (!strcmp(s, "user")) {
        free(co->user);
        co->user = turn_strdup(seq + 1);
      } else if (!strcmp(s, "uname")) {
        free(co->user);
        co->user = turn_strdup(seq + 1);
      } else if (!strcmp(s, "name")) {
        free(co->user);
        co->user = turn_strdup(seq + 1);
      } else if (!strcmp(s, "username")) {
        free(co->user);
        co->user = turn_strdup(seq + 1);
      } else if (!strcmp(s, "password")) {
        free(co->password);
        co->password = turn_strdup(seq + 1);
      } else if (!strcmp(s, "pwd")) {
        free(co->password);
        co->password = turn_strdup(seq + 1);
      } else if (!strcmp(s, "passwd")) {
        free(co->password);
        co->password = turn_strdup(seq + 1);
      } else if (!strcmp(s, "secret")) {
        free(co->password);
        co->password = turn_strdup(seq + 1);
      } else if (!strcmp(s, "port")) {
        co->port = (unsigned int)atoi(seq + 1);
      } else if (!strcmp(s, "p")) {
        co->port = (unsigned int)atoi(seq + 1);
      } else if (!strcmp(s, "connect_timeout")) {
        co->connect_timeout = (unsigned int)atoi(seq + 1);
      } else if (!strcmp(s, "timeout")) {
        co->connect_timeout = (unsigned int)atoi(seq + 1);
      } else if (!strcmp(s, "tls") || !strcmp(s, "ssl")) {
        co->use_tls = ry_parse_bool(seq + 1);
      } else if (!strcmp(s, "tls-ca") || !strcmp(s, "ca") || !strcmp(s, "cacert")) {
        free(co->tls_ca);
        co->tls_ca = turn_strdup(seq + 1);
      } else if (!strcmp(s, "tls-capath") || !strcmp(s, "capath")) {
        free(co->tls_capath);
        co->tls_capath = turn_strdup(seq + 1);
      } else if (!strcmp(s, "tls-cert") || !strcmp(s, "cert")) {
        free(co->tls_cert);
        co->tls_cert = turn_strdup(seq + 1);
      } else if (!strcmp(s, "tls-key") || !strcmp(s, "clientkey")) {
        free(co->tls_key);
        co->tls_key = turn_strdup(seq + 1);
      } else if (!strcmp(s, "tls-sni") || !strcmp(s, "sni") || !strcmp(s, "servername")) {
        free(co->tls_sni);
        co->tls_sni = turn_strdup(seq + 1);
      } else if (!strcmp(s, "tls-verify") || !strcmp(s, "verify")) {
        co->tls_verify = (!strcmp(seq + 1, "none") || !strcmp(seq + 1, "0") || !strcmp(seq + 1, "false")) ? 0 : 1;
      } else {
        RyconninfoFree(co);
        co = NULL;
        if (errmsg) {
          *errmsg = turn_strdup(s);
        }
        break;
      }

      s = snext;
    }

    free(s0);
  }

  if (co) {
    if (!(co->dbname)) {
      co->dbname = turn_strdup("0");
    }
    if (!(co->host)) {
      co->host = turn_strdup("127.0.0.1");
    }
    if (co->tls_verify < 0) {
      co->tls_verify = 1; /* secure default: verify the server certificate */
    }
  }

  return co;
}
