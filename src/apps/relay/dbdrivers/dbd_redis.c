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

#include "dbd_redis.h"
#include "../mainrelay.h"

#if !defined(TURN_NO_HIREDIS)
#include "../hiredis_libevent2.h"
#include "dbd_redis_conninfo.h"
#include <hiredis/hiredis.h>
#if defined(TURN_HAVE_HIREDIS_SSL)
#include <hiredis/hiredis_ssl.h>
#endif

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int donot_print_connection_success = 0;

static void turnFreeRedisReply(void *reply) {
  if (reply) {
    freeReplyObject(reply);
  }
}

#if defined(TURN_HAVE_HIREDIS_SSL)

static void redis_init_openssl_once(void) { (void)redisInitOpenSSL(); }

/* Build a reusable hiredis SSL context from the parsed connection options.
   The caller owns the returned context and must redisFreeSSLContext() it. */
static redisSSLContext *redis_create_ssl_ctx(Ryconninfo *co) {
  static pthread_once_t openssl_once = PTHREAD_ONCE_INIT;
  (void)pthread_once(&openssl_once, redis_init_openssl_once);

  redisSSLContextError ssl_error = REDIS_SSL_CTX_NONE;
  redisSSLOptions opt = {0};
  opt.cacert_filename = co->tls_ca;
  opt.capath = co->tls_capath;
  opt.cert_filename = co->tls_cert;
  opt.private_key_filename = co->tls_key;
  opt.server_name = co->tls_sni ? co->tls_sni : co->host;
  opt.verify_mode = co->tls_verify ? REDIS_SSL_VERIFY_PEER : REDIS_SSL_VERIFY_NONE;

  redisSSLContext *ssl_ctx = redisCreateSSLContextWithOptions(&opt, &ssl_error);
  if (!ssl_ctx) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis TLS: cannot create SSL context: %s\n",
                  redisSSLContextGetError(ssl_error));
  }
  return ssl_ctx;
}

/* Upgrade an already-connected synchronous redis context to TLS.
   Returns 0 on success, -1 on failure (the caller frees the context). */
static int redis_start_tls(redisContext *rc, Ryconninfo *co) {
  redisSSLContext *ssl_ctx = redis_create_ssl_ctx(co);
  if (!ssl_ctx) {
    return -1;
  }

  /* The synchronous handshake is blocking; bound it with the configured
     timeout so a plaintext endpoint mistakenly addressed with tls=true cannot
     hang the connection forever. This timeout also applies to later commands. */
  if (co->connect_timeout) {
    struct timeval tv = {0};
    tv.tv_sec = (time_t)co->connect_timeout;
    redisSetTimeout(rc, tv);
  }

  /* redisInitiateSSLWithContext() builds an SSL object that keeps its own
     reference to the context, so the context can be released right after. */
  int rc_ssl = redisInitiateSSLWithContext(rc, ssl_ctx);
  redisFreeSSLContext(ssl_ctx);

  if (rc_ssl != REDIS_OK) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis TLS: handshake failed: %s\n", rc->errstr);
    return -1;
  }
  return 0;
}

#endif /* TURN_HAVE_HIREDIS_SSL */

/* Upgrade a freshly connected synchronous redis context to TLS when the
   connection string requested it. Returns 0 if no TLS is needed or TLS was
   established; -1 if TLS was requested but could not be set up. */
static int redis_maybe_start_tls_sync(redisContext *rc, Ryconninfo *co) {
  if (!rc || !co->use_tls) {
    return 0;
  }
#if defined(TURN_HAVE_HIREDIS_SSL)
  return redis_start_tls(rc, co);
#else
  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis TLS requested but hiredis_ssl support is not compiled in\n");
  return -1;
#endif
}

redis_context_handle get_redis_async_connection(struct event_base *base, redis_stats_db_t *redis_stats_db,
                                                int delete_keys) {

  redis_context_handle ret = NULL;

  char *errmsg = NULL;
  if (base && redis_stats_db->connection_string[0]) {
    Ryconninfo *co = RyconninfoParse(redis_stats_db->connection_string, &errmsg);
    if (!co) {
      if (errmsg) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                      "Cannot open Redis DB connection <%s>, connection string format error: %s\n",
                      redis_stats_db->connection_string_sanitized, errmsg);
        free(errmsg);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error\n",
                      redis_stats_db->connection_string_sanitized);
      }
    } else if (errmsg) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error: %s\n",
                    redis_stats_db->connection_string_sanitized, errmsg);
      free(errmsg);
      RyconninfoFree(co);
    } else {

      if (delete_keys) {

        redisContext *rc = NULL;

        char ip[256] = "\0";
        int port = DEFAULT_REDIS_PORT;
        if (co->host) {
          STRCPY(ip, co->host);
        }
        if (!ip[0]) {
          strncpy(ip, "127.0.0.1", sizeof(ip));
        }

        if (co->port) {
          port = (int)(co->port);
        }

        if (co->connect_timeout) {
          struct timeval tv;
          tv.tv_usec = 0;
          tv.tv_sec = (time_t)(co->connect_timeout);
          rc = redisConnectWithTimeout(ip, port, tv);
        } else {
          rc = redisConnect(ip, port);
        }

        if (!rc) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot initialize Redis DB async connection\n");
        } else if (redis_maybe_start_tls_sync(rc, co) < 0) {
          redisFree(rc);
        } else {
          if (co->password && strlen(co->password)) {
            if (co->user && strlen(co->user)) {
              turnFreeRedisReply(redisCommand(rc, "AUTH %s %s", co->user, co->password));
            } else {
              turnFreeRedisReply(redisCommand(rc, "AUTH %s", co->password));
            }
          }
          if (co->dbname) {
            turnFreeRedisReply(redisCommand(rc, "select %s", co->dbname));
          }
          {
            redisReply *reply = (redisReply *)redisCommand(rc, "keys turn/*/allocation/*/status");
            if (reply) {
              secrets_list_t keys;
              size_t isz = 0;

              init_secrets_list(&keys);

              if (reply->type == REDIS_REPLY_ERROR) {
                TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
              } else if (reply->type != REDIS_REPLY_ARRAY) {
                if (reply->type != REDIS_REPLY_NIL) {
                  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
                }
              } else {
                size_t i;
                for (i = 0; i < reply->elements; ++i) {
                  add_to_secrets_list(&keys, reply->element[i]->str);
                }
              }

              for (isz = 0; isz < keys.sz; ++isz) {
                turnFreeRedisReply(redisCommand(rc, "del %s", keys.secrets[isz]));
              }

              clean_secrets_list(&keys);

              turnFreeRedisReply(reply);
            }
          }
          redisFree(rc);
        }
      }

      void *ssl_ctx = NULL;
      int tls_setup_failed = 0;
      if (co->use_tls) {
#if defined(TURN_HAVE_HIREDIS_SSL)
        ssl_ctx = redis_create_ssl_ctx(co);
        if (!ssl_ctx) {
          tls_setup_failed = 1;
        }
#else
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis TLS requested but hiredis_ssl support is not compiled in\n");
        tls_setup_failed = 1;
#endif
      }

      if (tls_setup_failed) {
        ret = NULL;
      } else {
        /* On success, ownership of ssl_ctx (if any) transfers to the async
           handle, which reuses it across reconnects for the handle's lifetime. */
        ret = redisLibeventAttach(base, co->host, co->port, co->user, co->password, atoi(co->dbname), ssl_ctx);
      }

      if (!ret) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot initialize Redis DB connection\n");
        /* Attach did not take ownership on failure; release the SSL context. */
#if defined(TURN_HAVE_HIREDIS_SSL)
        if (ssl_ctx) {
          redisFreeSSLContext((redisSSLContext *)ssl_ctx);
        }
#endif
      } else if (is_redis_asyncconn_good(ret) && !donot_print_connection_success) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Redis DB async connection to be used: %s\n",
                      redis_stats_db->connection_string_sanitized);
        donot_print_connection_success = 1;
      }
      RyconninfoFree(co);
    }
  }

  return ret;
}

static redisContext *get_redis_connection(void) {
  persistent_users_db_t *pud = get_persistent_users_db();

  redisContext *redisconnection = (redisContext *)pthread_getspecific(connection_key);

  if (redisconnection) {
    if (redisconnection->err) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot connect to redis, err=%d, flags=0x%lx\n", __FUNCTION__,
                    (int)redisconnection->err, (unsigned long)redisconnection->flags);
      redisFree(redisconnection);
      redisconnection = NULL;
      (void)pthread_setspecific(connection_key, redisconnection);
    }
  }

  if (!redisconnection) {

    char *errmsg = NULL;
    Ryconninfo *co = RyconninfoParse(pud->userdb, &errmsg);
    if (!co) {
      if (errmsg) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                      "Cannot open Redis DB connection <%s>, connection string format error: %s\n", pud->userdb,
                      errmsg);
        free(errmsg);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error\n",
                      pud->userdb);
      }
    } else if (errmsg) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open Redis DB connection <%s>, connection string format error: %s\n",
                    pud->userdb, errmsg);
      free(errmsg);
      RyconninfoFree(co);
    } else {
      char ip[256] = "\0";
      int port = DEFAULT_REDIS_PORT;
      if (co->host) {
        STRCPY(ip, co->host);
      }
      if (!ip[0]) {
        strncpy(ip, "127.0.0.1", sizeof(ip));
      }

      if (co->port) {
        port = (int)(co->port);
      }

      if (co->connect_timeout) {
        struct timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec = (time_t)(co->connect_timeout);
        redisconnection = redisConnectWithTimeout(ip, port, tv);
      } else {
        redisconnection = redisConnect(ip, port);
      }

      if (redisconnection && redisconnection->err) {
        if (redisconnection->errstr[0]) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis: %s\n", redisconnection->errstr);
        }
        redisFree(redisconnection);
        redisconnection = NULL;
      }

      /* Upgrade to TLS before any AUTH/SELECT/commands travel over the wire. */
      if (redisconnection && redis_maybe_start_tls_sync(redisconnection, co) < 0) {
        redisFree(redisconnection);
        redisconnection = NULL;
      }

      if (redisconnection && co->password && co->password[0]) {
        void *reply;
        if (co->user && co->user[0]) {
          reply = redisCommand(redisconnection, "AUTH %s %s", co->user, co->password);
        } else {
          reply = redisCommand(redisconnection, "AUTH %s", co->password);
        }
        if (!reply) {
          if (redisconnection->err && redisconnection->errstr[0]) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis: %s\n", redisconnection->errstr);
          }
          redisFree(redisconnection);
          redisconnection = NULL;
        } else {
          turnFreeRedisReply(reply);
        }
      }

      if (redisconnection && co->dbname) {
        void *reply = redisCommand(redisconnection, "select %s", co->dbname);
        if (!reply) {
          if (redisconnection->err && redisconnection->errstr[0]) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Redis: %s\n", redisconnection->errstr);
          }
          redisFree(redisconnection);
          redisconnection = NULL;
        } else {
          turnFreeRedisReply(reply);
        }
      }

      if (!redisconnection) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot initialize Redis DB connection\n");
      } else if (!donot_print_connection_success) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Redis DB sync connection success: %s\n", pud->userdb);
        donot_print_connection_success = 1;
      }

      RyconninfoFree(co);
    }
    if (redisconnection) {
      (void)pthread_setspecific(connection_key, redisconnection);
    }
  }

  return redisconnection;
}

static int set_redis_realm_opt(char *realm, const char *key, unsigned long *value) {
  int found = 0;

  redisContext *rc = get_redis_connection();

  if (rc) {
    redisReply *rget = NULL;

    /* Pass user/realm bytes as %s args to redisCommand, never as the format string itself.
       Otherwise a `%` in network-controlled input is interpreted as a printf format specifier,
       leading to crash or memory disclosure. */
    rget = (redisReply *)redisCommand(rc, "get turn/realm/%s/%s", realm, key);
    if (rget) {
      if (rget->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
      } else if (rget->type != REDIS_REPLY_STRING) {
        if (rget->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
        }
      } else {
        lock_realms();
        *value = (unsigned long)atol(rget->str);
        unlock_realms();
        found = 1;
      }
      turnFreeRedisReply(rget);
    }
  }

  return found;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static int redis_get_auth_secrets(secrets_list_t *sl, uint8_t *realm) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    redisReply *reply = (redisReply *)redisCommand(rc, "smembers turn/realm/%s/secret", (char *)realm);
    if (reply) {

      if (reply->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
      } else if (reply->type != REDIS_REPLY_ARRAY) {
        if (reply->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
        }
      } else {
        size_t i;
        for (i = 0; i < reply->elements; ++i) {
          add_to_secrets_list(sl, reply->element[i]->str);
        }
      }

      ret = 0;

      turnFreeRedisReply(reply);
    }
  }
  return ret;
}

static int redis_get_user_key(uint8_t *usname, uint8_t *realm, hmackey_t key) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    /* usname/realm come from STUN USERNAME/REALM attributes — passing them through the
       format string would let `%` in attacker-controlled bytes act as printf specifiers. */
    redisReply *rget = (redisReply *)redisCommand(rc, "get turn/realm/%s/user/%s/key", (char *)realm, (char *)usname);
    if (rget) {
      if (rget->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
      } else if (rget->type != REDIS_REPLY_STRING) {
        if (rget->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
        }
      } else {
        size_t sz = get_hmackey_size(SHATYPE_DEFAULT);
        if (strlen(rget->str) < sz * 2) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key format: %s, user %s\n", rget->str, usname);
        } else {
          convert_string_key_to_binary(rget->str, key, sz);
          ret = 0;
        }
      }
      turnFreeRedisReply(rget);
    }
  }
  return ret;
}

static int redis_get_oauth_key(const uint8_t *kid, oauth_key_data_raw *key) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    memset(key, 0, sizeof(oauth_key_data_raw));
    STRCPY(key->kid, kid);
    redisReply *reply = (redisReply *)redisCommand(rc, "hgetall turn/oauth/kid/%s", (const char *)kid);
    if (reply) {
      if (reply->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
      } else if (reply->type != REDIS_REPLY_ARRAY) {
        if (reply->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
        }
      } else if (reply->elements > 1) {
        size_t i;
        for (i = 0; i < (reply->elements) / 2; ++i) {
          char *kw = reply->element[2 * i]->str;
          char *val = reply->element[2 * i + 1]->str;
          if (kw) {
            if (!strcmp(kw, "as_rs_alg")) {
              STRCPY(key->as_rs_alg, val);
            } else if (!strcmp(kw, "realm")) {
              STRCPY(key->realm, val);
            } else if (!strcmp(kw, "ikm_key")) {
              STRCPY(key->ikm_key, val);
            } else if (!strcmp(kw, "timestamp")) {
              key->timestamp = (uint64_t)strtoull(val, NULL, 10);
            } else if (!strcmp(kw, "lifetime")) {
              key->lifetime = (uint32_t)strtoul(val, NULL, 10);
            }
          }
        }
        ret = 0;
      }
      turnFreeRedisReply(reply);
    }
  }
  return ret;
}

static int redis_set_user_key(uint8_t *usname, uint8_t *realm, const char *key) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    turnFreeRedisReply(redisCommand(rc, "set turn/realm/%s/user/%s/key %s", (char *)realm, (char *)usname, key));
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_set_oauth_key(oauth_key_data_raw *key) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    turnFreeRedisReply(redisCommand(
        rc, "hmset turn/oauth/kid/%s ikm_key %s as_rs_alg %s timestamp %llu lifetime %lu realm %s", key->kid,
        key->ikm_key, key->as_rs_alg, (unsigned long long)key->timestamp, (unsigned long)key->lifetime, key->realm));
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_del_user(uint8_t *usname, uint8_t *realm) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    turnFreeRedisReply(redisCommand(rc, "del turn/realm/%s/user/%s/key", (char *)realm, (char *)usname));
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_del_oauth_key(const uint8_t *kid) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    turnFreeRedisReply(redisCommand(rc, "del turn/oauth/kid/%s", (const char *)kid));
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_list_users(uint8_t *realm, secrets_list_t *users, secrets_list_t *realms) {
  int ret = -1;
  redisContext *rc = get_redis_connection();

  uint8_t realm0[STUN_MAX_REALM_SIZE + 1] = "\0";
  if (!realm) {
    realm = realm0;
  }

  if (rc) {
    secrets_list_t keys;
    size_t isz = 0;

    init_secrets_list(&keys);

    redisReply *reply = NULL;

    {
      if (realm && realm[0]) {
        reply = (redisReply *)redisCommand(rc, "keys turn/realm/%s/user/*/key", (char *)realm);
      } else {
        reply = (redisReply *)redisCommand(rc, "keys turn/realm/*/user/*/key");
      }

      if (reply) {

        if (reply->type == REDIS_REPLY_ERROR) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
        } else if (reply->type != REDIS_REPLY_ARRAY) {
          if (reply->type != REDIS_REPLY_NIL) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
          }
        } else {
          size_t i;
          for (i = 0; i < reply->elements; ++i) {
            add_to_secrets_list(&keys, reply->element[i]->str);
          }
        }
        turnFreeRedisReply(reply);
      }
    }

    size_t rhsz = strlen("turn/realm/");
    size_t uhsz = strlen("user/");

    for (isz = 0; isz < keys.sz; ++isz) {
      char *s = keys.secrets[isz];

      char *sh = strstr(s, "turn/realm/");
      if (sh != s) {
        continue;
      }
      sh += rhsz;
      char *st = strchr(sh, '/');
      if (!st) {
        continue;
      }
      *st = 0;
      char *sr = sh;
      ++st;

      sh = strstr(st, "user/");
      if (sh != st) {
        continue;
      }
      sh += uhsz;
      st = strchr(sh, '/');
      if (!st) {
        continue;
      }
      *st = 0;
      char *su = sh;

      if (users) {
        add_to_secrets_list(users, su);
        if (realms) {
          add_to_secrets_list(realms, sr);
        }
      } else {
        printf("%s[%s]\n", su, sr);
      }
    }

    clean_secrets_list(&keys);
    ret = 0;
  }
  return ret;
}

static int redis_list_oauth_keys(secrets_list_t *kids, secrets_list_t *teas, secrets_list_t *tss, secrets_list_t *lts,
                                 secrets_list_t *realms) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  secrets_list_t keys;
  size_t isz = 0;
  init_secrets_list(&keys);

  if (rc) {

    redisReply *reply = NULL;

    reply = (redisReply *)redisCommand(rc, "keys turn/oauth/kid/*");
    if (reply) {

      if (reply->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
      } else if (reply->type != REDIS_REPLY_ARRAY) {
        if (reply->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
        }
      } else {
        size_t i;
        for (i = 0; i < reply->elements; ++i) {
          add_to_secrets_list(&keys, reply->element[i]->str);
        }
      }
      turnFreeRedisReply(reply);
    }
  }

  for (isz = 0; isz < keys.sz; ++isz) {
    char *s = keys.secrets[isz];
    s += strlen("turn/oauth/kid/");
    oauth_key_data_raw key_;
    oauth_key_data_raw *key = &key_;
    if (redis_get_oauth_key((const uint8_t *)s, key) == 0) {
      if (kids) {
        add_to_secrets_list(kids, key->kid);
        add_to_secrets_list(teas, key->as_rs_alg);
        add_to_secrets_list(realms, key->realm);
        {
          char ts[256];
          snprintf(ts, sizeof(ts) - 1, "%llu", (unsigned long long)key->timestamp);
          add_to_secrets_list(tss, ts);
        }
        {
          char lt[256];
          snprintf(lt, sizeof(lt) - 1, "%lu", (unsigned long)key->lifetime);
          add_to_secrets_list(lts, lt);
        }
      } else {
        printf("  kid=%s, ikm_key=%s, timestamp=%llu, lifetime=%lu, as_rs_alg=%s, realm=%s\n", key->kid, key->ikm_key,
               (unsigned long long)key->timestamp, (unsigned long)key->lifetime, key->as_rs_alg, key->realm);
      }
    }
  }

  clean_secrets_list(&keys);
  ret = 0;

  return ret;
}

static int redis_list_secrets(uint8_t *realm, secrets_list_t *secrets, secrets_list_t *realms) {
  int ret = -1;

  uint8_t realm0[STUN_MAX_REALM_SIZE + 1] = "\0";
  if (!realm) {
    realm = realm0;
  }

  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    redisReply *reply = NULL;
    if (realm && realm[0]) {
      reply = (redisReply *)redisCommand(rc, "keys turn/realm/%s/secret", (char *)realm);
    } else {
      reply = (redisReply *)redisCommand(rc, "keys turn/realm/*/secret");
    }
    if (reply) {
      secrets_list_t keys;
      size_t isz = 0;
      init_secrets_list(&keys);

      if (reply->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
      } else if (reply->type != REDIS_REPLY_ARRAY) {
        if (reply->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
        }
      } else {
        size_t i;
        for (i = 0; i < reply->elements; ++i) {
          add_to_secrets_list(&keys, reply->element[i]->str);
        }
      }

      size_t rhsz = strlen("turn/realm/");

      for (isz = 0; isz < keys.sz; ++isz) {
        redisReply *rget = (redisReply *)redisCommand(rc, "smembers %s", keys.secrets[isz]);
        if (rget) {
          if (rget->type == REDIS_REPLY_ERROR) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
          } else if (rget->type == REDIS_REPLY_STRING) {
            printf("%s\n", rget->str);
          } else if (rget->type != REDIS_REPLY_ARRAY) {
            if (rget->type != REDIS_REPLY_NIL) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
            }
          } else {

            char *s = keys.secrets[isz];

            char *sh = strstr(s, "turn/realm/");
            if (sh != s) {
              continue;
            }
            sh += rhsz;
            char *st = strchr(sh, '/');
            if (!st) {
              continue;
            }
            *st = 0;
            const char *rval = sh;

            size_t i;
            for (i = 0; i < rget->elements; ++i) {
              const char *kval = rget->element[i]->str;
              if (secrets) {
                add_to_secrets_list(secrets, kval);
                if (realms) {
                  if (rval && *rval) {
                    add_to_secrets_list(realms, rval);
                  } else {
                    add_to_secrets_list(realms, (char *)realm);
                  }
                }
              } else {
                printf("%s[%s]\n", kval, rval);
              }
            }
          }
        }
        turnFreeRedisReply(rget);
      }

      clean_secrets_list(&keys);

      turnFreeRedisReply(reply);
      ret = 0;
    }
  }
  return ret;
}

static int redis_del_secret(uint8_t *secret, uint8_t *realm) {
  int ret = -1;
  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    turnFreeRedisReply(redisCommand(rc, "srem turn/realm/%s/secret %s", (char *)realm, (char *)secret));
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_set_secret(uint8_t *secret, uint8_t *realm) {
  int ret = -1;
  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    redis_del_secret(secret, realm);
    turnFreeRedisReply(redisCommand(rc, "sadd turn/realm/%s/secret %s", (char *)realm, (char *)secret));
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_set_permission_ip(const char *kind, uint8_t *realm, const char *ip, int del) {
  int ret = -1;

  uint8_t realm0[STUN_MAX_REALM_SIZE + 1] = "\0";
  if (!realm) {
    realm = realm0;
  }

  donot_print_connection_success = 1;

  redisContext *rc = get_redis_connection();
  if (rc) {
    if (del) {
      turnFreeRedisReply(redisCommand(rc, "srem turn/realm/%s/%s-peer-ip %s", (char *)realm, kind, ip));
    } else {
      turnFreeRedisReply(redisCommand(rc, "sadd turn/realm/%s/%s-peer-ip %s", (char *)realm, kind, ip));
    }
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_add_origin(uint8_t *origin, uint8_t *realm) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    turnFreeRedisReply(redisCommand(rc, "set turn/origin/%s %s", (char *)origin, (char *)realm));
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_del_origin(uint8_t *origin) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    turnFreeRedisReply(redisCommand(rc, "del turn/origin/%s", (char *)origin));
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_list_origins(uint8_t *realm, secrets_list_t *origins, secrets_list_t *realms) {
  int ret = -1;

  uint8_t realm0[STUN_MAX_REALM_SIZE + 1] = "\0";
  if (!realm) {
    realm = realm0;
  }

  donot_print_connection_success = 1;

  redisContext *rc = get_redis_connection();
  if (rc) {
    secrets_list_t keys;
    size_t isz = 0;

    init_secrets_list(&keys);

    redisReply *reply = NULL;

    {
      reply = (redisReply *)redisCommand(rc, "keys turn/origin/*");
      if (reply) {

        if (reply->type == REDIS_REPLY_ERROR) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
        } else if (reply->type != REDIS_REPLY_ARRAY) {
          if (reply->type != REDIS_REPLY_NIL) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
          }
        } else {
          size_t i;
          size_t offset = strlen("turn/origin/");
          for (i = 0; i < reply->elements; ++i) {
            add_to_secrets_list(&keys, reply->element[i]->str + offset);
          }
        }
        turnFreeRedisReply(reply);
      }
    }

    for (isz = 0; isz < keys.sz; ++isz) {

      char *o = keys.secrets[isz];

      reply = (redisReply *)redisCommand(rc, "get turn/origin/%s", o);
      if (reply) {

        if (reply->type == REDIS_REPLY_ERROR) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
        } else if (reply->type != REDIS_REPLY_STRING) {
          if (reply->type != REDIS_REPLY_NIL) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
          }
        } else {
          if (!(realm && realm[0] && strcmp((char *)realm, reply->str))) {
            if (origins) {
              add_to_secrets_list(origins, o);
              if (realms) {
                add_to_secrets_list(realms, reply->str);
              }
            } else {
              printf("%s ==>> %s\n", o, reply->str);
            }
          }
        }
        turnFreeRedisReply(reply);
      }
    }

    clean_secrets_list(&keys);
    ret = 0;
  }
  return ret;
}

static int redis_set_realm_option_one(uint8_t *realm, unsigned long value, const char *opt) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    if (value > 0) {
      turnFreeRedisReply(redisCommand(rc, "set turn/realm/%s/%s %lu", (char *)realm, opt, (unsigned long)value));
    } else {
      turnFreeRedisReply(redisCommand(rc, "del turn/realm/%s/%s", (char *)realm, opt));
    }
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_list_realm_options(uint8_t *realm) {
  int ret = -1;
  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    secrets_list_t keys;
    size_t isz = 0;

    init_secrets_list(&keys);

    redisReply *reply = NULL;

    {
      if (realm && realm[0]) {
        reply = (redisReply *)redisCommand(rc, "keys turn/realm/%s/*", realm);
      } else {
        reply = (redisReply *)redisCommand(rc, "keys turn/realm/*");
      }
      if (reply) {

        if (reply->type == REDIS_REPLY_ERROR) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
        } else if (reply->type != REDIS_REPLY_ARRAY) {
          if (reply->type != REDIS_REPLY_NIL) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
          }
        } else {
          size_t i;
          for (i = 0; i < reply->elements; ++i) {
            if (strstr(reply->element[i]->str, "/max-bps") || strstr(reply->element[i]->str, "/total-quota") ||
                strstr(reply->element[i]->str, "/user-quota")) {
              add_to_secrets_list(&keys, reply->element[i]->str);
            }
          }
        }
        turnFreeRedisReply(reply);
      }
    }

    size_t offset = strlen("turn/realm/");

    for (isz = 0; isz < keys.sz; ++isz) {
      char *o = keys.secrets[isz];

      reply = (redisReply *)redisCommand(rc, "get %s", o);
      if (reply) {

        if (reply->type == REDIS_REPLY_ERROR) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
        } else if (reply->type != REDIS_REPLY_STRING) {
          if (reply->type != REDIS_REPLY_NIL) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
          }
        } else {
          printf("%s = %s\n", o + offset, reply->str);
        }
        turnFreeRedisReply(reply);
      }
    }

    clean_secrets_list(&keys);
    ret = 0;
  }
  return ret;
}

static void redis_auth_ping(void *rch) {
  UNUSED_ARG(rch);
  redisContext *rc = get_redis_connection();
  if (rc) {
    turnFreeRedisReply(redisCommand(rc, "keys turn/origin/*"));
  }
}

static int redis_get_ip_list(const char *kind, ip_range_list_t *list) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    const char *header = "turn/realm/";
    size_t header_len = strlen(header);
    redisReply *reply = (redisReply *)redisCommand(rc, "keys %s*/%s-peer-ip", header, kind);
    if (reply) {
      secrets_list_t keys;
      size_t isz = 0;

      init_secrets_list(&keys);

      if (reply->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
      } else if (reply->type != REDIS_REPLY_ARRAY) {
        if (reply->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
        }
      } else {
        size_t i;
        for (i = 0; i < reply->elements; ++i) {
          add_to_secrets_list(&keys, reply->element[i]->str);
        }
      }

      for (isz = 0; isz < keys.sz; ++isz) {

        char *realm = NULL;

        redisReply *rget = (redisReply *)redisCommand(rc, "smembers %s", keys.secrets[isz]);

        char *ptr = ((char *)keys.secrets[isz]) + header_len;
        char *sep = strstr(ptr, "/");
        if (sep) {
          *sep = 0;
          realm = ptr;
        }

        if (rget) {
          if (rget->type == REDIS_REPLY_ERROR) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
          } else if (rget->type == REDIS_REPLY_STRING) {
            add_ip_list_range(rget->str, realm, list);
          } else if (rget->type != REDIS_REPLY_ARRAY) {
            if (rget->type != REDIS_REPLY_NIL) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
            }
          } else {
            size_t i;
            for (i = 0; i < rget->elements; ++i) {
              add_ip_list_range(rget->element[i]->str, realm, list);
            }
          }
          turnFreeRedisReply(rget);
        }

        if (sep) {
          *sep = '/';
        }
      }

      clean_secrets_list(&keys);

      turnFreeRedisReply(reply);
      ret = 0;
    }
  }
  return ret;
}

static void redis_reread_realms(secrets_list_t *realms_list) {
  redisContext *rc = get_redis_connection();
  if (rc) {

    redisReply *reply = (redisReply *)redisCommand(rc, "keys turn/origin/*");
    if (reply) {

      ur_string_map *o_to_realm_new = ur_string_map_create(free);

      secrets_list_t keys;

      init_secrets_list(&keys);

      size_t isz = 0;

      if (reply->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
      } else if (reply->type != REDIS_REPLY_ARRAY) {
        if (reply->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
        }
      } else {
        size_t i;
        for (i = 0; i < reply->elements; ++i) {
          add_to_secrets_list(&keys, reply->element[i]->str);
        }
      }

      size_t offset = strlen("turn/origin/");

      for (isz = 0; isz < keys.sz; ++isz) {
        char *origin = keys.secrets[isz] + offset;
        redisReply *rget = (redisReply *)redisCommand(rc, "get %s", keys.secrets[isz]);
        if (rget) {
          if (rget->type == REDIS_REPLY_ERROR) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", rget->str);
          } else if (rget->type != REDIS_REPLY_STRING) {
            if (rget->type != REDIS_REPLY_NIL) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", rget->type);
            }
          } else {
            get_realm(rget->str);
            ur_string_map_value_type value = strdup(rget->str);
            ur_string_map_put(o_to_realm_new, (ur_string_map_key_type)origin, value);
          }
          turnFreeRedisReply(rget);
        }
      }

      clean_secrets_list(&keys);

      update_o_to_realm(o_to_realm_new);

      turnFreeRedisReply(reply);
    }

    {
      size_t i = 0;
      size_t rlsz = 0;

      lock_realms();
      rlsz = realms_list->sz;
      unlock_realms();

      for (i = 0; i < rlsz; ++i) {
        char *realm = realms_list->secrets[i];
        realm_params_t *rp = get_realm(realm);
        {
          unsigned long value = 0;
          if (!set_redis_realm_opt(realm, "max-bps", &value)) {
            lock_realms();
            rp->options.perf_options.max_bps = turn_params.max_bps;
            unlock_realms();
          } else {
            rp->options.perf_options.max_bps = (band_limit_t)value;
          }
        }
        {
          unsigned long value = 0;
          if (!set_redis_realm_opt(realm, "total-quota", &value)) {
            lock_realms();
            rp->options.perf_options.total_quota = turn_params.total_quota;
            unlock_realms();
          } else {
            rp->options.perf_options.total_quota = (vint)value;
          }
        }
        {
          unsigned long value = 0;
          if (!set_redis_realm_opt(realm, "user-quota", &value)) {
            lock_realms();
            rp->options.perf_options.user_quota = turn_params.user_quota;
            unlock_realms();
          } else {
            rp->options.perf_options.user_quota = (vint)value;
          }
        }
      }
    }
  }
}

/////////////////////////////////////////////////////

static int redis_get_admin_user(const uint8_t *usname, uint8_t *realm, password_t pwd) {
  int ret = -1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    realm[0] = 0;
    pwd[0] = 0;
    redisReply *reply = (redisReply *)redisCommand(rc, "hgetall turn/admin_user/%s", (const char *)usname);
    if (reply) {
      if (reply->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
      } else if (reply->type != REDIS_REPLY_ARRAY) {
        if (reply->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
        }
      } else if (reply->elements > 1) {
        size_t i;
        for (i = 0; i < (reply->elements) / 2; ++i) {
          char *kw = reply->element[2 * i]->str;
          char *val = reply->element[2 * i + 1]->str;
          if (kw) {
            if (!strcmp(kw, "realm")) {
              strncpy((char *)realm, val, STUN_MAX_REALM_SIZE);
              realm[STUN_MAX_REALM_SIZE] = '\0';
            } else if (!strcmp(kw, "password")) {
              strncpy((char *)pwd, val, STUN_MAX_PWD_SIZE);
              pwd[STUN_MAX_PWD_SIZE] = '\0';
              ret = 0;
            }
          }
        }
      }
      turnFreeRedisReply(reply);
    }
  }
  return ret;
}

static int redis_set_admin_user(const uint8_t *usname, const uint8_t *realm, const password_t pwd) {
  int ret = -1;
  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    if (realm[0]) {
      turnFreeRedisReply(redisCommand(rc, "hmset turn/admin_user/%s realm %s password %s", (const char *)usname,
                                      (const char *)realm, (const char *)pwd));
    } else {
      turnFreeRedisReply(
          redisCommand(rc, "hmset turn/admin_user/%s password %s", (const char *)usname, (const char *)pwd));
    }
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_del_admin_user(const uint8_t *usname) {
  int ret = -1;
  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  if (rc) {
    turnFreeRedisReply(redisCommand(rc, "del turn/admin_user/%s", (const char *)usname));
    turnFreeRedisReply(redisCommand(rc, "save"));
    ret = 0;
  }
  return ret;
}

static int redis_list_admin_users(int no_print) {
  int ret = -1;
  donot_print_connection_success = 1;
  redisContext *rc = get_redis_connection();
  secrets_list_t keys;
  size_t isz = 0;
  init_secrets_list(&keys);

  if (rc) {

    redisReply *reply = NULL;

    reply = (redisReply *)redisCommand(rc, "keys turn/admin_user/*");
    if (reply) {

      if (reply->type == REDIS_REPLY_ERROR) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Error: %s\n", reply->str);
      } else if (reply->type != REDIS_REPLY_ARRAY) {
        if (reply->type != REDIS_REPLY_NIL) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unexpected type: %d\n", reply->type);
        }
      } else {
        size_t i;
        for (i = 0; i < reply->elements; ++i) {
          add_to_secrets_list(&keys, reply->element[i]->str);
        }
      }
      turnFreeRedisReply(reply);
    }
  }

  ret = 0;
  for (isz = 0; isz < keys.sz; ++isz) {
    char *s = keys.secrets[isz];
    s += strlen("turn/admin_user/");
    uint8_t realm[STUN_MAX_REALM_SIZE];
    password_t pwd;
    if (redis_get_admin_user((const uint8_t *)s, realm, pwd) == 0) {
      ++ret;
      if (!no_print) {
        if (realm[0]) {
          printf("%s[%s]\n", s, realm);
        } else {
          printf("%s\n", s);
        }
      }
    }
  }

  clean_secrets_list(&keys);

  return ret;
}

static void redis_disconnect(void) {
  redisContext *redisconnection = (redisContext *)pthread_getspecific(connection_key);
  if (redisconnection) {
    redisFree(redisconnection);
    redisconnection = NULL;
  }
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Redis connection was closed.\n");
}

//////////////////////////////////////////////////////

static const turn_dbdriver_t driver = {&redis_get_auth_secrets,   &redis_get_user_key,   &redis_set_user_key,
                                       &redis_del_user,           &redis_list_users,     &redis_list_secrets,
                                       &redis_del_secret,         &redis_set_secret,     &redis_add_origin,
                                       &redis_del_origin,         &redis_list_origins,   &redis_set_realm_option_one,
                                       &redis_list_realm_options, &redis_auth_ping,      &redis_get_ip_list,
                                       &redis_set_permission_ip,  &redis_reread_realms,  &redis_set_oauth_key,
                                       &redis_get_oauth_key,      &redis_del_oauth_key,  &redis_list_oauth_keys,
                                       &redis_get_admin_user,     &redis_set_admin_user, &redis_del_admin_user,
                                       &redis_list_admin_users,   &redis_disconnect,     NULL};

const turn_dbdriver_t *get_redis_dbdriver(void) { return &driver; }

///////////////////////////////////////////////////////////////////////////////////////////////////////////

#else

const turn_dbdriver_t *get_redis_dbdriver(void) { return NULL; }

redis_context_handle get_redis_async_connection(struct event_base *base, redis_stats_db_t *connection_string,
                                                int delete_keys) {
  UNUSED_ARG(base);
  UNUSED_ARG(connection_string);
  UNUSED_ARG(delete_keys);
  return NULL;
}
#endif /* !defined(TURN_NO_HIREDIS) */
