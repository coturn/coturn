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

#include "dbd_mysql.h"
#include "../mainrelay.h"

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
  unsigned int read_timeout;
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
  if (co) {
    if (co->host) {
      free(co->host);
    }
    if (co->dbname) {
      free(co->dbname);
    }
    if (co->user) {
      free(co->user);
    }
    if (co->password) {
      free(co->password);
    }
    if (co->key) {
      free(co->key);
    }
    if (co->ca) {
      free(co->ca);
    }
    if (co->cert) {
      free(co->cert);
    }
    if (co->capath) {
      free(co->capath);
    }
    if (co->cipher) {
      free(co->cipher);
    }
    memset(co, 0, sizeof(Myconninfo));
    free(co);
  }
}

char *decryptPassword(char *in, const unsigned char *mykey) {
  unsigned char iv[8] = {0};
  AES_KEY key;
  AES_set_encrypt_key(mykey, 128, &key);
  int newTotalSize = decodedTextSize(in);
  const int bytes_to_decode = strlen(in);
  unsigned char *encryptedText = base64decode(in, bytes_to_decode);
  struct ctr_state state;
  init_ctr(&state, iv);

  char *out = NULL;
  if (newTotalSize > 0) {
    out = (char *)malloc(newTotalSize + 1);
    if (out) {
      CRYPTO_ctr128_encrypt(encryptedText, (unsigned char *)out, newTotalSize, &key, state.ivec, state.ecount,
                            &state.num, (block128_f)AES_encrypt);
      out[newTotalSize] = '\0';
    }
  }
  free(encryptedText);
  return out;
}

static Myconninfo *MyconninfoParse(char *userdb, char **errmsg) {
  Myconninfo *co = (Myconninfo *)calloc(1, sizeof(Myconninfo));
  if (userdb) {
    char *s0 = strdup(userdb);
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
        MyconninfoFree(co);
        co = NULL;
        if (errmsg) {
          *errmsg = strdup(s);
        }
        break;
      }

      *seq = 0;
      if (!strcmp(s, "host")) {
        co->host = strdup(seq + 1);
      } else if (!strcmp(s, "ip")) {
        co->host = strdup(seq + 1);
      } else if (!strcmp(s, "addr")) {
        co->host = strdup(seq + 1);
      } else if (!strcmp(s, "ipaddr")) {
        co->host = strdup(seq + 1);
      } else if (!strcmp(s, "hostaddr")) {
        co->host = strdup(seq + 1);
      } else if (!strcmp(s, "dbname")) {
        co->dbname = strdup(seq + 1);
      } else if (!strcmp(s, "db")) {
        co->dbname = strdup(seq + 1);
      } else if (!strcmp(s, "database")) {
        co->dbname = strdup(seq + 1);
      } else if (!strcmp(s, "user")) {
        co->user = strdup(seq + 1);
      } else if (!strcmp(s, "uname")) {
        co->user = strdup(seq + 1);
      } else if (!strcmp(s, "name")) {
        co->user = strdup(seq + 1);
      } else if (!strcmp(s, "username")) {
        co->user = strdup(seq + 1);
      } else if (!strcmp(s, "password")) {
        co->password = strdup(seq + 1);
      } else if (!strcmp(s, "pwd")) {
        co->password = strdup(seq + 1);
      } else if (!strcmp(s, "passwd")) {
        co->password = strdup(seq + 1);
      } else if (!strcmp(s, "secret")) {
        co->password = strdup(seq + 1);
      } else if (!strcmp(s, "port")) {
        co->port = (unsigned int)atoi(seq + 1);
      } else if (!strcmp(s, "p")) {
        co->port = (unsigned int)atoi(seq + 1);
      } else if (!strcmp(s, "connect_timeout")) {
        co->connect_timeout = (unsigned int)atoi(seq + 1);
      } else if (!strcmp(s, "timeout")) {
        co->connect_timeout = (unsigned int)atoi(seq + 1);
      } else if (!strcmp(s, "read_timeout")) {
        co->read_timeout = (unsigned int)atoi(seq + 1);
      } else if (!strcmp(s, "key")) {
        co->key = strdup(seq + 1);
      } else if (!strcmp(s, "ssl-key")) {
        co->key = strdup(seq + 1);
      } else if (!strcmp(s, "ca")) {
        co->ca = strdup(seq + 1);
      } else if (!strcmp(s, "ssl-ca")) {
        co->ca = strdup(seq + 1);
      } else if (!strcmp(s, "capath")) {
        co->capath = strdup(seq + 1);
      } else if (!strcmp(s, "ssl-capath")) {
        co->capath = strdup(seq + 1);
      } else if (!strcmp(s, "cert")) {
        co->cert = strdup(seq + 1);
      } else if (!strcmp(s, "ssl-cert")) {
        co->cert = strdup(seq + 1);
      } else if (!strcmp(s, "cipher")) {
        co->cipher = strdup(seq + 1);
      } else if (!strcmp(s, "ssl-cipher")) {
        co->cipher = strdup(seq + 1);
      } else {
        MyconninfoFree(co);
        co = NULL;
        if (errmsg) {
          *errmsg = strdup(s);
        }
        break;
      }

      s = snext;
    }

    free(s0);
  }

  if (co) {
    if (!(co->dbname)) {
      co->dbname = strdup("0");
    }
    if (!(co->host)) {
      co->host = strdup("127.0.0.1");
    }
    if (!(co->user)) {
      co->user = strdup("");
    }
    if (!(co->password)) {
      co->password = strdup("");
    }
  }

  return co;
}

static MYSQL *get_mydb_connection(void) {

  persistent_users_db_t *pud = get_persistent_users_db();

  MYSQL *mydbconnection = (MYSQL *)pthread_getspecific(connection_key);

  if (mydbconnection) {
    if (mysql_ping(mydbconnection)) {
      mysql_close(mydbconnection);
      mydbconnection = NULL;
      (void)pthread_setspecific(connection_key, mydbconnection);
    }
  }

  if (!mydbconnection) {
    char *errmsg = NULL;
    Myconninfo *co = MyconninfoParse(pud->userdb, &errmsg);
    if (!co) {
      if (errmsg) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                      "Cannot open MySQL DB connection <%s>, connection string format error: %s\n",
                      pud->userdb_sanitized, errmsg);
        free(errmsg);
      } else {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open MySQL DB connection <%s>, connection string format error\n",
                      pud->userdb_sanitized);
      }
    } else if (errmsg) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open MySQL DB connection <%s>, connection string format error: %s\n",
                    pud->userdb_sanitized, errmsg);
      free(errmsg);
      MyconninfoFree(co);
    } else if (!(co->dbname)) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL Database name is not provided: <%s>\n", pud->userdb_sanitized);
      MyconninfoFree(co);
    } else {
      mydbconnection = mysql_init(NULL);
      if (!mydbconnection) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot initialize MySQL DB connection\n");
      } else {
        if (co->connect_timeout) {
          mysql_options(mydbconnection, MYSQL_OPT_CONNECT_TIMEOUT, &(co->connect_timeout));
        }
        if (co->read_timeout) {
          mysql_options(mydbconnection, MYSQL_OPT_READ_TIMEOUT, &(co->read_timeout));
        }
        if (co->ca || co->capath || co->cert || co->cipher || co->key) {
          mysql_ssl_set(mydbconnection, co->key, co->cert, co->ca, co->capath, co->cipher);
        }

        if (turn_params.secret_key_file[0]) {
          co->password = decryptPassword(co->password, turn_params.secret_key);
        }

        MYSQL *conn = mysql_real_connect(mydbconnection, co->host, co->user, co->password, co->dbname, co->port, NULL,
                                         CLIENT_IGNORE_SIGPIPE);
        if (!conn) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot open MySQL DB connection: <%s>, runtime error: %s\n",
                        pud->userdb_sanitized, mysql_error(mydbconnection));
          mysql_close(mydbconnection);
          mydbconnection = NULL;
        } else if (mysql_select_db(mydbconnection, co->dbname)) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot connect to MySQL DB: %s\n", co->dbname);
          mysql_close(mydbconnection);
          mydbconnection = NULL;
        } else if (!donot_print_connection_success) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "MySQL DB connection success: %s\n", pud->userdb_sanitized);
          if (turn_params.secret_key_file[0]) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Encryption with AES is activated.\n");
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Connection is secure.\n");
          } else {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Connection is not secure.\n");
          }
          donot_print_connection_success = 1;
        }
      }
      MyconninfoFree(co);
    }
    if (mydbconnection) {
      (void)pthread_setspecific(connection_key, mydbconnection);
    }
  }
  return mydbconnection;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

/* ===== prepared-statement helpers =====
 *
 * Every caller-supplied value travels as a bound parameter and never enters the
 * SQL text, so there is no SQL injection surface. Parameters and result columns
 * are bound as text (MYSQL_TYPE_STRING); integer columns are read back as their
 * decimal text and parsed, matching the previous mysql_fetch_row() behavior. */

#define MY_MAX_PARAMS 8
#define MY_MAX_COLS 6
#define MY_COL_SZ TURN_LONG_STRING_SIZE

static void my_bind_text_params(MYSQL_BIND *b, unsigned long *lengths, int nparams, const char *const params[]) {
  for (int i = 0; i < nparams && i < MY_MAX_PARAMS; i++) {
    lengths[i] = params[i] ? (unsigned long)strlen(params[i]) : 0;
    b[i].buffer_type = MYSQL_TYPE_STRING;
    b[i].buffer = (void *)(params[i] ? params[i] : "");
    b[i].buffer_length = lengths[i];
    b[i].length = &lengths[i];
  }
}

/* Run a parameterized statement that returns no result set (INSERT/UPDATE/
 * DELETE). Returns 0 on success. */
static int my_exec(MYSQL *myc, const char *sql, int nparams, const char *const params[]) {
  MYSQL_STMT *st = mysql_stmt_init(myc);
  if (!st) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL: cannot init statement: %s\n", mysql_error(myc));
    return -1;
  }
  int ret = -1;
  unsigned long lengths[MY_MAX_PARAMS] = {0};
  MYSQL_BIND b[MY_MAX_PARAMS];
  memset(b, 0, sizeof(b));
  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL prepare error: %s (%s)\n", mysql_stmt_error(st), sql);
  } else {
    my_bind_text_params(b, lengths, nparams, params);
    if (nparams > 0 && mysql_stmt_bind_param(st, b) != 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL bind error: %s\n", mysql_stmt_error(st));
    } else if (mysql_stmt_execute(st) != 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL execute error: %s (%s)\n", mysql_stmt_error(st), sql);
    } else {
      ret = 0;
    }
  }
  mysql_stmt_close(st);
  return ret;
}

/* Per-row callback for my_query_rows: receives `ncols` NUL-terminated column
 * strings plus their lengths. */
typedef void (*my_row_cb)(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx);

/* Run a parameterized SELECT, binding `nparams` text params and `ncols` text
 * result columns, invoking `cb` for each row. Returns 0 on success (including
 * the zero-row case). */
static int my_query_rows(MYSQL *myc, const char *sql, int nparams, const char *const params[], int ncols, my_row_cb cb,
                         void *ctx) {
  if (ncols > MY_MAX_COLS) {
    return -1;
  }
  MYSQL_STMT *st = mysql_stmt_init(myc);
  if (!st) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL: cannot init statement: %s\n", mysql_error(myc));
    return -1;
  }

  unsigned long plens[MY_MAX_PARAMS] = {0};
  MYSQL_BIND pb[MY_MAX_PARAMS];
  memset(pb, 0, sizeof(pb));

  if (mysql_stmt_prepare(st, sql, (unsigned long)strlen(sql)) != 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL prepare error: %s (%s)\n", mysql_stmt_error(st), sql);
    mysql_stmt_close(st);
    return -1;
  }
  my_bind_text_params(pb, plens, nparams, params);
  if (nparams > 0 && mysql_stmt_bind_param(st, pb) != 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL bind error: %s\n", mysql_stmt_error(st));
    mysql_stmt_close(st);
    return -1;
  }

  char cols[MY_MAX_COLS][MY_COL_SZ];
  unsigned long lens[MY_MAX_COLS] = {0};
  MYSQL_BIND rb[MY_MAX_COLS];
  memset(rb, 0, sizeof(rb));
  memset(cols, 0, sizeof(cols));
  for (int i = 0; i < ncols; i++) {
    rb[i].buffer_type = MYSQL_TYPE_STRING;
    rb[i].buffer = cols[i];
    rb[i].buffer_length = MY_COL_SZ - 1;
    rb[i].length = &lens[i];
  }

  int ret = -1;
  if (mysql_stmt_execute(st) != 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL execute error: %s (%s)\n", mysql_stmt_error(st), sql);
  } else if (ncols > 0 && mysql_stmt_bind_result(st, rb) != 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "MySQL bind-result error: %s\n", mysql_stmt_error(st));
  } else {
    ret = 0;
    for (;;) {
      int fr = mysql_stmt_fetch(st);
      if (fr != 0 && fr != MYSQL_DATA_TRUNCATED) {
        break; /* MYSQL_NO_DATA or error */
      }
      for (int i = 0; i < ncols; i++) {
        unsigned long n = lens[i];
        if (n >= MY_COL_SZ) {
          n = MY_COL_SZ - 1;
        }
        cols[i][n] = 0;
      }
      if (cb) {
        cb(cols, lens, ctx);
      }
    }
  }

  mysql_stmt_close(st);
  return ret;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static void cb_collect_col0(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  add_to_secrets_list((secrets_list_t *)ctx, cols[0]);
}

static int mysql_get_auth_secrets(secrets_list_t *sl, uint8_t *realm) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *const params[] = {(const char *)realm};
  return my_query_rows(myc, "select value from turn_secret where realm=?", 1, params, 1, cb_collect_col0, sl);
}

struct mysql_user_key_ctx {
  uint8_t *key;
  const uint8_t *usname;
  int ok;
};

static void cb_user_key(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  struct mysql_user_key_ctx *c = (struct mysql_user_key_ctx *)ctx;
  size_t sz = get_hmackey_size(SHATYPE_DEFAULT);
  if (lens[0] < sz * 2) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Wrong key format: string length=%d (must be %d): user %s\n", (int)lens[0],
                  (int)(sz * 2), c->usname);
  } else {
    convert_string_key_to_binary(cols[0], c->key, sz);
    c->ok = 1;
  }
}

static int mysql_get_user_key(uint8_t *usname, uint8_t *realm, hmackey_t key) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  struct mysql_user_key_ctx ctx = {key, usname, 0};
  const char *const params[] = {(const char *)usname, (const char *)realm};
  if (my_query_rows(myc, "select hmackey from turnusers_lt where name=? and realm=?", 2, params, 1, cb_user_key,
                    &ctx) != 0) {
    return -1;
  }
  return ctx.ok ? 0 : -1;
}

struct mysql_oauth_get_ctx {
  oauth_key_data_raw *key;
  const uint8_t *kid;
  int ok;
};

static void cb_oauth_get(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  struct mysql_oauth_get_ctx *c = (struct mysql_oauth_get_ctx *)ctx;
  oauth_key_data_raw *key = c->key;
  STRCPY(key->kid, c->kid);
  STRCPY(key->ikm_key, cols[0]);
  key->timestamp = (uint64_t)strtoull(cols[1], NULL, 10);
  key->lifetime = (uint32_t)strtoul(cols[2], NULL, 10);
  STRCPY(key->as_rs_alg, cols[3]);
  STRCPY(key->realm, cols[4]);
  c->ok = 1;
}

static int mysql_get_oauth_key(const uint8_t *kid, oauth_key_data_raw *key) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  struct mysql_oauth_get_ctx ctx = {key, kid, 0};
  const char *const params[] = {(const char *)kid};
  if (my_query_rows(myc, "select ikm_key,timestamp,lifetime,as_rs_alg,realm from oauth_key where kid=?", 1, params, 5,
                    cb_oauth_get, &ctx) != 0) {
    return -1;
  }
  return ctx.ok ? 0 : -1;
}

struct mysql_oauth_list_ctx {
  secrets_list_t *kids;
  secrets_list_t *teas;
  secrets_list_t *tss;
  secrets_list_t *lts;
  secrets_list_t *realms;
};

static void cb_oauth_list(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  struct mysql_oauth_list_ctx *c = (struct mysql_oauth_list_ctx *)ctx;
  /* columns: ikm_key,timestamp,lifetime,as_rs_alg,realm,kid */
  if (c->kids) {
    add_to_secrets_list(c->kids, cols[5]);
    add_to_secrets_list(c->teas, cols[3]);
    add_to_secrets_list(c->realms, cols[4]);
    add_to_secrets_list(c->tss, cols[1]);
    add_to_secrets_list(c->lts, cols[2]);
  } else {
    printf("  kid=%s, ikm_key=%s, timestamp=%s, lifetime=%s, as_rs_alg=%s, realm=%s\n", cols[5], cols[0], cols[1],
           cols[2], cols[3], cols[4]);
  }
}

static int mysql_list_oauth_keys(secrets_list_t *kids, secrets_list_t *teas, secrets_list_t *tss, secrets_list_t *lts,
                                 secrets_list_t *realms) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  struct mysql_oauth_list_ctx ctx = {kids, teas, tss, lts, realms};
  return my_query_rows(myc, "select ikm_key,timestamp,lifetime,as_rs_alg,realm,kid from oauth_key order by kid", 0,
                       NULL, 6, cb_oauth_list, &ctx);
}

static int mysql_set_user_key(uint8_t *usname, uint8_t *realm, const char *key) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *const ins[] = {(const char *)realm, (const char *)usname, key};
  if (my_exec(myc, "insert into turnusers_lt (realm,name,hmackey) values(?,?,?)", 3, ins) == 0) {
    return 0;
  }
  const char *const upd[] = {key, (const char *)usname, (const char *)realm};
  return my_exec(myc, "update turnusers_lt set hmackey=? where name=? and realm=?", 3, upd);
}

static int mysql_set_oauth_key(oauth_key_data_raw *key) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  char ts[32];
  char lt[32];
  snprintf(ts, sizeof(ts), "%llu", (unsigned long long)key->timestamp);
  snprintf(lt, sizeof(lt), "%lu", (unsigned long)key->lifetime);

  const char *const ins[] = {key->kid, key->ikm_key, ts, lt, key->as_rs_alg, key->realm};
  if (my_exec(myc, "insert into oauth_key (kid,ikm_key,timestamp,lifetime,as_rs_alg,realm) values(?,?,?,?,?,?)", 6,
              ins) == 0) {
    return 0;
  }
  const char *const upd[] = {key->ikm_key, ts, lt, key->as_rs_alg, key->realm, key->kid};
  return my_exec(myc, "update oauth_key set ikm_key=?,timestamp=?,lifetime=?, as_rs_alg=?, realm=? where kid=?", 6,
                 upd);
}

static int mysql_del_user(uint8_t *usname, uint8_t *realm) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *const params[] = {(const char *)usname, (const char *)realm};
  return my_exec(myc, "delete from turnusers_lt where name=? and realm=?", 2, params);
}

static int mysql_del_oauth_key(const uint8_t *kid) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *const params[] = {(const char *)kid};
  return my_exec(myc, "delete from oauth_key where kid = ?", 1, params);
}

/* shared context + callback for the "item + realm" listing queries (users,
 * secrets, origins): column 0 is the item, column 1 the realm. When `items` is
 * NULL the row is printed instead, using p_open/p_close around the realm so the
 * historical formats ("item[realm]" and "item ==>> realm") are preserved. */
struct mysql_pair_ctx {
  secrets_list_t *items;
  secrets_list_t *realms;
  const char *fallback_realm;
  const char *p_open;
  const char *p_close;
};

static void cb_pair_list(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  struct mysql_pair_ctx *c = (struct mysql_pair_ctx *)ctx;
  if (c->items) {
    add_to_secrets_list(c->items, cols[0]);
    if (c->realms) {
      add_to_secrets_list(c->realms, cols[1][0] ? cols[1] : c->fallback_realm);
    }
  } else {
    printf("%s%s%s%s\n", cols[0], c->p_open, cols[1], c->p_close);
  }
}

static int mysql_list_users(uint8_t *realm, secrets_list_t *users, secrets_list_t *realms) {
  uint8_t realm0[STUN_MAX_REALM_SIZE + 1] = "\0";
  if (!realm) {
    realm = realm0;
  }
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *statement;
  const char *params[1];
  int nparams = 0;
  if (realm[0]) {
    statement = "select name, realm from turnusers_lt where realm=? order by name";
    params[nparams++] = (const char *)realm;
  } else {
    statement = "select name, realm from turnusers_lt order by realm,name";
  }
  struct mysql_pair_ctx ctx = {users, realms, (const char *)realm, "[", "]"};
  return my_query_rows(myc, statement, nparams, params, 2, cb_pair_list, &ctx);
}

static int mysql_list_secrets(uint8_t *realm, secrets_list_t *secrets, secrets_list_t *realms) {
  uint8_t realm0[STUN_MAX_REALM_SIZE + 1] = "\0";
  if (!realm) {
    realm = realm0;
  }
  donot_print_connection_success = 1;
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *statement;
  const char *params[1];
  int nparams = 0;
  if (realm[0]) {
    statement = "select value,realm from turn_secret where realm=? order by value";
    params[nparams++] = (const char *)realm;
  } else {
    statement = "select value,realm from turn_secret order by realm,value";
  }
  struct mysql_pair_ctx ctx = {secrets, realms, (const char *)realm, "[", "]"};
  return my_query_rows(myc, statement, nparams, params, 2, cb_pair_list, &ctx);
}

static int mysql_del_secret(uint8_t *secret, uint8_t *realm) {
  donot_print_connection_success = 1;
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *statement;
  const char *params[2];
  int nparams = 0;
  if (!secret || (secret[0] == 0)) {
    statement = "delete from turn_secret where realm=?";
    params[nparams++] = (const char *)realm;
  } else {
    statement = "delete from turn_secret where value=? and realm=?";
    params[nparams++] = (const char *)secret;
    params[nparams++] = (const char *)realm;
  }
  my_exec(myc, statement, nparams, params);
  return 0; /* original ignored the result here */
}

static int mysql_set_secret(uint8_t *secret, uint8_t *realm) {
  donot_print_connection_success = 1;
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *const params[] = {(const char *)realm, (const char *)secret};
  return my_exec(myc, "insert into turn_secret (realm,value) values(?,?)", 2, params);
}

static int mysql_set_permission_ip(const char *kind, uint8_t *realm, const char *ip, int del) {
  uint8_t realm0[STUN_MAX_REALM_SIZE + 1] = "\0";
  if (!realm) {
    realm = realm0;
  }
  donot_print_connection_success = 1;
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  /* `kind` selects the table ("allowed"/"denied") and cannot be a bound
   * parameter; the caller has already validated it against that whitelist.
   * The realm and ip values are bound, never interpolated. */
  char statement[TURN_LONG_STRING_SIZE];
  if (del) {
    snprintf(statement, sizeof(statement), "delete from %s_peer_ip where realm = ?  and ip_range = ?", kind);
  } else {
    snprintf(statement, sizeof(statement), "insert into %s_peer_ip (realm,ip_range) values(?,?)", kind);
  }
  const char *const params[] = {(const char *)realm, ip};
  return my_exec(myc, statement, 2, params);
}

static int mysql_add_origin(uint8_t *origin, uint8_t *realm) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *const params[] = {(const char *)origin, (const char *)realm};
  return my_exec(myc, "insert into turn_origin_to_realm (origin,realm) values(?,?)", 2, params);
}

static int mysql_del_origin(uint8_t *origin) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *const params[] = {(const char *)origin};
  return my_exec(myc, "delete from turn_origin_to_realm where origin=?", 1, params);
}

static int mysql_list_origins(uint8_t *realm, secrets_list_t *origins, secrets_list_t *realms) {
  uint8_t realm0[STUN_MAX_REALM_SIZE + 1] = "\0";
  if (!realm) {
    realm = realm0;
  }
  donot_print_connection_success = 1;
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *statement;
  const char *params[1];
  int nparams = 0;
  if (realm[0]) {
    statement = "select origin,realm from turn_origin_to_realm where realm=? order by origin";
    params[nparams++] = (const char *)realm;
  } else {
    statement = "select origin,realm from turn_origin_to_realm order by realm,origin";
  }
  struct mysql_pair_ctx ctx = {origins, realms, (const char *)realm, " ==>> ", ""};
  return my_query_rows(myc, statement, nparams, params, 2, cb_pair_list, &ctx);
}

static int mysql_set_realm_option_one(uint8_t *realm, unsigned long value, const char *opt) {
  int ret = -1;
  MYSQL *myc = get_mydb_connection();
  if (myc) {
    {
      const char *const params[] = {(const char *)realm, opt};
      my_exec(myc, "delete from turn_realm_option where realm=? and opt=?", 2, params);
    }
    if (value > 0) {
      char val[32];
      snprintf(val, sizeof(val), "%lu", (unsigned long)value);
      const char *const params[] = {(const char *)realm, opt, val};
      ret = my_exec(myc, "insert into turn_realm_option (realm,opt,value) values(?,?,?)", 3, params);
    }
  }
  return ret;
}

static void cb_realm_options_print(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  (void)ctx;
  /* columns: realm,opt,value -> print "opt[realm]=value" as before */
  printf("%s[%s]=%s\n", cols[1], cols[0], cols[2]);
}

static int mysql_list_realm_options(uint8_t *realm) {
  donot_print_connection_success = 1;
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *statement;
  const char *params[1];
  int nparams = 0;
  if (realm && realm[0]) {
    statement = "select realm,opt,value from turn_realm_option where realm=? order by realm,opt";
    params[nparams++] = (const char *)realm;
  } else {
    statement = "select realm,opt,value from turn_realm_option order by realm,opt";
  }
  return my_query_rows(myc, statement, nparams, params, 3, cb_realm_options_print, NULL);
}

static void mysql_auth_ping(void *rch) {
  UNUSED_ARG(rch);
  MYSQL *myc = get_mydb_connection();
  if (myc) {
    my_query_rows(myc, "select value from turn_secret", 0, NULL, 1, NULL, NULL);
  }
}

static void cb_ip_list(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  add_ip_list_range(cols[0], cols[1], (ip_range_list_t *)ctx);
}

static int mysql_get_ip_list(const char *kind, ip_range_list_t *list) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  char statement[TURN_LONG_STRING_SIZE];
  snprintf(statement, sizeof(statement), "select ip_range,realm from %s_peer_ip", kind);
  if (my_query_rows(myc, statement, 0, NULL, 2, cb_ip_list, list) == 0) {
    return 0;
  }
  /* Older schema without the realm column: fall back to a constant. */
  static int wrong_table_reported = 0;
  if (!wrong_table_reported) {
    wrong_table_reported = 1;
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
                  "Error retrieving MySQL DB information; probably, the tables 'allowed_peer_ip' and/or "
                  "'denied_peer_ip' have to be upgraded to include the realm column.\n");
  }
  snprintf(statement, sizeof(statement), "select ip_range,'' from %s_peer_ip", kind);
  return my_query_rows(myc, statement, 0, NULL, 2, cb_ip_list, list);
}

static void cb_origin_to_realm(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  ur_string_map *o_to_realm_new = (ur_string_map *)ctx;
  char *rval = strdup(cols[1]);
  get_realm(rval);
  if (!ur_string_map_put(o_to_realm_new, (ur_string_map_key_type)cols[0], (ur_string_map_value_type)rval)) {
    free(rval);
  }
}

static void cb_realm_option_apply(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  (void)ctx;
  /* columns: realm,opt,value */
  realm_params_t *rp = get_realm(cols[0]);
  if (!strcmp(cols[1], "max-bps")) {
    rp->options.perf_options.max_bps = (band_limit_t)strtoul(cols[2], NULL, 10);
  } else if (!strcmp(cols[1], "total-quota")) {
    rp->options.perf_options.total_quota = (vint)atoi(cols[2]);
  } else if (!strcmp(cols[1], "user-quota")) {
    rp->options.perf_options.user_quota = (vint)atoi(cols[2]);
  } else {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unknown realm option: %s\n", cols[1]);
  }
}

static void mysql_reread_realms(secrets_list_t *realms_list) {
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return;
  }

  {
    ur_string_map *o_to_realm_new = ur_string_map_create(free);
    if (my_query_rows(myc, "select origin,realm from turn_origin_to_realm", 0, NULL, 2, cb_origin_to_realm,
                      o_to_realm_new) == 0) {
      update_o_to_realm(o_to_realm_new);
    } else {
      ur_string_map_free(&o_to_realm_new);
    }
  }

  {
    size_t rlsz = 0;
    lock_realms();
    rlsz = realms_list->sz;
    unlock_realms();

    for (size_t i = 0; i < rlsz; ++i) {
      char *realm = realms_list->secrets[i];
      realm_params_t *rp = get_realm(realm);

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

  my_query_rows(myc, "select realm,opt,value from turn_realm_option", 0, NULL, 3, cb_realm_option_apply, NULL);
}

/////////////////////////////////////////////////////

struct mysql_admin_get_ctx {
  uint8_t *realm;
  uint8_t *pwd;
  int ok;
};

static void cb_admin_get(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  struct mysql_admin_get_ctx *c = (struct mysql_admin_get_ctx *)ctx;
  strncpy((char *)c->realm, cols[0], STUN_MAX_REALM_SIZE);
  c->realm[STUN_MAX_REALM_SIZE] = '\0';
  strncpy((char *)c->pwd, cols[1], STUN_MAX_PWD_SIZE);
  c->pwd[STUN_MAX_PWD_SIZE] = '\0';
  c->ok = 1;
}

static int mysql_get_admin_user(const uint8_t *usname, uint8_t *realm, password_t pwd) {
  realm[0] = 0;
  pwd[0] = 0;

  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  struct mysql_admin_get_ctx ctx = {realm, pwd, 0};
  const char *const params[] = {(const char *)usname};
  if (my_query_rows(myc, "select realm,password from admin_user where name=?", 1, params, 2, cb_admin_get, &ctx) != 0) {
    return -1;
  }
  return ctx.ok ? 0 : -1;
}

static int mysql_set_admin_user(const uint8_t *usname, const uint8_t *realm, const password_t pwd) {
  donot_print_connection_success = 1;
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *const ins[] = {(const char *)realm, (const char *)usname, (const char *)pwd};
  if (my_exec(myc, "insert into admin_user (realm,name,password) values(?,?,?)", 3, ins) == 0) {
    return 0;
  }
  const char *const upd[] = {(const char *)realm, (const char *)pwd, (const char *)usname};
  return my_exec(myc, "update admin_user set realm=?,password=? where name=?", 3, upd);
}

static int mysql_del_admin_user(const uint8_t *usname) {
  donot_print_connection_success = 1;
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  const char *const params[] = {(const char *)usname};
  return my_exec(myc, "delete from admin_user where name=?", 1, params);
}

struct mysql_admin_list_ctx {
  int no_print;
  int count;
};

static void cb_admin_list(char cols[][MY_COL_SZ], const unsigned long *lens, void *ctx) {
  (void)lens;
  struct mysql_admin_list_ctx *c = (struct mysql_admin_list_ctx *)ctx;
  ++c->count;
  if (!c->no_print) {
    if (cols[1][0]) {
      printf("%s[%s]\n", cols[0], cols[1]);
    } else {
      printf("%s\n", cols[0]);
    }
  }
}

static int mysql_list_admin_users(int no_print) {
  donot_print_connection_success = 1;
  MYSQL *myc = get_mydb_connection();
  if (!myc) {
    return -1;
  }
  struct mysql_admin_list_ctx ctx = {no_print, 0};
  if (my_query_rows(myc, "select name, realm from admin_user order by realm,name", 0, NULL, 2, cb_admin_list, &ctx) !=
      0) {
    return -1;
  }
  return ctx.count;
}

static void mysql_disconnect(void) {
  MYSQL *mydbconnection = (MYSQL *)pthread_getspecific(connection_key);
  if (mydbconnection) {
    mysql_close(mydbconnection);
    mydbconnection = NULL;
  }
  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "MySQL connection was closed.\n");
}

//////////////////////////////////////////////////////

static const turn_dbdriver_t driver = {&mysql_get_auth_secrets,   &mysql_get_user_key,   &mysql_set_user_key,
                                       &mysql_del_user,           &mysql_list_users,     &mysql_list_secrets,
                                       &mysql_del_secret,         &mysql_set_secret,     &mysql_add_origin,
                                       &mysql_del_origin,         &mysql_list_origins,   &mysql_set_realm_option_one,
                                       &mysql_list_realm_options, &mysql_auth_ping,      &mysql_get_ip_list,
                                       &mysql_set_permission_ip,  &mysql_reread_realms,  &mysql_set_oauth_key,
                                       &mysql_get_oauth_key,      &mysql_del_oauth_key,  &mysql_list_oauth_keys,
                                       &mysql_get_admin_user,     &mysql_set_admin_user, &mysql_del_admin_user,
                                       &mysql_list_admin_users,   &mysql_disconnect,     NULL};

const turn_dbdriver_t *get_mysql_dbdriver(void) { return &driver; }

///////////////////////////////////////////////////////////////////////////////////////////////////////////

#else

const turn_dbdriver_t *get_mysql_dbdriver(void) { return NULL; }

#endif
