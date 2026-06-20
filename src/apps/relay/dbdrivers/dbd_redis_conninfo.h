/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Parser for the Redis connection string used by --redis-userdb and
 * --redis-statsdb. Kept in its own translation unit (free of any relay/server
 * dependencies) so the parsing rules can be unit-tested in isolation.
 */

#ifndef __TURN_DBD_REDIS_CONNINFO_H__
#define __TURN_DBD_REDIS_CONNINFO_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Parsed Redis connection string. All char* fields are heap-allocated and owned
 * by the struct; release with RyconninfoFree(). */
typedef struct _Ryconninfo {
  char *host;
  char *dbname;
  char *user;
  char *password;
  unsigned int connect_timeout;
  unsigned int port;
  /* TLS transport options (used only when use_tls != 0). */
  int use_tls;
  int tls_verify; /* peer-certificate verification; on by default */
  char *tls_ca;   /* CA certificate/bundle file */
  char *tls_capath;
  char *tls_cert; /* client certificate file (mutual TLS) */
  char *tls_key;  /* client private key file (mutual TLS) */
  char *tls_sni;  /* SNI / expected server name (defaults to host) */
} Ryconninfo;

/* Parse a "key=value key=value ..." Redis connection string.
 *
 * On success returns a populated Ryconninfo with sensible defaults applied
 * (host=127.0.0.1, dbname=0, peer verification on). On a malformed token
 * returns NULL and, when errmsg is non-NULL, sets *errmsg to a heap-allocated
 * copy of the offending key for the caller to log and free(). */
Ryconninfo *RyconninfoParse(const char *userdb, char **errmsg);

/* Free a Ryconninfo returned by RyconninfoParse(). NULL-safe. */
void RyconninfoFree(Ryconninfo *co);

#ifdef __cplusplus
}
#endif

#endif
/*__TURN_DBD_REDIS_CONNINFO_H__*/
