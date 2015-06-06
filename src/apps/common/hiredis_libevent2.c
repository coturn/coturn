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

#include <stdlib.h>
#include <stdarg.h>

#if !defined(TURN_NO_HIREDIS)

#include "hiredis_libevent2.h"
#include "ns_turn_utils.h"

#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>

//////////////// Libevent context ///////////////////////

struct redisLibeventEvents
{
	redisAsyncContext *context;
	int invalid;
	int allocated;
	struct event_base *base;
	struct event *rev, *wev;
	int rev_set, wev_set;
	char *ip;
	int port;
	char *pwd;
	int db;
};

///////////// Messages ////////////////////////////

struct redis_message
{
	char format[513];
	char arg[513];
};

/////////////////// forward declarations ///////////////

static void redis_reconnect(struct redisLibeventEvents *e);

//////////////////////////////////////////////////////////

static int redis_le_valid(struct redisLibeventEvents *e)
{
	return (e && !(e->invalid) && (e->context));
}

/////////////////// Callbacks ////////////////////////////

static void redisLibeventReadEvent(int fd, short event, void *arg) {
  ((void)fd); ((void)event);
  struct redisLibeventEvents *e = (struct redisLibeventEvents*)arg;
  if(redis_le_valid(e)) {
	  {
		  char buf[8];
		  int len = 0;
		  do {
			  len = recv(fd,buf,sizeof(buf),MSG_PEEK);
		  } while((len<0)&&(errno == EINTR));
		  if(len<1) {
			  e->invalid = 1;
			  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Redis connection broken: e=0x%lx\n", __FUNCTION__, ((unsigned long)e));
		  }
	  }
	  if(redis_le_valid(e)) {
		  redisAsyncHandleRead(e->context);
	  }
  } else {
	  redis_reconnect(e);
  }
}

static void redisLibeventWriteEvent(int fd, short event, void *arg) {
  ((void)fd); ((void)event);
  struct redisLibeventEvents *e = (struct redisLibeventEvents*)arg;
  if(redis_le_valid(e)) {
    redisAsyncHandleWrite(e->context);
  }
}

static void redisLibeventAddRead(void *privdata) {
  struct redisLibeventEvents *e = (struct redisLibeventEvents*)privdata;
  if(e && (e->rev) && !(e->rev_set)) {
    event_add(e->rev,NULL);
    e->rev_set = 1;
  }
}

static void redisLibeventDelRead(void *privdata) {
    struct redisLibeventEvents *e = (struct redisLibeventEvents*)privdata;
    if(e && e->rev && e->rev_set) {
      event_del(e->rev);
      e->rev_set = 0;
    }
}

static void redisLibeventAddWrite(void *privdata) {
    struct redisLibeventEvents *e = (struct redisLibeventEvents*)privdata;
    if(e && (e->wev) && !(e->wev_set)) {
      event_add(e->wev,NULL);
      e->wev_set = 1;
    }
}

static void redisLibeventDelWrite(void *privdata) {
  struct redisLibeventEvents *e = (struct redisLibeventEvents*)privdata;
  if(e && e->wev && e->wev_set) {
    event_del(e->wev);
    e->wev_set = 0;
  }
}

static void redisLibeventCleanup(void *privdata)
{

	if (privdata) {

		struct redisLibeventEvents *e = (struct redisLibeventEvents *) privdata;
		if (e->allocated) {
			if (e->rev) {
				if(e->rev_set)
					event_del(e->rev);
				event_free(e->rev);
				e->rev = NULL;
			}
			e->rev_set = 0;
			if (e->wev) {
				if(e->wev_set)
					event_del(e->wev);
				event_free(e->wev);
				e->wev = NULL;
			}
			e->wev_set = 0;
			e->context = NULL;
		}
	}
}

///////////////////////// Send-receive ///////////////////////////

void redis_async_init(void)
{
	;
}

int is_redis_asyncconn_good(redis_context_handle rch)
{
	if(rch) {
		struct redisLibeventEvents *e = (struct redisLibeventEvents*)rch;
		if(redis_le_valid(e))
			return 1;
	}
	return 0;
}

void send_message_to_redis(redis_context_handle rch, const char *command, const char *key, const char *format,...)
{
	if(!rch) {
		return;
	} else {

		struct redisLibeventEvents *e = (struct redisLibeventEvents*)rch;

		if(!redis_le_valid(e)) {
			redis_reconnect(e);
		}

		if(!redis_le_valid(e)) {
			;
		} else {

			redisAsyncContext *ac=e->context;

			struct redis_message rm;

			snprintf(rm.format,sizeof(rm.format)-3,"%s %s ", command, key);
			strcpy(rm.format+strlen(rm.format),"%s");

			va_list args;
			va_start (args, format);
			vsnprintf(rm.arg, sizeof(rm.arg)-1, format, args);
			va_end (args);

			if((redisAsyncCommand(ac, NULL, e, rm.format, rm.arg)!=REDIS_OK)) {
				e->invalid = 1;
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Redis connection broken: ac=0x%lx, e=0x%lx\n", __FUNCTION__,(unsigned long)ac,(unsigned long)e);
			}
		}
	}
}

///////////////////////// Attach /////////////////////////////////

redis_context_handle redisLibeventAttach(struct event_base *base, char *ip0, int port0, char *pwd, int db)
{

  struct redisLibeventEvents *e = NULL;
  redisAsyncContext *ac = NULL;

  char ip[256];
  if(ip0 && ip0[0])
	  STRCPY(ip,ip0);
  else
	  STRCPY(ip,"127.0.0.1");

  int port = DEFAULT_REDIS_PORT;
  if(port0>0)
	  port=port0;

  ac = redisAsyncConnect(ip, port);
  if (!ac) {
  	fprintf(stderr,"Error: %s:%s\n", ac->errstr, ac->c.errstr);
  	return NULL;
  }

  /* Create container for context and r/w events */
  e = (struct redisLibeventEvents*)turn_malloc(sizeof(struct redisLibeventEvents));
  ns_bzero(e,sizeof(struct redisLibeventEvents));

  e->allocated = 1;
  e->context = ac;
  e->base = base;
  e->ip = turn_strdup(ip);
  e->port = port;
  if(pwd)
	  e->pwd = turn_strdup(pwd);
  e->db = db;

  /* Register functions to start/stop listening for events */
  ac->ev.addRead = redisLibeventAddRead;
  ac->ev.delRead = redisLibeventDelRead;
  ac->ev.addWrite = redisLibeventAddWrite;
  ac->ev.delWrite = redisLibeventDelWrite;
  ac->ev.cleanup = redisLibeventCleanup;

  ac->ev.data = e;

  /* Initialize and install read/write events */
  e->rev = event_new(e->base,e->context->c.fd,
  		     EV_READ|EV_PERSIST,redisLibeventReadEvent,
  		     e);

  e->wev = event_new(e->base,e->context->c.fd,
		     EV_WRITE,redisLibeventWriteEvent,
  		     e);

  if (e->rev == NULL || e->wev == NULL) {
	  turn_free(e, sizeof(struct redisLibeventEvents));
	  return NULL;
  }
  
  event_add(e->wev, NULL);
  e->wev_set = 1;

  //Authentication
  if(redis_le_valid(e) && pwd) {
	  if(redisAsyncCommand(ac, NULL, e, "AUTH %s", pwd)!=REDIS_OK) {
		  e->invalid = 1;
	  }
  }

  if(redis_le_valid(e)) {
	  if(redisAsyncCommand(ac, NULL, e, "SELECT %d", db)!=REDIS_OK) {
		  e->invalid = 1;
	  }
  }

  return (redis_context_handle)e;
}

static void redis_reconnect(struct redisLibeventEvents *e)
{
  if(!e || !(e->allocated))
	  return;

  if (e->rev) {
  	if(e->rev_set)
  		event_del(e->rev);
  	event_free(e->rev);
  	e->rev = NULL;
  }
  e->rev_set = 0;

  if (e->wev) {
  	if(e->wev_set)
  		event_del(e->wev);
  	event_free(e->wev);
  	e->wev = NULL;
  }
  e->wev_set = 0;

  redisAsyncContext *ac = NULL;

  if(e->context) {
	  e->context = NULL;
  }

  ac = redisAsyncConnect(e->ip, e->port);
  if(!ac) {
	  return;
  }

  e->context = ac;

 /* Register functions to start/stop listening for events */
  ac->ev.addRead = redisLibeventAddRead;
  ac->ev.delRead = redisLibeventDelRead;
  ac->ev.addWrite = redisLibeventAddWrite;
  ac->ev.delWrite = redisLibeventDelWrite;
  ac->ev.cleanup = redisLibeventCleanup;

  ac->ev.data = e;

  /* Initialize and install read/write events */
  e->rev = event_new(e->base,e->context->c.fd,
  		     EV_READ,redisLibeventReadEvent,
  		     e);

  e->wev = event_new(e->base,e->context->c.fd,
		     EV_WRITE,redisLibeventWriteEvent,
  		     e);

  if (e->rev == NULL || e->wev == NULL) {
	  return;
  }

  event_add(e->wev, NULL);
  e->wev_set = 1;
  e->invalid = 0;

  //Authentication
  if(redis_le_valid(e) && e->pwd) {
	  if(redisAsyncCommand(ac, NULL, e, "AUTH %s", e->pwd)!=REDIS_OK) {
		  e->invalid = 1;
	  }
  }

  if(redis_le_valid(e)) {
	  if(redisAsyncCommand(ac, NULL, e, "SELECT %d", e->db)!=REDIS_OK) {
		  e->invalid = 1;
	  }
  }

  if(redis_le_valid(e)) {
	  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: Re-connected to redis, async\n", __FUNCTION__);
  }
}

/////////////////////////////////////////////////////////

#endif
/* TURN_NO_HIREDIS */

