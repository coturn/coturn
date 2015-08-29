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

#include "ns_turn_utils.h"
#include "ns_turn_ioalib.h"
#include "ns_turn_msg_defs.h"

#include <event2/http.h>

#include <time.h>

#include <pthread.h>

#include <syslog.h>
#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>

#include <signal.h>

////////// LOG TIME OPTIMIZATION ///////////

static volatile turn_time_t log_start_time = 0;
volatile int _log_time_value_set = 0;
volatile turn_time_t _log_time_value = 0;

static inline turn_time_t log_time(void)
{
  if(!log_start_time)
    log_start_time = turn_time();

  if(_log_time_value_set)
    return (_log_time_value - log_start_time);

  return (turn_time() - log_start_time);
}

////////// MUTEXES /////////////

#define MAGIC_CODE (0xEFCD1983)

int turn_mutex_lock(const turn_mutex *mutex) {
  if(mutex && mutex->mutex && (mutex->data == MAGIC_CODE)) {
    int ret = 0;
    ret = pthread_mutex_lock((pthread_mutex_t*)mutex->mutex);
    if(ret<0) {
      perror("Mutex lock");
    }
    return ret;
  } else {
    printf("Uninitialized mutex\n");
    return -1;
  }
}

int turn_mutex_unlock(const turn_mutex *mutex) {
  if(mutex && mutex->mutex && (mutex->data == MAGIC_CODE)) {
    int ret = 0;
    ret = pthread_mutex_unlock((pthread_mutex_t*)mutex->mutex);
    if(ret<0) {
      perror("Mutex unlock");
    }
    return ret;
  } else {
    printf("Uninitialized mutex\n");
    return -1;
  }
}

int turn_mutex_init(turn_mutex* mutex) {
  if(mutex) {
    mutex->data=MAGIC_CODE;
    mutex->mutex=turn_malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init((pthread_mutex_t*)mutex->mutex,NULL);
    return 0;
  } else {
    return -1;
  }
}

int turn_mutex_init_recursive(turn_mutex* mutex) {
	int ret = -1;
	if (mutex) {
		pthread_mutexattr_t attr;
		if (pthread_mutexattr_init(&attr) < 0) {
			perror("Cannot init mutex attr");
		} else {
			if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) < 0) {
				perror("Cannot set type on mutex attr");
			} else {
				mutex->mutex = turn_malloc(sizeof(pthread_mutex_t));
				mutex->data = MAGIC_CODE;
				if ((ret = pthread_mutex_init((pthread_mutex_t*) mutex->mutex,
						&attr)) < 0) {
					perror("Cannot init mutex");
					mutex->data = 0;
					turn_free(mutex->mutex,sizeof(pthread_mutex_t));
					mutex->mutex = NULL;
				}
			}
			pthread_mutexattr_destroy(&attr);
		}
	}
  return ret;
}

int turn_mutex_destroy(turn_mutex* mutex) {
  if(mutex && mutex->mutex && mutex->data == MAGIC_CODE) {
    int ret = 0;
    ret = pthread_mutex_destroy((pthread_mutex_t*)(mutex->mutex));
    turn_free(mutex->mutex, sizeof(pthread_mutex_t));
    mutex->mutex=NULL;
    mutex->data=0;
    return ret;
  } else {
    return 0;
  }
}

///////////////////////// LOG ///////////////////////////////////

#if defined(TURN_LOG_FUNC_IMPL)
extern void TURN_LOG_FUNC_IMPL(TURN_LOG_LEVEL level, const s08bits* format, va_list args);
#endif

static int no_stdout_log = 0;

void set_no_stdout_log(int val)
{
	no_stdout_log = val;
}

void turn_log_func_default(TURN_LOG_LEVEL level, const s08bits* format, ...)
{
#if !defined(TURN_LOG_FUNC_IMPL)
	{
		va_list args;
		va_start(args,format);
		vrtpprintf(level, format, args);
		va_end(args);
	}
#endif

	{
		va_list args;
		va_start(args,format);
#if defined(TURN_LOG_FUNC_IMPL)
		TURN_LOG_FUNC_IMPL(level,format,args);
#else
#define MAX_RTPPRINTF_BUFFER_SIZE (1024)
		char s[MAX_RTPPRINTF_BUFFER_SIZE+1];
#undef MAX_RTPPRINTF_BUFFER_SIZE
		if (level == TURN_LOG_LEVEL_ERROR) {
			snprintf(s,sizeof(s)-100,"%lu: ERROR: ",(unsigned long)log_time());
			size_t slen = strlen(s);
			vsnprintf(s+slen,sizeof(s)-slen-1,format, args);
			fwrite(s,strlen(s),1,stdout);
		} else if(!no_stdout_log) {
			snprintf(s,sizeof(s)-100,"%lu: ",(unsigned long)log_time());
			size_t slen = strlen(s);
			vsnprintf(s+slen,sizeof(s)-slen-1,format, args);
			fwrite(s,strlen(s),1,stdout);
		}
#endif
		va_end(args);
	}
}

void addr_debug_print(int verbose, const ioa_addr *addr, const s08bits* s)
{
	if (verbose) {
		if (!addr) {
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: EMPTY\n", s);
		} else {
			s08bits addrbuf[INET6_ADDRSTRLEN];
			if (!s)
				s = "";
			if (addr->ss.sa_family == AF_INET) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "IPv4. %s: %s:%d\n", s, inet_ntop(AF_INET,
								&addr->s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
								nswap16(addr->s4.sin_port));
			} else if (addr->ss.sa_family == AF_INET6) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "IPv6. %s: %s:%d\n", s, inet_ntop(AF_INET6,
								&addr->s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
								nswap16(addr->s6.sin6_port));
			} else {
				if (addr_any_no_port(addr)) {
					TURN_LOG_FUNC(
									TURN_LOG_LEVEL_INFO,
									"IP. %s: 0.0.0.0:%d\n",
									s,
									nswap16(addr->s4.sin_port));
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: wrong IP address family: %d\n", s,
									(int) (addr->ss.sa_family));
				}
			}
		}
	}
}

/*************************************/

#define FILE_STR_LEN (1025)

static FILE* _rtpfile = NULL;
static int to_syslog = 0;
static int simple_log = 0;
static char log_fn[FILE_STR_LEN]="\0";
static char log_fn_base[FILE_STR_LEN]="\0";
static volatile int to_reset_log_file = 0;

static turn_mutex log_mutex;
static int log_mutex_inited = 0;

static void log_lock(void) {
	if(!log_mutex_inited) {
		log_mutex_inited=1;
		turn_mutex_init_recursive(&log_mutex);
	}
	turn_mutex_lock(&log_mutex);
}

static void log_unlock(void) {
	turn_mutex_unlock(&log_mutex);
}

static void get_date(char *s, size_t sz) {
	time_t curtm;
    struct tm* tm_info;

    curtm = time(NULL);
    tm_info = localtime(&curtm);

    strftime(s, sz, "%F", tm_info);
}

void set_logfile(const char *fn)
{
	if(fn) {
		log_lock();
		if(strcmp(fn,log_fn_base)) {
			reset_rtpprintf();
			STRCPY(log_fn_base,fn);
		}
		log_unlock();
	}
}

void reset_rtpprintf(void)
{
	log_lock();
	if(_rtpfile) {
		if(_rtpfile != stdout)
			fclose(_rtpfile);
		_rtpfile = NULL;
	}
	log_unlock();
}

#define set_log_file_name(base, f) set_log_file_name_func(base, f, sizeof(f))

static void set_log_file_name_func(char *base, char *f, size_t fsz)
{
	if(simple_log) {
	  strncpy(f,base,fsz);
	  return;
	}

	char logdate[125];
	char *tail=turn_strdup(".log");

	get_date(logdate,sizeof(logdate));

	char *base1=turn_strdup(base);

	int len=(int)strlen(base1);

	--len;

	while(len>=0) {
		if((base1[len]==' ')||(base1[len]=='\t')) {
			base1[len]='_';
		}
		--len;
	}

	len=(int)strlen(base1);

	while(len>=0) {
		if(base1[len]=='/')
			break;
		else if(base1[len]=='.') {
			turn_free(tail,strlen(tail)+1);
			tail=turn_strdup(base1+len);
			base1[len]=0;
			if(strlen(tail)<2) {
				turn_free(tail,strlen(tail)+1);
				tail = turn_strdup(".log");
			}
			break;
		}
		--len;
	}

	len=(int)strlen(base1);
	if(len>0 && (base1[len-1]!='/') && (base1[len-1]!='-') && (base1[len-1]!='_')) {
	  snprintf(f, FILE_STR_LEN, "%s_%s%s", base1,logdate,tail);
	} else {
	  snprintf(f, FILE_STR_LEN, "%s%s%s", base1,logdate,tail);
	}

	turn_free(base1,strlen(base1)+1);
	turn_free(tail,strlen(tail)+1);
}

static void sighup_callback_handler(int signum)
{
	if(signum == SIGHUP) {
		to_reset_log_file = 1;
	}
}

static void set_rtpfile(void)
{
	if(to_reset_log_file) {
		printf("%s: resetting the log file\n",__FUNCTION__);
		reset_rtpprintf();
		to_reset_log_file = 0;
	}

	if(to_syslog) {
		return;
	} else if (!_rtpfile) {
		signal(SIGHUP, sighup_callback_handler);
		if(log_fn_base[0]) {
			if(!strcmp(log_fn_base,"syslog")) {
				_rtpfile = stdout;
				to_syslog = 1;
			} else if(!strcmp(log_fn_base,"stdout")|| !strcmp(log_fn_base,"-")) {
				_rtpfile = stdout;
				no_stdout_log = 1;
			} else {
				set_log_file_name(log_fn_base,log_fn);
				_rtpfile = fopen(log_fn, "w");
				if(_rtpfile)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", log_fn);
			}
			if (!_rtpfile) {
				fprintf(stderr,"ERROR: Cannot open log file for writing: %s\n",log_fn);
			} else {
				return;
			}
		}
	}

	if(!_rtpfile) {

		char logbase[FILE_STR_LEN];
		char logtail[FILE_STR_LEN];
		char logf[FILE_STR_LEN];

		if(simple_log)
			snprintf(logtail, FILE_STR_LEN, "turn.log");
		else
			snprintf(logtail, FILE_STR_LEN, "turn_%d_", (int)getpid());

		snprintf(logbase, FILE_STR_LEN, "/var/log/turnserver/%s", logtail);

		set_log_file_name(logbase, logf);

		_rtpfile = fopen(logf, "w");
		if(_rtpfile)
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
		else {
			snprintf(logbase, FILE_STR_LEN, "/var/log/%s", logtail);

			set_log_file_name(logbase, logf);
			_rtpfile = fopen(logf, "w");
			if(_rtpfile)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
			else {
				snprintf(logbase, FILE_STR_LEN, "/var/tmp/%s", logtail);
				set_log_file_name(logbase, logf);
				_rtpfile = fopen(logf, "w");
				if(_rtpfile)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
				else {
					snprintf(logbase, FILE_STR_LEN, "/tmp/%s", logtail);
					set_log_file_name(logbase, logf);
					_rtpfile = fopen(logf, "w");
					if(_rtpfile)
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
					else {
						snprintf(logbase, FILE_STR_LEN, "%s", logtail);
						set_log_file_name(logbase, logf);
						_rtpfile = fopen(logf, "w");
						if(_rtpfile)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
						else {
							_rtpfile = stdout;
							return;
						}
					}
				}
			}
		}

		STRCPY(log_fn_base,logbase);
		STRCPY(log_fn,logf);
	}
}

void set_log_to_syslog(int val)
{
	to_syslog = val;
}

void set_simple_log(int val)
{
	simple_log = val;
}

#define Q(x) #x
#define QUOTE(x) Q(x)

void rollover_logfile(void)
{
	if(to_syslog || !(log_fn[0]))
		return;

	{
		FILE *f = fopen(log_fn,"r");
		if(!f) {
			fprintf(stderr, "log file is damaged\n");
			reset_rtpprintf();
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file reopened: %s\n", log_fn);
			return;
		} else {
			fclose(f);
		}
	}

	if(simple_log)
		return;

	log_lock();
	if(_rtpfile && log_fn[0] && (_rtpfile != stdout)) {
		char logf[FILE_STR_LEN];

		set_log_file_name(log_fn_base,logf);
		if(strcmp(log_fn,logf)) {
			fclose(_rtpfile);
			log_fn[0]=0;
			_rtpfile = fopen(logf, "w");
			if(_rtpfile) {
				STRCPY(log_fn,logf);
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", log_fn);
			} else {
				_rtpfile = stdout;
			}
		}
	}
	log_unlock();
}

static int get_syslog_level(TURN_LOG_LEVEL level)
{
	switch(level) {
	case TURN_LOG_LEVEL_CONTROL:
		return LOG_NOTICE;
	case TURN_LOG_LEVEL_WARNING:
		return LOG_WARNING;
	case TURN_LOG_LEVEL_ERROR:
		return LOG_ERR;
	default:
		;
	};
	return LOG_INFO;
}

int vrtpprintf(TURN_LOG_LEVEL level, const char *format, va_list args)
{
	/* Fix for Issue 24, raised by John Selbie: */
#define MAX_RTPPRINTF_BUFFER_SIZE (1024)
	char s[MAX_RTPPRINTF_BUFFER_SIZE+1];
#undef MAX_RTPPRINTF_BUFFER_SIZE

	size_t sz;

	snprintf(s, sizeof(s), "%lu: ",(unsigned long)log_time());
	sz=strlen(s);
	vsnprintf(s+sz, sizeof(s)-1-sz, format, args);
	s[sizeof(s)-1]=0;

	if(to_syslog) {
		syslog(get_syslog_level(level),"%s",s);
	} else {
		log_lock();
		set_rtpfile();
		if(fprintf(_rtpfile,"%s",s)<0) {
			reset_rtpprintf();
		} else if(fflush(_rtpfile)<0) {
			reset_rtpprintf();
		}
		log_unlock();
	}

	return 0;
}

void rtpprintf(const char *format, ...)
{
	va_list args;
	va_start (args, format);
	vrtpprintf(TURN_LOG_LEVEL_INFO, format, args);
	va_end (args);
}

///////////// ORIGIN ///////////////////

int get_default_protocol_port(const char* scheme, size_t slen)
{
	if(scheme && (slen>0)) {
		switch(slen) {
		case 3:
			if(!memcmp("ftp",scheme,3))
				return 21;
			if(!memcmp("svn",scheme,3))
				return 3690;
			if(!memcmp("ssh",scheme,4))
				return 22;
			if(!memcmp("sip",scheme,3))
				return 5060;
			break;
		case 4:
			if(!memcmp("http",scheme,4))
				return 80;
			if(!memcmp("ldap",scheme,4))
				return 389;
			if(!memcmp("sips",scheme,4))
				return 5061;
			if(!memcmp("turn",scheme,4))
				return 3478;
			if(!memcmp("stun",scheme,4))
				return 3478;
			break;
		case 5:
			if(!memcmp("https",scheme,5))
				return 443;
			if(!memcmp("ldaps",scheme,5))
				return 636;
			if(!memcmp("turns",scheme,5))
				return 5349;
			if(!memcmp("stuns",scheme,5))
				return 5349;
			break;
		case 6:
			if(!memcmp("telnet",scheme,6))
				return 23;
			if(!memcmp("radius",scheme,6))
				return 1645;
			break;
		case 7:
			if(!memcmp("svn+ssh",scheme,7))
				return 22;
			break;
		default:
			return 0;
		};
	}
	return 0;
}

int get_canonic_origin(const char* o, char *co, int sz)
{
	int ret = -1;

	if(o && o[0] && co) {
		co[0]=0;
		struct evhttp_uri *uri = evhttp_uri_parse(o);
		if(uri) {
			const char *scheme = evhttp_uri_get_scheme(uri);
			if(scheme && scheme[0]) {
				size_t schlen = strlen(scheme);
				if((schlen<(size_t)sz) && (schlen<STUN_MAX_ORIGIN_SIZE)) {
					const char *host = evhttp_uri_get_host(uri);
					if(host && host[0]) {
						char otmp[STUN_MAX_ORIGIN_SIZE+STUN_MAX_ORIGIN_SIZE];
						ns_bcopy(scheme,otmp,schlen);
						otmp[schlen]=0;

						{
							unsigned char *s = (unsigned char*)otmp;
							while(*s) {
								*s = (unsigned char)tolower((int)*s);
								++s;
							}
						}

						int port = evhttp_uri_get_port(uri);
						if(port<1) {
							port = get_default_protocol_port(otmp, schlen);
						}
						if(port>0)
							snprintf(otmp+schlen,sizeof(otmp)-schlen-1,"://%s:%d",host,port);
						else
							snprintf(otmp+schlen,sizeof(otmp)-schlen-1,"://%s",host);

						{
							unsigned char *s = (unsigned char*)otmp + schlen + 3;
							while(*s) {
								*s = (unsigned char)tolower((int)*s);
								++s;
							}
						}

						strncpy(co,otmp,sz);
						co[sz]=0;
						ret = 0;
					}
				}
			}
			evhttp_uri_free(uri);
		}
	}

	if(ret<0) {
		strncpy(co,o,sz);
		co[sz]=0;
	}

	return ret;
}

//////////////////////////////////////////////////////////////////

#ifdef __cplusplus
#if defined(TURN_MEMORY_DEBUG)

#include <map>
#include <set>
#include <string>

static volatile int tmm_init = 0;
static pthread_mutex_t tm;

typedef void* ptrtype;
typedef std::set<ptrtype> ptrs_t;
typedef std::map<std::string,ptrs_t> str_to_ptrs_t;
typedef std::map<ptrtype,std::string> ptr_to_str_t;

static str_to_ptrs_t str_to_ptrs;
static ptr_to_str_t ptr_to_str;

static void tm_init(void) {
  if(!tmm_init) {
    pthread_mutex_init(&tm,NULL);
    tmm_init = 1;
  }
}

static void add_tm_ptr(void *ptr, const char *id) {

  UNUSED_ARG(ptr);
  UNUSED_ARG(id);

  if(!ptr)
    return;

  std::string sid(id);

  str_to_ptrs_t::iterator iter;

  pthread_mutex_lock(&tm);

  iter = str_to_ptrs.find(sid);

  if(iter == str_to_ptrs.end()) {
    std::set<ptrtype> sp;
    sp.insert(ptr);
    str_to_ptrs[sid]=sp;
  } else {
	iter->second.insert(ptr);
  }

  ptr_to_str[ptr]=sid;

  pthread_mutex_unlock(&tm);
}

static void del_tm_ptr(void *ptr, const char *id) {

  UNUSED_ARG(ptr);
  UNUSED_ARG(id);

  if(!ptr)
    return;

  pthread_mutex_lock(&tm);

  ptr_to_str_t::iterator pts_iter = ptr_to_str.find(ptr);
  if(pts_iter == ptr_to_str.end()) {

	  printf("Tring to free unknown pointer (1): %s\n",id);

  } else {

    std::string sid = pts_iter->second;
    ptr_to_str.erase(pts_iter);

    str_to_ptrs_t::iterator iter = str_to_ptrs.find(sid);

    if(iter == str_to_ptrs.end()) {

    	printf("Tring to free unknown pointer (2): %s\n",id);

    } else {

      iter->second.erase(ptr);

    }
  }

  pthread_mutex_unlock(&tm);
}

static void tm_id(char *id, const char* function, int line) {
  sprintf(id,"%s:%d",function,line);
}

#define TM_START() char id[128];tm_id(id,function,line);tm_init()

extern "C" void* debug_ptr_add_func(void *ptr, const char* function, int line) {

	TM_START();

	add_tm_ptr(ptr,id);

	return ptr;
}

extern "C" void debug_ptr_del_func(void *ptr, const char* function, int line) {

	TM_START();

	del_tm_ptr(ptr,id);
}

extern "C" void tm_print_func(void);
void tm_print_func(void) {
  pthread_mutex_lock(&tm);
  printf("=============================================\n");
  for(str_to_ptrs_t::const_iterator iter=str_to_ptrs.begin();iter != str_to_ptrs.end();++iter) {
	  if(iter->second.size())
		  printf("%s: %s: %d\n",__FUNCTION__,iter->first.c_str(),(int)(iter->second.size()));
  }
  printf("=============================================\n");
  pthread_mutex_unlock(&tm);
} 

extern "C" void *turn_malloc_func(size_t sz, const char* function, int line);
void *turn_malloc_func(size_t sz, const char* function, int line) {

  TM_START();

  void *ptr = malloc(sz);
  
  add_tm_ptr(ptr,id);

  return ptr;
}

extern "C" void *turn_realloc_func(void *ptr, size_t old_sz, size_t new_sz, const char* function, int line);
void *turn_realloc_func(void *ptr, size_t old_sz, size_t new_sz, const char* function, int line) {

  UNUSED_ARG(old_sz);

  TM_START();

  if(ptr)
	  del_tm_ptr(ptr,id);

  ptr = realloc(ptr,new_sz);

  add_tm_ptr(ptr,id);

  return ptr;
}

extern "C" void turn_free_func(void *ptr, size_t sz, const char* function, int line);
void turn_free_func(void *ptr, size_t sz, const char* function, int line) {

  UNUSED_ARG(sz);

  TM_START();

  del_tm_ptr(ptr,id);

  free(ptr);
}

extern "C" void turn_free_simple(void *ptr);
void turn_free_simple(void *ptr) {

  tm_init();

  del_tm_ptr(ptr,__FUNCTION__);

  free(ptr);
}

extern "C" void *turn_calloc_func(size_t number, size_t size, const char* function, int line);
void *turn_calloc_func(size_t number, size_t size, const char* function, int line) {
  
  TM_START();

  void *ptr = calloc(number,size);

  add_tm_ptr(ptr,id);

  return ptr;
}

extern "C" char *turn_strdup_func(const char* s, const char* function, int line);
char *turn_strdup_func(const char* s, const char* function, int line) {

  TM_START();

  char *ptr = strdup(s);

  add_tm_ptr(ptr,id);

  return ptr;
}

#endif
#endif

////////////////////////////////

int is_secure_username(const u08bits *username)
{
	int ret = 0;
	if(username) {
		unsigned char *s0 = (unsigned char*)turn_strdup((const char*)username);
		unsigned char *s = s0;
		while(*s) {
			*s = (unsigned char)tolower((int)*s);
			++s;
		}
		s = s0;
		if(strstr((char*)s," ")||strstr((char*)s,"\t")||strstr((char*)s,"'")||strstr((char*)s,"\"")||strstr((char*)s,"\n")||strstr((char*)s,"\r")||strstr((char*)s,"\\")) {
			;
		} else if(strstr((char*)s,"union")&&strstr((char*)s,"select")) {
			;
		} else {
			ret = 1;
		}
		turn_free(s,strlen((char*)s));
	}
	return ret;
}

//////////////////////////////////////////////////////////////////

