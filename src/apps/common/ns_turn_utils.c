/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
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

#if defined(__unix__) || defined(unix) || defined(__APPLE__)
#include <syslog.h>
#endif

#include <stdarg.h>

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>

#include <ctype.h> // for tolower
#include <errno.h>
#include <string.h> // for memcmp, strstr, strcmp, strdup, strlen, strerror

////////// LOG TIME OPTIMIZATION ///////////

static volatile int _log_file_line_set = 0;

static volatile turn_time_t log_start_time = 0;
turn_atomic_u32 _log_time_value = 0;

static inline turn_time_t log_time(void) {
  if (!log_start_time) {
    log_start_time = turn_time();
  }

  const turn_time_t t = turn_atomic_load_u32(&_log_time_value);
  if (t) {
    return (t - log_start_time);
  }

  return (turn_time() - log_start_time);
}

////////// MUTEXES /////////////

#define MAGIC_CODE (0xEFCD1983)

int turn_mutex_lock(const turn_mutex *mutex) {
  if (mutex && mutex->mutex && (mutex->data == MAGIC_CODE)) {
    int ret = 0;
    ret = pthread_mutex_lock((pthread_mutex_t *)mutex->mutex);
    if (ret < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Mutex lock: %s\n", strerror(errno));
    }
    return ret;
  } else {
    printf("Uninitialized mutex\n");
    return -1;
  }
}

int turn_mutex_unlock(const turn_mutex *mutex) {
  if (mutex && mutex->mutex && (mutex->data == MAGIC_CODE)) {
    int ret = 0;
    ret = pthread_mutex_unlock((pthread_mutex_t *)mutex->mutex);
    if (ret < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Mutex unlock: %s\n", strerror(errno));
    }
    return ret;
  } else {
    printf("Uninitialized mutex\n");
    return -1;
  }
}

int turn_mutex_init(turn_mutex *mutex) {
  if (!mutex) {
    return -1;
  }

  mutex->mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
  if (!(mutex->mutex)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot allocate mutex: %s\n", strerror(errno));
    return -1;
  }

  if (pthread_mutex_init((pthread_mutex_t *)mutex->mutex, NULL) != 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot init mutex: %s\n", strerror(errno));
    free(mutex->mutex);
    mutex->mutex = NULL;
    return -1;
  }

  mutex->data = MAGIC_CODE;
  return 0;
}

int turn_mutex_init_recursive(turn_mutex *mutex) {
  if (!mutex) {
    return -1;
  }

  pthread_mutexattr_t attr;
  if (pthread_mutexattr_init(&attr) != 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot init mutex attr: %s\n", strerror(errno));
    return -1;
  }

  if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot set type on mutex attr: %s\n", strerror(errno));
    return -1;
  }

  mutex->mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
  if (!(mutex->mutex)) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot allocate mutex: %s\n", strerror(errno));
    return -1;
  }

  if (pthread_mutex_init((pthread_mutex_t *)mutex->mutex, &attr) != 0) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot init mutex: %s\n", strerror(errno));
    free(mutex->mutex);
    mutex->mutex = NULL;
    return -1;
  }

  pthread_mutexattr_destroy(&attr);

  mutex->data = MAGIC_CODE;
  return 0;
}

int turn_mutex_destroy(turn_mutex *mutex) {
  if (mutex && mutex->mutex && mutex->data == MAGIC_CODE) {
    int ret = 0;
    ret = pthread_mutex_destroy((pthread_mutex_t *)(mutex->mutex));
    free(mutex->mutex);
    mutex->mutex = NULL;
    mutex->data = 0;
    return ret;
  } else {
    return 0;
  }
}

///////////////////////// LOG ///////////////////////////////////

/* syslog facility */
/*BVB-594  Syslog facility */
static const char *const str_fac[] = {"LOG_AUTH",   "LOG_CRON",   "LOG_DAEMON",   "LOG_KERN",   "LOG_LOCAL0",
                                      "LOG_LOCAL1", "LOG_LOCAL2", "LOG_LOCAL3",   "LOG_LOCAL4", "LOG_LOCAL5",
                                      "LOG_LOCAL6", "LOG_LOCAL7", "LOG_LPR",      "LOG_MAIL",   "LOG_NEWS",
                                      "LOG_USER",   "LOG_UUCP",   "LOG_AUTHPRIV", "LOG_SYSLOG", 0};

#if defined(__unix__) || defined(unix) || defined(__APPLE__)
static const int int_fac[] = {LOG_AUTH,   LOG_CRON,   LOG_DAEMON, LOG_KERN,     LOG_LOCAL0, LOG_LOCAL1, LOG_LOCAL2,
                              LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6,   LOG_LOCAL7, LOG_LPR,    LOG_MAIL,
                              LOG_NEWS,   LOG_USER,   LOG_UUCP,   LOG_AUTHPRIV, LOG_SYSLOG, 0};

static int syslog_facility = 0;

static int str_to_syslog_facility(char *s) {
  int i;
  for (i = 0; str_fac[i]; i++) {
    if (!strcasecmp(s, str_fac[i])) {
      return int_fac[i];
    }
  }
  return -1;
}
#endif
void set_syslog_facility(char *val) {
  if (val == NULL) {
    return;
  }
#if defined(__unix__) || defined(unix) || defined(__APPLE__)
  const int tmp = str_to_syslog_facility(val);
  if (tmp == -1) {
    TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "WARNING: invalid syslog-facility value (%s); ignored.\n", val);
    return;
  }
  syslog_facility = tmp;
#endif
}

TURN_LOG_LEVEL log_min_level = TURN_LOG_LEVEL_DEBUG;

#if defined(TURN_LOG_FUNC_IMPL)
extern void TURN_LOG_FUNC_IMPL(TURN_LOG_LEVEL level, const char *format, va_list args);
#endif

static int no_stdout_log = 0;

void set_no_stdout_log(int val) { no_stdout_log = val; }

#define MAX_LOG_TIMESTAMP_FORMAT_LEN 48
/* %f is not a strftime conversion; it is expanded here to milliseconds. */
static char turn_log_timestamp_format[MAX_LOG_TIMESTAMP_FORMAT_LEN] = "%FT%T.%f%z";

/* Bumped so that per-thread timestamp caches re-render after a format change. */
static turn_atomic_u32 log_timestamp_format_generation = 0;

void set_turn_log_timestamp_format(char *new_format) {
  strncpy(turn_log_timestamp_format, new_format, MAX_LOG_TIMESTAMP_FORMAT_LEN - 1);
  turn_atomic_fetch_add_u32(&log_timestamp_format_generation, 1);
}

static const struct {
  const char *const name;
  const TURN_LOG_LEVEL level;
} log_min_level_names[] = {{"debug", TURN_LOG_LEVEL_DEBUG},
                           {"info", TURN_LOG_LEVEL_INFO},
                           {"warning", TURN_LOG_LEVEL_WARNING},
                           {"error", TURN_LOG_LEVEL_ERROR}};

void set_log_min_level(const char *value) {
  if (value == NULL) {
    return;
  }
  for (size_t i = 0; i < sizeof(log_min_level_names) / sizeof(log_min_level_names[0]); i++) {
    if (!strcasecmp(value, log_min_level_names[i].name)) {
      log_min_level = log_min_level_names[i].level;
      return;
    }
  }
  TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING,
                "WARNING: invalid log-min-level value (%s); ignored. Valid values: debug, info, warning, error.\n",
                value);
}

int use_new_log_timestamp_format = 1;

void addr_debug_print(int verbose, const ioa_addr *addr, const char *s) {
  if (verbose) {
    if (!addr) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: EMPTY\n", s);
    } else {
      char addrbuf[INET6_ADDRSTRLEN];
      if (!s) {
        s = "";
      }
      if (addr->ss.sa_family == AF_INET) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "IPv4. %s: %s:%d\n", s,
                      inet_ntop(AF_INET, &addr->s4.sin_addr, addrbuf, INET6_ADDRSTRLEN), nswap16(addr->s4.sin_port));
      } else if (addr->ss.sa_family == AF_INET6) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "IPv6. %s: %s:%d\n", s,
                      inet_ntop(AF_INET6, &addr->s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN), nswap16(addr->s6.sin6_port));
      } else {
        if (addr_any_no_port(addr)) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "IP. %s: 0.0.0.0:%d\n", s, nswap16(addr->s4.sin_port));
        } else {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: wrong IP address family: %d\n", s, (int)(addr->ss.sa_family));
        }
      }
    }
  }
}

/*************************************/

#define FILE_STR_LEN (1025)

static FILE *_rtpfile = NULL;
static int to_syslog = 0;
static int simple_log = 0;
static char log_fn[FILE_STR_LEN] = "\0";
static char log_fn_base[FILE_STR_LEN] = "\0";
static volatile int to_reset_log_file = 0;

static turn_mutex log_mutex;
static int log_mutex_inited = 0;

static void log_lock(void) {
  if (!log_mutex_inited) {
    log_mutex_inited = 1;
    turn_mutex_init_recursive(&log_mutex);
  }
  turn_mutex_lock(&log_mutex);
}

static void log_unlock(void) { turn_mutex_unlock(&log_mutex); }

/* localtime() returns a pointer to a static struct tm shared by all threads;
 * every relay thread logs, so use the reentrant form. */
static struct tm *turn_localtime(const time_t *timep, struct tm *result) {
#if defined(WINDOWS)
  return (localtime_s(result, timep) == 0) ? result : NULL;
#else
  return localtime_r(timep, result);
#endif
}

static void get_date(char *s, size_t sz) {
  time_t curtm;
  struct tm tm_info = {0};

  curtm = time(NULL);

  if (turn_localtime(&curtm, &tm_info)) {
    strftime(s, sz, "%F", &tm_info);
  } else if (sz) {
    s[0] = 0;
  }
}

/* Wall clock as whole seconds plus milliseconds from one reading, so the
 * seconds text and the fraction appended to it cannot straddle a boundary. */
static void turn_wall_clock(time_t *secs, unsigned *msec) {
#if defined(_MSC_VER)
  /* 100ns ticks since 1601-01-01; 11644473600s from there to the Unix epoch. */
  FILETIME ft;
  ULARGE_INTEGER ticks;
  GetSystemTimeAsFileTime(&ft);
  ticks.LowPart = ft.dwLowDateTime;
  ticks.HighPart = ft.dwHighDateTime;
  const uint64_t since_epoch = ticks.QuadPart - 116444736000000000ULL;
  *secs = (time_t)(since_epoch / 10000000ULL);
  *msec = (unsigned)((since_epoch / 10000ULL) % 1000ULL);
#elif defined(CLOCK_REALTIME)
  struct timespec tp = {0, 0};
  clock_gettime(CLOCK_REALTIME, &tp);
  *secs = tp.tv_sec;
  *msec = (unsigned)(tp.tv_nsec / 1000000);
#else
  *secs = time(NULL);
  *msec = 0;
#endif
}

/* First unescaped %f in the format, skipping %% pairs. */
static const char *turn_find_msec_spec(const char *format) {
  for (const char *p = format; *p; ++p) {
    if (*p != '%') {
      continue;
    }
    if (p[1] == '%') {
      ++p;
      continue;
    }
    if (p[1] == 'f') {
      return p;
    }
  }
  return NULL;
}

#define TURN_LOG_MSEC_DIGITS 3

static void turn_write_msec(char *p, unsigned msec) {
  p[0] = (char)('0' + (msec / 100) % 10);
  p[1] = (char)('0' + (msec / 10) % 10);
  p[2] = (char)('0' + msec % 10);
}

#define TURN_LOG_NO_MSEC ((size_t)-1)

/* Renders turn_log_timestamp_format, expanding the first %f to milliseconds.
 * Returns 0 if the result does not fit. *msec_off receives the offset of the
 * millisecond digits, or TURN_LOG_NO_MSEC when the format has none. */
static size_t turn_render_timestamp_format(char *buf, size_t bufsz, const struct tm *tm_now, unsigned msec,
                                           size_t *msec_off) {
  *msec_off = TURN_LOG_NO_MSEC;

  const char *spec = turn_find_msec_spec(turn_log_timestamp_format);
  if (!spec) {
    return strftime(buf, bufsz, turn_log_timestamp_format, tm_now);
  }

  size_t len = 0;
  const size_t head_len = (size_t)(spec - turn_log_timestamp_format);
  if (head_len) {
    char head[MAX_LOG_TIMESTAMP_FORMAT_LEN] = {0};
    memcpy(head, turn_log_timestamp_format, head_len);
    len = strftime(buf, bufsz, head, tm_now);
    if (len == 0) {
      return 0;
    }
  }

  if (len + TURN_LOG_MSEC_DIGITS >= bufsz) {
    return 0;
  }
  turn_write_msec(buf + len, msec);
  *msec_off = len;
  len += TURN_LOG_MSEC_DIGITS;

  const char *tail = spec + 2;
  if (*tail) {
    const size_t tail_len = strftime(buf + len, bufsz - len, tail, tm_now);
    if (tail_len == 0) {
      return 0;
    }
    len += tail_len;
  }
  return len;
}

/*
 * The timestamp prefix is re-rendered on every log line, but everything down to
 * the second only changes once a second. Rendering costs a localtime_r() --
 * which takes a lock inside libc, so it serializes relay threads -- plus a
 * strftime(). Cache the rendered text per thread and patch in just the
 * millisecond digits per line: the steady state is a comparison, a memcpy and
 * three stores, with no state shared between threads to contend on.
 */
#define TURN_LOG_TIMESTAMP_CACHE_SIZE 128

static size_t turn_log_render_timestamp(char *out, size_t outsz) {
  static TURN_THREAD_LOCAL struct {
    bool valid;
    bool iso_format;
    uint32_t generation;
    turn_time_t key;
    size_t len;
    size_t msec_off;
    char text[TURN_LOG_TIMESTAMP_CACHE_SIZE];
  } cache;

  const bool iso_format = (use_new_log_timestamp_format != 0);
  const uint32_t generation = turn_atomic_load_u32(&log_timestamp_format_generation);

  time_t now = 0;
  unsigned msec = 0;
  if (iso_format) {
    turn_wall_clock(&now, &msec);
  }
  const turn_time_t key = iso_format ? (turn_time_t)now : log_time();

  if (!cache.valid || cache.key != key || cache.iso_format != iso_format || cache.generation != generation) {
    size_t len = 0;
    size_t msec_off = TURN_LOG_NO_MSEC;
    if (iso_format) {
      struct tm tm_now = {0};
      if (turn_localtime(&now, &tm_now)) {
        len = turn_render_timestamp_format(cache.text, sizeof(cache.text), &tm_now, msec, &msec_off);
        if (len == 0) {
          /* Rendering does not fit the cache; fall back to the caller's buffer. */
          size_t direct_off = TURN_LOG_NO_MSEC;
          return turn_render_timestamp_format(out, outsz, &tm_now, msec, &direct_off);
        }
      }
    } else {
      const int written = snprintf(cache.text, sizeof(cache.text), "%lu", (unsigned long)key);
      if (written > 0 && (size_t)written < sizeof(cache.text)) {
        len = (size_t)written;
      }
    }
    cache.len = len;
    cache.msec_off = msec_off;
    cache.key = key;
    cache.iso_format = iso_format;
    cache.generation = generation;
    cache.valid = true;
  }

  const size_t len = min(cache.len, outsz);
  memcpy(out, cache.text, len);
  if (cache.msec_off != TURN_LOG_NO_MSEC && cache.msec_off + TURN_LOG_MSEC_DIGITS <= len) {
    turn_write_msec(out + cache.msec_off, msec);
  }
  return len;
}

void set_logfile(const char *fn) {
  if (fn) {
    log_lock();
    if (strcmp(fn, log_fn_base) != 0) {
      reset_rtpprintf();
      STRCPY(log_fn_base, fn);
    }
    log_unlock();
  }
}

void set_log_file_line(int set) { _log_file_line_set = set; }

void reset_rtpprintf(void) {
  log_lock();
  if (_rtpfile) {
    if (_rtpfile != stdout) {
      fclose(_rtpfile);
    }
    _rtpfile = NULL;
  }
  log_unlock();
}

#define set_log_file_name(base, f) set_log_file_name_func(base, f, sizeof(f))

static void set_log_file_name_func(char *base, char *f, size_t fsz) {
  if (simple_log) {
    strncpy(f, base, fsz);
    return;
  }

  char logdate[125];
  char *tail = strdup(".log");

  get_date(logdate, sizeof(logdate));

  char *base1 = strdup(base);

  int len = (int)strlen(base1);

  --len;

  while (len >= 0) {
    if ((base1[len] == ' ') || (base1[len] == '\t')) {
      base1[len] = '_';
    }
    --len;
  }

  len = (int)strlen(base1);

  while (len >= 0) {
    if (base1[len] == '/') {
      break;
    } else if (base1[len] == '.') {
      free(tail);
      tail = strdup(base1 + len);
      base1[len] = 0;
      if (strlen(tail) < 2) {
        free(tail);
        tail = strdup(".log");
      }
      break;
    }
    --len;
  }

  len = (int)strlen(base1);
  if (len > 0 && (base1[len - 1] != '/') && (base1[len - 1] != '-') && (base1[len - 1] != '_')) {
    snprintf(f, FILE_STR_LEN, "%s_%s%s", base1, logdate, tail);
  } else {
    snprintf(f, FILE_STR_LEN, "%s%s%s", base1, logdate, tail);
  }

  free(base1);
  free(tail);
}

static void sighup_callback_handler(int signum) {
#if defined(__unix__) || defined(unix) || defined(__APPLE__)
  if (signum == SIGHUP) {
    to_reset_log_file = 1;
  }
#endif
}

static void set_rtpfile(void) {
  if (to_reset_log_file) {
    printf("%s: resetting the log file\n", __FUNCTION__);
    reset_rtpprintf();
    to_reset_log_file = 0;
  }

  if (to_syslog) {
    return;
  } else if (!_rtpfile) {

#if defined(__unix__) || defined(unix) || defined(__APPLE__)
    signal(SIGHUP, sighup_callback_handler);
#endif

    if (log_fn_base[0]) {
      if (!strcmp(log_fn_base, "syslog")) {
        _rtpfile = stdout;
        to_syslog = 1;
      } else if (!strcmp(log_fn_base, "stdout") || !strcmp(log_fn_base, "-")) {
        _rtpfile = stdout;
        no_stdout_log = 1;
      } else {
        set_log_file_name(log_fn_base, log_fn);
        _rtpfile = fopen(log_fn, "a");
        if (_rtpfile) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", log_fn);
        }
      }
      if (!_rtpfile) {
        fprintf(stderr, "ERROR: Cannot open log file for writing: %s\n", log_fn);
      } else {
        return;
      }
    }
  }

  if (!_rtpfile) {

    char logbase[FILE_STR_LEN];
    char logtail[FILE_STR_LEN];
    char logf[FILE_STR_LEN];

    if (simple_log) {
      snprintf(logtail, FILE_STR_LEN, "turn.log");
    } else {
      snprintf(logtail, FILE_STR_LEN, "turn_%d_", (int)getpid());
    }

    if (snprintf(logbase, FILE_STR_LEN, "/var/log/turnserver/%s", logtail) < 0) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "String truncation occured.\n");
    }

    set_log_file_name(logbase, logf);

    _rtpfile = fopen(logf, "a");
    if (_rtpfile) {
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
    } else {
      if (snprintf(logbase, FILE_STR_LEN, "/var/log/%s", logtail) < 0) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "String truncation occured.\n");
      }

      set_log_file_name(logbase, logf);
      _rtpfile = fopen(logf, "a");
      if (_rtpfile) {
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
      } else {
        if (snprintf(logbase, FILE_STR_LEN, "/var/tmp/%s", logtail) < 0) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "String truncation occured.\n");
        }

        set_log_file_name(logbase, logf);
        _rtpfile = fopen(logf, "a");
        if (_rtpfile) {
          TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
        } else {
          if (snprintf(logbase, FILE_STR_LEN, "/tmp/%s", logtail) < 0) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "String truncation occured.\n");
          }
          set_log_file_name(logbase, logf);
          _rtpfile = fopen(logf, "a");
          if (_rtpfile) {
            TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
          } else {
            snprintf(logbase, FILE_STR_LEN, "%s", logtail);
            set_log_file_name(logbase, logf);
            _rtpfile = fopen(logf, "a");
            if (_rtpfile) {
              TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", logf);
            } else {
              _rtpfile = stdout;
              return;
            }
          }
        }
      }
    }

    STRCPY(log_fn_base, logbase);
    STRCPY(log_fn, logf);
  }
}

void set_log_to_syslog(int val) { to_syslog = val; }

void set_simple_log(int val) { simple_log = val; }

#define Q(x) #x
#define QUOTE(x) Q(x)

void rollover_logfile(void) {
  if (to_syslog || !(log_fn[0])) {
    return;
  }

  {
    FILE *f = fopen(log_fn, "r");
    if (!f) {
      fprintf(stderr, "log file is damaged\n");
      reset_rtpprintf();
      TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file reopened: %s\n", log_fn);
      return;
    } else {
      fclose(f);
    }
  }

  if (simple_log) {
    return;
  }

  log_lock();
  if (_rtpfile && log_fn[0] && (_rtpfile != stdout)) {
    char logf[FILE_STR_LEN];

    set_log_file_name(log_fn_base, logf);
    if (strcmp(log_fn, logf) != 0) {
      fclose(_rtpfile);
      log_fn[0] = 0;
      _rtpfile = fopen(logf, "w");
      if (_rtpfile) {
        STRCPY(log_fn, logf);
        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "log file opened: %s\n", log_fn);
      } else {
        _rtpfile = stdout;
      }
    }
  }
  log_unlock();
}

static int get_syslog_level(TURN_LOG_LEVEL level) {
#if defined(__unix__) || defined(unix) || defined(__APPLE__)
  switch (level) {
  case TURN_LOG_LEVEL_WARNING:
    return LOG_WARNING;
  case TURN_LOG_LEVEL_ERROR:
    return LOG_ERR;
  default:;
  };
  return LOG_INFO;
#endif
  return level;
}

#if defined(WINDOWS)
void err(int eval, const char *format, ...) {
  va_list args;
  va_start(args, format);
  TURN_LOG_FUNC(eval, format, args);
  va_end(args);
}
#endif

void turn_log_func_default(const char *const file, const int line, const TURN_LOG_LEVEL level, const char *const format,
                           ...) {
  if (level < log_min_level) {
    return;
  }
  va_list args;
  va_start(args, format);
#if defined(TURN_LOG_FUNC_IMPL)
  TURN_LOG_FUNC_IMPL(level, format, args);
#else
  /* Fix for Issue 24, raised by John Selbie: */
#define MAX_RTPPRINTF_BUFFER_SIZE (1024)
  char s[MAX_RTPPRINTF_BUFFER_SIZE + 1];
  size_t so_far = 0;
  so_far += turn_log_render_timestamp(s, sizeof(s));

  /* Fields are separated by a single space: ':' occurs throughout message
   * bodies, so it cannot delimit anything a log parser can rely on. */
  if (so_far < MAX_RTPPRINTF_BUFFER_SIZE) {
    s[so_far++] = ' ';
  }

  if (_log_file_line_set) {
    so_far += snprintf(s + so_far, MAX_RTPPRINTF_BUFFER_SIZE - (so_far + 1), "%s(%d) ", file, line);
  }

  switch (level) {
  case TURN_LOG_LEVEL_DEBUG:
    so_far += snprintf(s + so_far, MAX_RTPPRINTF_BUFFER_SIZE - (so_far + 1), "DEBUG ");
    break;
  case TURN_LOG_LEVEL_INFO:
    so_far += snprintf(s + so_far, MAX_RTPPRINTF_BUFFER_SIZE - (so_far + 1), "INFO ");
    break;
  case TURN_LOG_LEVEL_WARNING:
    so_far += snprintf(s + so_far, MAX_RTPPRINTF_BUFFER_SIZE - (so_far + 1), "WARNING ");
    break;
  case TURN_LOG_LEVEL_ERROR:
    so_far += snprintf(s + so_far, MAX_RTPPRINTF_BUFFER_SIZE - (so_far + 1), "ERROR ");
    break;
  }
  so_far += vsnprintf(s + so_far, MAX_RTPPRINTF_BUFFER_SIZE - (so_far + 1), format, args);

  if (so_far > MAX_RTPPRINTF_BUFFER_SIZE + 1) {
    so_far = MAX_RTPPRINTF_BUFFER_SIZE + 1;
  }
  if (!no_stdout_log) {
    fwrite(s, so_far, 1, stdout);
  }
  /* write to syslog or to log file */
  if (to_syslog) {

#if defined(WINDOWS)
    // TODO: add event tracing: https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing
    //  windows10: https://docs.microsoft.com/en-us/windows/win32/tracelogging/trace-logging-portal
    printf("%s", s);
#else
    syslog(syslog_facility | get_syslog_level(level), "%s", s);
#endif

  } else {
    log_lock();
    set_rtpfile();
    if (fprintf(_rtpfile, "%s", s) < 0) {
      reset_rtpprintf();
    } else if (fflush(_rtpfile) < 0) {
      reset_rtpprintf();
    }
    log_unlock();
  }
#endif
  va_end(args);
}

///////////// MEMORY ///////////////////

/*
 * Fail-fast allocation wrappers. On allocation failure they log the failing
 * call site and abort(): a TURN server that cannot allocate cannot correctly
 * continue, and a controlled abort is preferable to a NULL dereference or a
 * silently degraded process. The logger writes into a stack buffer (no heap
 * allocation), so it remains usable when the heap is exhausted.
 */

static void turn_out_of_memory(const char *file, int line, const char *what, size_t sz) {
  turn_log_func_default(file, line, TURN_LOG_LEVEL_ERROR, "FATAL: out of memory: %s(%lu) failed, aborting\n", what,
                        (unsigned long)sz);
  abort();
}

void *turn_malloc_impl(size_t sz, const char *file, int line) {
  void *ptr = malloc(sz);
  if (!ptr && sz) {
    turn_out_of_memory(file, line, "malloc", sz);
  }
  return ptr;
}

void *turn_calloc_impl(size_t number, size_t size, const char *file, int line) {
  void *ptr = calloc(number, size);
  if (!ptr && number && size) {
    turn_out_of_memory(file, line, "calloc", number * size);
  }
  return ptr;
}

void *turn_realloc_impl(void *ptr, size_t sz, const char *file, int line) {
  void *newptr = realloc(ptr, sz);
  if (!newptr && sz) {
    turn_out_of_memory(file, line, "realloc", sz);
  }
  return newptr;
}

char *turn_strdup_impl(const char *s, const char *file, int line) {
  if (!s) {
    return NULL;
  }
  char *ptr = strdup(s);
  if (!ptr) {
    turn_out_of_memory(file, line, "strdup", strlen(s) + 1);
  }
  return ptr;
}

///////////// ORIGIN ///////////////////

int get_default_protocol_port(const char *scheme, size_t slen) {
  if (scheme && (slen > 0)) {
    switch (slen) {
    case 3:
      if (!memcmp("ftp", scheme, 3)) {
        return 21;
      }
      if (!memcmp("svn", scheme, 3)) {
        return 3690;
      }
      if (!memcmp("ssh", scheme, 3)) {
        return 22;
      }
      if (!memcmp("sip", scheme, 3)) {
        return 5060;
      }
      break;
    case 4:
      if (!memcmp("http", scheme, 4)) {
        return 80;
      }
      if (!memcmp("ldap", scheme, 4)) {
        return 389;
      }
      if (!memcmp("sips", scheme, 4)) {
        return 5061;
      }
      if (!memcmp("turn", scheme, 4)) {
        return 3478;
      }
      if (!memcmp("stun", scheme, 4)) {
        return 3478;
      }
      break;
    case 5:
      if (!memcmp("https", scheme, 5)) {
        return 443;
      }
      if (!memcmp("ldaps", scheme, 5)) {
        return 636;
      }
      if (!memcmp("turns", scheme, 5)) {
        return 5349;
      }
      if (!memcmp("stuns", scheme, 5)) {
        return 5349;
      }
      break;
    case 6:
      if (!memcmp("telnet", scheme, 6)) {
        return 23;
      }
      if (!memcmp("radius", scheme, 6)) {
        return 1645;
      }
      break;
    case 7:
      if (!memcmp("svn+ssh", scheme, 7)) {
        return 22;
      }
      break;
    default:
      return 0;
    };
  }
  return 0;
}

int get_canonic_origin(const char *o, char *co, int sz) {
  int ret = -1;

  if (o && o[0] && co) {
    co[0] = 0;
    struct evhttp_uri *uri = evhttp_uri_parse(o);
    if (uri) {
      const char *scheme = evhttp_uri_get_scheme(uri);
      if (scheme && scheme[0]) {
        const size_t schlen = strlen(scheme);
        if ((schlen < (size_t)sz) && (schlen < STUN_MAX_ORIGIN_SIZE)) {
          const char *host = evhttp_uri_get_host(uri);
          if (host && host[0]) {
            char otmp[STUN_MAX_ORIGIN_SIZE + STUN_MAX_ORIGIN_SIZE];
            memcpy(otmp, scheme, schlen);
            otmp[schlen] = 0;

            {
              unsigned char *s = (unsigned char *)otmp;
              while (*s) {
                *s = (unsigned char)tolower((int)*s);
                ++s;
              }
            }

            int port = evhttp_uri_get_port(uri);
            if (port < 1) {
              port = get_default_protocol_port(otmp, schlen);
            }
            if (port > 0) {
              snprintf(otmp + schlen, sizeof(otmp) - schlen - 1, "://%s:%d", host, port);
            } else {
              snprintf(otmp + schlen, sizeof(otmp) - schlen - 1, "://%s", host);
            }

            {
              unsigned char *s = (unsigned char *)otmp + schlen + 3;
              while (*s) {
                *s = (unsigned char)tolower((int)*s);
                ++s;
              }
            }

            strncpy(co, otmp, sz);
            co[sz] = 0;
            ret = 0;
          }
        }
      }
      evhttp_uri_free(uri);
    }

    if (ret < 0) {
      strncpy(co, o, sz);
      co[sz] = 0;
    }
  }

  return ret;
}

//////////////////////////////////////////////////////////////////

int is_secure_string(const uint8_t *string, int sanitizesql) {
  int ret = 0;
  if (string) {
    unsigned char *s0 = (unsigned char *)strdup((const char *)string);
    unsigned char *s = s0;
    while (*s) {
      *s = (unsigned char)tolower((int)*s);
      ++s;
    }
    s = s0;
    if (strstr((char *)s, " ") || strstr((char *)s, "\t") || strstr((char *)s, "'") || strstr((char *)s, "\"") ||
        strstr((char *)s, "\n") || strstr((char *)s, "\r") || strstr((char *)s, "\\")) {
      ;
    } else if (sanitizesql && strstr((char *)s, "union") && strstr((char *)s, "select")) {
      ;
    } else {
      ret = 1;
    }
    free(s);
  }
  return ret;
}

//////////////////////////////////////////////////////////////////
