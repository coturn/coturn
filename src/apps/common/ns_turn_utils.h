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

#ifndef __TURN_ULIB__
#define __TURN_ULIB__

#if !defined(TURN_LOG_FUNC)
//#define TURN_LOG_FUNC(level, ...) printf (__VA_ARGS__)
#define TURN_LOG_FUNC turn_log_func_default
#endif

#include "ns_turn_ioaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////// LOG //////////////////////////

typedef enum {
  TURN_LOG_LEVEL_INFO = 0,
  TURN_LOG_LEVEL_CONTROL,
  TURN_LOG_LEVEL_WARNING,
  TURN_LOG_LEVEL_ERROR
} TURN_LOG_LEVEL;

#define TURN_VERBOSE_NONE (0)
#define TURN_VERBOSE_NORMAL (1)
#define TURN_VERBOSE_EXTRA (2)

#define eve(v) ((v)==TURN_VERBOSE_EXTRA)

void set_no_stdout_log(int val);
void set_log_to_syslog(int val);
void set_simple_log(int val);

void turn_log_func_default(TURN_LOG_LEVEL level, const s08bits* format, ...);

void addr_debug_print(int verbose, const ioa_addr *addr, const s08bits* s);

/* Log */

extern volatile int _log_time_value_set;
extern volatile turn_time_t _log_time_value;

void rtpprintf(const char *format, ...);
int vrtpprintf(TURN_LOG_LEVEL level, const char *format, va_list args);
void reset_rtpprintf(void);
void set_logfile(const char *fn);
void rollover_logfile(void);

///////////////////////////////////////////////////////

int is_secure_username(const u08bits *username);

///////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_ULIB__
