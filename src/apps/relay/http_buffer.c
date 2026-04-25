/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * Copyright (C) 2011, 2012, 2013, 2014 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and/or other materials provided
 *    with the distribution.
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

#include "http_server.h"

#include <event2/http.h>

#include <string.h>

struct str_buffer {
  size_t capacity;
  size_t sz;
  char *buffer;
};

struct str_buffer *str_buffer_new(void) {
  struct str_buffer *ret = (struct str_buffer *)calloc(1, sizeof(struct str_buffer));
  if (!ret) {
    return NULL;
  }
  ret->buffer = (char *)malloc(1);
  if (!(ret->buffer)) {
    free(ret);
    return NULL;
  }
  ret->buffer[0] = 0;
  ret->capacity = 1;
  return ret;
}

void str_buffer_append(struct str_buffer *sb, const char *str) {
  if (sb && str && str[0]) {
    const size_t len = strlen(str);
    while (sb->sz + len + 1 > sb->capacity) {
      sb->capacity += len + 1024;
      sb->buffer = (char *)realloc(sb->buffer, sb->capacity);
    }
    memcpy(sb->buffer + sb->sz, str, len + 1);
    sb->sz += len;
  }
}

void str_buffer_append_html_escaped(struct str_buffer *sb, const char *str) {
  if (!sb || !str) {
    return;
  }

  while (*str) {
    switch (*str) {
    case '&':
      str_buffer_append(sb, "&amp;");
      break;
    case '<':
      str_buffer_append(sb, "&lt;");
      break;
    case '>':
      str_buffer_append(sb, "&gt;");
      break;
    case '"':
      str_buffer_append(sb, "&quot;");
      break;
    case '\'':
      str_buffer_append(sb, "&#x27;");
      break;
    default: {
      char ch[2] = {*str, 0};
      str_buffer_append(sb, ch);
      break;
    }
    }
    ++str;
  }
}

void str_buffer_append_uri_escaped(struct str_buffer *sb, const char *str) {
  if (!sb || !str) {
    return;
  }

  char *encoded = evhttp_encode_uri(str);
  if (encoded) {
    str_buffer_append_html_escaped(sb, encoded);
    free(encoded);
  }
}

void str_buffer_append_sz(struct str_buffer *sb, size_t sz) {
  char ssz[129];
  snprintf(ssz, sizeof(ssz) - 1, "%lu", (unsigned long)sz);
  str_buffer_append(sb, ssz);
}

void str_buffer_append_sid(struct str_buffer *sb, turnsession_id sid) {
  char ssz[129];
  snprintf(ssz, sizeof(ssz) - 1, "%018llu", (unsigned long long)sid);
  str_buffer_append(sb, ssz);
}

const char *str_buffer_get_str(const struct str_buffer *sb) {
  if (sb) {
    return sb->buffer;
  }
  return NULL;
}

size_t str_buffer_get_str_len(const struct str_buffer *sb) {
  if (sb) {
    return sb->sz;
  }
  return 0;
}

void str_buffer_free(struct str_buffer *sb) {
  if (sb) {
    free(sb->buffer);
    free(sb);
  }
}
