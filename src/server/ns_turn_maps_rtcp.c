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

#include "ns_turn_maps_rtcp.h"

#include "ns_turn_defs.h" // for NULL, UNUSED_ARG, size_t, turn_time,

#include <stdlib.h> // for free, calloc

////////////////////////////////////////////

#define MAGIC_RTCP_MAP (0x76859403)
#define RTCP_TIMEOUT (300)
#define MAX_TOKEN_DEL (1024)

////////////////////////////////////////////

struct _rtcp_map {
  uint32_t magic;
  ur_map *map;
  ioa_timer_handle timer_ev;
  TURN_MUTEX_DECLARE(mutex)
};

typedef struct {
  ioa_socket_handle s;
  turn_time_t t;
  rtcp_token_type token;
} rtcp_alloc_type;

////////////////////////////////////////////

static bool rtcp_map_valid(const rtcp_map *map) { return (map && (map->magic == MAGIC_RTCP_MAP) && map->map); }

typedef struct {
  rtcp_token_type tokens[MAX_TOKEN_DEL];
  size_t tn;
  turn_time_t t;
} timeout_check_arg_type;

static bool timeout_check(ur_map_key_type key, ur_map_value_type value, void *arg) {

  if (value && arg) {

    timeout_check_arg_type *tcat = (timeout_check_arg_type *)arg;

    rtcp_alloc_type *rat = (rtcp_alloc_type *)value;

    if (turn_time_before(rat->t, tcat->t) && (tcat->tn < MAX_TOKEN_DEL)) {
      tcat->tokens[(tcat->tn)++] = key;
    }
  }

  return false;
}

static void rtcp_alloc_free(ur_map_value_type value) {
  rtcp_alloc_type *at = (rtcp_alloc_type *)value;
  if (at) {
    IOA_CLOSE_SOCKET(at->s);
    free(at);
  }
}

static void rtcp_alloc_free_savefd(ur_map_value_type value) {
  rtcp_alloc_type *at = (rtcp_alloc_type *)value;
  if (at) {
    free(at);
  }
}

static bool foreachcb_free(ur_map_key_type key, ur_map_value_type value) {
  UNUSED_ARG(key);
  if (value) {
    rtcp_alloc_free(value);
  }
  return false;
}

/**
 * @ret:
 * true - success
 * false - not found
 */
static bool rtcp_map_del(rtcp_map *map, rtcp_token_type token) {
  if (!rtcp_map_valid(map)) {
    return false;
  }

  TURN_MUTEX_LOCK(&map->mutex);
  bool ret = ur_map_del(map->map, token, rtcp_alloc_free);
  TURN_MUTEX_UNLOCK(&map->mutex);
  return ret;
}

static bool rtcp_map_del_savefd(rtcp_map *map, rtcp_token_type token) {
  if (!rtcp_map_valid(map)) {
    return false;
  }
  return ur_map_del(map->map, token, rtcp_alloc_free_savefd);
}

static void rtcp_map_timeout_handler(ioa_engine_handle e, void *arg) {

  UNUSED_ARG(e);

  if (!arg) {
    return;
  }

  rtcp_map *map = (rtcp_map *)arg;

  if (rtcp_map_valid(map)) {

    TURN_MUTEX_LOCK(&map->mutex);

    timeout_check_arg_type tcat;
    tcat.tn = 0;
    tcat.t = turn_time();

    ur_map_foreach_arg(map->map, timeout_check, &tcat);

    TURN_MUTEX_UNLOCK(&map->mutex);

    for (size_t i = 0; i < tcat.tn; i++) {
      rtcp_map_del(map, tcat.tokens[i]);
    }
  }
}

static bool rtcp_map_init(rtcp_map *map, ioa_engine_handle e) {
  if (map) {
    if (map->magic != MAGIC_RTCP_MAP) {
      map->magic = MAGIC_RTCP_MAP;
      map->map = ur_map_create();
      if (e) {
        map->timer_ev = set_ioa_timer(e, 3, 0, rtcp_map_timeout_handler, map, 1, "rtcp_map_timeout_handler");
      }
      TURN_MUTEX_INIT(&map->mutex);
      if (rtcp_map_valid(map)) {
        return true;
      }
    }
  }
  return false;
}

rtcp_map *rtcp_map_create(ioa_engine_handle e) {
  rtcp_map *map = (rtcp_map *)calloc(sizeof(rtcp_map), 1);
  if (!rtcp_map_init(map, e)) {
    free(map);
    return NULL;
  }
  return map;
}

/**
 * @ret:
 * true - success
 * false - error
 */
bool rtcp_map_put(rtcp_map *map, rtcp_token_type token, ioa_socket_handle s) {
  if (!rtcp_map_valid(map)) {
    return false;
  } else {
    rtcp_alloc_type *value = (rtcp_alloc_type *)calloc(sizeof(rtcp_alloc_type), 1);
    if (!value) {
      return false;
    }

    value->s = s;
    value->t = turn_time() + RTCP_TIMEOUT;
    value->token = token;
    TURN_MUTEX_LOCK(&map->mutex);
    bool ret = ur_map_put(map->map, token, (ur_map_value_type)value);
    // TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: 111.111: ret=%d, token=%llu\n",__FUNCTION__,ret,token);
    TURN_MUTEX_UNLOCK(&map->mutex);
    if (!ret) {
      free(value);
    }
    return ret;
  }
}

/**
 * @ret:
 * >=0 - success
 * <0 - not found
 */
ioa_socket_handle rtcp_map_get(rtcp_map *map, rtcp_token_type token) {
  ioa_socket_handle s = NULL;
  if (rtcp_map_valid(map)) {
    ur_map_value_type value;
    TURN_MUTEX_LOCK(&map->mutex);
    int ret = ur_map_get(map->map, token, &value);
    if (ret) {
      rtcp_alloc_type *rval = (rtcp_alloc_type *)value;
      if (rval) {
        s = rval->s;
        rtcp_map_del_savefd(map, token);
      }
    }
    TURN_MUTEX_UNLOCK(&map->mutex);
  }
  return s;
}

void rtcp_map_free(rtcp_map **map) {
  if (map && rtcp_map_valid(*map)) {
    TURN_MUTEX_LOCK(&((*map)->mutex));
    IOA_EVENT_DEL((*map)->timer_ev);
    ur_map_foreach((*map)->map, foreachcb_free);
    ur_map_free(&((*map)->map));
    (*map)->magic = 0;
    TURN_MUTEX_UNLOCK(&((*map)->mutex));
    TURN_MUTEX_DESTROY(&((*map)->mutex));
    free(*map);
    *map = NULL;
  }
}

size_t rtcp_map_size(const rtcp_map *map) {
  if (rtcp_map_valid(map)) {
    TURN_MUTEX_LOCK(&map->mutex);
    size_t ret = ur_map_size(map->map);
    TURN_MUTEX_UNLOCK(&map->mutex);
    return ret;
  } else {
    return 0;
  }
}

////////////////////////////////////////////////////////////////
