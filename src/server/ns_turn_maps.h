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

#ifndef __TURN_MAPS__
#define __TURN_MAPS__

#include "ns_turn_ioaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

//////////////// UR MAP //////////////////

struct _ur_map;
typedef struct _ur_map ur_map;

//////////////// Common Definitions //////

typedef u64bits ur_map_key_type;
typedef unsigned long ur_map_value_type;

typedef void (*ur_map_del_func)(ur_map_value_type);

typedef int (*foreachcb_type)(ur_map_key_type key, ur_map_value_type value);
typedef int (*foreachcb_arg_type)(ur_map_key_type key, 
				  ur_map_value_type value, 
				  void *arg);

///////////// non-local map /////////////////////

ur_map* ur_map_create(void);

/**
 * @ret:
 * 0 - success
 * -1 - error
 */

int ur_map_put(ur_map* map, ur_map_key_type key, ur_map_value_type value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int ur_map_get(const ur_map* map, ur_map_key_type key, ur_map_value_type *value);
/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int ur_map_del(ur_map* map, ur_map_key_type key,ur_map_del_func delfunc);
/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int ur_map_exist(const ur_map* map, ur_map_key_type key);

void ur_map_free(ur_map** map);

size_t ur_map_size(const ur_map* map);

int ur_map_foreach(ur_map* map, foreachcb_type func);

int ur_map_foreach_arg(ur_map* map, foreachcb_arg_type func, void* arg);

int ur_map_lock(const ur_map* map);
int ur_map_unlock(const ur_map* map);

///////////// "local" map /////////////////////

#define LM_MAP_HASH_SIZE (8)
#define LM_MAP_ARRAY_SIZE (3)

typedef struct _lm_map_array {
	ur_map_key_type main_keys[LM_MAP_ARRAY_SIZE];
	ur_map_value_type main_values[LM_MAP_ARRAY_SIZE];
	size_t extra_sz;
	ur_map_key_type **extra_keys;
	ur_map_value_type **extra_values;
} lm_map_array;

typedef struct _lm_map {
	lm_map_array table[LM_MAP_HASH_SIZE];
} lm_map;

void lm_map_init(lm_map *map);

/**
 * @ret:
 * 0 - success
 * -1 - error
 */

int lm_map_put(lm_map* map, ur_map_key_type key, ur_map_value_type value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int lm_map_get(const lm_map* map, ur_map_key_type key, ur_map_value_type *value);
/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int lm_map_del(lm_map* map, ur_map_key_type key,ur_map_del_func delfunc);
/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int lm_map_exist(const lm_map* map, ur_map_key_type key);

void lm_map_clean(lm_map* map);

size_t lm_map_size(const lm_map* map);

int lm_map_foreach(lm_map* map, foreachcb_type func);

int lm_map_foreach_arg(lm_map* map, foreachcb_arg_type func, void* arg);

//////////////// UR ADDR MAP //////////////////

typedef unsigned long ur_addr_map_value_type;

#define ADDR_MAP_SIZE (1024)
#define ADDR_ARRAY_SIZE (4)

typedef struct _addr_elem {
  ioa_addr key;
  ur_addr_map_value_type value;
} addr_elem;

typedef struct _addr_list_header {
  addr_elem main_list[ADDR_ARRAY_SIZE];
  addr_elem *extra_list;
  size_t extra_sz;
} addr_list_header;

struct _ur_addr_map {
  addr_list_header lists[ADDR_MAP_SIZE];
  u64bits magic;
};

struct _ur_addr_map;
typedef struct _ur_addr_map ur_addr_map;

typedef void (*ur_addr_map_func)(ur_addr_map_value_type);

void ur_addr_map_init(ur_addr_map* map);
void ur_addr_map_clean(ur_addr_map* map);

/**
 * @ret:
 * 0 - success
 * -1 - error
 * if the addr key exists, the value is updated.
 */
int ur_addr_map_put(ur_addr_map* map, ioa_addr* key, ur_addr_map_value_type value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_addr_map_get(const ur_addr_map* map, ioa_addr* key, ur_addr_map_value_type *value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_addr_map_del(ur_addr_map* map, ioa_addr* key,ur_addr_map_func func);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
void ur_addr_map_foreach(ur_addr_map* map, ur_addr_map_func func);

size_t ur_addr_map_num_elements(const ur_addr_map* map);
size_t ur_addr_map_size(const ur_addr_map* map);

//////////////// UR STRING MAP //////////////////

typedef s08bits* ur_string_map_key_type;
typedef void* ur_string_map_value_type;
struct _ur_string_map;
typedef struct _ur_string_map ur_string_map;

typedef void (*ur_string_map_func)(ur_string_map_value_type);

ur_string_map* ur_string_map_create(ur_string_map_func del_value_func);

/**
 * @ret:
 * 0 - success
 * -1 - error
 * if the string key exists, and the value is different, return error.
 */
int ur_string_map_put(ur_string_map* map, const ur_string_map_key_type key, ur_string_map_value_type value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_string_map_get(ur_string_map* map, const ur_string_map_key_type key, ur_string_map_value_type *value);

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_string_map_del(ur_string_map* map, const ur_string_map_key_type key);

void ur_string_map_clean(ur_string_map* map);
void ur_string_map_free(ur_string_map** map);

size_t ur_string_map_size(const ur_string_map* map);

int ur_string_map_lock(const ur_string_map* map);
int ur_string_map_unlock(const ur_string_map* map);

////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif //__TURN_MAPS__
