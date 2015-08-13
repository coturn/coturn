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

#include "ns_turn_maps.h"

#include "ns_turn_ioalib.h"

#include "ns_turn_khash.h"

KHASH_MAP_INIT_INT64(3, ur_map_value_type)

#define MAGIC_HASH ((u64bits)(0x90ABCDEFL))

struct _ur_map {
  khash_t(3) *h;
  u64bits magic;
  TURN_MUTEX_DECLARE(mutex)
};

static int ur_map_init(ur_map* map) {
  if(map) {
    map->h=kh_init(3);
    if(map->h) {
      map->magic=MAGIC_HASH;
      TURN_MUTEX_INIT_RECURSIVE(&(map->mutex));
      return 0;
    }
  }
  return -1;
}

#define ur_map_valid(map) ((map) && ((map)->h) && ((map)->magic==MAGIC_HASH))

ur_map* ur_map_create() {
  ur_map *map=(ur_map*)turn_malloc(sizeof(ur_map));
  if(ur_map_init(map)<0) {
    turn_free(map,sizeof(ur_map));
    return NULL;
  }
  return map;
}

/**
 * @ret:
 * 0 - success
 * -1 - error
 */
int ur_map_put(ur_map* map, ur_map_key_type key, ur_map_value_type value) {
  if(!ur_map_valid(map)) return -1;
  else {

    int ret=0;
    khiter_t k;

    k = kh_get(3, map->h, key);
    if(k != kh_end(map->h)) {
      kh_del(3, map->h, k);
    }
    
    k = kh_put(3,map->h,key,&ret);

    if (!ret) {
      kh_del(3, map->h, k);
      return -1;
    }

    kh_value(map->h, k) = value;

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_map_get(const ur_map* map, ur_map_key_type key, ur_map_value_type *value) {
  if(!ur_map_valid(map)) return 0;
  else {

    khiter_t k;

    k = kh_get(3, map->h, key);
    if((k != kh_end(map->h)) && kh_exist(map->h,k)) {
      if(value) *value=kh_value(map->h,k);
      return 1;
    }

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_map_del(ur_map* map, ur_map_key_type key,ur_map_del_func delfunc) {
  if(!ur_map_valid(map)) return 0;
  else {

    khiter_t k;

    k = kh_get(3, map->h, key);
    if((k != kh_end(map->h)) && kh_exist(map->h,k)) {
      if(delfunc) {
	delfunc(kh_value(map->h,k));
      }
      kh_del(3,map->h,k);
      return 1;
    }

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_map_exist(const ur_map* map, ur_map_key_type key) {
  if(!ur_map_valid(map)) return 0;
  else {

    khiter_t k;

    k = kh_get(3, map->h, key);
    if((k != kh_end(map->h)) && kh_exist(map->h,k)) {
      return 1;
    }

    return 0;
  }
}

void ur_map_free(ur_map** map) {
  if(map && ur_map_valid(*map)) {
	  {
		  static int khctest=0;
		  if(khctest)
			  kh_clear(3,(*map)->h);
	  }
    kh_destroy(3,(*map)->h);
    (*map)->h=NULL;
    (*map)->magic=0;
    TURN_MUTEX_DESTROY(&((*map)->mutex));
    turn_free(*map,sizeof(ur_map));
    *map=NULL;
  }
}

size_t ur_map_size(const ur_map* map) {
  if(ur_map_valid(map)) {
    return kh_size(map->h);
  } else {
    return 0;
  }
}

int ur_map_foreach(ur_map* map, foreachcb_type func) {
  if(map && func && ur_map_valid(map)) {
    khiter_t k;
    for (k = kh_begin((*map)->h); k != kh_end(map->h); ++k) {
      if (kh_exist(map->h, k)) {
	if(func((ur_map_key_type)(kh_key(map->h, k)),
		(ur_map_value_type)(kh_value(map->h, k)))) {
	  return 1;
	}
      }
    }
  }
  return 0;
}

int ur_map_foreach_arg(ur_map* map, foreachcb_arg_type func, void* arg) {
  if(map && func && ur_map_valid(map)) {
    khiter_t k;
    for (k = kh_begin((*map)->h); k != kh_end(map->h); ++k) {
      if (kh_exist(map->h, k)) {
	if(func((ur_map_key_type)(kh_key(map->h, k)),
		(ur_map_value_type)(kh_value(map->h, k)),
		arg)
	   ) {
	  return 1;
	}
      }
    }
  }
  return 0;
}

int ur_map_lock(const ur_map* map) {
  if(ur_map_valid(map)) {
    TURN_MUTEX_LOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

int ur_map_unlock(const ur_map* map) {
  if(ur_map_valid(map)) {
    TURN_MUTEX_UNLOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

//////////////////// LOCAL MAPS ////////////////////////////////////

void lm_map_init(lm_map *map)
{
	if(map) {
		ns_bzero(map,sizeof(lm_map));
	}
}

/**
 * @ret:
 * 0 - success
 * -1 - error
 */

int lm_map_put(lm_map* map, ur_map_key_type key, ur_map_value_type value)
{
	int ret = -1;
	if(map && key && value) {

		size_t index = (size_t)(key & (LM_MAP_HASH_SIZE - 1));
		lm_map_array *a = &(map->table[index]);

		size_t i;

		for(i=0;i<LM_MAP_ARRAY_SIZE;++i) {

			ur_map_key_type key0 = a->main_keys[i];
			ur_map_value_type value0 = a->main_values[i];

			if(key0 == key) {
				if(value0 == value) {
					return 0;
				} else {
					return -1;
				}
			}

			if(!key0 || !value0) {
				a->main_keys[i] = key;
				a->main_values[i] = value;
				return 0;
			}
		}

		size_t esz = a->extra_sz;
		if(esz && a->extra_keys && a->extra_values) {
			for(i=0;i<esz;++i) {
				ur_map_key_type *keyp = a->extra_keys[i];
				ur_map_value_type *valuep = a->extra_values[i];
				if(keyp && valuep) {
					if(!(*keyp) || !(*valuep)) {
						*keyp = key;
						*valuep = value;
						return 0;
					}
				} else {
					if(!(*keyp)) {
						a->extra_keys[i] = (ur_map_key_type*)turn_malloc(sizeof(ur_map_key_type));
						keyp = a->extra_keys[i];
					}
					if(!(*valuep)) {
						a->extra_values[i] = (ur_map_value_type*)turn_malloc(sizeof(ur_map_value_type));
						valuep = a->extra_values[i];
					}
					*keyp = key;
					*valuep = value;
					return 0;
				}
			}
		}

		size_t old_sz = esz;
		size_t old_sz_mem = esz * sizeof(ur_map_key_type*);
		a->extra_keys = (ur_map_key_type**)turn_realloc(a->extra_keys,old_sz_mem,old_sz_mem + sizeof(ur_map_key_type*));
		a->extra_keys[old_sz] = (ur_map_key_type*)turn_malloc(sizeof(ur_map_key_type));
		*(a->extra_keys[old_sz]) = key;

		old_sz_mem = esz * sizeof(ur_map_value_type*);
		a->extra_values = (ur_map_value_type**)turn_realloc(a->extra_values,old_sz_mem,old_sz_mem + sizeof(ur_map_value_type*));
		a->extra_values[old_sz] = (ur_map_value_type*)turn_malloc(sizeof(ur_map_value_type));
		*(a->extra_values[old_sz]) = value;

		a->extra_sz += 1;

		return 0;
	}
	return ret;
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int lm_map_get(const lm_map* map, ur_map_key_type key, ur_map_value_type *value)
{
	int ret = 0;
	if(map && key) {
		size_t index = (size_t)(key & (LM_MAP_HASH_SIZE - 1));
		const lm_map_array *a = &(map->table[index]);

		size_t i;

		for(i=0;i<LM_MAP_ARRAY_SIZE;++i) {

			ur_map_key_type key0 = a->main_keys[i];
			if((key0 == key) && a->main_values[i]) {
				if(value) {
					*value = a->main_values[i];
				}
				return 1;
			}
		}

		size_t esz = a->extra_sz;
		if(esz && a->extra_keys && a->extra_values) {
			for(i=0;i<esz;++i) {
				ur_map_key_type *keyp = a->extra_keys[i];
				ur_map_value_type *valuep = a->extra_values[i];
				if(keyp && valuep) {
					if(*keyp == key) {
						if(value)
							*value = *valuep;
						return 1;
					}
				}
			}
		}
	}

	return ret;
}
/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int lm_map_del(lm_map* map, ur_map_key_type key,ur_map_del_func delfunc)
{
	int ret = 0;

	if(map && key) {
		size_t index = (size_t)(key & (LM_MAP_HASH_SIZE - 1));
		lm_map_array *a = &(map->table[index]);

		size_t i;

		for(i=0;i<LM_MAP_ARRAY_SIZE;++i) {

			ur_map_key_type key0 = a->main_keys[i];

			if((key0 == key) && a->main_values[i]) {
				if(delfunc) {
					delfunc(a->main_values[i]);
				}
				a->main_keys[i] = 0;
				a->main_values[i] = 0;
				return 1;
			}
		}

		size_t esz = a->extra_sz;
		if(esz && a->extra_keys && a->extra_values) {
			for(i=0;i<esz;++i) {
				ur_map_key_type *keyp = a->extra_keys[i];
				ur_map_value_type *valuep = a->extra_values[i];
				if(keyp && valuep) {
					if(*keyp == key) {
						if(delfunc)
							delfunc(*valuep);
						*keyp = 0;
						*valuep = 0;
						return 1;
					}
				}
			}
		}
	}

	return ret;
}
/**
 * @ret:
 * 1 - success
 * 0 - not found
 */

int lm_map_exist(const lm_map* map, ur_map_key_type key)
{
	return lm_map_get(map, key, NULL);
}

void lm_map_clean(lm_map* map)
{
	size_t j;
	for(j=0;j<LM_MAP_HASH_SIZE;++j) {

		lm_map_array *a = &(map->table[j]);

		size_t esz = a->extra_sz;
		if(esz) {
			size_t i;
			if(a->extra_keys) {
				for(i=0;i<esz;++i) {
					ur_map_key_type *keyp = a->extra_keys[i];
					if(keyp) {
						*keyp = 0;
						turn_free(keyp,sizeof(ur_map_key_type));
					}
				}
				turn_free(a->extra_keys,esz * sizeof(ur_map_key_type));
				a->extra_keys = NULL;
			}
			if(a->extra_values) {
				for(i=0;i<esz;++i) {
					ur_map_value_type *valuep = a->extra_values[i];
					if(valuep) {
						*valuep = 0;
						turn_free(valuep,sizeof(ur_map_value_type));
					}
				}
				turn_free(a->extra_values,esz * sizeof(ur_map_value_type));
				a->extra_values = NULL;
			}
		}
	}

	lm_map_init(map);
}

size_t lm_map_size(const lm_map* map)
{
	size_t ret = 0;

	if(map) {

		size_t i;

		for(i=0;i<LM_MAP_HASH_SIZE;++i) {

			const lm_map_array *a = &(map->table[i]);

			size_t j;

			for(j=0;j<LM_MAP_ARRAY_SIZE;++j) {
				if(a->main_keys[j] && a->main_values[j]) {
					++ret;
				}
			}

			size_t esz = a->extra_sz;
			if(esz && a->extra_values && a->extra_keys) {
				for(j=0;j<esz;++j) {
					if(*(a->extra_keys[j]) && *(a->extra_values[j])) {
						++ret;
					}
				}
			}
		}
	}

	return ret;
}

int lm_map_foreach(lm_map* map, foreachcb_type func)
{
	size_t ret = 0;

	if(map) {

		size_t i;

		for(i=0;i<LM_MAP_HASH_SIZE;++i) {

			lm_map_array *a = &(map->table[i]);

			size_t j;

			for(j=0;j<LM_MAP_ARRAY_SIZE;++j) {
				if(a->main_keys[j] && a->main_values[j]) {
					if(func((ur_map_key_type)a->main_keys[j],
						(ur_map_value_type)a->main_values[j])) {
						return 1;
					}
				}
			}

			size_t esz = a->extra_sz;
			if(esz && a->extra_values && a->extra_keys) {
				for(j=0;j<esz;++j) {
					if(*(a->extra_keys[j]) && *(a->extra_values[j])) {
						if(func((ur_map_key_type)*(a->extra_keys[j]),
							(ur_map_value_type)*(a->extra_values[j]))) {
							return 1;
						}
					}
				}
			}
		}
	}

	return ret;
}

int lm_map_foreach_arg(lm_map* map, foreachcb_arg_type func, void* arg)
{
	size_t ret = 0;

	if(map) {

		size_t i;

		for(i=0;i<LM_MAP_HASH_SIZE;++i) {

			lm_map_array *a = &(map->table[i]);

			size_t j;

			for(j=0;j<LM_MAP_ARRAY_SIZE;++j) {
				if(a->main_keys[j] && a->main_values[j]) {
					if(func((ur_map_key_type)a->main_keys[j],
						(ur_map_value_type)a->main_values[j],
						arg)) {
						return 1;
					}
				}
			}

			size_t esz = a->extra_sz;
			if(esz && a->extra_values && a->extra_keys) {
				for(j=0;j<esz;++j) {
					if(*(a->extra_keys[j]) && *(a->extra_values[j])) {
						if(func((ur_map_key_type)*(a->extra_keys[j]),
							(ur_map_value_type)*(a->extra_values[j]),
							arg)) {
							return 1;
						}
					}
				}
			}
		}
	}

	return ret;
}

////////////////////  ADDR LISTS ///////////////////////////////////

static void addr_list_free(addr_list_header* slh) {
  if(slh) {
    if(slh->extra_list) {
      turn_free(slh->extra_list,sizeof(addr_elem)*(slh->extra_sz));
    }
    ns_bzero(slh,sizeof(addr_list_header));
  }
}
    
static void addr_list_add(addr_list_header* slh, const ioa_addr* key,  ur_addr_map_value_type value) {

  if(!key || !value) return;

  addr_elem *elem = NULL;
  size_t i;

  for(i=0;i<ADDR_ARRAY_SIZE;++i) {
	  if(!(slh->main_list[i].value)) {
		  elem = &(slh->main_list[i]);
		  break;
	  }
  }

  if(!elem && slh->extra_list) {
	  for(i=0;i<slh->extra_sz;++i) {
		  if(!(slh->extra_list[i].value)) {
			  elem = &(slh->extra_list[i]);
			  break;
		  }
	  }
  }

  if(!elem) {
	  size_t old_sz = slh->extra_sz;
	  size_t old_sz_mem = old_sz * sizeof(addr_elem);
	  slh->extra_list = (addr_elem*)turn_realloc(slh->extra_list, old_sz_mem, old_sz_mem + sizeof(addr_elem));
	  elem = &(slh->extra_list[old_sz]);
	  slh->extra_sz += 1;
  }

  addr_cpy(&(elem->key),key);
  elem->value=value;
}

static void addr_list_remove(addr_list_header* slh, const ioa_addr* key,
				   ur_addr_map_func delfunc, int *counter) {
  if(!slh || !key) return;

  if(counter)
	  *counter = 0;

  size_t i;

  for(i=0;i<ADDR_ARRAY_SIZE;++i) {
	addr_elem *elem=&(slh->main_list[i]);
	if(elem->value) {
		if(addr_eq(&(elem->key),key)) {
			if(delfunc && elem->value)
				delfunc(elem->value);
			elem->value = 0;
			if(counter) {
			  *counter += 1;
			}
		}
	}
  }

  if(slh->extra_list) {
  	  for(i=0;i<slh->extra_sz;++i) {
  		  addr_elem *elem=&(slh->extra_list[i]);
  		  if(elem->value) {
  			  if(addr_eq(&(elem->key),key)) {
  				  if(delfunc && elem->value)
  					  delfunc(elem->value);
  				  elem->value = 0;
  				  if(counter) {
  					  *counter += 1;
  				  }
  			  }
  		  }
  	  }
  }
}

static void addr_list_foreach(addr_list_header* slh,  ur_addr_map_func func) {
  if(slh && func) {

    	  size_t i;

    	  for(i=0;i<ADDR_ARRAY_SIZE;++i) {
    		  addr_elem *elem=&(slh->main_list[i]);
    		  if(elem->value) {
    			  func(elem->value);
    		  }
    	  }

	  if(slh->extra_list) {
	    	  for(i=0;i<slh->extra_sz;++i) {
	    		  addr_elem *elem=&(slh->extra_list[i]);
	    		  if(elem->value) {
	    			func(elem->value);
	    		  }
	    	  }
	    }
  }
}

static size_t addr_list_num_elements(const addr_list_header* slh) {

	size_t ret = 0;

	if (slh) {

		size_t i;

		for (i = 0; i < ADDR_ARRAY_SIZE; ++i) {
			const addr_elem *elem = &(slh->main_list[i]);
			if (elem->value) {
				++ret;
			}
		}

		if (slh->extra_list) {
			for (i = 0; i < slh->extra_sz; ++i) {
				addr_elem *elem = &(slh->extra_list[i]);
				if (elem->value) {
					++ret;
				}
			}
		}
	}

	return ret;
}

static size_t addr_list_size(const addr_list_header* slh) {

	size_t ret = 0;

	if (slh) {

		ret += ADDR_ARRAY_SIZE;

		ret += slh->extra_sz;
	}

	return ret;
}

static addr_elem* addr_list_get(addr_list_header* slh, const ioa_addr* key) {

  if(!slh || !key) return NULL;

  size_t i;

  for(i=0;i<ADDR_ARRAY_SIZE;++i) {
	  addr_elem *elem=&(slh->main_list[i]);
	  if(elem->value) {
		  if(addr_eq(&(elem->key),key)) {
			  return elem;
		  }
	  }
  }

  if(slh->extra_list) {
    	  for(i=0;i<slh->extra_sz;++i) {
    		  addr_elem *elem=&(slh->extra_list[i]);
    		  if(elem->value) {
    			  if(addr_eq(&(elem->key),key)) {
    				  return elem;
    			  }
    		  }
    	  }
  }

  return NULL;
}

static const addr_elem* addr_list_get_const(const addr_list_header* slh, const ioa_addr* key) {

  if(!slh || !key) return NULL;

  size_t i;

  for(i=0;i<ADDR_ARRAY_SIZE;++i) {
	  const addr_elem *elem=&(slh->main_list[i]);
	  if(elem->value) {
		  if(addr_eq(&(elem->key),key)) {
			  return elem;
		  }
	  }
  }

  if(slh->extra_list) {
    	  for(i=0;i<slh->extra_sz;++i) {
    		  const addr_elem *elem=&(slh->extra_list[i]);
    		  if(elem->value) {
    			  if(addr_eq(&(elem->key),key)) {
    				  return elem;
    			  }
    		  }
    	  }
  }

  return NULL;
}

////////// ADDR MAPS ////////////////////////////////////////////

#define addr_map_index(key) (addr_hash((key)) & (ADDR_MAP_SIZE - 1))

#define get_addr_list_header(map, key) (&((map)->lists[addr_map_index((key))]))

#define ur_addr_map_valid(map) ((map) && ((map)->magic==MAGIC_HASH))

void ur_addr_map_init(ur_addr_map* map) {
  if(map) {
    ns_bzero(map,sizeof(ur_addr_map));
    map->magic=MAGIC_HASH;
  }
}

void ur_addr_map_clean(ur_addr_map* map) {
  if(map && ur_addr_map_valid(map)) {
    u32bits i=0;
    for(i=0;i<ADDR_MAP_SIZE;i++) {
      addr_list_free(&(map->lists[i]));
    }
    ns_bzero(map,sizeof(ur_addr_map));
  }
}

/**
 * @ret:
 * 0 - success
 * -1 - error
 * if the addr key exists, the value is updated.
 */
int ur_addr_map_put(ur_addr_map* map, ioa_addr* key, ur_addr_map_value_type value) {

  if(!ur_addr_map_valid(map)) return -1;

  else {

    addr_list_header* slh = get_addr_list_header(map, key);

    addr_elem* elem = addr_list_get(slh, key);
    if(elem) {
      elem->value=value;
    } else {
      addr_list_add(slh,key,value);
    }

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_addr_map_get(const ur_addr_map* map, ioa_addr* key, ur_addr_map_value_type *value) {

  if(!ur_addr_map_valid(map)) return 0;

  else {

    const addr_list_header* slh = get_addr_list_header(map, key);

    const addr_elem *elem = addr_list_get_const(slh, key);
    if(elem) {
      if(value) *value=elem->value;
      return 1;
    }

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_addr_map_del(ur_addr_map* map, ioa_addr* key,ur_addr_map_func delfunc) {

  if(!ur_addr_map_valid(map)) return 0;

  else {

    addr_list_header* slh = get_addr_list_header(map, key);

    int counter=0;

    addr_list_remove(slh, key, delfunc, &counter);

    return (counter>0);
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
void ur_addr_map_foreach(ur_addr_map* map, ur_addr_map_func func) {

  if(ur_addr_map_valid(map)) {

    u32bits i=0;
    for(i=0;i<ADDR_MAP_SIZE;i++) {
      
      addr_list_header* slh = &(map->lists[i]);
      
      addr_list_foreach(slh, func);
    }
  }
}

size_t ur_addr_map_num_elements(const ur_addr_map* map) {

	size_t ret = 0;

	if (ur_addr_map_valid(map)) {
		u32bits i = 0;
		for (i = 0; i < ADDR_MAP_SIZE; i++) {

			const addr_list_header* slh = &(map->lists[i]);

			ret += addr_list_num_elements(slh);
		}
	}

	return ret;
}

size_t ur_addr_map_size(const ur_addr_map* map) {

	size_t ret = 0;

	if (ur_addr_map_valid(map)) {
		u32bits i = 0;
		for (i = 0; i < ADDR_MAP_SIZE; i++) {

			const addr_list_header* slh = &(map->lists[i]);

			ret += addr_list_size(slh);
		}
	}

	return ret;
}

////////////////////  STRING LISTS ///////////////////////////////////

typedef struct _string_list {
  struct _string_list* next;
} string_list;

typedef struct _string_elem {
  string_list list;
  ur_string_map_key_type key;
  u32bits key_size;
  ur_string_map_value_type value;
} string_elem;

typedef struct _string_list_header {
  string_list *list;
} string_list_header;

static size_t string_list_size(const string_list *sl) {
  if(!sl) return 0;
  return 1+string_list_size(sl->next);
}

static void string_list_free(string_list_header* slh, ur_string_map_func del_value_func) {
  if(slh) {
    string_list* list=slh->list;
    while(list) {
      string_elem *elem=(string_elem*)list;
      string_list* tail=elem->list.next;
      if(elem->key) turn_free(elem->key,elem->key_size);
      if(del_value_func && elem->value)
	      del_value_func(elem->value);
      turn_free(elem,sizeof(string_elem));
      list=tail;
    }
    slh->list=NULL;
  }
}

static string_list* string_list_add(string_list* sl, const ur_string_map_key_type key, ur_string_map_value_type value) {
  if(!key) return sl;
  string_elem *elem=(string_elem*)turn_malloc(sizeof(string_elem));
  elem->list.next=sl;
  elem->key_size = strlen(key)+1;
  elem->key=(s08bits*)turn_malloc(elem->key_size);
  ns_bcopy(key,elem->key,elem->key_size);
  elem->value=value;
  return &(elem->list);
}

static string_list* string_list_remove(string_list* sl, const ur_string_map_key_type key,
					ur_string_map_func del_value_func, int *counter) {
  if(!sl || !key) return sl;
  string_elem *elem=(string_elem*)sl;
  string_list* tail=elem->list.next;
  if(strcmp(elem->key,key)==0) {
    turn_free(elem->key,elem->key_size);
    if(del_value_func)
	    del_value_func(elem->value);
    turn_free(elem,sizeof(string_elem));
    if(counter) *counter+=1;
    sl=string_list_remove(tail, key, del_value_func, counter);
  } else {
    elem->list.next=string_list_remove(tail,key,del_value_func,counter);
  }
  return sl;
}

static string_elem* string_list_get(string_list* sl, const ur_string_map_key_type key) {

  if(!sl || !key) return NULL;

  string_elem *elem=(string_elem*)sl;
  if(strcmp(elem->key,key)==0) {
    return elem;
  } else {
    return string_list_get(elem->list.next, key);
  }
}

////////// STRING MAPS ////////////////////////////////////////////

#define STRING_MAP_SIZE (1024)

struct _ur_string_map {
  string_list_header lists[STRING_MAP_SIZE];
  u64bits magic;
  ur_string_map_func del_value_func;
  TURN_MUTEX_DECLARE(mutex)
};

static u32bits string_hash(const ur_string_map_key_type key) {

  u08bits *str=(u08bits*)key;

  u32bits hash = 0;
  int c = 0;

  while ((c = *str++))
    hash = c + (hash << 6) + (hash << 16) - hash;

  return hash;
}

static int string_map_index(const ur_string_map_key_type key) {
  return (int)(string_hash(key) % STRING_MAP_SIZE);
}

static string_list_header* get_string_list_header(ur_string_map *map, const ur_string_map_key_type key) {
  return &(map->lists[string_map_index(key)]);
}

static int ur_string_map_init(ur_string_map* map) {
  if(map) {
    ns_bzero(map,sizeof(ur_string_map));
    map->magic=MAGIC_HASH;

    TURN_MUTEX_INIT_RECURSIVE(&(map->mutex));

    return 0;
  }
  return -1;
}

static int ur_string_map_valid(const ur_string_map *map) {
  return (map && map->magic==MAGIC_HASH);
}

ur_string_map* ur_string_map_create(ur_string_map_func del_value_func) {
  ur_string_map *map=(ur_string_map*)turn_malloc(sizeof(ur_string_map));
  if(ur_string_map_init(map)<0) {
    turn_free(map,sizeof(ur_string_map));
    return NULL;
  }
  map->del_value_func = del_value_func;
  return map;
}

/**
 * @ret:
 * 0 - success
 * -1 - error
 * if the string key exists, and the value is different, return error.
 */
int ur_string_map_put(ur_string_map* map, const ur_string_map_key_type key, ur_string_map_value_type value) {

  if(!ur_string_map_valid(map)) return -1;

  else {

    string_list_header* slh = get_string_list_header(map, key);

    string_elem *elem = string_list_get(slh->list, key);
    if(elem) {
      if(elem->value != value) {
	      if(map->del_value_func)
		      map->del_value_func(elem->value);
	      elem->value = value;
      }
      return 0;
    }

    slh->list=string_list_add(slh->list,key,value);

    return 0;
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_string_map_get(ur_string_map* map, const ur_string_map_key_type key, ur_string_map_value_type *value) {

  if(!ur_string_map_valid(map)) return 0;

  else {

    string_list_header* slh = get_string_list_header(map, key);
    string_elem *elem = string_list_get(slh->list, key);
    if(elem) {
      if(value) *value=elem->value;
      return 1;
    } else {
      return 0;
    }
  }
}

/**
 * @ret:
 * 1 - success
 * 0 - not found
 */
int ur_string_map_del(ur_string_map* map, const ur_string_map_key_type key) {

  if(!ur_string_map_valid(map)) return 0;

  else {

    string_list_header* slh = get_string_list_header(map, key);

    int counter=0;

    slh->list=string_list_remove(slh->list, key, map->del_value_func, &counter);

    return (counter>0);
  }
}

void ur_string_map_clean(ur_string_map* map) {
	if (ur_string_map_valid(map)) {
		int i = 0;
		for (i = 0; i < STRING_MAP_SIZE; i++) {
			string_list_free(&(map->lists[i]), map->del_value_func);
		}
	}
}

void ur_string_map_free(ur_string_map** map) {
  if(map && ur_string_map_valid(*map)) {
    int i=0;
    for(i=0;i<STRING_MAP_SIZE;i++) {
      string_list_free(&((*map)->lists[i]),(*map)->del_value_func);
    }
    (*map)->magic=0;
    TURN_MUTEX_DESTROY(&((*map)->mutex));
    turn_free(*map,sizeof(ur_string_map));
    *map=NULL;
  }
}

size_t ur_string_map_size(const ur_string_map* map) {
  if(ur_string_map_valid(map)) {
    size_t ret=0;
    int i=0;
    for(i=0;i<STRING_MAP_SIZE;i++) {
      ret+=string_list_size(map->lists[i].list);
    }
    return ret;
  } else {
    return 0;
  }
}

int ur_string_map_lock(const ur_string_map* map) {
  if(ur_string_map_valid(map)) {
    TURN_MUTEX_LOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

int ur_string_map_unlock(const ur_string_map* map) {
  if(ur_string_map_valid(map)) {
    TURN_MUTEX_UNLOCK((const turn_mutex*)&(map->mutex));
    return 0;
  }
  return -1;
}

////////////////////////////////////////////////////////////////
