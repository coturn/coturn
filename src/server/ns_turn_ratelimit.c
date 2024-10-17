/*
 * Copyright (C) 2024 Wire Swiss GmbH
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
#include "ns_turn_ratelimit.h"

/////////////////// rate limit //////////////////////////

ur_addr_map *rate_limit_map = NULL;
int ratelimit_window_secs = RATELIMIT_DEFAULT_WINDOW_SECS;
TURN_MUTEX_DECLARE(rate_limit_main_mutex);

void ratelimit_add_node(ioa_addr *address) {
  // copy address
  ratelimit_entry *rateLimitEntry = (ratelimit_entry *)malloc(sizeof(ratelimit_entry));
  TURN_MUTEX_INIT(&(rateLimitEntry->mutex));
  rateLimitEntry->request_count = 1;
  rateLimitEntry->last_request_time = time(NULL);

  ur_addr_map_put_no_port(rate_limit_map, address, (ur_addr_map_value_type)rateLimitEntry);
}

int ratelimit_delete_expired(ur_map_value_type value) {
  time_t current_time = time(NULL);
  ratelimit_entry *rateLimitEntry = (ratelimit_entry*)(void*)(ur_map_value_type)value;
  if (rateLimitEntry->last_request_time + RATELIMIT_DEFAULT_WINDOW_SECS < current_time)
    return 1;
  return 0;
}

void ratelimit_init_map() {
  TURN_MUTEX_INIT(&rate_limit_main_mutex);
  TURN_MUTEX_LOCK(&rate_limit_main_mutex);

  rate_limit_map = (ur_addr_map*)malloc(sizeof(ur_addr_map));
  ur_addr_map_init(rate_limit_map);
  TURN_MUTEX_UNLOCK(&rate_limit_main_mutex);
}

int ratelimit_is_address_limited(ioa_addr *address, int max_requests, int window_seconds) {
  /* Housekeeping, prune the map when ADDR_MAP_SIZE is hit and delete expired items */
  time_t current_time = time(NULL);

  if (rate_limit_map == NULL) {
    ratelimit_init_map();
  }

  if (ur_addr_map_num_elements(rate_limit_map) >= ADDR_MAP_SIZE) {
    TURN_MUTEX_LOCK(&rate_limit_main_mutex);
    /* Set ratelimit_window_secs to grant access to our delete function */
    ratelimit_window_secs = window_seconds;

    addr_list_foreach_del_condition(rate_limit_map, ratelimit_delete_expired);
    TURN_MUTEX_UNLOCK(&rate_limit_main_mutex);
  }

  ur_addr_map_value_type ratelimit_ptr = 0;
  int returnValue = 0;

  if (ur_addr_map_get_no_port(rate_limit_map, address, &ratelimit_ptr)) {
    ratelimit_entry *rateLimitEntry = (ratelimit_entry *)(void *)(ur_map_value_type)ratelimit_ptr;
    TURN_MUTEX_LOCK(&(rateLimitEntry->mutex));

    if (current_time - rateLimitEntry->last_request_time > window_seconds) {
      /* Check if request is inside the ratelimit window; reset the count and request time */
      rateLimitEntry->request_count = 1;
      rateLimitEntry->last_request_time = current_time;
      returnValue = 0;
    } else if (rateLimitEntry->request_count < max_requests) {
      /* Check if request count is below requests per window; increment the count */
      if (rateLimitEntry->request_count < UINT32_MAX)
        rateLimitEntry->request_count++;
      rateLimitEntry->last_request_time = current_time;
      returnValue = 0;
    } else {
      /* Request is outside of defined window and count, request is ratelimited */
      if (rateLimitEntry->request_count < UINT32_MAX)
        rateLimitEntry->request_count++;
      rateLimitEntry->last_request_time = current_time;
      returnValue = 1;
    }
    TURN_MUTEX_UNLOCK(&(rateLimitEntry->mutex));
  } else {
    // New entry, allow response
    TURN_MUTEX_LOCK(&rate_limit_main_mutex);
    ratelimit_add_node(address);
    TURN_MUTEX_UNLOCK(&rate_limit_main_mutex);
    returnValue = 0;
  }
  return returnValue;
}
