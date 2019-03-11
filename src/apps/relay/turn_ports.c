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
#include "ns_turn_msg_defs.h"

#include "ns_turn_ioalib.h"
#include "ns_ioalib_impl.h"

#include "turn_ports.h"

////////// DATA ////////////////////////////////////////////

#define PORTS_SIZE (0xFFFF+1)
#define TPS_OUT_OF_RANGE ((uint32_t)(-1))
#define TPS_TAKEN_SINGLE ((uint32_t)(-2))
#define TPS_TAKEN_EVEN ((uint32_t)(-3))
#define TPS_TAKEN_ODD ((uint32_t)(-4))

struct _turnports {
  uint32_t status[PORTS_SIZE];
  uint32_t low;
  uint32_t high;
  uint16_t range_start;
  uint16_t range_stop;
  uint16_t ports[PORTS_SIZE];
  TURN_MUTEX_DECLARE(mutex)
};
typedef struct _turnports turnports;

/////////////// TURNPORTS statics //////////////////////////

static turnports* turnports_create(super_memory_t *sm, uint16_t start, uint16_t end);
static uint16_t turnports_size(turnports* tp);

static int turnports_allocate(turnports* tp);
static int turnports_allocate_even(turnports* tp, int allocate_rtcp, uint64_t *reservation_token);

static void turnports_release(turnports* tp, uint16_t port);

static int turnports_is_allocated(turnports* tp, uint16_t port);
static int turnports_is_available(turnports* tp, uint16_t port);

/////////////// UTILS //////////////////////////////////////

static int is_taken(uint32_t status) {
	int ret = -1;
	switch (status) {
	case TPS_TAKEN_SINGLE :
	case TPS_TAKEN_EVEN :
	case TPS_TAKEN_ODD :
		ret = 1;
		break;
	default:
		ret = 0;
	};
	return ret;
}

static void turnports_randomize(turnports* tp) {
  if(tp) {
    unsigned int size=(unsigned int)(tp->high-tp->low);
    unsigned int i=0;
    unsigned int cycles=size*10;
    for(i=0;i<cycles;i++) {
      uint16_t port1 = (uint16_t)(tp->low + (uint16_t)(((unsigned long)random())%((unsigned long)size)));
      uint16_t port2 = (uint16_t)(tp->low + (uint16_t)(((unsigned long)random())%((unsigned long)size)));
      if(port1!=port2) {
    	  int pos1=tp->status[port1];
    	  int pos2=tp->status[port2];
    	  int tmp=(int)tp->status[port1];
    	  tp->status[port1]=tp->status[port2];
    	  tp->status[port2]=(uint32_t)tmp;
    	  tmp=(int)tp->ports[pos1];
    	  tp->ports[pos1]=tp->ports[pos2];
    	  tp->ports[pos2]=(uint16_t)tmp;
      }
    }
  }
}   

static void turnports_init(turnports* tp, uint16_t start, uint16_t end) {

  tp->low=start;
  tp->high=((uint32_t)end)+1;

  tp->range_start=start;
  tp->range_stop=end;
  
  int i=0;
  for(i=0;i<start;i++) {
    tp->status[i]=TPS_OUT_OF_RANGE;
    tp->ports[i]=(uint16_t)i;
  }
  for(i=start;i<=end;i++) {
    tp->status[i]=(uint32_t)i;
    tp->ports[i]=(uint16_t)i;
  }
  for(i=((int)end)+1;i<PORTS_SIZE;i++) {
    tp->status[i]=TPS_OUT_OF_RANGE;
    tp->ports[i]=(uint16_t)i;
  }

  turnports_randomize(tp);

  TURN_MUTEX_INIT_RECURSIVE(&(tp->mutex));
}

/////////////// FUNC ///////////////////////////////////////

turnports* turnports_create(super_memory_t *sm, uint16_t start, uint16_t end) {

  if(start>end) return NULL;

  turnports* ret=(turnports*)allocate_super_memory_region(sm, sizeof(turnports));
  turnports_init(ret,start,end);

  return ret;
}

uint16_t turnports_size(turnports* tp) {
  if(!tp) return 0;
  else {
    TURN_MUTEX_LOCK(&tp->mutex);
    uint16_t ret = (uint16_t)((tp->high-tp->low));
    TURN_MUTEX_UNLOCK(&tp->mutex);
    return ret;
  }
}

int turnports_allocate(turnports* tp) {

  int port=-1;

  TURN_MUTEX_LOCK(&tp->mutex);

  if(tp) {

    while(1) {
      
      if(tp->high <= tp->low) {
    	  TURN_MUTEX_UNLOCK(&tp->mutex);
    	  return -1;
      }
      
      int position=(uint16_t)(tp->low & 0x0000FFFF);
      
      port=(int)tp->ports[position];
      if(port<(int)(tp->range_start) || port>((int)(tp->range_stop))) {
    	  TURN_MUTEX_UNLOCK(&tp->mutex);
    	  return -1;
      }
      if(is_taken(tp->status[port])) {
    	  ++(tp->low);
    	  continue;
      } 
      if(tp->status[port]!=tp->low) {
    	  ++(tp->low);
    	  continue;
      }
      tp->status[port]=TPS_TAKEN_SINGLE;
      ++(tp->low);
      break;
    }
  }

  TURN_MUTEX_UNLOCK(&tp->mutex);

  return port;
}

void turnports_release(turnports* tp, uint16_t port) {
  TURN_MUTEX_LOCK(&tp->mutex);
  if(tp && port>=tp->range_start && port<=tp->range_stop) {
    uint16_t position=(uint16_t)(tp->high & 0x0000FFFF);
    if(is_taken(tp->status[port])) {
      tp->status[port]=tp->high;
      tp->ports[position]=port;
      ++(tp->high);
    }
  }
  TURN_MUTEX_UNLOCK(&tp->mutex);
}

int turnports_allocate_even(turnports* tp, int allocate_rtcp, uint64_t *reservation_token) {
  if(tp) {
    TURN_MUTEX_LOCK(&tp->mutex);
    uint16_t size = turnports_size(tp);
    if(size>1) {
      uint16_t i=0;
      for(i=0;i<size;i++) {
    	  int port=turnports_allocate(tp);
    	  if(port & 0x00000001) {
    		  turnports_release(tp,port);
    	  } else {
    		  if(!allocate_rtcp) {
    			  TURN_MUTEX_UNLOCK(&tp->mutex);
    			  return port;
    		  } else {
    			  int rtcp_port=port+1;
    			  if(rtcp_port>tp->range_stop) {
    				  turnports_release(tp,port);
    			  } else if(!turnports_is_available(tp,rtcp_port)) {
    				  turnports_release(tp,port);
    			  } else {
    				  tp->status[port]=TPS_TAKEN_EVEN;
    				  tp->status[rtcp_port]=TPS_TAKEN_ODD;
    				  if(reservation_token) {
    					  uint16_t *v16=(uint16_t*)reservation_token;
    					  uint32_t *v32=(uint32_t*)reservation_token;
    					  v16[0]=(uint16_t)(tp->ports[(uint16_t)(tp->low & 0x0000FFFF)]);
    					  v16[1]=(uint16_t)(tp->ports[(uint16_t)(tp->high & 0x0000FFFF)]);
    					  v32[1]=(uint32_t)turn_random();
    				  }
    				  TURN_MUTEX_UNLOCK(&tp->mutex);
    				  return port;
    			  }
    		  }
    	  }
      }
    }
    TURN_MUTEX_UNLOCK(&tp->mutex);
  }
  return -1;
}

int turnports_is_allocated(turnports* tp, uint16_t port) {
  if(!tp) return 0;
  else {
    TURN_MUTEX_LOCK(&tp->mutex);
    int ret = is_taken(tp->status[port]);
    TURN_MUTEX_UNLOCK(&tp->mutex);
    return ret;
  }
}

int turnports_is_available(turnports* tp, uint16_t port) {
  if(tp) {
    TURN_MUTEX_LOCK(&tp->mutex);
    uint32_t status = tp->status[port];
    if((status!=TPS_OUT_OF_RANGE) && !is_taken(status)) {
      uint16_t position=(uint16_t)(status & 0x0000FFFF);
      if(tp->ports[position]==port) {
    	  TURN_MUTEX_UNLOCK(&tp->mutex);
    	  return 1;
      }
    }
    TURN_MUTEX_UNLOCK(&tp->mutex);
  }
  return 0;
}

/////////////////// IP-mapped PORTS /////////////////////////////////////

struct _turnipports
{
	super_memory_t *sm;
	uint16_t start;
	uint16_t end;
	ur_addr_map ip_to_turnports_udp;
	ur_addr_map ip_to_turnports_tcp;
	TURN_MUTEX_DECLARE(mutex)
};

//////////////////////////////////////////////////

static ur_addr_map *get_map(turnipports *tp, uint8_t transport)
{
	if(transport == STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE)
		return &(tp->ip_to_turnports_tcp);
	return &(tp->ip_to_turnports_udp);
}
//////////////////////////////////////////////////

static turnipports* turnipports_singleton = NULL;

turnipports* turnipports_create(super_memory_t *sm, uint16_t start, uint16_t end)
{
	turnipports *ret = (turnipports*) allocate_super_memory_region(sm, sizeof(turnipports));
	ret->sm = sm;
	ur_addr_map_init(&(ret->ip_to_turnports_udp));
	ur_addr_map_init(&(ret->ip_to_turnports_tcp));
	ret->start = start;
	ret->end = end;
	TURN_MUTEX_INIT_RECURSIVE(&(ret->mutex));
	turnipports_singleton = ret;
	return ret;
}

static turnports* turnipports_add(turnipports* tp, uint8_t transport, const ioa_addr *backend_addr)
{
	ur_addr_map_value_type t = 0;
	if (tp && backend_addr) {
		ioa_addr ba;
		addr_cpy(&ba, backend_addr);
		addr_set_port(&ba, 0);
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		if (!ur_addr_map_get(get_map(tp, transport), &ba, &t)) {
			t = (ur_addr_map_value_type) turnports_create(tp->sm, tp->start, tp->end);
			ur_addr_map_put(get_map(tp, transport), &ba, t);
		}
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return (turnports*) t;
}

void turnipports_add_ip(uint8_t transport, const ioa_addr *backend_addr)
{
	turnipports_add(turnipports_singleton, transport, backend_addr);
}

int turnipports_allocate(turnipports* tp, uint8_t transport, const ioa_addr *backend_addr)
{
	int ret = -1;
	if (tp && backend_addr) {
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		turnports *t = turnipports_add(tp, transport, backend_addr);
		ret = turnports_allocate(t);
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return ret;
}

int turnipports_allocate_even(turnipports* tp, const ioa_addr *backend_addr, int allocate_rtcp,
				uint64_t *reservation_token)
{
	int ret = -1;
	if (tp && backend_addr) {
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		turnports *t = turnipports_add(tp, STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE, backend_addr);
		ret = turnports_allocate_even(t, allocate_rtcp, reservation_token);
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return ret;
}

void turnipports_release(turnipports* tp, uint8_t transport, const ioa_addr *socket_addr)
{
	if (tp && socket_addr) {
		ioa_addr ba;
		ur_addr_map_value_type t;
		addr_cpy(&ba, socket_addr);
		addr_set_port(&ba, 0);
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		if (ur_addr_map_get(get_map(tp, transport), &ba, &t)) {
			turnports_release((turnports*) t, addr_get_port(socket_addr));
		}
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
}

int turnipports_is_allocated(turnipports* tp, uint8_t transport, const ioa_addr *backend_addr, uint16_t port)
{
	int ret = 0;
	if (tp && backend_addr) {
		ioa_addr ba;
		ur_addr_map_value_type t;
		addr_cpy(&ba, backend_addr);
		addr_set_port(&ba, 0);
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		if (ur_addr_map_get(get_map(tp,transport), &ba, &t)) {
			ret = turnports_is_allocated((turnports*) t, port);
		}
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return ret;
}

int turnipports_is_available(turnipports* tp, uint8_t transport, const ioa_addr *backend_addr, uint16_t port)
{
	int ret = 0;
	if (tp && backend_addr) {
		ioa_addr ba;
		ur_addr_map_value_type t;
		addr_cpy(&ba, backend_addr);
		addr_set_port(&ba, 0);
		TURN_MUTEX_LOCK((const turn_mutex*)&(tp->mutex));
		if (!ur_addr_map_get(get_map(tp,transport), &ba, &t)) {
			ret = 1;
		} else {
			ret = turnports_is_available((turnports*) t, port);
		}
		TURN_MUTEX_UNLOCK((const turn_mutex*)&(tp->mutex));
	}
	return ret;
}

//////////////////////////////////////////////////////////////////


