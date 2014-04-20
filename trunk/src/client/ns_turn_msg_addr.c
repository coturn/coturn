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

#include "ns_turn_msg_addr.h"

//////////////////////////////////////////////////////////////////////////////

int stun_addr_encode(const ioa_addr* ca, u08bits *cfield, int *clen, int xor_ed, u32bits mc, const u08bits *tsx_id) {

  if(!cfield || !clen || !ca || !tsx_id) return -1;

  if (ca->ss.sa_family == AF_INET || ca->ss.sa_family==0) {

    /* IPv4 address */

    *clen=8;
    
    cfield[0]=0;
    cfield[1]=1; //IPv4 family
    
    if (xor_ed) {

      /* Port */
      ((u16bits*)cfield)[1] = (ca->s4.sin_port) ^ nswap16(mc >> 16);

      /* Address */
      ((u32bits*)cfield)[1] = (ca->s4.sin_addr.s_addr) ^ nswap32(mc);

    } else {

      /* Port */
      ((u16bits*)cfield)[1]=ca->s4.sin_port;

      /* Address */
      ((u32bits*)cfield)[1]=ca->s4.sin_addr.s_addr;
    }

  } else if (ca->ss.sa_family == AF_INET6) {

    /* IPv6 address */

    *clen=20;

    cfield[0]=0;
    cfield[1]=2; //IPv6 family
    
    if (xor_ed) {

      unsigned int i;
      u08bits *dst = ((u08bits*)cfield)+4;
      const u08bits *src = (const u08bits*)&(ca->s6.sin6_addr);
      u32bits magic = nswap32(mc);

      /* Port */
      ((u16bits*)cfield)[1] = ca->s6.sin6_port ^ nswap16(mc >> 16);

      /* Address */

      for (i=0; i<4; ++i) {
	dst[i] = (u08bits)(src[i] ^ ((const u08bits*)&magic)[i]);
      }
      for (i=0; i<12; ++i) {
	dst[i+4] = (u08bits)(src[i+4] ^ tsx_id[i]);
      }

    } else {

      /* Port */
      ((u16bits*)cfield)[1]=ca->s6.sin6_port;
      
      /* Address */
      ns_bcopy(&ca->s6.sin6_addr, ((u08bits*)cfield)+4, 16);
    }

  } else {
    return -1;
  }

  return 0;
}

int stun_addr_decode(ioa_addr* ca, const u08bits *cfield, int len, int xor_ed, u32bits mc, const u08bits *tsx_id) {

  if(!cfield || !len || !ca || !tsx_id || (len<8)) return -1;

  if(cfield[0]!=0) {
    return -1;
  }

  int sa_family;

  if(cfield[1]==1) sa_family=AF_INET;
  else if(cfield[1]==2) sa_family=AF_INET6;
  else return -1;
  
  ca->ss.sa_family=sa_family;

  if (sa_family == AF_INET) {

    if(len!=8) return -1;

    /* IPv4 address */

    /* Port */
    ca->s4.sin_port=((const u16bits*)cfield)[1];

    /* Address */
    ca->s4.sin_addr.s_addr=((const u32bits*)cfield)[1];
    
    if (xor_ed) {
      ca->s4.sin_port ^= nswap16(mc >> 16);
      ca->s4.sin_addr.s_addr ^= nswap32(mc);
    }

  } else if (sa_family == AF_INET6) {

    /* IPv6 address */

    if(len!=20) return -1;

    /* Port */
    ca->s6.sin6_port = ((const u16bits*)cfield)[1];

    /* Address */
    ns_bcopy(((const u08bits*)cfield)+4, &ca->s6.sin6_addr, 16);

    if (xor_ed) {

      unsigned int i;
      u08bits *dst;
      const u08bits *src;
      u32bits magic = nswap32(mc);

      /* Port */
      ca->s6.sin6_port ^= nswap16(mc >> 16);

      /* Address */
      src = ((const u08bits*)cfield)+4;
      dst = (u08bits*)&ca->s6.sin6_addr;
      for (i=0; i<4; ++i) {
	dst[i] = (u08bits)(src[i] ^ ((const u08bits*)&magic)[i]);
      }
      for (i=0; i<12; ++i) {
	dst[i+4] = (u08bits)(src[i+4] ^ tsx_id[i]);
      }
    }

  } else {
    return -1;
  }

  return 0;
}

//////////////////////////////////////////////////////////////////////////////

