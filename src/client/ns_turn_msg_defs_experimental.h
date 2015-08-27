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

#ifndef __LIB_TURN_MSG_DEFS_NEW__
#define __LIB_TURN_MSG_DEFS_NEW__

/***** POST-RFC5766 FRESH SPECS ***********/

/* Origin ==>> */
#define STUN_MAX_ORIGIN_SIZE (127)
#define STUN_ATTRIBUTE_ORIGIN (0x802F)
/* <<== Origin */

/* Mobility ==>> */
/* conflicts with third-party authorization ! 0x802E is used for third-party authorization now */
#define STUN_ATTRIBUTE_MOBILITY_TICKET (0x8030)
/* <<== Mobility */

/* Bandwidth */

#define STUN_ATTRIBUTE_NEW_BANDWIDTH (0x8000 + STUN_ATTRIBUTE_BANDWIDTH)

/* <<== Bandwidth */

////////////// SSODA ///////////////////

#define STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY (0x8032)
#define STUN_ATTRIBUTE_ADDRESS_ERROR_CODE (0x8033)

#endif //__LIB_TURN_MSG_DEFS_NEW__
