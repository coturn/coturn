/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * https://opensource.org/license/bsd-3-clause
 *
 * DTLS half-open handshake caps.
 */

#ifndef TURN_DTLS_HALF_OPEN_H_
#define TURN_DTLS_HALF_OPEN_H_

#include "ns_turn_ioaddr.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Global cap bounds total memory; per-source share (IP, or IPv6 /64) stops one
 * return-routable host from consuming every slot via source-port rotation.
 * try_inc reserves both; false means drop. dec releases both for src. */
#define TURN_DTLS_HALF_OPEN_PER_SOURCE 4u

bool turn_dtls_half_open_try_inc(uint32_t global_cap, const ioa_addr *src);
void turn_dtls_half_open_dec(const ioa_addr *src);
uint32_t turn_dtls_half_open_count(void);

/* Clear global and per-source state. For unit tests between cases. */
void turn_dtls_half_open_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* TURN_DTLS_HALF_OPEN_H_ */
