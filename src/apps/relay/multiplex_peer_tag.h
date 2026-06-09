/*
 * Multiplex-peer tagging wire format.
 *
 * When --multiplex-peer-tag is enabled the relay appends a fixed-size,
 * big-endian per-session mux-id as a TRAILER to every UDP datagram on the
 * relay<->peer leg, and strips it on the way back. A trailer (rather than a
 * prefix) keeps the tag at the opposite end of the buffer from coturn's own
 * framing (ChannelData/STUN/fingerprint headers), so add/strip are a tail
 * write and a length decrement that never touch the reserved front headroom.
 *
 * This is a private, non-RFC extension: it must be enabled on BOTH the
 * turnserver (--multiplex-peer-tag) and the multiplexing peer
 * (turnutils_peer --multiplex). It exists to disambiguate multiple TURN
 * sessions that share one peer IP:port on a per-thread shared relay socket,
 * a case plain --multiplex-peer rejects (see docs/multiplex-peer.md).
 *
 * The codec lives in its own dependency-free header so it can be unit-tested
 * in isolation (tests/test_multiplex_tag.c) without pulling in the engine.
 */

#ifndef __MULTIPLEX_PEER_TAG_H__
#define __MULTIPLEX_PEER_TAG_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Size in bytes of the mux-id trailer appended on the relay<->peer leg. */
#define MULTIPLEX_PEER_TAG_SIZE 4

/* mux-id 0 means "unassigned" and is never put on the wire. */
#define MULTIPLEX_PEER_TAG_NONE 0u

/*
 * Append the 4-byte big-endian mux-id trailer to a datagram of payload length
 * *len held in buffer buf of total capacity cap. On success *len is advanced
 * by MULTIPLEX_PEER_TAG_SIZE and true is returned. Returns false (leaving *len
 * untouched) if mux_id is unassigned or there is no tailroom for the trailer.
 */
static inline bool multiplex_peer_tag_append(uint8_t *buf, size_t *len, size_t cap, uint32_t mux_id) {
  if (!buf || !len || mux_id == MULTIPLEX_PEER_TAG_NONE) {
    return false;
  }
  if (*len + MULTIPLEX_PEER_TAG_SIZE > cap) {
    return false;
  }
  uint8_t *p = buf + *len;
  p[0] = (uint8_t)((mux_id >> 24) & 0xFFu);
  p[1] = (uint8_t)((mux_id >> 16) & 0xFFu);
  p[2] = (uint8_t)((mux_id >> 8) & 0xFFu);
  p[3] = (uint8_t)(mux_id & 0xFFu);
  *len += MULTIPLEX_PEER_TAG_SIZE;
  return true;
}

/*
 * Read and strip the 4-byte big-endian mux-id trailer from a datagram of
 * length *len in buf. On success *len is reduced by MULTIPLEX_PEER_TAG_SIZE,
 * the decoded id is stored in *mux_id and true is returned. Returns false
 * (leaving *len untouched) if the datagram is too short to carry a trailer.
 */
static inline bool multiplex_peer_tag_strip(const uint8_t *buf, size_t *len, uint32_t *mux_id) {
  if (!buf || !len || !mux_id || *len < MULTIPLEX_PEER_TAG_SIZE) {
    return false;
  }
  const uint8_t *p = buf + (*len - MULTIPLEX_PEER_TAG_SIZE);
  *mux_id = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
  *len -= MULTIPLEX_PEER_TAG_SIZE;
  return true;
}

#ifdef __cplusplus
}
#endif

#endif /* __MULTIPLEX_PEER_TAG_H__ */
