/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

#ifndef MEROS_AES67_SAP_H
#define MEROS_AES67_SAP_H

/* libaes67 SAP (RFC 2974) packets: the announcement and deletion of a
 * session's SDP on 239.255.255.255:9875, which is how receivers without NMOS
 * find AES67 streams.
 *
 * Pure byte arithmetic, like rtp.h: an announcer with its own sockets builds
 * here, and aes67_tx's announcer uses the same code. A deletion carries the
 * SDP it withdraws, under the message hash that announced it, so a receiver
 * can match it either way.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_SAP_GROUP       "239.255.255.255"   /* the global-scope SAP group */
#define AES67_SAP_PORT        9875
#define AES67_SAP_INTERVAL_MS 30000               /* how often a session is announced */

/* Builds a SAP v1 packet with an IPv4 origin (the announcer's own address,
   four bytes in network order), no authentication and no compression, of
   payload type application/sdp. `msg_hash` should come from
   aes67_new_sap_hash (rtp.h) and change whenever the SDP does. Returns the
   packet length, or 0 when it would not fit `cap` or the hash is zero. */
size_t aes67_sap_build(uint8_t *packet, size_t cap, bool deletion, uint16_t msg_hash,
                       const uint8_t origin[4], const char *sdp, size_t sdp_len);

typedef struct aes67_sap_msg {
    bool        deletion;
    uint16_t    msg_hash;
    bool        origin_ipv6;
    uint8_t     origin[16];     /* the first 4 bytes for IPv4 */
    /* The payload, inside the packet: not NUL-terminated. */
    const char *sdp;
    size_t      sdp_len;
} aes67_sap_msg_t;

/* Parses a received SAP packet. False when it is not SAP v1, is encrypted
   or compressed (neither of which AES67 senders use), or carries a payload
   type other than application/sdp. */
bool aes67_sap_parse(const uint8_t *packet, size_t len, aes67_sap_msg_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MEROS_AES67_SAP_H */
