/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libaes67 -- SAP packets. See sap.h. */

#include "aes67/sap.h"

#include <string.h>

#define SAP_MIME "application/sdp"

size_t aes67_sap_build(uint8_t *packet, size_t cap, bool deletion, uint16_t msg_hash,
                       const uint8_t origin[4], const char *sdp, size_t sdp_len)
{
    const size_t mime = sizeof SAP_MIME;   /* with its NUL */
    if (packet == NULL || msg_hash == 0 || (sdp == NULL && sdp_len > 0) || 8 + mime + sdp_len > cap)
        return 0;
    packet[0] = (uint8_t) (0x20 | (deletion ? 0x04 : 0));   /* V=1, IPv4, no encryption or compression */
    packet[1] = 0;                                         /* no authentication data */
    packet[2] = (uint8_t) (msg_hash >> 8);
    packet[3] = (uint8_t) msg_hash;
    if (origin != NULL)
        memcpy(packet + 4, origin, 4);
    else
        memset(packet + 4, 0, 4);
    memcpy(packet + 8, SAP_MIME, mime);
    if (sdp_len > 0)
        memcpy(packet + 8 + mime, sdp, sdp_len);
    return 8 + mime + sdp_len;
}

bool aes67_sap_parse(const uint8_t *p, size_t len, aes67_sap_msg_t *out)
{
    if (p == NULL || out == NULL || len < 8)
        return false;
    memset(out, 0, sizeof *out);
    if ((p[0] >> 5) != 1 || (p[0] & 0x02) || (p[0] & 0x01))   /* version 1; not encrypted or compressed */
        return false;
    out->origin_ipv6 = (p[0] & 0x10) != 0;
    out->deletion = (p[0] & 0x04) != 0;
    out->msg_hash = (uint16_t) ((p[2] << 8) | p[3]);
    const size_t origin_len = out->origin_ipv6 ? 16 : 4;
    const size_t at = 4 + origin_len + (size_t) p[1] * 4;   /* auth length is in 32-bit words */
    if (len < at)
        return false;
    memcpy(out->origin, p + 4, origin_len);
    const char *payload = (const char *) p + at;
    size_t n = len - at;
    /* RFC 2974: the payload type may be left out, in which case it is SDP,
       which always begins "v=". */
    if (!(n >= 2 && payload[0] == 'v' && payload[1] == '=')) {
        const char *end = memchr(payload, '\0', n);
        if (end == NULL || (size_t) (end - payload) != sizeof SAP_MIME - 1 ||
            memcmp(payload, SAP_MIME, sizeof SAP_MIME - 1) != 0)
            return false;
        n -= sizeof SAP_MIME;
        payload += sizeof SAP_MIME;
    }
    out->sdp = payload;
    out->sdp_len = n;
    return true;
}
