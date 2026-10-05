/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

#ifndef MEROS_AES67_SDP_H
#define MEROS_AES67_SDP_H

/* libaes67 SDP parsing. Generation lives in rtp.h beside the packet
 * arithmetic; this is the other direction: an SDP that arrived by SAP, from
 * an NMOS sender's manifest, or pasted by an operator, turned into the facts
 * a receiver needs to subscribe and to decide whether it *should* -- above
 * all which PTP grandmaster the stream is timed against, since a mismatch is
 * the commonest AES67 failure and the least self-evident.
 *
 * Understands what AES67, ST 2110-30/-31, RAVENNA and Dante senders write:
 *   m=audio, a=rtpmap (L16/L24/AM824), a=ptime/maxptime (fractional ms),
 *   a=mediaclk:direct=N, a=ts-refclk (ptp=IEEE1588-2008:GMID:domain, or
 *   ptp=...:traceable, or localmac=...), a=source-filter (SSM), a=fmtp
 *   channel-order (2110-30), a=framecount (RAVENNA), a=clock-domain
 *   (older RAVENNA), the direction attributes, and c= with a TTL.
 *
 * Only the first audio media section is described; an SDP with several is
 * several streams, and the caller can split on "m=" if it wants the rest.
 * Anything unknown is skipped, never fatal: the wire is full of vendor lines.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum aes67_sdp_direction {
    AES67_SDP_SENDRECV = 0,
    AES67_SDP_SENDONLY,
    AES67_SDP_RECVONLY,
    AES67_SDP_INACTIVE
} aes67_sdp_direction_t;

typedef struct aes67_sdp {
    char     session_name[128];
    char     origin_ip[64];        /* o= unicast address of the sender */
    char     connection_ip[64];    /* c= address: the multicast group, usually */
    int      connection_ttl;       /* c= /ttl, or -1 when absent */
    char     source_ip[64];        /* a=source-filter's source, for SSM joins; empty when none */
    uint16_t port;                 /* m=audio port */
    uint8_t  payload_type;         /* the first payload type on the m= line */
    char     encoding[16];         /* "L24", "L16", "AM824" */
    uint32_t sample_rate;          /* from rtpmap; 0 when no rtpmap named our PT */
    uint8_t  channels;             /* from rtpmap; 1 when it omits the count, per RFC 4566 */
    uint32_t ptime_us;             /* a=ptime, in microseconds; 0 when absent */
    uint32_t maxptime_us;
    uint32_t framecount;           /* a=framecount (RAVENNA); 0 when absent */
    bool     mediaclk_direct;      /* a=mediaclk:direct=<offset> present */
    int64_t  mediaclk_offset;
    bool     refclk_ptp;           /* a=ts-refclk names a PTP clock */
    char     ptp_version[24];      /* "IEEE1588-2008", "IEEE1588-2019" */
    bool     gm_traceable;         /* ...:traceable -- any clock in the domain */
    bool     gm_known;             /* an identity was given */
    uint8_t  gm_identity[8];
    int      ptp_domain;           /* -1 when not stated */
    bool     refclk_localmac;      /* a=ts-refclk:localmac= -- not PTP: the sender's own clock */
    char     channel_order[64];    /* 2110-30 fmtp channel-order, e.g. "SMPTE2110.(ST)" */
    aes67_sdp_direction_t direction;
    bool     is_st2110_31;         /* AM824: AES3 transparent */
    /* What the first media section carries, said the way a broadcast
       engineer would: "AES67 audio (L24)", "ST 2110-31 AES3",
       "ST 2110-20 video", "ST 2110-22 video (JPEG XS)", "ST 2110-40
       ancillary data". Filled even when parsing fails for want of audio, so
       a stream list can show a video announcement for what it is rather
       than drop it. */
    char     essence[48];
    uint16_t other_port;           /* the non-audio section's port, when there was no audio */
} aes67_sdp_t;

/* Parses `len` bytes of SDP (CRLF or LF). False, with a reason in errbuf,
   when there is no audio media section or the m= line is unusable; every
   other shortfall is reflected in the fields (a zero sample_rate says "no
   rtpmap for this payload type") rather than refused. */
bool aes67_sdp_parse(const char *text, size_t len, aes67_sdp_t *out, char *errbuf, size_t errlen);

/* Whether a parsed stream is timed against the grandmaster we are locked to.
   The question the UI asks before it lets an operator connect: a stream on
   another grandmaster will drift, and the symptom -- clicks, minutes later --
   never looks like a clock problem. `our_gm` all zero means we have no PTP
   lock at all, which is its own answer (false). A stream marked traceable
   in our domain is accepted; one with no clock statement is *not*, because
   silence about the clock is not the same as agreement. */
bool aes67_sdp_shares_grandmaster(const aes67_sdp_t *sdp, const uint8_t our_gm[8], int our_domain);

#ifdef __cplusplus
}
#endif

#endif /* MEROS_AES67_SDP_H */
