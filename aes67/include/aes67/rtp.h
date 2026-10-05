/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

#ifndef MANIFOLD_AES67_RTP_H
#define MANIFOLD_AES67_RTP_H

/* libaes67 -- the parts of an AES67 stream that are pure arithmetic.
 *
 * RTP framing, L24 sample conversion, the timestamp-indexed playout ring and
 * SDP generation. No sockets, no threads, no platform: this is what the
 * receive and transmit paths are built on, and what the tests exercise
 * exhaustively on every platform, because the socket paths differ per OS and
 * this must not.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "aes67_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_RTP_HEADER_BYTES 12
/* AES67 packets fit one Ethernet frame with headroom; 1440 keeps a 48-frame
   L24 8-channel packet (1152 B) and the header well under 1500. */
#define AES67_MAX_PAYLOAD_BYTES 1440

/* The most channels one stream can carry: what fits in one packet's payload
   at this sample width and packet length. That is the wire's limit, not the
   library's: 8 at 1 ms is AES67's interoperability profile, 80 at 125 us is
   ST 2110-30 level C territory. 0 when not even one channel fits. */
int aes67_max_channels(int bytes_per_sample, int frames_per_packet);

typedef struct aes67_rtp_header {
    uint8_t  payload_type;   /* 7 bits */
    bool     marker;
    uint16_t sequence;
    uint32_t timestamp;      /* media-clock frames */
    uint32_t ssrc;
} aes67_rtp_header_t;

/* Writes the 12-byte header (V=2, no padding/extension/CSRC). */
void aes67_rtp_write_header(uint8_t out[AES67_RTP_HEADER_BYTES], const aes67_rtp_header_t *h);

/* Parses a packet's header. False when it is too short or not RTP v2. */
bool aes67_rtp_parse_header(const uint8_t *packet, size_t len, aes67_rtp_header_t *out);

/* Network-order L24 <-> sign-extended, right-justified 24-in-32. */
int32_t aes67_l24_to_i32(const uint8_t p[3]);
void    aes67_i32_to_l24(int32_t v, uint8_t out[3]);

/* The media clock AES67 means by `a=mediaclk:direct=0`: PTP time (TAI, ns
   since the PTP epoch) in frames at `rate`, modulo 2^32 -- the RTP timestamp
   of a sample taken at `ptp_ns`. Exact integer arithmetic. */
uint32_t aes67_media_clock_ts(uint64_t ptp_ns, uint32_t rate);

/* Packs `frames` x `channels` right-justified 24-bit samples into L24 after a
   header, returning the packet length, or 0 when it would not fit. */
size_t aes67_rtp_pack_l24(uint8_t *packet, size_t cap, const aes67_rtp_header_t *h,
                          const int32_t *interleaved, int frames, int channels);

/* ---- the playout ring ---------------------------------------------------
 *
 * One per received channel: a single-writer (the receive thread), single-
 * reader (the audio thread) ring of samples indexed by RTP timestamp, so the
 * reader chooses its own latency by choosing which timestamp to read and a
 * packet arriving out of order lands in the right place regardless.
 */

#define AES67_RING_FRAMES 4096   /* power of two; ~85 ms at 48 kHz */

typedef struct aes67_ring {
    int32_t samples[AES67_RING_FRAMES];
    /* Highest timestamp written + 1: the next frame the writer expects. */
    aes67_atomic_u64 head_ts;
    aes67_atomic_u64 writes, late_drops;
} aes67_ring_t;

void aes67_ring_init(aes67_ring_t *r);

/* Writer. A sample older than a whole ring behind the head is dropped as
   stale rather than overwriting what the reader is about to play. */
void aes67_ring_write(aes67_ring_t *r, uint32_t ts, int32_t sample);

/* Reader, wait-free. Fills out[] with the frames at ts..ts+frames-1 that are
   present and zero for the ones that are not (concealment is the caller's
   policy); returns how many were present. */
int aes67_ring_read(const aes67_ring_t *r, uint32_t ts, int32_t *out, int frames);

/* The writer's head, for playout scheduling. */
uint32_t aes67_ring_head(const aes67_ring_t *r);

/* How samples sit in the payload. L24 is AES67's own; L16 is allowed by
   it; AM824 is ST 2110-31, AES3 subframes of four octets whose last three
   are the audio word (the first carries the AES3 flags). */
typedef enum aes67_sample_format {
    AES67_FORMAT_L24 = 0,
    AES67_FORMAT_L16 = 1,
    AES67_FORMAT_AM824 = 2,
} aes67_sample_format_t;

/* Bytes per sample for a format; the rtpmap encoding name to a format
   (false for one this library does not decode). */
int  aes67_format_bytes(aes67_sample_format_t format);
bool aes67_format_from_encoding(const char *encoding, aes67_sample_format_t *out);

/* ---- a received packet into rings ---------------------------------------
 *
 * The decode step on its own, for a receiver that owns its sockets and its
 * rings (shared memory a driver reads, say): one RTP packet in, its samples
 * written to the caller's rings. aes67_rx and aes67_netrx use it too.
 */

#define AES67_PACKET_MALFORMED  (-1)   /* too short, or not RTP version 2 */
#define AES67_PACKET_WRONG_PT   (-2)   /* not the payload type expected */

/* Writes the samples of one RTP packet into `rings`, one ring per channel of
   the stream, in channel order. Frame f of the packet lands at the packet's
   RTP timestamp + f - `media_clock_offset` (the SDP's
   `a=mediaclk:direct=<offset>`), so a ring is indexed by the media clock and a
   reader finds a sample at the media-clock time it was taken. L16 is scaled to
   24 bits; AM824's flags octet is skipped.

   Returns the frames written, or AES67_PACKET_MALFORMED or
   AES67_PACKET_WRONG_PT, in which case nothing is written. `header`, when not
   NULL, gets the parsed header (for the caller's sequence and loss counting)
   whenever it could be parsed. NULL `rings` checks and parses only. Single
   writer per ring, like aes67_ring_write. */
int aes67_rtp_write_rings(const uint8_t *packet, size_t len, uint8_t payload_type,
                          aes67_sample_format_t format, int channels, uint32_t media_clock_offset,
                          aes67_ring_t *rings, aes67_rtp_header_t *header);

/* ---- SDP ----------------------------------------------------------------- */

typedef struct aes67_sdp_params {
    const char *session_name;
    const char *origin_ip;      /* the sender's interface address */
    const char *group;          /* destination multicast group */
    uint16_t    port;
    uint8_t     payload_type;
    uint8_t     channels;
    uint32_t    sample_rate;    /* 48000 or 96000 */
    uint32_t    ptime_us;       /* 1000, 250, 125 ... */
    uint32_t    ssrc;
    uint8_t     ttl;
    /* The PTP grandmaster this stream is timed against, as eight bytes; all
       zero when unknown, which a receiver should read as "not stated". */
    uint8_t     gm_identity[8];
    uint16_t    ptp_domain;
} aes67_sdp_params_t;

/* Generates an AES67 SDP (RFC 4566 + the AES67 attributes a receiver
   needs: rtpmap, ptime, mediaclk, ts-refclk). Returns the length it wrote,
   or would have written, snprintf-style. */
int aes67_sdp_write(char *buf, size_t len, const aes67_sdp_params_t *p);

#ifdef __cplusplus
}
#endif

#endif /* MANIFOLD_AES67_RTP_H */
