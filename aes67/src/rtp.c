/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libaes67 -- RTP framing, L24, the playout ring and SDP. See rtp.h. */

#include "aes67/rtp.h"

int aes67_max_channels(int bytes_per_sample, int frames_per_packet)
{
    if (bytes_per_sample <= 0 || frames_per_packet <= 0)
        return 0;
    return AES67_MAX_PAYLOAD_BYTES / (bytes_per_sample * frames_per_packet);
}

#include <stdio.h>
#include <string.h>

#define RING_MASK (AES67_RING_FRAMES - 1)

/* ---- RTP ------------------------------------------------------------------ */

void aes67_rtp_write_header(uint8_t out[AES67_RTP_HEADER_BYTES], const aes67_rtp_header_t *h)
{
    out[0] = 0x80;                                    /* V=2, no P/X/CC */
    out[1] = (uint8_t) ((h->payload_type & 0x7F) | (h->marker ? 0x80 : 0));
    out[2] = (uint8_t) (h->sequence >> 8);
    out[3] = (uint8_t) h->sequence;
    out[4] = (uint8_t) (h->timestamp >> 24);
    out[5] = (uint8_t) (h->timestamp >> 16);
    out[6] = (uint8_t) (h->timestamp >> 8);
    out[7] = (uint8_t) h->timestamp;
    out[8]  = (uint8_t) (h->ssrc >> 24);
    out[9]  = (uint8_t) (h->ssrc >> 16);
    out[10] = (uint8_t) (h->ssrc >> 8);
    out[11] = (uint8_t) h->ssrc;
}

bool aes67_rtp_parse_header(const uint8_t *p, size_t len, aes67_rtp_header_t *out)
{
    if (p == NULL || len < AES67_RTP_HEADER_BYTES || (p[0] >> 6) != 2)
        return false;
    out->payload_type = (uint8_t) (p[1] & 0x7F);
    out->marker = (p[1] & 0x80) != 0;
    out->sequence = (uint16_t) ((p[2] << 8) | p[3]);
    out->timestamp = ((uint32_t) p[4] << 24) | ((uint32_t) p[5] << 16) | ((uint32_t) p[6] << 8) | (uint32_t) p[7];
    out->ssrc = ((uint32_t) p[8] << 24) | ((uint32_t) p[9] << 16) | ((uint32_t) p[10] << 8) | (uint32_t) p[11];
    return true;
}

int32_t aes67_l24_to_i32(const uint8_t p[3])
{
    int32_t v = ((int32_t) p[0] << 16) | ((int32_t) p[1] << 8) | (int32_t) p[2];
    if (v & 0x800000)
        v |= (int32_t) 0xFF000000;
    return v;
}

void aes67_i32_to_l24(int32_t v, uint8_t out[3])
{
    out[0] = (uint8_t) (v >> 16);
    out[1] = (uint8_t) (v >> 8);
    out[2] = (uint8_t) v;
}

uint32_t aes67_media_clock_ts(uint64_t ptp_ns, uint32_t rate)
{
    const uint64_t sec = ptp_ns / 1000000000u;
    const uint64_t rem = ptp_ns % 1000000000u;
    /* sec * rate stays well inside 64 bits for centuries at any audio rate;
       rem * rate < 1e9 * 384000 < 2^64. Truncation to 32 bits is the wrap. */
    return (uint32_t) (sec * rate + rem * rate / 1000000000u);
}

size_t aes67_rtp_pack_l24(uint8_t *packet, size_t cap, const aes67_rtp_header_t *h,
                          const int32_t *interleaved, int frames, int channels)
{
    if (packet == NULL || frames <= 0 || channels <= 0)
        return 0;
    const size_t payload = (size_t) frames * (size_t) channels * 3;
    if (payload > AES67_MAX_PAYLOAD_BYTES || AES67_RTP_HEADER_BYTES + payload > cap)
        return 0;
    aes67_rtp_write_header(packet, h);
    uint8_t *d = packet + AES67_RTP_HEADER_BYTES;
    for (int i = 0; i < frames * channels; ++i, d += 3)
        aes67_i32_to_l24(interleaved[i], d);
    return AES67_RTP_HEADER_BYTES + payload;
}

/* ---- ring ----------------------------------------------------------------- */

void aes67_ring_init(aes67_ring_t *r)
{
    memset(r->samples, 0, sizeof r->samples);
    aes67_atomic_store(&r->head_ts, 0, AES67_MO_SEQ_CST);
    aes67_atomic_store(&r->writes, 0, AES67_MO_SEQ_CST);
    aes67_atomic_store(&r->late_drops, 0, AES67_MO_SEQ_CST);
}

void aes67_ring_write(aes67_ring_t *r, uint32_t ts, int32_t sample)
{
    const uint32_t head = (uint32_t) aes67_atomic_load(&r->head_ts, AES67_MO_RELAXED);
    /* Older than the whole ring behind the head: the reader may be on it. */
    if (head != 0 && (int32_t) (ts - head) < -(int32_t) AES67_RING_FRAMES) {
        aes67_atomic_fetch_add(&r->late_drops, 1, AES67_MO_RELAXED);
        return;
    }
    r->samples[ts & RING_MASK] = sample;
    aes67_atomic_fetch_add(&r->writes, 1, AES67_MO_RELAXED);
    /* An empty ring (head 0) takes whatever timestamp comes first. Senders
       start RTP timestamps at random (GStreamer, most devices); half of
       them are past 2^31, where the signed comparison below would call the
       very first frame "older than the head" and the ring would never
       prime -- a stream heard by the stats and never by the graph. */
    if (head == 0 || (int32_t) (ts + 1 - head) > 0)
        aes67_atomic_store(&r->head_ts, (uint64_t) (ts + 1), AES67_MO_RELEASE);
}

int aes67_ring_read(const aes67_ring_t *r, uint32_t ts, int32_t *out, int frames)
{
    const uint32_t head = (uint32_t) aes67_atomic_load(&r->head_ts, AES67_MO_ACQUIRE);
    int have = 0;
    for (int f = 0; f < frames; ++f) {
        const uint32_t t = ts + (uint32_t) f;
        /* Readable iff within [head - RING, head). */
        if ((int32_t) (head - t) > 0 && (int32_t) (head - t) <= AES67_RING_FRAMES) {
            out[f] = r->samples[t & RING_MASK];
            ++have;
        } else {
            out[f] = 0;
        }
    }
    return have;
}

uint32_t aes67_ring_head(const aes67_ring_t *r)
{
    return (uint32_t) aes67_atomic_load(&r->head_ts, AES67_MO_ACQUIRE);
}

/* ---- SDP ------------------------------------------------------------------ */

int aes67_sdp_write(char *buf, size_t len, const aes67_sdp_params_t *p)
{
    const double ptime_ms = (double) p->ptime_us / 1000.0;
    const uint8_t *g = p->gm_identity;
    bool gm_known = false;
    for (int i = 0; i < 8; ++i)
        if (g[i] != 0)
            gm_known = true;

    int n = snprintf(buf, len,
        "v=0\r\n"
        "o=- %u 0 IN IP4 %s\r\n"
        "s=%s\r\n"
        "c=IN IP4 %s/%u\r\n"
        "t=0 0\r\n"
        "a=clock-domain:PTPv2 %u\r\n"
        "m=audio %u RTP/AVP %u\r\n"
        "a=rtpmap:%u L24/%u/%u\r\n"
        "a=sync-time:0\r\n"
        "a=ptime:%.3f\r\n"
        "a=mediaclk:direct=0\r\n",
        p->ssrc, p->origin_ip ? p->origin_ip : "0.0.0.0",
        p->session_name && p->session_name[0] ? p->session_name : "manifold",
        p->group, p->ttl ? p->ttl : 15,
        p->ptp_domain,
        p->port, p->payload_type,
        p->payload_type, p->sample_rate ? p->sample_rate : 48000, p->channels,
        ptime_ms);
    if (n < 0)
        return n;

    /* The reference clock. A receiver decides whether it shares a grandmaster
       with us from this line, so an unknown identity is stated as such
       (traceable=1 says "any PTP clock in this domain") rather than as a
       string of zeros a receiver would take for a real clock. */
    int m;
    if (gm_known)
        m = snprintf(buf + (n < (int) len ? n : (int) len), n < (int) len ? len - (size_t) n : 0,
                     "a=ts-refclk:ptp=IEEE1588-2008:%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X:%u\r\n",
                     g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7], p->ptp_domain);
    else
        m = snprintf(buf + (n < (int) len ? n : (int) len), n < (int) len ? len - (size_t) n : 0,
                     "a=ts-refclk:ptp=IEEE1588-2008:traceable\r\n");
    return m < 0 ? m : n + m;
}
