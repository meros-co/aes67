/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libaes67 tests: the arithmetic that must be identical on every platform
   (RTP framing, L24, the timestamp-indexed ring, SDP), the packet path end
   to end through injection, and -- where the machine allows multicast on a
   loopback -- a real socket round trip. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes67/netrx.h"
#include "aes67/rtp.h"
#include "aes67/rx.h"
#include "aes67/sdp.h"
#include "aes67/tx.h"

#if defined(_WIN32)
#  include <windows.h>
#  define sleep_ms(ms) Sleep(ms)
#else
#  include <time.h>
static void sleep_ms(int ms) { struct timespec t = { ms / 1000, (ms % 1000) * 1000000L }; nanosleep(&t, NULL); }
#endif

static int checks = 0, failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        ++checks;                                                          \
        if (!(cond)) {                                                     \
            ++failures;                                                    \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                  \
    } while (0)

static void test_rtp_header_round_trips(void)
{
    aes67_rtp_header_t in = { 98, true, 0xBEEF, 0xDEADBEEFu, 0x3AE50001u };
    uint8_t bytes[AES67_RTP_HEADER_BYTES];
    aes67_rtp_write_header(bytes, &in);
    CHECK(bytes[0] == 0x80);
    CHECK(bytes[1] == (0x80 | 98));

    aes67_rtp_header_t out;
    CHECK(aes67_rtp_parse_header(bytes, sizeof bytes, &out));
    CHECK(out.payload_type == 98 && out.marker && out.sequence == 0xBEEF);
    CHECK(out.timestamp == 0xDEADBEEFu && out.ssrc == 0x3AE50001u);

    /* Too short, or not version 2, is not RTP. */
    CHECK(!aes67_rtp_parse_header(bytes, 11, &out));
    bytes[0] = 0x40;
    CHECK(!aes67_rtp_parse_header(bytes, sizeof bytes, &out));
}

static void test_l24_is_exact_and_signed(void)
{
    const int32_t values[] = { 0, 1, -1, 0x7FFFFF, -0x800000, 0x123456, -0x123456 };
    for (size_t i = 0; i < sizeof values / sizeof values[0]; ++i) {
        uint8_t b[3];
        aes67_i32_to_l24(values[i], b);
        CHECK(aes67_l24_to_i32(b) == values[i]);
    }
    const uint8_t full_scale_neg[3] = { 0x80, 0x00, 0x00 };
    CHECK(aes67_l24_to_i32(full_scale_neg) == -0x800000);
}

static void test_pack_respects_the_mtu(void)
{
    int32_t frames[48 * 8];
    memset(frames, 0, sizeof frames);
    aes67_rtp_header_t h = { 96, false, 0, 0, 0 };
    uint8_t pkt[1500];
    /* 48 frames x 8 channels x 3 bytes = 1152: the largest AES67 1 ms packet. */
    CHECK(aes67_rtp_pack_l24(pkt, sizeof pkt, &h, frames, 48, 8) == 12 + 1152);
    /* Past the payload ceiling: refused rather than fragmented. */
    CHECK(aes67_rtp_pack_l24(pkt, sizeof pkt, &h, frames, 96, 8) == 0);
    /* A buffer too small for the packet: refused. */
    CHECK(aes67_rtp_pack_l24(pkt, 100, &h, frames, 48, 8) == 0);
}

static void test_ring_is_timestamp_indexed(void)
{
    static aes67_ring_t r;
    aes67_ring_init(&r);
    int32_t out[8];

    /* Nothing written: nothing readable, and the gaps are zero. */
    CHECK(aes67_ring_read(&r, 1000, out, 8) == 0);
    CHECK(out[3] == 0);

    /* Frames 1000..1007 written in order. */
    for (uint32_t t = 1000; t < 1008; ++t)
        aes67_ring_write(&r, t, (int32_t) t);
    CHECK(aes67_ring_head(&r) == 1008);
    CHECK(aes67_ring_read(&r, 1000, out, 8) == 8);
    CHECK(out[0] == 1000 && out[7] == 1007);

    /* A read straddling the head: the future is zero, the past is present. */
    CHECK(aes67_ring_read(&r, 1004, out, 8) == 4);
    CHECK(out[3] == 1007 && out[4] == 0);

    /* A late packet (reordered) lands in place without moving the head. */
    aes67_ring_write(&r, 1002, -2);
    CHECK(aes67_ring_head(&r) == 1008);
    CHECK(aes67_ring_read(&r, 1002, out, 1) == 1 && out[0] == -2);

    /* Older than a whole ring behind the head: dropped, not written over
       what the reader is about to play. */
    aes67_ring_write(&r, 1008 - AES67_RING_FRAMES - 1, 99);
    CHECK((uint32_t) aes67_atomic_load(&r.late_drops, AES67_MO_SEQ_CST) == 1);

    /* Timestamps wrap at 2^32 and the ring does not care. */
    aes67_ring_init(&r);
    aes67_ring_write(&r, 0xFFFFFFFEu, 1);
    aes67_ring_write(&r, 0xFFFFFFFFu, 2);
    aes67_ring_write(&r, 0u, 3);
    CHECK(aes67_ring_head(&r) == 1);
    CHECK(aes67_ring_read(&r, 0xFFFFFFFEu, out, 3) == 3);
    CHECK(out[0] == 1 && out[1] == 2 && out[2] == 3);
}

static void test_sdp_says_what_a_receiver_needs(void)
{
    aes67_sdp_params_t p;
    memset(&p, 0, sizeof p);
    p.session_name = "Console main";
    p.origin_ip = "192.168.1.10";
    p.group = "239.69.1.1";
    p.port = 5004;
    p.payload_type = 98;
    p.channels = 8;
    p.sample_rate = 48000;
    p.ptime_us = 1000;
    p.ssrc = 0x3AE50000u;
    p.ptp_domain = 0;

    char sdp[1024];
    const int n = aes67_sdp_write(sdp, sizeof sdp, &p);
    CHECK(n > 0 && n < (int) sizeof sdp);
    CHECK(strstr(sdp, "v=0\r\n") == sdp);
    CHECK(strstr(sdp, "s=Console main\r\n") != NULL);
    CHECK(strstr(sdp, "c=IN IP4 239.69.1.1/15\r\n") != NULL);
    CHECK(strstr(sdp, "m=audio 5004 RTP/AVP 98\r\n") != NULL);
    CHECK(strstr(sdp, "a=rtpmap:98 L24/48000/8\r\n") != NULL);
    CHECK(strstr(sdp, "a=ptime:1.000\r\n") != NULL);
    CHECK(strstr(sdp, "a=mediaclk:direct=0\r\n") != NULL);
    /* No grandmaster known: stated as traceable, never as a zero identity. */
    CHECK(strstr(sdp, "a=ts-refclk:ptp=IEEE1588-2008:traceable\r\n") != NULL);
    CHECK(strstr(sdp, "00-00-00-00") == NULL);

    /* With a grandmaster: its identity and domain, in the AES67 form. */
    const uint8_t gm[8] = { 0x00, 0x1D, 0xC1, 0xFF, 0xFE, 0x12, 0x34, 0x56 };
    memcpy(p.gm_identity, gm, 8);
    p.ptp_domain = 3;
    p.ptime_us = 125;
    aes67_sdp_write(sdp, sizeof sdp, &p);
    CHECK(strstr(sdp, "a=ts-refclk:ptp=IEEE1588-2008:00-1D-C1-FF-FE-12-34-56:3\r\n") != NULL);
    CHECK(strstr(sdp, "a=clock-domain:PTPv2 3\r\n") != NULL);
    CHECK(strstr(sdp, "a=ptime:0.125\r\n") != NULL);

    /* A short buffer reports the length it wanted, snprintf-style. */
    char tiny[16];
    CHECK(aes67_sdp_write(tiny, sizeof tiny, &p) > 16);
}

/* A packet as a sender would build it, without a socket. */
static size_t build_packet(uint8_t *pkt, size_t cap, uint8_t pt, uint16_t seq, uint32_t ts,
                           int frames, int channels, int32_t base)
{
    int32_t samples[48 * 8];
    for (int f = 0; f < frames; ++f)
        for (int c = 0; c < channels; ++c)
            samples[f * channels + c] = base + f * 10 + c;
    aes67_rtp_header_t h = { pt, false, seq, ts, 0x1234 };
    return aes67_rtp_pack_l24(pkt, cap, &h, samples, frames, channels);
}

/* The decode step alone, into rings the caller owns, at a media-clock offset:
   what a receiver with its own sockets and shared-memory rings uses. */
static void test_packets_into_the_callers_rings(void)
{
    aes67_ring_t *rings = (aes67_ring_t *) calloc(3, sizeof *rings);
    CHECK(rings != NULL);
    if (rings == NULL)
        return;
    for (int i = 0; i < 3; ++i)
        aes67_ring_init(&rings[i]);

    uint8_t pkt[1500];
    aes67_rtp_header_t h;
    size_t n = build_packet(pkt, sizeof pkt, 97, 40, 5000, 6, 3, 700);
    /* a=mediaclk:direct=1000: RTP 5000 is media-clock 4000. */
    CHECK(aes67_rtp_write_rings(pkt, n, 97, AES67_FORMAT_L24, 3, 1000, rings, &h) == 6);
    CHECK(h.sequence == 40 && h.timestamp == 5000);
    int32_t out[6];
    CHECK(aes67_ring_read(&rings[0], 4000, out, 6) == 6 && out[0] == 700 && out[5] == 750);
    CHECK(aes67_ring_read(&rings[2], 4000, out, 6) == 6 && out[0] == 702);
    CHECK(aes67_ring_read(&rings[0], 5000, out, 1) == 0);           /* not at the RTP timestamp */

    /* Refused packets write nothing, and say why. */
    n = build_packet(pkt, sizeof pkt, 96, 41, 5006, 6, 3, 900);
    CHECK(aes67_rtp_write_rings(pkt, n, 97, AES67_FORMAT_L24, 3, 1000, rings, &h) == AES67_PACKET_WRONG_PT);
    CHECK(h.sequence == 41);                                          /* parsed, for loss counting */
    CHECK(aes67_rtp_write_rings(pkt, 5, 97, AES67_FORMAT_L24, 3, 1000, rings, NULL) == AES67_PACKET_MALFORMED);
    CHECK(aes67_ring_read(&rings[0], 4006, out, 6) == 0);

    /* L16 lands at 24-bit scale; the offset wraps with the 32-bit clock. */
    uint8_t l16[AES67_RTP_HEADER_BYTES + 4];
    aes67_rtp_header_t hh = { 97, false, 42, 10, 1 };
    aes67_rtp_write_header(l16, &hh);
    l16[12] = 0x01; l16[13] = 0x00;          /* frame 0: 256 */
    l16[14] = 0xFF; l16[15] = 0xFF;          /* frame 1: -1 */
    CHECK(aes67_rtp_write_rings(l16, sizeof l16, 97, AES67_FORMAT_L16, 1, 20, rings, NULL) == 2);
    CHECK(aes67_ring_read(&rings[0], (uint32_t) -10, out, 2) == 2 && out[0] == 256 * 256 && out[1] == -256);
    free(rings);
}

static uint32_t ip4(const char *s)
{
    uint32_t v = 0;
    aes67_parse_ipv4(s, &v);
    return v;
}

static aes67_ring_t *new_rings(int n)
{
    aes67_ring_t *r = (aes67_ring_t *) calloc((size_t) n, sizeof *r);
    for (int i = 0; r != NULL && i < n; ++i)
        aes67_ring_init(&r[i]);
    return r;
}

/* The caller-owned receiver: two streams on one port told apart by
   destination, a third by its source; loss, reordering and a wrong payload
   type counted; a removed stream no longer written. */
static void test_netrx_sorts_one_port(void)
{
    char err[128] = { 0 };
    aes67_netrx_t *rx = aes67_netrx_open(NULL, err, sizeof err);
    CHECK(rx != NULL);
    if (rx == NULL)
        return;
    aes67_ring_t *a = new_rings(2), *b = new_rings(1), *c = new_rings(1);

    aes67_netrx_stream_cfg_t ca;
    memset(&ca, 0, sizeof ca);
    ca.group = ip4("239.69.1.1");
    ca.port = 5004;
    ca.payload_type = 96;
    ca.channels = 2;
    ca.media_clock_offset = 1000;
    ca.rings = a;
    aes67_netrx_stream_cfg_t cb = ca;
    cb.group = ip4("239.69.1.2");
    cb.channels = 1;
    cb.media_clock_offset = 0;
    cb.rings = b;
    aes67_netrx_stream_cfg_t cc = cb;
    cc.group = ip4("232.1.1.1");
    cc.source = ip4("192.168.1.20");
    cc.rings = c;

    const int sa = aes67_netrx_add_stream(rx, &ca, err, sizeof err);
    const int sb = sa >= 0 ? aes67_netrx_add_stream(rx, &cb, err, sizeof err) : -1;
    const int sc = sb >= 0 ? aes67_netrx_add_stream(rx, &cc, err, sizeof err) : -1;
    if (sa < 0 || sb < 0 || sc < 0) {
        printf("  netrx sorting skipped: %s (no multicast here?)\n", err);
        aes67_netrx_close(rx);
        free(a); free(b); free(c);
        return;
    }
    CHECK(aes67_netrx_add_stream(rx, &cb, err, sizeof err) < 0);    /* the same stream twice */

    uint8_t pkt[1500];
    const uint32_t src = ip4("192.168.1.10");
    size_t n = build_packet(pkt, sizeof pkt, 96, 1, 5000, 2, 2, 100);
    aes67_netrx_inject(rx, src, ip4("239.69.1.1"), 5004, pkt, n, 1);
    n = build_packet(pkt, sizeof pkt, 96, 7, 9000, 2, 1, 40);
    aes67_netrx_inject(rx, src, ip4("239.69.1.2"), 5004, pkt, n, 2);
    aes67_netrx_inject(rx, src, ip4("239.69.1.2"), 5006, pkt, n, 3);       /* same group, other port: nobody's */
    n = build_packet(pkt, sizeof pkt, 96, 1, 77, 1, 1, 9);
    aes67_netrx_inject(rx, src, ip4("232.1.1.1"), 5004, pkt, n, 4);        /* SSM, wrong source */
    aes67_netrx_inject(rx, ip4("192.168.1.20"), ip4("232.1.1.1"), 5004, pkt, n, 5);

    int32_t out[2];
    /* Indexed by the media clock: RTP 5000 less the offset of 1000. */
    CHECK(aes67_ring_read(&a[0], 4000, out, 2) == 2 && out[0] == 100 && out[1] == 110);
    CHECK(aes67_ring_read(&a[1], 4000, out, 2) == 2 && out[0] == 101);
    CHECK(aes67_ring_read(&b[0], 9000, out, 2) == 2 && out[1] == 50);
    CHECK(aes67_ring_read(&c[0], 77, out, 1) == 1 && out[0] == 9);
    aes67_netrx_stats_t st;
    aes67_netrx_get_stats(rx, sb, &st);
    CHECK(st.packets == 1 && st.last_seq_valid && st.last_seq == 7);
    aes67_netrx_get_stats(rx, sc, &st);
    CHECK(st.packets == 1);
    CHECK(aes67_netrx_foreign_packets(rx) == 2);

    n = build_packet(pkt, sizeof pkt, 96, 4, 5012, 2, 2, 1);               /* 2 and 3 missing */
    aes67_netrx_inject(rx, src, ip4("239.69.1.1"), 5004, pkt, n, 10);
    n = build_packet(pkt, sizeof pkt, 96, 2, 5004, 2, 2, 2);               /* late */
    aes67_netrx_inject(rx, src, ip4("239.69.1.1"), 5004, pkt, n, 11);
    n = build_packet(pkt, sizeof pkt, 97, 5, 5016, 1, 2, 3);
    aes67_netrx_inject(rx, src, ip4("239.69.1.1"), 5004, pkt, n, 12);
    aes67_netrx_inject(rx, src, ip4("239.69.1.1"), 5004, pkt, 5, 13);
    aes67_netrx_get_stats(rx, sa, &st);
    CHECK(st.packets == 3 && st.lost == 2 && st.reordered == 1 && st.wrong_pt == 1 && st.malformed == 1);
    CHECK(aes67_ring_read(&a[0], 4004, out, 1) == 1 && out[0] == 2);       /* the late one still landed */

    aes67_netrx_remove_stream(rx, sb);
    n = build_packet(pkt, sizeof pkt, 96, 8, 9002, 1, 1, 50);
    aes67_netrx_inject(rx, src, ip4("239.69.1.2"), 5004, pkt, n, 14);
    CHECK(aes67_ring_read(&b[0], 9002, out, 1) == 0);
    CHECK(aes67_netrx_add_stream(rx, &cb, err, sizeof err) >= 0);          /* and it can come back */

    aes67_netrx_close(rx);
    free(a); free(b); free(c);
}

/* Real datagrams through the sockets on loopback: two streams on one port,
   started, then one removed while the thread runs. */
static void test_netrx_from_the_wire_if_possible(void)
{
    char err[128] = { 0 };
    aes67_netrx_t *rx = aes67_netrx_open("127.0.0.1", err, sizeof err);
    CHECK(rx != NULL);
    if (rx == NULL)
        return;
    aes67_ring_t *r1 = new_rings(1), *r2 = new_rings(1);
    aes67_netrx_stream_cfg_t c1;
    memset(&c1, 0, sizeof c1);
    c1.group = ip4("239.69.200.1");
    c1.port = 15004;
    c1.payload_type = 98;
    c1.channels = 1;
    c1.rings = r1;
    aes67_netrx_stream_cfg_t c2 = c1;
    c2.group = ip4("239.69.200.2");
    c2.rings = r2;
    const int s1 = aes67_netrx_add_stream(rx, &c1, err, sizeof err);
    const int s2 = s1 >= 0 ? aes67_netrx_add_stream(rx, &c2, err, sizeof err) : -1;

    aes67_tx_cfg_t tcfg;
    memset(&tcfg, 0, sizeof tcfg);
    tcfg.stream_count = 2;
    strcpy(tcfg.iface_ip, "127.0.0.1");
    for (int i = 0; i < 2; ++i) {
        strcpy(tcfg.streams[i].group, i == 0 ? "239.69.200.1" : "239.69.200.2");
        tcfg.streams[i].port = 15004;
        tcfg.streams[i].payload_type = 98;
        tcfg.streams[i].channels = 1;
        tcfg.streams[i].ptime_us = 1000;
    }
    aes67_tx_t *tx = s2 >= 0 ? aes67_tx_open(&tcfg, err, sizeof err) : NULL;
    if (tx == NULL) {
        printf("  netrx from the wire skipped: %s\n", err);
        aes67_netrx_close(rx);
        free(r1); free(r2);
        return;
    }
    CHECK(aes67_netrx_start(rx));
    int32_t frames[48];
    for (int p = 0; p < 20; ++p) {
        for (int i = 0; i < 48; ++i) frames[i] = 1000 + p;
        aes67_tx_send(tx, 0, frames, 48, (uint32_t) p * 48);
        for (int i = 0; i < 48; ++i) frames[i] = -1000 - p;
        aes67_tx_send(tx, 1, frames, 48, (uint32_t) p * 48);
        sleep_ms(1);
    }
    aes67_netrx_stats_t a1, a2;
    memset(&a1, 0, sizeof a1);
    memset(&a2, 0, sizeof a2);
    for (int tries = 0; tries < 200 && (a1.packets < 20 || a2.packets < 20); ++tries) {
        sleep_ms(10);
        aes67_netrx_get_stats(rx, s1, &a1);
        aes67_netrx_get_stats(rx, s2, &a2);
    }
    if (a1.packets == 0 && a2.packets == 0) {
        printf("  netrx from the wire skipped: multicast loopback not delivered\n");
    } else {
        CHECK(a1.packets == 20 && a2.packets == 20 && a1.lost == 0);
        int32_t v = 0;
        CHECK(aes67_ring_read(&r1[0], 48 * 19, &v, 1) == 1 && v == 1019);
        CHECK(aes67_ring_read(&r2[0], 48 * 19, &v, 1) == 1 && v == -1019);
        /* Removed while running: the thread lets go of its rings. */
        aes67_netrx_remove_stream(rx, s2);
        for (int i = 0; i < 48; ++i) frames[i] = 7;
        aes67_tx_send(tx, 1, frames, 48, 48 * 20);
        sleep_ms(50);
        CHECK(aes67_ring_read(&r2[0], 48 * 20, &v, 1) == 0);
    }
    aes67_tx_close(tx);
    aes67_netrx_close(rx);
    free(r1); free(r2);
}

static void test_receive_path_end_to_end(void)
{
    aes67_rx_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.stream_count = 1;
    cfg.cpu = -1;
    strcpy(cfg.streams[0].group, "239.69.1.1");
    cfg.streams[0].port = 5004;
    cfg.streams[0].payload_type = 98;
    cfg.streams[0].channels = 2;
    cfg.streams[0].first_channel = 4;

    char err[128] = { 0 };
    aes67_rx_t *rx = aes67_rx_open(&cfg, err, sizeof err);
    if (rx == NULL) {
        /* No multicast on this machine (a container, a locked-down VM):
           the socket cannot be opened, and that is reported, not hidden. */
        printf("  receive path: socket unavailable (%s) -- exercising the packet path only\n", err);
    }
    /* The packet path does not need the socket; open a receiver that is
       never started if the real one could not be. */
    aes67_rx_t *r = rx;
    if (r == NULL) {
        /* Fall back to a receiver bound to a unicast loopback port so the
           parse and ring path can still be tested here. */
        strcpy(cfg.streams[0].group, "127.0.0.1");
        cfg.streams[0].port = 0;
        r = aes67_rx_open(&cfg, err, sizeof err);
    }
    CHECK(r != NULL);
    if (r == NULL)
        return;

    uint8_t pkt[1500];
    int32_t out[48];

    /* Two packets of 48 frames, in order, land on channels 4 and 5. */
    size_t n = build_packet(pkt, sizeof pkt, 98, 10, 96000, 48, 2, 1000);
    aes67_rx_inject(r, 0, pkt, n, 1000000);
    n = build_packet(pkt, sizeof pkt, 98, 11, 96048, 48, 2, 2000);
    aes67_rx_inject(r, 0, pkt, n, 2000000);

    CHECK(aes67_rx_read(r, 4, 96000, out, 48) == 48);
    CHECK(out[0] == 1000 && out[1] == 1010 && out[47] == 1000 + 470);
    CHECK(aes67_rx_read(r, 5, 96048, out, 48) == 48);
    CHECK(out[0] == 2001);
    CHECK(aes67_rx_playout_ts(r, 0, 48) == 96048);

    aes67_rx_stream_stats_t st;
    aes67_rx_get_stats(r, 0, &st);
    CHECK(st.packets == 2 && st.seq_lost == 0 && st.seq_reordered == 0);
    CHECK(st.jitter_worst_ns == 1000000);

    /* Sequence 13 after 11: one lost; then 12 arrives late: reordered but
       its samples still land where they belong. */
    n = build_packet(pkt, sizeof pkt, 98, 13, 96144, 48, 2, 4000);
    aes67_rx_inject(r, 0, pkt, n, 4000000);
    n = build_packet(pkt, sizeof pkt, 98, 12, 96096, 48, 2, 3000);
    aes67_rx_inject(r, 0, pkt, n, 4100000);
    aes67_rx_get_stats(r, 0, &st);
    CHECK(st.seq_lost == 1 && st.seq_reordered == 1);
    CHECK(aes67_rx_read(r, 4, 96096, out, 48) == 48 && out[0] == 3000);
    CHECK(aes67_rx_playout_ts(r, 0, 0) == 96192);

    /* The wrong payload type and a runt are counted, not delivered. */
    n = build_packet(pkt, sizeof pkt, 97, 14, 96192, 48, 2, 5000);
    aes67_rx_inject(r, 0, pkt, n, 5000000);
    aes67_rx_inject(r, 0, pkt, 5, 5000001);
    aes67_rx_get_stats(r, 0, &st);
    CHECK(st.wrong_pt == 1 && st.too_short == 1);
    CHECK(aes67_rx_read(r, 4, 96192, out, 48) == 0);

    aes67_rx_close(r);
}

static void test_transmit_builds_what_receive_reads(void)
{
    aes67_tx_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.stream_count = 1;
    strcpy(cfg.streams[0].group, "239.69.1.2");
    cfg.streams[0].port = 5004;
    cfg.streams[0].payload_type = 98;
    cfg.streams[0].channels = 2;
    cfg.streams[0].ptime_us = 1000;
    strcpy(cfg.streams[0].name, "Test send");

    char err[128] = { 0 };
    aes67_tx_t *tx = aes67_tx_open(&cfg, err, sizeof err);
    CHECK(tx != NULL);
    if (tx == NULL) {
        printf("  transmit: %s\n", err);
        return;
    }

    /* Sequence numbers advance per packet built, and the packet is one a
       receiver parses back to the same samples. */
    int32_t frames[48 * 2];
    for (int i = 0; i < 96; ++i)
        frames[i] = i - 48;
    uint8_t pkt[1500];
    size_t n = aes67_tx_build(tx, 0, frames, 48, 48000, pkt, sizeof pkt);
    CHECK(n == 12 + 48 * 2 * 3);
    aes67_rtp_header_t h;
    CHECK(aes67_rtp_parse_header(pkt, n, &h));
    CHECK(h.sequence == 0 && h.timestamp == 48000 && h.payload_type == 98);
    n = aes67_tx_build(tx, 0, frames, 48, 48048, pkt, sizeof pkt);
    CHECK(aes67_rtp_parse_header(pkt, n, &h) && h.sequence == 1);
    CHECK(aes67_l24_to_i32(pkt + 12) == -48);
    CHECK(aes67_l24_to_i32(pkt + 12 + 95 * 3) == 47);

    /* Too many frames for one packet (300 x 2 x 3 = 1800 B, past the 1440
       ceiling): refused, sequence untouched. */
    int32_t big[300 * 2];
    memset(big, 0, sizeof big);
    CHECK(aes67_tx_build(tx, 0, big, 300, 0, pkt, sizeof pkt) == 0);
    n = aes67_tx_build(tx, 0, frames, 48, 48096, pkt, sizeof pkt);
    CHECK(aes67_rtp_parse_header(pkt, n, &h) && h.sequence == 2);

    char sdp[1024];
    CHECK(aes67_tx_sdp(tx, 0, sdp, sizeof sdp) > 0);
    CHECK(strstr(sdp, "s=Test send\r\n") != NULL);
    CHECK(strstr(sdp, "m=audio 5004 RTP/AVP 98\r\n") != NULL);

    aes67_tx_close(tx);
}

/* Real sockets, when the machine allows multicast on a loopback. Skipped
   loudly otherwise: a test that cannot run says so rather than passing. */
static void test_socket_round_trip_if_possible(void)
{
    aes67_rx_cfg_t rcfg;
    memset(&rcfg, 0, sizeof rcfg);
    rcfg.stream_count = 1;
    rcfg.cpu = -1;
    strcpy(rcfg.iface_ip, "127.0.0.1");
    strcpy(rcfg.streams[0].group, "239.69.7.7");
    rcfg.streams[0].port = 5107;
    rcfg.streams[0].payload_type = 98;
    rcfg.streams[0].channels = 2;
    rcfg.streams[0].first_channel = 0;

    aes67_tx_cfg_t tcfg;
    memset(&tcfg, 0, sizeof tcfg);
    tcfg.stream_count = 1;
    strcpy(tcfg.iface_ip, "127.0.0.1");
    strcpy(tcfg.streams[0].group, "239.69.7.7");
    tcfg.streams[0].port = 5107;
    tcfg.streams[0].payload_type = 98;
    tcfg.streams[0].channels = 2;
    tcfg.streams[0].ptime_us = 1000;

    char err[128] = { 0 };
    aes67_rx_t *rx = aes67_rx_open(&rcfg, err, sizeof err);
    if (rx == NULL) {
        printf("  socket round trip skipped: %s\n", err);
        return;
    }
    aes67_tx_t *tx = aes67_tx_open(&tcfg, err, sizeof err);
    if (tx == NULL) {
        printf("  socket round trip skipped: %s\n", err);
        aes67_rx_close(rx);
        return;
    }
    CHECK(aes67_rx_start(rx));

    int32_t frames[48 * 2];
    for (int i = 0; i < 96; ++i)
        frames[i] = 7000 + i;
    int sent = 0;
    for (int p = 0; p < 20; ++p) {
        if (aes67_tx_send(tx, 0, frames, 48, 480000 + (uint32_t) p * 48))
            ++sent;
        sleep_ms(1);
    }
    CHECK(sent == 20);

    /* Give the receive thread a moment, then the samples are in the ring. */
    aes67_rx_stream_stats_t st;
    memset(&st, 0, sizeof st);
    for (int tries = 0; tries < 100 && st.packets < 20; ++tries) {
        sleep_ms(10);
        aes67_rx_get_stats(rx, 0, &st);
    }
    if (st.packets == 0) {
        /* Multicast loopback delivered nothing: the OS does not route it
           here (some VMs, some containers). Not a fault in the library. */
        printf("  socket round trip skipped: multicast loopback not delivered\n");
    } else {
        CHECK(st.packets == 20);
        int32_t out[48];
        CHECK(aes67_rx_read(rx, 1, 480000, out, 48) == 48);
        CHECK(out[0] == 7001);
        CHECK(aes67_tx_packets_sent(tx, 0) == 20);
    }
    aes67_rx_stop(rx);
    aes67_tx_close(tx);
    aes67_rx_close(rx);
}

/* ---- SDP parsing ---------------------------------------------------------
   The goldens below are the forms the standards and the common senders
   write (AES67 Annex, ST 2110-30/-31, RAVENNA, Dante), hand-written from
   their documentation. They are NOT captures from real devices: none exist
   in the repository yet; that waits until a third-party box has been put on
   the bench. */

static const char kAes67Sdp[] =
    "v=0\r\n"
    "o=- 1311738121 1311738121 IN IP4 192.168.1.10\r\n"
    "s=Stage box 1-8\r\n"
    "c=IN IP4 239.69.1.1/32\r\n"
    "t=0 0\r\n"
    "a=clock-domain:PTPv2 0\r\n"
    "m=audio 5004 RTP/AVP 98\r\n"
    "i=Channels 1-8\r\n"
    "a=rtpmap:98 L24/48000/8\r\n"
    "a=sync-time:0\r\n"
    "a=ptime:1\r\n"
    "a=mediaclk:direct=963214424\r\n"
    "a=ts-refclk:ptp=IEEE1588-2008:00-1D-C1-FF-FE-12-34-56:0\r\n"
    "a=recvonly\r\n";

static const char kSt2110_30Sdp[] =
    "v=0\n"
    "o=- 123456 11 IN IP4 192.168.100.2\n"
    "s=Example of a SMPTE ST2110-30 signal\n"
    "i=this example is for 48kHz audio with 8 channels in 125 us packets\n"
    "t=0 0\n"
    "a=recvonly\n"
    "a=group:DUP primary secondary\n"
    "m=audio 5004 RTP/AVP 97\n"
    "c=IN IP4 239.100.9.10/32\n"
    "a=source-filter: incl IN IP4 239.100.9.10 192.168.100.2\n"
    "a=rtpmap:97 L24/48000/8\n"
    "a=fmtp:97 channel-order=SMPTE2110.(ST)\n"
    "a=ptime:0.125\n"
    "a=maxptime:0.125\n"
    "a=ts-refclk:ptp=IEEE1588-2008:39-A7-94-FF-FE-07-CB-D0:127\n"
    "a=mediaclk:direct=0\n"
    "a=mid:primary\n"
    "m=audio 5004 RTP/AVP 97\n"
    "c=IN IP4 239.101.9.10/32\n"
    "a=rtpmap:97 L24/48000/8\n"
    "a=mid:secondary\n";

static const char kSt2110_31Sdp[] =
    "v=0\r\n"
    "o=- 1 1 IN IP4 10.0.0.5\r\n"
    "s=AES3 transparent\r\n"
    "c=IN IP4 239.200.1.1/64\r\n"
    "t=0 0\r\n"
    "m=audio 5004 RTP/AVP 99\r\n"
    "a=rtpmap:99 AM824/48000/2\r\n"
    "a=ptime:1\r\n"
    "a=ts-refclk:ptp=IEEE1588-2008:traceable\r\n"
    "a=mediaclk:direct=0\r\n";

static const char kDanteSdp[] =
    "v=0\r\n"
    "o=- 1601 0 IN IP4 169.254.30.4\r\n"
    "s=DESK-1 : 2\r\n"
    "c=IN IP4 239.69.40.11/32\r\n"
    "t=0 0\r\n"
    "a=keywds:Dante\r\n"
    "a=recvonly\r\n"
    "m=audio 5004 RTP/AVP 97\r\n"
    "a=rtpmap:97 L24/48000/2\r\n"
    "a=ptime:1\r\n"
    "a=ts-refclk:ptp=IEEE1588-2008:00-1D-C1-FF-FE-AA-BB-CC:0\r\n"
    "a=mediaclk:direct=0\r\n";

static const char kRavennaSdp[] =
    "v=0\r\n"
    "o=- 1614 1614 IN IP4 192.168.20.7\r\n"
    "s=Merging Anubis - 1\r\n"
    "c=IN IP4 239.1.20.7/15\r\n"
    "t=0 0\r\n"
    "a=clock-domain:PTPv2 0\r\n"
    "m=audio 5004 RTP/AVP 98\r\n"
    "c=IN IP4 239.1.20.7/15\r\n"
    "a=rtpmap:98 L24/48000/2\r\n"
    "a=sync-time:0\r\n"
    "a=framecount:48\r\n"
    "a=ptime:1\r\n"
    "a=mediaclk:direct=0\r\n"
    "a=ts-refclk:ptp=IEEE1588-2008:00-1D-C1-FF-FE-AB-CD-EF:0\r\n"
    "a=recvonly\r\n";

/* Real AES67 sends every stream to 5004 and tells them apart by group. Two
   receivers in one process, three streams on one port: each stream gets its
   own packets and nothing else -- on Windows and macOS by the destination
   address the socket reports, on Linux by binding each socket to its group. */
static void test_streams_share_one_port_if_possible(void)
{
    static const char *groups[3] = { "239.69.7.8", "239.69.7.9", "239.69.7.10" };
    aes67_rx_cfg_t a;
    memset(&a, 0, sizeof a);
    a.stream_count = 2;
    a.cpu = -1;
    a.shared_port = true;
    strcpy(a.iface_ip, "127.0.0.1");
    for (int i = 0; i < 2; ++i) {
        strcpy(a.streams[i].group, groups[i]);
        a.streams[i].port = 5108;
        a.streams[i].payload_type = 98;
        a.streams[i].channels = 2;
        a.streams[i].first_channel = i * 2;
    }
    aes67_rx_cfg_t b = a;
    b.stream_count = 1;
    strcpy(b.streams[0].group, groups[2]);
    b.streams[0].first_channel = 0;

    aes67_tx_cfg_t tcfg;
    memset(&tcfg, 0, sizeof tcfg);
    tcfg.stream_count = 3;
    strcpy(tcfg.iface_ip, "127.0.0.1");
    for (int i = 0; i < 3; ++i) {
        strcpy(tcfg.streams[i].group, groups[i]);
        tcfg.streams[i].port = 5108;
        tcfg.streams[i].payload_type = 98;
        tcfg.streams[i].channels = 2;
        tcfg.streams[i].ptime_us = 1000;
    }

    char err[128] = { 0 };
    aes67_rx_t *rxa = aes67_rx_open(&a, err, sizeof err);
    aes67_rx_t *rxb = rxa ? aes67_rx_open(&b, err, sizeof err) : NULL;
    aes67_tx_t *tx = rxb ? aes67_tx_open(&tcfg, err, sizeof err) : NULL;
    if (tx == NULL) {
        printf("  shared port skipped: %s\n", err);
        if (rxb) aes67_rx_close(rxb);
        if (rxa) aes67_rx_close(rxa);
        return;
    }
    CHECK(aes67_rx_start(rxa));
    CHECK(aes67_rx_start(rxb));

    int32_t frames[48 * 2];
    for (int p = 0; p < 20; ++p)
        for (int k = 0; k < 3; ++k) {
            for (int i = 0; i < 96; ++i)
                frames[i] = (k + 1) * 100000 + i;
            aes67_tx_send(tx, k, frames, 48, 960000 + (uint32_t) p * 48);
            if (k == 2)
                sleep_ms(1);
        }

    aes67_rx_stream_stats_t s0, s1, s2;
    memset(&s0, 0, sizeof s0);
    memset(&s1, 0, sizeof s1);
    memset(&s2, 0, sizeof s2);
    for (int tries = 0; tries < 100 && (s0.packets < 20 || s1.packets < 20 || s2.packets < 20); ++tries) {
        sleep_ms(10);
        aes67_rx_get_stats(rxa, 0, &s0);
        aes67_rx_get_stats(rxa, 1, &s1);
        aes67_rx_get_stats(rxb, 0, &s2);
    }
    if (s0.packets == 0 && s1.packets == 0 && s2.packets == 0) {
        printf("  shared port skipped: multicast loopback not delivered\n");
    } else {
        /* Exactly its own twenty each: a stream fed another's packets would
           count them (and the samples below would be the other's). */
        CHECK(s0.packets == 20);
        CHECK(s1.packets == 20);
        CHECK(s2.packets == 20);
        int32_t out[48];
        CHECK(aes67_rx_read(rxa, 0, 960000, out, 48) == 48);
        CHECK(out[0] == 100000);
        CHECK(aes67_rx_read(rxa, 2, 960000, out, 48) == 48);
        CHECK(out[0] == 200000);
        CHECK(aes67_rx_read(rxb, 1, 960000, out, 48) == 48);
        CHECK(out[0] == 300001);
        printf("  shared port: %llu + %llu packets for other receivers dropped\n",
               (unsigned long long) aes67_rx_foreign_packets(rxa),
               (unsigned long long) aes67_rx_foreign_packets(rxb));
    }
    aes67_rx_stop(rxb);
    aes67_rx_stop(rxa);
    aes67_tx_close(tx);
    aes67_rx_close(rxb);
    aes67_rx_close(rxa);
}

static void test_sdp_parses_the_common_forms(void)
{
    aes67_sdp_t s;
    char err[128];
    const uint8_t gm1[8] = { 0x00, 0x1D, 0xC1, 0xFF, 0xFE, 0x12, 0x34, 0x56 };
    const uint8_t gm2[8] = { 0x39, 0xA7, 0x94, 0xFF, 0xFE, 0x07, 0xCB, 0xD0 };

    /* AES67 */
    CHECK(aes67_sdp_parse(kAes67Sdp, strlen(kAes67Sdp), &s, err, sizeof err));
    CHECK(strcmp(s.session_name, "Stage box 1-8") == 0);
    CHECK(strcmp(s.origin_ip, "192.168.1.10") == 0);
    CHECK(strcmp(s.connection_ip, "239.69.1.1") == 0 && s.connection_ttl == 32);
    CHECK(s.port == 5004 && s.payload_type == 98);
    CHECK(strcmp(s.encoding, "L24") == 0 && s.sample_rate == 48000 && s.channels == 8);
    CHECK(s.ptime_us == 1000);
    CHECK(s.mediaclk_direct && s.mediaclk_offset == 963214424);
    CHECK(s.refclk_ptp && s.gm_known && memcmp(s.gm_identity, gm1, 8) == 0 && s.ptp_domain == 0);
    CHECK(strcmp(s.ptp_version, "IEEE1588-2008") == 0);
    CHECK(s.direction == AES67_SDP_RECVONLY);
    CHECK(!s.is_st2110_31 && s.source_ip[0] == '\0');

    /* ST 2110-30 with 2022-7 duplication: the first media section is the
       stream; the secondary is left for the caller. */
    CHECK(aes67_sdp_parse(kSt2110_30Sdp, strlen(kSt2110_30Sdp), &s, err, sizeof err));
    CHECK(strcmp(s.connection_ip, "239.100.9.10") == 0);
    CHECK(strcmp(s.source_ip, "192.168.100.2") == 0);
    CHECK(s.channels == 8 && s.ptime_us == 125 && s.maxptime_us == 125);
    CHECK(strcmp(s.channel_order, "SMPTE2110.(ST)") == 0);
    CHECK(s.gm_known && memcmp(s.gm_identity, gm2, 8) == 0 && s.ptp_domain == 127);
    CHECK(s.direction == AES67_SDP_RECVONLY);

    /* ST 2110-31: AES3 transparent, traceable clock. */
    CHECK(aes67_sdp_parse(kSt2110_31Sdp, strlen(kSt2110_31Sdp), &s, err, sizeof err));
    CHECK(s.is_st2110_31 && strcmp(s.encoding, "AM824") == 0 && s.channels == 2);
    CHECK(s.refclk_ptp && s.gm_traceable && !s.gm_known);
    CHECK(s.connection_ttl == 64);

    /* Dante */
    CHECK(aes67_sdp_parse(kDanteSdp, strlen(kDanteSdp), &s, err, sizeof err));
    CHECK(strcmp(s.session_name, "DESK-1 : 2") == 0);
    CHECK(s.channels == 2 && s.payload_type == 97 && s.gm_known && s.ptp_domain == 0);

    /* RAVENNA, with framecount and a media-level c= repeating the session's. */
    CHECK(aes67_sdp_parse(kRavennaSdp, strlen(kRavennaSdp), &s, err, sizeof err));
    CHECK(s.framecount == 48 && s.connection_ttl == 15);
    CHECK(strcmp(s.connection_ip, "239.1.20.7") == 0);

    /* What we generate, we parse back to the same facts. */
    aes67_sdp_params_t p;
    memset(&p, 0, sizeof p);
    p.session_name = "Round trip";
    p.origin_ip = "10.1.1.1";
    p.group = "239.10.10.10";
    p.port = 5006;
    p.payload_type = 96;
    p.channels = 4;
    p.sample_rate = 96000;
    p.ptime_us = 250;
    p.ssrc = 7;
    p.ttl = 8;
    memcpy(p.gm_identity, gm1, 8);
    p.ptp_domain = 5;
    char text[1024];
    aes67_sdp_write(text, sizeof text, &p);
    CHECK(aes67_sdp_parse(text, strlen(text), &s, err, sizeof err));
    CHECK(strcmp(s.session_name, "Round trip") == 0 && s.port == 5006 && s.payload_type == 96);
    CHECK(s.channels == 4 && s.sample_rate == 96000 && s.ptime_us == 250 && s.connection_ttl == 8);
    CHECK(s.gm_known && memcmp(s.gm_identity, gm1, 8) == 0 && s.ptp_domain == 5);
    CHECK(s.mediaclk_direct && s.mediaclk_offset == 0);
}

static void test_sdp_refuses_only_what_it_must(void)
{
    aes67_sdp_t s;
    char err[128];

    /* No audio at all: refused, and it says so. */
    const char video[] = "v=0\r\nm=video 5000 RTP/AVP 96\r\na=rtpmap:96 raw/90000\r\n";
    CHECK(!aes67_sdp_parse(video, strlen(video), &s, err, sizeof err));
    CHECK(strstr(err, "no audio") != NULL);
    CHECK(!aes67_sdp_parse("", 0, &s, err, sizeof err));

    /* An rtpmap for another payload type is not ours; missing ours leaves
       the rate at zero for the caller to notice, rather than a refusal. */
    const char odd[] = "v=0\r\nm=audio 5004 RTP/AVP 98\r\na=rtpmap:97 L16/44100/2\r\na=x-vendor:whatever\r\n";
    CHECK(aes67_sdp_parse(odd, strlen(odd), &s, err, sizeof err));
    CHECK(s.sample_rate == 0 && s.encoding[0] == '\0');

    /* A sender's own clock, not PTP: parsed, and never "shares" ours. */
    const char localmac[] = "v=0\r\nm=audio 5004 RTP/AVP 98\r\na=rtpmap:98 L24/48000/2\r\na=ts-refclk:localmac=00-11-22-33-44-55\r\n";
    CHECK(aes67_sdp_parse(localmac, strlen(localmac), &s, err, sizeof err));
    CHECK(s.refclk_localmac && !s.refclk_ptp);
}

static void test_grandmaster_agreement_is_strict(void)
{
    aes67_sdp_t s;
    char err[128];
    const uint8_t ours[8] = { 0x00, 0x1D, 0xC1, 0xFF, 0xFE, 0x12, 0x34, 0x56 };
    const uint8_t theirs[8] = { 0x39, 0xA7, 0x94, 0xFF, 0xFE, 0x07, 0xCB, 0xD0 };
    const uint8_t none[8] = { 0 };

    CHECK(aes67_sdp_parse(kAes67Sdp, strlen(kAes67Sdp), &s, err, sizeof err));
    CHECK(aes67_sdp_shares_grandmaster(&s, ours, 0));       /* same clock, same domain */
    CHECK(!aes67_sdp_shares_grandmaster(&s, ours, 1));      /* same clock, other domain */
    CHECK(!aes67_sdp_shares_grandmaster(&s, theirs, 0));    /* the mismatch the UI must show */
    CHECK(!aes67_sdp_shares_grandmaster(&s, none, 0));      /* we have no lock at all */

    /* Traceable: any clock in the domain will do. */
    CHECK(aes67_sdp_parse(kSt2110_31Sdp, strlen(kSt2110_31Sdp), &s, err, sizeof err));
    CHECK(aes67_sdp_shares_grandmaster(&s, ours, 0));
    CHECK(!aes67_sdp_shares_grandmaster(&s, ours, 3));

    /* Silence about the clock is not agreement. */
    const char mute[] = "v=0\r\nm=audio 5004 RTP/AVP 98\r\na=rtpmap:98 L24/48000/2\r\n";
    CHECK(aes67_sdp_parse(mute, strlen(mute), &s, err, sizeof err));
    CHECK(!aes67_sdp_shares_grandmaster(&s, ours, 0));
}

/* A ring primes on its first frame whatever the timestamp: senders start
   RTP timestamps at random and half of them are past 2^31. */
static void test_ring_primes_on_a_high_timestamp(void)
{
    static aes67_ring_t ring;
    aes67_ring_init(&ring);
    const uint32_t start = 0x9ABCDEF0u;
    for (uint32_t f = 0; f < 96; ++f)
        aes67_ring_write(&ring, start + f, (int32_t) (f + 1));
    CHECK(aes67_ring_head(&ring) == start + 96);
    int32_t out[48];
    CHECK(aes67_ring_read(&ring, start + 48, out, 48) == 48);
    CHECK(out[0] == 49 && out[47] == 96);
    /* and a ring that starts just below wrap keeps counting past it */
    aes67_ring_init(&ring);
    for (uint32_t f = 0; f < 96; ++f)
        aes67_ring_write(&ring, 0xFFFFFFF0u + f, (int32_t) (f + 1));
    CHECK(aes67_ring_head(&ring) == 0xFFFFFFF0u + 96);
    CHECK(aes67_ring_read(&ring, 0xFFFFFFF0u + 40, out, 48) == 48);
    CHECK(out[0] == 41);
}

static void test_media_clock_is_ptp_time(void)
{
    /* a=mediaclk:direct=0: the timestamp is PTP seconds times the rate. */
    CHECK(aes67_media_clock_ts(0, 48000) == 0);
    CHECK(aes67_media_clock_ts(1000000000u, 48000) == 48000);
    CHECK(aes67_media_clock_ts(1500000000u, 48000) == 72000);
    CHECK(aes67_media_clock_ts(20833u, 48000) == 0);     /* just under one frame */
    CHECK(aes67_media_clock_ts(20834u, 48000) == 1);
    /* 2026 in TAI: wraps modulo 2^32 exactly as (sec*rate + frac) would. */
    {
        const uint64_t sec = 1790000000u, frac = 123456789u;
        const uint64_t frames = sec * 48000u + frac * 48000u / 1000000000u;
        CHECK(aes67_media_clock_ts(sec * 1000000000u + frac, 48000) == (uint32_t) frames);
    }
    CHECK(aes67_media_clock_ts(1000000000u, 96000) == 96000);
}

static void test_sdp_names_every_2110_essence(void)
{
    aes67_sdp_t s;
    char err[160];
    static const char video[] =
        "v=0\r\no=- 1 1 IN IP4 10.0.0.9\r\ns=Camera 1\r\nc=IN IP4 239.100.0.1/32\r\nt=0 0\r\n"
        "m=video 5000 RTP/AVP 96\r\na=rtpmap:96 raw/90000\r\na=fmtp:96 sampling=YCbCr-4:2:2; width=1920\r\n"
        "a=ts-refclk:ptp=IEEE1588-2008:traceable\r\n";
    CHECK(!aes67_sdp_parse(video, sizeof video - 1, &s, err, sizeof err));
    CHECK(strcmp(s.essence, "ST 2110-20 video") == 0);
    CHECK(strstr(err, "ST 2110-20 video") != NULL);
    CHECK(strcmp(s.session_name, "Camera 1") == 0 && strcmp(s.connection_ip, "239.100.0.1") == 0 && s.other_port == 5000);
    CHECK(!s.refclk_ptp);   /* another essence's clock line is not taken as ours */

    static const char xs[] = "v=0\r\ns=XS\r\nc=IN IP4 239.100.0.2/32\r\nm=video 5000 RTP/AVP 112\r\na=rtpmap:112 jxsv/90000\r\n";
    CHECK(!aes67_sdp_parse(xs, sizeof xs - 1, &s, err, sizeof err) && strcmp(s.essence, "ST 2110-22 video (JPEG XS)") == 0);
    static const char anc[] = "v=0\r\ns=ANC\r\nc=IN IP4 239.100.0.3/32\r\nm=video 5000 RTP/AVP 100\r\na=rtpmap:100 smpte291/90000\r\n";
    CHECK(!aes67_sdp_parse(anc, sizeof anc - 1, &s, err, sizeof err) && strcmp(s.essence, "ST 2110-40 ancillary data") == 0);

    /* Video first, audio second: the audio is ours and the video left alone. */
    static const char both[] =
        "v=0\r\ns=Both\r\nc=IN IP4 239.100.0.4/32\r\nm=video 5000 RTP/AVP 96\r\na=rtpmap:96 raw/90000\r\n"
        "m=audio 5004 RTP/AVP 97\r\na=rtpmap:97 L24/48000/2\r\na=ptime:1\r\n";
    CHECK(aes67_sdp_parse(both, sizeof both - 1, &s, err, sizeof err));
    CHECK(s.port == 5004 && s.channels == 2 && strcmp(s.essence, "AES67 audio (L24)") == 0);

    static const char aes3[] = "v=0\r\ns=AES3\r\nc=IN IP4 239.100.0.5/32\r\nm=audio 5004 RTP/AVP 97\r\na=rtpmap:97 AM824/48000/2\r\n";
    CHECK(aes67_sdp_parse(aes3, sizeof aes3 - 1, &s, err, sizeof err) && s.is_st2110_31 && strcmp(s.essence, "ST 2110-31 AES3") == 0);
}

static void test_receive_decodes_l16_and_am824(void)
{
    aes67_sample_format_t f;
    CHECK(aes67_format_from_encoding("L16", &f) && f == AES67_FORMAT_L16 && aes67_format_bytes(f) == 2);
    CHECK(aes67_format_from_encoding("AM824", &f) && f == AES67_FORMAT_AM824 && aes67_format_bytes(f) == 4);
    CHECK(aes67_format_from_encoding("L24", &f) && f == AES67_FORMAT_L24 && aes67_format_bytes(f) == 3);
    CHECK(!aes67_format_from_encoding("opus", &f));

    for (int which = 0; which < 2; ++which) {
        aes67_rx_cfg_t cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.stream_count = 1;
        cfg.cpu = -1;
        strcpy(cfg.streams[0].group, "239.69.1.9");
        cfg.streams[0].port = 5004;
        cfg.streams[0].payload_type = 97;
        cfg.streams[0].channels = 2;
        cfg.streams[0].format = which == 0 ? AES67_FORMAT_L16 : AES67_FORMAT_AM824;
        char err[128];
        aes67_rx_t *rx = aes67_rx_open(&cfg, err, sizeof err);
        if (rx == NULL) {
            /* No multicast here: the packet path works the same on loopback. */
            strcpy(cfg.streams[0].group, "127.0.0.1");
            rx = aes67_rx_open(&cfg, err, sizeof err);
        }
        CHECK(rx != NULL);
        if (rx == NULL)
            continue;
        uint8_t pkt[AES67_RTP_HEADER_BYTES + 4 * 2 * 4];
        aes67_rtp_header_t h = { 0 };
        h.payload_type = 97;
        h.sequence = 1;
        h.timestamp = 1000;
        h.ssrc = 7;
        aes67_rtp_write_header(pkt, &h);
        uint8_t *d = pkt + AES67_RTP_HEADER_BYTES;
        const int bps = which == 0 ? 2 : 4;
        for (int fr = 0; fr < 4; ++fr)
            for (int c = 0; c < 2; ++c, d += bps) {
                const int32_t v24 = (c == 0 ? 1 : -1) * (fr + 1) * 4096;   /* a 24-bit value, a multiple of 256 */
                if (which == 0) {
                    const int16_t v16 = (int16_t) (v24 / 256);
                    d[0] = (uint8_t) ((uint16_t) v16 >> 8);
                    d[1] = (uint8_t) v16;
                } else {
                    d[0] = (uint8_t) (fr == 0 && c == 0 ? 0x10 : 0x00);   /* AES3 flags: ignored by the decoder */
                    aes67_i32_to_l24(v24, d + 1);
                }
            }
        aes67_rx_inject(rx, 0, pkt, AES67_RTP_HEADER_BYTES + (size_t) (4 * 2 * bps), 1);
        int32_t out[4];
        CHECK(aes67_rx_read(rx, 0, 1000, out, 4) == 4);
        CHECK(out[0] == 4096 && out[3] == 4 * 4096);
        CHECK(aes67_rx_read(rx, 1, 1000, out, 4) == 4);
        CHECK(out[0] == -4096 && out[3] == -4 * 4096);
        aes67_rx_close(rx);
    }
}

/* No channel ceiling but the packet's: 16 channels do not fit a 1 ms
   packet and are refused there, go at 125 us, and every one of them lands in
   its own ring on the far side -- which a fixed table of 8 per stream once
   made impossible. */
static void test_wide_streams_are_bounded_by_the_packet(void)
{
    CHECK(aes67_max_channels(3, 48) == 10);   /* L24, 1 ms at 48 kHz */
    CHECK(aes67_max_channels(3, 6) == 80);    /* L24, 125 us */
    CHECK(aes67_max_channels(2, 6) == 120);   /* L16, 125 us */
    CHECK(aes67_max_channels(3, 0) == 0);

    aes67_tx_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.stream_count = 1;
    strcpy(cfg.streams[0].group, "239.69.1.3");
    cfg.streams[0].port = 5004;
    cfg.streams[0].payload_type = 98;
    cfg.streams[0].channels = 16;
    cfg.streams[0].ptime_us = 1000;
    strcpy(cfg.streams[0].name, "Wide");
    char err[160] = { 0 };
    aes67_tx_t *tx = aes67_tx_open(&cfg, err, sizeof err);
    CHECK(tx == NULL && strstr(err, "do not fit") != NULL);
    aes67_tx_close(tx);

    cfg.streams[0].ptime_us = 125;
    tx = aes67_tx_open(&cfg, err, sizeof err);
    CHECK(tx != NULL);
    if (tx == NULL) {
        printf("  wide transmit: %s\n", err);
        return;
    }
    int32_t frames[6 * 16];
    for (int f = 0; f < 6; ++f)
        for (int c = 0; c < 16; ++c)
            frames[f * 16 + c] = (c + 1) * 1000 + f;
    uint8_t pkt[1500];
    const size_t n = aes67_tx_build(tx, 0, frames, 6, 480, pkt, sizeof pkt);
    CHECK(n == 12 + 6 * 16 * 3);
    aes67_tx_close(tx);

    aes67_rx_cfg_t rc;
    memset(&rc, 0, sizeof rc);
    rc.stream_count = 1;
    rc.cpu = -1;
    strcpy(rc.streams[0].group, "239.69.1.3");
    rc.streams[0].port = 5004;
    rc.streams[0].payload_type = 98;
    rc.streams[0].channels = 16;
    aes67_rx_t *rx = aes67_rx_open(&rc, err, sizeof err);
    if (rx == NULL) {
        /* No multicast here: a unicast loopback receiver runs the same
           packet path (as test_receive_path_end_to_end does). */
        strcpy(rc.streams[0].group, "127.0.0.1");
        rc.streams[0].port = 0;
        rx = aes67_rx_open(&rc, err, sizeof err);
    }
    CHECK(rx != NULL);
    if (rx == NULL) {
        printf("  wide receive: %s\n", err);
        return;
    }
    aes67_rx_inject(rx, 0, pkt, n, 1);
    int32_t out[6];
    CHECK(aes67_rx_read(rx, 15, 480, out, 6) == 6);
    CHECK(out[0] == 16000 && out[5] == 16005);
    CHECK(aes67_rx_read(rx, 0, 480, out, 6) == 6 && out[3] == 1003);
    CHECK(aes67_rx_read(rx, 16, 480, out, 6) == 0);   /* past what the stream carries */
    aes67_rx_close(rx);
}

int main(void)
{
    test_sdp_names_every_2110_essence();
    test_receive_decodes_l16_and_am824();
    test_media_clock_is_ptp_time();
    test_ring_primes_on_a_high_timestamp();
    test_rtp_header_round_trips();
    test_l24_is_exact_and_signed();
    test_pack_respects_the_mtu();
    test_ring_is_timestamp_indexed();
    test_sdp_says_what_a_receiver_needs();
    test_packets_into_the_callers_rings();
    test_netrx_sorts_one_port();
    test_netrx_from_the_wire_if_possible();
    test_receive_path_end_to_end();
    test_transmit_builds_what_receive_reads();
    test_socket_round_trip_if_possible();
    test_streams_share_one_port_if_possible();
    test_sdp_parses_the_common_forms();
    test_sdp_refuses_only_what_it_must();
    test_grandmaster_agreement_is_strict();
    test_wide_streams_are_bounded_by_the_packet();

    if (failures) {
        printf("aes67: %d/%d checks FAILED\n", failures, checks);
        return 1;
    }
    printf("aes67: %d checks passed\n", checks);
    return 0;
}
