/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libaes67 receive. See rx.h.
 *
 * Real AES67 puts every stream on one port (5004) and tells them apart by
 * multicast group. Linux binds a socket to each group, which does the sorting
 * in the kernel, and reads it with recvmmsg and kernel timestamps. Everywhere
 * else this receiver runs on aes67_netrx: one socket per port, every group
 * joined on it, each packet sorted by its destination address (and, on
 * Windows, received through an I/O completion port). Its rings are this
 * receiver's, handed to aes67_netrx as the caller's.
 *
 * The packet path is aes67_rtp_write_rings either way; on Linux the
 * statistics are kept here, elsewhere aes67_netrx keeps them. */

#if defined(__linux__)
#  define _GNU_SOURCE
#endif

#include "aes67/rx.h"
#include "aes67/netrx.h"
#include "platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#  include <sched.h>
#  include <sys/epoll.h>
#  include <sys/uio.h>
#endif

#define BATCH 64

typedef struct aes67_rx_stream {
    aes67_rx_stream_cfg_t   cfg;
    uint32_t                group_addr;    /* the group, network order */
#if defined(__linux__)
    aes67_sock_t            fd;
    uint16_t                last_seq;
    bool                    have_seq;
    uint64_t                last_arr_ns;
    aes67_rx_stream_stats_t stats;
#else
    int                     slot;          /* in rx->net */
#endif
} aes67_rx_stream_t;

struct aes67_rx {
    aes67_rx_cfg_t    cfg;
    aes67_rx_stream_t streams[AES67_RX_MAX_STREAMS];
    aes67_ring_t     *rings;        /* one per channel the streams carry */
    int               ring_count;
#if defined(__linux__)
    int               epfd;
    aes67_thread_t    thread;
    bool              have_thread;
    aes67_atomic_u64  running;
#else
    aes67_netrx_t    *net;
#endif
};

#if defined(__linux__)

/* ---- the packet path ------------------------------------------------------ */

static void process_packet(aes67_rx_t *rx, aes67_rx_stream_t *s, const uint8_t *p, size_t len,
                           uint64_t arr_ns)
{
    aes67_rx_stream_stats_t *st = &s->stats;
    aes67_rtp_header_t h;
    /* The rings are this receiver's, one per channel the streams carry; the
       stream's start at its first channel, indexed by RTP timestamp. */
    const int got = aes67_rtp_write_rings(p, len, s->cfg.payload_type, (aes67_sample_format_t) s->cfg.format,
                                          s->cfg.channels, 0, rx->rings + s->cfg.first_channel, &h);
    if (got == AES67_PACKET_MALFORMED) { st->too_short++; return; }
    if (got == AES67_PACKET_WRONG_PT) { st->wrong_pt++; return; }

    if (s->have_seq) {
        const uint16_t expect = (uint16_t) (s->last_seq + 1);
        if (h.sequence != expect) {
            const int16_t d = (int16_t) (h.sequence - expect);
            if (d > 0) st->seq_lost += (uint64_t) d;
            else       st->seq_reordered++;   /* still delivered: the ring is timestamp-indexed */
        }
    }
    s->last_seq = h.sequence;
    s->have_seq = true;
    st->last_seq = h.sequence;
    st->last_seq_valid = 1;

    if (s->last_arr_ns && arr_ns > s->last_arr_ns) {
        const uint64_t gap = arr_ns - s->last_arr_ns;
        if (gap > st->jitter_worst_ns)
            st->jitter_worst_ns = gap;
    }
    s->last_arr_ns = arr_ns;
    st->packets++;
    st->bytes += (uint64_t) len;
}

/* ---- sockets: one per stream, bound to its group ---------------------------- */

static aes67_sock_t open_stream_socket(const aes67_rx_cfg_t *cfg, const aes67_rx_stream_cfg_t *sc,
                                       char *errbuf, size_t errlen)
{
    aes67_sock_t fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd == AES67_BAD_SOCK) {
        snprintf(errbuf, errlen, "socket: error %d", aes67_sockerr());
        return AES67_BAD_SOCK;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof one);
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *) &rcvbuf, sizeof rcvbuf);
    setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &one, sizeof one);
    if (cfg->busy_poll && cfg->busy_poll_us > 0)
        setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &cfg->busy_poll_us, sizeof cfg->busy_poll_us);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(sc->port);
    /* Bound to the group itself, one shared port demuxes by destination --
       the real AES67 convention (everything on 5004). */
    addr.sin_addr.s_addr = cfg->shared_port ? inet_addr(sc->group) : htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *) &addr, sizeof addr) < 0) {
        snprintf(errbuf, errlen, "bind %s:%u: error %d", sc->group, sc->port, aes67_sockerr());
        aes67_closesock(fd);
        return AES67_BAD_SOCK;
    }

    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof mreq);
    mreq.imr_multiaddr.s_addr = inet_addr(sc->group);
    mreq.imr_interface.s_addr = cfg->iface_ip[0] ? inet_addr(cfg->iface_ip) : htonl(INADDR_ANY);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *) &mreq, sizeof mreq) < 0) {
        snprintf(errbuf, errlen, "IP_ADD_MEMBERSHIP %s: error %d", sc->group, aes67_sockerr());
        aes67_closesock(fd);
        return AES67_BAD_SOCK;
    }
    return fd;
}

/* ---- receive thread ---------------------------------------------------------- */

static uint64_t cmsg_arrival_ns(struct msghdr *mh)
{
    for (struct cmsghdr *c = CMSG_FIRSTHDR(mh); c; c = CMSG_NXTHDR(mh, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS) {
            struct timespec ts;
            memcpy(&ts, CMSG_DATA(c), sizeof ts);
            return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
        }
    return aes67_now_ns();
}

static void drain_stream(aes67_rx_t *rx, aes67_rx_stream_t *s)
{
    static __thread uint8_t bufs[BATCH][2048];
    static __thread struct mmsghdr msgs[BATCH];
    static __thread struct iovec iovs[BATCH];
    static __thread uint8_t ctrl[BATCH][256];

    for (;;) {
        for (int i = 0; i < BATCH; ++i) {
            iovs[i].iov_base = bufs[i];
            iovs[i].iov_len = sizeof bufs[i];
            memset(&msgs[i].msg_hdr, 0, sizeof msgs[i].msg_hdr);
            msgs[i].msg_hdr.msg_iov = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = ctrl[i];
            msgs[i].msg_hdr.msg_controllen = sizeof ctrl[i];
        }
        const int n = recvmmsg(s->fd, msgs, BATCH, 0, NULL);
        if (n <= 0)
            return;
        for (int i = 0; i < n; ++i)
            process_packet(rx, s, bufs[i], (size_t) msgs[i].msg_len, cmsg_arrival_ns(&msgs[i].msg_hdr));
        if (n < BATCH)
            return;
    }
}

AES67_THREAD_FN(rx_thread_main, arg)
{
    aes67_rx_t *rx = arg;
    if (rx->cfg.cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(rx->cfg.cpu, &set);
        pthread_setaffinity_np(pthread_self(), sizeof set, &set);
    }
    struct sched_param sp = { .sched_priority = 80 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);   /* best effort */

    struct epoll_event evs[AES67_RX_MAX_STREAMS];
    while (aes67_atomic_load(&rx->running, AES67_MO_RELAXED)) {
        const int n = epoll_wait(rx->epfd, evs, AES67_RX_MAX_STREAMS, 100);
        for (int i = 0; i < n; ++i)
            drain_stream(rx, (aes67_rx_stream_t *) evs[i].data.ptr);
    }
    AES67_THREAD_RETURN;
}

#endif /* __linux__ */

/* ---- public API ------------------------------------------------------------- */

aes67_rx_t *aes67_rx_open(const aes67_rx_cfg_t *cfg, char *errbuf, size_t errlen)
{
    if (cfg->stream_count < 1 || cfg->stream_count > AES67_RX_MAX_STREAMS) {
        snprintf(errbuf, errlen, "bad stream_count %d", cfg->stream_count);
        return NULL;
    }
    aes67_rx_t *rx = calloc(1, sizeof *rx);
    if (!rx) {
        snprintf(errbuf, errlen, "oom");
        return NULL;
    }
    rx->cfg = *cfg;
#if defined(__linux__)
    rx->epfd = -1;
    for (int i = 0; i < AES67_RX_MAX_STREAMS; ++i)
        rx->streams[i].fd = AES67_BAD_SOCK;
#endif
    /* As many rings as the streams reach, and no more: a ring is 16 KB, and
       a fixed table of 64 was both a ceiling and a megabyte per receiver. */
    for (int i = 0; i < cfg->stream_count; ++i) {
        const int end = cfg->streams[i].first_channel + cfg->streams[i].channels;
        if (end > rx->ring_count)
            rx->ring_count = end;
    }
    rx->rings = rx->ring_count > 0 ? calloc((size_t) rx->ring_count, sizeof *rx->rings) : NULL;
    if (rx->ring_count > 0 && rx->rings == NULL) {
        snprintf(errbuf, errlen, "oom");
        free(rx);
        return NULL;
    }
    for (int i = 0; i < rx->ring_count; ++i)
        aes67_ring_init(&rx->rings[i]);

#if defined(__linux__)
    rx->epfd = epoll_create1(0);
    if (rx->epfd < 0) {
        snprintf(errbuf, errlen, "epoll_create1: %s", strerror(errno));
        aes67_rx_close(rx);
        return NULL;
    }
    for (int i = 0; i < cfg->stream_count; ++i) {
        aes67_rx_stream_t *s = &rx->streams[i];
        s->cfg = cfg->streams[i];
        s->group_addr = inet_addr(s->cfg.group);
        s->fd = open_stream_socket(cfg, &s->cfg, errbuf, errlen);
        if (s->fd == AES67_BAD_SOCK) {
            aes67_rx_close(rx);
            return NULL;
        }
        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = s };
        if (epoll_ctl(rx->epfd, EPOLL_CTL_ADD, s->fd, &ev) < 0) {
            snprintf(errbuf, errlen, "epoll_ctl: %s", strerror(errno));
            aes67_rx_close(rx);
            return NULL;
        }
    }
#else
    rx->net = aes67_netrx_open(cfg->iface_ip, errbuf, errlen);
    if (rx->net == NULL) {
        aes67_rx_close(rx);
        return NULL;
    }
    for (int i = 0; i < cfg->stream_count; ++i) {
        aes67_rx_stream_t *s = &rx->streams[i];
        s->cfg = cfg->streams[i];
        if (!aes67_parse_ipv4(s->cfg.group, &s->group_addr)) {
            snprintf(errbuf, errlen, "bad group %s", s->cfg.group);
            aes67_rx_close(rx);
            return NULL;
        }
        aes67_netrx_stream_cfg_t nc;
        memset(&nc, 0, sizeof nc);
        nc.group = s->group_addr;
        nc.port = s->cfg.port;
        nc.payload_type = s->cfg.payload_type;
        nc.format = s->cfg.format;
        nc.channels = s->cfg.channels;
        nc.media_clock_offset = 0;   /* this receiver's rings are indexed by RTP timestamp */
        nc.rings = rx->rings + s->cfg.first_channel;
        s->slot = aes67_netrx_add_stream(rx->net, &nc, errbuf, errlen);
        if (s->slot < 0) {
            aes67_rx_close(rx);
            return NULL;
        }
    }
#endif
    return rx;
}

bool aes67_rx_start(aes67_rx_t *rx)
{
#if defined(__linux__)
    if (rx->have_thread)
        return true;
    aes67_atomic_store(&rx->running, 1, AES67_MO_SEQ_CST);
    rx->have_thread = aes67_thread_start(&rx->thread, rx_thread_main, rx);
    if (!rx->have_thread)
        aes67_atomic_store(&rx->running, 0, AES67_MO_SEQ_CST);
    return rx->have_thread;
#else
    return aes67_netrx_start(rx->net);
#endif
}

void aes67_rx_inject(aes67_rx_t *rx, int stream, const uint8_t *packet, size_t len, uint64_t arrival_ns)
{
    if (rx == NULL || stream < 0 || stream >= rx->cfg.stream_count)
        return;
#if defined(__linux__)
    process_packet(rx, &rx->streams[stream], packet, len, arrival_ns);
#else
    const aes67_rx_stream_t *s = &rx->streams[stream];
    aes67_netrx_inject(rx->net, 0, s->group_addr, s->cfg.port, packet, len, arrival_ns);
#endif
}

int aes67_rx_read(aes67_rx_t *rx, int channel, uint32_t ts, int32_t *out, int frames)
{
    if (channel < 0 || channel >= rx->ring_count)
        return 0;
    return aes67_ring_read(&rx->rings[channel], ts, out, frames);
}

uint32_t aes67_rx_playout_ts(aes67_rx_t *rx, int stream, uint32_t margin_frames)
{
    if (stream < 0 || stream >= rx->cfg.stream_count)
        return 0;
    const aes67_rx_stream_cfg_t *sc = &rx->streams[stream].cfg;
    uint32_t min_head = 0;
    bool first = true;
    for (int c = 0; c < sc->channels; ++c) {
        const int ch = sc->first_channel + c;
        if (ch >= rx->ring_count)
            break;
        const uint32_t h = aes67_ring_head(&rx->rings[ch]);
        if (first || (int32_t) (h - min_head) < 0) {
            min_head = h;
            first = false;
        }
    }
    return min_head - margin_frames;
}

uint64_t aes67_rx_foreign_packets(aes67_rx_t *rx)
{
#if defined(__linux__)
    (void) rx;
    return 0;   /* each socket is bound to its group: the kernel never hands us another's */
#else
    return aes67_netrx_foreign_packets(rx->net);
#endif
}

void aes67_rx_get_stats(aes67_rx_t *rx, int stream, aes67_rx_stream_stats_t *out)
{
    if (stream < 0 || stream >= rx->cfg.stream_count)
        return;
#if defined(__linux__)
    *out = rx->streams[stream].stats;   /* a torn read of statistics is acceptable */
#else
    aes67_netrx_stats_t n;
    aes67_netrx_get_stats(rx->net, rx->streams[stream].slot, &n);
    memset(out, 0, sizeof *out);
    out->packets = n.packets;
    out->bytes = n.bytes;
    out->seq_lost = n.lost;
    out->seq_reordered = n.reordered;
    out->wrong_pt = n.wrong_pt;
    out->too_short = n.malformed;
    out->last_seq_valid = n.last_seq_valid ? 1 : 0;
    out->last_seq = n.last_seq;
    out->jitter_worst_ns = n.jitter_worst_ns;
#endif
}

void aes67_rx_stop(aes67_rx_t *rx)
{
#if defined(__linux__)
    if (!rx->have_thread)
        return;
    aes67_atomic_store(&rx->running, 0, AES67_MO_SEQ_CST);
    aes67_thread_join(rx->thread);
    rx->have_thread = false;
#else
    aes67_netrx_stop(rx->net);
#endif
}

void aes67_rx_close(aes67_rx_t *rx)
{
    if (rx == NULL)
        return;
#if defined(__linux__)
    aes67_rx_stop(rx);
    for (int i = 0; i < AES67_RX_MAX_STREAMS; ++i)
        if (rx->streams[i].fd != AES67_BAD_SOCK)
            aes67_closesock(rx->streams[i].fd);
    if (rx->epfd >= 0)
        close(rx->epfd);
#else
    aes67_netrx_close(rx->net);   /* stops, leaves, closes: the rings are untouched after */
#endif
    free(rx->rings);
    free(rx);
}
