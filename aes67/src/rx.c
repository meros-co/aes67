/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libaes67 receive. See rx.h.
 *
 * The packet path (aes67_rx_inject and below) is shared by both socket
 * paths and by the tests; only how packets get off the wire differs.
 *
 * Real AES67 puts every stream on one port (5004) and tells them apart by
 * multicast group. Linux binds a socket to each group, which does the
 * sorting in the kernel. Windows cannot bind a multicast address, and a
 * socket bound to the port receives every group joined on it (macOS is no
 * better with several streams on one socket), so there the receiver opens
 * one socket per port, joins every stream's group on it, and sorts each
 * packet by the destination address the kernel reports with it (IP_PKTINFO;
 * IP_RECVDSTADDR on BSD). A packet for a group no stream here asked for --
 * another receiver's, on the same port -- is dropped and counted. */

#if defined(__linux__)
#  define _GNU_SOURCE
#endif

#include "aes67/rx.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <mswsock.h>
#  include <windows.h>
#  include <process.h>
   typedef SOCKET aes67_sock_t;
#  define AES67_BAD_SOCK INVALID_SOCKET
#  define aes67_closesock closesocket
#  define aes67_sockerr() WSAGetLastError()
   typedef HANDLE aes67_thread_t;
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <pthread.h>
#  include <sched.h>
#  include <sys/socket.h>
#  include <sys/uio.h>
#  include <time.h>
#  include <unistd.h>
#  if defined(__linux__)
#    include <sys/epoll.h>
#  else
#    include <poll.h>
#  endif
   typedef int aes67_sock_t;
#  define AES67_BAD_SOCK (-1)
#  define aes67_closesock close
#  define aes67_sockerr() errno
   typedef pthread_t aes67_thread_t;
#endif

#define BATCH 64

typedef struct aes67_rx_stream {
    aes67_rx_stream_cfg_t   cfg;
    aes67_sock_t            fd;
    int                     sock;          /* index into rx->socks (not Linux) */
    uint32_t                group_addr;    /* the group, network order */
    uint16_t                last_seq;
    bool                    have_seq;
    uint64_t                last_arr_ns;
    aes67_rx_stream_stats_t stats;
} aes67_rx_stream_t;

struct aes67_rx {
    aes67_rx_cfg_t    cfg;
    aes67_rx_stream_t streams[AES67_RX_MAX_STREAMS];
    aes67_ring_t     *rings;        /* one per channel the streams carry */
    int               ring_count;
#if defined(__linux__)
    int               epfd;
#else
    /* One socket per port; streams on that port share it (see the top). */
    aes67_sock_t      socks[AES67_RX_MAX_STREAMS];
    uint16_t          sock_port[AES67_RX_MAX_STREAMS];
    int               sock_count;
    aes67_atomic_u64  not_ours;     /* packets for a group no stream here joined */
#  if defined(_WIN32)
    LPFN_WSARECVMSG   wsa_recvmsg;
#  endif
#endif
    aes67_thread_t    thread;
    bool              have_thread;
    aes67_atomic_u64  running;
#if defined(_WIN32)
    bool              wsa_started;
#endif
};

/* ---- the packet path (platform-free) -------------------------------------- */

static void process_packet(aes67_rx_t *rx, aes67_rx_stream_t *s, const uint8_t *p, size_t len,
                           uint64_t arr_ns)
{
    aes67_rx_stream_stats_t *st = &s->stats;
    aes67_rtp_header_t h;
    if (!aes67_rtp_parse_header(p, len, &h)) { st->too_short++; return; }
    if (h.payload_type != s->cfg.payload_type) { st->wrong_pt++; return; }

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

    const int cps = s->cfg.channels;
    if (cps <= 0)
        return;
    const aes67_sample_format_t fmt = (aes67_sample_format_t) s->cfg.format;
    const int bps = aes67_format_bytes(fmt);
    const size_t payload = len - AES67_RTP_HEADER_BYTES;
    const int frames = (int) (payload / (size_t) (bps * cps));
    const uint8_t *d = p + AES67_RTP_HEADER_BYTES;
    for (int f = 0; f < frames; ++f)
        for (int c = 0; c < cps; ++c, d += bps) {
            const int ch = s->cfg.first_channel + c;
            if (ch >= rx->ring_count)
                continue;
            int32_t v;
            if (fmt == AES67_FORMAT_L16)
                v = (int32_t) (int16_t) (((uint16_t) d[0] << 8) | d[1]) * 256;   /* to 24-bit scale */
            else if (fmt == AES67_FORMAT_AM824)
                v = aes67_l24_to_i32(d + 1);   /* the AES3 flags octet first, then the audio word */
            else
                v = aes67_l24_to_i32(d);
            aes67_ring_write(&rx->rings[ch], h.timestamp + (uint32_t) f, v);
        }
}

int aes67_format_bytes(aes67_sample_format_t format)
{
    return format == AES67_FORMAT_L16 ? 2 : format == AES67_FORMAT_AM824 ? 4 : 3;
}

bool aes67_format_from_encoding(const char *encoding, aes67_sample_format_t *out)
{
    if (encoding == NULL || strcmp(encoding, "L24") == 0 || encoding[0] == '\0') { *out = AES67_FORMAT_L24; return true; }
    if (strcmp(encoding, "L16") == 0)   { *out = AES67_FORMAT_L16;   return true; }
    if (strcmp(encoding, "AM824") == 0) { *out = AES67_FORMAT_AM824; return true; }
    return false;
}

void aes67_rx_inject(aes67_rx_t *rx, int stream, const uint8_t *packet, size_t len, uint64_t arrival_ns)
{
    if (rx == NULL || stream < 0 || stream >= rx->cfg.stream_count)
        return;
    process_packet(rx, &rx->streams[stream], packet, len, arrival_ns);
}

static uint64_t now_ns(void)
{
#if defined(_WIN32)
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (uint64_t) ((double) c.QuadPart * 1e9 / (double) f.QuadPart);
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t) t.tv_sec * 1000000000ull + (uint64_t) t.tv_nsec;
#endif
}

/* ---- sockets --------------------------------------------------------------- */

static bool set_nonblocking(aes67_sock_t fd)
{
#if defined(_WIN32)
    u_long one = 1;
    return ioctlsocket(fd, FIONBIO, &one) == 0;
#else
    (void) fd;
    return true;   /* opened with SOCK_NONBLOCK below, or polled with a timeout */
#endif
}

#if defined(__linux__)
static aes67_sock_t open_stream_socket(const aes67_rx_cfg_t *cfg, const aes67_rx_stream_cfg_t *sc,
                                       char *errbuf, size_t errlen)
{
#if defined(__linux__)
    aes67_sock_t fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
#else
    aes67_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (fd == AES67_BAD_SOCK) {
        snprintf(errbuf, errlen, "socket: error %d", aes67_sockerr());
        return AES67_BAD_SOCK;
    }
    set_nonblocking(fd);

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof one);
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *) &rcvbuf, sizeof rcvbuf);
#if defined(__linux__)
    setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &one, sizeof one);
    if (cfg->busy_poll && cfg->busy_poll_us > 0)
        setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &cfg->busy_poll_us, sizeof cfg->busy_poll_us);
#endif

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
#endif

/* ---- receive thread ---------------------------------------------------------- */

#if defined(__linux__)

static uint64_t cmsg_arrival_ns(struct msghdr *mh)
{
    for (struct cmsghdr *c = CMSG_FIRSTHDR(mh); c; c = CMSG_NXTHDR(mh, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS) {
            struct timespec ts;
            memcpy(&ts, CMSG_DATA(c), sizeof ts);
            return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
        }
    return now_ns();
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

static void *rx_thread_main(void *arg)
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
    return NULL;
}

#else /* ---- portable: one socket per port, sorted by destination ---------- */

/* A socket for every stream on `port`: bound to any address on it, told to
   report each packet's destination. */
static aes67_sock_t open_port_socket(const aes67_rx_cfg_t *cfg, uint16_t port, char *errbuf, size_t errlen)
{
    (void) cfg;
    aes67_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == AES67_BAD_SOCK) {
        snprintf(errbuf, errlen, "socket: error %d", aes67_sockerr());
        return AES67_BAD_SOCK;
    }
    set_nonblocking(fd);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof one);
#if defined(SO_REUSEPORT)
    /* BSD: another socket (another receiver, another program) on the same
       port needs it as well as SO_REUSEADDR. */
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *) &one, sizeof one);
#endif
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *) &rcvbuf, sizeof rcvbuf);
#if defined(_WIN32) || (defined(IP_PKTINFO) && !defined(IP_RECVDSTADDR))
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, (const char *) &one, sizeof one) != 0) {
        snprintf(errbuf, errlen, "IP_PKTINFO: error %d", aes67_sockerr());
        aes67_closesock(fd);
        return AES67_BAD_SOCK;
    }
#else
    if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, (const char *) &one, sizeof one) != 0) {
        snprintf(errbuf, errlen, "IP_RECVDSTADDR: error %d", aes67_sockerr());
        aes67_closesock(fd);
        return AES67_BAD_SOCK;
    }
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *) &addr, sizeof addr) < 0) {
        snprintf(errbuf, errlen, "bind port %u: error %d", port, aes67_sockerr());
        aes67_closesock(fd);
        return AES67_BAD_SOCK;
    }
    return fd;
}

static bool join_group(aes67_sock_t fd, const aes67_rx_cfg_t *cfg, const char *group, char *errbuf, size_t errlen)
{
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof mreq);
    mreq.imr_multiaddr.s_addr = inet_addr(group);
    mreq.imr_interface.s_addr = cfg->iface_ip[0] ? inet_addr(cfg->iface_ip) : htonl(INADDR_ANY);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *) &mreq, sizeof mreq) < 0) {
        snprintf(errbuf, errlen, "IP_ADD_MEMBERSHIP %s: error %d", group, aes67_sockerr());
        return false;
    }
    return true;
}

/* One datagram and the address it was sent to (network order; 0 when the
   kernel did not say). -1 when there is nothing to read. */
static int recv_with_destination(aes67_rx_t *rx, aes67_sock_t fd, uint8_t *buf, size_t cap, uint32_t *dst)
{
    *dst = 0;
#if defined(_WIN32)
    char ctrl[128];
    struct sockaddr_in from;
    WSABUF wb;
    wb.len = (ULONG) cap;
    wb.buf = (CHAR *) buf;
    WSAMSG msg;
    memset(&msg, 0, sizeof msg);
    msg.name = (LPSOCKADDR) &from;
    msg.namelen = sizeof from;
    msg.lpBuffers = &wb;
    msg.dwBufferCount = 1;
    msg.Control.buf = ctrl;
    msg.Control.len = sizeof ctrl;
    DWORD got = 0;
    if (rx->wsa_recvmsg == NULL || rx->wsa_recvmsg(fd, &msg, &got, NULL, NULL) != 0)
        return -1;
    for (WSACMSGHDR *c = WSA_CMSG_FIRSTHDR(&msg); c != NULL; c = WSA_CMSG_NXTHDR(&msg, c))
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            IN_PKTINFO pi;
            memcpy(&pi, WSA_CMSG_DATA(c), sizeof pi);
            *dst = pi.ipi_addr.s_addr;
        }
    return (int) got;
#else
    (void) rx;
    union { char buf[128]; struct cmsghdr align; } ctrl;
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = cap;
    struct msghdr mh;
    memset(&mh, 0, sizeof mh);
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = ctrl.buf;
    mh.msg_controllen = sizeof ctrl.buf;
    const ssize_t n = recvmsg(fd, &mh, MSG_DONTWAIT);
    if (n <= 0)
        return -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c != NULL; c = CMSG_NXTHDR(&mh, c)) {
#  if defined(IP_RECVDSTADDR)
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_RECVDSTADDR)
            memcpy(dst, CMSG_DATA(c), sizeof *dst);
#  else
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo pi;
            memcpy(&pi, CMSG_DATA(c), sizeof pi);
            *dst = pi.ipi_addr.s_addr;
        }
#  endif
    }
    return (int) n;
#endif
}

static void drain_socket(aes67_rx_t *rx, int sock)
{
    uint8_t buf[2048];
    for (int i = 0; i < BATCH; ++i) {
        uint32_t dst = 0;
        const int n = recv_with_destination(rx, rx->socks[sock], buf, sizeof buf, &dst);
        if (n <= 0)
            return;
        const uint64_t arrived = now_ns();
        /* Every stream on this socket that the packet was addressed to (two
           streams may read different channels of one group). Without a
           destination, a socket with one group can still only mean it. */
        int matched = 0, only = -1, groups = 0;
        for (int k = 0; k < rx->cfg.stream_count; ++k) {
            aes67_rx_stream_t *s = &rx->streams[k];
            if (s->sock != sock)
                continue;
            if (only < 0 || rx->streams[only].group_addr != s->group_addr)
                ++groups;
            only = k;
            if (dst != 0 && s->group_addr == dst) {
                process_packet(rx, s, buf, (size_t) n, arrived);
                ++matched;
            }
        }
        if (matched == 0 && dst == 0 && groups == 1 && only >= 0)
            process_packet(rx, &rx->streams[only], buf, (size_t) n, arrived);
        else if (matched == 0)
            aes67_atomic_fetch_add(&rx->not_ours, 1, AES67_MO_RELAXED);
    }
}

#if defined(_WIN32)
static unsigned __stdcall rx_thread_main(void *arg)
#else
static void *rx_thread_main(void *arg)
#endif
{
    aes67_rx_t *rx = arg;
#if defined(_WIN32)
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    WSAPOLLFD fds[AES67_RX_MAX_STREAMS];
#else
    struct pollfd fds[AES67_RX_MAX_STREAMS];
#endif
    while (aes67_atomic_load(&rx->running, AES67_MO_RELAXED)) {
        for (int i = 0; i < rx->sock_count; ++i) {
            fds[i].fd = rx->socks[i];
            fds[i].events = POLLIN;
            fds[i].revents = 0;
        }
#if defined(_WIN32)
        const int n = WSAPoll(fds, (ULONG) rx->sock_count, 100);
#else
        const int n = poll(fds, (nfds_t) rx->sock_count, 100);
#endif
        if (n <= 0)
            continue;
        for (int i = 0; i < rx->sock_count; ++i)
            if (fds[i].revents & POLLIN)
                drain_socket(rx, i);
    }
#if defined(_WIN32)
    return 0;
#else
    return NULL;
#endif
}

#endif

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
    for (int i = 0; i < AES67_RX_MAX_STREAMS; ++i) {
        rx->streams[i].fd = AES67_BAD_SOCK;
        rx->streams[i].sock = -1;
#if !defined(__linux__)
        rx->socks[i] = AES67_BAD_SOCK;
#endif
    }
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
        free(rx->rings);
        free(rx);
        return NULL;
    }
    for (int i = 0; i < rx->ring_count; ++i)
        aes67_ring_init(&rx->rings[i]);
#if defined(_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        snprintf(errbuf, errlen, "WSAStartup failed");
        free(rx->rings);
        free(rx);
        return NULL;
    }
    rx->wsa_started = true;
#endif
#if defined(__linux__)
    rx->epfd = epoll_create1(0);
    if (rx->epfd < 0) {
        snprintf(errbuf, errlen, "epoll_create1: %s", strerror(errno));
        free(rx->rings);
        free(rx);
        return NULL;
    }
#endif
    for (int i = 0; i < cfg->stream_count; ++i) {
        aes67_rx_stream_t *s = &rx->streams[i];
        s->cfg = cfg->streams[i];
        s->group_addr = inet_addr(s->cfg.group);
#if defined(__linux__)
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
#else
        /* The port's socket, opened by the first stream on it; the group
           joined once per socket however many streams read it. */
        int sock = -1;
        for (int k = 0; k < rx->sock_count; ++k)
            if (rx->sock_port[k] == s->cfg.port)
                sock = k;
        if (sock < 0) {
            sock = rx->sock_count;
            rx->socks[sock] = open_port_socket(cfg, s->cfg.port, errbuf, errlen);
            if (rx->socks[sock] == AES67_BAD_SOCK) {
                aes67_rx_close(rx);
                return NULL;
            }
            rx->sock_port[sock] = s->cfg.port;
            rx->sock_count++;
#  if defined(_WIN32)
            if (rx->wsa_recvmsg == NULL) {
                GUID id = WSAID_WSARECVMSG;
                DWORD bytes = 0;
                if (WSAIoctl(rx->socks[sock], SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id,
                             &rx->wsa_recvmsg, sizeof rx->wsa_recvmsg, &bytes, NULL, NULL) != 0) {
                    snprintf(errbuf, errlen, "WSARecvMsg: error %d", aes67_sockerr());
                    aes67_rx_close(rx);
                    return NULL;
                }
            }
#  endif
        }
        bool joined = false;
        for (int k = 0; k < i; ++k)
            if (rx->streams[k].sock == sock && rx->streams[k].group_addr == s->group_addr)
                joined = true;
        if (!joined && !join_group(rx->socks[sock], cfg, s->cfg.group, errbuf, errlen)) {
            aes67_rx_close(rx);
            return NULL;
        }
        s->sock = sock;
        s->fd = rx->socks[sock];
#endif
    }
    return rx;
}

bool aes67_rx_start(aes67_rx_t *rx)
{
    if (rx->have_thread)
        return true;
    aes67_atomic_store(&rx->running, 1, AES67_MO_SEQ_CST);
#if defined(_WIN32)
    rx->thread = (HANDLE) _beginthreadex(NULL, 0, rx_thread_main, rx, 0, NULL);
    rx->have_thread = rx->thread != NULL;
#else
    rx->have_thread = pthread_create(&rx->thread, NULL, rx_thread_main, rx) == 0;
#endif
    if (!rx->have_thread)
        aes67_atomic_store(&rx->running, 0, AES67_MO_SEQ_CST);
    return rx->have_thread;
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
    return aes67_atomic_load(&rx->not_ours, AES67_MO_RELAXED);
#endif
}

void aes67_rx_get_stats(aes67_rx_t *rx, int stream, aes67_rx_stream_stats_t *out)
{
    if (stream >= 0 && stream < rx->cfg.stream_count)
        *out = rx->streams[stream].stats;   /* a torn read of statistics is acceptable */
}

void aes67_rx_stop(aes67_rx_t *rx)
{
    if (!rx->have_thread)
        return;
    aes67_atomic_store(&rx->running, 0, AES67_MO_SEQ_CST);
#if defined(_WIN32)
    WaitForSingleObject(rx->thread, INFINITE);
    CloseHandle(rx->thread);
#else
    pthread_join(rx->thread, NULL);
#endif
    rx->have_thread = false;
}

void aes67_rx_close(aes67_rx_t *rx)
{
    if (rx == NULL)
        return;
    aes67_rx_stop(rx);
#if defined(__linux__)
    for (int i = 0; i < AES67_RX_MAX_STREAMS; ++i)
        if (rx->streams[i].fd != AES67_BAD_SOCK)
            aes67_closesock(rx->streams[i].fd);
    if (rx->epfd >= 0)
        close(rx->epfd);
#else
    for (int i = 0; i < rx->sock_count; ++i)   /* the streams share these */
        if (rx->socks[i] != AES67_BAD_SOCK)
            aes67_closesock(rx->socks[i]);
#endif
#if defined(_WIN32)
    if (rx->wsa_started)
        WSACleanup();
#endif
    free(rx->rings);
    free(rx);
}
