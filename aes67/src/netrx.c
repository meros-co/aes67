/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libaes67 network receive into the caller's rings. See netrx.h.
 *
 * The packet path (process, below) is shared by the sockets and by
 * aes67_netrx_inject. Streams are slots a control thread fills and empties
 * while the receive thread reads them: a slot is Free, Busy (being changed)
 * or Active, and only an Active slot is touched by the receive thread. A
 * removal marks the slot Busy and waits two passes of the receive loop, after
 * which no packet that saw it Active is still being written. */

#if defined(__linux__)
#  define _GNU_SOURCE
#endif

#include "aes67/netrx.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <avrt.h>
#else
#  include <fcntl.h>
#  include <poll.h>
#  include <sys/uio.h>
#  if defined(__linux__)
#    include <sched.h>
#  endif
#  if defined(__APPLE__)
#    include <sys/qos.h>
#  endif
#endif

enum { SLOT_FREE = 0, SLOT_BUSY = 1, SLOT_ACTIVE = 2 };

typedef struct netrx_slot {
    aes67_atomic_u64         state;
    aes67_netrx_stream_cfg_t cfg;

    /* Receive thread only. */
    uint16_t last_seq;
    bool     have_seq;
    uint64_t last_arrival;

    /* Written by the receive thread, read by anyone. */
    aes67_atomic_u64 packets, bytes, lost, reordered, wrong_pt, malformed, jitter_worst, last_arrival_ns, seq;
} netrx_slot_t;

#if defined(_WIN32)
#define OPS_PER_SOCKET 64

typedef struct recv_op {
    OVERLAPPED         ov;
    WSAMSG             msg;
    WSABUF             buf;
    struct sockaddr_in from;
    char               data[2048];
    char               control[WSA_CMSG_SPACE(sizeof(IN_PKTINFO))];
    int                port;   /* index into ports[] */
} recv_op_t;
#endif

typedef struct netrx_port {
    uint16_t     port;
    aes67_sock_t fd;
#if defined(_WIN32)
    recv_op_t   *ops;
#endif
} netrx_port_t;

struct aes67_netrx {
    uint32_t         iface;   /* network order; 0 = any */
    netrx_slot_t     slots[AES67_NETRX_MAX_STREAMS];
    netrx_port_t     ports[AES67_NETRX_MAX_PORTS];
    aes67_atomic_u64 port_count;
    aes67_atomic_u64 foreign;

    aes67_mutex_t    control;   /* add and remove, one at a time */
    aes67_atomic_u64 running;
    aes67_atomic_u64 passes;    /* receive-loop iterations: removal waits on these */
    aes67_thread_t   thread;
    bool             have_thread;

#if defined(_WIN32)
    bool             wsa_started;
    HANDLE           iocp;
    LPFN_WSARECVMSG  recv_msg;
    aes67_atomic_u64 outstanding;
    aes67_atomic_u64 closing;
#endif
};

#define LOAD(p)     aes67_atomic_load((p), AES67_MO_RELAXED)
#define BUMP(p, v)  aes67_atomic_fetch_add((p), (v), AES67_MO_RELAXED)

bool aes67_parse_ipv4(const char *text, uint32_t *out)
{
    struct in_addr a;
    if (text == NULL || inet_pton(AF_INET, text, &a) != 1)
        return false;
    *out = a.s_addr;
    return true;
}

static bool is_multicast(uint32_t addr_net)
{
    return (ntohl(addr_net) & 0xF0000000u) == 0xE0000000u;
}

/* ---- the packet path ------------------------------------------------------- */

static void process(aes67_netrx_t *rx, uint32_t src, uint32_t dst, uint16_t port, const uint8_t *p, size_t len,
                    uint64_t arrival)
{
    for (int i = 0; i < AES67_NETRX_MAX_STREAMS; ++i) {
        netrx_slot_t *s = &rx->slots[i];
        if (aes67_atomic_load(&s->state, AES67_MO_ACQUIRE) != SLOT_ACTIVE)
            continue;
        const aes67_netrx_stream_cfg_t *c = &s->cfg;
        /* A destination of 0 is a socket that did not say: the port decides. */
        if (c->port != port || (dst != 0 && c->group != dst) || (c->source != 0 && c->source != src))
            continue;

        aes67_rtp_header_t h;
        const int got = aes67_rtp_write_rings(p, len, c->payload_type, (aes67_sample_format_t) c->format,
                                              c->channels, c->media_clock_offset, c->rings, &h);
        if (got == AES67_PACKET_MALFORMED) {
            BUMP(&s->malformed, 1);
            return;
        }
        if (got == AES67_PACKET_WRONG_PT) {
            BUMP(&s->wrong_pt, 1);
            return;
        }
        if (s->have_seq) {
            const uint16_t expect = (uint16_t) (s->last_seq + 1);
            if (h.sequence != expect) {
                const int16_t d = (int16_t) (h.sequence - expect);
                if (d > 0)
                    BUMP(&s->lost, (uint64_t) d);
                else
                    BUMP(&s->reordered, 1);   /* still played: the rings are timestamp-indexed */
            }
        }
        s->last_seq = h.sequence;
        s->have_seq = true;
        aes67_atomic_store(&s->seq, 0x10000u | h.sequence, AES67_MO_RELAXED);
        if (s->last_arrival != 0 && arrival > s->last_arrival) {
            const uint64_t gap = arrival - s->last_arrival;
            if (gap > LOAD(&s->jitter_worst))
                aes67_atomic_store(&s->jitter_worst, gap, AES67_MO_RELAXED);
        }
        s->last_arrival = arrival;
        aes67_atomic_store(&s->last_arrival_ns, arrival, AES67_MO_RELAXED);
        BUMP(&s->packets, 1);
        BUMP(&s->bytes, (uint64_t) len);
        return;   /* one stream per (group, port, source) */
    }
    BUMP(&rx->foreign, 1);
}

/* ---- sockets ----------------------------------------------------------------- */

#if defined(_WIN32)
static bool post_receive(aes67_netrx_t *rx, recv_op_t *op)
{
    memset(&op->ov, 0, sizeof op->ov);
    op->buf.buf = op->data;
    op->buf.len = sizeof op->data;
    op->msg.name = (struct sockaddr *) &op->from;
    op->msg.namelen = sizeof op->from;
    op->msg.lpBuffers = &op->buf;
    op->msg.dwBufferCount = 1;
    op->msg.Control.buf = op->control;
    op->msg.Control.len = sizeof op->control;
    op->msg.dwFlags = 0;
    BUMP(&rx->outstanding, 1);
    const int rc = rx->recv_msg(rx->ports[op->port].fd, &op->msg, NULL, &op->ov, NULL);
    if (rc == 0 || WSAGetLastError() == WSA_IO_PENDING)
        return true;   /* completes through the port either way */
    BUMP(&rx->outstanding, (uint64_t) -1);
    return false;
}
#endif

/* The socket for `port`, opened on first use. */
static int open_port(aes67_netrx_t *rx, uint16_t port, char *errbuf, size_t errlen)
{
    const int n = (int) LOAD(&rx->port_count);
    for (int i = 0; i < n; ++i)
        if (rx->ports[i].port == port)
            return i;
    if (n >= AES67_NETRX_MAX_PORTS) {
        snprintf(errbuf, errlen, "too many receive ports");
        return -1;
    }

#if defined(_WIN32)
    aes67_sock_t fd = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
#else
    aes67_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (fd == AES67_BAD_SOCK) {
        snprintf(errbuf, errlen, "socket: error %d", aes67_sockerr());
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof one);
#if defined(SO_REUSEPORT)
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *) &one, sizeof one);
#endif
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *) &rcvbuf, sizeof rcvbuf);
    /* Each datagram's destination address: how streams on one port are told apart. */
#if defined(_WIN32)
    setsockopt(fd, IPPROTO_IP, IP_PKTINFO, (const char *) &one, sizeof one);
#elif defined(IP_RECVPKTINFO)
    setsockopt(fd, IPPROTO_IP, IP_RECVPKTINFO, &one, sizeof one);
#else
    setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof one);
#endif
#if defined(IP_MULTICAST_ALL)
    int zero = 0;   /* Linux: only the groups this socket joined */
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, &zero, sizeof zero);
#endif
#if !defined(_WIN32)
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *) &addr, sizeof addr) != 0) {
        snprintf(errbuf, errlen, "bind port %u: error %d", port, aes67_sockerr());
        aes67_closesock(fd);
        return -1;
    }

    netrx_port_t *ps = &rx->ports[n];
    ps->port = port;
    ps->fd = fd;
#if defined(_WIN32)
    if (CreateIoCompletionPort((HANDLE) fd, rx->iocp, (ULONG_PTR) n, 0) == NULL) {
        snprintf(errbuf, errlen, "completion port: error %lu", GetLastError());
        aes67_closesock(fd);
        ps->fd = AES67_BAD_SOCK;
        return -1;
    }
    ps->ops = (recv_op_t *) calloc(OPS_PER_SOCKET, sizeof *ps->ops);
    if (ps->ops == NULL) {
        snprintf(errbuf, errlen, "oom");
        aes67_closesock(fd);
        ps->fd = AES67_BAD_SOCK;
        return -1;
    }
    for (int i = 0; i < OPS_PER_SOCKET; ++i) {
        ps->ops[i].port = n;
        post_receive(rx, &ps->ops[i]);
    }
#endif
    aes67_atomic_store(&rx->port_count, (uint64_t) (n + 1), AES67_MO_RELEASE);
    return n;
}

static bool join(aes67_netrx_t *rx, const aes67_netrx_stream_cfg_t *cfg, int port_index, bool add,
                 char *errbuf, size_t errlen)
{
    if (!is_multicast(cfg->group))
        return true;   /* a unicast destination is this host's own address: nothing to join */
    const aes67_sock_t fd = rx->ports[port_index].fd;
    int rc;
    if (cfg->source != 0) {
        struct ip_mreq_source m;
        memset(&m, 0, sizeof m);
        m.imr_multiaddr.s_addr = cfg->group;
        m.imr_sourceaddr.s_addr = cfg->source;
        m.imr_interface.s_addr = rx->iface;
        rc = setsockopt(fd, IPPROTO_IP, add ? IP_ADD_SOURCE_MEMBERSHIP : IP_DROP_SOURCE_MEMBERSHIP,
                        (const char *) &m, sizeof m);
    } else {
        struct ip_mreq m;
        memset(&m, 0, sizeof m);
        m.imr_multiaddr.s_addr = cfg->group;
        m.imr_interface.s_addr = rx->iface;
        rc = setsockopt(fd, IPPROTO_IP, add ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, (const char *) &m, sizeof m);
    }
    if (rc != 0) {
        char g[INET_ADDRSTRLEN] = { 0 };
        struct in_addr ga;
        ga.s_addr = cfg->group;
        inet_ntop(AF_INET, &ga, g, sizeof g);
        snprintf(errbuf, errlen, "%s %s: error %d", add ? "join" : "leave", g, aes67_sockerr());
        return false;
    }
    return true;
}

/* ---- the receive thread -------------------------------------------------------- */

#if defined(_WIN32)

AES67_THREAD_FN(netrx_thread_main, arg)
{
    aes67_netrx_t *rx = (aes67_netrx_t *) arg;
    DWORD task = 0;
    HANDLE mmcss = AvSetMmThreadCharacteristicsW(L"Pro Audio", &task);
    if (mmcss == NULL)
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    OVERLAPPED_ENTRY entries[64];
    while (LOAD(&rx->running)) {
        ULONG n = 0;
        if (GetQueuedCompletionStatusEx(rx->iocp, entries, 64, &n, 20, FALSE)) {
            const uint64_t arrival = aes67_now_ns();
            for (ULONG i = 0; i < n; ++i) {
                if (entries[i].lpOverlapped == NULL)
                    continue;   /* a wake-up */
                recv_op_t *op = CONTAINING_RECORD(entries[i].lpOverlapped, recv_op_t, ov);
                BUMP(&rx->outstanding, (uint64_t) -1);
                if (LOAD(&rx->closing))
                    continue;
                if (entries[i].Internal == 0) {
                    uint32_t dst = 0;
                    for (WSACMSGHDR *c = WSA_CMSG_FIRSTHDR(&op->msg); c != NULL; c = WSA_CMSG_NXTHDR(&op->msg, c))
                        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
                            IN_PKTINFO pi;
                            memcpy(&pi, WSA_CMSG_DATA(c), sizeof pi);
                            dst = pi.ipi_addr.s_addr;
                        }
                    process(rx, op->from.sin_addr.s_addr, dst, rx->ports[op->port].port, (const uint8_t *) op->data,
                            entries[i].dwNumberOfBytesTransferred, arrival);
                }
                post_receive(rx, op);
            }
        }
        aes67_atomic_fetch_add(&rx->passes, 1, AES67_MO_RELEASE);
    }
    if (mmcss != NULL)
        AvRevertMmThreadCharacteristics(mmcss);
    AES67_THREAD_RETURN;
}

#else

AES67_THREAD_FN(netrx_thread_main, arg)
{
    aes67_netrx_t *rx = (aes67_netrx_t *) arg;
#if defined(__APPLE__)
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#elif defined(__linux__)
    struct sched_param sp = { .sched_priority = 80 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);   /* best effort */
#endif
    struct pollfd fds[AES67_NETRX_MAX_PORTS];
    uint8_t buf[2048];
    union { char buf[256]; struct cmsghdr align; } control;
    while (LOAD(&rx->running)) {
        const int n = (int) aes67_atomic_load(&rx->port_count, AES67_MO_ACQUIRE);
        for (int i = 0; i < n; ++i) {
            fds[i].fd = rx->ports[i].fd;
            fds[i].events = POLLIN;
            fds[i].revents = 0;
        }
        int ready = 0;
        if (n > 0)
            ready = poll(fds, (nfds_t) n, 20);
        else
            aes67_sleep_ms(20);
        if (ready > 0)
            for (int i = 0; i < n; ++i) {
                if (!(fds[i].revents & POLLIN))
                    continue;
                for (int k = 0; k < 64; ++k) {
                    struct sockaddr_in from;
                    struct iovec iov = { buf, sizeof buf };
                    struct msghdr mh;
                    memset(&from, 0, sizeof from);
                    memset(&mh, 0, sizeof mh);
                    mh.msg_name = &from;
                    mh.msg_namelen = sizeof from;
                    mh.msg_iov = &iov;
                    mh.msg_iovlen = 1;
                    mh.msg_control = control.buf;
                    mh.msg_controllen = sizeof control.buf;
                    const ssize_t got = recvmsg(rx->ports[i].fd, &mh, 0);
                    if (got <= 0)
                        break;
                    uint32_t dst = 0;
                    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c != NULL; c = CMSG_NXTHDR(&mh, c))
                        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
                            struct in_pktinfo pi;
                            memcpy(&pi, CMSG_DATA(c), sizeof pi);
                            dst = pi.ipi_addr.s_addr;
                        }
                    process(rx, from.sin_addr.s_addr, dst, rx->ports[i].port, buf, (size_t) got, aes67_now_ns());
                }
            }
        aes67_atomic_fetch_add(&rx->passes, 1, AES67_MO_RELEASE);
    }
    AES67_THREAD_RETURN;
}

#endif

/* ---- public ------------------------------------------------------------------- */

aes67_netrx_t *aes67_netrx_open(const char *iface_ip, char *errbuf, size_t errlen)
{
    aes67_netrx_t *rx = (aes67_netrx_t *) calloc(1, sizeof *rx);
    if (rx == NULL) {
        snprintf(errbuf, errlen, "oom");
        return NULL;
    }
    for (int i = 0; i < AES67_NETRX_MAX_PORTS; ++i)
        rx->ports[i].fd = AES67_BAD_SOCK;
    aes67_mutex_init(&rx->control);
    if (iface_ip != NULL && iface_ip[0] != '\0' && !aes67_parse_ipv4(iface_ip, &rx->iface)) {
        snprintf(errbuf, errlen, "bad interface address %s", iface_ip);
        aes67_netrx_close(rx);
        return NULL;
    }
#if defined(_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        snprintf(errbuf, errlen, "WSAStartup failed");
        aes67_netrx_close(rx);
        return NULL;
    }
    rx->wsa_started = true;
    rx->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    if (rx->iocp == NULL) {
        snprintf(errbuf, errlen, "completion port: error %lu", GetLastError());
        aes67_netrx_close(rx);
        return NULL;
    }
    /* WSARecvMsg is an extension function, fetched through any socket. */
    SOCKET probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    GUID guid = WSAID_WSARECVMSG;
    DWORD bytes = 0;
    const int rc = WSAIoctl(probe, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof guid, &rx->recv_msg,
                            sizeof rx->recv_msg, &bytes, NULL, NULL);
    closesocket(probe);
    if (rc != 0 || rx->recv_msg == NULL) {
        snprintf(errbuf, errlen, "WSARecvMsg unavailable");
        aes67_netrx_close(rx);
        return NULL;
    }
#endif
    return rx;
}

int aes67_netrx_add_stream(aes67_netrx_t *rx, const aes67_netrx_stream_cfg_t *cfg, char *errbuf, size_t errlen)
{
    if (rx == NULL || cfg == NULL)
        return -1;
    if (cfg->channels == 0 || cfg->rings == NULL) {
        snprintf(errbuf, errlen, "a stream needs channels and rings");
        return -1;
    }
    aes67_mutex_lock(&rx->control);
    int slot = -1;
    bool joined = false;
    for (int i = 0; i < AES67_NETRX_MAX_STREAMS; ++i) {
        const netrx_slot_t *s = &rx->slots[i];
        const uint64_t st = LOAD(&s->state);
        if (st == SLOT_FREE && slot < 0)
            slot = i;
        if (st == SLOT_ACTIVE && s->cfg.group == cfg->group && s->cfg.port == cfg->port) {
            if (s->cfg.source == cfg->source) {
                snprintf(errbuf, errlen, "that stream is already being received");
                aes67_mutex_unlock(&rx->control);
                return -1;
            }
            joined = joined || (s->cfg.source == 0 && cfg->source == 0);
        }
    }
    if (slot < 0) {
        snprintf(errbuf, errlen, "too many receive streams");
        aes67_mutex_unlock(&rx->control);
        return -1;
    }
    const int port = open_port(rx, cfg->port, errbuf, errlen);
    if (port < 0 || (!joined && !join(rx, cfg, port, true, errbuf, errlen))) {
        aes67_mutex_unlock(&rx->control);
        return -1;
    }

    netrx_slot_t *s = &rx->slots[slot];
    aes67_atomic_store(&s->state, SLOT_BUSY, AES67_MO_RELAXED);
    s->cfg = *cfg;
    s->have_seq = false;
    s->last_seq = 0;
    s->last_arrival = 0;
    aes67_atomic_u64 *counters[] = { &s->packets, &s->bytes, &s->lost, &s->reordered, &s->wrong_pt,
                                     &s->malformed, &s->jitter_worst, &s->last_arrival_ns, &s->seq };
    for (size_t i = 0; i < sizeof counters / sizeof counters[0]; ++i)
        aes67_atomic_store(counters[i], 0, AES67_MO_RELAXED);
    aes67_atomic_store(&s->state, SLOT_ACTIVE, AES67_MO_RELEASE);
    aes67_mutex_unlock(&rx->control);
    return slot;
}

void aes67_netrx_remove_stream(aes67_netrx_t *rx, int slot)
{
    if (rx == NULL || slot < 0 || slot >= AES67_NETRX_MAX_STREAMS)
        return;
    aes67_mutex_lock(&rx->control);
    netrx_slot_t *s = &rx->slots[slot];
    if (LOAD(&s->state) != SLOT_ACTIVE) {
        aes67_mutex_unlock(&rx->control);
        return;
    }
    aes67_atomic_store(&s->state, SLOT_BUSY, AES67_MO_SEQ_CST);
    /* Two passes of the receive loop: a packet that saw the slot active has
       been written by then. */
    if (LOAD(&rx->running)) {
        const uint64_t p0 = aes67_atomic_load(&rx->passes, AES67_MO_ACQUIRE);
        while (aes67_atomic_load(&rx->passes, AES67_MO_ACQUIRE) < p0 + 2 && LOAD(&rx->running))
            aes67_sleep_ms(1);
    }
    bool shared = false;
    for (int i = 0; i < AES67_NETRX_MAX_STREAMS; ++i) {
        const netrx_slot_t *o = &rx->slots[i];
        if (i != slot && LOAD(&o->state) == SLOT_ACTIVE && o->cfg.group == s->cfg.group
            && o->cfg.port == s->cfg.port && o->cfg.source == s->cfg.source)
            shared = true;
    }
    if (!shared) {
        const int n = (int) LOAD(&rx->port_count);
        for (int i = 0; i < n; ++i)
            if (rx->ports[i].port == s->cfg.port) {
                char ignored[64];
                join(rx, &s->cfg, i, false, ignored, sizeof ignored);
            }
    }
    aes67_atomic_store(&s->state, SLOT_FREE, AES67_MO_RELEASE);
    aes67_mutex_unlock(&rx->control);
}

bool aes67_netrx_start(aes67_netrx_t *rx)
{
    if (rx == NULL)
        return false;
    if (aes67_atomic_exchange(&rx->running, 1) != 0)
        return true;
    rx->have_thread = aes67_thread_start(&rx->thread, netrx_thread_main, rx);
    if (!rx->have_thread)
        aes67_atomic_store(&rx->running, 0, AES67_MO_SEQ_CST);
    return rx->have_thread;
}

void aes67_netrx_stop(aes67_netrx_t *rx)
{
    if (rx == NULL)
        return;
    aes67_atomic_store(&rx->running, 0, AES67_MO_SEQ_CST);
    if (rx->have_thread) {
        aes67_thread_join(rx->thread);
        rx->have_thread = false;
    }
}

void aes67_netrx_close(aes67_netrx_t *rx)
{
    if (rx == NULL)
        return;
    aes67_netrx_stop(rx);
#if defined(_WIN32)
    aes67_atomic_store(&rx->closing, 1, AES67_MO_SEQ_CST);
#endif
    const int n = (int) LOAD(&rx->port_count);
    for (int i = 0; i < n; ++i)
        if (rx->ports[i].fd != AES67_BAD_SOCK)
            aes67_closesock(rx->ports[i].fd);
#if defined(_WIN32)
    /* Closing cancels every outstanding receive; their buffers stay ours
       until each cancellation has come back through the port. */
    if (rx->iocp != NULL) {
        const ULONGLONG until = GetTickCount64() + 2000;
        OVERLAPPED_ENTRY entries[64];
        while (LOAD(&rx->outstanding) > 0 && LOAD(&rx->outstanding) < (1ull << 62) && GetTickCount64() < until) {
            ULONG got = 0;
            if (GetQueuedCompletionStatusEx(rx->iocp, entries, 64, &got, 50, FALSE))
                for (ULONG i = 0; i < got; ++i)
                    if (entries[i].lpOverlapped != NULL)
                        BUMP(&rx->outstanding, (uint64_t) -1);
        }
        CloseHandle(rx->iocp);
    }
    for (int i = 0; i < n; ++i)
        free(rx->ports[i].ops);
    if (rx->wsa_started)
        WSACleanup();
#endif
    aes67_mutex_destroy(&rx->control);
    free(rx);
}

void aes67_netrx_get_stats(aes67_netrx_t *rx, int slot, aes67_netrx_stats_t *out)
{
    memset(out, 0, sizeof *out);
    if (rx == NULL || slot < 0 || slot >= AES67_NETRX_MAX_STREAMS)
        return;
    netrx_slot_t *s = &rx->slots[slot];
    out->packets = LOAD(&s->packets);
    out->bytes = LOAD(&s->bytes);
    out->lost = LOAD(&s->lost);
    out->reordered = LOAD(&s->reordered);
    out->wrong_pt = LOAD(&s->wrong_pt);
    out->malformed = LOAD(&s->malformed);
    out->jitter_worst_ns = LOAD(&s->jitter_worst);
    out->last_arrival_ns = LOAD(&s->last_arrival_ns);
    const uint64_t seq = LOAD(&s->seq);
    out->last_seq_valid = (seq & 0x10000u) != 0;
    out->last_seq = (uint16_t) seq;
}

uint64_t aes67_netrx_foreign_packets(aes67_netrx_t *rx)
{
    return rx != NULL ? LOAD(&rx->foreign) : 0;
}

void aes67_netrx_inject(aes67_netrx_t *rx, uint32_t source, uint32_t destination, uint16_t port,
                        const uint8_t *packet, size_t len, uint64_t arrival_ns)
{
    if (rx != NULL)
        process(rx, source, destination, port, packet, len, arrival_ns);
}
