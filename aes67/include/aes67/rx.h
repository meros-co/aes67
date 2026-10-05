/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

#ifndef MANIFOLD_AES67_RX_H
#define MANIFOLD_AES67_RX_H

/* libaes67 receive: N multicast streams -> RTP -> per-channel playout rings.
 *
 * The receive thread is the only writer; the consumer (the engine's audio
 * thread) reads rings with aes67_rx_read() and is never blocked. Latency is
 * the reader's choice: it picks the timestamp it plays, a margin behind the
 * newest the stream has delivered.
 *
 * Two socket paths behind one interface:
 *  - Linux: recvmmsg batches, epoll, SO_TIMESTAMPNS for arrival jitter,
 *    optional SO_BUSY_POLL and CPU pinning. This is the appliance path, and
 *    it is the one the receive benchmarks were measured on.
 *  - Everything else (Windows, macOS): one socket per port with every
 *    stream's group joined on it, poll + recvmsg one packet at a time, each
 *    packet sorted to its stream by its destination address (IP_PKTINFO, or
 *    IP_RECVDSTADDR on BSD), arrival stamped with the monotonic clock. So
 *    every stream can share 5004, as real AES67 does.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rtp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_RX_MAX_STREAMS        64
/* No channel ceiling: a receiver holds a ring for every channel its streams
   carry, sized when it opens. How many one stream can carry is the packet's
   business (aes67_max_channels). */

typedef struct aes67_rx_stream_cfg {
    char     group[16];        /* dotted-quad multicast group */
    uint16_t port;             /* AES67 convention: 5004, shared */
    uint8_t  payload_type;     /* expected RTP PT (96..127) */
    uint8_t  channels;         /* channels interleaved in this stream */
    uint16_t first_channel;    /* index of its first channel in the ring map */
    uint8_t  format;           /* aes67_sample_format_t; zero (L24) when left alone */
} aes67_rx_stream_cfg_t;

typedef struct aes67_rx_cfg {
    char                  iface_ip[16];   /* local interface for the IGMP join */
    aes67_rx_stream_cfg_t streams[AES67_RX_MAX_STREAMS];
    int                   stream_count;
    int                   cpu;            /* pin the receive thread; -1 = do not */
    bool                  busy_poll;      /* SO_BUSY_POLL escalation (Linux) */
    int                   busy_poll_us;
    bool                  shared_port;    /* Linux: bind each socket to its group, one port for all (real AES67).
                                             Windows and macOS always share the port: one socket per port, each
                                             packet sorted to its stream by destination address. */
} aes67_rx_cfg_t;

typedef struct aes67_rx_stream_stats {
    uint64_t packets, bytes;
    uint64_t seq_lost, seq_reordered, wrong_pt, too_short;
    uint32_t last_seq_valid;
    uint16_t last_seq;
    uint64_t jitter_worst_ns;  /* worst inter-arrival gap */
} aes67_rx_stream_stats_t;

typedef struct aes67_rx aes67_rx_t;

/* Allocates, opens and joins every stream's socket. NULL on failure with the
   reason in errbuf. */
aes67_rx_t *aes67_rx_open(const aes67_rx_cfg_t *cfg, char *errbuf, size_t errlen);

/* Starts the receive thread (real-time priority where permitted). */
bool aes67_rx_start(aes67_rx_t *rx);

/* Reads `frames` samples of `channel` from timestamp `ts`; missing frames are
   zero. Audio thread; wait-free. Returns how many were present. */
int aes67_rx_read(aes67_rx_t *rx, int channel, uint32_t ts, int32_t *out, int frames);

/* Newest timestamp every channel of a stream has reached, less a margin:
   the playout scheduling input. */
uint32_t aes67_rx_playout_ts(aes67_rx_t *rx, int stream, uint32_t margin_frames);

void aes67_rx_get_stats(aes67_rx_t *rx, int stream, aes67_rx_stream_stats_t *out);
/* Packets that reached this receiver's sockets for a group none of its
   streams joined -- another receiver's on the same port -- and were dropped.
   Always 0 on Linux, where each socket is bound to its own group. */
uint64_t aes67_rx_foreign_packets(aes67_rx_t *rx);
void aes67_rx_stop(aes67_rx_t *rx);
void aes67_rx_close(aes67_rx_t *rx);

/* Feeds one packet as if it had arrived on `stream`: the whole parse, stats
   and ring path without a socket. What the tests use, and what a bench can
   replay a capture through. */
void aes67_rx_inject(aes67_rx_t *rx, int stream, const uint8_t *packet, size_t len, uint64_t arrival_ns);

#ifdef __cplusplus
}
#endif

#endif /* MANIFOLD_AES67_RX_H */
