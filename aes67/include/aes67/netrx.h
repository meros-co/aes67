/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

#ifndef MEROS_AES67_NETRX_H
#define MEROS_AES67_NETRX_H

/* libaes67 network receive into rings the caller owns.
 *
 * AES67 puts every stream on one port (5004) and tells them apart by multicast
 * group. This receiver opens one socket per port, joins every stream's group
 * on it, and sorts each datagram by its destination address (IP_PKTINFO) and,
 * for a source-specific stream, its source. A datagram for no stream here --
 * another receiver's group on the same port -- is counted and dropped.
 *
 *  - Windows: overlapped WSARecvMsg on an I/O completion port, many receives
 *    outstanding per socket, the thread in the MMCSS "Pro Audio" class.
 *  - macOS, Linux and other POSIX: poll and recvmsg (IP_RECVPKTINFO or
 *    IP_PKTINFO; on Linux, IP_MULTICAST_ALL off).
 *
 * The rings are the caller's: in shared memory a driver reads, say. Each
 * packet is written with aes67_rtp_write_rings at the stream's media-clock
 * offset, so a ring's index is the media clock. Streams come and go while it
 * runs.
 *
 * aes67_rx (rx.h) is the other receiver: it owns its rings, and its streams
 * are fixed when it opens. Off Linux it runs on this one. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rtp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_NETRX_MAX_STREAMS 128
#define AES67_NETRX_MAX_PORTS   16

typedef struct aes67_netrx_stream_cfg {
    uint32_t      group;               /* destination: a multicast group (or a local unicast address), network order */
    uint32_t      source;              /* source-specific sender, network order; 0 = any */
    uint16_t      port;                /* AES67 convention: 5004 */
    uint8_t       payload_type;
    uint8_t       format;              /* aes67_sample_format_t */
    uint16_t      channels;
    uint32_t      media_clock_offset;  /* SDP a=mediaclk:direct=<offset> */
    aes67_ring_t *rings;               /* `channels` of them, the caller's; written until the stream is removed */
} aes67_netrx_stream_cfg_t;

typedef struct aes67_netrx_stats {
    uint64_t packets, bytes;
    uint64_t lost, reordered, wrong_pt, malformed;
    uint64_t jitter_worst_ns;          /* worst inter-arrival gap */
    uint64_t last_arrival_ns;          /* monotonic; 0 = nothing yet */
    uint16_t last_seq;
    bool     last_seq_valid;
} aes67_netrx_stats_t;

typedef struct aes67_netrx aes67_netrx_t;

/* `iface_ip`: the local interface (dotted quad) the groups are joined on;
   NULL or "" = the system's choice. NULL with the reason when sockets are not
   available. */
aes67_netrx_t *aes67_netrx_open(const char *iface_ip, char *errbuf, size_t errlen);
/* Stops, leaves every group, closes the sockets. */
void aes67_netrx_close(aes67_netrx_t *rx);

/* Starts receiving a stream: a socket for its port if there is none yet, a
   join of its group (unless another stream here has joined it). Any thread,
   running or not. Returns the stream's slot, or -1 with the reason. The same
   group, port and source twice is refused. */
int  aes67_netrx_add_stream(aes67_netrx_t *rx, const aes67_netrx_stream_cfg_t *cfg, char *errbuf, size_t errlen);
/* Leaves the group (unless another stream shares it) and stops writing the
   stream's rings: on return the receive thread no longer touches them. */
void aes67_netrx_remove_stream(aes67_netrx_t *rx, int slot);

bool aes67_netrx_start(aes67_netrx_t *rx);
void aes67_netrx_stop(aes67_netrx_t *rx);

void aes67_netrx_get_stats(aes67_netrx_t *rx, int slot, aes67_netrx_stats_t *out);
/* Datagrams that reached these sockets for no stream here. */
uint64_t aes67_netrx_foreign_packets(aes67_netrx_t *rx);

/* Feeds one datagram as if it had arrived: the demultiplexing, parsing and
   ring path without a socket. Addresses in network byte order. */
void aes67_netrx_inject(aes67_netrx_t *rx, uint32_t source, uint32_t destination, uint16_t port,
                        const uint8_t *packet, size_t len, uint64_t arrival_ns);

/* Dotted quad to network-order IPv4; false when malformed. */
bool aes67_parse_ipv4(const char *text, uint32_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MEROS_AES67_NETRX_H */
