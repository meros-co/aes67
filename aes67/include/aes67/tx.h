/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

#ifndef MANIFOLD_AES67_TX_H
#define MANIFOLD_AES67_TX_H

/* libaes67 transmit: frames in, RTP/L24 multicast packets out, plus the SDP
 * that makes the stream subscribable and a SAP announcer for receivers that
 * have no NMOS.
 *
 * Transmit is cheap next to receive -- one packet per packet-time per stream
 * -- so it is done synchronously from the caller's thread at packet cadence;
 * the media clock the caller stamps frames with is the same domain the
 * receive side reads by.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "rtp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES67_TX_MAX_STREAMS  16
/* No channel ceiling of its own: a stream carries as many channels as fit
   in one packet at its packet time (aes67_max_channels). */

typedef struct aes67_tx_stream_cfg {
    char     group[16];       /* destination multicast group */
    uint16_t port;            /* 5004 by convention */
    uint8_t  payload_type;    /* 96..127 */
    uint8_t  channels;        /* interleaved channel count */
    uint32_t ptime_us;        /* 1000, 250, 125 */
    uint32_t sample_rate;     /* 48000 default */
    char     name[64];        /* session name for the SDP */
} aes67_tx_stream_cfg_t;

typedef struct aes67_tx_cfg {
    char     iface_ip[16];
    uint8_t  ttl;             /* 0 = 15 */
    bool     announce_sap;    /* periodic SAP/SDP on 239.255.255.255:9875 */
    uint8_t  gm_identity[8];  /* the PTP grandmaster, for the SDP; zero = unstated */
    uint16_t ptp_domain;
    aes67_tx_stream_cfg_t streams[AES67_TX_MAX_STREAMS];
    int      stream_count;
} aes67_tx_cfg_t;

typedef struct aes67_tx aes67_tx_t;

aes67_tx_t *aes67_tx_open(const aes67_tx_cfg_t *cfg, char *errbuf, size_t errlen);

/* Sends one packet-time of frames for a stream: `frames` x channels of
   right-justified 24-bit samples, `ts` the media-clock timestamp of the first
   frame. False when the packet would not fit or the send failed. */
bool aes67_tx_send(aes67_tx_t *tx, int stream, const int32_t *interleaved, int frames, uint32_t ts);

/* Builds the packet without sending it -- what the tests check, and what a
   caller with its own transport (a bench, a capture) wants. Returns the
   packet length or 0. Advances the sequence number exactly as a send does. */
size_t aes67_tx_build(aes67_tx_t *tx, int stream, const int32_t *interleaved, int frames, uint32_t ts,
                      uint8_t *packet, size_t cap);

/* Sends a packet aes67_tx_build made earlier (a paced sender builds on the
   audio thread and sends on its own). False when the send failed. */
bool aes67_tx_send_packet(aes67_tx_t *tx, int stream, const uint8_t *packet, size_t len);

/* This stream's SDP, for SAP, RTSP, or the control plane to hand out. */
int aes67_tx_sdp(aes67_tx_t *tx, int stream, char *buf, size_t len);

/* Call at about 1 Hz when announce_sap is set; announces each stream every
   30 s (RFC 2974). */
void aes67_tx_sap_tick(aes67_tx_t *tx, uint64_t now_ms);

uint64_t aes67_tx_packets_sent(aes67_tx_t *tx, int stream);
void aes67_tx_close(aes67_tx_t *tx);

#ifdef __cplusplus
}
#endif

#endif /* MANIFOLD_AES67_TX_H */
