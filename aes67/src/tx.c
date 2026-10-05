/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libaes67 transmit. See tx.h. RTP packetisation and the socket path are
   complete; SAP is a minimal, conformant RFC 2974 v1 announcement (no
   deletion, no auth, no compression). */

#include "aes67/tx.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
   typedef SOCKET aes67_sock_t;
#  define AES67_BAD_SOCK INVALID_SOCKET
#  define aes67_closesock closesocket
#  define aes67_sockerr() WSAGetLastError()
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
   typedef int aes67_sock_t;
#  define AES67_BAD_SOCK (-1)
#  define aes67_closesock close
#  define aes67_sockerr() errno
#endif

#define SAP_GROUP       "239.255.255.255"
#define SAP_PORT        9875
#define SAP_INTERVAL_MS 30000

typedef struct aes67_tx_stream {
    aes67_tx_stream_cfg_t cfg;
    aes67_sock_t          fd;
    struct sockaddr_in    dst;
    uint16_t              seq;
    uint32_t              ssrc;
    uint64_t              packets_sent;
    uint64_t              last_sap_ms;
    uint16_t              sap_hash;
} aes67_tx_stream_t;

struct aes67_tx {
    aes67_tx_cfg_t     cfg;
    aes67_tx_stream_t  streams[AES67_TX_MAX_STREAMS];
    aes67_sock_t       sap_fd;
    struct sockaddr_in sap_dst;
#if defined(_WIN32)
    bool               wsa_started;
#endif
};

static bool open_out_socket(aes67_tx_t *tx, aes67_sock_t *fd_out, char *errbuf, size_t errlen)
{
    aes67_sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == AES67_BAD_SOCK) {
        snprintf(errbuf, errlen, "socket: error %d", aes67_sockerr());
        return false;
    }
    if (tx->cfg.iface_ip[0]) {
        struct in_addr iface;
        iface.s_addr = inet_addr(tx->cfg.iface_ip);
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (const char *) &iface, sizeof iface) < 0) {
            snprintf(errbuf, errlen, "IP_MULTICAST_IF %s: error %d", tx->cfg.iface_ip, aes67_sockerr());
            aes67_closesock(fd);
            return false;
        }
    }
    const int ttl = tx->cfg.ttl ? tx->cfg.ttl : 15;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (const char *) &ttl, sizeof ttl);
#if !defined(_WIN32)
    /* DSCP EF (46) for media, per AES67 section 7. Windows ignores IP_TOS
       from user code; QoS there is a policy matter, not a socket option. */
    const int tos = 46 << 2;
    setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof tos);
#endif
    *fd_out = fd;
    return true;
}

aes67_tx_t *aes67_tx_open(const aes67_tx_cfg_t *cfg, char *errbuf, size_t errlen)
{
    if (cfg->stream_count < 1 || cfg->stream_count > AES67_TX_MAX_STREAMS) {
        snprintf(errbuf, errlen, "bad stream_count %d", cfg->stream_count);
        return NULL;
    }
    aes67_tx_t *tx = calloc(1, sizeof *tx);
    if (!tx) {
        snprintf(errbuf, errlen, "oom");
        return NULL;
    }
    tx->cfg = *cfg;
    tx->sap_fd = AES67_BAD_SOCK;
    for (int i = 0; i < AES67_TX_MAX_STREAMS; ++i)
        tx->streams[i].fd = AES67_BAD_SOCK;
#if defined(_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        snprintf(errbuf, errlen, "WSAStartup failed");
        free(tx);
        return NULL;
    }
    tx->wsa_started = true;
#endif

    for (int i = 0; i < cfg->stream_count; ++i) {
        aes67_tx_stream_t *s = &tx->streams[i];
        s->cfg = cfg->streams[i];
        const uint32_t rate = s->cfg.sample_rate ? s->cfg.sample_rate : 48000;
        const uint32_t ptime = s->cfg.ptime_us ? s->cfg.ptime_us : 1000;
        /* Rounded, as a sender counts them: 125 us at 44.1 kHz is 6 frames. */
        const int frames = (int) (((uint64_t) rate * ptime + 500000u) / 1000000u);
        const int fits = aes67_max_channels(3, frames);
        if (s->cfg.channels == 0 || s->cfg.channels > fits) {
            snprintf(errbuf, errlen, "stream %d: %u channels do not fit a %u us packet (up to %d)",
                     i, s->cfg.channels, ptime, fits);
            aes67_tx_close(tx);
            return NULL;
        }
        if (!open_out_socket(tx, &s->fd, errbuf, errlen)) {
            aes67_tx_close(tx);
            return NULL;
        }
        memset(&s->dst, 0, sizeof s->dst);
        s->dst.sin_family = AF_INET;
        s->dst.sin_port = htons(s->cfg.port);
        s->dst.sin_addr.s_addr = inet_addr(s->cfg.group);
        s->ssrc = 0x3AE50000u | (uint32_t) i;   /* stable and recognisable in a capture */
        s->sap_hash = (uint16_t) (0xAE50u + i);
    }

    if (cfg->announce_sap) {
        if (!open_out_socket(tx, &tx->sap_fd, errbuf, errlen)) {
            aes67_tx_close(tx);
            return NULL;
        }
        memset(&tx->sap_dst, 0, sizeof tx->sap_dst);
        tx->sap_dst.sin_family = AF_INET;
        tx->sap_dst.sin_port = htons(SAP_PORT);
        tx->sap_dst.sin_addr.s_addr = inet_addr(SAP_GROUP);
    }
    return tx;
}

size_t aes67_tx_build(aes67_tx_t *tx, int stream, const int32_t *interleaved, int frames, uint32_t ts,
                      uint8_t *packet, size_t cap)
{
    if (tx == NULL || stream < 0 || stream >= tx->cfg.stream_count)
        return 0;
    aes67_tx_stream_t *s = &tx->streams[stream];
    aes67_rtp_header_t h;
    h.payload_type = (uint8_t) (s->cfg.payload_type & 0x7F);
    h.marker = false;
    h.sequence = s->seq;
    h.timestamp = ts;
    h.ssrc = s->ssrc;
    const size_t n = aes67_rtp_pack_l24(packet, cap, &h, interleaved, frames, s->cfg.channels);
    if (n > 0)
        s->seq++;
    return n;
}

bool aes67_tx_send(aes67_tx_t *tx, int stream, const int32_t *interleaved, int frames, uint32_t ts)
{
    uint8_t pkt[1500];
    const size_t n = aes67_tx_build(tx, stream, interleaved, frames, ts, pkt, sizeof pkt);
    if (n == 0)
        return false;
    aes67_tx_stream_t *s = &tx->streams[stream];
    const int sent = (int) sendto(s->fd, (const char *) pkt, (int) n, 0,
                                  (struct sockaddr *) &s->dst, sizeof s->dst);
    if (sent == (int) n) {
        s->packets_sent++;
        return true;
    }
    return false;
}

bool aes67_tx_send_packet(aes67_tx_t *tx, int stream, const uint8_t *packet, size_t len)
{
    if (tx == NULL || stream < 0 || stream >= tx->cfg.stream_count || packet == NULL || len == 0)
        return false;
    aes67_tx_stream_t *s = &tx->streams[stream];
    const int sent = (int) sendto(s->fd, (const char *) packet, (int) len, 0,
                                  (struct sockaddr *) &s->dst, sizeof s->dst);
    if (sent == (int) len) {
        s->packets_sent++;
        return true;
    }
    return false;
}

int aes67_tx_sdp(aes67_tx_t *tx, int stream, char *buf, size_t len)
{
    if (tx == NULL || stream < 0 || stream >= tx->cfg.stream_count)
        return -1;
    const aes67_tx_stream_t *s = &tx->streams[stream];
    aes67_sdp_params_t p;
    memset(&p, 0, sizeof p);
    p.session_name = s->cfg.name;
    p.origin_ip = tx->cfg.iface_ip[0] ? tx->cfg.iface_ip : "0.0.0.0";
    p.group = s->cfg.group;
    p.port = s->cfg.port;
    p.payload_type = s->cfg.payload_type;
    p.channels = s->cfg.channels;
    p.sample_rate = s->cfg.sample_rate ? s->cfg.sample_rate : 48000;
    p.ptime_us = s->cfg.ptime_us ? s->cfg.ptime_us : 1000;
    p.ssrc = s->ssrc;
    p.ttl = tx->cfg.ttl;
    memcpy(p.gm_identity, tx->cfg.gm_identity, sizeof p.gm_identity);
    p.ptp_domain = tx->cfg.ptp_domain;
    return aes67_sdp_write(buf, len, &p);
}

void aes67_tx_sap_tick(aes67_tx_t *tx, uint64_t now_ms)
{
    if (tx == NULL || tx->sap_fd == AES67_BAD_SOCK)
        return;
    for (int i = 0; i < tx->cfg.stream_count; ++i) {
        aes67_tx_stream_t *s = &tx->streams[i];
        if (s->last_sap_ms && now_ms - s->last_sap_ms < SAP_INTERVAL_MS)
            continue;
        s->last_sap_ms = now_ms;

        uint8_t pkt[1200];
        const uint32_t origin = tx->cfg.iface_ip[0] ? inet_addr(tx->cfg.iface_ip) : 0;
        pkt[0] = 0x20;   /* v=1, announce, IPv4, no auth or compression */
        pkt[1] = 0;      /* auth length */
        pkt[2] = (uint8_t) (s->sap_hash >> 8);
        pkt[3] = (uint8_t) s->sap_hash;
        memcpy(pkt + 4, &origin, 4);
        const char *mime = "application/sdp";
        size_t off = 8;
        memcpy(pkt + off, mime, strlen(mime) + 1);
        off += strlen(mime) + 1;
        const int n = aes67_tx_sdp(tx, i, (char *) pkt + off, sizeof pkt - off);
        if (n > 0 && off + (size_t) n <= sizeof pkt)
            sendto(tx->sap_fd, (const char *) pkt, (int) (off + (size_t) n), 0,
                   (struct sockaddr *) &tx->sap_dst, sizeof tx->sap_dst);
    }
}

uint64_t aes67_tx_packets_sent(aes67_tx_t *tx, int stream)
{
    if (tx == NULL || stream < 0 || stream >= tx->cfg.stream_count)
        return 0;
    return tx->streams[stream].packets_sent;
}

void aes67_tx_close(aes67_tx_t *tx)
{
    if (tx == NULL)
        return;
    for (int i = 0; i < AES67_TX_MAX_STREAMS; ++i)
        if (tx->streams[i].fd != AES67_BAD_SOCK)
            aes67_closesock(tx->streams[i].fd);
    if (tx->sap_fd != AES67_BAD_SOCK)
        aes67_closesock(tx->sap_fd);
#if defined(_WIN32)
    if (tx->wsa_started)
        WSACleanup();
#endif
    free(tx);
}
