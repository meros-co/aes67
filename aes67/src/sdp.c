/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libaes67 SDP parsing. See sdp.h.
   Line-oriented and forgiving: SDP on a real network carries every vendor's
   private attributes, and refusing a stream over one of them would be
   refusing the device. */

#include "aes67/sdp.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- small helpers -------------------------------------------------------- */

static void copy_token(char *dst, size_t cap, const char *src, size_t n)
{
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool starts_with(const char *line, size_t len, const char *prefix)
{
    const size_t p = strlen(prefix);
    return len >= p && memcmp(line, prefix, p) == 0;
}

/* Fractional milliseconds ("0.125", "1", "4.0") to whole microseconds. */
static uint32_t ms_text_to_us(const char *s, size_t n)
{
    char buf[32];
    copy_token(buf, sizeof buf, s, n);
    const double ms = atof(buf);
    return ms > 0 ? (uint32_t) (ms * 1000.0 + 0.5) : 0;
}

/* "00-1D-C1-FF-FE-12-34-56" (AES67) or "00:1D:..." -> eight bytes. */
static bool parse_gm_identity(const char *s, size_t n, uint8_t out[8])
{
    int byte = 0, digits = 0, value = 0;
    for (size_t i = 0; i < n && byte < 8; ++i) {
        const char c = s[i];
        if (isxdigit((unsigned char) c)) {
            value = value * 16 + (isdigit((unsigned char) c) ? c - '0' : (tolower((unsigned char) c) - 'a' + 10));
            if (++digits == 2) {
                out[byte++] = (uint8_t) value;
                value = 0;
                digits = 0;
            }
        } else if (c == '-' || c == ':') {
            if (digits != 0)
                return false;
        } else {
            break;
        }
    }
    return byte == 8 && digits == 0;
}

/* ---- the parser ----------------------------------------------------------- */

typedef struct parse_state {
    aes67_sdp_t *out;
    bool in_media;          /* past the m=audio line we chose */
    bool media_done;        /* past the end of that section */
    bool have_media;
    /* The first media section that is not audio, for the essence. */
    bool in_other;
    char other_media[16];
    int  other_pt;
    char other_encoding[24];
} parse_state_t;

static void note_other_media(parse_state_t *st, const char *v, size_t n)
{
    /* m=video 5000 RTP/AVP 96 -- remembered once, never parsed as ours */
    if (st->other_media[0] != '\0')
        return;
    char buf[128];
    copy_token(buf, sizeof buf, v, n);
    const char *media = strtok(buf, " ");
    const char *port = strtok(NULL, " ");
    strtok(NULL, " ");
    const char *pt = strtok(NULL, " ");
    if (media == NULL)
        return;
    copy_token(st->other_media, sizeof st->other_media, media, strlen(media));
    st->out->other_port = port != NULL ? (uint16_t) atoi(port) : 0;
    st->other_pt = pt != NULL ? atoi(pt) : -1;
    st->in_other = true;
}

static void note_other_rtpmap(parse_state_t *st, const char *v, size_t n)
{
    /* a=rtpmap:96 raw/90000 */
    char buf[128];
    copy_token(buf, sizeof buf, v, n);
    char *sp = strchr(buf, ' ');
    if (sp == NULL || atoi(buf) != st->other_pt)
        return;
    char *enc = sp + 1;
    char *slash = strchr(enc, '/');
    if (slash != NULL)
        *slash = '\0';
    copy_token(st->other_encoding, sizeof st->other_encoding, enc, strlen(enc));
}

static void describe_essence(char *out, size_t len, const char *media, const char *enc)
{
    if (strcmp(media, "audio") == 0 && strcmp(enc, "AM824") == 0)
        snprintf(out, len, "ST 2110-31 AES3");
    else if (strcmp(media, "audio") == 0)
        snprintf(out, len, "AES67 audio (%s)", enc[0] ? enc : "?");
    else if (strcmp(media, "video") == 0 && strcmp(enc, "raw") == 0)
        snprintf(out, len, "ST 2110-20 video");
    else if (strcmp(media, "video") == 0 && strcmp(enc, "jxsv") == 0)
        snprintf(out, len, "ST 2110-22 video (JPEG XS)");
    else if (strcmp(enc, "smpte291") == 0)
        snprintf(out, len, "ST 2110-40 ancillary data");
    else if (strcmp(media, "video") == 0)
        snprintf(out, len, "ST 2110-22 video (%s)", enc[0] ? enc : "?");
    else
        snprintf(out, len, "%s (%s)", media[0] ? media : "?", enc[0] ? enc : "?");
}

static void parse_c_line(parse_state_t *st, const char *v, size_t n)
{
    /* c=IN IP4 239.69.1.1/15 */
    const char *addr = NULL;
    size_t addr_len = 0;
    int field = 0;
    const char *tok = v;
    for (size_t i = 0; i <= n; ++i) {
        if (i == n || v[i] == ' ') {
            if (field == 2) { addr = tok; addr_len = (size_t) (v + i - tok); }
            ++field;
            tok = v + i + 1;
        }
    }
    if (addr == NULL)
        return;
    const char *slash = memchr(addr, '/', addr_len);
    if (slash != NULL) {
        st->out->connection_ttl = atoi(slash + 1);
        addr_len = (size_t) (slash - addr);
    }
    copy_token(st->out->connection_ip, sizeof st->out->connection_ip, addr, addr_len);
}

static void parse_rtpmap(parse_state_t *st, const char *v, size_t n)
{
    /* a=rtpmap:98 L24/48000/8 */
    char buf[128];
    copy_token(buf, sizeof buf, v, n);
    char *sp = strchr(buf, ' ');
    if (sp == NULL)
        return;
    *sp = '\0';
    if (atoi(buf) != (int) st->out->payload_type)
        return;   /* another payload type's description */
    char *enc = sp + 1;
    char *slash = strchr(enc, '/');
    if (slash != NULL)
        *slash++ = '\0';
    copy_token(st->out->encoding, sizeof st->out->encoding, enc, strlen(enc));
    st->out->is_st2110_31 = strcmp(enc, "AM824") == 0;
    st->out->channels = 1;   /* RFC 4566: absent means one */
    if (slash != NULL) {
        st->out->sample_rate = (uint32_t) atoi(slash);
        char *slash2 = strchr(slash, '/');
        if (slash2 != NULL)
            st->out->channels = (uint8_t) atoi(slash2 + 1);
    }
}

static void parse_fmtp(parse_state_t *st, const char *v, size_t n)
{
    /* a=fmtp:97 channel-order=SMPTE2110.(ST) */
    char buf[256];
    copy_token(buf, sizeof buf, v, n);
    char *sp = strchr(buf, ' ');
    if (sp == NULL || atoi(buf) != (int) st->out->payload_type)
        return;
    const char *co = strstr(sp + 1, "channel-order=");
    if (co != NULL) {
        co += strlen("channel-order=");
        size_t len = strcspn(co, "; ");
        copy_token(st->out->channel_order, sizeof st->out->channel_order, co, len);
    }
}

static void parse_ts_refclk(parse_state_t *st, const char *v, size_t n)
{
    aes67_sdp_t *o = st->out;
    if (starts_with(v, n, "ptp=")) {
        /* ptp=IEEE1588-2008:00-1D-C1-FF-FE-12-34-56:0
           ptp=IEEE1588-2008:traceable
           ptp=IEEE1588-2019:...              */
        o->refclk_ptp = true;
        const char *p = v + 4;
        size_t rem = n - 4;
        const char *colon = memchr(p, ':', rem);
        const size_t ver_len = colon ? (size_t) (colon - p) : rem;
        copy_token(o->ptp_version, sizeof o->ptp_version, p, ver_len);
        if (colon == NULL)
            return;
        p = colon + 1;
        rem = n - (size_t) (p - v);
        if (starts_with(p, rem, "traceable")) {
            o->gm_traceable = true;
            return;
        }
        const char *colon2 = memchr(p, ':', rem);
        const size_t id_len = colon2 ? (size_t) (colon2 - p) : rem;
        if (parse_gm_identity(p, id_len, o->gm_identity))
            o->gm_known = true;
        if (colon2 != NULL)
            o->ptp_domain = atoi(colon2 + 1);
    } else if (starts_with(v, n, "localmac=")) {
        o->refclk_localmac = true;
    }
}

static void parse_source_filter(parse_state_t *st, const char *v, size_t n)
{
    /* a=source-filter: incl IN IP4 239.69.1.1 192.168.1.10 */
    char buf[256];
    copy_token(buf, sizeof buf, v, n);
    char *tok = strtok(buf, " ");
    int field = 0;
    const char *src = NULL;
    while (tok != NULL) {
        if (field == 4)
            src = tok;   /* incl, IN, IP4, dest, src */
        ++field;
        tok = strtok(NULL, " ");
    }
    if (src != NULL)
        copy_token(st->out->source_ip, sizeof st->out->source_ip, src, strlen(src));
}

static void parse_attribute(parse_state_t *st, const char *v, size_t n)
{
    aes67_sdp_t *o = st->out;
    const char *colon = memchr(v, ':', n);
    const size_t name_len = colon ? (size_t) (colon - v) : n;
    const char *val = colon ? colon + 1 : v + n;
    size_t val_len = colon ? n - name_len - 1 : 0;
    /* Some senders write "a=source-filter: incl ..." with a space after the colon. */
    while (val_len > 0 && *val == ' ') { ++val; --val_len; }

#define NAME_IS(s) (name_len == strlen(s) && memcmp(v, s, name_len) == 0)
    if (NAME_IS("rtpmap"))              parse_rtpmap(st, val, val_len);
    else if (NAME_IS("fmtp"))           parse_fmtp(st, val, val_len);
    else if (NAME_IS("ptime"))          o->ptime_us = ms_text_to_us(val, val_len);
    else if (NAME_IS("maxptime"))       o->maxptime_us = ms_text_to_us(val, val_len);
    else if (NAME_IS("framecount"))     o->framecount = (uint32_t) atoi(val);
    else if (NAME_IS("ts-refclk"))      parse_ts_refclk(st, val, val_len);
    else if (NAME_IS("source-filter"))  parse_source_filter(st, val, val_len);
    else if (NAME_IS("mediaclk")) {
        if (starts_with(val, val_len, "direct=")) {
            o->mediaclk_direct = true;
            o->mediaclk_offset = atoll(val + 7);
        }
    }
    else if (NAME_IS("clock-domain")) {
        /* Older RAVENNA: "PTPv2 0" -- the domain, when no ts-refclk gave one. */
        const char *sp = memchr(val, ' ', val_len);
        if (sp != NULL && o->ptp_domain < 0)
            o->ptp_domain = atoi(sp + 1);
    }
    else if (NAME_IS("sendonly"))       o->direction = AES67_SDP_SENDONLY;
    else if (NAME_IS("recvonly"))       o->direction = AES67_SDP_RECVONLY;
    else if (NAME_IS("inactive"))       o->direction = AES67_SDP_INACTIVE;
    else if (NAME_IS("sendrecv"))       o->direction = AES67_SDP_SENDRECV;
#undef NAME_IS
}

static bool parse_m_line(parse_state_t *st, const char *v, size_t n, char *errbuf, size_t errlen)
{
    /* m=audio 5004 RTP/AVP 98 */
    char buf[128];
    copy_token(buf, sizeof buf, v, n);
    char *tok = strtok(buf, " ");
    if (tok == NULL || strcmp(tok, "audio") != 0)
        return false;   /* not ours; the caller keeps scanning */
    const char *port = strtok(NULL, " ");
    const char *proto = strtok(NULL, " ");
    const char *pt = strtok(NULL, " ");
    if (port == NULL || proto == NULL || pt == NULL) {
        snprintf(errbuf, errlen, "audio m= line is incomplete");
        return false;
    }
    if (strncmp(proto, "RTP/AVP", 7) != 0) {
        snprintf(errbuf, errlen, "audio media is not RTP/AVP (%s)", proto);
        return false;
    }
    st->out->port = (uint16_t) atoi(port);
    st->out->payload_type = (uint8_t) atoi(pt);
    st->have_media = true;
    st->in_media = true;
    return true;
}

bool aes67_sdp_parse(const char *text, size_t len, aes67_sdp_t *out, char *errbuf, size_t errlen)
{
    if (errlen > 0)
        errbuf[0] = '\0';
    memset(out, 0, sizeof *out);
    out->connection_ttl = -1;
    out->ptp_domain = -1;
    if (text == NULL || len == 0) {
        snprintf(errbuf, errlen, "empty SDP");
        return false;
    }

    parse_state_t st = { out, false, false, false };
    size_t pos = 0;
    while (pos < len) {
        const char *line = text + pos;
        size_t n = 0;
        while (pos + n < len && text[pos + n] != '\n')
            ++n;
        size_t consumed = n + 1;
        if (n > 0 && line[n - 1] == '\r')
            --n;
        pos += consumed;
        if (n < 2 || line[1] != '=')
            continue;
        const char type = line[0];
        const char *v = line + 2;
        const size_t vn = n - 2;

        if (type == 'm') {
            st.in_other = false;
            if (st.in_media) {
                /* The end of our section; later media are other streams. */
                st.in_media = false;
                st.media_done = true;
                continue;
            }
            if (st.media_done)
                continue;
            if (parse_m_line(&st, v, vn, errbuf, errlen))
                continue;
            if (errbuf[0] != '\0')
                return false;
            note_other_media(&st, v, vn);
            continue;
        }
        if (st.media_done)
            continue;
        if (st.in_other) {
            /* Another essence's attributes: its rtpmap names it, the rest
               (its clock, its format) is not ours to take. */
            if (type == 'a' && vn > 7 && strncmp(v, "rtpmap:", 7) == 0)
                note_other_rtpmap(&st, v + 7, vn - 7);
            continue;
        }

        switch (type) {
            case 's': copy_token(out->session_name, sizeof out->session_name, v, vn); break;
            case 'o': {
                /* o=- 12345 0 IN IP4 192.168.1.10: the last field */
                const char *last = v + vn;
                while (last > v && last[-1] != ' ')
                    --last;
                copy_token(out->origin_ip, sizeof out->origin_ip, last, (size_t) (v + vn - last));
                break;
            }
            case 'c': parse_c_line(&st, v, vn); break;   /* session or media level, later wins */
            case 'a': parse_attribute(&st, v, vn); break;
            default: break;
        }
    }

    if (!st.have_media) {
        if (st.other_media[0] != '\0') {
            describe_essence(out->essence, sizeof out->essence, st.other_media, st.other_encoding);
            snprintf(errbuf, errlen, "no audio media section: this is %s", out->essence);
        }
        else
            snprintf(errbuf, errlen, "no audio media section");
        return false;
    }
    describe_essence(out->essence, sizeof out->essence, "audio", out->encoding);
    return true;
}

bool aes67_sdp_shares_grandmaster(const aes67_sdp_t *sdp, const uint8_t our_gm[8], int our_domain)
{
    bool we_have_gm = false;
    for (int i = 0; i < 8; ++i)
        if (our_gm[i] != 0)
            we_have_gm = true;
    if (!we_have_gm || !sdp->refclk_ptp)
        return false;
    const int stream_domain = sdp->ptp_domain < 0 ? 0 : sdp->ptp_domain;
    if (stream_domain != our_domain)
        return false;
    if (sdp->gm_traceable)
        return true;
    return sdp->gm_known && memcmp(sdp->gm_identity, our_gm, 8) == 0;
}
