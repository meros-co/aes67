/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libmdns -- see mdns.h. The wire code first (no socket in it), then the
 * responder/browser state machine over it, then the one socket. */

#if defined(__linux__)
#  define _GNU_SOURCE
#endif

#include "mdns/mdns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
   typedef SOCKET mdns_sock_t;
#  define MDNS_BAD_SOCK INVALID_SOCKET
#  define mdns_closesock closesocket
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <time.h>
#  include <unistd.h>
   typedef int mdns_sock_t;
#  define MDNS_BAD_SOCK (-1)
#  define mdns_closesock close
#endif

#define MDNS_GROUP  "224.0.0.251"
#define MDNS_PORT   5353
#define MDNS_TTL_HOST 120      /* SRV, TXT, A: things that change with the box */
#define MDNS_TTL_PTR  4500     /* the name of a service: stable */
#define MDNS_BROWSE_TYPES 8

static void copy_str(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

static uint64_t now_ms(void)
{
#if defined(_WIN32)
    return (uint64_t) GetTickCount64();
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t) t.tv_sec * 1000u + (uint64_t) t.tv_nsec / 1000000u;
#endif
}

/* ====================================================================== wire */

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t) (v >> 8); p[1] = (uint8_t) v; }
static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t) (v >> 24); p[1] = (uint8_t) (v >> 16); p[2] = (uint8_t) (v >> 8); p[3] = (uint8_t) v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t) ((p[0] << 8) | p[1]); }
static uint32_t get32(const uint8_t *p) { return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3]; }

/* Presentation name -> labels. A label may be up to 63 bytes; the name up
 * to 255 on the wire. No escaping: a dot inside an instance name is not
 * representable, which DNS-SD tolerates by convention and we document. */
static size_t write_name(uint8_t *buf, size_t cap, const char *name)
{
    size_t off = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t n = dot ? (size_t) (dot - p) : strlen(p);
        if (n == 0 || n > 63 || off + 1 + n + 1 > cap)
            return 0;
        buf[off++] = (uint8_t) n;
        memcpy(buf + off, p, n);
        off += n;
        p += n;
        if (*p == '.')
            ++p;
    }
    if (off + 1 > cap)
        return 0;
    buf[off++] = 0;
    return off;
}

/* Wire name at `off` -> presentation, following compression pointers.
 * Returns the offset just past the name in the *original* stream. */
static size_t read_name(const uint8_t *pkt, size_t len, size_t off, char *out, size_t out_cap)
{
    size_t end = 0;       /* where the un-jumped stream resumes */
    size_t o = 0;
    int jumps = 0;
    out[0] = 0;
    for (;;) {
        if (off >= len)
            return 0;
        uint8_t c = pkt[off];
        if (c == 0) {
            if (!end)
                end = off + 1;
            break;
        }
        if ((c & 0xC0) == 0xC0) {
            if (off + 1 >= len || ++jumps > 16)
                return 0;
            size_t ptr = (size_t) ((c & 0x3F) << 8 | pkt[off + 1]);
            if (!end)
                end = off + 2;
            if (ptr >= off)      /* pointers only go backwards */
                return 0;
            off = ptr;
            continue;
        }
        if (c > 63 || off + 1 + c > len)
            return 0;
        if (o + c + 2 > out_cap)
            return 0;
        if (o)
            out[o++] = '.';
        memcpy(out + o, pkt + off + 1, c);
        o += c;
        out[o] = 0;
        off += 1 + c;
    }
    return end;
}

bool mdns_parse_message(const uint8_t *pkt, size_t len, mdns_message_t *out)
{
    memset(out, 0, sizeof *out);
    if (len < 12)
        return false;
    out->id = get16(pkt);
    const uint16_t flags = get16(pkt + 2);
    out->is_response = (flags & 0x8000) != 0;
    const int qd = get16(pkt + 4);
    const int rr = get16(pkt + 6) + get16(pkt + 8) + get16(pkt + 10);
    size_t off = 12;

    for (int i = 0; i < qd; ++i) {
        char name[MDNS_NAME_MAX];
        off = read_name(pkt, len, off, name, sizeof name);
        if (!off || off + 4 > len)
            return false;
        if (out->question_count < MDNS_MSG_QUESTIONS) {
            mdns_question_t *q = &out->questions[out->question_count++];
            copy_str(q->name, sizeof q->name, name);
            q->type = get16(pkt + off);
            q->unicast_reply = (get16(pkt + off + 2) & 0x8000) != 0;
        }
        off += 4;
    }

    for (int i = 0; i < rr; ++i) {
        char name[MDNS_NAME_MAX];
        off = read_name(pkt, len, off, name, sizeof name);
        if (!off || off + 10 > len)
            return false;
        const uint16_t type = get16(pkt + off);
        const uint16_t cls = get16(pkt + off + 2);
        const uint32_t ttl = get32(pkt + off + 4);
        const size_t rdlen = get16(pkt + off + 8);
        const size_t rd = off + 10;
        if (rd + rdlen > len)
            return false;
        off = rd + rdlen;

        if (out->record_count >= MDNS_MSG_RECORDS)
            continue;
        mdns_record_t *r = &out->records[out->record_count];
        memset(r, 0, sizeof *r);
        copy_str(r->name, sizeof r->name, name);
        r->type = type;
        r->ttl = ttl;
        r->cache_flush = (cls & 0x8000) != 0;
        bool keep = true;
        switch (type) {
        case MDNS_TYPE_PTR:
            keep = read_name(pkt, len, rd, r->rd.ptr.target, sizeof r->rd.ptr.target) != 0;
            break;
        case MDNS_TYPE_SRV:
            if (rdlen < 7) { keep = false; break; }
            r->rd.srv.priority = get16(pkt + rd);
            r->rd.srv.weight = get16(pkt + rd + 2);
            r->rd.srv.port = get16(pkt + rd + 4);
            keep = read_name(pkt, len, rd + 6, r->rd.srv.target, sizeof r->rd.srv.target) != 0;
            break;
        case MDNS_TYPE_TXT: {
            size_t p = rd;
            while (p < rd + rdlen && r->rd.txt.count < MDNS_TXT_MAX) {
                size_t n = pkt[p];
                if (p + 1 + n > rd + rdlen) { keep = false; break; }
                if (n >= MDNS_TXT_LEN) n = MDNS_TXT_LEN - 1;
                memcpy(r->rd.txt.text[r->rd.txt.count], pkt + p + 1, n);
                r->rd.txt.text[r->rd.txt.count][n] = 0;
                if (n)                       /* an empty string is "no TXT", not a key */
                    ++r->rd.txt.count;
                p += 1 + pkt[p];
            }
            break;
        }
        case MDNS_TYPE_A:
            if (rdlen != 4) { keep = false; break; }
            memcpy(r->rd.a.addr, pkt + rd, 4);
            break;
        default:
            keep = false;   /* AAAA, NSEC, OPT: not ours */
        }
        if (keep)
            ++out->record_count;
    }
    return true;
}

size_t mdns_build_query(uint8_t *buf, size_t cap, const char *name, uint16_t type)
{
    if (cap < 12)
        return 0;
    memset(buf, 0, 12);
    put16(buf + 4, 1);
    size_t off = 12;
    size_t n = write_name(buf + off, cap - off, name);
    if (!n || off + n + 4 > cap)
        return 0;
    off += n;
    put16(buf + off, type);
    put16(buf + off + 2, 1);   /* IN, multicast reply wanted */
    return off + 4;
}

static size_t write_record(uint8_t *buf, size_t cap, const mdns_record_t *r)
{
    size_t off = write_name(buf, cap, r->name);
    if (!off || off + 10 > cap)
        return 0;
    put16(buf + off, r->type);
    put16(buf + off + 2, (uint16_t) (1 | (r->cache_flush ? 0x8000 : 0)));
    put32(buf + off + 4, r->ttl);
    uint8_t *rdlen = buf + off + 8;
    off += 10;
    size_t start = off;
    switch (r->type) {
    case MDNS_TYPE_PTR: {
        size_t n = write_name(buf + off, cap - off, r->rd.ptr.target);
        if (!n) return 0;
        off += n;
        break;
    }
    case MDNS_TYPE_SRV: {
        if (off + 6 > cap) return 0;
        put16(buf + off, r->rd.srv.priority);
        put16(buf + off + 2, r->rd.srv.weight);
        put16(buf + off + 4, r->rd.srv.port);
        off += 6;
        size_t n = write_name(buf + off, cap - off, r->rd.srv.target);
        if (!n) return 0;
        off += n;
        break;
    }
    case MDNS_TYPE_TXT:
        if (r->rd.txt.count == 0) {
            if (off + 1 > cap) return 0;
            buf[off++] = 0;          /* an empty TXT is one zero-length string */
        }
        for (int i = 0; i < r->rd.txt.count; ++i) {
            size_t n = strlen(r->rd.txt.text[i]);
            if (n > 255) n = 255;
            if (off + 1 + n > cap) return 0;
            buf[off++] = (uint8_t) n;
            memcpy(buf + off, r->rd.txt.text[i], n);
            off += n;
        }
        break;
    case MDNS_TYPE_A:
        if (off + 4 > cap) return 0;
        memcpy(buf + off, r->rd.a.addr, 4);
        off += 4;
        break;
    default:
        return 0;
    }
    put16(rdlen, (uint16_t) (off - start));
    return off;
}

static size_t build_response_id(uint8_t *buf, size_t cap, uint16_t id, const mdns_record_t *records, int count)
{
    if (cap < 12)
        return 0;
    memset(buf, 0, 12);
    put16(buf, id);
    put16(buf + 2, 0x8400);     /* response, authoritative */
    put16(buf + 6, (uint16_t) count);
    size_t off = 12;
    for (int i = 0; i < count; ++i) {
        size_t n = write_record(buf + off, cap - off, &records[i]);
        if (!n)
            return 0;
        off += n;
    }
    return off;
}

size_t mdns_build_response(uint8_t *buf, size_t cap, const mdns_record_t *records, int count)
{
    return build_response_id(buf, cap, 0, records, count);
}

/* ================================================================== state */

typedef struct cache_entry {
    bool     used;
    mdns_result_t r;
    uint64_t expires_ms;
    bool     complete_reported;   /* on_result has seen it at least once */
    bool     dirty;               /* changed since last report */
} cache_entry_t;

struct mdns {
    char hostname[MDNS_NAME_MAX];     /* "box.local" */
    uint8_t addr[4];
    char addr_text[16];
    mdns_sock_t sock;
    bool detached;

    mdns_service_t services[MDNS_SERVICES_MAX];
    int  announce_left[MDNS_SERVICES_MAX];
    uint64_t next_announce_ms[MDNS_SERVICES_MAX];
    bool used[MDNS_SERVICES_MAX];

    char browse_types[MDNS_BROWSE_TYPES][64];   /* "_nmos-register._tcp.local" */
    int  browse_count;
    cache_entry_t cache[MDNS_CACHE_MAX];
};

static bool name_eq(const char *a, const char *b)
{
    /* DNS names compare case-insensitively (RFC 6762 §16, labels excepted
     * in theory, in practice everyone folds). */
    for (;; ++a, ++b) {
        unsigned ca = (unsigned char) *a, cb = (unsigned char) *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
        if (!ca) return true;
    }
}

static void service_full_name(const mdns_service_t *s, char *out, size_t cap)
{
    snprintf(out, cap, "%s.%s.local", s->instance, s->type);
}

static void service_type_name(const mdns_service_t *s, char *out, size_t cap)
{
    snprintf(out, cap, "%s.local", s->type);
}

int mdns_service_records(const mdns_t *m, const mdns_service_t *svc, mdns_record_t *out, int cap)
{
    if (cap < 4)
        return 0;
    char full[MDNS_NAME_MAX], type[MDNS_NAME_MAX];
    service_full_name(svc, full, sizeof full);
    service_type_name(svc, type, sizeof type);
    memset(out, 0, sizeof out[0] * 4);

    copy_str(out[0].name, sizeof out[0].name, type);
    out[0].type = MDNS_TYPE_PTR;
    out[0].ttl = MDNS_TTL_PTR;
    copy_str(out[0].rd.ptr.target, sizeof out[0].rd.ptr.target, full);

    copy_str(out[1].name, sizeof out[1].name, full);
    out[1].type = MDNS_TYPE_SRV;
    out[1].ttl = MDNS_TTL_HOST;
    out[1].cache_flush = true;
    out[1].rd.srv.port = svc->port;
    copy_str(out[1].rd.srv.target, sizeof out[1].rd.srv.target, m->hostname);

    copy_str(out[2].name, sizeof out[2].name, full);
    out[2].type = MDNS_TYPE_TXT;
    out[2].ttl = MDNS_TTL_HOST;
    out[2].cache_flush = true;
    out[2].rd.txt.count = svc->txt_count;
    for (int i = 0; i < svc->txt_count && i < MDNS_TXT_MAX; ++i)
        copy_str(out[2].rd.txt.text[i], MDNS_TXT_LEN, svc->txt[i]);

    copy_str(out[3].name, sizeof out[3].name, m->hostname);
    out[3].type = MDNS_TYPE_A;
    out[3].ttl = MDNS_TTL_HOST;
    out[3].cache_flush = true;
    memcpy(out[3].rd.a.addr, m->addr, 4);
    return 4;
}

static mdns_t *make(const char *hostname, const char *ipv4)
{
    mdns_t *m = (mdns_t *) calloc(1, sizeof *m);
    if (!m)
        return NULL;
    snprintf(m->hostname, sizeof m->hostname, "%s.local", hostname && *hostname ? hostname : "mdns-node");
    m->sock = MDNS_BAD_SOCK;
    if (ipv4 && *ipv4) {
        unsigned a, b, c, d;
        if (sscanf(ipv4, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            m->addr[0] = (uint8_t) a; m->addr[1] = (uint8_t) b; m->addr[2] = (uint8_t) c; m->addr[3] = (uint8_t) d;
        }
        copy_str(m->addr_text, sizeof m->addr_text, ipv4);
    }
    return m;
}

mdns_t *mdns_open_detached(const char *hostname, const char *ipv4)
{
    mdns_t *m = make(hostname, ipv4);
    if (m)
        m->detached = true;
    return m;
}

bool mdns_add_service(mdns_t *m, const mdns_service_t *svc)
{
    int slot = -1;
    for (int i = 0; i < MDNS_SERVICES_MAX; ++i) {
        if (m->used[i] && name_eq(m->services[i].instance, svc->instance) && name_eq(m->services[i].type, svc->type)) {
            slot = i;
            break;
        }
        if (!m->used[i] && slot < 0)
            slot = i;
    }
    if (slot < 0)
        return false;
    m->services[slot] = *svc;
    m->used[slot] = true;
    m->announce_left[slot] = 2;
    m->next_announce_ms[slot] = 0;
    return true;
}

static int send_records(mdns_t *m, const mdns_record_t *records, int count, const struct sockaddr_in *to);

void mdns_remove_service(mdns_t *m, const char *instance, const char *type)
{
    for (int i = 0; i < MDNS_SERVICES_MAX; ++i) {
        if (!m->used[i] || !name_eq(m->services[i].instance, instance) || !name_eq(m->services[i].type, type))
            continue;
        mdns_record_t recs[4];
        int n = mdns_service_records(m, &m->services[i], recs, 4);
        for (int k = 0; k < n; ++k)
            recs[k].ttl = 0;         /* goodbye: the same records, zero TTL */
        send_records(m, recs, n, NULL);
        m->used[i] = false;
    }
}

bool mdns_browse(mdns_t *m, const char *type)
{
    char name[64];
    snprintf(name, sizeof name, "%s.local", type);
    int found = -1;
    for (int i = 0; i < m->browse_count; ++i)
        if (name_eq(m->browse_types[i], name))
            found = i;
    if (found < 0) {
        if (m->browse_count >= MDNS_BROWSE_TYPES)
            return false;
        copy_str(m->browse_types[m->browse_count++], 64, name);
    }
    if (m->detached)
        return true;
    uint8_t buf[512];
    size_t n = mdns_build_query(buf, sizeof buf, name, MDNS_TYPE_PTR);
    if (!n)
        return false;
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(MDNS_PORT);
    to.sin_addr.s_addr = inet_addr(MDNS_GROUP);
    return sendto(m->sock, (const char *) buf, (int) n, 0, (struct sockaddr *) &to, sizeof to) == (int) n;
}

/* --------------------------------------------------------- answering */

static int add_record(mdns_record_t *out, int count, int cap, const mdns_record_t *r)
{
    for (int i = 0; i < count; ++i)
        if (out[i].type == r->type && name_eq(out[i].name, r->name)
            && (r->type != MDNS_TYPE_PTR || name_eq(out[i].rd.ptr.target, r->rd.ptr.target)))
            return count;        /* once is enough; two services share one PTR name, not one PTR */
    if (count < cap)
        out[count++] = *r;
    return count;
}

/* The records that answer one question. */
static int answer_question(const mdns_t *m, const mdns_question_t *q, mdns_record_t *out, int count, int cap)
{
    const bool any = q->type == MDNS_TYPE_ANY;

    if ((q->type == MDNS_TYPE_PTR || any) && name_eq(q->name, "_services._dns-sd._udp.local")) {
        for (int i = 0; i < MDNS_SERVICES_MAX; ++i) {
            if (!m->used[i]) continue;
            mdns_record_t r;
            memset(&r, 0, sizeof r);
            copy_str(r.name, sizeof r.name, q->name);
            r.type = MDNS_TYPE_PTR;
            r.ttl = MDNS_TTL_PTR;
            service_type_name(&m->services[i], r.rd.ptr.target, sizeof r.rd.ptr.target);
            count = add_record(out, count, cap, &r);
        }
        return count;
    }

    if ((q->type == MDNS_TYPE_A || any) && name_eq(q->name, m->hostname)) {
        mdns_record_t r;
        memset(&r, 0, sizeof r);
        copy_str(r.name, sizeof r.name, m->hostname);
        r.type = MDNS_TYPE_A;
        r.ttl = MDNS_TTL_HOST;
        r.cache_flush = true;
        memcpy(r.rd.a.addr, m->addr, 4);
        count = add_record(out, count, cap, &r);
    }

    for (int i = 0; i < MDNS_SERVICES_MAX; ++i) {
        if (!m->used[i]) continue;
        mdns_record_t recs[4];
        mdns_service_records(m, &m->services[i], recs, 4);
        char full[MDNS_NAME_MAX], type[MDNS_NAME_MAX];
        service_full_name(&m->services[i], full, sizeof full);
        service_type_name(&m->services[i], type, sizeof type);

        if ((q->type == MDNS_TYPE_PTR || any) && name_eq(q->name, type)) {
            /* The browse: PTR answer, and SRV/TXT/A so nobody has to ask again. */
            for (int k = 0; k < 4; ++k)
                count = add_record(out, count, cap, &recs[k]);
        } else if (name_eq(q->name, full)) {
            if (q->type == MDNS_TYPE_SRV || any) {
                count = add_record(out, count, cap, &recs[1]);
                count = add_record(out, count, cap, &recs[3]);
            }
            if (q->type == MDNS_TYPE_TXT || any)
                count = add_record(out, count, cap, &recs[2]);
        }
    }
    return count;
}

/* --------------------------------------------------------- browsing */

static bool browsing(const mdns_t *m, const char *type_name)
{
    for (int i = 0; i < m->browse_count; ++i)
        if (name_eq(m->browse_types[i], type_name))
            return true;
    return false;
}

static cache_entry_t *cache_find(mdns_t *m, const char *full_name)
{
    char full[MDNS_NAME_MAX];
    for (int i = 0; i < MDNS_CACHE_MAX; ++i) {
        if (!m->cache[i].used) continue;
        snprintf(full, sizeof full, "%s.%s.local", m->cache[i].r.instance, m->cache[i].r.type);
        if (name_eq(full, full_name))
            return &m->cache[i];
    }
    return NULL;
}

static cache_entry_t *cache_get(mdns_t *m, const char *instance, const char *type)
{
    char full[MDNS_NAME_MAX];
    snprintf(full, sizeof full, "%s.%s.local", instance, type);
    cache_entry_t *e = cache_find(m, full);
    if (e)
        return e;
    for (int i = 0; i < MDNS_CACHE_MAX; ++i) {
        if (m->cache[i].used) continue;
        e = &m->cache[i];
        memset(e, 0, sizeof *e);
        e->used = true;
        copy_str(e->r.instance, sizeof e->r.instance, instance);
        copy_str(e->r.type, sizeof e->r.type, type);
        return e;
    }
    return NULL;   /* full: a segment with more than 64 services of interest */
}

static void report(cache_entry_t *e, mdns_result_fn fn, void *user)
{
    if (fn)
        fn(&e->r, user);
    e->complete_reported = true;
    e->dirty = false;
}

/* What a response teaches us. Returns bytes of follow-up query written. */
static size_t learn(mdns_t *m, const mdns_message_t *msg, uint64_t now, uint8_t *reply, size_t reply_cap,
                    mdns_result_fn fn, void *user)
{
    /* PTRs first: they create entries the other records fill in. */
    for (int i = 0; i < msg->record_count; ++i) {
        const mdns_record_t *r = &msg->records[i];
        if (r->type != MDNS_TYPE_PTR || !browsing(m, r->name))
            continue;
        /* target = "Instance.<type>.local"; the type is the PTR's own name */
        const size_t tlen = strlen(r->name);
        const size_t flen = strlen(r->rd.ptr.target);
        if (flen <= tlen + 1 || !name_eq(r->rd.ptr.target + (flen - tlen), r->name))
            continue;
        char instance[64], type[64];
        size_t ilen = flen - tlen - 1;
        if (ilen >= sizeof instance) ilen = sizeof instance - 1;
        memcpy(instance, r->rd.ptr.target, ilen);
        instance[ilen] = 0;
        copy_str(type, sizeof type, r->name);
        type[tlen - 6] = 0;                     /* strip ".local" */
        cache_entry_t *e = cache_get(m, instance, type);
        if (!e)
            continue;
        if (r->ttl == 0) {
            e->r.ttl = 0;
            if (e->complete_reported)
                report(e, fn, user);
            e->used = false;
            continue;
        }
        e->r.ttl = r->ttl;
        e->expires_ms = now + (uint64_t) r->ttl * 1000u;
    }

    for (int i = 0; i < msg->record_count; ++i) {
        const mdns_record_t *r = &msg->records[i];
        if (r->type == MDNS_TYPE_SRV) {
            cache_entry_t *e = cache_find(m, r->name);
            if (!e) continue;
            if (e->r.port != r->rd.srv.port || !name_eq(e->r.host, r->rd.srv.target)) {
                e->r.port = r->rd.srv.port;
                copy_str(e->r.host, sizeof e->r.host, r->rd.srv.target);
                e->r.ipv4[0] = 0;   /* a new host means the address is unknown again */
                e->dirty = true;
            }
            if (r->ttl && (uint64_t) r->ttl * 1000u + now < e->expires_ms)
                e->expires_ms = now + (uint64_t) r->ttl * 1000u;
        } else if (r->type == MDNS_TYPE_TXT) {
            cache_entry_t *e = cache_find(m, r->name);
            if (!e) continue;
            bool same = e->r.txt_count == r->rd.txt.count;
            for (int k = 0; same && k < r->rd.txt.count; ++k)
                same = strcmp(e->r.txt[k], r->rd.txt.text[k]) == 0;
            if (!same) {
                e->r.txt_count = r->rd.txt.count;
                for (int k = 0; k < r->rd.txt.count; ++k)
                    copy_str(e->r.txt[k], MDNS_TXT_LEN, r->rd.txt.text[k]);
                e->dirty = true;
            }
        }
    }

    for (int i = 0; i < msg->record_count; ++i) {
        const mdns_record_t *r = &msg->records[i];
        if (r->type != MDNS_TYPE_A)
            continue;
        char text[16];
        snprintf(text, sizeof text, "%u.%u.%u.%u", r->rd.a.addr[0], r->rd.a.addr[1], r->rd.a.addr[2], r->rd.a.addr[3]);
        for (int k = 0; k < MDNS_CACHE_MAX; ++k) {
            cache_entry_t *e = &m->cache[k];
            if (!e->used || !name_eq(e->r.host, r->name))
                continue;
            if (strcmp(e->r.ipv4, text) != 0) {
                copy_str(e->r.ipv4, sizeof e->r.ipv4, text);
                e->dirty = true;
            }
        }
    }

    /* Report what became complete or changed; ask for what is missing. */
    size_t reply_len = 0;
    for (int k = 0; k < MDNS_CACHE_MAX; ++k) {
        cache_entry_t *e = &m->cache[k];
        if (!e->used)
            continue;
        const bool complete = e->r.host[0] && e->r.ipv4[0];
        if (complete && (e->dirty || !e->complete_reported))
            report(e, fn, user);
        else if (!complete && reply_len == 0 && reply) {
            char full[MDNS_NAME_MAX];
            snprintf(full, sizeof full, "%s.%s.local", e->r.instance, e->r.type);
            reply_len = e->r.host[0] ? mdns_build_query(reply, reply_cap, e->r.host, MDNS_TYPE_A)
                                     : mdns_build_query(reply, reply_cap, full, MDNS_TYPE_SRV);
        }
    }
    return reply_len;
}

void mdns_expire(mdns_t *m, uint64_t now, mdns_result_fn fn, void *user)
{
    for (int k = 0; k < MDNS_CACHE_MAX; ++k) {
        cache_entry_t *e = &m->cache[k];
        if (!e->used || now < e->expires_ms)
            continue;
        e->r.ttl = 0;
        if (e->complete_reported)
            report(e, fn, user);
        e->used = false;
    }
}

size_t mdns_handle_packet(mdns_t *m, const uint8_t *packet, size_t len, uint8_t *reply, size_t reply_cap,
                          mdns_result_fn fn, void *user)
{
    mdns_message_t msg;
    if (!mdns_parse_message(packet, len, &msg))
        return 0;
    if (msg.is_response)
        return learn(m, &msg, now_ms(), reply, reply_cap, fn, user);

    mdns_record_t answers[32];
    int count = 0;
    for (int i = 0; i < msg.question_count; ++i)
        count = answer_question(m, &msg.questions[i], answers, count, 32);
    if (count == 0)
        return 0;
    return build_response_id(reply, reply_cap, 0, answers, count);
}

/* ================================================================= socket */

static int send_records(mdns_t *m, const mdns_record_t *records, int count, const struct sockaddr_in *to)
{
    if (m->detached || m->sock == MDNS_BAD_SOCK)
        return 0;
    uint8_t buf[MDNS_PACKET_MAX];
    size_t n = mdns_build_response(buf, sizeof buf, records, count);
    if (!n)
        return -1;
    struct sockaddr_in group;
    if (!to) {
        memset(&group, 0, sizeof group);
        group.sin_family = AF_INET;
        group.sin_port = htons(MDNS_PORT);
        group.sin_addr.s_addr = inet_addr(MDNS_GROUP);
        to = &group;
    }
    return sendto(m->sock, (const char *) buf, (int) n, 0, (const struct sockaddr *) to, sizeof *to) == (int) n ? 0 : -1;
}

mdns_t *mdns_open(const char *hostname, const char *ipv4, char *err, size_t err_len)
{
#if defined(_WIN32)
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    mdns_t *m = make(hostname, ipv4);
    if (!m) {
        if (err) copy_str(err, err_len, "out of memory");
        return NULL;
    }
    m->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (m->sock == MDNS_BAD_SOCK) {
        if (err) copy_str(err, err_len, "socket() failed");
        free(m);
        return NULL;
    }
    int one = 1;
    setsockopt(m->sock, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof one);
#if defined(SO_REUSEPORT)
    setsockopt(m->sock, SOL_SOCKET, SO_REUSEPORT, (const char *) &one, sizeof one);
#endif
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof bind_addr);
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(MDNS_PORT);
    bind_addr.sin_addr.s_addr = INADDR_ANY;    /* the group needs the wildcard, on every OS */
    if (bind(m->sock, (struct sockaddr *) &bind_addr, sizeof bind_addr) != 0) {
        if (err) copy_str(err, err_len, "bind 5353 failed: another responder owns the port without address reuse");
        mdns_closesock(m->sock);
        free(m);
        return NULL;
    }
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_GROUP);
    mreq.imr_interface.s_addr = m->addr_text[0] ? inet_addr(m->addr_text) : INADDR_ANY;
    if (setsockopt(m->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *) &mreq, sizeof mreq) != 0) {
        if (err) copy_str(err, err_len, "joining 224.0.0.251 failed: no multicast on this interface");
        mdns_closesock(m->sock);
        free(m);
        return NULL;
    }
    if (m->addr_text[0]) {
        struct in_addr ifa;
        ifa.s_addr = inet_addr(m->addr_text);
        setsockopt(m->sock, IPPROTO_IP, IP_MULTICAST_IF, (const char *) &ifa, sizeof ifa);
    }
    int ttl = 255;                 /* RFC 6762: link-local, TTL 255 */
    setsockopt(m->sock, IPPROTO_IP, IP_MULTICAST_TTL, (const char *) &ttl, sizeof ttl);
    int loop = 1;                  /* a controller on this same box must hear us */
    setsockopt(m->sock, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *) &loop, sizeof loop);
    if (err && err_len) err[0] = 0;
    return m;
}

void mdns_close(mdns_t *m)
{
    if (!m)
        return;
    for (int i = 0; i < MDNS_SERVICES_MAX; ++i)
        if (m->used[i])
            mdns_remove_service(m, m->services[i].instance, m->services[i].type);
    if (m->sock != MDNS_BAD_SOCK)
        mdns_closesock(m->sock);
    free(m);
}

static void announce_due(mdns_t *m, uint64_t now)
{
    for (int i = 0; i < MDNS_SERVICES_MAX; ++i) {
        if (!m->used[i] || m->announce_left[i] <= 0 || now < m->next_announce_ms[i])
            continue;
        mdns_record_t recs[4];
        int n = mdns_service_records(m, &m->services[i], recs, 4);
        send_records(m, recs, n, NULL);
        --m->announce_left[i];
        m->next_announce_ms[i] = now + 1000;
    }
}

int mdns_poll(mdns_t *m, int timeout_ms, mdns_result_fn fn, void *user)
{
    if (m->detached || m->sock == MDNS_BAD_SOCK)
        return -1;
    const uint64_t now = now_ms();
    announce_due(m, now);
    mdns_expire(m, now, fn, user);

    int handled = 0;
    int wait = timeout_ms;
    for (;;) {
#if defined(_WIN32)
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m->sock, &fds);
        struct timeval tv = { wait / 1000, (wait % 1000) * 1000 };
        int r = select(0, &fds, NULL, NULL, &tv);
#else
        struct pollfd pfd = { m->sock, POLLIN, 0 };
        int r = poll(&pfd, 1, wait);
#endif
        if (r < 0)
            return -1;
        if (r == 0)
            return handled;

        uint8_t pkt[MDNS_PACKET_MAX];
        struct sockaddr_in from;
        socklen_t from_len = sizeof from;
        int n = recvfrom(m->sock, (char *) pkt, sizeof pkt, 0, (struct sockaddr *) &from, &from_len);
        if (n <= 0)
            return handled;
        ++handled;
        wait = 0;   /* drain what is queued, then return */

        mdns_message_t msg;
        if (!mdns_parse_message(pkt, (size_t) n, &msg))
            continue;

        uint8_t reply[MDNS_PACKET_MAX];
        if (msg.is_response) {
            size_t q = learn(m, &msg, now_ms(), reply, sizeof reply, fn, user);
            if (q) {
                struct sockaddr_in to;
                memset(&to, 0, sizeof to);
                to.sin_family = AF_INET;
                to.sin_port = htons(MDNS_PORT);
                to.sin_addr.s_addr = inet_addr(MDNS_GROUP);
                sendto(m->sock, (const char *) reply, (int) q, 0, (struct sockaddr *) &to, sizeof to);
            }
            continue;
        }

        mdns_record_t answers[32];
        int count = 0;
        bool unicast = ntohs(from.sin_port) != MDNS_PORT;   /* a legacy one-shot resolver */
        for (int i = 0; i < msg.question_count; ++i) {
            if (msg.questions[i].unicast_reply)
                unicast = true;
            count = answer_question(m, &msg.questions[i], answers, count, 32);
        }
        if (count == 0)
            continue;
        /* A legacy unicast query wants the ID echoed and a short TTL. */
        if (ntohs(from.sin_port) != MDNS_PORT)
            for (int i = 0; i < count; ++i)
                if (answers[i].ttl > 10) answers[i].ttl = 10;
        size_t len = build_response_id(reply, sizeof reply, ntohs(from.sin_port) != MDNS_PORT ? msg.id : 0, answers, count);
        if (!len)
            continue;
        struct sockaddr_in to;
        if (unicast) {
            to = from;
        } else {
            memset(&to, 0, sizeof to);
            to.sin_family = AF_INET;
            to.sin_port = htons(MDNS_PORT);
            to.sin_addr.s_addr = inet_addr(MDNS_GROUP);
        }
        sendto(m->sock, (const char *) reply, (int) len, 0, (struct sockaddr *) &to, sizeof to);
    }
}
