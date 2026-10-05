/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libmdns -- DNS-SD over multicast DNS (RFC 6762 / 6763), the small part a
 * device needs: announce its own services and find others'.
 *
 * Why a library of our own rather than Avahi or Bonjour: an AES67 device
 * is often an appliance whose image should not need a system daemon and a D-Bus
 * for its outputs to be found, and the developer's desk is Windows, whose
 * own responder answers no queries for us. The NMOS contract (IS-04) is
 * DNS-SD: a node advertises `_nmos-node._tcp` and finds a registry through
 * `_nmos-register._tcp`; an NMOS controller browses exactly that.
 * That is the whole of what this does, and it does it with one socket.
 *
 * One object is both responder and browser because they are the same
 * socket: bound to 5353, joined to 224.0.0.251, reading everything the
 * segment says. Single-threaded by design -- the owner calls mdns_poll()
 * from whichever thread it likes and everything happens inside that call.
 *
 * Deliberately not implemented, and not hidden: name-conflict probing (a
 * second device with the same instance name is the operator's mistake to
 * see, not ours to rename around), IPv6, and unicast DNS-SD. The packet
 * arithmetic (mdns_build_*, mdns_parse_message) has no socket in it and
 * is what the tests pin.
 */
#ifndef MANIFOLD_MDNS_H
#define MANIFOLD_MDNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MDNS_NAME_MAX      256   /* a DNS name in presentation form, dots included */
#define MDNS_TXT_MAX       16    /* key=value strings per service */
#define MDNS_TXT_LEN       200   /* one TXT string; DNS allows 255 */
#define MDNS_SERVICES_MAX  16    /* services one responder advertises */
#define MDNS_CACHE_MAX     64    /* browse results remembered at once */
#define MDNS_PACKET_MAX    9000  /* RFC 6762 says packets may be that large */

/* Record types this library understands. Everything else is skipped. */
enum {
    MDNS_TYPE_A    = 1,
    MDNS_TYPE_PTR  = 12,
    MDNS_TYPE_TXT  = 16,
    MDNS_TYPE_AAAA = 28,
    MDNS_TYPE_SRV  = 33,
    MDNS_TYPE_ANY  = 255
};

/* ------------------------------------------------------------------ wire */

typedef struct mdns_question {
    char     name[MDNS_NAME_MAX];
    uint16_t type;
    bool     unicast_reply;      /* the QU bit: answer this one by unicast */
} mdns_question_t;

typedef struct mdns_record {
    char     name[MDNS_NAME_MAX];
    uint16_t type;
    uint32_t ttl;                /* 0 is a goodbye */
    bool     cache_flush;
    union {
        struct { char target[MDNS_NAME_MAX]; } ptr;
        struct { char target[MDNS_NAME_MAX]; uint16_t port, priority, weight; } srv;
        struct { char text[MDNS_TXT_MAX][MDNS_TXT_LEN]; int count; } txt;
        struct { uint8_t addr[4]; } a;
    } rd;
} mdns_record_t;

#define MDNS_MSG_QUESTIONS 16
#define MDNS_MSG_RECORDS   48

typedef struct mdns_message {
    uint16_t id;
    bool     is_response;
    int      question_count;
    int      record_count;       /* answers + authority + additional, in wire order */
    mdns_question_t questions[MDNS_MSG_QUESTIONS];
    mdns_record_t   records[MDNS_MSG_RECORDS];
} mdns_message_t;

/* Parses one packet. Names are decompressed into presentation form
 * ("Instance._nmos-node._tcp.local"); labels keep their bytes, so a space
 * in an instance name stays a space. Returns false on a malformed packet.
 * Records beyond MDNS_MSG_RECORDS are counted but dropped. */
bool mdns_parse_message(const uint8_t *packet, size_t len, mdns_message_t *out);

/* A query for one name and type (a PTR query for "_nmos-node._tcp.local"
 * is a browse). Returns bytes written, 0 if it does not fit. */
size_t mdns_build_query(uint8_t *buf, size_t cap, const char *name, uint16_t type);

/* A response carrying the records given, no compression. 0 if too big. */
size_t mdns_build_response(uint8_t *buf, size_t cap, const mdns_record_t *records, int count);

/* -------------------------------------------------------------- services */

typedef struct mdns_service {
    char     instance[64];               /* "Manifold Console" -- shown to people */
    char     type[64];                   /* "_nmos-node._tcp" */
    uint16_t port;
    int      txt_count;
    char     txt[MDNS_TXT_MAX][MDNS_TXT_LEN];   /* "api_ver=v1.3" */
} mdns_service_t;

/* A browse result, complete once its SRV and A records are known. */
typedef struct mdns_result {
    char     instance[64];
    char     type[64];
    char     host[MDNS_NAME_MAX];        /* "box.local" */
    char     ipv4[16];                   /* "" until an A record arrives */
    uint16_t port;
    int      txt_count;
    char     txt[MDNS_TXT_MAX][MDNS_TXT_LEN];
    uint32_t ttl;                        /* 0 means it said goodbye */
} mdns_result_t;

typedef struct mdns mdns_t;

/* Opens the socket. `hostname` is the bare name this machine answers for
 * ("manifold-1"; ".local" is appended); `ipv4` is the address the A record
 * carries and the interface multicast goes out of. Null with `err` set. */
mdns_t *mdns_open(const char *hostname, const char *ipv4, char *err, size_t err_len);
void    mdns_close(mdns_t *m);          /* says goodbye for every service */

/* Advertised from the next poll: announced twice a second apart, then
 * answered on request. Replaces a service with the same instance+type. */
bool mdns_add_service(mdns_t *m, const mdns_service_t *svc);
void mdns_remove_service(mdns_t *m, const char *instance, const char *type);   /* with a goodbye */

/* Sends a PTR query for a service type ("_nmos-register._tcp"). Results
 * arrive through mdns_poll's callback as responses come in. Browsing is a
 * question repeated by the caller at its own cadence, not a subscription. */
bool mdns_browse(mdns_t *m, const char *type);

/* Handles what the socket has for up to `timeout_ms`: answers queries for
 * our services, sends due announcements, and reports browse results.
 * `on_result` sees a result when it becomes complete, when its TXT or
 * address changes, and once more with ttl 0 when it says goodbye or its
 * TTL runs out. Returns the number of packets handled, -1 on a socket
 * error. */
typedef void (*mdns_result_fn)(const mdns_result_t *result, void *user);
int  mdns_poll(mdns_t *m, int timeout_ms, mdns_result_fn on_result, void *user);

/* Socket-free entry points, for tests and for anyone with their own
 * transport: feed a packet in, get what would have been sent back. */
mdns_t *mdns_open_detached(const char *hostname, const char *ipv4);
/* Returns bytes of reply written to `reply` (0 for none). */
size_t  mdns_handle_packet(mdns_t *m, const uint8_t *packet, size_t len, uint8_t *reply, size_t reply_cap,
                           mdns_result_fn on_result, void *user);
/* The full record set for one service, as an announcement would carry. */
int     mdns_service_records(const mdns_t *m, const mdns_service_t *svc, mdns_record_t *out, int cap);

/* Expires cached browse results that have outlived their TTL, reporting
 * each once with ttl 0. `now_ms` is any monotonic millisecond clock. */
void mdns_expire(mdns_t *m, uint64_t now_ms, mdns_result_fn on_result, void *user);

#ifdef __cplusplus
}
#endif
#endif
