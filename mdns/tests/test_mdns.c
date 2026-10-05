/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Meros Inc. */

/* libmdns tests: the wire arithmetic (names, compression, each record
   type, round trips), the responder's answers to the questions a DNS-SD
   browser asks, the browser's assembly of a result from PTR/SRV/TXT/A
   across packets, goodbyes and expiry -- all socket-free -- and, where the
   machine allows multicast on a loopback, one real round trip. */

#include <stdio.h>
#include <string.h>

#include "mdns/mdns.h"


static int checks = 0, failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        ++checks;                                                          \
        if (!(cond)) {                                                     \
            ++failures;                                                    \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
        }                                                                  \
    } while (0)

static mdns_service_t nmos_node(void)
{
    mdns_service_t s;
    memset(&s, 0, sizeof s);
    strcpy(s.instance, "Manifold Console");
    strcpy(s.type, "_nmos-node._tcp");
    s.port = 8080;
    s.txt_count = 2;
    strcpy(s.txt[0], "api_ver=v1.2,v1.3");
    strcpy(s.txt[1], "api_proto=http");
    return s;
}

/* ----------------------------------------------------------------- wire */

static void test_query_round_trips(void)
{
    uint8_t buf[256];
    size_t n = mdns_build_query(buf, sizeof buf, "_nmos-node._tcp.local", MDNS_TYPE_PTR);
    CHECK(n == 12 + 1 + 10 + 1 + 4 + 1 + 5 + 1 + 4);
    /* header: id 0, flags 0, one question */
    CHECK(buf[2] == 0 && buf[3] == 0 && buf[5] == 1);
    CHECK(buf[12] == 10 && memcmp(buf + 13, "_nmos-node", 10) == 0);

    mdns_message_t msg;
    CHECK(mdns_parse_message(buf, n, &msg));
    CHECK(!msg.is_response);
    CHECK(msg.question_count == 1);
    CHECK(strcmp(msg.questions[0].name, "_nmos-node._tcp.local") == 0);
    CHECK(msg.questions[0].type == MDNS_TYPE_PTR);
    CHECK(!msg.questions[0].unicast_reply);

    /* the QU bit is read */
    buf[n - 2] |= 0x80;
    CHECK(mdns_parse_message(buf, n, &msg) && msg.questions[0].unicast_reply);

    /* too small a buffer is refused, not truncated */
    CHECK(mdns_build_query(buf, 20, "_nmos-node._tcp.local", MDNS_TYPE_PTR) == 0);
}

static void test_records_round_trip(void)
{
    mdns_t *m = mdns_open_detached("box", "192.168.1.20");
    mdns_service_t svc = nmos_node();
    mdns_record_t recs[4];
    CHECK(mdns_service_records(m, &svc, recs, 4) == 4);

    uint8_t buf[1024];
    size_t n = mdns_build_response(buf, sizeof buf, recs, 4);
    CHECK(n > 0);
    CHECK(buf[2] == 0x84);          /* response, authoritative */
    CHECK(buf[7] == 4);             /* four answers */

    mdns_message_t msg;
    CHECK(mdns_parse_message(buf, n, &msg));
    CHECK(msg.is_response);
    CHECK(msg.record_count == 4);

    const mdns_record_t *ptr = &msg.records[0];
    CHECK(ptr->type == MDNS_TYPE_PTR);
    CHECK(strcmp(ptr->name, "_nmos-node._tcp.local") == 0);
    CHECK(strcmp(ptr->rd.ptr.target, "Manifold Console._nmos-node._tcp.local") == 0);
    CHECK(ptr->ttl == 4500 && !ptr->cache_flush);

    const mdns_record_t *srv = &msg.records[1];
    CHECK(srv->type == MDNS_TYPE_SRV);
    CHECK(strcmp(srv->name, "Manifold Console._nmos-node._tcp.local") == 0);
    CHECK(srv->rd.srv.port == 8080);
    CHECK(strcmp(srv->rd.srv.target, "box.local") == 0);
    CHECK(srv->ttl == 120 && srv->cache_flush);

    const mdns_record_t *txt = &msg.records[2];
    CHECK(txt->type == MDNS_TYPE_TXT);
    CHECK(txt->rd.txt.count == 2);
    CHECK(strcmp(txt->rd.txt.text[0], "api_ver=v1.2,v1.3") == 0);
    CHECK(strcmp(txt->rd.txt.text[1], "api_proto=http") == 0);

    const mdns_record_t *a = &msg.records[3];
    CHECK(a->type == MDNS_TYPE_A);
    CHECK(strcmp(a->name, "box.local") == 0);
    CHECK(a->rd.a.addr[0] == 192 && a->rd.a.addr[3] == 20);
    mdns_close(m);
}

/* A packet the way a real responder compresses it: the SRV and TXT names
   are pointers into the PTR's rdata, the A name a pointer into the SRV. */
static void test_compression_pointers_are_followed(void)
{
    uint8_t p[512];
    size_t o = 0;
    memset(p, 0, 12);
    p[2] = 0x84; p[7] = 3;
    o = 12;
    /* answer 1: PTR _x._tcp.local -> Inst._x._tcp.local */
    const size_t ptr_name = o;
    p[o++] = 2; memcpy(p + o, "_x", 2); o += 2;
    p[o++] = 4; memcpy(p + o, "_tcp", 4); o += 4;
    p[o++] = 5; memcpy(p + o, "local", 5); o += 5;
    p[o++] = 0;
    p[o++] = 0; p[o++] = 12; p[o++] = 0; p[o++] = 1;             /* PTR IN */
    p[o++] = 0; p[o++] = 0; p[o++] = 0x11; p[o++] = 0x94;        /* ttl 4500 */
    p[o++] = 0; p[o++] = 7;                                      /* rdlen: "Inst" + pointer */
    const size_t inst_name = o;
    p[o++] = 4; memcpy(p + o, "Inst", 4); o += 4;
    p[o++] = 0xC0; p[o++] = (uint8_t) ptr_name;                  /* -> _x._tcp.local */
    /* answer 2: SRV Inst._x._tcp.local (pointer) -> host.local:9 */
    p[o++] = 0xC0; p[o++] = (uint8_t) inst_name;
    p[o++] = 0; p[o++] = 33; p[o++] = 0x80; p[o++] = 1;          /* SRV, cache flush */
    p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 120;
    p[o++] = 0; p[o++] = 6 + 1 + 4 + 2;                          /* rdlen */
    p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 9;
    const size_t host_name = o;
    p[o++] = 4; memcpy(p + o, "host", 4); o += 4;
    p[o++] = 0xC0; p[o++] = (uint8_t) (ptr_name + 3 + 5);        /* -> local */
    /* answer 3: A host.local (pointer) */
    p[o++] = 0xC0; p[o++] = (uint8_t) host_name;
    p[o++] = 0; p[o++] = 1; p[o++] = 0x80; p[o++] = 1;
    p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 120;
    p[o++] = 0; p[o++] = 4;
    p[o++] = 10; p[o++] = 0; p[o++] = 0; p[o++] = 7;

    mdns_message_t msg;
    CHECK(mdns_parse_message(p, o, &msg));
    CHECK(msg.record_count == 3);
    CHECK(strcmp(msg.records[0].rd.ptr.target, "Inst._x._tcp.local") == 0);
    CHECK(strcmp(msg.records[1].name, "Inst._x._tcp.local") == 0);
    CHECK(strcmp(msg.records[1].rd.srv.target, "host.local") == 0);
    CHECK(msg.records[1].rd.srv.port == 9);
    CHECK(strcmp(msg.records[2].name, "host.local") == 0);
    CHECK(msg.records[2].rd.a.addr[0] == 10 && msg.records[2].rd.a.addr[3] == 7);

    /* a pointer loop is refused, not followed forever */
    p[inst_name + 5] = 0xC0; p[inst_name + 6] = (uint8_t) inst_name;
    CHECK(!mdns_parse_message(p, o, &msg));
    /* and so is a truncated packet */
    p[inst_name + 5] = 0xC0; p[inst_name + 6] = (uint8_t) ptr_name;
    CHECK(!mdns_parse_message(p, o - 3, &msg));
    CHECK(!mdns_parse_message(p, 5, &msg));
}

/* ------------------------------------------------------------ responder */

static size_t ask(mdns_t *m, const char *name, uint16_t type, mdns_message_t *reply_out)
{
    uint8_t q[256], reply[2048];
    size_t qn = mdns_build_query(q, sizeof q, name, type);
    size_t rn = mdns_handle_packet(m, q, qn, reply, sizeof reply, NULL, NULL);
    if (rn)
        mdns_parse_message(reply, rn, reply_out);
    else
        memset(reply_out, 0, sizeof *reply_out);
    return rn;
}

static int count_type(const mdns_message_t *msg, uint16_t type)
{
    int n = 0;
    for (int i = 0; i < msg->record_count; ++i)
        if (msg->records[i].type == type) ++n;
    return n;
}

static void test_responder_answers_a_browse(void)
{
    mdns_t *m = mdns_open_detached("console", "10.1.1.5");
    mdns_service_t svc = nmos_node();
    CHECK(mdns_add_service(m, &svc));

    /* The browse (what Sluice sends): PTR, and everything needed to use
       the result rides along so no second round trip is needed. */
    mdns_message_t r;
    CHECK(ask(m, "_nmos-node._tcp.local", MDNS_TYPE_PTR, &r) > 0);
    CHECK(r.is_response);
    CHECK(count_type(&r, MDNS_TYPE_PTR) == 1);
    CHECK(count_type(&r, MDNS_TYPE_SRV) == 1);
    CHECK(count_type(&r, MDNS_TYPE_TXT) == 1);
    CHECK(count_type(&r, MDNS_TYPE_A) == 1);

    /* Other people's services are not our business. */
    CHECK(ask(m, "_http._tcp.local", MDNS_TYPE_PTR, &r) == 0);
    CHECK(ask(m, "nobody.local", MDNS_TYPE_A, &r) == 0);

    /* Direct questions about the instance and the host. */
    CHECK(ask(m, "Manifold Console._nmos-node._tcp.local", MDNS_TYPE_SRV, &r) > 0);
    CHECK(count_type(&r, MDNS_TYPE_SRV) == 1 && count_type(&r, MDNS_TYPE_A) == 1 && count_type(&r, MDNS_TYPE_TXT) == 0);
    CHECK(ask(m, "manifold console._NMOS-NODE._tcp.local", MDNS_TYPE_TXT, &r) > 0);   /* case-folded */
    CHECK(count_type(&r, MDNS_TYPE_TXT) == 1);
    CHECK(ask(m, "console.local", MDNS_TYPE_A, &r) > 0);
    CHECK(r.record_count == 1 && r.records[0].rd.a.addr[0] == 10);

    /* The service enumeration meta-query lists our types. */
    CHECK(ask(m, "_services._dns-sd._udp.local", MDNS_TYPE_PTR, &r) > 0);
    CHECK(r.record_count == 1 && strcmp(r.records[0].rd.ptr.target, "_nmos-node._tcp.local") == 0);

    /* Two services, one query: both answered, records not repeated. */
    mdns_service_t second = nmos_node();
    strcpy(second.instance, "Manifold Stagebox");
    second.port = 8081;
    CHECK(mdns_add_service(m, &second));
    CHECK(ask(m, "_nmos-node._tcp.local", MDNS_TYPE_ANY, &r) > 0);
    CHECK(count_type(&r, MDNS_TYPE_PTR) == 2);
    CHECK(count_type(&r, MDNS_TYPE_SRV) == 2);
    CHECK(count_type(&r, MDNS_TYPE_A) == 1);

    /* Re-adding an instance replaces it. */
    second.port = 9000;
    CHECK(mdns_add_service(m, &second));
    CHECK(ask(m, "Manifold Stagebox._nmos-node._tcp.local", MDNS_TYPE_SRV, &r) > 0);
    CHECK(r.records[0].rd.srv.port == 9000);

    /* A response packet is never answered (no storms). */
    uint8_t buf[1024], reply[64];
    mdns_record_t recs[4];
    mdns_service_records(m, &svc, recs, 4);
    size_t n = mdns_build_response(buf, sizeof buf, recs, 4);
    CHECK(mdns_handle_packet(m, buf, n, reply, sizeof reply, NULL, NULL) == 0);
    mdns_close(m);
}

/* -------------------------------------------------------------- browser */

typedef struct { mdns_result_t last; int calls; int goodbyes; } seen_t;

static void on_result(const mdns_result_t *r, void *user)
{
    seen_t *s = (seen_t *) user;
    s->last = *r;
    ++s->calls;
    if (r->ttl == 0) ++s->goodbyes;
}

static void test_browser_assembles_a_result(void)
{
    /* The registry, as Sluice advertises it; the node, browsing for it. */
    mdns_t *registry = mdns_open_detached("sluice-box", "10.1.1.9");
    mdns_service_t reg;
    memset(&reg, 0, sizeof reg);
    strcpy(reg.instance, "sluice");
    strcpy(reg.type, "_nmos-register._tcp");
    reg.port = 3210;
    reg.txt_count = 3;
    strcpy(reg.txt[0], "api_ver=v1.2,v1.3");
    strcpy(reg.txt[1], "api_proto=http");
    strcpy(reg.txt[2], "pri=100");
    mdns_add_service(registry, &reg);

    mdns_t *node = mdns_open_detached("console", "10.1.1.5");
    CHECK(mdns_browse(node, "_nmos-register._tcp"));

    seen_t seen;
    memset(&seen, 0, sizeof seen);

    /* One complete response: reported once, complete. */
    uint8_t q[256], resp[2048], follow[256];
    size_t qn = mdns_build_query(q, sizeof q, "_nmos-register._tcp.local", MDNS_TYPE_PTR);
    size_t rn = mdns_handle_packet(registry, q, qn, resp, sizeof resp, NULL, NULL);
    CHECK(rn > 0);
    CHECK(mdns_handle_packet(node, resp, rn, follow, sizeof follow, on_result, &seen) == 0);
    CHECK(seen.calls == 1);
    CHECK(strcmp(seen.last.instance, "sluice") == 0);
    CHECK(strcmp(seen.last.type, "_nmos-register._tcp") == 0);
    CHECK(strcmp(seen.last.host, "sluice-box.local") == 0);
    CHECK(strcmp(seen.last.ipv4, "10.1.1.9") == 0);
    CHECK(seen.last.port == 3210);
    CHECK(seen.last.txt_count == 3 && strcmp(seen.last.txt[2], "pri=100") == 0);
    CHECK(seen.last.ttl == 4500);

    /* The same response again: nothing changed, nothing reported. */
    CHECK(mdns_handle_packet(node, resp, rn, follow, sizeof follow, on_result, &seen) == 0);
    CHECK(seen.calls == 1);

    /* A type we did not ask for is ignored. */
    mdns_t *other = mdns_open_detached("printer", "10.1.1.77");
    mdns_service_t http;
    memset(&http, 0, sizeof http);
    strcpy(http.instance, "Printer");
    strcpy(http.type, "_http._tcp");
    http.port = 80;
    mdns_add_service(other, &http);
    mdns_record_t recs[4];
    mdns_service_records(other, &http, recs, 4);
    size_t on = mdns_build_response(resp, sizeof resp, recs, 4);
    CHECK(mdns_handle_packet(node, resp, on, follow, sizeof follow, on_result, &seen) == 0);
    CHECK(seen.calls == 1);

    /* Records spread across packets, the PTR alone first: the browser asks
       for the SRV, then the A, and reports once it has both. */
    mdns_service_t reg2 = reg;
    strcpy(reg2.instance, "sluice-2");
    reg2.port = 3211;
    mdns_t *registry2 = mdns_open_detached("second-box", "10.1.1.10");
    mdns_add_service(registry2, &reg2);
    mdns_service_records(registry2, &reg2, recs, 4);
    size_t pn = mdns_build_response(resp, sizeof resp, recs, 1);              /* PTR only */
    size_t fn = mdns_handle_packet(node, resp, pn, follow, sizeof follow, on_result, &seen);
    CHECK(seen.calls == 1);
    mdns_message_t fq;
    CHECK(fn > 0 && mdns_parse_message(follow, fn, &fq) && fq.question_count == 1);
    CHECK(fq.questions[0].type == MDNS_TYPE_SRV);
    CHECK(strcmp(fq.questions[0].name, "sluice-2._nmos-register._tcp.local") == 0);

    size_t sn = mdns_build_response(resp, sizeof resp, recs + 1, 2);          /* SRV + TXT */
    fn = mdns_handle_packet(node, resp, sn, follow, sizeof follow, on_result, &seen);
    CHECK(seen.calls == 1);
    CHECK(fn > 0 && mdns_parse_message(follow, fn, &fq) && fq.questions[0].type == MDNS_TYPE_A);
    CHECK(strcmp(fq.questions[0].name, "second-box.local") == 0);

    size_t an = mdns_build_response(resp, sizeof resp, recs + 3, 1);          /* A */
    CHECK(mdns_handle_packet(node, resp, an, follow, sizeof follow, on_result, &seen) == 0);
    CHECK(seen.calls == 2);
    CHECK(strcmp(seen.last.instance, "sluice-2") == 0 && strcmp(seen.last.ipv4, "10.1.1.10") == 0);
    CHECK(seen.last.port == 3211);

    /* A changed port is a change worth hearing about. */
    reg2.port = 4000;
    mdns_add_service(registry2, &reg2);
    mdns_service_records(registry2, &reg2, recs, 4);
    size_t cn = mdns_build_response(resp, sizeof resp, recs, 4);
    mdns_handle_packet(node, resp, cn, follow, sizeof follow, on_result, &seen);
    CHECK(seen.calls == 3 && seen.last.port == 4000);

    /* Goodbye: reported once with ttl 0, then forgotten. */
    for (int i = 0; i < 4; ++i) recs[i].ttl = 0;
    size_t gn = mdns_build_response(resp, sizeof resp, recs, 4);
    mdns_handle_packet(node, resp, gn, follow, sizeof follow, on_result, &seen);
    CHECK(seen.calls == 4 && seen.goodbyes == 1 && strcmp(seen.last.instance, "sluice-2") == 0);
    mdns_handle_packet(node, resp, gn, follow, sizeof follow, on_result, &seen);
    CHECK(seen.calls == 4);

    /* Expiry: the first registry's TTL runs out. */
    mdns_expire(node, 1, on_result, &seen);
    CHECK(seen.goodbyes == 1);                        /* not yet */
    mdns_expire(node, (uint64_t) 1 << 62, on_result, &seen);   /* the clock is the real one: far enough */
    CHECK(seen.goodbyes == 2 && strcmp(seen.last.instance, "sluice") == 0);

    mdns_close(registry);
    mdns_close(registry2);
    mdns_close(other);
    mdns_close(node);
}

/* --------------------------------------------------------------- socket */

static void test_socket_round_trip(void)
{
    char err[128];
    mdns_t *responder = mdns_open("mdns-test-box", "127.0.0.1", err, sizeof err);
    if (!responder) {
        printf("      socket round trip skipped: %s\n", err);
        return;
    }
    mdns_t *browser = mdns_open("mdns-test-browser", "127.0.0.1", err, sizeof err);
    if (!browser) {
        printf("      socket round trip skipped: %s\n", err);
        mdns_close(responder);
        return;
    }
    mdns_service_t svc = nmos_node();
    strcpy(svc.instance, "mdns-test-instance");
    mdns_add_service(responder, &svc);
    mdns_poll(responder, 10, NULL, NULL);      /* the first announcement goes out */

    seen_t seen;
    memset(&seen, 0, sizeof seen);
    CHECK(mdns_browse(browser, "_nmos-node._tcp"));
    for (int i = 0; i < 40 && seen.calls == 0; ++i) {
        mdns_poll(responder, 25, NULL, NULL);
        mdns_poll(browser, 25, on_result, &seen);
    }
    if (seen.calls == 0) {
        /* Multicast loopback is not a given (CI containers, some VPNs). */
        printf("      socket round trip inconclusive: no multicast loopback here\n");
    } else {
        CHECK(strcmp(seen.last.instance, "mdns-test-instance") == 0);
        CHECK(seen.last.port == 8080);
        CHECK(strcmp(seen.last.ipv4, "127.0.0.1") == 0);
        CHECK(seen.last.txt_count == 2);

        /* Removal says goodbye, and the browser hears it. */
        mdns_remove_service(responder, svc.instance, svc.type);
        for (int i = 0; i < 40 && seen.goodbyes == 0; ++i)
            mdns_poll(browser, 25, on_result, &seen);
        CHECK(seen.goodbyes == 1);
    }
    mdns_close(browser);
    mdns_close(responder);
}

int main(void)
{
    test_query_round_trips();
    test_records_round_trip();
    test_compression_pointers_are_followed();
    test_responder_answers_a_browse();
    test_browser_assembles_a_result();
    test_socket_round_trip();

    if (failures) {
        printf("mdns: %d/%d checks FAILED\n", failures, checks);
        return 1;
    }
    printf("mdns: %d checks passed\n", checks);
    return 0;
}
