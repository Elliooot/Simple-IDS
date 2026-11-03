#include <pcap.h>

#include "pkt.h"
#include "simpleids/anomaly.h"
#include "simpleids/engine.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"
#include "test.h"

#define CLIENT_IP 0x0a000002u

static void add_rule(const char *line) {
    rule_t r;
    char err[128];
    if (rule_parse(line, &r, err, sizeof(err)) == 1) rules_add(&r);
}

static void setup_cfg(const engine_config_t *cfg) {
    engine_shutdown();
    rules_free();
    anomaly_reset();
    output_open(NULL);
    output_set_quiet(1);
    add_rule("alert http any any -> any any (http.uri; content:\"<script>\"; sid:1001; nocase;)");
    add_rule("alert http any any -> any any (http.request_body; content:\"<script>\"; nocase; sid:1011;)");
    add_rule("alert tls any any -> any any (tls.sni; content:\"malicious.com\"; sid:7001;)");
    add_rule("alert dns any any -> any any (dns.query; dotprefix; content:\".evil.com\"; endswith; nocase; sid:8001;)");
    add_rule("alert tcp any any -> any 21 (content:\"USER root\"; sid:9001;)");
    engine_init(cfg);
    engine_reset_stats();
}

static void setup(void) {
    engine_config_t cfg;
    engine_config_defaults(&cfg);
    setup_cfg(&cfg);
}

static void teardown(void) {
    engine_shutdown();
    rules_free();
    anomaly_reset();
    output_close();
    output_set_quiet(0);
}

/* Feed one frame from an exact-size heap buffer (ASan catches over-reads). */
static void feed_ex(uint32_t src, uint16_t sport, uint16_t dport, uint32_t seq,
                    uint8_t flags, const void *payload, size_t plen, size_t cut) {
    uint8_t frame[2048];
    size_t n = build_tcp_frame_ex(frame, src, sport, dport, seq, flags, payload, plen);
    n -= cut;
    uint8_t *buf = exact_bytes(frame, n);
    struct timeval ts = { 1700000000, 0 };
    engine_process_frame(DLT_EN10MB, &ts, buf, n);
    free(buf);
}

static void feed(uint16_t dport, const char *payload, size_t cut) {
    feed_ex(CLIENT_IP, 40000, dport, 1, 0x18, payload, strlen(payload), cut);
}

/* B1: the whole pipeline works on non NUL-terminated payloads. */
static void test_engine_http_alert(void) {
    setup();
    const char *req = "GET /?x=<SCRIPT> HTTP/1.1\r\nUser-Agent: curl/8.0\r\n\r\n";
    feed_ex(CLIENT_IP, 40000, 80, 1, 0x18, req, strlen(req), 0);
    feed_ex(CLIENT_IP, 40001, 8080, 1, 0x18, req, strlen(req), 0);
    const engine_stats_t *s = engine_stats();
    CHECK_EQ_INT(s->packets, 2);
    CHECK_EQ_INT(s->http_requests, 2);
    CHECK_EQ_INT(s->signature_alerts, 2);
    CHECK_EQ_INT(s->anomaly_alerts, 0);
    teardown();
}

static void test_engine_partial_match_is_clean(void) {
    setup();
    feed(80, "GET /?x=<scrip", 0);
    engine_shutdown(); /* flush: the incomplete request is still checked */
    CHECK_EQ_INT(engine_stats()->signature_alerts, 0);
    CHECK_EQ_INT(engine_stats()->http_requests, 1);
    teardown();
}

/* B2: content beyond caplen is not inspected. */
static void test_engine_respects_caplen(void) {
    setup();
    feed(80, "GET /?x=<script>", 5); /* cuts off "ript>" */
    engine_shutdown();
    CHECK_EQ_INT(engine_stats()->signature_alerts, 0);
    CHECK_EQ_INT(engine_stats()->truncated_payloads, 1);
    teardown();
}

/* Phase 2 acceptance: <script> split into 3 segments, out of order. */
static void test_engine_split_out_of_order(void) {
    static const int orders[6][3] = {
        {0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}
    };
    const char *parts[3] = { "GET /?x=<scr", "ip", "t> HTTP/1.1\r\n\r\n" };
    uint32_t offs[3] = { 0, 12, 14 };

    for (int o = 0; o < 6; o++) {
        setup();
        uint16_t port = (uint16_t)(41000 + o);
        feed_ex(CLIENT_IP, port, 80, 999, 0x02, "", 0, 0);              /* SYN */
        for (int i = 0; i < 3; i++) {
            int k = orders[o][i];
            feed_ex(CLIENT_IP, port, 80, 1000 + offs[k], 0x18, parts[k], strlen(parts[k]), 0);
        }
        CHECK_EQ_INT(engine_stats()->signature_alerts, 1);
        CHECK_EQ_INT(engine_stats()->http_requests, 1);
        teardown();
    }
}

/* Sequence numbers that wrap around 2^32 in the middle of the request. */
static void test_engine_seq_wraparound(void) {
    setup();
    uint32_t isn = 0xfffffff5u; /* first data byte at 0xfffffff6 */
    feed_ex(CLIENT_IP, 41100, 80, isn, 0x02, "", 0, 0);
    feed_ex(CLIENT_IP, 41100, 80, isn + 1 + 12, 0x18, "ipt> HTTP/1.1\r\n\r\n", 18, 0);
    feed_ex(CLIENT_IP, 41100, 80, isn + 1, 0x18, "GET /?x=<scr", 12, 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);
    teardown();
}

/* The same match seen again (retransmission, rescan) alerts once. */
static void test_engine_dedupes_per_flow(void) {
    setup();
    const char *req = "GET /?x=<script> HTTP/1.1\r\n\r\n";
    feed_ex(CLIENT_IP, 41200, 80, 1, 0x18, req, strlen(req), 0);
    feed_ex(CLIENT_IP, 41200, 80, 1, 0x18, req, strlen(req), 0);
    feed_ex(CLIENT_IP, 41200, 80, 1 + (uint32_t)strlen(req), 0x18, req, strlen(req), 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);
    CHECK_EQ_INT(engine_stats()->http_requests, 2);
    teardown();
}

/* Data after a hole is inspected on its own; no match across the hole. */
static void test_engine_gap_no_false_match(void) {
    setup();
    const char *after = "ipt> HTTP/1.1\r\n\r\nGET /<script> HTTP/1.1\r\n\r\n";
    feed_ex(CLIENT_IP, 41300, 80, 1, 0x18, "GET /?x=<scr", 12, 0);
    feed_ex(CLIENT_IP, 41300, 80, 1 + 15, 0x18, after, strlen(after), 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 0); /* waiting for the hole */
    engine_shutdown();                                  /* flush skips it */
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);  /* only the real one */
    CHECK_EQ_INT(engine_stats()->http_requests, 2);     /* cut one + resynced one */
    teardown();
}

static void test_engine_tls_sni_split(void) {
    setup();
    uint8_t rec[512], exts[64], body[32];
    size_t blen = tls_sni_body(body, "malicious.com");
    size_t elen = tls_put_ext(exts, 0, 0, body, blen);
    size_t n = tls_client_hello(rec, exts, elen);

    feed_ex(CLIENT_IP, 41400, 443, 0, 0x02, "", 0, 0);                 /* SYN */
    feed_ex(CLIENT_IP, 41400, 443, 1 + 60, 0x18, rec + 60, n - 60, 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 0);
    feed_ex(CLIENT_IP, 41400, 443, 1, 0x18, rec, 60, 0);
    CHECK_EQ_INT(engine_stats()->tls_client_hellos, 1);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);

    /* HTTP is recognized by content, so it is parsed on 443 too. */
    feed_ex(CLIENT_IP, 41401, 443, 1, 0x18, "GET /<script> HTTP/1.1\r\n\r\n", 26, 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 2);
    CHECK_EQ_INT(engine_stats()->http_requests, 1);
    teardown();
}

/* A request body split across segments and chunks, and a form post. */
static void test_engine_http_bodies(void) {
    setup();
    const char *hdr = "POST /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    const char *b1 = "5\r\n<scri\r\n", *b2 = "3\r\npt>\r\n0\r\n\r\n";
    size_t h = strlen(hdr), l1 = strlen(b1);
    feed_ex(CLIENT_IP, 41500, 80, 0, 0x02, "", 0, 0);
    feed_ex(CLIENT_IP, 41500, 80, 1, 0x18, hdr, h, 0);
    feed_ex(CLIENT_IP, 41500, 80, 1 + (uint32_t)(h + l1), 0x18, b2, strlen(b2), 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 0);
    feed_ex(CLIENT_IP, 41500, 80, 1 + (uint32_t)h, 0x18, b1, l1, 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);
    CHECK_EQ_INT(engine_stats()->http_bodies, 1);

    /* The next request on the connection is found after the body. */
    feed_ex(CLIENT_IP, 41500, 80, 1 + (uint32_t)(h + l1 + strlen(b2)), 0x18,
            "GET / HTTP/1.1\r\n\r\n", 18, 0);
    CHECK_EQ_INT(engine_stats()->http_requests, 2);

    const char *form = "POST /f HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                       "Content-Length: 16\r\n\r\nq=%3Cscript%3E&z";
    feed_ex(CLIENT_IP, 41501, 80, 1, 0x18, form, strlen(form), 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 2);
    teardown();
}

/* Normalization anomalies fire once per flow. */
static void test_engine_norm_anomaly(void) {
    setup();
    const char *req = "GET /a/../../etc/passwd HTTP/1.1\r\n\r\n";
    feed_ex(CLIENT_IP, 41600, 80, 1, 0x18, req, strlen(req), 0);
    feed_ex(CLIENT_IP, 41600, 80, 1 + (uint32_t)strlen(req), 0x18, req, strlen(req), 0);
    CHECK_EQ_INT(engine_stats()->http_requests, 2);
    CHECK_EQ_INT(engine_stats()->anomaly_alerts, 1);
    teardown();
}

/* HTTP on an unusual port, and raw rules on a stream with no parser. */
static void test_engine_any_port(void) {
    setup();
    feed_ex(CLIENT_IP, 41700, 8888, 1, 0x18, "GET /<script> HTTP/1.1\r\n\r\n", 26, 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);
    feed_ex(CLIENT_IP, 41701, 21, 1, 0x18, "USER ro", 7, 0);
    feed_ex(CLIENT_IP, 41701, 21, 8, 0x18, "ot\r\n", 4, 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 2);
    /* Not HTTP, no raw rule for the port: the stream is dropped at once. */
    size_t before = stream_stats()->mem_used;
    feed_ex(CLIENT_IP, 41702, 22, 1, 0x18, "SSH-2.0-x\r\n", 11, 0);
    CHECK_EQ_INT(stream_stats()->mem_used, before);
    teardown();
}

static size_t dns_msg(uint8_t *out, const char *const *labels, int tcp) {
    size_t n = tcp ? 2 : 0, s = n;
    memset(out + n, 0, 12);
    put16(out + n + 4, 1);
    n += 12;
    for (int i = 0; labels[i]; i++) {
        size_t l = strlen(labels[i]);
        out[n++] = (uint8_t)l;
        memcpy(out + n, labels[i], l);
        n += l;
    }
    out[n++] = 0;
    memcpy(out + n, "\x00\x01\x00\x01", 4);
    n += 4;
    if (tcp) put16(out, (unsigned)(n - s));
    return n;
}

static void feed_udp(uint16_t sport, uint16_t dport, const uint8_t *p, size_t n) {
    uint8_t frame[1024];
    size_t fl = build_udp_frame(frame, CLIENT_IP, sport, dport, p, n);
    uint8_t *buf = exact_bytes(frame, fl);
    struct timeval ts = { 1700000000, 0 };
    engine_process_frame(DLT_EN10MB, &ts, buf, fl);
    free(buf);
}

static void test_engine_dns(void) {
    setup();
    uint8_t msg[512];
    static const char *const bad[] = { "WWW", "Evil", "com", NULL };
    static const char *const good[] = { "notevil", "com", NULL };
    size_t n = dns_msg(msg, bad, 0);
    feed_udp(5353, 53, msg, n);
    CHECK_EQ_INT(engine_stats()->dns_queries, 1);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);
    n = dns_msg(msg, good, 0);
    feed_udp(5354, 53, msg, n);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);

    /* A response (QR set) is not inspected; neither is port 5353. */
    n = dns_msg(msg, bad, 0);
    msg[2] |= 0x80;
    feed_udp(5355, 53, msg, n);
    msg[2] &= 0x7f;
    feed_udp(5356, 5353, msg, n);
    CHECK_EQ_INT(engine_stats()->dns_queries, 2);

    /* Tunneling-like name: one very long label. */
    char label[60];
    memset(label, 'a', sizeof(label) - 1);
    label[sizeof(label) - 1] = '\0';
    const char *const tunnel[] = { label, "t", "example", NULL };
    n = dns_msg(msg, tunnel, 0);
    feed_udp(5357, 53, msg, n);
    CHECK_EQ_INT(engine_stats()->anomaly_alerts, 1);

    /* DNS over TCP: two length-prefixed queries split across segments. */
    size_t a = dns_msg(msg, good, 1);
    size_t b = dns_msg(msg + a, bad, 1);
    feed_ex(CLIENT_IP, 41800, 53, 1, 0x18, msg, a + 5, 0);
    feed_ex(CLIENT_IP, 41800, 53, 1 + (uint32_t)(a + 5), 0x18, msg + a + 5, b - 5, 0);
    CHECK_EQ_INT(engine_stats()->dns_queries, 5);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 2);
    teardown();
}

/* Non-HTTP data on port 80 is dropped from inspection right away. */
static void test_engine_non_http_on_80(void) {
    setup();
    feed(80, "\x16\x03\x01 <script>", 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 0);
    CHECK_EQ_INT(stream_stats()->mem_used, 0);
    teardown();
}

static void test_engine_counts_decode_failures(void) {
    setup();
    uint8_t junk[10] = { 0 };
    struct timeval ts = { 0, 0 };
    engine_process_frame(DLT_EN10MB, &ts, junk, sizeof(junk));
    CHECK_EQ_INT(engine_stats()->decode[DECODE_TRUNCATED], 1);
    CHECK_EQ_INT(engine_stats()->decode[DECODE_OK], 0);
    teardown();
}

/*
 * Phase 2 acceptance: one million flows, each with request data, must
 * stay inside the configured limits (flow pool and reassembly memcap).
 */
static void test_engine_million_flows_bounded(void) {
    engine_config_t cfg;
    engine_config_defaults(&cfg);
    cfg.flow.max_flows = 4096;
    cfg.stream.memcap = 1024 * 1024;
    setup_cfg(&cfg);

    const char *req = "GET /index.html HTTP/1.1\r\nHost: x\r\n";  /* never ends */
    size_t rlen = strlen(req);
    uint8_t frame[256];
    struct timeval ts = { 1700000000, 0 };

    for (uint32_t i = 0; i < 1000000; i++) {
        size_t n = build_tcp_frame_ex(frame, 0x0b000000u + (i >> 6), (uint16_t)(1024 + (i & 63)),
                                      80, 1, 0x18, req, rlen);
        ts.tv_usec = (int)(i % 1000000);
        engine_process_frame(DLT_EN10MB, &ts, frame, n);
        if (flow_stats()->active > cfg.flow.max_flows) break;
        if (stream_stats()->mem_used > cfg.stream.memcap) break;
    }

    const flow_stats_t *fs = flow_stats();
    CHECK_EQ_INT(fs->created, 1000000);
    CHECK(fs->active_peak <= cfg.flow.max_flows);
    CHECK_EQ_INT(fs->evicted, 1000000 - cfg.flow.max_flows);
    CHECK(stream_stats()->mem_peak <= cfg.stream.memcap);
    CHECK(stream_stats()->memcap_drops > 0); /* the cap was actually hit */

    engine_shutdown();
    CHECK_EQ_INT(stream_stats()->mem_used, 0);
    CHECK(engine_stats()->http_requests > 0);       /* evicted flows were inspected */
    teardown();
}

const test_case_t engine_tests[] = {
    TEST(test_engine_http_alert),
    TEST(test_engine_partial_match_is_clean),
    TEST(test_engine_respects_caplen),
    TEST(test_engine_split_out_of_order),
    TEST(test_engine_seq_wraparound),
    TEST(test_engine_dedupes_per_flow),
    TEST(test_engine_gap_no_false_match),
    TEST(test_engine_tls_sni_split),
    TEST(test_engine_non_http_on_80),
    TEST(test_engine_http_bodies),
    TEST(test_engine_norm_anomaly),
    TEST(test_engine_any_port),
    TEST(test_engine_dns),
    TEST(test_engine_counts_decode_failures),
    TEST(test_engine_million_flows_bounded),
    TEST_END
};
