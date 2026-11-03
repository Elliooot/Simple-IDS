#include <pcap.h>

#include "pkt.h"
#include "simpleids/anomaly.h"
#include "simpleids/engine.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"
#include "test.h"

static void setup(void) {
    rules_free();
    anomaly_reset();
    engine_reset();
    output_open(NULL);
    output_set_quiet(1);
    rule_t r;
    char err[128];
    rule_parse("alert tcp any any -> any 80 (content:\"<script>\"; sid:1001; nocase;)",
               &r, err, sizeof(err));
    rules_add(&r);
    rule_parse("alert tcp any any -> any 443 (content:\"malicious.com\"; sid:7001;)",
               &r, err, sizeof(err));
    rules_add(&r);
}

static void teardown(void) {
    rules_free();
    anomaly_reset();
    output_close();
    output_set_quiet(0);
}

/* Run one frame from an exact-size heap buffer (ASan catches over-reads). */
static void feed(uint16_t dport, const void *payload, size_t plen, size_t caplen_cut) {
    uint8_t frame[2048];
    size_t n = build_tcp_frame(frame, 40000, dport, payload, plen);
    if (caplen_cut) n -= caplen_cut;
    uint8_t *buf = exact_bytes(frame, n);
    struct timeval ts = { 1700000000, 0 };
    engine_process_frame(DLT_EN10MB, &ts, buf, n);
    free(buf);
}

/* B1: the whole pipeline works on non NUL-terminated payloads. */
static void test_engine_http_alert(void) {
    setup();
    const char *req = "GET /?x=<SCRIPT> HTTP/1.1\r\nUser-Agent: curl/8.0\r\n\r\n";
    feed(80, req, strlen(req), 0);
    feed(8080, req, strlen(req), 0);
    const engine_stats_t *s = engine_stats();
    CHECK_EQ_INT(s->packets, 2);
    CHECK_EQ_INT(s->http_requests, 2);
    CHECK_EQ_INT(s->signature_alerts, 2);
    CHECK_EQ_INT(s->anomaly_alerts, 0);
    teardown();
}

static void test_engine_partial_match_is_clean(void) {
    setup();
    const char *req = "GET /?x=<scrip";
    feed(80, req, strlen(req), 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 0);
    CHECK_EQ_INT(engine_stats()->http_requests, 1);
    teardown();
}

/* B2: content beyond caplen is not inspected. */
static void test_engine_respects_caplen(void) {
    setup();
    const char *req = "GET /aaaa HTTP/1.1\r\nX: <script>";
    feed(80, req, strlen(req), 5); /* cuts off "ript>" */
    CHECK_EQ_INT(engine_stats()->signature_alerts, 0);
    CHECK_EQ_INT(engine_stats()->truncated_payloads, 1);
    teardown();
}

static void test_engine_tls_sni(void) {
    setup();
    uint8_t rec[512], exts[64], body[32];
    size_t blen = tls_sni_body(body, "malicious.com");
    size_t elen = tls_put_ext(exts, 0, 0, body, blen);
    size_t n = tls_client_hello(rec, exts, elen);
    feed(443, rec, n, 0);
    CHECK_EQ_INT(engine_stats()->tls_client_hellos, 1);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);
    /* The HTTP rule set must not run on 443. */
    const char *req = "GET /<script> HTTP/1.1\r\n\r\n";
    feed(443, req, strlen(req), 0);
    CHECK_EQ_INT(engine_stats()->signature_alerts, 1);
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

const test_case_t engine_tests[] = {
    TEST(test_engine_http_alert),
    TEST(test_engine_partial_match_is_clean),
    TEST(test_engine_respects_caplen),
    TEST(test_engine_tls_sni),
    TEST(test_engine_counts_decode_failures),
    TEST_END
};
