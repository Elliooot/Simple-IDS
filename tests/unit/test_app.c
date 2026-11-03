#include "pkt.h"
#include "simpleids/http.h"
#include "simpleids/tls.h"
#include "test.h"

/* ---------------------------------------------------------------- HTTP */

static void test_http_request_line(void) {
    size_t n;
    http_request_t req;
    uint8_t *buf = exact_buf("GET /index.html?a=1 HTTP/1.1\r\nHost: x\r\n\r\n", &n);
    CHECK_EQ_INT(http_parse_request(buf, n, &req), 0);
    CHECK_EQ_INT(req.method_len, 3);
    CHECK_EQ_INT(req.uri_len, strlen("/index.html?a=1"));
    CHECK(memcmp(req.uri, "/index.html?a=1", req.uri_len) == 0);
    CHECK_EQ_INT(req.has_version, 1);
    free(buf);
}

static void test_http_methods(void) {
    static const char *ok[] = { "GET / HTTP/1.0", "POST /", "PUT /", "DELETE /",
                                "HEAD /", "OPTIONS *", "PATCH /", NULL };
    static const char *bad[] = { "GETX / HTTP/1.1", "get / HTTP/1.1", "GET", "GET",
                                 "\x16\x03\x01", "", "CONNECT host:443 HTTP/1.1", NULL };
    http_request_t req;
    for (int i = 0; ok[i]; i++) {
        size_t n;
        uint8_t *b = exact_buf(ok[i], &n);
        CHECK_EQ_INT(http_parse_request(b, n, &req), 0);
        free(b);
    }
    for (int i = 0; bad[i]; i++) {
        size_t n;
        uint8_t *b = exact_buf(bad[i], &n);
        CHECK_EQ_INT(http_parse_request(b, n, &req), -1);
        free(b);
    }
}

/* B1: a request line cut off by the end of the buffer (no NUL). */
static void test_http_truncated_request_line(void) {
    size_t n;
    http_request_t req;
    uint8_t *buf = exact_buf("GET /aaaaaaaaaa", &n);
    CHECK_EQ_INT(http_parse_request(buf, n, &req), 0);
    CHECK_EQ_INT(req.uri_len, 11);
    CHECK_EQ_INT(req.has_version, 0);
    free(buf);

    buf = exact_buf("GET ", &n);
    CHECK_EQ_INT(http_parse_request(buf, n, &req), 0);
    CHECK_EQ_INT(req.uri_len, 0);
    free(buf);
}

static void test_http_find_header(void) {
    size_t n, vlen;
    const uint8_t *v;
    uint8_t *buf = exact_buf("GET / HTTP/1.1\r\nHost: a\r\nuser-agent:   curl/8\r\n"
                             "\r\nUser-Agent: in-body", &n);
    CHECK_EQ_INT(http_find_header(buf, n, "User-Agent", &v, &vlen), 0);
    CHECK_EQ_INT(vlen, 6);
    CHECK(memcmp(v, "curl/8", 6) == 0);
    CHECK_EQ_INT(http_find_header(buf, n, "Cookie", &v, &vlen), -1);
    CHECK_EQ_INT(http_find_header(buf, n, "Hos", &v, &vlen), -1); /* prefix only */
    free(buf);

    /* Header value running into the end of the buffer. */
    buf = exact_buf("GET / HTTP/1.1\nUser-Agent: sqlm", &n);
    CHECK_EQ_INT(http_find_header(buf, n, "User-Agent", &v, &vlen), 0);
    CHECK_EQ_INT(vlen, 4);
    free(buf);

    /* Header name at the very end with no colon. */
    buf = exact_buf("GET / HTTP/1.1\r\nUser-Agent", &n);
    CHECK_EQ_INT(http_find_header(buf, n, "User-Agent", &v, &vlen), -1);
    free(buf);
}

/* ---------------------------------------------------------------- TLS */

static size_t hello_with_sni(uint8_t *out, const char *name) {
    uint8_t body[512], exts[600];
    size_t blen = tls_sni_body(body, name);
    size_t elen = tls_put_ext(exts, 0, 43, "\x02\x03\x04", 3);
    elen = tls_put_ext(exts, elen, 0, body, blen);
    return tls_client_hello(out, exts, elen);
}

static void test_tls_sni_found(void) {
    uint8_t rec[1024];
    size_t n = hello_with_sni(rec, "malicious.example");
    uint8_t *buf = exact_bytes(rec, n);
    char sni[TLS_SNI_MAX];
    CHECK_EQ_INT(tls_extract_sni(buf, n, sni, sizeof(sni)), 17);
    CHECK_EQ_STR(sni, "malicious.example");
    free(buf);
}

/* Every prefix: either fails cleanly or (once the SNI is in) succeeds. */
static void test_tls_every_prefix(void) {
    uint8_t rec[1024];
    size_t n = hello_with_sni(rec, "a.example");
    char sni[TLS_SNI_MAX];

    for (size_t len = 0; len <= n; len++) {
        uint8_t *buf = exact_bytes(rec, len);
        int r = tls_extract_sni(buf, len, sni, sizeof(sni));
        CHECK(r == -1 || (r == 9 && len == n));
        free(buf);
    }
}

static void test_tls_malformed(void) {
    uint8_t rec[1024];
    char sni[TLS_SNI_MAX];
    size_t n = hello_with_sni(rec, "a.example");

    /* Extension length larger than the extensions block. */
    uint8_t bad[1024];
    memcpy(bad, rec, n);
    put16(bad + n - 14 - 2, 0xffff); /* SNI ext length field */
    CHECK_EQ_INT(tls_extract_sni(bad, n, sni, sizeof(sni)), -1);

    /* Handshake length larger than the record. */
    memcpy(bad, rec, n);
    bad[6] = 0x10;
    CHECK_EQ_INT(tls_extract_sni(bad, n, sni, sizeof(sni)), -1);

    /* Not a handshake / not a ClientHello. */
    memcpy(bad, rec, n);
    bad[0] = 0x17;
    CHECK_EQ_INT(tls_extract_sni(bad, n, sni, sizeof(sni)), -1);
    memcpy(bad, rec, n);
    bad[5] = 0x02;
    CHECK_EQ_INT(tls_extract_sni(bad, n, sni, sizeof(sni)), -1);

    /* Control character in the host name. */
    n = hello_with_sni(rec, "a.exa\nmple");
    CHECK_EQ_INT(tls_extract_sni(rec, n, sni, sizeof(sni)), -1);
}

static void test_tls_name_limits(void) {
    uint8_t rec[1024];
    char name[300], sni[TLS_SNI_MAX];
    memset(name, 'a', sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';

    size_t n = hello_with_sni(rec, name);           /* 299 chars: too long */
    CHECK_EQ_INT(tls_extract_sni(rec, n, sni, sizeof(sni)), -1);

    n = hello_with_sni(rec, "example.com");
    char small[5];
    CHECK_EQ_INT(tls_extract_sni(rec, n, small, sizeof(small)), -1);
    CHECK_EQ_INT(tls_extract_sni(rec, n, sni, sizeof(sni)), 11);
}

static void test_tls_no_sni(void) {
    uint8_t rec[256], exts[16];
    size_t elen = tls_put_ext(exts, 0, 43, "\x02\x03\x04", 3);
    size_t n = tls_client_hello(rec, exts, elen);
    char sni[TLS_SNI_MAX];
    CHECK_EQ_INT(tls_extract_sni(rec, n, sni, sizeof(sni)), -1);
    CHECK_EQ_STR(sni, "");
}

const test_case_t http_tests[] = {
    TEST(test_http_request_line),
    TEST(test_http_methods),
    TEST(test_http_truncated_request_line),
    TEST(test_http_find_header),
    TEST_END
};

const test_case_t tls_tests[] = {
    TEST(test_tls_sni_found),
    TEST(test_tls_every_prefix),
    TEST(test_tls_malformed),
    TEST(test_tls_name_limits),
    TEST(test_tls_no_sni),
    TEST_END
};
