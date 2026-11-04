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
                                "HEAD /", "OPTIONS *", "PATCH /", "TRACE /",
                                "CONNECT host:443 HTTP/1.1", NULL };
    static const char *bad[] = { "GETX / HTTP/1.1", "get / HTTP/1.1", "GET", "GET",
                                 "\x16\x03\x01", "", "BREW /pot HTTP/1.1", NULL };
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

/* ------------------------------------------------- TLS fingerprints */

/*
 * A ClientHello with GREASE values, ALPN, groups, point formats,
 * signature algorithms and supported_versions. Expected JA3/JA4 values
 * were computed independently with Python's hashlib.
 */
static size_t fingerprint_hello(uint8_t *out, int with_ech) {
    uint8_t ext[512], sni[32];
    size_t e = 0;
    e = tls_put_ext(ext, e, 0x1a1a, "", 0);                              /* GREASE */
    e = tls_put_ext(ext, e, 0, sni, tls_sni_body(sni, "example.com"));
    e = tls_put_ext(ext, e, 10, "\x00\x06\x2a\x2a\x00\x1d\x00\x17", 8); /* groups */
    e = tls_put_ext(ext, e, 11, "\x01\x00", 2);                          /* formats */
    e = tls_put_ext(ext, e, 16, "\x00\x0c\x02h2\x08http/1.1", 14);       /* ALPN */
    e = tls_put_ext(ext, e, 13, "\x00\x06\x04\x03\x08\x04\x04\x01", 8); /* sig algs */
    e = tls_put_ext(ext, e, 43, "\x06\x3a\x3a\x03\x04\x03\x03", 7);     /* versions */
    if (with_ech) e = tls_put_ext(ext, e, 0xfe0d, "\x00\x01\x02", 3);

    uint8_t *b = out + 9;
    size_t n = 0;
    b[n++] = 3; b[n++] = 3;
    for (int i = 0; i < 32; i++) b[n++] = (uint8_t)i;
    b[n++] = 0;
    static const uint8_t cs[] = { 0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f, 0x00, 0x2f };
    put16(b + n, sizeof(cs)); n += 2;
    memcpy(b + n, cs, sizeof(cs)); n += sizeof(cs);
    b[n++] = 1; b[n++] = 0;
    put16(b + n, (unsigned)e); n += 2;
    memcpy(b + n, ext, e); n += e;
    out[5] = 1;
    out[6] = (uint8_t)(n >> 16); out[7] = (uint8_t)(n >> 8); out[8] = (uint8_t)n;
    out[0] = 0x16; out[1] = 3; out[2] = 1;
    put16(out + 3, (unsigned)(n + 4));
    return 9 + n;
}

static void test_tls_fingerprints(void) {
    uint8_t rec[1024];
    size_t n = fingerprint_hello(rec, 0);
    uint8_t *buf = exact_bytes(rec, n);
    tls_hello_t h;

    CHECK_EQ_INT(tls_parse_client_hello(buf, n, &h), 0);
    CHECK_EQ_INT(h.version, 0x0303);
    CHECK_EQ_INT(h.sni_present, 1);
    CHECK_EQ_STR(h.sni, "example.com");
    CHECK_EQ_STR(h.alpn, "h2,http/1.1");
    CHECK_EQ_INT(h.ech, 0);
    CHECK_EQ_STR(h.ja3, "771,4865-4866-49199-47,0-10-11-16-13-43,29-23,0");
    CHECK_EQ_STR(h.ja3_hash, "8b773e3f902fc5932235b874b965084b");
    CHECK_EQ_STR(h.ja4, "t13d0406h2_f0ee03a69c40_0d385148b956");

    /* Every prefix asks for more data, never reads past it. */
    for (size_t len = 0; len < n; len++) {
        uint8_t *p = exact_bytes(rec, len);
        CHECK_EQ_INT(tls_parse_client_hello(p, len, &h), 1);
        free(p);
    }
    free(buf);
}

static void test_tls_ech(void) {
    uint8_t rec[1024];
    size_t n = fingerprint_hello(rec, 1);
    tls_hello_t h;
    CHECK_EQ_INT(tls_parse_client_hello(rec, n, &h), 0);
    CHECK_EQ_INT(h.ech, 1);
    CHECK_EQ_STR(h.ja4, "t13d0407h2_f0ee03a69c40_3f16740eecf0");
}

/* The handshake message split over three TLS records is joined first. */
static void test_tls_hello_across_records(void) {
    uint8_t rec[1024], split[1100];
    size_t n = fingerprint_hello(rec, 0);
    const uint8_t *hs = rec + 5;
    size_t hl = n - 5, cuts[] = { 0, 3, 40, hl }, o = 0;
    for (int i = 0; i < 3; i++) {
        size_t part = cuts[i + 1] - cuts[i];
        split[o] = 0x16; split[o + 1] = 3; split[o + 2] = 1;
        put16(split + o + 3, (unsigned)part);
        memcpy(split + o + 5, hs + cuts[i], part);
        o += 5 + part;
    }
    tls_hello_t h;
    CHECK_EQ_INT(tls_parse_client_hello(split, o, &h), 0);
    CHECK_EQ_STR(h.ja4, "t13d0406h2_f0ee03a69c40_0d385148b956");
    CHECK_EQ_INT(tls_parse_client_hello(split, o - 1, &h), 1);

    /* A non-handshake record in between is not a ClientHello. */
    split[5 + 3] = 0x17;
    CHECK_EQ_INT(tls_parse_client_hello(split, o, &h), -1);
}

static void test_tls_parse_malformed(void) {
    uint8_t rec[1024];
    size_t n = fingerprint_hello(rec, 0);
    tls_hello_t h;
    uint8_t bad[1024];

    memcpy(bad, rec, n);
    bad[9 + 34 + 1 + 1] = 0x0b;                  /* odd cipher suites length */
    CHECK_EQ_INT(tls_parse_client_hello(bad, n, &h), -1);

    memcpy(bad, rec, n);
    bad[5] = 2;                                  /* ServerHello */
    CHECK_EQ_INT(tls_parse_client_hello(bad, n, &h), -1);

    memcpy(bad, rec, n);
    put16(bad + 3, 0);                           /* empty record */
    CHECK_EQ_INT(tls_parse_client_hello(bad, n, &h), -1);

    CHECK_EQ_INT(tls_parse_client_hello(NULL, 0, &h), -1);
    CHECK(tls_is_grease(0x0a0a) && tls_is_grease(0xfafa) && !tls_is_grease(0x0a1a));
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
    TEST(test_tls_fingerprints),
    TEST(test_tls_ech),
    TEST(test_tls_hello_across_records),
    TEST(test_tls_parse_malformed),
    TEST_END
};
