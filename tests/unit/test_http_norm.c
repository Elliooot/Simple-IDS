#include "simpleids/http.h"
#include "test.h"

/* Normalize a NUL-terminated URI from an exact-size heap copy. */
static size_t norm(const char *uri, char *out, size_t cap, unsigned *flags) {
    size_t n;
    uint8_t *in = exact_buf(uri, &n);
    *flags = 0;
    size_t o = http_normalize_uri(in, n, (uint8_t *)out, cap - 1, flags);
    out[o] = '\0';
    free(in);
    return o;
}

static void test_norm_table(void) {
    static const struct {
        const char *in, *out;
        unsigned flags;
    } cases[] = {
        /* Plain */
        { "/", "/", 0 },
        { "/index.html?a=1", "/index.html?a=1", 0 },
        { "", "", 0 },
        { "*", "*", 0 },
        /* Percent-decoding, both hex cases, '+' only in the query */
        { "/%3Cscript%3E", "/<script>", 0 },
        { "/%3cscript%3e", "/<script>", 0 },
        { "/a+b?q=a+b", "/a+b?q=a b", 0 },
        { "/?q=%2B", "/?q=+", 0 },
        { "/?q=%zz%4", "/?q=%zz%4", 0 },           /* invalid escapes stay */
        /* Double and triple encoding */
        { "/?q=%253Cscript%253E", "/?q=<script>", HTTP_NORM_DOUBLE_ENCODED },
        { "/?q=%25253C", "/?q=<", HTTP_NORM_DOUBLE_ENCODED },
        /* %u and full-width forms */
        { "/?q=%u003cscript%u003E", "/?q=<script>", HTTP_NORM_UNICODE },
        { "/?q=%uFF1Cscript%uFF1E", "/?q=<script>", HTTP_NORM_UNICODE },
        { "/?q=%u00e9", "/?q=\xc3\xa9", HTTP_NORM_UNICODE },
        /* Overlong UTF-8 */
        { "/..%c0%af..%c0%afetc/passwd", "/etc/passwd",
          HTTP_NORM_OVERLONG_UTF8 | HTTP_NORM_TRAVERSAL_ROOT },
        { "/?q=%e0%80%bcscript%e0%80%be", "/?q=<script>", HTTP_NORM_OVERLONG_UTF8 },
        /* Path normalization */
        { "//etc///passwd", "/etc/passwd", 0 },
        { "/./etc/./passwd", "/etc/passwd", 0 },
        { "/a/b/../../etc/passwd", "/etc/passwd", 0 },
        { "/a/../../../etc/passwd", "/etc/passwd", HTTP_NORM_TRAVERSAL_ROOT },
        { "/%2e%2e/%2E%2E/etc/passwd", "/etc/passwd", HTTP_NORM_TRAVERSAL_ROOT },
        { "/a\\..\\..\\windows\\win.ini", "/windows/win.ini", HTTP_NORM_TRAVERSAL_ROOT },
        { "/a/b/.", "/a/b/", 0 },
        { "/a/b/..", "/a/", 0 },
        { "/a/", "/a/", 0 },
        { "/..", "/", HTTP_NORM_TRAVERSAL_ROOT },
        { "/...", "/...", 0 },
        /* The query is decoded but not path-normalized */
        { "/x/../y?f=../../etc/passwd", "/y?f=../../etc/passwd", 0 },
        { "/?a=%3F&b=1", "/?a=?&b=1", 0 },
        /* Absolute form */
        { "http://example.com/a/../b?x=1", "/b?x=1", 0 },
        { "HTTPS://example.com", "/", 0 },
        { "http://example.com?x", "/?x", 0 },
        /* NUL byte */
        { "/a%00.jpg", "/a\0.jpg", HTTP_NORM_NUL },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char out[256];
        unsigned flags;
        size_t n = norm(cases[i].in, out, sizeof(out), &flags);
        size_t want = strlen(cases[i].out);
        if (cases[i].flags & HTTP_NORM_NUL) want = 7;    /* "/a\0.jpg" */
        if (n != want || memcmp(out, cases[i].out, n) != 0 || flags != cases[i].flags) {
            TEST_FAIL_("normalize(\"%s\") = \"%s\" flags %#x, want \"%s\" flags %#x",
                       cases[i].in, out, flags, cases[i].out, cases[i].flags);
            return;
        }
    }
}

/* Output never exceeds cap; long input is cut and flagged. */
static void test_norm_bounds(void) {
    char out[16];
    unsigned flags;
    norm("/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?bbbbbbbbbbbbbbbbbbb", out, sizeof(out), &flags);
    CHECK_EQ_INT(strlen(out), 15);
    CHECK(flags & HTTP_NORM_TRUNCATED);

    /* Thousands of "/.." cost linear time and stay at the root. */
    size_t big = 3 * 20000;
    char *in = malloc(big + 1);
    CHECK(in != NULL);
    for (size_t i = 0; i < big; i += 3) memcpy(in + i, "/..", 3);
    in[big] = '\0';
    char out2[64];
    norm(in, out2, sizeof(out2), &flags);
    CHECK_EQ_STR(out2, "/");
    CHECK(flags & HTTP_NORM_TRAVERSAL_ROOT);
    CHECK(flags & HTTP_NORM_TRUNCATED);
    free(in);
}

static void test_form_decode(void) {
    size_t n;
    uint8_t *in = exact_buf("q=%27+OR+1%3D1&x=%253C", &n);
    uint8_t out[64];
    unsigned flags = 0;
    size_t o = http_decode_form(in, n, out, sizeof(out), &flags);
    CHECK_EQ_INT(o, strlen("q=' OR 1=1&x=<"));
    CHECK(memcmp(out, "q=' OR 1=1&x=<", o) == 0);
    CHECK_EQ_INT(flags, HTTP_NORM_DOUBLE_ENCODED);
    free(in);
}

static void test_hpp(void) {
    static const struct { const char *q; int dups; unsigned flags; } cases[] = {
        { "a=1&b=2", 0, 0 },
        { "a=1&a=2", 1, 0 },
        { "id=1/*&id=*/UNION/*&id=*/SELECT", 1, HTTP_NORM_HPP_COMMENT },
        { "id=1%2F*&id=*%2Fx", 1, HTTP_NORM_HPP_COMMENT },  /* encoded */
        { "%69d=1&id=2", 1, 0 },                              /* name decoded */
        { "a=/*x*/&b=1", 0, 0 },                              /* no duplicate */
        { "&&a&a", 1, 0 },
        { "", 0, 0 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t n;
        uint8_t *q = exact_buf(cases[i].q, &n);
        unsigned flags = 0;
        int d = http_check_params(q, n, &flags);
        free(q);
        if (d != cases[i].dups || flags != cases[i].flags) {
            TEST_FAIL_("params(\"%s\") = %d / %#x, want %d / %#x", cases[i].q, d, flags,
                       cases[i].dups, cases[i].flags);
            return;
        }
    }
}

/* Found by fuzz_http: a name longer than the decode buffer (192 bytes)
 * made the value length come out too large, so the value was read past
 * the end of the parameter and of the buffer. */
static void test_hpp_long_name(void) {
    char q[1024];
    char name[301];
    memset(name, 'a', 300);
    name[300] = '\0';
    size_t n;
    unsigned flags = 0;

    snprintf(q, sizeof(q), "%s=1", name);           /* last parameter */
    uint8_t *in = exact_buf(q, &n);
    CHECK_EQ_INT(http_check_params(in, n, &flags), 0);
    CHECK_EQ_INT(flags, 0);
    free(in);

    snprintf(q, sizeof(q), "%s=/*x&%s=*/y", name, name);
    in = exact_buf(q, &n);
    CHECK_EQ_INT(http_check_params(in, n, &flags), 1);
    CHECK_EQ_INT(flags, HTTP_NORM_HPP_COMMENT);
    free(in);
}

static void test_dechunk(void) {
    uint8_t out[64];
    size_t ol, used, n;
    const char *body = "4\r\nWiki\r\n6;ext=1\r\npedia \r\n0\r\nX-Trailer: 1\r\n\r\nGET";
    uint8_t *in = exact_buf(body, &n);
    CHECK_EQ_INT(http_dechunk(in, n, out, sizeof(out), &ol, &used), 1);
    CHECK_EQ_INT(ol, 10);
    CHECK(memcmp(out, "Wikipedia ", 10) == 0);
    CHECK_EQ_INT(used, n - 3);                     /* stops before "GET" */

    /* Every prefix needs more data, and what it decoded is a prefix. */
    for (size_t len = 0; len < n - 3; len++) {
        uint8_t *p = exact_bytes(in, len);
        CHECK_EQ_INT(http_dechunk(p, len, out, sizeof(out), &ol, &used), 0);
        CHECK(ol <= 10 && memcmp(out, "Wikipedia ", ol) == 0);
        free(p);
    }
    free(in);

    /* Output is bounded by cap. */
    in = exact_buf("a\r\n0123456789\r\n0\r\n\r\n", &n);
    CHECK_EQ_INT(http_dechunk(in, n, out, 4, &ol, &used), 1);
    CHECK_EQ_INT(ol, 4);
    free(in);

    static const char *bad[] = { "zz\r\n", "4\r\nWikiX\r\n", "ffffffffff\r\n",
                                 "4 x\r\nWiki\r\n", NULL };
    for (int i = 0; bad[i]; i++) {
        in = exact_buf(bad[i], &n);
        CHECK_EQ_INT(http_dechunk(in, n, out, sizeof(out), &ol, &used), -1);
        free(in);
    }
}

static http_tx_t g_tx;

static void test_parse_tx(void) {
    size_t n;
    uint8_t *buf = exact_buf(
        "POST  http://Example.COM:8080/a/./b/../c%2ephp?id=1&id=2 HTTP/1.1\r\n"
        "Host: WWW.Example.com:8080\r\n"
        "User-Agent:  sqlmap/1.7  \r\n"
        "X-Long: one\r\n"
        "  two\r\n"
        "Cookie: s=1\r\n"
        "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n"
        "Content-Length: 12\r\n"
        "\r\n", &n);
    CHECK_EQ_INT(http_parse_tx(buf, n, &g_tx), 0);
    CHECK_EQ_INT(g_tx.method_len, 4);
    CHECK(memcmp(g_tx.uri, "/a/c.php?id=1&id=2", g_tx.uri_len) == 0);
    CHECK_EQ_INT(g_tx.uri_len, 18);
    CHECK(memcmp(g_tx.uri_raw, "http://", 7) == 0);
    CHECK_EQ_INT(g_tx.host_len, 15);
    CHECK(memcmp(g_tx.host, "www.example.com", 15) == 0);
    CHECK_EQ_INT(g_tx.user_agent_len, 10);
    CHECK(memcmp(g_tx.user_agent, "sqlmap/1.7", 10) == 0);
    CHECK_EQ_INT(g_tx.has_cookie, 1);
    CHECK_EQ_INT(g_tx.content_length, 12);
    CHECK_EQ_INT(g_tx.chunked, 0);
    CHECK_EQ_INT(g_tx.dup_params, 1);
    CHECK_EQ_INT(http_is_form(&g_tx), 1);
    const char *hdr = "Host: WWW.Example.com:8080\r\nUser-Agent: sqlmap/1.7\r\n"
                      "X-Long: one two\r\nCookie: s=1\r\n";
    CHECK(g_tx.header_len > strlen(hdr));
    CHECK(memcmp(g_tx.header, hdr, strlen(hdr)) == 0);
    free(buf);

    /* Conflicting Content-Length values (request smuggling) are invalid. */
    buf = exact_buf("GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n"
                    "Transfer-Encoding: gzip, Chunked\r\nHost: [::1]:80\r\n\r\n", &n);
    CHECK_EQ_INT(http_parse_tx(buf, n, &g_tx), 0);
    CHECK_EQ_INT(g_tx.content_length, HTTP_CL_INVALID);
    CHECK_EQ_INT(g_tx.chunked, 1);
    CHECK_EQ_INT(g_tx.host_len, 5);
    CHECK(memcmp(g_tx.host, "[::1]", 5) == 0);
    free(buf);

    /* A request cut off anywhere still parses what is there. */
    const char *req = "GET /x HTTP/1.1\r\nHost: a\r\nUser-Agent: b\r\n\r\n";
    for (size_t len = 4; len <= strlen(req); len++) {
        uint8_t *p = exact_bytes(req, len);
        CHECK_EQ_INT(http_parse_tx(p, len, &g_tx), 0);
        free(p);
    }
    buf = exact_buf("SSH-2.0-OpenSSH\r\n", &n);
    CHECK_EQ_INT(http_parse_tx(buf, n, &g_tx), -1);
    free(buf);
}

const test_case_t http_norm_tests[] = {
    TEST(test_norm_table),
    TEST(test_norm_bounds),
    TEST(test_form_decode),
    TEST(test_hpp),
    TEST(test_hpp_long_name),
    TEST(test_dechunk),
    TEST(test_parse_tx),
    TEST_END
};
