#include <stdio.h>
#include <unistd.h>

#include "simpleids/rules.h"
#include "test.h"

#define R(opts) "alert tcp any any -> any 80 (" opts ")"

static int parse(const char *line, rule_t *r) {
    char err[160];
    return rule_parse(line, r, err, sizeof(err));
}

static void test_parse_full_rule(void) {
    rule_t r;
    CHECK_EQ_INT(parse(R("content:\"<script>\"; msg:\"XSS\"; sid:1001; nocase; priority:1;"), &r), 1);
    CHECK_EQ_INT(r.sid, 1001);
    CHECK_EQ_INT(r.priority, 1);
    CHECK_EQ_INT(r.nocase, 1);
    CHECK_EQ_INT(r.dst_port, 80);
    CHECK_EQ_STR(r.protocol, "tcp");
    CHECK_EQ_STR(r.msg, "XSS");
    CHECK_EQ_INT(r.content_len, 8);
    CHECK(memcmp(r.content, "<script>", 8) == 0);
}

static void test_parse_defaults_and_any_port(void) {
    rule_t r;
    CHECK_EQ_INT(parse("alert ip any any -> any any (content:\"x\"; sid:5)", &r), 1);
    CHECK_EQ_INT(r.dst_port, 0);
    CHECK_EQ_INT(r.priority, 2);
    CHECK_EQ_INT(r.nocase, 0);
    CHECK_EQ_STR(r.msg, "sid 5");
}

static void test_parse_skips_comments_and_blanks(void) {
    rule_t r;
    CHECK_EQ_INT(parse("# comment", &r), 0);
    CHECK_EQ_INT(parse("   \t\r\n", &r), 0);
    CHECK_EQ_INT(parse("", &r), 0);
}

/* B3: overlong header fields must be rejected, never overflow. */
static void test_parse_overlong_fields(void) {
    rule_t r;
    char line[1024];
    char longtok[300];
    memset(longtok, 'A', sizeof(longtok) - 1);
    longtok[sizeof(longtok) - 1] = '\0';

    snprintf(line, sizeof(line), "%s tcp any any -> any 80 (content:\"x\"; sid:1;)", longtok);
    CHECK_EQ_INT(parse(line, &r), -1);
    snprintf(line, sizeof(line), "alert %s any any -> any 80 (content:\"x\"; sid:1;)", longtok);
    CHECK_EQ_INT(parse(line, &r), -1);
    /* Fits TOKEN_MAX but not protocol[8]. */
    CHECK_EQ_INT(parse("alert tcptcptcp any any -> any 80 (content:\"x\"; sid:1;)", &r), -1);
    snprintf(line, sizeof(line), "alert tcp %s any -> any 80 (content:\"x\"; sid:1;)", longtok);
    CHECK_EQ_INT(parse(line, &r), -1);
    snprintf(line, sizeof(line), "alert tcp any any -> any %s (content:\"x\"; sid:1;)", longtok);
    CHECK_EQ_INT(parse(line, &r), -1);
}

/* B3 / B4: overlong strings are errors, not silently empty content. */
static void test_parse_overlong_strings(void) {
    rule_t r;
    char line[2048], big[600];
    memset(big, 'B', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    snprintf(line, sizeof(line), R("content:\"%s\"; sid:1;"), big);
    CHECK_EQ_INT(parse(line, &r), -1);
    snprintf(line, sizeof(line), R("content:\"x\"; msg:\"%s\"; sid:1;"), big);
    CHECK_EQ_INT(parse(line, &r), -1);

    /* Exactly RULE_CONTENT_MAX bytes is fine. */
    big[RULE_CONTENT_MAX] = '\0';
    snprintf(line, sizeof(line), R("content:\"%s\"; sid:1;"), big);
    CHECK_EQ_INT(parse(line, &r), 1);
    CHECK_EQ_INT(r.content_len, RULE_CONTENT_MAX);
}

/* B4: a rule without usable content must never be loaded. */
static void test_parse_requires_content(void) {
    rule_t r;
    CHECK_EQ_INT(parse(R("msg:\"no content\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"a\"; content:\"b\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"a\";"), &r), -1); /* no sid */
}

/* B5: escapes are decoded, so these rules can actually match. */
static void test_parse_escapes(void) {
    rule_t r;
    CHECK_EQ_INT(parse(R("content:\"..\\\\\"; sid:4002;"), &r), 1);
    CHECK_EQ_INT(r.content_len, 3);
    CHECK(memcmp(r.content, "..\\", 3) == 0);

    CHECK_EQ_INT(parse(R("content:\"C:\\\\Windows\\\\System32\"; sid:4004;"), &r), 1);
    CHECK_EQ_INT(r.content_len, strlen("C:\\Windows\\System32"));
    CHECK(memcmp(r.content, "C:\\Windows\\System32", r.content_len) == 0);

    CHECK_EQ_INT(parse(R("content:\"say \\\"hi\\\"\\;\"; sid:1;"), &r), 1);
    CHECK_EQ_INT(r.content_len, 9);
    CHECK(memcmp(r.content, "say \"hi\";", 9) == 0);

    CHECK_EQ_INT(parse(R("content:\"bad \\x escape\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"trailing \\"), &r), -1);
}

static void test_parse_hex_content(void) {
    rule_t r;
    CHECK_EQ_INT(parse(R("content:\"|3C 73|cript|3e|\"; sid:1;"), &r), 1);
    CHECK_EQ_INT(r.content_len, 8);
    CHECK(memcmp(r.content, "<script>", 8) == 0);

    CHECK_EQ_INT(parse(R("content:\"|00 FF|\"; sid:1;"), &r), 1);
    CHECK_EQ_INT(r.content_len, 2);
    CHECK_EQ_INT(r.content[0], 0x00);
    CHECK_EQ_INT(r.content[1], 0xff);

    CHECK_EQ_INT(parse(R("content:\"|3G|\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"|3C\"; sid:1;"), &r), -1);
    /* '|' in msg is literal */
    CHECK_EQ_INT(parse(R("content:\"x\"; msg:\"a|b\"; sid:1;"), &r), 1);
    CHECK_EQ_STR(r.msg, "a|b");
}

/* Parentheses and semicolons inside quotes do not end the options. */
static void test_parse_specials_inside_quotes(void) {
    rule_t r;
    CHECK_EQ_INT(parse(R("content:\"exec(\"; msg:\"a (b); c\"; sid:2004;"), &r), 1);
    CHECK(memcmp(r.content, "exec(", 5) == 0);
    CHECK_EQ_STR(r.msg, "a (b); c");
    CHECK_EQ_INT(parse(R("content:\"a)b\"; sid:1;"), &r), 1);
    CHECK_EQ_INT(r.content_len, 3);
}

static void test_parse_rejects_bad_syntax(void) {
    rule_t r;
    CHECK_EQ_INT(parse("drop tcp any any -> any 80 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert icmp any any -> any 80 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any <> any 80 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any -> any 70000 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any -> any 0 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any -> any 80 content:\"x\"; sid:1;", &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:1;") " trailing", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any -> any 80 (content:\"x\"; sid:1;", &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:0;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:abc;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:99999999999;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:1; priority:256;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:1; pcre:\"/a/\";"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\" sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:1; nocase:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"unterminated; sid:1;"), &r), -1);
}

static void test_parse_ignores_metadata(void) {
    rule_t r;
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:7; rev:2; classtype:web-application-attack; "
                         "reference:url,example.com; metadata:\"a b\";"), &r), 1);
    CHECK_EQ_INT(r.sid, 7);
}

static int g_hits[8];
static int g_nhits;

static void collect(const rule_t *r, const uint8_t *match, void *ctx) {
    (void)ctx;
    (void)match;
    if (g_nhits < 8) g_hits[g_nhits++] = r->sid;
}

static void add_rule(const char *line) {
    rule_t r;
    char err[160];
    if (rule_parse(line, &r, err, sizeof(err)) == 1) rules_add(&r);
}

/* B7: the matcher reports which rules hit. B1: no NUL needed. */
static void test_match_reports_sids(void) {
    rules_free();
    add_rule(R("content:\"<script>\"; sid:1001; nocase;"));
    add_rule(R("content:\"../\"; sid:4001;"));
    add_rule("alert tcp any any -> any 443 (content:\"evil\"; sid:7001;)");
    add_rule("alert ip any any -> any any (content:\"needle\"; sid:9;)");

    size_t n;
    uint8_t *buf = exact_buf("GET /../<SCRIPT> needle", &n);
    g_nhits = 0;
    CHECK_EQ_INT(rules_match(buf, n, "tcp", NULL, 80, collect, NULL), 3);
    CHECK_EQ_INT(g_nhits, 3);
    CHECK_EQ_INT(g_hits[0], 1001);
    CHECK_EQ_INT(g_hits[1], 4001);
    CHECK_EQ_INT(g_hits[2], 9);

    g_nhits = 0;
    CHECK_EQ_INT(rules_match(buf, n, "tcp", NULL, 443, collect, NULL), 1); /* only "ip any" */
    free(buf);

    /* A payload that ends right before the match must not hit. */
    buf = exact_buf("GET /<script", &n);
    CHECK_EQ_INT(rules_match(buf, n, "tcp", NULL, 80, NULL, NULL), 0);
    free(buf);
    rules_free();
}

static void test_duplicate_sid_rejected(void) {
    rules_free();
    rule_t r;
    CHECK_EQ_INT(parse(R("content:\"a\"; sid:42;"), &r), 1);
    CHECK_EQ_INT(rules_add(&r), 0);
    CHECK_EQ_INT(rules_add(&r), -1);
    CHECK_EQ_INT(rules_count(), 1);
    rules_free();
    CHECK_EQ_INT(rules_count(), 0);
}

static void test_load_file_counts_errors(void) {
    char path[] = "/tmp/simpleids-rules-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    CHECK(fp != NULL);
    fprintf(fp, "# comment\n\n");
    fprintf(fp, R("content:\"a\"; sid:1;") "\n");
    fprintf(fp, R("msg:\"no content\"; sid:2;") "\n");   /* error */
    fprintf(fp, R("content:\"b\"; sid:1;") "\n");         /* duplicate */
    for (int i = 0; i < 5000; i++) fputc('x', fp);        /* overlong */
    fputc('\n', fp);
    fprintf(fp, R("content:\"c\"; sid:3;"));              /* no final newline */
    fclose(fp);

    rules_free();
    int errors = -1;
    CHECK_EQ_INT(rules_load_file(path, &errors), 2);
    CHECK_EQ_INT(errors, 3);
    CHECK_EQ_INT(rules_count(), 2);
    unlink(path);
    rules_free();

    CHECK_EQ_INT(rules_load_file("/nonexistent/rules", NULL), -1);
}

/* The shipped rule files must load without a single error. */
static void test_repo_rules_load_cleanly(void) {
    rules_free();
    static const char *const files[] = { "rules/http.rules", "rules/tls.rules",
                                         "rules/dns.rules", NULL };
    for (int i = 0; files[i]; i++) {
        int e = -1;
        CHECK(rules_load_file(files[i], &e) > 0);
        CHECK_EQ_INT(e, 0);
    }
    rules_free();
}

/* Phase 3: protocols, sticky buffers and their pairing. */
static void test_parse_buffers(void) {
    rule_t r;
    CHECK_EQ_INT(parse("alert http any any -> any any (http.uri; content:\"a\"; sid:1;)", &r), 1);
    CHECK_EQ_INT(r.buffer, RULE_BUF_HTTP_URI);
    CHECK_EQ_INT(parse("alert http any any -> any any (http.uri.raw; content:\"a\"; sid:1;)", &r), 1);
    CHECK_EQ_INT(r.buffer, RULE_BUF_HTTP_URI_RAW);
    CHECK_EQ_INT(parse("alert tls any any -> any any (ja3.hash; content:\"ab\"; sid:1;)", &r), 1);
    CHECK_EQ_INT(r.buffer, RULE_BUF_JA3_HASH);
    CHECK_EQ_INT(parse("alert tls any any -> any any (ja4.hash; content:\"t13\"; startswith; sid:1;)", &r), 1);
    CHECK_EQ_INT(r.startswith, 1);
    CHECK_EQ_INT(parse("alert dns any any -> any any (dns.query; dotprefix; content:\".a.com\"; endswith; sid:1;)", &r), 1);
    CHECK_EQ_INT(r.buffer, RULE_BUF_DNS_QUERY);
    CHECK_EQ_INT(r.dotprefix, 1);
    CHECK_EQ_INT(r.endswith, 1);
    /* Raw content is allowed for the application protocols too. */
    CHECK_EQ_INT(parse("alert http any any -> any any (content:\"a\"; sid:1;)", &r), 1);
    CHECK_EQ_INT(r.buffer, RULE_BUF_RAW);
    CHECK_EQ_INT(parse("alert udp any any -> any 53 (content:\"a\"; sid:1;)", &r), 1);
    CHECK_EQ_STR(rule_buffer_name(RULE_BUF_TLS_SNI), "tls.sni");
}

static void test_parse_buffer_errors(void) {
    rule_t r;
    char err[160];
    /* The buffer must fit the protocol. */
    CHECK_EQ_INT(rule_parse("alert tcp any any -> any 80 (http.uri; content:\"a\"; sid:1;)",
                            &r, err, sizeof(err)), -1);
    CHECK(strstr(err, "needs protocol 'http'") != NULL);
    CHECK_EQ_INT(parse("alert http any any -> any any (tls.sni; content:\"a\"; sid:1;)", &r), -1);
    /* Order: buffer, then content, then modifiers. */
    CHECK_EQ_INT(parse("alert http any any -> any any (content:\"a\"; http.uri; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert http any any -> any any (endswith; http.uri; content:\"a\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert dns any any -> any any (dotprefix; dns.query; content:\"a\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert dns any any -> any any (content:\"a\"; dotprefix; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert http any any -> any any (http.uri; http.header; content:\"a\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert http any any -> any any (http.uri:1; content:\"a\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert smtp any any -> any any (content:\"a\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert http any any -> any any (http.nope; content:\"a\"; sid:1;)", &r), -1);
}

static void test_match_buffer_modifiers(void) {
    rules_free();
    add_rule("alert dns any any -> any any (dns.query; dotprefix; content:\".evil.com\"; nocase; endswith; sid:1;)");
    add_rule("alert dns any any -> any any (dns.query; content:\"www.\"; startswith; sid:2;)");
    add_rule("alert dns any any -> any any (dns.query; content:\"exact.org\"; startswith; endswith; sid:3;)");
    add_rule("alert http any any -> any 80 (http.uri; content:\"x\"; sid:4;)");

    static const struct { const char *name; int hits; int first; } cases[] = {
        { "evil.com", 1, 1 },          /* the domain itself              */
        { "a.b.EVIL.com", 1, 1 },      /* any subdomain, any case        */
        { "notevil.com", 0, 0 },       /* not a suffix match             */
        { "evil.com.example", 0, 0 },  /* must end the name              */
        { "www.example.net", 1, 2 },
        { "a.www.example.net", 0, 0 }, /* startswith                     */
        { "exact.org", 1, 3 },
        { "exact.org.uk", 0, 0 },
        { "", 0, 0 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        size_t n;
        uint8_t *buf = exact_buf(cases[i].name, &n);
        g_nhits = 0;
        CHECK_EQ_INT(rules_match_buffer(RULE_BUF_DNS_QUERY, buf, n, 53, collect, NULL),
                     cases[i].hits);
        if (cases[i].hits) CHECK_EQ_INT(g_hits[0], cases[i].first);
        free(buf);
    }

    /* Buffer rules check the port; raw matching ignores buffer rules. */
    size_t n;
    uint8_t *buf = exact_buf("/x", &n);
    CHECK_EQ_INT(rules_match_buffer(RULE_BUF_HTTP_URI, buf, n, 80, NULL, NULL), 1);
    CHECK_EQ_INT(rules_match_buffer(RULE_BUF_HTTP_URI, buf, n, 8080, NULL, NULL), 0);
    CHECK_EQ_INT(rules_match_buffer(RULE_BUF_HTTP_HEADER, buf, n, 80, NULL, NULL), 0);
    CHECK_EQ_INT(rules_match(buf, n, "tcp", "http", 80, NULL, NULL), 0);
    CHECK_EQ_INT(rules_any_raw("tcp", "http", 80), 0);
    CHECK_EQ_INT(rules_max_content_len(), 0);
    free(buf);
    rules_free();
}

/* Raw rules: "http" applies to HTTP streams, "tcp" to all TCP, "udp" to UDP. */
static void test_match_raw_protocols(void) {
    rules_free();
    add_rule("alert http any any -> any any (content:\"x\"; sid:1;)");
    add_rule("alert tcp any any -> any any (content:\"x\"; sid:2;)");
    add_rule("alert udp any any -> any 53 (content:\"x\"; sid:3;)");
    size_t n;
    uint8_t *buf = exact_buf("x", &n);
    CHECK_EQ_INT(rules_match(buf, n, "tcp", "http", 80, NULL, NULL), 2);
    CHECK_EQ_INT(rules_match(buf, n, "tcp", "tls", 443, NULL, NULL), 1);
    CHECK_EQ_INT(rules_match(buf, n, "udp", "dns", 53, NULL, NULL), 1);
    CHECK_EQ_INT(rules_match(buf, n, "udp", NULL, 54, NULL, NULL), 0);
    CHECK_EQ_INT(rules_any_raw("tcp", NULL, 22), 1);
    CHECK_EQ_INT(rules_any_raw("udp", NULL, 54), 0);
    free(buf);
    rules_free();
}

const test_case_t rules_tests[] = {
    TEST(test_parse_full_rule),
    TEST(test_parse_buffers),
    TEST(test_parse_buffer_errors),
    TEST(test_match_buffer_modifiers),
    TEST(test_match_raw_protocols),
    TEST(test_parse_defaults_and_any_port),
    TEST(test_parse_skips_comments_and_blanks),
    TEST(test_parse_overlong_fields),
    TEST(test_parse_overlong_strings),
    TEST(test_parse_requires_content),
    TEST(test_parse_escapes),
    TEST(test_parse_hex_content),
    TEST(test_parse_specials_inside_quotes),
    TEST(test_parse_rejects_bad_syntax),
    TEST(test_parse_ignores_metadata),
    TEST(test_match_reports_sids),
    TEST(test_duplicate_sid_rejected),
    TEST(test_load_file_counts_errors),
    TEST(test_repo_rules_load_cleanly),
    TEST_END
};
