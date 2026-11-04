#include <glob.h>
#include <stdio.h>
#include <unistd.h>

#include "simpleids/mpm.h"
#include "simpleids/rules.h"
#include "test.h"

#define R(opts) "alert tcp any any -> any 80 (" opts ")"

static int parse(const char *line, rule_t *r) {
    char err[200];
    int rc = rule_parse(NULL, line, r, err, sizeof(err));
    if (rc == 1) rule_free(r);
    return rc;
}

/* Parse and keep the rule (caller frees). */
static int parse_keep(const char *line, rule_t *r, char *err, size_t errlen) {
    return rule_parse(NULL, line, r, err, errlen);
}

/* A compiled ruleset from rule lines (NULL-terminated). */
static ruleset_t *rs_of(const char *const *lines) {
    ruleset_t *rs = ruleset_new();
    for (int i = 0; lines[i]; i++) {
        rule_t r;
        char err[200];
        if (rule_parse(rs, lines[i], &r, err, sizeof(err)) != 1) {
            fprintf(stderr, "    bad test rule %s: %s\n", lines[i], err);
            abort();
        }
        if (ruleset_add(rs, &r) < 0) abort();
    }
    if (ruleset_compile(rs) < 0) abort();
    return rs;
}

static int g_hits[32];
static size_t g_offs[32];
static int g_nhits;

static void collect(const rule_t *r, rule_buffer_t b, size_t off, void *ctx) {
    (void)ctx;
    (void)b;
    if (g_nhits < 32) {
        g_offs[g_nhits] = off;
        g_hits[g_nhits++] = r->sid;
    }
}

static void input_default(rule_input_t *in, uint8_t app) {
    static const uint8_t client[16] = { 10, 0, 0, 2 }, server[16] = { 10, 0, 0, 1 };
    memset(in, 0, sizeof(*in));
    in->l4 = RULE_PROTO_TCP;
    in->app = app;
    in->established = 1;
    in->src = client;
    in->dst = server;
    in->ip_version = 4;
    in->sport = 40000;
    in->dport = 80;
}

static uint8_t app_of(rule_phase_t ph) {
    switch (ph) {
    case RULE_PHASE_HTTP_REQUEST:
    case RULE_PHASE_HTTP_BODY: return RULE_PROTO_HTTP;
    case RULE_PHASE_TLS_HELLO: return RULE_PROTO_TLS;
    case RULE_PHASE_DNS_QUERY: return RULE_PROTO_DNS;
    default:                   return RULE_PROTO_IP;
    }
}

/* Evaluate one buffer (exact-size heap copy, no NUL). Returns hits. */
static int eval1(ruleset_t *rs, rule_phase_t ph, rule_buffer_t b, const char *data) {
    rule_input_t in;
    input_default(&in, app_of(ph));
    size_t n;
    uint8_t *buf = exact_buf(data, &n);
    in.buf[b] = buf;
    in.len[b] = n;
    g_nhits = 0;
    int rc = rules_eval(rs, ph, &in, collect, NULL);
    free(buf);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Parsing: Phase 1.5 regressions                                     */
/* ------------------------------------------------------------------ */

static void test_parse_full_rule(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep(R("content:\"<script>\"; msg:\"XSS\"; sid:1001; nocase; priority:1;"),
                            &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.sid, 1001);
    CHECK_EQ_INT(r.priority, 1);
    CHECK_EQ_INT(r.action, RULE_ACTION_ALERT);
    CHECK_EQ_INT(r.proto, RULE_PROTO_TCP);
    CHECK_EQ_INT(r.dport.npos, 1);
    CHECK_EQ_INT(r.dport.pos[0].lo, 80);
    CHECK_EQ_INT(r.dport.pos[0].hi, 80);
    CHECK_EQ_INT(r.sport.npos, 0);
    CHECK_EQ_STR(r.msg, "XSS");
    CHECK_EQ_INT(r.nm, 1);
    CHECK_EQ_INT(r.m[0].nocase, 1);
    CHECK_EQ_INT(r.m[0].len, 8);
    CHECK(memcmp(r.m[0].data, "<script>", 8) == 0);
    CHECK_EQ_INT(r.raw_tcp, 1);
    CHECK_EQ_INT(r.raw_udp, 0);
    CHECK_EQ_INT(r.fast_pattern, 0);
    rule_free(&r);
}

static void test_parse_defaults_and_any_port(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep("alert ip any any -> any any (content:\"x\"; sid:5)", &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.dport.npos, 0);
    CHECK_EQ_INT(r.priority, 2);
    CHECK_EQ_INT(r.rev, 0);
    CHECK_EQ_INT(r.m[0].nocase, 0);
    CHECK_EQ_STR(r.msg, "sid 5");
    CHECK_EQ_INT(r.raw_tcp, 1);
    CHECK_EQ_INT(r.raw_udp, 1);
    rule_free(&r);
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
    char line[4096];
    char longtok[1500];
    memset(longtok, 'A', sizeof(longtok) - 1);
    longtok[sizeof(longtok) - 1] = '\0';

    snprintf(line, sizeof(line), "%s tcp any any -> any 80 (content:\"x\"; sid:1;)", longtok);
    CHECK_EQ_INT(parse(line, &r), -1);
    snprintf(line, sizeof(line), "alert %s any any -> any 80 (content:\"x\"; sid:1;)", longtok);
    CHECK_EQ_INT(parse(line, &r), -1);
    CHECK_EQ_INT(parse("alert tcptcptcp any any -> any 80 (content:\"x\"; sid:1;)", &r), -1);
    snprintf(line, sizeof(line), "alert tcp %s any -> any 80 (content:\"x\"; sid:1;)", longtok);
    CHECK_EQ_INT(parse(line, &r), -1);
    snprintf(line, sizeof(line), "alert tcp any any -> any %s (content:\"x\"; sid:1;)", longtok);
    CHECK_EQ_INT(parse(line, &r), -1);
    /* A list longer than the token buffer. */
    snprintf(line, sizeof(line), "alert tcp [%s] any -> any 80 (content:\"x\"; sid:1;)", longtok);
    CHECK_EQ_INT(parse(line, &r), -1);
}

/* B3 / B4: overlong strings are errors, not silently empty content. */
static void test_parse_overlong_strings(void) {
    rule_t r;
    char line[2048], big[600];
    char err[200];
    memset(big, 'B', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    snprintf(line, sizeof(line), R("content:\"%s\"; sid:1;"), big);
    CHECK_EQ_INT(parse(line, &r), -1);
    snprintf(line, sizeof(line), R("content:\"x\"; msg:\"%s\"; sid:1;"), big);
    CHECK_EQ_INT(parse(line, &r), -1);

    big[RULE_CONTENT_MAX] = '\0';
    snprintf(line, sizeof(line), R("content:\"%s\"; sid:1;"), big);
    CHECK_EQ_INT(parse_keep(line, &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[0].len, RULE_CONTENT_MAX);
    rule_free(&r);
}

/* B4: a rule without usable content must never be loaded. */
static void test_parse_requires_content(void) {
    rule_t r;
    CHECK_EQ_INT(parse(R("msg:\"no content\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"a\";"), &r), -1); /* no sid */
    /* Phase 4: several contents are fine. */
    CHECK_EQ_INT(parse(R("content:\"a\"; content:\"b\"; sid:1;"), &r), 1);
}

/* B5: escapes are decoded, so these rules can actually match. */
static void test_parse_escapes(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep(R("content:\"..\\\\\"; sid:4002;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[0].len, 3);
    CHECK(memcmp(r.m[0].data, "..\\", 3) == 0);
    rule_free(&r);

    CHECK_EQ_INT(parse_keep(R("content:\"say \\\"hi\\\"\\;\"; sid:1;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[0].len, 9);
    CHECK(memcmp(r.m[0].data, "say \"hi\";", 9) == 0);
    rule_free(&r);

    CHECK_EQ_INT(parse(R("content:\"bad \\x escape\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"trailing \\"), &r), -1);
}

static void test_parse_hex_content(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep(R("content:\"|3C 73|cript|3e|\"; sid:1;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[0].len, 8);
    CHECK(memcmp(r.m[0].data, "<script>", 8) == 0);
    rule_free(&r);

    CHECK_EQ_INT(parse_keep(R("content:\"|00 FF|\"; sid:1;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[0].data[0], 0x00);
    CHECK_EQ_INT(r.m[0].data[1], 0xff);
    rule_free(&r);

    CHECK_EQ_INT(parse(R("content:\"|3G|\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"|3C\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse_keep(R("content:\"x\"; msg:\"a|b\"; sid:1;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_STR(r.msg, "a|b");
    rule_free(&r);
}

static void test_parse_specials_inside_quotes(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep(R("content:\"exec(\"; msg:\"a (b); c\"; sid:2004;"), &r, err, sizeof(err)), 1);
    CHECK(memcmp(r.m[0].data, "exec(", 5) == 0);
    CHECK_EQ_STR(r.msg, "a (b); c");
    rule_free(&r);
}

static void test_parse_rejects_bad_syntax(void) {
    rule_t r;
    CHECK_EQ_INT(parse("reject tcp any any -> any 80 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert icmp any any -> any 80 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any <- any 80 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any -> any 70000 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any -> any 0 (content:\"x\"; sid:1;)", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any -> any 80 content:\"x\"; sid:1;", &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:1;") " trailing", &r), -1);
    CHECK_EQ_INT(parse("alert tcp any any -> any 80 (content:\"x\"; sid:1;", &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:0;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:abc;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:99999999999;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:1; priority:256;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\" sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:1; nocase:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"unterminated; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; sid:1; bogus;"), &r), -1);
}

/* ------------------------------------------------------------------ */
/* Parsing: v2 language                                                */
/* ------------------------------------------------------------------ */

static void test_parse_actions_and_metadata(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep("drop tcp any any <> any 80 (content:\"x\"; sid:7; rev:2; "
                            "classtype:web-application-attack; reference:url,example.com; "
                            "metadata:created_at 2026_11_04;)", &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.action, RULE_ACTION_DROP);
    CHECK_EQ_INT(r.bidirectional, 1);
    CHECK_EQ_INT(r.rev, 2);
    CHECK_EQ_STR(r.classtype, "web-application-attack");
    CHECK_EQ_INT(r.priority, 1);               /* from the classtype */
    rule_free(&r);

    CHECK_EQ_INT(parse_keep(R("content:\"x\"; sid:7; classtype:attempted-recon; priority:3;"),
                            &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.priority, 3);               /* explicit wins */
    rule_free(&r);
    CHECK_EQ_INT(parse_keep("pass tcp any any -> any 80 (content:\"x\"; sid:8;)", &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.action, RULE_ACTION_PASS);
    rule_free(&r);

    CHECK_EQ_INT(parse_keep(R("content:\"x\"; sid:7; classtype:made-up;"), &r, err, sizeof(err)), -1);
    CHECK(strstr(err, "unknown classtype") != NULL);
    CHECK_EQ_INT(rule_classtype_priority("trojan-activity"), 1);
    CHECK_EQ_INT(rule_classtype_priority("nope"), -1);
}

static void test_parse_header_sets(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep("alert tcp [10.0.0.0/8, !10.1.0.0/16] [1024:, !8080] -> "
                            "!192.168.1.1 [80,443,8000:8010] (content:\"x\"; sid:1;)",
                            &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.src.npos, 1);
    CHECK_EQ_INT(r.src.pos[0].prefix, 8);
    CHECK_EQ_INT(r.src.nneg, 1);
    CHECK_EQ_INT(r.src.neg[0].prefix, 16);
    CHECK_EQ_INT(r.sport.npos, 1);
    CHECK_EQ_INT(r.sport.pos[0].lo, 1024);
    CHECK_EQ_INT(r.sport.pos[0].hi, 65535);
    CHECK_EQ_INT(r.sport.nneg, 1);
    CHECK_EQ_INT(r.dst.npos, 0);
    CHECK_EQ_INT(r.dst.nneg, 1);
    CHECK_EQ_INT(r.dport.npos, 3);
    CHECK_EQ_INT(r.dport.pos[2].lo, 8000);
    CHECK_EQ_INT(r.dport.pos[2].hi, 8010);
    rule_free(&r);

    CHECK_EQ_INT(parse_keep("alert tcp 2001:db8::/32 :1023 -> ::1 any (content:\"x\"; sid:1;)",
                            &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.src.pos[0].version, 6);
    CHECK_EQ_INT(r.src.pos[0].prefix, 32);
    CHECK_EQ_INT(r.sport.pos[0].lo, 0);
    CHECK_EQ_INT(r.sport.pos[0].hi, 1023);
    CHECK_EQ_INT(r.dst.pos[0].prefix, 128);
    rule_free(&r);

    rule_t t;
    CHECK_EQ_INT(parse("alert tcp !any any -> any any (content:\"x\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert tcp ![1.2.3.4,!5.6.7.8] any -> any any (content:\"x\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert tcp 1.2.3.4/33 any -> any any (content:\"x\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert tcp 1.2.3 any -> any any (content:\"x\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert tcp any 90:80 -> any any (content:\"x\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert tcp [1.2.3.4 any -> any any (content:\"x\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert tcp $NOPE any -> any any (content:\"x\"; sid:1;)", &t), -1);
}

static void test_parse_variables(void) {
    ruleset_t *rs = ruleset_new();
    rule_t r;
    char err[200];
    CHECK_EQ_INT(ruleset_set_var(rs, "HOME_NET", "[10.0.0.0/8,192.168.0.0/16]"), 0);
    CHECK_EQ_INT(ruleset_set_var(rs, "WEB", "$HOME_NET"), 0);
    CHECK_EQ_INT(ruleset_set_var(rs, "WEB_PORTS", "[80,8080]"), 0);
    CHECK_EQ_INT(rule_parse(rs, "alert tcp !$WEB any -> $WEB $WEB_PORTS (content:\"x\"; sid:1;)",
                            &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.src.nneg, 2);
    CHECK_EQ_INT(r.dst.npos, 2);
    CHECK_EQ_INT(r.dport.npos, 2);
    rule_free(&r);

    /* Built-in defaults; a reference loop is an error, not a hang. */
    CHECK_EQ_INT(rule_parse(rs, "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS "
                            "(content:\"x\"; sid:1;)", &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.src.npos + r.src.nneg, 0);
    CHECK_EQ_INT(r.dst.npos, 2);               /* HTTP_SERVERS -> HOME_NET */
    rule_free(&r);
    CHECK_EQ_INT(ruleset_set_var(rs, "A", "$B"), 0);
    CHECK_EQ_INT(ruleset_set_var(rs, "B", "$A"), 0);
    CHECK_EQ_INT(rule_parse(rs, "alert tcp $A any -> any any (content:\"x\"; sid:1;)", &r, err, sizeof(err)), -1);
    CHECK(strstr(err, "nested too deeply") != NULL);
    CHECK_EQ_INT(ruleset_set_var(rs, "bad-name", "any"), -1);
    CHECK_EQ_INT(ruleset_set_var(rs, "EMPTY", ""), -1);
    ruleset_free(rs);

    /* Global (command line) definitions apply to every ruleset. */
    CHECK_EQ_INT(rules_define_var("HOME_NET", "172.16.0.0/12"), 0);
    CHECK_EQ_INT(rule_parse(NULL, "alert tcp any any -> $HOME_NET any (content:\"x\"; sid:1;)",
                            &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.dst.pos[0].prefix, 12);
    rule_free(&r);
    rules_clear_vars();
}

static void test_parse_content_modifiers(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep(R("content:\"GET\"; offset:0; depth:3; content:\"union\"; nocase; "
                              "content:!\"x\"; content:\"select\"; distance:-2; within:20; "
                              "fast_pattern; sid:1;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.nm, 4);
    CHECK_EQ_INT(r.m[0].has_offset && r.m[0].has_depth, 1);
    CHECK_EQ_INT(r.m[0].depth, 3);
    CHECK_EQ_INT(r.m[2].negated, 1);
    CHECK_EQ_INT(r.m[3].distance, -2);
    CHECK_EQ_INT(r.m[3].within, 20);
    CHECK_EQ_INT(r.m[3].relative, 1);
    CHECK_EQ_INT(r.fast_pattern, 3);           /* named, though not longest */
    CHECK_EQ_INT(r.m[1].backtrack, 1);         /* select is relative to union */
    CHECK_EQ_INT(r.m[0].backtrack, 0);
    CHECK_EQ_INT(r.first_positive, 0);
    rule_free(&r);

    /* Longest positive content is the default fast pattern. */
    CHECK_EQ_INT(parse_keep(R("content:!\"longest-but-negated\"; content:\"ab\"; content:\"abcd\"; sid:1;"),
                            &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.fast_pattern, 2);
    CHECK_EQ_INT(r.first_positive, 1);
    rule_free(&r);

    rule_t t;
    CHECK_EQ_INT(parse(R("nocase; content:\"x\"; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; startswith; offset:2; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"abcd\"; depth:2; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"a\"; content:\"abcd\"; within:2; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"a\"; content:\"b\"; distance:1; depth:5; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; offset:-1; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; depth:0; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:!\"x\"; fast_pattern; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; fast_pattern; content:\"y\"; fast_pattern; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("pcre:\"/x/\"; nocase; sid:1;"), &t), -1);

    char line[2048] = "alert tcp any any -> any 80 (";
    for (int i = 0; i <= RULE_MATCH_MAX; i++) strcat(line, "content:\"a\"; ");
    strcat(line, "sid:1;)");
    CHECK_EQ_INT(parse(line, &t), -1);
}

static void test_parse_pcre(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep(R("pcre:\"/union\\s+(all\\s+)?select/i\"; sid:1;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[0].type, RULE_MATCH_PCRE);
    CHECK_EQ_STR((const char *)r.m[0].data, "union\\s+(all\\s+)?select");
    CHECK_EQ_INT(r.m[0].nocase, 1);
    CHECK_EQ_INT(r.fast_pattern, -1);          /* pcre is never the prefilter */
    rule_free(&r);

    CHECK_EQ_INT(parse_keep(R("content:\"a\"; pcre:!\"/b\\/c\\\"d/R\"; sid:1;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[1].negated, 1);
    CHECK_EQ_INT(r.m[1].relative, 1);
    CHECK_EQ_STR((const char *)r.m[1].data, "b\\/c\"d");
    rule_free(&r);

    CHECK_EQ_INT(parse_keep(R("pcre:\"/a(b/\"; sid:1;"), &r, err, sizeof(err)), -1);
    CHECK(strstr(err, "pcre:") != NULL);
    CHECK_EQ_INT(parse_keep(R("pcre:\"/a/U\"; sid:1;"), &r, err, sizeof(err)), -1);
    CHECK(strstr(err, "sticky buffer") != NULL);
    CHECK_EQ_INT(parse(R("pcre:\"abc\"; sid:1;"), &r), -1);
    CHECK_EQ_INT(parse(R("pcre:\"/abc\"; sid:1;"), &r), -1);
}

static void test_parse_flow_threshold(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep(R("flow:to_server, established; content:\"x\"; "
                              "threshold: type limit, track by_src, count 2, seconds 60; sid:1;"),
                            &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.flow, RULE_FLOW_TO_SERVER | RULE_FLOW_ESTABLISHED);
    CHECK_EQ_INT(r.threshold.type, THRESHOLD_LIMIT);
    CHECK_EQ_INT(r.threshold.track, TRACK_BY_SRC);
    CHECK_EQ_INT(r.threshold.count, 2);
    CHECK_EQ_INT(r.threshold.seconds, 60);
    rule_free(&r);

    CHECK_EQ_INT(parse_keep(R("content:\"x\"; detection_filter:track by_dst, count 5, seconds 10; sid:1;"),
                            &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.threshold.type, THRESHOLD_DETECTION_FILTER);
    CHECK_EQ_INT(r.threshold.track, TRACK_BY_DST);
    rule_free(&r);

    rule_t t;
    CHECK_EQ_INT(parse(R("flow:to_server,to_client; content:\"x\"; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("flow:sideways; content:\"x\"; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; threshold:type limit, track by_src, count 1; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; threshold:type often, track by_src, count 1, seconds 1; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; threshold:type limit, track by_src, count 0, seconds 1; sid:1;"), &t), -1);
    CHECK_EQ_INT(parse(R("content:\"x\"; detection_filter:track by_src, count 1, seconds 1; "
                         "threshold:type limit, track by_src, count 1, seconds 1; sid:1;"), &t), -1);
}

/* Phase 3: protocols, sticky buffers and their pairing. */
static void test_parse_buffers(void) {
    rule_t r;
    char err[200];
    CHECK_EQ_INT(parse_keep("alert http any any -> any any (http.uri; content:\"a\"; "
                            "http.user_agent; content:\"b\"; sid:1;)", &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[0].buffer, RULE_BUF_HTTP_URI);
    CHECK_EQ_INT(r.m[1].buffer, RULE_BUF_HTTP_USER_AGENT);
    CHECK_EQ_INT(r.phase, RULE_PHASE_HTTP_REQUEST);
    rule_free(&r);
    CHECK_EQ_INT(parse_keep("alert http any any -> any any (http.uri; content:\"a\"; "
                            "http.request_body; content:\"b\"; sid:1;)", &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.phase, RULE_PHASE_HTTP_BODY);
    rule_free(&r);
    CHECK_EQ_INT(parse_keep("alert dns any any -> any any (dns.query; dotprefix; content:\".a.com\"; "
                            "endswith; sid:1;)", &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[0].dotprefix, 1);
    CHECK_EQ_INT(r.phase, RULE_PHASE_DNS_QUERY);
    rule_free(&r);
    CHECK_EQ_INT(parse_keep("alert http any any -> any any (content:\"a\"; sid:1;)", &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(r.m[0].buffer, RULE_BUF_RAW);
    CHECK_EQ_INT(r.raw_tcp, 1);
    CHECK_EQ_INT(r.raw_udp, 0);
    rule_free(&r);
    CHECK_EQ_STR(rule_buffer_name(RULE_BUF_TLS_SNI), "tls.sni");
    CHECK_EQ_STR(rule_phase_name(RULE_PHASE_HTTP_BODY), "http-body");

    rule_t t;
    CHECK_EQ_INT(parse_keep("alert tcp any any -> any 80 (http.uri; content:\"a\"; sid:1;)", &t, err, sizeof(err)), -1);
    CHECK(strstr(err, "needs protocol 'http'") != NULL);
    CHECK_EQ_INT(parse("alert http any any -> any any (tls.sni; content:\"a\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert http any any -> any any (content:\"a\"; http.uri; content:\"b\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert dns any any -> any any (dotprefix; dns.query; content:\"a\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert dns any any -> any any (dns.query; content:\"a\"; dotprefix; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert http any any -> any any (http.uri:1; content:\"a\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert http any any -> any any (http.nope; content:\"a\"; sid:1;)", &t), -1);
    CHECK_EQ_INT(parse("alert http any any -> any any (http.uri; sid:1;)", &t), -1);
}

/* ------------------------------------------------------------------ */
/* Aho-Corasick                                                        */
/* ------------------------------------------------------------------ */

static int g_mpm_seen[64];
static void mpm_count(uint32_t id, size_t end, void *ctx) {
    (void)end;
    (void)ctx;
    if (id < 64) g_mpm_seen[id]++;
}

static void test_mpm_classic(void) {
    mpm_t *m = mpm_new();
    const char *pats[] = { "he", "she", "his", "HERS" };
    for (uint32_t i = 0; i < 4; i++)
        CHECK_EQ_INT(mpm_add(m, (const uint8_t *)pats[i], strlen(pats[i]), i), 0);
    CHECK_EQ_INT(mpm_add(m, (const uint8_t *)"she", 3, 9), 0);     /* same bytes, 2nd id */
    CHECK_EQ_INT(mpm_add(m, (const uint8_t *)"", 0, 5), -1);
    CHECK_EQ_INT(mpm_build(m), 0);
    CHECK_EQ_INT(mpm_add(m, (const uint8_t *)"x", 1, 6), -1);       /* after build */

    memset(g_mpm_seen, 0, sizeof(g_mpm_seen));
    size_t n;
    uint8_t *buf = exact_buf("uSHErs his", &n);
    CHECK_EQ_INT(mpm_search(m, buf, n, mpm_count, NULL), 5);  /* she he hers his + 2nd she id */
    CHECK_EQ_INT(g_mpm_seen[0], 1);     /* he   */
    CHECK_EQ_INT(g_mpm_seen[1], 1);     /* she  */
    CHECK_EQ_INT(g_mpm_seen[9], 1);     /* she (second id) */
    CHECK_EQ_INT(g_mpm_seen[2], 1);     /* his  */
    CHECK_EQ_INT(g_mpm_seen[3], 1);     /* hers, case-insensitive */
    free(buf);
    CHECK_EQ_INT(mpm_search(m, NULL, 0, mpm_count, NULL), 0);
    CHECK(mpm_state_count(m) > 1);
    CHECK(mpm_memory(m) > 0);
    mpm_free(m);

    m = mpm_new();                      /* empty automaton */
    CHECK_EQ_INT(mpm_build(m), 0);
    CHECK_EQ_INT(mpm_search(m, (const uint8_t *)"abc", 3, mpm_count, NULL), 0);
    mpm_free(m);
}

/* Against a naive search: random patterns and texts over a small
 * alphabet (lots of overlaps), including high bytes and NUL. */
static uint32_t g_rng = 12345;
static uint32_t rnd(void) {
    g_rng = g_rng * 1103515245u + 12345u;
    return g_rng >> 8;
}

static void test_mpm_vs_naive(void) {
    static const uint8_t alpha[] = { 'a', 'B', 'b', 0x00, 0xff, '%' };
    for (int round = 0; round < 50; round++) {
        mpm_t *m = mpm_new();
        uint8_t pats[20][6];
        size_t plen[20];
        int np = 1 + (int)(rnd() % 20);
        for (int i = 0; i < np; i++) {
            plen[i] = 1 + rnd() % 5;
            for (size_t k = 0; k < plen[i]; k++) pats[i][k] = alpha[rnd() % sizeof(alpha)];
            CHECK_EQ_INT(mpm_add(m, pats[i], plen[i], (uint32_t)i), 0);
        }
        CHECK_EQ_INT(mpm_build(m), 0);
        uint8_t text[200];
        size_t tl = rnd() % sizeof(text);
        for (size_t k = 0; k < tl; k++) text[k] = alpha[rnd() % sizeof(alpha)];
        uint8_t *buf = exact_bytes(text, tl);

        memset(g_mpm_seen, 0, sizeof(g_mpm_seen));
        mpm_search(m, buf, tl, mpm_count, NULL);
        for (int i = 0; i < np; i++) {
            int want = 0;
            for (size_t s = 0; s + plen[i] <= tl; s++) {
                size_t k = 0;
                for (; k < plen[i]; k++) {
                    uint8_t a = text[s + k], b = pats[i][k];
                    if (a >= 'A' && a <= 'Z') a = (uint8_t)(a + 32);
                    if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + 32);
                    if (a != b) break;
                }
                if (k == plen[i]) want++;
            }
            CHECK_EQ_INT(g_mpm_seen[i], want);
        }
        free(buf);
        mpm_free(m);
    }
}

/* ------------------------------------------------------------------ */
/* Evaluation                                                          */
/* ------------------------------------------------------------------ */

/* B7: the matcher reports which rules hit. B1: no NUL needed. */
static void test_eval_reports_sids(void) {
    static const char *const lines[] = {
        R("content:\"<script>\"; sid:1001; nocase;"),
        R("content:\"../\"; sid:4001;"),
        "alert tcp any any -> any 443 (content:\"evil\"; sid:7001;)",
        "alert ip any any -> any any (content:\"needle\"; sid:9;)",
        NULL
    };
    ruleset_t *rs = rs_of(lines);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "GET /../<SCRIPT> needle"), 3);
    CHECK_EQ_INT(g_hits[0], 1001);           /* load order */
    CHECK_EQ_INT(g_hits[1], 4001);
    CHECK_EQ_INT(g_hits[2], 9);
    CHECK_EQ_INT(g_offs[0], 8);
    /* A buffer that ends right before the match must not hit. */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "GET /<script"), 0);
    CHECK_EQ_INT(rules_raw_span(rs), 8);
    ruleset_free(rs);
}

static void test_eval_offset_depth(void) {
    static const char *const lines[] = {
        R("content:\"abc\"; offset:2; depth:4; sid:1;"),     /* window [2,6) */
        R("content:\"xyz\"; startswith; sid:2;"),
        R("content:\"end\"; endswith; sid:3;"),
        NULL
    };
    ruleset_t *rs = rs_of(lines);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "..abc..."), 1);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "...abc.."), 1);   /* ends at 6 */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "....abc."), 0);   /* ends at 7 */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, ".abc...."), 0);   /* before offset */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "xyz"), 1);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, " xyz"), 0);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "the end"), 1);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "end of"), 0);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "endend"), 1);
    ruleset_free(rs);
}

/* distance/within, with backtracking to a later first match. */
static void test_eval_relative(void) {
    static const char *const lines[] = {
        "alert http any any -> any any (http.uri; content:\"union\"; nocase; "
        "content:\"select\"; nocase; distance:0; within:20; sid:2002;)",
        "alert http any any -> any any (http.uri; content:\"a\"; content:\"b\"; distance:2; within:1; sid:2;)",
        "alert http any any -> any any (http.uri; content:\"q=\"; content:\"z\"; distance:-1; within:1; sid:3;)",
        NULL
    };
    ruleset_t *rs = rs_of(lines);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "/?id=1 UNION SELECT 1"), 1);
    CHECK_EQ_INT(g_hits[0], 2002);
    CHECK_EQ_INT(g_offs[0], 7);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI,
                       "/?id=1 union                          select"), 0);
    /* The first "union" is too far away; the second one is close. */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI,
                       "/?q=union of everything we have, union all select 1"), 1);
    CHECK_EQ_INT(g_offs[0], 33);
    /* select before union does not count. */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "select union"), 0);
    /* distance:2; within:1 -> b exactly 2 bytes after a. */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "a..b"), 1);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "a.b"), 0);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "a...b"), 0);
    /* Negative distance reaches back into the previous match. */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "/?q=z"), 0);
    ruleset_free(rs);
}

static void test_eval_negation(void) {
    static const char *const lines[] = {
        R("content:\"admin\"; content:!\"token=\"; sid:1;"),
        R("content:\"GET \"; startswith; content:!\"HTTP/1.1\"; distance:0; within:200; sid:2;"),
        R("content:!\"x\"; sid:3;"),
        NULL
    };
    ruleset_t *rs = rs_of(lines);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "/admin?x"), 1);
    CHECK_EQ_INT(g_hits[0], 1);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "/admin?token=x"), 0);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "GET / HTTP/1.0"), 2);  /* 2 and 3 */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "GET / HTTP/1.1x"), 0);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "y"), 1);      /* sid 3 */
    CHECK_EQ_INT(g_hits[0], 3);
    CHECK_EQ_INT(rules_raw_span(rs), SIZE_MAX);   /* multi-condition raw rules */
    ruleset_free(rs);
}

static void test_eval_pcre(void) {
    static const char *const lines[] = {
        "alert http any any -> any any (http.uri; content:\"select\"; nocase; "
        "pcre:\"/union\\s+(all\\s+)?select/i\"; sid:2002;)",
        "alert http any any -> any any (http.uri; content:\"id=\"; pcre:\"/^\\d+'/R\"; sid:2;)",
        "alert http any any -> any any (http.uri; content:\"cmd=\"; pcre:!\"/^[a-z]+$/R\"; sid:3;)",
        "alert http any any -> any any (http.uri; content:\"slow\"; pcre:\"/(a+)+$/\"; sid:4;)",
        NULL
    };
    ruleset_t *rs = rs_of(lines);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "/?q=1 UNION\tALL\nSELECT 2"), 1);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "/?q=union-select"), 0);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "/?id=12' or"), 1);
    CHECK_EQ_INT(g_hits[0], 2);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "/?x=12'&id=ab"), 0);  /* R */
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "/?cmd=ls"), 0);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "/?cmd=ls;id"), 1);

    /* Catastrophic backtracking stops at the match limit. */
    rules_reset_stats();
    char evil[80] = "/slow?";
    memset(evil + 6, 'a', 40);
    strcpy(evil + 46, "!");
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, evil), 0);
    CHECK(rules_stats()->pcre_limit >= 1);
    ruleset_free(rs);
}

/* Several sticky buffers in one rule: all must match. */
static void test_eval_multi_buffer(void) {
    static const char *const lines[] = {
        "alert http any any -> any any (http.method; content:\"POST\"; startswith; endswith; "
        "http.uri; content:\"/login\"; http.user_agent; content:\"curl\"; sid:1;)",
        "alert http any any -> any any (http.uri; content:\"/upload\"; "
        "http.request_body; content:\"<?php\"; sid:2;)",
        NULL
    };
    ruleset_t *rs = rs_of(lines);
    rule_input_t in;
    input_default(&in, RULE_PROTO_HTTP);
    in.buf[RULE_BUF_HTTP_METHOD] = (const uint8_t *)"POST";
    in.len[RULE_BUF_HTTP_METHOD] = 4;
    in.buf[RULE_BUF_HTTP_URI] = (const uint8_t *)"/login";
    in.len[RULE_BUF_HTTP_URI] = 6;
    g_nhits = 0;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_HTTP_REQUEST, &in, collect, NULL), 0); /* no UA */
    in.buf[RULE_BUF_HTTP_USER_AGENT] = (const uint8_t *)"curl/8.0";
    in.len[RULE_BUF_HTTP_USER_AGENT] = 8;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_HTTP_REQUEST, &in, collect, NULL), 1);
    in.buf[RULE_BUF_HTTP_METHOD] = (const uint8_t *)"GET";
    in.len[RULE_BUF_HTTP_METHOD] = 3;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_HTTP_REQUEST, &in, collect, NULL), 0);

    /* Body rules see the header buffers too, in their own phase. */
    in.buf[RULE_BUF_HTTP_URI] = (const uint8_t *)"/upload";
    in.len[RULE_BUF_HTTP_URI] = 7;
    in.buf[RULE_BUF_HTTP_REQUEST_BODY] = (const uint8_t *)"x=<?php";
    in.len[RULE_BUF_HTTP_REQUEST_BODY] = 7;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_HTTP_REQUEST, &in, collect, NULL), 0);
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_HTTP_BODY, &in, collect, NULL), 1);
    ruleset_free(rs);
}

static void test_eval_header(void) {
    static const char *const lines[] = {
        "alert tcp 10.0.0.0/8 any -> [10.0.0.1,10.0.0.3] 80 (content:\"x\"; sid:1;)",
        "alert tcp !10.0.0.2 any -> any any (content:\"x\"; sid:2;)",
        "alert tcp any 80 <> any 40000 (content:\"x\"; sid:3;)",     /* reversed: matches */
        "alert tcp any any -> any any (flow:established; content:\"x\"; sid:4;)",
        "alert tcp any any -> any any (flow:not_established; content:\"x\"; sid:5;)",
        "alert tcp any any -> any any (flow:to_client; content:\"x\"; sid:6;)",
        "alert udp any any -> any any (content:\"x\"; sid:7;)",
        "alert tcp any [1:1023,!80] -> any any (content:\"x\"; sid:8;)",
        "alert tcp any any -> any !$HTTP_PORTS (content:\"x\"; sid:9;)",
        NULL
    };
    /* HTTP_PORTS defaults to any, so sid 9 is "nothing"; make it 80. */
    ruleset_t *rs = ruleset_new();
    ruleset_set_var(rs, "HTTP_PORTS", "[80,8080]");
    for (int i = 0; lines[i]; i++) {
        rule_t r;
        char err[200];
        CHECK_EQ_INT(rule_parse(rs, lines[i], &r, err, sizeof(err)), 1);
        CHECK_EQ_INT(ruleset_add(rs, &r), 0);
    }
    CHECK_EQ_INT(ruleset_compile(rs), 0);

    CHECK_EQ_INT(eval1(rs, RULE_PHASE_TCP_STREAM, RULE_BUF_RAW, "x"), 3);
    CHECK_EQ_INT(g_hits[0], 1);
    CHECK_EQ_INT(g_hits[1], 3);
    CHECK_EQ_INT(g_hits[2], 4);

    rule_input_t in;
    input_default(&in, RULE_PROTO_IP);
    static const uint8_t other[16] = { 192, 168, 0, 9 };
    in.src = other;
    in.sport = 22;
    in.dport = 9999;
    in.established = 0;
    in.buf[RULE_BUF_RAW] = (const uint8_t *)"x";
    in.len[RULE_BUF_RAW] = 1;
    g_nhits = 0;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_TCP_STREAM, &in, collect, NULL), 4);
    CHECK_EQ_INT(g_hits[0], 2);
    CHECK_EQ_INT(g_hits[1], 5);
    CHECK_EQ_INT(g_hits[2], 8);
    CHECK_EQ_INT(g_hits[3], 9);
    /* IPv6 never matches an IPv4 CIDR, but does match "any". */
    in.ip_version = 6;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_TCP_STREAM, &in, NULL, NULL), 4);
    in.l4 = RULE_PROTO_UDP;
    g_nhits = 0;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_UDP, &in, collect, NULL), 1);  /* only the udp rule */
    CHECK_EQ_INT(g_hits[0], 7);
    CHECK_EQ_INT(rules_raw_applies(rs, RULE_PHASE_UDP, &in), 1);           /* sid 7 */
    ruleset_free(rs);
}

/* A matching pass rule is reported first and stops the evaluation. */
static void test_eval_pass(void) {
    static const char *const lines[] = {
        "alert http any any -> any any (http.uri; content:\"/admin\"; sid:1;)",
        "pass http 10.0.0.2 any -> any any (http.uri; content:\"/admin\"; sid:2;)",
        NULL
    };
    ruleset_t *rs = rs_of(lines);
    CHECK_EQ_INT(eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, "/admin"), 1);
    CHECK_EQ_INT(g_hits[0], 2);
    ruleset_free(rs);
}

/* Phase 3 behaviour, unchanged: dotprefix, startswith, endswith. */
static void test_eval_dotprefix(void) {
    static const char *const lines[] = {
        "alert dns any any -> any any (dns.query; dotprefix; content:\".evil.com\"; nocase; endswith; sid:1;)",
        "alert dns any any -> any any (dns.query; content:\"www.\"; startswith; sid:2;)",
        "alert dns any any -> any any (dns.query; content:\"exact.org\"; startswith; endswith; sid:3;)",
        NULL
    };
    ruleset_t *rs = rs_of(lines);
    static const struct { const char *name; int hits; int first; size_t off; } cases[] = {
        { "evil.com", 1, 1, 0 },
        { "a.b.EVIL.com", 1, 1, 3 },
        { "notevil.com", 0, 0, 0 },
        { "evil.com.example", 0, 0, 0 },
        { "www.example.net", 1, 2, 0 },
        { "a.www.example.net", 0, 0, 0 },
        { "exact.org", 1, 3, 0 },
        { "exact.org.uk", 0, 0, 0 },
        { "", 0, 0, 0 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CHECK_EQ_INT(eval1(rs, RULE_PHASE_DNS_QUERY, RULE_BUF_DNS_QUERY, cases[i].name), cases[i].hits);
        if (cases[i].hits) {
            CHECK_EQ_INT(g_hits[0], cases[i].first);
            CHECK_EQ_INT(g_offs[0], cases[i].off);
        }
    }
    ruleset_free(rs);
}

/* Raw rules: "http" applies to HTTP streams, "tcp" to all TCP, "udp" to UDP. */
static void test_eval_raw_protocols(void) {
    static const char *const lines[] = {
        "alert http any any -> any any (content:\"x\"; sid:1;)",
        "alert tcp any any -> any any (content:\"x\"; sid:2;)",
        "alert udp any any -> any 53 (content:\"x\"; sid:3;)",
        "alert dns any any -> any any (content:\"x\"; sid:4;)",
        NULL
    };
    ruleset_t *rs = rs_of(lines);
    rule_input_t in;
    input_default(&in, RULE_PROTO_HTTP);
    in.buf[RULE_BUF_RAW] = (const uint8_t *)"x";
    in.len[RULE_BUF_RAW] = 1;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_TCP_STREAM, &in, NULL, NULL), 2);
    in.app = RULE_PROTO_TLS;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_TCP_STREAM, &in, NULL, NULL), 1);
    in.app = RULE_PROTO_DNS;                       /* DNS over TCP */
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_TCP_STREAM, &in, NULL, NULL), 2);
    in.l4 = RULE_PROTO_UDP;
    in.dport = 53;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_UDP, &in, NULL, NULL), 2);
    in.dport = 54;
    in.app = RULE_PROTO_IP;
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_UDP, &in, NULL, NULL), 0);
    CHECK_EQ_INT(rules_raw_applies(rs, RULE_PHASE_UDP, &in), 0);
    in.l4 = RULE_PROTO_TCP;
    in.dport = 22;
    CHECK_EQ_INT(rules_raw_applies(rs, RULE_PHASE_TCP_STREAM, &in), 1);
    /* Buffer rules are not raw rules. */
    CHECK_EQ_INT(rules_eval(rs, RULE_PHASE_HTTP_REQUEST, &in, NULL, NULL), 0);
    ruleset_free(rs);
}

/* Every rule found alone is found in the full set, and vice versa: the
 * shared prefilter loses nothing. */
static void test_eval_prefilter_consistent(void) {
    static const char *const lines[] = {
        "alert http any any -> any any (http.uri; content:\"etc/passwd\"; sid:1;)",
        "alert http any any -> any any (http.uri; content:\"passwd\"; nocase; sid:2;)",
        "alert http any any -> any any (http.uri; content:\"pass\"; content:\"wd\"; distance:0; within:3; sid:3;)",
        "alert http any any -> any any (http.uri; content:\"/etc\"; startswith; sid:4;)",
        "alert http any any -> any any (http.uri; pcre:\"/e.c/\"; sid:5;)",
        "alert http any any -> any any (http.uri; content:\"sswd\"; fast_pattern; content:\"/\"; sid:6;)",
        "alert http any any -> any any (http.uri; content:!\"passwd\"; sid:7;)",
        "alert http any any -> any any (http.uri; content:\"PASSWD\"; sid:8;)",
        NULL
    };
    static const char *const inputs[] = {
        "/etc/passwd", "/ETC/PASSWD", "/x?f=../etc/passwd", "passwd", "/etc", "", "/e c/pa wd",
        "/a/b/c/etc/passwdpasswd", NULL
    };
    ruleset_t *all = rs_of(lines);
    for (int k = 0; inputs[k]; k++) {
        eval1(all, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, inputs[k]);
        int got[32], ngot = g_nhits;
        memcpy(got, g_hits, sizeof(got));
        int want = 0;
        for (int i = 0; lines[i]; i++) {
            const char *one[] = { lines[i], NULL };
            ruleset_t *rs = rs_of(one);
            if (eval1(rs, RULE_PHASE_HTTP_REQUEST, RULE_BUF_HTTP_URI, inputs[k])) {
                CHECK(want < ngot);
                CHECK_EQ_INT(got[want], g_hits[0]);
                want++;
            }
            ruleset_free(rs);
        }
        CHECK_EQ_INT(ngot, want);
    }
    ruleset_free(all);
}

/* ------------------------------------------------------------------ */
/* Ruleset                                                             */
/* ------------------------------------------------------------------ */

static void test_duplicate_sid_rejected(void) {
    ruleset_t *rs = ruleset_new();
    rule_t r;
    char err[200];
    CHECK_EQ_INT(rule_parse(rs, R("content:\"a\"; sid:42;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(ruleset_add(rs, &r), 0);
    CHECK_EQ_INT(rule_parse(rs, R("content:\"b\"; sid:42;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(ruleset_add(rs, &r), -1);
    rule_free(&r);
    CHECK_EQ_INT(ruleset_count(rs), 1);
    CHECK(ruleset_find(rs, 42) != NULL);
    CHECK(ruleset_find(rs, 43) == NULL);
    CHECK_EQ_INT(ruleset_compile(rs), 0);
    CHECK_EQ_INT(rule_parse(rs, R("content:\"c\"; sid:43;"), &r, err, sizeof(err)), 1);
    CHECK_EQ_INT(ruleset_add(rs, &r), -1);       /* compiled sets are frozen */
    rule_free(&r);
    ruleset_free(rs);
}

static void test_load_file(void) {
    char path[] = "/tmp/simpleids-rules-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    CHECK(fp != NULL);
    fprintf(fp, "# comment\n\n");
    fprintf(fp, "var WEB [10.0.0.1, 10.0.0.3]\r\n");
    fprintf(fp, "portvar WEB_PORTS 8080\n");
    fprintf(fp, R("content:\"a\"; sid:1;") "\n");
    fprintf(fp, R("msg:\"no content\"; sid:2;") "\n");              /* error */
    fprintf(fp, R("content:\"b\"; sid:1;") "\n");                    /* duplicate */
    for (int i = 0; i < 9000; i++) fputc('x', fp);                   /* overlong */
    fputc('\n', fp);
    fprintf(fp, "alert tcp any any -> $WEB $WEB_PORTS ( \\\n"
                "    content:\"multi\"; \\\n"
                "    sid:3;)\n");                                     /* line 9 */
    for (int i = 0; i < 9000; i++) fputc('y', fp);                   /* overlong and */
    fputs("\\\r\n    content:\"z\"; sid:99;)\n", fp);                 /* continued: one error */
    fprintf(fp, "var BAD\n");                                          /* error */
    fprintf(fp, R("content:\"c\"; sid:4;"));                         /* no final newline */
    fclose(fp);

    ruleset_t *rs = ruleset_new();
    int errors = -1;
    CHECK_EQ_INT(ruleset_load_file(rs, path, &errors), 3);
    CHECK_EQ_INT(errors, 5);
    CHECK(ruleset_find(rs, 99) == NULL);
    CHECK(ruleset_find(rs, 4) != NULL);
    const rule_t *r = ruleset_find(rs, 3);
    CHECK(r != NULL);
    CHECK_EQ_INT(r->line, 9);
    CHECK_EQ_STR(r->file, path);
    CHECK_EQ_INT(r->dst.npos, 2);
    CHECK_EQ_INT(r->dport.pos[0].lo, 8080);
    CHECK_EQ_INT(r->m[0].len, 5);
    unlink(path);
    ruleset_free(rs);

    rs = ruleset_new();
    CHECK_EQ_INT(ruleset_load_file(rs, "/nonexistent/rules", NULL), -1);
    ruleset_free(rs);
}

static int g_warnings;
static void count_warning(const rule_t *r, const char *msg, void *ctx) {
    (void)r;
    (void)msg;
    (void)ctx;
    g_warnings++;
}

/* The shipped rule files must load without a single error, and the
 * library in rules/crs/ must also pass the lint without a warning. */
static void test_repo_rules_load_cleanly(void) {
    static const char *const dirs[] = { "rules/*.rules", "rules/crs/*.rules" };
    int total = 0;
    for (size_t d = 0; d < 2; d++) {
        glob_t g;
        CHECK_EQ_INT(glob(dirs[d], 0, NULL, &g), 0);
        ruleset_t *rs = ruleset_new();
        for (size_t i = 0; i < g.gl_pathc; i++) {
            int e = -1;
            CHECK(ruleset_load_file(rs, g.gl_pathv[i], &e) > 0);
            CHECK_EQ_INT(e, 0);
        }
        globfree(&g);
        CHECK_EQ_INT(ruleset_compile(rs), 0);
        total += ruleset_count(rs);
        if (d == 1) {
            g_warnings = 0;
            CHECK_EQ_INT(ruleset_lint(rs, count_warning, NULL), 0);
            CHECK_EQ_INT(g_warnings, 0);
        }
        ruleset_free(rs);
    }
    CHECK(total >= 150 && total <= 300);       /* ROADMAP Phase 4 */
}


static void test_lint(void) {
    static const char *const clean[] = {
        "alert http any any -> any any (msg:\"ok\"; http.uri; content:\"/etc/passwd\"; sid:1;)",
        "alert tcp any any -> any 21 (msg:\"ok\"; content:\"USER root\"; sid:2;)",
        NULL
    };
    ruleset_t *rs = rs_of(clean);
    CHECK_EQ_INT(ruleset_lint(rs, NULL, NULL), 0);
    rule_phase_info_t pi;
    ruleset_phase_info(rs, RULE_PHASE_HTTP_REQUEST, &pi);
    CHECK_EQ_INT(pi.rules, 1);
    CHECK_EQ_INT(pi.prefiltered, 1);
    CHECK_EQ_INT(pi.patterns, 1);
    CHECK(pi.states >= 12);
    ruleset_free(rs);

    static const char *const bad[] = {
        "alert http any any -> any any (msg:\"m\"; http.uri; pcre:\"/x/\"; sid:1;)",  /* 2 */
        "alert http any any -> any any (msg:\"m\"; http.uri; content:\"ab\"; sid:2;)", /* 1 */
        "alert tcp any any -> any any (msg:\"m\"; content:\"abcdef\"; sid:3;)",        /* 1 */
        "alert tcp any any -> any 80 (msg:\"m\"; flow:to_client; content:\"abc\"; sid:4;)", /* 1 */
        "drop tcp any any -> any 80 (msg:\"m\"; content:\"abc\"; sid:5;)",            /* 1 */
        "alert tcp any any -> any 80 (content:\"abc\"; sid:6;)",                      /* 1 */
        NULL
    };
    rs = rs_of(bad);
    g_warnings = 0;
    CHECK_EQ_INT(ruleset_lint(rs, count_warning, NULL), 7);
    CHECK_EQ_INT(g_warnings, 7);
    ruleset_free(rs);
}

static void test_active_swap(void) {
    static const char *const a[] = { R("content:\"a\"; sid:1;"), NULL };
    ruleset_t *rs = rs_of(a);
    CHECK(rules_set_active(rs) == NULL);
    CHECK(rules_active() == rs);
    CHECK(rules_set_active(NULL) == rs);
    ruleset_free(rs);
    CHECK(rules_active() == NULL);
    CHECK_EQ_INT(rules_raw_span(NULL), 0);
    rule_input_t in;
    input_default(&in, RULE_PROTO_IP);
    CHECK_EQ_INT(rules_eval(NULL, RULE_PHASE_TCP_STREAM, &in, NULL, NULL), 0);
}

const test_case_t rules_tests[] = {
    TEST(test_parse_full_rule),
    TEST(test_parse_defaults_and_any_port),
    TEST(test_parse_skips_comments_and_blanks),
    TEST(test_parse_overlong_fields),
    TEST(test_parse_overlong_strings),
    TEST(test_parse_requires_content),
    TEST(test_parse_escapes),
    TEST(test_parse_hex_content),
    TEST(test_parse_specials_inside_quotes),
    TEST(test_parse_rejects_bad_syntax),
    TEST(test_parse_actions_and_metadata),
    TEST(test_parse_header_sets),
    TEST(test_parse_variables),
    TEST(test_parse_content_modifiers),
    TEST(test_parse_pcre),
    TEST(test_parse_flow_threshold),
    TEST(test_parse_buffers),
    TEST(test_mpm_classic),
    TEST(test_mpm_vs_naive),
    TEST(test_eval_reports_sids),
    TEST(test_eval_offset_depth),
    TEST(test_eval_relative),
    TEST(test_eval_negation),
    TEST(test_eval_pcre),
    TEST(test_eval_multi_buffer),
    TEST(test_eval_header),
    TEST(test_eval_pass),
    TEST(test_eval_dotprefix),
    TEST(test_eval_raw_protocols),
    TEST(test_eval_prefilter_consistent),
    TEST(test_duplicate_sid_rejected),
    TEST(test_load_file),
    TEST(test_repo_rules_load_cleanly),
    TEST(test_lint),
    TEST(test_active_swap),
    TEST_END
};
