#include <stdio.h>
#include <string.h>

#include "simpleids/settings.h"
#include "test.h"

/* Collects the errors settings_parse() reports. */
typedef struct {
    int  n;
    int  lines[16];
    char last[256];
} errs_t;

static void collect(const char *name, int line, const char *msg, void *ctx) {
    errs_t *e = ctx;
    (void)name;
    if (e->n < 16) e->lines[e->n] = line;
    e->n++;
    snprintf(e->last, sizeof(e->last), "%s", msg);
}

/* Parse NUL-terminated text from an exact-size heap copy. */
static int parse(settings_t *s, const char *text, errs_t *e) {
    size_t n;
    uint8_t *buf = exact_buf(text, &n);
    memset(e, 0, sizeof(*e));
    int rc = settings_parse(s, "test.conf", buf, n, collect, e);
    free(buf);
    return rc;
}

static void test_settings_defaults(void) {
    settings_t s;
    settings_defaults(&s);
    CHECK_EQ_STR(s.log, "logs/ids.log");
    CHECK_EQ_INT(s.sandbox, 1);
    CHECK_EQ_INT(s.log_max_size, 0);
    CHECK_EQ_INT(s.log_max_files, 5);
    CHECK_EQ_INT(s.nrule_paths, 0);
    CHECK_EQ_INT(s.engine.flow.max_flows, 65536);
}

static void test_settings_full_file(void) {
    settings_t s;
    errs_t e;
    settings_defaults(&s);
    const char *text =
        "# SimpleIDS\r\n"
        "; also a comment\n"
        "\n"
        "[capture]\n"
        "  interface = eth0  \n"
        "filter = \"tcp port 80 or tcp port 8080\"\n"
        "[rules]\n"
        "path = rules\n"
        "path=rules/crs\n"
        "[vars]\n"
        "HOME_NET = [10.0.0.0/8,192.168.0.0/16]\n"
        "[output]\n"
        "log = /var/log/simpleids/eve.json\r\n"
        "quiet = yes\n"
        "log-max-size = 100M\n"
        "log-max-files = 9\n"
        "stats-interval = 30\n"
        "[engine]\n"
        "max-flows = 128K\n"
        "stream-depth = 1M\n"
        "stream-memcap = 1G\n"
        "overlap = last\n"
        "timeout-udp = 5\n"
        "measure-latency = on\n"
        "[security]\n"
        "user = nobody\n"
        "group = nogroup\n"
        "sandbox = false\n";
    CHECK_EQ_INT(parse(&s, text, &e), 0);
    CHECK_EQ_STR(s.interface, "eth0");
    CHECK_EQ_STR(s.filter, "tcp port 80 or tcp port 8080");
    CHECK_EQ_INT(s.filter_set, 1);
    CHECK_EQ_INT(s.nrule_paths, 2);
    CHECK_EQ_STR(s.rule_paths[1], "rules/crs");
    CHECK_EQ_INT(s.nvars, 1);
    CHECK_EQ_STR(s.vars[0].name, "HOME_NET");
    CHECK_EQ_STR(s.vars[0].value, "[10.0.0.0/8,192.168.0.0/16]");
    CHECK_EQ_STR(s.log, "/var/log/simpleids/eve.json");
    CHECK_EQ_INT(s.quiet, 1);
    CHECK_EQ_INT(s.log_max_size, 100ULL * 1024 * 1024);
    CHECK_EQ_INT(s.log_max_files, 9);
    CHECK_EQ_INT(s.stats_interval, 30);
    CHECK_EQ_INT(s.engine.flow.max_flows, 128 * 1024);
    CHECK_EQ_INT(s.engine.stream.depth, 1024 * 1024);
    CHECK_EQ_INT(s.engine.stream.memcap, 1024ULL * 1024 * 1024);
    CHECK_EQ_INT(s.engine.stream.policy, OVERLAP_LAST);
    CHECK_EQ_INT(s.engine.flow.timeout_udp, 5);
    CHECK_EQ_INT(s.latency, 1);
    CHECK_EQ_STR(s.user, "nobody");
    CHECK_EQ_STR(s.group, "nogroup");
    CHECK_EQ_INT(s.sandbox, 0);
}

/* Every mistake is reported with its line, and parsing goes on. */
static void test_settings_errors(void) {
    settings_t s;
    errs_t e;
    settings_defaults(&s);
    const char *text =
        "max-flows = 10\n"              /* 1: outside a section    */
        "[engine]\n"
        "max-flow = 10\n"               /* 3: unknown key (typo)   */
        "max-flows = ten\n"             /* 4: not a number         */
        "max-flows = 0\n"               /* 5: below the minimum    */
        "overlap = middle\n"            /* 6: bad choice           */
        "just words\n"                  /* 7: no '='               */
        "[nope]\n"                      /* 8: unknown section      */
        "key = ignored\n"               /*    (not reported again) */
        "[engine\n"                     /* 10: malformed header    */
        "[output]\n"
        "quiet = maybe\n"               /* 12: not a boolean       */
        "log =\n"                       /* 13: empty log           */
        "log-max-files = 0\n"           /* 14: below the minimum   */
        "stats-interval = 1K\n"         /* 15: no suffix for secs  */
        "[security]\n"
        "user = root;rm\n"              /* 17: not a name          */
        "[vars]\n"
        "BAD-NAME = x\n"                /* 19: bad variable name   */
        "[engine]\n"
        "max-flows = 99999999999999999999999\n"   /* 21: overflow */
        "stream-memcap = -1\n";         /* 22: negative            */
    CHECK_EQ_INT(parse(&s, text, &e), 16);
    static const int want[] = { 1, 3, 4, 5, 6, 7, 8, 10, 12, 13, 14, 15, 17, 19, 21, 22 };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) CHECK_EQ_INT(e.lines[i], want[i]);
    CHECK_EQ_INT(s.engine.flow.max_flows, 65536);     /* defaults kept */
}

static void test_settings_hostile_input(void) {
    settings_t s;
    errs_t e;
    settings_defaults(&s);

    /* An overlong line is one error, and the next line still parses. */
    size_t big = SETTINGS_LINE_MAX + 100;
    char *text = malloc(big + 64);
    memset(text, 'a', big);
    snprintf(text + big, 64, "\n[output]\nquiet = yes\n");
    CHECK_EQ_INT(parse(&s, text, &e), 1);
    CHECK_EQ_INT(e.lines[0], 1);
    CHECK_EQ_INT(s.quiet, 1);
    free(text);

    /* NUL and control bytes. */
    static const uint8_t nul[] = "[output]\nlog = a\0b\nquiet = y\x01s\n";
    uint8_t *p = exact_bytes(nul, sizeof(nul) - 1);
    memset(&e, 0, sizeof(e));
    CHECK_EQ_INT(settings_parse(&s, "t", p, sizeof(nul) - 1, collect, &e), 2);
    free(p);

    /* Too many rule paths and variables. */
    char err[256];
    settings_defaults(&s);
    for (int i = 0; i < SETTINGS_MAX_RULES; i++)
        CHECK_EQ_INT(settings_set(&s, "rules.path", "x.rules", err, sizeof(err)), 0);
    CHECK_EQ_INT(settings_set(&s, "rules.path", "x.rules", err, sizeof(err)), -1);
    for (int i = 0; i < SETTINGS_MAX_VARS; i++) {
        char key[32];
        snprintf(key, sizeof(key), "vars.V%d", i);
        CHECK_EQ_INT(settings_set(&s, key, "any", err, sizeof(err)), 0);
    }
    CHECK_EQ_INT(settings_set(&s, "vars.ONE_MORE", "any", err, sizeof(err)), -1);
    CHECK_EQ_INT(settings_set(&s, "vars.V3", "[1.2.3.4]", err, sizeof(err)), 0);  /* redefine */

    /* A file over the size limit is refused as a whole. */
    memset(&e, 0, sizeof(e));
    CHECK_EQ_INT(settings_parse(&s, "t", (const uint8_t *)"", SETTINGS_FILE_MAX + 1, collect, &e), 1);
}

static void test_settings_sizes(void) {
    unsigned long long v;
    CHECK_EQ_INT(settings_parse_size("64K", 1ULL << 40, &v), 0);
    CHECK_EQ_INT(v, 65536);
    CHECK_EQ_INT(settings_parse_size("0", 10, &v), 0);
    CHECK_EQ_INT(v, 0);
    CHECK_EQ_INT(settings_parse_size("2G", 1ULL << 40, &v), 0);
    CHECK_EQ_INT(v, 2ULL << 30);
    CHECK_EQ_INT(settings_parse_size("1T", 1ULL << 40, &v), -1);
    CHECK_EQ_INT(settings_parse_size("17179869184G", ~0ULL, &v), -1);  /* 2^34 G overflows */
    CHECK_EQ_INT(settings_parse_size(" 1", 10, &v), -1);
    CHECK_EQ_INT(settings_parse_size("+1", 10, &v), -1);
    CHECK_EQ_INT(settings_parse_size("11", 10, &v), -1);
    CHECK_EQ_INT(settings_parse_size("", 10, &v), -1);
}

/* "none" turns the log off; the same names work as CLI keys. */
static void test_settings_set_keys(void) {
    settings_t s;
    char err[256];
    settings_defaults(&s);
    CHECK_EQ_INT(settings_set(&s, "output.log", "none", err, sizeof(err)), 0);
    CHECK_EQ_STR(s.log, "");
    CHECK_EQ_INT(settings_set(&s, "output.log", "-", err, sizeof(err)), 0);
    CHECK_EQ_STR(s.log, "-");
    CHECK_EQ_INT(settings_set(&s, "capture.filter", "", err, sizeof(err)), 0);
    CHECK_EQ_INT(s.filter_set, 1);
    CHECK_EQ_INT(settings_set(&s, "security.user", "1000", err, sizeof(err)), 0);
    CHECK_EQ_INT(settings_set(&s, "nosuch.key", "1", err, sizeof(err)), -1);
    CHECK(strstr(err, "nosuch.key") != NULL);
    CHECK_EQ_INT(settings_set(&s, "engine.stream-depth", "2G", err, sizeof(err)), -1);
}

const test_case_t settings_tests[] = {
    TEST(test_settings_defaults),
    TEST(test_settings_full_file),
    TEST(test_settings_errors),
    TEST(test_settings_hostile_input),
    TEST(test_settings_sizes),
    TEST(test_settings_set_keys),
    TEST_END
};
