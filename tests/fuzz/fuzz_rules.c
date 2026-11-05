/*
 * Fuzz target: the rule language. The input is loaded as a rules file
 * (variables, continuation lines, comments), compiled into the
 * Aho-Corasick prefilters and PCRE2 programs, linted, and then evaluated
 * with the same input as every buffer, so patterns and data both come
 * from the fuzzer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "simpleids/rules.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return 0;
}

static void no_warn(const rule_t *r, const char *msg, void *ctx) {
    (void)r; (void)msg; (void)ctx;
}

static void no_hit(const rule_t *r, rule_buffer_t b, size_t off, void *ctx) {
    (void)r; (void)b; (void)off;
    (*(int *)ctx)++;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 65536) return 0;
    /* fmemopen needs a writable buffer on some libcs. */
    char *copy = malloc(size);
    if (!copy) return 0;
    memcpy(copy, data, size);
    FILE *fp = fmemopen(copy, size, "r");
    if (!fp) { free(copy); return 0; }

    ruleset_t *rs = ruleset_new();
    int errors = 0;
    if (rs) (void)ruleset_load_stream(rs, fp, "fuzz.rules", &errors);
    fclose(fp);
    free(copy);
    if (!rs) return 0;

    if (ruleset_count(rs) > 0 && ruleset_compile(rs) == 0) {
        (void)ruleset_lint(rs, no_warn, NULL);
        static const uint8_t addr[16] = { 10, 0, 0, 1 };
        rule_input_t in;
        memset(&in, 0, sizeof(in));
        in.l4 = RULE_PROTO_TCP;
        in.established = 1;
        in.src = in.dst = addr;
        in.ip_version = 4;
        in.sport = 40000;
        in.dport = 80;
        for (int b = 0; b < RULE_BUF_COUNT; b++) {
            in.buf[b] = data;
            in.len[b] = size;
        }
        int hits = 0;
        for (int p = 0; p < RULE_PHASE_COUNT; p++) {
            in.app = p == RULE_PHASE_HTTP_REQUEST || p == RULE_PHASE_HTTP_BODY ? RULE_PROTO_HTTP
                   : p == RULE_PHASE_TLS_HELLO ? RULE_PROTO_TLS
                   : p == RULE_PHASE_DNS_QUERY ? RULE_PROTO_DNS : RULE_PROTO_IP;
            in.l4 = p == RULE_PHASE_UDP || p == RULE_PHASE_DNS_QUERY ? RULE_PROTO_UDP : RULE_PROTO_TCP;
            (void)rules_eval(rs, (rule_phase_t)p, &in, no_hit, &hits);
            (void)rules_raw_applies(rs, (rule_phase_t)p, &in);
        }
        (void)rules_raw_span(rs);
    }
    ruleset_free(rs);
    return 0;
}
