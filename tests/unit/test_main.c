#include <stdio.h>
#include <string.h>

#include "test.h"

int g_test_failed = 0;

extern const test_case_t bytes_tests[];
extern const test_case_t rules_tests[];
extern const test_case_t decode_tests[];
extern const test_case_t http_tests[];
extern const test_case_t tls_tests[];
extern const test_case_t anomaly_tests[];
extern const test_case_t output_tests[];
extern const test_case_t flow_tests[];
extern const test_case_t stream_tests[];
extern const test_case_t engine_tests[];

static const struct {
    const char *name;
    const test_case_t *cases;
} SUITES[] = {
    { "bytes",   bytes_tests },
    { "rules",   rules_tests },
    { "decode",  decode_tests },
    { "http",    http_tests },
    { "tls",     tls_tests },
    { "anomaly", anomaly_tests },
    { "output",  output_tests },
    { "flow",    flow_tests },
    { "stream",  stream_tests },
    { "engine",  engine_tests },
};

/* Usage: unit_tests [substring]   runs tests whose name contains it. */
int main(int argc, char **argv) {
    const char *filter = argc > 1 ? argv[1] : NULL;
    int run = 0, failed = 0;

    for (size_t s = 0; s < sizeof(SUITES) / sizeof(SUITES[0]); s++) {
        for (const test_case_t *t = SUITES[s].cases; t->name; t++) {
            if (filter && !strstr(t->name, filter) && !strstr(SUITES[s].name, filter))
                continue;
            g_test_failed = 0;
            t->fn();
            run++;
            if (g_test_failed) {
                failed++;
                printf("FAIL %s/%s\n", SUITES[s].name, t->name);
            } else {
                printf("ok   %s/%s\n", SUITES[s].name, t->name);
            }
        }
    }

    printf("\n%d/%d unit tests passed\n", run - failed, run);
    return failed ? 1 : 0;
}
