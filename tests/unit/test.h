#ifndef SIMPLEIDS_TEST_H
#define SIMPLEIDS_TEST_H

/*
 * A deliberately tiny unit test framework.
 *
 *   static void test_something(void) {
 *       CHECK(x == 1);
 *       CHECK_EQ_INT(a, b);
 *       CHECK_EQ_STR(s, "abc");
 *   }
 *   const test_case_t foo_tests[] = { TEST(test_something), TEST_END };
 *
 * and list foo_tests in test_main.c. A failing CHECK prints the location
 * and returns from the test function. Build with SAN=1 so that memory
 * errors abort the run as well.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    void (*fn)(void);
} test_case_t;

#define TEST(fn) { #fn, fn }
#define TEST_END { NULL, NULL }

extern int g_test_failed;

#define TEST_FAIL_(...) do {                                         \
        fprintf(stderr, "    %s:%d: ", __FILE__, __LINE__);          \
        fprintf(stderr, __VA_ARGS__);                                \
        fprintf(stderr, "\n");                                       \
        g_test_failed = 1;                                           \
    } while (0)

#define CHECK(cond) do {                                             \
        if (!(cond)) { TEST_FAIL_("CHECK(%s) failed", #cond); return; } \
    } while (0)

#define CHECK_EQ_INT(a, b) do {                                      \
        long long a_ = (long long)(a), b_ = (long long)(b);          \
        if (a_ != b_) {                                              \
            TEST_FAIL_("%s == %s failed: %lld != %lld", #a, #b, a_, b_); \
            return;                                                  \
        }                                                            \
    } while (0)

#define CHECK_EQ_STR(a, b) do {                                      \
        const char *a_ = (a), *b_ = (b);                             \
        if (!a_ || !b_ || strcmp(a_, b_) != 0) {                     \
            TEST_FAIL_("%s == %s failed: \"%s\" != \"%s\"", #a, #b,  \
                       a_ ? a_ : "(null)", b_ ? b_ : "(null)");      \
            return;                                                  \
        }                                                            \
    } while (0)

/*
 * Copy a string into a heap buffer of exactly strlen(s) bytes with NO
 * terminating NUL, the way packet payloads arrive. Under ASan, any read
 * past the end is reported immediately. Free with free().
 */
static inline uint8_t *exact_buf(const char *s, size_t *len) {
    size_t n = strlen(s);
    uint8_t *p = malloc(n ? n : 1);
    if (!p) abort();
    memcpy(p, s, n);
    *len = n;
    return p;
}

/* Same, for arbitrary bytes. */
static inline uint8_t *exact_bytes(const void *src, size_t n) {
    uint8_t *p = malloc(n ? n : 1);
    if (!p) abort();
    memcpy(p, src, n);
    return p;
}

#endif
