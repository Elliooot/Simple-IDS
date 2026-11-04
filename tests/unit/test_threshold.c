#include <string.h>

#include "simpleids/threshold.h"
#include "test.h"

static const uint8_t A[16] = { 10, 0, 0, 1 };
static const uint8_t B[16] = { 10, 0, 0, 2 };
static const uint8_t C[16] = { 10, 0, 0, 3 };

static threshold_t th(threshold_type_t type, threshold_track_t track,
                      uint32_t count, uint32_t seconds) {
    threshold_t t = { (uint8_t)type, (uint8_t)track, count, seconds };
    return t;
}

/* Run n matches at time `now` and return how many would alert. */
static int run(int sid, const threshold_t *t, const uint8_t *src, const uint8_t *dst,
               time_t now, int n) {
    int alerts = 0;
    for (int i = 0; i < n; i++) alerts += threshold_check(sid, t, src, dst, now);
    return alerts;
}

static void test_threshold_none_always_alerts(void) {
    threshold_free();
    threshold_t t = th(THRESHOLD_NONE, TRACK_BY_SRC, 0, 0);
    CHECK_EQ_INT(run(1, &t, A, B, 100, 5), 5);
    CHECK_EQ_INT(run(1, NULL, A, B, 100, 5), 5);
    CHECK_EQ_INT((int)threshold_stats()->checked, 0);   /* not even counted */
    threshold_free();
}

/* limit: the first N matches in each window alert, the rest are dropped. */
static void test_threshold_limit(void) {
    threshold_free();
    threshold_t t = th(THRESHOLD_LIMIT, TRACK_BY_SRC, 2, 60);
    CHECK_EQ_INT(run(1, &t, A, B, 100, 5), 2);
    CHECK_EQ_INT(run(1, &t, A, B, 159, 3), 0);          /* same window */
    CHECK_EQ_INT(run(1, &t, A, B, 160, 3), 2);          /* window restarts */
    CHECK_EQ_INT((int)threshold_stats()->checked, 11);
    CHECK_EQ_INT((int)threshold_stats()->suppressed, 7);
    threshold_free();
}

/* threshold: an alert on every Nth match within the window. */
static void test_threshold_every_nth(void) {
    threshold_free();
    threshold_t t = th(THRESHOLD_THRESHOLD, TRACK_BY_SRC, 3, 60);
    int pattern[7];
    for (int i = 0; i < 7; i++) pattern[i] = threshold_check(1, &t, A, B, 100);
    CHECK_EQ_INT(pattern[0], 0);
    CHECK_EQ_INT(pattern[1], 0);
    CHECK_EQ_INT(pattern[2], 1);
    CHECK_EQ_INT(pattern[3], 0);
    CHECK_EQ_INT(pattern[5], 1);
    CHECK_EQ_INT(pattern[6], 0);
    /* Two matches, then the window expires: the count starts over. */
    threshold_free();
    CHECK_EQ_INT(run(1, &t, A, B, 100, 2), 0);
    CHECK_EQ_INT(run(1, &t, A, B, 161, 2), 0);
    CHECK_EQ_INT(run(1, &t, A, B, 162, 1), 1);
    threshold_free();
}

/* both: exactly one alert, at the Nth match, per window. */
static void test_threshold_both(void) {
    threshold_free();
    threshold_t t = th(THRESHOLD_BOTH, TRACK_BY_SRC, 3, 60);
    CHECK_EQ_INT(run(1, &t, A, B, 100, 2), 0);
    CHECK_EQ_INT(threshold_check(1, &t, A, B, 101), 1);
    CHECK_EQ_INT(run(1, &t, A, B, 102, 20), 0);
    CHECK_EQ_INT(run(1, &t, A, B, 200, 3), 1);          /* next window */
    threshold_free();
}

/* detection_filter: silent until the count is exceeded, then every match. */
static void test_threshold_detection_filter(void) {
    threshold_free();
    threshold_t t = th(THRESHOLD_DETECTION_FILTER, TRACK_BY_SRC, 5, 60);
    CHECK_EQ_INT(run(1, &t, A, B, 100, 5), 0);
    CHECK_EQ_INT(run(1, &t, A, B, 130, 3), 3);
    CHECK_EQ_INT(run(1, &t, A, B, 160, 5), 0);          /* window expired */
    threshold_free();
}

/* Tracking keys: by_src separates sources, by_dst destinations, by_rule
 * neither; different sids never share a counter. */
static void test_threshold_tracking(void) {
    threshold_free();
    threshold_t s = th(THRESHOLD_LIMIT, TRACK_BY_SRC, 1, 60);
    CHECK_EQ_INT(run(1, &s, A, C, 100, 3), 1);
    CHECK_EQ_INT(run(1, &s, B, C, 100, 3), 1);          /* other source */
    CHECK_EQ_INT(run(1, &s, A, B, 100, 3), 0);          /* other dst, same src */
    CHECK_EQ_INT(run(2, &s, A, C, 100, 3), 1);          /* other sid */

    threshold_t d = th(THRESHOLD_LIMIT, TRACK_BY_DST, 1, 60);
    CHECK_EQ_INT(run(3, &d, A, C, 100, 2), 1);
    CHECK_EQ_INT(run(3, &d, B, C, 100, 2), 0);          /* same dst */
    CHECK_EQ_INT(run(3, &d, A, B, 100, 2), 1);

    threshold_t r = th(THRESHOLD_LIMIT, TRACK_BY_RULE, 1, 60);
    CHECK_EQ_INT(run(4, &r, A, B, 100, 2), 1);
    CHECK_EQ_INT(run(4, &r, C, A, 100, 2), 0);          /* anyone */

    threshold_t both = th(THRESHOLD_LIMIT, TRACK_BY_BOTH, 1, 60);
    CHECK_EQ_INT(run(5, &both, A, B, 100, 2), 1);
    CHECK_EQ_INT(run(5, &both, A, C, 100, 2), 1);
    CHECK_EQ_INT(run(5, &both, B, A, 100, 2), 1);       /* direction matters */
    CHECK_EQ_INT(run(5, &both, A, B, 100, 2), 0);
    threshold_free();
}

/* A full table evicts the least recently used entries instead of failing;
 * an evicted key starts counting from scratch. */
static void test_threshold_eviction(void) {
    CHECK_EQ_INT(threshold_init(1), 0);                 /* rounds up to 64 */
    threshold_t t = th(THRESHOLD_LIMIT, TRACK_BY_SRC, 1, 3600);
    uint8_t src[16] = { 0 };
    int alerts = 0;
    for (int i = 0; i < 1000; i++) {
        src[0] = (uint8_t)(i >> 8);
        src[1] = (uint8_t)i;
        alerts += threshold_check(1, &t, src, B, 100 + i);
    }
    CHECK_EQ_INT(alerts, 1000);                         /* all distinct */
    CHECK(threshold_stats()->entries <= 64);
    CHECK(threshold_stats()->evicted >= 1000 - 64);
    /* The very first source was evicted long ago: it alerts again. */
    memset(src, 0, sizeof(src));
    CHECK_EQ_INT(threshold_check(1, &t, src, B, 2000), 1);
    CHECK_EQ_INT(threshold_check(1, &t, src, B, 2000), 0);
    threshold_free();
    CHECK_EQ_INT((int)threshold_stats()->entries, 0);
}

const test_case_t threshold_tests[] = {
    TEST(test_threshold_none_always_alerts),
    TEST(test_threshold_limit),
    TEST(test_threshold_every_nth),
    TEST(test_threshold_both),
    TEST(test_threshold_detection_filter),
    TEST(test_threshold_tracking),
    TEST(test_threshold_eviction),
    TEST_END
};
