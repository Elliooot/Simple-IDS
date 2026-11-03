#include <stdio.h>

#include "simpleids/anomaly.h"
#include "test.h"

static anomaly_hit_t g_last;
static int g_count;

static void collect(const anomaly_hit_t *h, void *ctx) {
    (void)ctx;
    g_last = *h;
    g_count++;
}

/* Send one request; returns the number of anomalies it raised. */
static int send_req(const char *ip, time_t now, const char *req) {
    size_t n;
    uint8_t *buf = exact_buf(req, &n);
    g_count = 0;
    int r = anomaly_check(ip, now, buf, n, collect, NULL);
    free(buf);
    return r;
}

#define PLAIN "GET / HTTP/1.1\r\nHost: x\r\n\r\n"

static void test_rate_threshold(void) {
    anomaly_reset();
    for (int i = 1; i <= ANOMALY_RATE_THRESHOLD; i++)
        CHECK_EQ_INT(send_req("10.0.0.1", 1000, PLAIN), 0);

    CHECK_EQ_INT(send_req("10.0.0.1", 1000, PLAIN), 1); /* 101st */
    CHECK_EQ_INT(g_last.sid, ANOMALY_SID_RATE);

    for (int i = 102; i <= 109; i++)
        CHECK_EQ_INT(send_req("10.0.0.1", 1000, PLAIN), 0);
    CHECK_EQ_INT(send_req("10.0.0.1", 1000, PLAIN), 1); /* 110th */

    /* Other sources are counted separately. */
    CHECK_EQ_INT(send_req("10.0.0.2", 1000, PLAIN), 0);
}

static void test_rate_window_resets(void) {
    anomaly_reset();
    for (int i = 0; i < ANOMALY_RATE_THRESHOLD; i++)
        CHECK_EQ_INT(send_req("10.0.0.1", 1000, PLAIN), 0);
    /* Next window: counting starts over. */
    CHECK_EQ_INT(send_req("10.0.0.1", 1000 + ANOMALY_RATE_WINDOW, PLAIN), 0);
    for (int i = 0; i < ANOMALY_RATE_THRESHOLD - 1; i++)
        CHECK_EQ_INT(send_req("10.0.0.1", 1000 + ANOMALY_RATE_WINDOW, PLAIN), 0);
}

/* B8: a full table evicts the idlest source instead of ignoring new ones. */
static void test_rate_table_eviction(void) {
    char ip[32];
    anomaly_reset();
    for (int i = 0; i < ANOMALY_MAX_IPS; i++) {
        snprintf(ip, sizeof(ip), "10.1.%d.%d", i / 256, i % 256);
        CHECK_EQ_INT(send_req(ip, 1000 + i / 100, PLAIN), 0);
    }
    CHECK_EQ_INT(anomaly_tracked_ips(), ANOMALY_MAX_IPS);
    CHECK_EQ_INT(anomaly_evictions(), 0);

    for (int i = 1; i <= ANOMALY_RATE_THRESHOLD; i++)
        CHECK_EQ_INT(send_req("192.168.9.9", 1020, PLAIN), 0);
    CHECK_EQ_INT(send_req("192.168.9.9", 1020, PLAIN), 1);
    CHECK_EQ_INT(g_last.sid, ANOMALY_SID_RATE);
    CHECK_EQ_INT(anomaly_evictions(), 1);
    CHECK_EQ_INT(anomaly_tracked_ips(), ANOMALY_MAX_IPS);
}

static void test_long_url(void) {
    char req[2100];
    anomaly_reset();

    snprintf(req, sizeof(req), "GET /%0*d HTTP/1.1\r\n\r\n", ANOMALY_URL_MAX - 1, 0);
    CHECK_EQ_INT(send_req("10.0.0.3", 1, req), 0); /* exactly the limit */

    snprintf(req, sizeof(req), "GET /%0*d HTTP/1.1\r\n\r\n", ANOMALY_URL_MAX, 0);
    CHECK_EQ_INT(send_req("10.0.0.3", 1, req), 1);
    CHECK_EQ_INT(g_last.sid, ANOMALY_SID_LONG_URL);

    /* Works for every method, and when the line is cut off. */
    snprintf(req, sizeof(req), "OPTIONS /%0*d", ANOMALY_URL_MAX + 10, 0);
    CHECK_EQ_INT(send_req("10.0.0.3", 1, req), 1);
}

static void test_user_agent(void) {
    anomaly_reset();
    CHECK_EQ_INT(send_req("10.0.0.4", 1, "GET / HTTP/1.1\r\nUser-Agent: SQLMap/1.7\r\n\r\n"), 1);
    CHECK_EQ_INT(g_last.sid, ANOMALY_SID_BAD_UA);
    CHECK_EQ_INT(send_req("10.0.0.4", 1, "GET / HTTP/1.1\r\nuser-agent: ab\r\n\r\n"), 1);
    CHECK_EQ_INT(g_last.sid, ANOMALY_SID_SHORT_UA);
    CHECK_EQ_INT(send_req("10.0.0.4", 1, "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n\r\n"), 0);
    CHECK_EQ_INT(send_req("10.0.0.4", 1, "GET / HTTP/1.1\r\n\r\n"), 0);
    /* B1: User-Agent value cut off at the end of the buffer. */
    CHECK_EQ_INT(send_req("10.0.0.4", 1, "GET / HTTP/1.1\r\nUser-Agent: nikt"), 0);
    CHECK_EQ_INT(send_req("10.0.0.4", 1, "GET / HTTP/1.1\r\nUser-Agent: nikto"), 1);
    /* "User-Agent" in the body is not a header. */
    CHECK_EQ_INT(send_req("10.0.0.4", 1, "POST / HTTP/1.1\r\n\r\nUser-Agent: sqlmap\r\n"), 0);
}

/* B14: messages are single-line and well-formed. */
static void test_messages_are_clean(void) {
    anomaly_reset();
    for (int i = 0; i < 110; i++) send_req("10.0.0.5", 1, PLAIN);
    CHECK_EQ_INT(g_count, 1);
    CHECK(strstr(g_last.msg, "rate still high") != NULL);
    CHECK(strchr(g_last.msg, '\n') == NULL);
    CHECK_EQ_INT(g_last.msg[strlen(g_last.msg) - 1], ')');
}

const test_case_t anomaly_tests[] = {
    TEST(test_rate_threshold),
    TEST(test_rate_window_resets),
    TEST(test_rate_table_eviction),
    TEST(test_long_url),
    TEST(test_user_agent),
    TEST(test_messages_are_clean),
    TEST_END
};
