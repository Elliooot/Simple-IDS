#include <stdio.h>
#include <unistd.h>

#include "simpleids/config.h"
#include "simpleids/output.h"
#include "test.h"

/* B10: everything that is not printable ASCII gets escaped. */
static void test_json_escape(void) {
    char out[128];
    const uint8_t in[] = { 'a', '"', '\\', '\n', '\r', '\t', 0x01, 0x7f, 0xff, 'z' };
    CHECK_EQ_INT(json_escape(out, sizeof(out), in, sizeof(in)), sizeof(in));
    CHECK_EQ_STR(out, "a\\\"\\\\\\n\\r\\t\\u0001\\u007f\\u00ffz");
}

/* Truncation never splits an escape sequence and always terminates. */
static void test_json_escape_truncation(void) {
    char out[8];
    const uint8_t in[] = { 'a', 'b', 'c', 0x01, 'd' };
    size_t used = json_escape(out, sizeof(out), in, sizeof(in));
    CHECK_EQ_INT(used, 3);
    CHECK_EQ_STR(out, "abc");

    CHECK_EQ_INT(json_escape(out, 1, in, sizeof(in)), 0);
    CHECK_EQ_STR(out, "");
}

static void test_timestamp_is_utc(void) {
    struct timeval tv = { 1700000000, 42 };
    char buf[40];
    format_timestamp(&tv, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "2023-11-14T22:13:20.000042Z");
}

/* B11: a log file that cannot be opened is an error, not silently ignored. */
static void test_open_failure_reported(void) {
    CHECK_EQ_INT(output_open("/nonexistent-dir/ids.log"), -1);
    CHECK_EQ_INT(output_open(NULL), 0);
    output_close();
}

static void test_alert_line_is_json(void) {
    char path[] = "/tmp/simpleids-log-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    close(fd);

    CHECK_EQ_INT(output_open(path), 0);
    output_set_quiet(1);

    packet_t p;
    memset(&p, 0, sizeof(p));
    strcpy(p.src_ip, "10.0.0.2");
    strcpy(p.dst_ip, "10.0.0.1");
    p.src_port = 1234;
    p.dst_port = 80;

    const uint8_t data[] = { 'G', 'E', 'T', ' ', '"', 0x00, 0x80 };
    alert_event_t ev = {
        .ts = { 1700000000, 0 }, .pkt = &p, .sid = 1001, .priority = 1,
        .msg = "quote \" and \\ backslash", .source = ALERT_SOURCE_SIGNATURE,
        .data = data, .data_len = sizeof(data),
    };
    output_alert(&ev);
    CHECK_EQ_INT(output_alert_count(), 1);
    output_close();

    char line[1024] = "";
    FILE *fp = fopen(path, "r");
    CHECK(fp != NULL);
    CHECK(fgets(line, sizeof(line), fp) != NULL);
    fclose(fp);
    unlink(path);

    CHECK(strstr(line, "\"sid\":1001") != NULL);
    CHECK(strstr(line, "\"msg\":\"quote \\\" and \\\\ backslash\"") != NULL);
    CHECK(strstr(line, "\"payload\":\"GET \\\"\\u0000\\u0080\"") != NULL);
    CHECK(strstr(line, "\"src_port\":1234") != NULL);
    CHECK_EQ_INT(line[strlen(line) - 1], '\n');
    output_set_quiet(0);
}

/* B12: the default interface matches the OS loopback name. */
static void test_default_iface(void) {
#ifdef __APPLE__
    CHECK_EQ_STR(DEFAULT_IFACE, "lo0");
#else
    CHECK_EQ_STR(DEFAULT_IFACE, "lo");
#endif
}

const test_case_t output_tests[] = {
    TEST(test_json_escape),
    TEST(test_json_escape_truncation),
    TEST(test_timestamp_is_utc),
    TEST(test_open_failure_reported),
    TEST(test_alert_line_is_json),
    TEST(test_default_iface),
    TEST_END
};
