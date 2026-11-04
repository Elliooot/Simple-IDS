#include "pkt.h"
#include "simpleids/dns.h"
#include "test.h"

/* A query message for one dotted name. Returns the length. */
static size_t dns_query(uint8_t *out, const char *name, uint16_t qtype) {
    memset(out, 0, DNS_HEADER_LEN);
    put16(out, 0x1234);
    out[2] = 0x01;                /* RD */
    put16(out + 4, 1);            /* QDCOUNT */
    size_t n = DNS_HEADER_LEN;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        out[n++] = (uint8_t)l;
        memcpy(out + n, p, l);
        n += l;
        p += l + (dot ? 1 : 0);
    }
    out[n++] = 0;
    put16(out + n, qtype);
    put16(out + n + 2, 1);
    return n + 4;
}

static void test_dns_query(void) {
    uint8_t msg[300];
    size_t n = dns_query(msg, "www.Example.com", 1);
    uint8_t *buf = exact_bytes(msg, n);
    dns_message_t m;
    CHECK_EQ_INT(dns_parse_message(buf, n, &m), 0);
    CHECK_EQ_INT(m.id, 0x1234);
    CHECK_EQ_INT(m.response, 0);
    CHECK_EQ_INT(m.nquestions, 1);
    CHECK_EQ_STR(m.q[0].name, "www.Example.com");
    CHECK_EQ_INT(m.q[0].name_len, 15);
    CHECK_EQ_INT(m.q[0].longest_label, 7);
    CHECK_EQ_INT(m.q[0].qtype, 1);

    /* Every shorter message is rejected without reading past it. */
    for (size_t len = 0; len < n; len++) {
        uint8_t *p = exact_bytes(msg, len);
        CHECK_EQ_INT(dns_parse_message(p, len, &m), -1);
        free(p);
    }
    free(buf);

    n = dns_query(msg, "", 2);    /* the root */
    CHECK_EQ_INT(dns_parse_message(msg, n, &m), 0);
    CHECK_EQ_STR(m.q[0].name, "");
}

static void test_dns_compression(void) {
    uint8_t msg[64];
    size_t n = dns_query(msg, "evil.com", 1);
    /* Second question: "www" + pointer to "evil.com" at offset 12. */
    put16(msg + 4, 2);
    memcpy(msg + n, "\x03www\xc0\x0c\x00\x10\x00\x01", 10);
    n += 10;
    dns_message_t m;
    CHECK_EQ_INT(dns_parse_message(msg, n, &m), 0);
    CHECK_EQ_INT(m.nquestions, 2);
    CHECK_EQ_STR(m.q[1].name, "www.evil.com");
    CHECK_EQ_INT(m.q[1].qtype, 16);

    /* A pointer to itself must not loop forever. */
    uint8_t loop[] = { 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1 };
    CHECK_EQ_INT(dns_parse_message(loop, sizeof(loop), &m), -1);
    /* A pointer past the end. */
    uint8_t far[] = { 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 200, 0, 1, 0, 1 };
    CHECK_EQ_INT(dns_parse_message(far, sizeof(far), &m), -1);
    /* Reserved label type 0x40. */
    uint8_t ext[] = { 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x41, 'a', 0, 0, 1, 0, 1 };
    CHECK_EQ_INT(dns_parse_message(ext, sizeof(ext), &m), -1);
}

static void test_dns_limits(void) {
    uint8_t msg[600];
    char name[400];
    /* 4 labels of 63 = 4*64 + 1 = 257 wire bytes: over 255. */
    memset(name, 'a', sizeof(name));
    for (int i = 63; i < 4 * 64; i += 64) name[i] = '.';
    name[4 * 64 - 1] = '\0';
    size_t n = dns_query(msg, name, 1);
    dns_message_t m;
    CHECK_EQ_INT(dns_parse_message(msg, n, &m), -1);

    /* 3 labels of 63 + one of 61 = 255 wire bytes: the maximum. */
    name[3 * 64 + 61] = '\0';
    n = dns_query(msg, name, 1);
    CHECK_EQ_INT(dns_parse_message(msg, n, &m), 0);
    CHECK_EQ_INT(m.q[0].name_len, 253);
    CHECK_EQ_INT(m.q[0].longest_label, 63);

    /* Responses are parsed too (the engine skips them). */
    n = dns_query(msg, "a.b", 1);
    msg[2] |= 0x80;
    CHECK_EQ_INT(dns_parse_message(msg, n, &m), 0);
    CHECK_EQ_INT(m.response, 1);

    /* QDCOUNT larger than what is present. */
    put16(msg + 4, 3);
    CHECK_EQ_INT(dns_parse_message(msg, n, &m), -1);
    CHECK_EQ_INT(dns_parse_message(NULL, 0, &m), -1);
}

const test_case_t dns_tests[] = {
    TEST(test_dns_query),
    TEST(test_dns_compression),
    TEST(test_dns_limits),
    TEST_END
};
