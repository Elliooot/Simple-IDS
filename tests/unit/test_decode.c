#include <pcap.h>

#include "pkt.h"
#include "simpleids/decode.h"
#include "test.h"

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

static const char REQ[] = "GET /?x=<script> HTTP/1.1\r\n\r\n";

static void test_decode_ethernet_ipv4_tcp(void) {
    uint8_t frame[256];
    size_t n = build_tcp_frame(frame, 40000, 80, REQ, strlen(REQ));
    uint8_t *buf = exact_bytes(frame, n);
    packet_t p;

    CHECK_EQ_INT(decode_packet(DLT_EN10MB, buf, n, &p), DECODE_OK);
    CHECK_EQ_STR(p.src_ip, "10.0.0.2");
    CHECK_EQ_STR(p.dst_ip, "10.0.0.1");
    CHECK_EQ_INT(p.src_port, 40000);
    CHECK_EQ_INT(p.dst_port, 80);
    CHECK_EQ_INT(p.payload_len, strlen(REQ));
    CHECK(p.payload == buf + HDRS_LEN);
    CHECK_EQ_INT(p.truncated, 0);
    free(buf);
}

/* B2: when caplen < IP total length, only captured bytes are payload. */
static void test_decode_truncated_capture(void) {
    uint8_t frame[256];
    size_t n = build_tcp_frame(frame, 1, 80, REQ, strlen(REQ));
    size_t caplen = HDRS_LEN + 5;
    uint8_t *buf = exact_bytes(frame, caplen);
    packet_t p;

    CHECK_EQ_INT(decode_packet(DLT_EN10MB, buf, caplen, &p), DECODE_OK);
    CHECK_EQ_INT(p.payload_len, 5);
    CHECK_EQ_INT(p.truncated, 1);
    CHECK(n > caplen);
    free(buf);
}

/* Ethernet padding after the IP datagram is not payload. */
static void test_decode_ignores_link_padding(void) {
    uint8_t frame[256];
    size_t n = build_tcp_frame(frame, 1, 80, "GET", 3);
    memset(frame + n, 0x41, 20); /* padding bytes */
    uint8_t *buf = exact_bytes(frame, n + 20);
    packet_t p;

    CHECK_EQ_INT(decode_packet(DLT_EN10MB, buf, n + 20, &p), DECODE_OK);
    CHECK_EQ_INT(p.payload_len, 3);
    free(buf);
}

/* Every possible truncation must be handled without reading past caplen. */
static void test_decode_every_prefix(void) {
    uint8_t frame[256];
    size_t n = build_tcp_frame(frame, 1, 80, REQ, strlen(REQ));
    packet_t p;

    for (size_t len = 0; len <= n; len++) {
        uint8_t *buf = exact_bytes(frame, len);
        decode_result_t r = decode_packet(DLT_EN10MB, buf, len, &p);
        if (len < HDRS_LEN) {
            CHECK_EQ_INT(r, DECODE_TRUNCATED);
        } else {
            CHECK_EQ_INT(r, DECODE_OK);
            CHECK_EQ_INT(p.payload_len, len - HDRS_LEN);
        }
        free(buf);
    }
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, NULL, 0, &p), DECODE_TRUNCATED);
}

/* B6: non-IPv4 traffic is classified, never parsed as IPv4. */
static void test_decode_rejects_non_ipv4(void) {
    uint8_t frame[256];
    size_t n = build_tcp_frame(frame, 1, 80, REQ, strlen(REQ));
    packet_t p;

    put16(frame + 12, 0x86dd); /* IPv6 ethertype */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_NOT_IPV4);

    put16(frame + 12, 0x0806); /* ARP */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_NOT_IPV4);

    put16(frame + 12, 0x0800);
    frame[ETH_LEN] = 0x65;     /* says IPv4 ethertype, but version 6 */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_NOT_IPV4);
}

static void test_decode_bad_headers(void) {
    uint8_t frame[256];
    size_t n = build_tcp_frame(frame, 1, 80, REQ, strlen(REQ));
    packet_t p;

    frame[ETH_LEN] = 0x44; /* IHL 4 (< 5) */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_BAD_HEADER);
    frame[ETH_LEN] = 0x4f;               /* IHL 15 = 60 bytes ...      */
    put16(frame + ETH_LEN + 2, 40);      /* ... but total length is 40 */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_BAD_HEADER);
    frame[ETH_LEN] = 0x45;
    put16(frame + ETH_LEN + 2, (unsigned)(n - ETH_LEN));

    frame[ETH_LEN + IP_LEN + 12] = 4 << 4; /* TCP data offset 4 */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_BAD_HEADER);
    frame[ETH_LEN + IP_LEN + 12] = 15 << 4; /* 60 bytes, more than present */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, HDRS_LEN + 10, &p), DECODE_TRUNCATED);
    frame[ETH_LEN + IP_LEN + 12] = 5 << 4;

    frame[ETH_LEN + 9] = 17; /* UDP */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_NOT_TCP);
    frame[ETH_LEN + 9] = 6;

    put16(frame + ETH_LEN + 6, 0x0010); /* fragment offset 16 */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_FRAGMENT);

    CHECK_EQ_INT(decode_packet(9999, frame, n, &p), DECODE_UNSUPPORTED_L2);
}

/* Loopback (DLT_NULL) in either byte order, DLT_LOOP, SLL and raw IP. */
static void test_decode_other_link_types(void) {
    uint8_t eth[256], buf[300];
    size_t n = build_tcp_frame(eth, 1, 80, REQ, strlen(REQ));
    size_t l3 = n - ETH_LEN;
    packet_t p;

    memcpy(buf, "\x02\x00\x00\x00", 4); /* AF_INET little-endian */
    memcpy(buf + 4, eth + ETH_LEN, l3);
    CHECK_EQ_INT(decode_packet(DLT_NULL, buf, l3 + 4, &p), DECODE_OK);
    CHECK_EQ_INT(p.payload_len, strlen(REQ));

    memcpy(buf, "\x00\x00\x00\x02", 4); /* big-endian capture host */
    CHECK_EQ_INT(decode_packet(DLT_NULL, buf, l3 + 4, &p), DECODE_OK);
    CHECK_EQ_INT(decode_packet(DLT_LOOP, buf, l3 + 4, &p), DECODE_OK);

    memcpy(buf, "\x1e\x00\x00\x00", 4); /* AF_INET6 on macOS (30) */
    CHECK_EQ_INT(decode_packet(DLT_NULL, buf, l3 + 4, &p), DECODE_NOT_IPV4);

    memset(buf, 0, 16);
    put16(buf + 14, 0x0800);
    memcpy(buf + 16, eth + ETH_LEN, l3);
    CHECK_EQ_INT(decode_packet(DLT_LINUX_SLL, buf, l3 + 16, &p), DECODE_OK);
    put16(buf + 14, 0x86dd);
    CHECK_EQ_INT(decode_packet(DLT_LINUX_SLL, buf, l3 + 16, &p), DECODE_NOT_IPV4);

    CHECK_EQ_INT(decode_packet(DLT_RAW, eth + ETH_LEN, l3, &p), DECODE_OK);
    CHECK_EQ_INT(p.dst_port, 80);
}

/* B13: headers are read byte-wise, so any alignment works (UBSan checks). */
static void test_decode_unaligned_buffer(void) {
    uint8_t frame[256];
    size_t n = build_tcp_frame(frame, 1234, 8080, REQ, strlen(REQ));
    uint8_t *raw = malloc(n + 3);
    CHECK(raw != NULL);
    packet_t p;

    for (size_t shift = 0; shift < 3; shift++) {
        memcpy(raw + shift, frame, n);
        CHECK_EQ_INT(decode_packet(DLT_EN10MB, raw + shift, n, &p), DECODE_OK);
        CHECK_EQ_INT(p.src_port, 1234);
        CHECK_EQ_INT(p.dst_port, 8080);
    }
    free(raw);
}

const test_case_t decode_tests[] = {
    TEST(test_decode_ethernet_ipv4_tcp),
    TEST(test_decode_truncated_capture),
    TEST(test_decode_ignores_link_padding),
    TEST(test_decode_every_prefix),
    TEST(test_decode_rejects_non_ipv4),
    TEST(test_decode_bad_headers),
    TEST(test_decode_other_link_types),
    TEST(test_decode_unaligned_buffer),
    TEST_END
};
