#include <arpa/inet.h>
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

/* B6: the IP version must agree with the link layer's type field. */
static void test_decode_rejects_non_ipv4(void) {
    uint8_t frame[256];
    size_t n = build_tcp_frame(frame, 1, 80, REQ, strlen(REQ));
    packet_t p;

    put16(frame + 12, 0x86dd); /* IPv6 ethertype, IPv4 header */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_NOT_IP);

    put16(frame + 12, 0x0806); /* ARP */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_NOT_IP);

    put16(frame + 12, 0x0800);
    frame[ETH_LEN] = 0x65;     /* says IPv4 ethertype, but version 6 */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_NOT_IP);
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
    frame[ETH_LEN + IP_LEN + 12] = 15 << 4; /* 60 bytes, more than the datagram */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_BAD_HEADER);
    frame[ETH_LEN + IP_LEN + 12] = 8 << 4;  /* 32 bytes, more than captured */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, HDRS_LEN + 10, &p), DECODE_TRUNCATED);
    frame[ETH_LEN + IP_LEN + 12] = 5 << 4;

    frame[ETH_LEN + 9] = 1; /* ICMP */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_UNSUPPORTED_L4);
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

    memcpy(buf, "\x63\x00\x00\x00", 4); /* unknown family 99 */
    CHECK_EQ_INT(decode_packet(DLT_NULL, buf, l3 + 4, &p), DECODE_NOT_IP);

    memset(buf, 0, 16);
    put16(buf + 14, 0x0800);
    memcpy(buf + 16, eth + ETH_LEN, l3);
    CHECK_EQ_INT(decode_packet(DLT_LINUX_SLL, buf, l3 + 16, &p), DECODE_OK);
    put16(buf + 14, 0x0806);
    CHECK_EQ_INT(decode_packet(DLT_LINUX_SLL, buf, l3 + 16, &p), DECODE_NOT_IP);

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

/* A minimal TCP header (data offset 5, PSH|ACK) followed by a payload. */
static size_t tcp_seg(uint8_t *out, uint16_t sport, uint16_t dport, const char *payload) {
    size_t plen = strlen(payload);
    memset(out, 0, TCP_LEN);
    put16(out, sport);
    put16(out + 2, dport);
    put32(out + 4, 0x01020304);
    out[12] = 5 << 4;
    out[13] = 0x18;
    memcpy(out + TCP_LEN, payload, plen);
    return TCP_LEN + plen;
}

static void test_decode_ipv6_tcp(void) {
    uint8_t l4[128], frame[256];
    size_t l4len = tcp_seg(l4, 40000, 80, REQ);
    size_t n = build_ipv6_frame(frame, 6, NULL, 0, l4, l4len);
    uint8_t *buf = exact_bytes(frame, n);
    packet_t p;

    CHECK_EQ_INT(decode_packet(DLT_EN10MB, buf, n, &p), DECODE_OK);
    CHECK_EQ_INT(p.ip_version, 6);
    CHECK_EQ_INT(p.l4proto, L4_TCP);
    CHECK_EQ_STR(p.src_ip, "2001:db8::2");
    CHECK_EQ_STR(p.dst_ip, "2001:db8::1");
    CHECK_EQ_INT(p.src_port, 40000);
    CHECK_EQ_INT(p.seq, 0x01020304);
    CHECK_EQ_INT(p.payload_len, strlen(REQ));
    CHECK(p.payload == buf + ETH_LEN + IP6_LEN + TCP_LEN);

    /* Every shorter capture is handled without reading past it. */
    for (size_t cut = 1; cut <= n; cut++) {
        uint8_t *b = exact_bytes(frame, n - cut);
        decode_result_t r = decode_packet(DLT_EN10MB, b, n - cut, &p);
        CHECK(r == DECODE_OK || r == DECODE_TRUNCATED);
        if (r == DECODE_OK) CHECK(p.truncated == (cut <= strlen(REQ)));
        free(b);
    }
    free(buf);

    put16(frame + ETH_LEN + 4, 0);    /* jumbogram payload length */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_BAD_HEADER);
}

/* Hop-by-hop, routing and destination options are skipped. */
static void test_decode_ipv6_ext_headers(void) {
    uint8_t l4[128], frame[300], ext[24];
    size_t l4len = tcp_seg(l4, 40000, 80, REQ);
    packet_t p;

    memset(ext, 0, sizeof(ext));
    ext[0] = 43; ext[1] = 0;          /* hop-by-hop (8 bytes) -> routing */
    ext[8] = 60; ext[9] = 0;          /* routing (8 bytes) -> dest opts  */
    ext[16] = 6; ext[17] = 0;         /* dest opts (8 bytes) -> TCP      */
    size_t n = build_ipv6_frame(frame, 0, ext, 24, l4, l4len);
    uint8_t *buf = exact_bytes(frame, n);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, buf, n, &p), DECODE_OK);
    CHECK_EQ_INT(p.dst_port, 80);
    CHECK_EQ_INT(p.payload_len, strlen(REQ));
    free(buf);

    /* An extension header longer than the payload length is malformed. */
    ext[17] = 200;
    n = build_ipv6_frame(frame, 0, ext, 24, l4, l4len);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_BAD_HEADER);

    /* A chain longer than we walk is given up on. */
    uint8_t many[80];
    memset(many, 0, sizeof(many));
    for (int i = 0; i < 10; i++) many[i * 8] = 60;
    n = build_ipv6_frame(frame, 60, many, sizeof(many), l4, l4len);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_UNSUPPORTED_L4);

    /* ICMPv6 is not a transport we inspect. */
    n = build_ipv6_frame(frame, 58, NULL, 0, l4, l4len);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_UNSUPPORTED_L4);
}

static void test_decode_ipv6_fragment(void) {
    uint8_t l4[128], frame[300], frag[8];
    size_t l4len = tcp_seg(l4, 40000, 80, REQ);
    packet_t p;

    memset(frag, 0, sizeof(frag));
    frag[0] = 6;
    put16(frag + 2, 0x0001);          /* offset 0, more fragments */
    size_t n = build_ipv6_frame(frame, 44, frag, 8, l4, l4len);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_OK);
    CHECK_EQ_INT(p.dst_port, 80);

    put16(frag + 2, (185 << 3));      /* a later fragment: no L4 header */
    n = build_ipv6_frame(frame, 44, frag, 8, l4, l4len);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n, &p), DECODE_FRAGMENT);
}

/* 802.1Q and QinQ tags are skipped and recorded; three tags are refused. */
static void test_decode_vlan(void) {
    uint8_t plain[256], frame[300];
    size_t n = build_tcp_frame(plain, 40000, 80, REQ, strlen(REQ));
    packet_t p;

    memcpy(frame, plain, 12);
    put16(frame + 12, 0x8100);
    put16(frame + 14, 0x2064);        /* PCP 1, VID 100 */
    memcpy(frame + 16, plain + 12, n - 12);
    uint8_t *buf = exact_bytes(frame, n + 4);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, buf, n + 4, &p), DECODE_OK);
    CHECK_EQ_INT(p.vlan_count, 1);
    CHECK_EQ_INT(p.vlan[0], 100);
    CHECK_EQ_INT(p.payload_len, strlen(REQ));
    free(buf);

    memcpy(frame, plain, 12);
    put16(frame + 12, 0x88a8);
    put16(frame + 14, 10);
    put16(frame + 16, 0x8100);
    put16(frame + 18, 20);
    memcpy(frame + 20, plain + 12, n - 12);
    buf = exact_bytes(frame, n + 8);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, buf, n + 8, &p), DECODE_OK);
    CHECK_EQ_INT(p.vlan_count, 2);
    CHECK_EQ_INT(p.vlan[0], 10);
    CHECK_EQ_INT(p.vlan[1], 20);
    CHECK_EQ_INT(p.dst_port, 80);
    for (size_t len = 0; len < 34 + 8; len++) {  /* cut inside the tags/IP */
        uint8_t *b = exact_bytes(frame, len);
        CHECK_EQ_INT(decode_packet(DLT_EN10MB, b, len, &p), DECODE_TRUNCATED);
        free(b);
    }
    free(buf);

    memcpy(frame, plain, 12);
    put16(frame + 12, 0x88a8);
    put16(frame + 14, 1);
    put16(frame + 16, 0x8100);
    put16(frame + 18, 2);
    put16(frame + 20, 0x8100);
    put16(frame + 22, 3);
    memcpy(frame + 24, plain + 12, n - 12);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, frame, n + 12, &p), DECODE_UNSUPPORTED_L2);
}

static void test_decode_udp(void) {
    uint8_t plain[256];
    const char *dns = "\x12\x34\x01\x00";
    size_t n = build_tcp_frame(plain, 5353, 53, dns, 4);
    /* Turn the 20-byte TCP header into UDP (8 bytes) + 12 bytes of data. */
    plain[ETH_LEN + 9] = L4_UDP;
    uint8_t *udp = plain + ETH_LEN + IP_LEN;
    put16(udp + 4, 8 + 16);
    put16(udp + 6, 0);
    memset(udp + 8, 'A', 12);
    packet_t p;

    uint8_t *buf = exact_bytes(plain, n);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, buf, n, &p), DECODE_OK);
    CHECK_EQ_INT(p.l4proto, L4_UDP);
    CHECK_EQ_INT(p.src_port, 5353);
    CHECK_EQ_INT(p.dst_port, 53);
    CHECK_EQ_INT(p.payload_len, 16);
    CHECK(p.payload == buf + ETH_LEN + IP_LEN + 8);
    CHECK_EQ_INT(p.tcp_flags, 0);
    free(buf);

    /* Snaplen cut: fewer captured bytes than the UDP length says. */
    buf = exact_bytes(plain, n - 3);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, buf, n - 3, &p), DECODE_OK);
    CHECK_EQ_INT(p.payload_len, 13);
    CHECK_EQ_INT(p.wire_payload_len, 16);
    CHECK_EQ_INT(p.truncated, 1);
    free(buf);

    /* A UDP length shorter than the datagram limits the payload. */
    put16(udp + 4, 8 + 5);
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, plain, n, &p), DECODE_OK);
    CHECK_EQ_INT(p.payload_len, 5);
    CHECK_EQ_INT(p.truncated, 0);

    put16(udp + 4, 7);                /* shorter than the header */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, plain, n, &p), DECODE_BAD_HEADER);
    put16(udp + 4, 8 + 17);           /* longer than the IP datagram */
    CHECK_EQ_INT(decode_packet(DLT_EN10MB, plain, n, &p), DECODE_BAD_HEADER);
}

/* BSD loopback uses several values for AF_INET6. */
static void test_decode_null_ipv6_families(void) {
    uint8_t l4[128], frame[256], buf[300];
    size_t l4len = tcp_seg(l4, 40000, 80, REQ);
    size_t n = build_ipv6_frame(frame, 6, NULL, 0, l4, l4len);
    size_t l3 = n - ETH_LEN;
    static const uint8_t fams[] = { 10, 24, 28, 30 };
    packet_t p;

    for (size_t i = 0; i < sizeof(fams); i++) {
        memset(buf, 0, 4);
        buf[0] = fams[i];
        memcpy(buf + 4, frame + ETH_LEN, l3);
        CHECK_EQ_INT(decode_packet(DLT_NULL, buf, l3 + 4, &p), DECODE_OK);
        CHECK_EQ_INT(p.ip_version, 6);
    }
    CHECK_EQ_INT(decode_packet(DLT_RAW, frame + ETH_LEN, l3, &p), DECODE_OK);
    CHECK_EQ_INT(p.ip_version, 6);
}

/* decode_addr_str: the hand-written dotted quad matches inet_ntop. */
static void test_decode_addr_str(void) {
    static const uint8_t cases[][4] = {
        {0, 0, 0, 0}, {255, 255, 255, 255}, {9, 10, 99, 100}, {101, 110, 199, 200}, {1, 2, 3, 4},
    };
    char got[IP_STR_LEN], want[IP_STR_LEN];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint8_t addr[16] = {0};
        memcpy(addr, cases[i], 4);
        decode_addr_str(4, addr, got, sizeof(got));
        inet_ntop(AF_INET, addr, want, sizeof(want));
        CHECK_EQ_STR(got, want);
    }
    uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 1};
    decode_addr_str(6, v6, got, sizeof(got));
    CHECK_EQ_STR(got, "2001:db8::1");
    char tiny[4] = "xyz";
    decode_addr_str(4, v6, tiny, sizeof(tiny));   /* too small: empty, no overflow */
    CHECK_EQ_STR(tiny, "");
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
    TEST(test_decode_ipv6_tcp),
    TEST(test_decode_ipv6_ext_headers),
    TEST(test_decode_ipv6_fragment),
    TEST(test_decode_vlan),
    TEST(test_decode_udp),
    TEST(test_decode_null_ipv6_families),
    TEST(test_decode_addr_str),
    TEST_END
};
