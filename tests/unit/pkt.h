#ifndef SIMPLEIDS_TEST_PKT_H
#define SIMPLEIDS_TEST_PKT_H

/* Helpers that build raw frames and TLS records for unit tests. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ETH_LEN 14
#define IP_LEN  20
#define TCP_LEN 20
#define HDRS_LEN (ETH_LEN + IP_LEN + TCP_LEN)

static inline void put16(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/*
 * Ethernet + IPv4 (src -> 10.0.0.1) + TCP + payload, with a given source
 * address (host order), sequence number and flags. Returns the length.
 */
static inline size_t build_tcp_frame_ex(uint8_t *buf, uint32_t src, uint16_t sport,
                                        uint16_t dport, uint32_t seq, uint8_t flags,
                                        const void *payload, size_t plen) {
    memset(buf, 0, HDRS_LEN);
    /* Ethernet */
    memcpy(buf, "\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02", 12);
    put16(buf + 12, 0x0800);
    /* IPv4 */
    uint8_t *ip = buf + ETH_LEN;
    ip[0] = 0x45;
    put16(ip + 2, (unsigned)(IP_LEN + TCP_LEN + plen));
    put16(ip + 6, 0x4000); /* DF */
    ip[8] = 64;
    ip[9] = 6;
    put32(ip + 12, src);
    memcpy(ip + 16, "\x0a\x00\x00\x01", 4);
    /* TCP */
    uint8_t *tcp = ip + IP_LEN;
    put16(tcp, sport);
    put16(tcp + 2, dport);
    put32(tcp + 4, seq);
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    if (plen) memcpy(buf + HDRS_LEN, payload, plen);
    return HDRS_LEN + plen;
}

/* 10.0.0.2 -> 10.0.0.1, seq 0, PSH|ACK. buf must hold HDRS_LEN + plen. */
static inline size_t build_tcp_frame(uint8_t *buf, uint16_t sport, uint16_t dport,
                                     const void *payload, size_t plen) {
    return build_tcp_frame_ex(buf, 0x0a000002, sport, dport, 0, 0x18, payload, plen);
}

/* Ethernet + IPv4 (src -> 10.0.0.1) + UDP + payload. */
static inline size_t build_udp_frame(uint8_t *buf, uint32_t src, uint16_t sport,
                                     uint16_t dport, const void *payload, size_t plen) {
    memset(buf, 0, ETH_LEN + IP_LEN + 8);
    put16(buf + 12, 0x0800);
    uint8_t *ip = buf + ETH_LEN;
    ip[0] = 0x45;
    put16(ip + 2, (unsigned)(IP_LEN + 8 + plen));
    ip[8] = 64;
    ip[9] = 17;
    put32(ip + 12, src);
    memcpy(ip + 16, "\x0a\x00\x00\x01", 4);
    uint8_t *udp = ip + IP_LEN;
    put16(udp, sport);
    put16(udp + 2, dport);
    put16(udp + 4, (unsigned)(8 + plen));
    if (plen) memcpy(udp + 8, payload, plen);
    return ETH_LEN + IP_LEN + 8 + plen;
}

#define IP6_LEN 40

/* Ethernet + IPv6 (2001:db8::2 -> ::1) + ext headers + an L4 blob. */
static inline size_t build_ipv6_frame(uint8_t *buf, uint8_t next, const void *ext,
                                      size_t elen, const void *l4, size_t l4len) {
    memset(buf, 0, ETH_LEN + IP6_LEN);
    put16(buf + 12, 0x86dd);
    uint8_t *ip = buf + ETH_LEN;
    ip[0] = 0x60;
    put16(ip + 4, (unsigned)(elen + l4len));
    ip[6] = next;
    ip[7] = 64;
    memcpy(ip + 8, "\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x02", 16);
    memcpy(ip + 24, "\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x01", 16);
    if (elen) memcpy(ip + IP6_LEN, ext, elen);
    memcpy(ip + IP6_LEN + elen, l4, l4len);
    return ETH_LEN + IP6_LEN + elen + l4len;
}

/* Append a TLS extension; returns new length. */
static inline size_t tls_put_ext(uint8_t *p, size_t n, unsigned type,
                                 const void *data, size_t dlen) {
    put16(p + n, type);
    put16(p + n + 2, (unsigned)dlen);
    memcpy(p + n + 4, data, dlen);
    return n + 4 + dlen;
}

/* server_name extension body for one host name. */
static inline size_t tls_sni_body(uint8_t *p, const char *name) {
    size_t nl = strlen(name);
    put16(p, (unsigned)(nl + 3));
    p[2] = 0;
    put16(p + 3, (unsigned)nl);
    memcpy(p + 5, name, nl);
    return nl + 5;
}

/*
 * Build a ClientHello record carrying the given extensions blob.
 * Returns the record length. out must hold 5 + 4 + 76 + elen bytes.
 */
static inline size_t tls_client_hello(uint8_t *out, const uint8_t *exts, size_t elen) {
    uint8_t *b = out + 9;
    size_t n = 0;
    b[n++] = 3; b[n++] = 3;                         /* version          */
    for (int i = 0; i < 32; i++) b[n++] = (uint8_t)i; /* random         */
    b[n++] = 0;                                     /* session id len   */
    put16(b + n, 2); n += 2;                        /* cipher suites    */
    b[n++] = 0x13; b[n++] = 0x01;
    b[n++] = 1; b[n++] = 0;                         /* compression null */
    put16(b + n, (unsigned)elen); n += 2;
    memcpy(b + n, exts, elen); n += elen;

    out[5] = 1;                                     /* ClientHello      */
    out[6] = (uint8_t)(n >> 16); out[7] = (uint8_t)(n >> 8); out[8] = (uint8_t)n;
    out[0] = 0x16; out[1] = 3; out[2] = 1;
    put16(out + 3, (unsigned)(n + 4));
    return 9 + n;
}

#endif
