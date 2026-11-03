#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>

#include "simpleids/bytes.h"
#include "simpleids/decode.h"

#define ETHERTYPE_IPV4 0x0800
#define ETH_HDR_LEN    14
#define SLL_HDR_LEN    16
#define NULL_HDR_LEN   4
#define BSD_AF_INET    2   /* AF_INET is 2 on every BSD, macOS and Linux */

#define IPV4_MIN_HDR   20
#define TCP_MIN_HDR    20

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

static const char *result_names[DECODE_RESULT_COUNT] = {
    [DECODE_OK]             = "ok",
    [DECODE_TRUNCATED]      = "truncated",
    [DECODE_UNSUPPORTED_L2] = "unsupported link layer",
    [DECODE_NOT_IPV4]       = "not IPv4",
    [DECODE_BAD_HEADER]     = "bad header",
    [DECODE_FRAGMENT]       = "IP fragment",
    [DECODE_NOT_TCP]        = "not TCP",
};

const char *decode_result_str(decode_result_t r) {
    if ((unsigned)r >= DECODE_RESULT_COUNT) return "?";
    return result_names[r];
}

/*
 * Work out where the IPv4 header starts for this link type.
 * Returns DECODE_OK and sets *l3_off, or the reason it cannot.
 */
static decode_result_t link_layer(int linktype, const uint8_t *data,
                                  size_t caplen, size_t *l3_off) {
    switch (linktype) {
    case DLT_EN10MB: {
        if (caplen < ETH_HDR_LEN) return DECODE_TRUNCATED;
        uint16_t type = rd_be16(data + 12);
        if (type != ETHERTYPE_IPV4) return DECODE_NOT_IPV4;
        *l3_off = ETH_HDR_LEN;
        return DECODE_OK;
    }
    case DLT_NULL: {
        /* 4-byte address family in the *capturing* host's byte order. */
        if (caplen < NULL_HDR_LEN) return DECODE_TRUNCATED;
        uint32_t le = rd_le32(data), be = rd_be32(data);
        if (le != BSD_AF_INET && be != BSD_AF_INET) return DECODE_NOT_IPV4;
        *l3_off = NULL_HDR_LEN;
        return DECODE_OK;
    }
    case DLT_LOOP: {
        /* Like DLT_NULL, but always network byte order. */
        if (caplen < NULL_HDR_LEN) return DECODE_TRUNCATED;
        if (rd_be32(data) != BSD_AF_INET) return DECODE_NOT_IPV4;
        *l3_off = NULL_HDR_LEN;
        return DECODE_OK;
    }
    case DLT_LINUX_SLL: {
        if (caplen < SLL_HDR_LEN) return DECODE_TRUNCATED;
        if (rd_be16(data + 14) != ETHERTYPE_IPV4) return DECODE_NOT_IPV4;
        *l3_off = SLL_HDR_LEN;
        return DECODE_OK;
    }
    case DLT_RAW:
        *l3_off = 0;
        return DECODE_OK;
    default:
        return DECODE_UNSUPPORTED_L2;
    }
}

decode_result_t decode_packet(int linktype, const uint8_t *data, size_t caplen,
                              packet_t *out) {
    memset(out, 0, sizeof(*out));
    if (!data) return DECODE_TRUNCATED;

    size_t off = 0;
    decode_result_t r = link_layer(linktype, data, caplen, &off);
    if (r != DECODE_OK) return r;

    /* ---- IPv4 ---- */
    const uint8_t *ip = data + off;
    size_t ip_avail = caplen - off;
    if (ip_avail < 1) return DECODE_TRUNCATED;
    if ((ip[0] >> 4) != 4) return DECODE_NOT_IPV4;
    if (ip_avail < IPV4_MIN_HDR) return DECODE_TRUNCATED;

    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    size_t total = rd_be16(ip + 2);
    if (ihl < IPV4_MIN_HDR || total < ihl) return DECODE_BAD_HEADER;
    if (ihl > ip_avail) return DECODE_TRUNCATED;

    /* Bytes of this datagram we actually have. A frame can be longer than
     * the datagram (Ethernet padding) or shorter (snaplen cut it off). */
    size_t ip_len = total;
    if (ip_len > ip_avail) {
        ip_len = ip_avail;
        out->truncated = 1;
    }

    uint16_t frag = rd_be16(ip + 6);
    if ((frag & 0x1fff) != 0) return DECODE_FRAGMENT;
    if (ip[9] != 6 /* TCP */) return DECODE_NOT_TCP;

    inet_ntop(AF_INET, ip + 12, out->src_ip, sizeof(out->src_ip));
    inet_ntop(AF_INET, ip + 16, out->dst_ip, sizeof(out->dst_ip));

    /* ---- TCP ---- */
    const uint8_t *tcp = ip + ihl;
    size_t tcp_avail = ip_len - ihl;
    if (tcp_avail < TCP_MIN_HDR) return DECODE_TRUNCATED;

    size_t thl = (size_t)(tcp[12] >> 4) * 4;
    if (thl < TCP_MIN_HDR) return DECODE_BAD_HEADER;
    if (thl > tcp_avail) return DECODE_TRUNCATED;

    out->src_port = rd_be16(tcp);
    out->dst_port = rd_be16(tcp + 2);
    out->payload = tcp + thl;
    out->payload_len = tcp_avail - thl;
    return DECODE_OK;
}
