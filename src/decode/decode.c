#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>

#include "simpleids/bytes.h"
#include "simpleids/decode.h"

#define ETHERTYPE_IPV4   0x0800
#define ETHERTYPE_IPV6   0x86dd
#define ETHERTYPE_8021Q  0x8100
#define ETHERTYPE_8021AD 0x88a8
#define ETHERTYPE_QINQ   0x9100 /* pre-standard QinQ */

#define ETH_HDR_LEN   14
#define VLAN_TAG_LEN  4
#define SLL_HDR_LEN   16
#define NULL_HDR_LEN  4

#define IPV4_MIN_HDR  20
#define IPV6_HDR      40
#define TCP_MIN_HDR   20
#define UDP_HDR       8
#define IPV6_MAX_EXT  8  /* extension headers we are willing to walk */

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

static const char *result_names[DECODE_RESULT_COUNT] = {
    [DECODE_OK]             = "ok",
    [DECODE_TRUNCATED]      = "truncated",
    [DECODE_UNSUPPORTED_L2] = "unsupported link layer",
    [DECODE_NOT_IP]         = "not IP",
    [DECODE_BAD_HEADER]     = "bad header",
    [DECODE_FRAGMENT]       = "IP fragment",
    [DECODE_UNSUPPORTED_L4] = "not TCP/UDP",
};

const char *decode_result_str(decode_result_t r) {
    if ((unsigned)r >= DECODE_RESULT_COUNT) return "?";
    return result_names[r];
}

/* Network-layer type found by the link layer: 4, 6, or 0 = look at the
 * version nibble (raw IP). */
static int family_to_version(uint32_t af) {
    switch (af) {
    case 2:  return 4;  /* AF_INET everywhere                         */
    case 10:            /* AF_INET6 Linux                             */
    case 24:            /* AF_INET6 NetBSD / OpenBSD                  */
    case 28:            /* AF_INET6 FreeBSD / DragonFly               */
    case 30: return 6;  /* AF_INET6 macOS                             */
    default: return -1;
    }
}

static int ethertype_to_version(uint16_t type) {
    if (type == ETHERTYPE_IPV4) return 4;
    if (type == ETHERTYPE_IPV6) return 6;
    return -1;
}

static int is_vlan_type(uint16_t type) {
    return type == ETHERTYPE_8021Q || type == ETHERTYPE_8021AD || type == ETHERTYPE_QINQ;
}

static decode_result_t link_layer(int linktype, const uint8_t *data, size_t caplen,
                                  packet_t *out, size_t *l3_off, int *version) {
    switch (linktype) {
    case DLT_EN10MB: {
        size_t off = 12;
        if (caplen < ETH_HDR_LEN) return DECODE_TRUNCATED;
        uint16_t type = rd_be16(data + off);
        while (is_vlan_type(type)) {
            if (out->vlan_count == DECODE_MAX_VLAN) return DECODE_UNSUPPORTED_L2;
            if (caplen < off + 2 + VLAN_TAG_LEN) return DECODE_TRUNCATED;
            out->vlan[out->vlan_count++] = rd_be16(data + off + 2) & 0x0fff;
            off += VLAN_TAG_LEN;
            type = rd_be16(data + off);
        }
        *l3_off = off + 2;
        *version = ethertype_to_version(type);
        return *version < 0 ? DECODE_NOT_IP : DECODE_OK;
    }
    case DLT_NULL: {
        /* 4-byte address family in the *capturing* host's byte order. */
        if (caplen < NULL_HDR_LEN) return DECODE_TRUNCATED;
        int v = family_to_version(rd_le32(data));
        if (v < 0) v = family_to_version(rd_be32(data));
        *l3_off = NULL_HDR_LEN;
        *version = v;
        return v < 0 ? DECODE_NOT_IP : DECODE_OK;
    }
    case DLT_LOOP: {
        if (caplen < NULL_HDR_LEN) return DECODE_TRUNCATED;
        *l3_off = NULL_HDR_LEN;
        *version = family_to_version(rd_be32(data));
        return *version < 0 ? DECODE_NOT_IP : DECODE_OK;
    }
    case DLT_LINUX_SLL: {
        if (caplen < SLL_HDR_LEN) return DECODE_TRUNCATED;
        *l3_off = SLL_HDR_LEN;
        *version = ethertype_to_version(rd_be16(data + 14));
        return *version < 0 ? DECODE_NOT_IP : DECODE_OK;
    }
    case DLT_RAW:
        *l3_off = 0;
        *version = 0;
        return DECODE_OK;
    default:
        return DECODE_UNSUPPORTED_L2;
    }
}

/*
 * The layer-3 decoders find where the L4 header starts and how long the
 * L4 segment is on the wire (from the IP length fields). `avail` is what
 * was captured from the start of the IP header.
 */
typedef struct {
    size_t l4_off;   /* from the start of the IP header */
    size_t l4_wire;  /* L4 header + payload length on the wire */
    uint8_t proto;
} l3_info_t;

/* Dotted quad without sprintf: inet_ntop formats IPv4 with sprintf,
 * which showed up at ~10% of the time per packet. out: >= 16 bytes. */
static void ipv4_str(const uint8_t a[4], char *out) {
    char *p = out;
    for (int i = 0; i < 4; i++) {
        unsigned v = a[i];
        if (v >= 100) { *p++ = (char)('0' + v / 100); v %= 100; *p++ = (char)('0' + v / 10); }
        else if (v >= 10) *p++ = (char)('0' + v / 10);
        *p++ = (char)('0' + v % 10);
        if (i < 3) *p++ = '.';
    }
    *p = '\0';
}

void decode_addr_str(uint8_t ip_version, const uint8_t addr[16], char *out, size_t outlen) {
    if (outlen < IP_STR_LEN) {
        if (outlen) out[0] = '\0';
        return;
    }
    if (ip_version == 4) ipv4_str(addr, out);
    else inet_ntop(AF_INET6, addr, out, (socklen_t)outlen);
}

static decode_result_t decode_ipv4(const uint8_t *ip, size_t avail, packet_t *out,
                                   l3_info_t *l3) {
    if (avail < IPV4_MIN_HDR) return DECODE_TRUNCATED;
    if ((ip[0] >> 4) != 4) return DECODE_NOT_IP;

    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    size_t total = rd_be16(ip + 2);
    if (ihl < IPV4_MIN_HDR || total < ihl) return DECODE_BAD_HEADER;
    if (ihl > avail) return DECODE_TRUNCATED;

    if ((rd_be16(ip + 6) & 0x1fff) != 0) return DECODE_FRAGMENT;

    out->ip_version = 4;
    memcpy(out->src_addr, ip + 12, 4);
    memcpy(out->dst_addr, ip + 16, 4);
    ipv4_str(ip + 12, out->src_ip);
    ipv4_str(ip + 16, out->dst_ip);

    l3->l4_off = ihl;
    l3->l4_wire = total - ihl;
    l3->proto = ip[9];
    return DECODE_OK;
}

static decode_result_t decode_ipv6(const uint8_t *ip, size_t avail, packet_t *out,
                                   l3_info_t *l3) {
    if (avail < IPV6_HDR) return DECODE_TRUNCATED;
    if ((ip[0] >> 4) != 6) return DECODE_NOT_IP;

    size_t plen = rd_be16(ip + 4);
    if (plen == 0) return DECODE_BAD_HEADER; /* jumbograms not supported */
    size_t total = IPV6_HDR + plen;

    out->ip_version = 6;
    memcpy(out->src_addr, ip + 8, 16);
    memcpy(out->dst_addr, ip + 24, 16);
    inet_ntop(AF_INET6, ip + 8, out->src_ip, sizeof(out->src_ip));
    inet_ntop(AF_INET6, ip + 24, out->dst_ip, sizeof(out->dst_ip));

    /* Walk extension headers until a transport protocol. */
    uint8_t next = ip[6];
    size_t off = IPV6_HDR;
    for (int i = 0; ; i++) {
        size_t hlen;
        switch (next) {
        case 0:   /* hop-by-hop options */
        case 43:  /* routing            */
        case 60:  /* destination opts   */
        case 51:  /* authentication     */
            if (off + 2 > total) return DECODE_BAD_HEADER;
            if (off + 2 > avail) return DECODE_TRUNCATED;
            hlen = next == 51 ? ((size_t)ip[off + 1] + 2) * 4
                              : ((size_t)ip[off + 1] + 1) * 8;
            break;
        case 44:  /* fragment           */
            if (off + 8 > total) return DECODE_BAD_HEADER;
            if (off + 8 > avail) return DECODE_TRUNCATED;
            if ((rd_be16(ip + off + 2) >> 3) != 0) return DECODE_FRAGMENT;
            hlen = 8;
            break;
        default:
            l3->l4_off = off;
            l3->l4_wire = total - off;
            l3->proto = next;
            return DECODE_OK;
        }
        if (i == IPV6_MAX_EXT) return DECODE_UNSUPPORTED_L4;
        if (off + hlen > total) return DECODE_BAD_HEADER;
        next = ip[off];
        off += hlen;
    }
}

decode_result_t decode_packet(int linktype, const uint8_t *data, size_t caplen,
                              packet_t *out) {
    memset(out, 0, sizeof(*out));
    if (!data) return DECODE_TRUNCATED;

    size_t off = 0;
    int version = 0;
    decode_result_t r = link_layer(linktype, data, caplen, out, &off, &version);
    if (r != DECODE_OK) return r;

    const uint8_t *ip = data + off;
    size_t avail = caplen - off;
    if (version == 0) {
        if (avail < 1) return DECODE_TRUNCATED;
        version = ip[0] >> 4;
    }

    l3_info_t l3;
    if (version == 4)      r = decode_ipv4(ip, avail, out, &l3);
    else if (version == 6) r = decode_ipv6(ip, avail, out, &l3);
    else                   r = DECODE_NOT_IP;
    if (r != DECODE_OK) return r;

    /* What we have of the L4 segment. A frame can be longer than the
     * datagram (Ethernet padding) or shorter (snaplen cut it off). */
    if (l3.l4_off > avail) return DECODE_TRUNCATED;
    const uint8_t *l4 = ip + l3.l4_off;
    size_t l4_cap = avail - l3.l4_off;
    if (l4_cap > l3.l4_wire) l4_cap = l3.l4_wire;

    size_t hdr;
    if (l3.proto == L4_TCP) {
        if (l3.l4_wire < TCP_MIN_HDR) return DECODE_BAD_HEADER;
        if (l4_cap < TCP_MIN_HDR) return DECODE_TRUNCATED;
        hdr = (size_t)(l4[12] >> 4) * 4;
        if (hdr < TCP_MIN_HDR || hdr > l3.l4_wire) return DECODE_BAD_HEADER;
        if (hdr > l4_cap) return DECODE_TRUNCATED;
        out->seq = rd_be32(l4 + 4);
        out->ack = rd_be32(l4 + 8);
        out->tcp_flags = l4[13];
        out->wire_payload_len = l3.l4_wire - hdr;
    } else if (l3.proto == L4_UDP) {
        if (l3.l4_wire < UDP_HDR) return DECODE_BAD_HEADER;
        if (l4_cap < UDP_HDR) return DECODE_TRUNCATED;
        size_t ulen = rd_be16(l4 + 4);
        if (ulen < UDP_HDR || ulen > l3.l4_wire) return DECODE_BAD_HEADER;
        hdr = UDP_HDR;
        out->wire_payload_len = ulen - UDP_HDR;
        if (l4_cap > ulen) l4_cap = ulen;
    } else {
        return DECODE_UNSUPPORTED_L4;
    }

    out->l4proto = l3.proto;
    out->src_port = rd_be16(l4);
    out->dst_port = rd_be16(l4 + 2);
    out->payload = l4 + hdr;
    out->payload_len = l4_cap - hdr;
    out->truncated = out->payload_len < out->wire_payload_len;
    return DECODE_OK;
}
