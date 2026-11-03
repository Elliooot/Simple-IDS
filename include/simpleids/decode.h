#ifndef SIMPLEIDS_DECODE_H
#define SIMPLEIDS_DECODE_H

#include <stddef.h>
#include <stdint.h>

#define IP_STR_LEN      46 /* INET6_ADDRSTRLEN */
#define DECODE_MAX_VLAN 2  /* 802.1Q, plus one outer 802.1ad (QinQ) tag */

#define L4_TCP 6
#define L4_UDP 17

/* TCP flags */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

typedef enum {
    DECODE_OK = 0,
    DECODE_TRUNCATED,       /* captured bytes too short for a header       */
    DECODE_UNSUPPORTED_L2,  /* unknown link type, too many VLAN tags       */
    DECODE_NOT_IP,          /* ARP, LLDP, ... (neither IPv4 nor IPv6)      */
    DECODE_BAD_HEADER,      /* header fields are inconsistent              */
    DECODE_FRAGMENT,        /* non-first IP fragment (no L4 header)        */
    DECODE_UNSUPPORTED_L4,  /* neither TCP nor UDP (ICMP, ESP, ...)        */
    DECODE_RESULT_COUNT
} decode_result_t;

typedef struct {
    uint8_t  ip_version;            /* 4 or 6                             */
    uint8_t  l4proto;               /* L4_TCP or L4_UDP                   */
    uint8_t  src_addr[16];          /* IPv4 uses the first 4 bytes        */
    uint8_t  dst_addr[16];
    char     src_ip[IP_STR_LEN];
    char     dst_ip[IP_STR_LEN];
    uint16_t src_port;
    uint16_t dst_port;

    uint16_t vlan[DECODE_MAX_VLAN]; /* VLAN ids, outermost first          */
    uint8_t  vlan_count;

    /* TCP only */
    uint8_t  tcp_flags;
    uint32_t seq;
    uint32_t ack;

    /* L4 payload. Points into the captured packet; NOT NUL-terminated. */
    const uint8_t *payload;
    size_t         payload_len;      /* bytes actually captured            */
    size_t         wire_payload_len; /* bytes on the wire (IP length)      */

    /* 1 when snaplen cut the packet, so payload_len < wire_payload_len. */
    int truncated;
} packet_t;

/*
 * Decode one captured frame.
 *   linktype: value of pcap_datalink()
 *   data/caplen: the captured bytes (pcap_pkthdr.caplen, never .len)
 * Every header is bounds-checked against caplen and read byte-wise, so
 * the buffer may have any alignment.
 */
decode_result_t decode_packet(int linktype, const uint8_t *data, size_t caplen,
                              packet_t *out);

const char *decode_result_str(decode_result_t r);

#endif
