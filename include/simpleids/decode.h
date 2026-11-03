#ifndef SIMPLEIDS_DECODE_H
#define SIMPLEIDS_DECODE_H

#include <stddef.h>
#include <stdint.h>

#define IP_STR_LEN 46 /* INET6_ADDRSTRLEN, so IPv6 fits once Phase 2 adds it */

typedef enum {
    DECODE_OK = 0,
    DECODE_TRUNCATED,       /* captured bytes too short for a header       */
    DECODE_UNSUPPORTED_L2,  /* unknown link type / ethertype / family      */
    DECODE_NOT_IPV4,        /* IPv6 etc. (IPv6 decoding is Phase 2)        */
    DECODE_BAD_HEADER,      /* header fields are inconsistent              */
    DECODE_FRAGMENT,        /* non-first IP fragment (no TCP header)       */
    DECODE_NOT_TCP,         /* IPv4, but not TCP                           */
    DECODE_RESULT_COUNT
} decode_result_t;

typedef struct {
    char     src_ip[IP_STR_LEN];
    char     dst_ip[IP_STR_LEN];
    uint16_t src_port;
    uint16_t dst_port;

    /* TCP payload. Points into the captured packet; NOT NUL-terminated. */
    const uint8_t *payload;
    size_t         payload_len;

    /* 1 when the IP datagram is longer than what was captured (snaplen),
     * so payload holds only the captured part. */
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
