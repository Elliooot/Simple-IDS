#ifndef SIMPLEIDS_DNS_H
#define SIMPLEIDS_DNS_H

#include <stddef.h>
#include <stdint.h>

#define DNS_HEADER_LEN    12
#define DNS_NAME_MAX      256  /* dotted text, at most 253 chars + NUL  */
#define DNS_MAX_QUESTIONS 4    /* questions parsed per message           */

typedef struct {
    char     name[DNS_NAME_MAX]; /* dotted, bytes as sent ("" = root)   */
    size_t   name_len;
    size_t   longest_label;
    uint16_t qtype;
    uint16_t qclass;
} dns_question_t;

typedef struct {
    uint16_t id;
    int      response;                 /* QR bit                         */
    int      opcode;
    uint16_t qdcount;                  /* as declared                    */
    int      nquestions;               /* parsed (<= DNS_MAX_QUESTIONS)  */
    dns_question_t q[DNS_MAX_QUESTIONS];
} dns_message_t;

/*
 * Parse the header and question section of a DNS message (the UDP
 * payload, or one message from a TCP stream without its length prefix).
 * Compression pointers are followed with a hop limit, so a pointer loop
 * cannot hang the parser. Returns 0, or -1 when the message is truncated
 * or malformed (label too long, name over 255 bytes, bad pointer).
 */
int dns_parse_message(const uint8_t *msg, size_t len, dns_message_t *out);

#endif
