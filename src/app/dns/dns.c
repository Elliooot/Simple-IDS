#include <string.h>

#include "simpleids/bytes.h"
#include "simpleids/dns.h"

#define DNS_WIRE_NAME_MAX 255  /* RFC 1035 limit on the encoded name   */
#define DNS_MAX_HOPS      16   /* compression pointers followed        */

/*
 * Read the name starting at msg[*pos]. On return *pos is just past the
 * name as it appears at that position (after the first pointer, if any).
 */
static int read_name(const uint8_t *msg, size_t len, size_t *pos, dns_question_t *q) {
    size_t p = *pos, out = 0, wire = 0;
    int hops = 0, jumped = 0;

    q->longest_label = 0;
    for (;;) {
        if (p >= len) return -1;
        uint8_t l = msg[p];

        if ((l & 0xc0) == 0xc0) {                       /* compression pointer */
            if (p + 1 >= len) return -1;
            size_t target = ((size_t)(l & 0x3f) << 8) | msg[p + 1];
            if (!jumped) *pos = p + 2;
            jumped = 1;
            if (++hops > DNS_MAX_HOPS || target >= len) return -1;
            p = target;
            continue;
        }
        if (l & 0xc0) return -1;                        /* reserved label types */

        p++;
        wire += 1u + l;
        if (wire > DNS_WIRE_NAME_MAX) return -1;
        if (l == 0) break;
        if (p + l > len) return -1;

        if (out) q->name[out++] = '.';
        memcpy(q->name + out, msg + p, l);
        out += l;
        if (l > q->longest_label) q->longest_label = l;
        p += l;
    }
    if (!jumped) *pos = p;
    q->name[out] = '\0';
    q->name_len = out;
    return 0;
}

int dns_parse_message(const uint8_t *msg, size_t len, dns_message_t *out) {
    memset(out, 0, sizeof(*out));
    if (!msg || len < DNS_HEADER_LEN) return -1;

    out->id = rd_be16(msg);
    out->response = (msg[2] >> 7) & 1;
    out->opcode = (msg[2] >> 3) & 0x0f;
    out->qdcount = rd_be16(msg + 4);

    size_t pos = DNS_HEADER_LEN;
    for (unsigned i = 0; i < out->qdcount && i < DNS_MAX_QUESTIONS; i++) {
        dns_question_t *q = &out->q[i];
        if (read_name(msg, len, &pos, q) < 0) return -1;
        if (pos + 4 > len) return -1;
        q->qtype = rd_be16(msg + pos);
        q->qclass = rd_be16(msg + pos + 2);
        pos += 4;
        out->nquestions++;
    }
    return 0;
}
