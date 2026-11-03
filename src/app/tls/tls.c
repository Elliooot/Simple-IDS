#include <string.h>

#include "simpleids/bytes.h"
#include "simpleids/tls.h"

#define TLS_RECORD_HANDSHAKE 0x16
#define TLS_HS_CLIENT_HELLO  0x01
#define TLS_EXT_SERVER_NAME  0x0000
#define SNI_TYPE_HOST_NAME   0x00

/*
 * ClientHello layout (all lengths big-endian):
 *   record:   type(1)=0x16 version(2) length(2)
 *   handshake:type(1)=0x01 length(3)
 *   body:     version(2) random(32) session_id<1> cipher_suites<2>
 *             compression_methods<1> extensions<2>
 *   extension:type(2) length(2) data
 *   server_name data: list_len(2) { name_type(1) name_len(2) name }
 *
 * Two different limits apply:
 *   - a nested length larger than its parent's declared length means the
 *     message is malformed (a server would reject it): return -1;
 *   - a declared length larger than what was captured just means the
 *     ClientHello continues in a later TCP segment (common with large
 *     post-quantum key shares). We parse what we have; reassembly comes
 *     in Phase 2.
 * `end` is always min(declared end of the current structure, len).
 */
int tls_extract_sni(const uint8_t *buf, size_t len, char *out, size_t outlen) {
    if (!buf || !out || outlen == 0) return -1;
    out[0] = '\0';

    if (len < 9) return -1;
    if (buf[0] != TLS_RECORD_HANDSHAKE || buf[1] != 0x03) return -1;
    if (buf[5] != TLS_HS_CLIENT_HELLO) return -1;

    size_t rec_end = 5 + (size_t)rd_be16(buf + 3);
    size_t hs_end = 9 + (((size_t)buf[6] << 16) | ((size_t)buf[7] << 8) | buf[8]);
    if (hs_end > rec_end) return -1;
    size_t end = hs_end < len ? hs_end : len;

    size_t pos = 9 + 2 + 32; /* version + random */

    /* session_id */
    if (pos + 1 > end) return -1;
    pos += 1 + buf[pos];

    /* cipher_suites */
    if (pos + 2 > end) return -1;
    pos += 2 + rd_be16(buf + pos);

    /* compression_methods */
    if (pos + 1 > end) return -1;
    pos += 1 + buf[pos];

    /* extensions */
    if (pos + 2 > end) return -1;
    size_t ext_end = pos + 2 + rd_be16(buf + pos);
    pos += 2;
    if (ext_end > hs_end) return -1;
    if (ext_end < end) end = ext_end;

    while (pos + 4 <= end) {
        uint16_t type = rd_be16(buf + pos);
        size_t elen = rd_be16(buf + pos + 2);
        pos += 4;
        if (pos + elen > ext_end) return -1; /* malformed            */
        if (pos + elen > end) return -1;     /* not captured (yet)   */

        if (type == TLS_EXT_SERVER_NAME) {
            if (elen < 5) return -1;
            const uint8_t *e = buf + pos;
            size_t list_len = rd_be16(e);
            if (list_len + 2 > elen) return -1;
            if (e[2] != SNI_TYPE_HOST_NAME) return -1;
            size_t name_len = rd_be16(e + 3);
            if (name_len == 0 || 5 + name_len > elen) return -1;
            if (name_len >= outlen || name_len >= TLS_SNI_MAX) return -1;

            for (size_t i = 0; i < name_len; i++) {
                uint8_t c = e[5 + i];
                if (c < 0x21 || c > 0x7e) return -1; /* printable ASCII only */
                out[i] = (char)c;
            }
            out[name_len] = '\0';
            return (int)name_len;
        }
        pos += elen;
    }
    return -1;
}
