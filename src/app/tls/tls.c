#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simpleids/bytes.h"
#include "simpleids/digest.h"
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
 *     post-quantum key shares). We parse what we have; the engine reassembles
 *     the stream and calls this again.
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

/* ------------------------------------------------------------------ */
/* Full ClientHello: ALPN, ECH, JA3, JA4                               */
/* ------------------------------------------------------------------ */

#define TLS_EXT_SUPPORTED_GROUPS   0x000a
#define TLS_EXT_EC_POINT_FORMATS   0x000b
#define TLS_EXT_SIG_ALGS           0x000d
#define TLS_EXT_ALPN               0x0010
#define TLS_EXT_SUPPORTED_VERSIONS 0x002b
#define TLS_EXT_ECH                0xfe0d

#define MAX_LIST 256   /* ciphers / extensions / groups we record */

int tls_is_grease(uint16_t v) {
    return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

typedef struct {
    uint16_t v[MAX_LIST];
    size_t   n;
} u16list_t;

static void push(u16list_t *l, uint16_t v) {
    if (!tls_is_grease(v) && l->n < MAX_LIST) l->v[l->n++] = v;
}

/* A bounded string; once something does not fit, `full` is set and
 * further appends are ignored. */
typedef struct {
    char  *p;
    size_t len, cap;
    int    full;
} sbuf_t;

__attribute__((format(printf, 2, 3)))
static void sb_printf(sbuf_t *b, const char *fmt, ...) {
    if (b->full) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= b->cap - b->len) {
        b->full = 1;
        b->p[b->len] = '\0';
        return;
    }
    b->len += (size_t)n;
}

static void sb_list(sbuf_t *b, const u16list_t *l, const char *sep, int hex) {
    for (size_t i = 0; i < l->n; i++) {
        if (i) sb_printf(b, "%s", sep);
        if (hex) sb_printf(b, "%04x", l->v[i]);
        else     sb_printf(b, "%u", l->v[i]);
    }
}

static int cmp_u16(const void *a, const void *b) {
    return (int)*(const uint16_t *)a - (int)*(const uint16_t *)b;
}

/* First 12 hex digits of SHA-256(text), or zeros when text is empty. */
static void ja4_hash12(const char *text, size_t len, char out[13]) {
    if (len == 0) {
        memcpy(out, "000000000000", 13);
        return;
    }
    uint8_t d[SHA256_LEN];
    char hex[2 * SHA256_LEN + 1];
    sha256(text, len, d);
    digest_hex(d, SHA256_LEN, hex);
    memcpy(out, hex, 12);
    out[12] = '\0';
}

static const char *ja4_version(uint16_t v) {
    switch (v) {
    case 0x0304: return "13";
    case 0x0303: return "12";
    case 0x0302: return "11";
    case 0x0301: return "10";
    case 0x0300: return "s3";
    case 0x0002: return "s2";
    case 0xfeff: return "d1";
    case 0xfefd: return "d2";
    case 0xfefc: return "d3";
    default:     return "00";
    }
}

static int is_alnum(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/*
 * Join the handshake message carried by consecutive handshake records.
 * Returns the message length in *hlen (0 = complete, 1 = need more,
 * -1 = not a handshake / too big).
 */
static int join_handshake(const uint8_t *buf, size_t len, uint8_t *hs, size_t *hlen) {
    size_t pos = 0, n = 0;
    for (;;) {
        if (n >= 4) {
            size_t want = 4 + (((size_t)hs[1] << 16) | ((size_t)hs[2] << 8) | hs[3]);
            if (want > TLS_HELLO_MAX) return -1;
            if (n >= want) {
                *hlen = want;
                return 0;
            }
        }
        if (pos + 5 > len) return 1;
        if (buf[pos] != TLS_RECORD_HANDSHAKE || buf[pos + 1] != 0x03) return -1;
        size_t rl = rd_be16(buf + pos + 3);
        if (rl == 0 || rl > 16384 + 2048) return -1;
        /* Reject early: no need to wait for a record that is not a hello. */
        if (n == 0 && pos + 5 < len && buf[pos + 5] != TLS_HS_CLIENT_HELLO) return -1;
        if (pos + 5 + rl > len) return 1;
        if (n + rl > TLS_HELLO_MAX) return -1;
        memcpy(hs + n, buf + pos + 5, rl);
        n += rl;
        pos += 5 + rl;
        if (hs[0] != TLS_HS_CLIENT_HELLO) return -1;
    }
}

int tls_parse_client_hello(const uint8_t *buf, size_t len, tls_hello_t *out) {
    static uint8_t hs[TLS_HELLO_MAX];
    size_t hlen;

    memset(out, 0, sizeof(*out));
    if (!buf) return -1;
    int r = join_handshake(buf, len, hs, &hlen);
    if (r != 0) return r;

    const uint8_t *b = hs + 4;
    size_t end = hlen - 4, pos = 0;
    u16list_t ciphers = { .n = 0 }, exts = { .n = 0 }, groups = { .n = 0 };
    u16list_t formats = { .n = 0 }, sigs = { .n = 0 };
    uint16_t best_version = 0;
    const uint8_t *alpn1 = NULL;
    size_t alpn1_len = 0;

    if (pos + 34 > end) return -1;
    out->version = rd_be16(b);
    pos += 34;

    if (pos + 1 > end) return -1;
    pos += 1 + b[pos];                                   /* session id */

    if (pos + 2 > end) return -1;
    size_t cs_len = rd_be16(b + pos);
    pos += 2;
    if (cs_len % 2 || pos + cs_len > end) return -1;
    for (size_t i = 0; i < cs_len; i += 2) push(&ciphers, rd_be16(b + pos + i));
    pos += cs_len;

    if (pos + 1 > end) return -1;
    pos += 1 + b[pos];                                   /* compression */
    if (pos > end) return -1;

    size_t ext_end = pos;
    if (pos + 2 <= end) {                                /* extensions are optional */
        ext_end = pos + 2 + rd_be16(b + pos);
        pos += 2;
        if (ext_end > end) return -1;
    }

    while (pos + 4 <= ext_end) {
        uint16_t type = rd_be16(b + pos);
        size_t el = rd_be16(b + pos + 2);
        pos += 4;
        if (pos + el > ext_end) return -1;
        const uint8_t *e = b + pos;
        push(&exts, type);

        switch (type) {
        case TLS_EXT_SERVER_NAME:
            out->sni_present = 1;
            if (el >= 5 && e[2] == SNI_TYPE_HOST_NAME) {
                size_t nl = rd_be16(e + 3);
                int ok = nl > 0 && nl < TLS_SNI_MAX && 5 + nl <= el;
                for (size_t i = 0; ok && i < nl; i++)
                    if (e[5 + i] < 0x21 || e[5 + i] > 0x7e) ok = 0;
                if (ok) {
                    memcpy(out->sni, e + 5, nl);
                    out->sni[nl] = '\0';
                    out->sni_len = nl;
                }
            }
            break;
        case TLS_EXT_ALPN: {
            if (el < 2 || rd_be16(e) + 2u > el) return -1;
            size_t l_end = 2 + rd_be16(e);
            for (size_t i = 2; i < l_end;) {
                size_t pl = e[i++];
                if (i + pl > l_end) return -1;
                if (!alpn1) { alpn1 = e + i; alpn1_len = pl; }
                if (out->alpn_len && out->alpn_len + 1 < TLS_ALPN_MAX)
                    out->alpn[out->alpn_len++] = ',';
                for (size_t k = 0; k < pl && out->alpn_len + 1 < TLS_ALPN_MAX; k++) {
                    uint8_t c = e[i + k];
                    out->alpn[out->alpn_len++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
                }
                i += pl;
            }
            out->alpn[out->alpn_len] = '\0';
            break;
        }
        case TLS_EXT_SUPPORTED_GROUPS:
        case TLS_EXT_SIG_ALGS: {
            if (el < 2 || rd_be16(e) + 2u > el || rd_be16(e) % 2) return -1;
            u16list_t *l = type == TLS_EXT_SIG_ALGS ? &sigs : &groups;
            for (size_t i = 0; i < rd_be16(e); i += 2) push(l, rd_be16(e + 2 + i));
            break;
        }
        case TLS_EXT_EC_POINT_FORMATS:
            if (el < 1 || e[0] + 1u > el) return -1;
            for (size_t i = 0; i < e[0]; i++) push(&formats, e[1 + i]);
            break;
        case TLS_EXT_SUPPORTED_VERSIONS:
            if (el < 1 || e[0] + 1u > el || e[0] % 2) return -1;
            for (size_t i = 0; i < e[0]; i += 2) {
                uint16_t v = rd_be16(e + 1 + i);
                if (!tls_is_grease(v) && v > best_version) best_version = v;
            }
            break;
        case TLS_EXT_ECH:
            out->ech = 1;
            break;
        default:
            break;
        }
        pos += el;
    }

    /* JA3: version,ciphers,extensions,groups,point formats (decimal). */
    sbuf_t j3 = { out->ja3, 0, sizeof(out->ja3), 0 };
    sb_printf(&j3, "%u,", out->version);
    sb_list(&j3, &ciphers, "-", 0);
    sb_printf(&j3, ",");
    sb_list(&j3, &exts, "-", 0);
    sb_printf(&j3, ",");
    sb_list(&j3, &groups, "-", 0);
    sb_printf(&j3, ",");
    sb_list(&j3, &formats, "-", 0);
    out->ja3_len = j3.len;
    uint8_t d[MD5_LEN];
    md5(out->ja3, out->ja3_len, d);
    digest_hex(d, MD5_LEN, out->ja3_hash);

    /* JA4_a: t + version + d/i + #ciphers + #extensions + ALPN chars. */
    char alpn_chars[3] = "00";
    if (alpn1 && alpn1_len > 0) {
        uint8_t f = alpn1[0], l = alpn1[alpn1_len - 1];
        if (is_alnum(f) && is_alnum(l)) {
            alpn_chars[0] = (char)f;
            alpn_chars[1] = (char)l;
        } else {
            static const char HEX[] = "0123456789abcdef";
            alpn_chars[0] = HEX[f >> 4];
            alpn_chars[1] = HEX[l & 15];
        }
    }
    size_t nc = ciphers.n > 99 ? 99 : ciphers.n, ne = exts.n > 99 ? 99 : exts.n;
    char ja4a[16];
    snprintf(ja4a, sizeof(ja4a), "t%s%c%02zu%02zu%s",
             ja4_version(best_version ? best_version : out->version),
             out->sni_present ? 'd' : 'i', nc, ne, alpn_chars);

    /* JA4_b: sorted cipher suites. JA4_c: sorted extensions without SNI
     * and ALPN, then "_" and the signature algorithms in order. */
    static char text[8192];
    sbuf_t t = { text, 0, sizeof(text), 0 };
    u16list_t sorted = ciphers;
    qsort(sorted.v, sorted.n, sizeof(uint16_t), cmp_u16);
    sb_list(&t, &sorted, ",", 1);
    char ja4b[13], ja4c[13];
    ja4_hash12(text, t.len, ja4b);

    sorted.n = 0;
    for (size_t i = 0; i < exts.n; i++)
        if (exts.v[i] != TLS_EXT_SERVER_NAME && exts.v[i] != TLS_EXT_ALPN)
            sorted.v[sorted.n++] = exts.v[i];
    qsort(sorted.v, sorted.n, sizeof(uint16_t), cmp_u16);
    t.len = 0;
    t.full = 0;
    text[0] = '\0';
    sb_list(&t, &sorted, ",", 1);
    if (sorted.n && sigs.n) {
        sb_printf(&t, "_");
        sb_list(&t, &sigs, ",", 1);
    }
    ja4_hash12(text, sorted.n ? t.len : 0, ja4c);

    snprintf(out->ja4, sizeof(out->ja4), "%.10s_%.12s_%.12s", ja4a, ja4b, ja4c);
    return 0;
}
