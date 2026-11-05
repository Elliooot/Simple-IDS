#include <string.h>

#include "simpleids/bytes.h"
#include "simpleids/http.h"

/* RFC 9110 methods plus WebDAV (RFC 4918), which servers such as IIS and
 * Apache mod_dav accept and attackers probe for. */
static const char *const METHODS[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", NULL
};

/* Length of the line starting at p (excluding CR/LF), bounded by len. */
static size_t line_len(const uint8_t *p, size_t len) {
    size_t i = 0;
    while (i < len && p[i] != '\r' && p[i] != '\n') i++;
    return i;
}

/* Skip past the line ending at p[n] (CRLF or LF). */
static size_t skip_eol(const uint8_t *p, size_t len, size_t n) {
    if (n < len && p[n] == '\r') n++;
    if (n < len && p[n] == '\n') n++;
    return n;
}

static int is_ws(uint8_t c) {
    return c == ' ' || c == '\t';
}

int http_maybe_request(const uint8_t *buf, size_t len) {
    for (int i = 0; METHODS[i]; i++) {
        size_t m = strlen(METHODS[i]);
        size_t n = len < m ? len : m;
        if (memcmp(buf, METHODS[i], n) == 0 && (len <= m || buf[m] == ' ')) return 1;
    }
    return 0;
}

int http_parse_request(const uint8_t *buf, size_t len, http_request_t *out) {
    memset(out, 0, sizeof(*out));
    if (!buf) return -1;

    size_t mlen = 0;
    for (int i = 0; METHODS[i]; i++) {
        size_t n = strlen(METHODS[i]);
        if (len > n && memcmp(buf, METHODS[i], n) == 0 && buf[n] == ' ') {
            mlen = n;
            break;
        }
    }
    if (mlen == 0) return -1;

    out->method = buf;
    out->method_len = mlen;

    size_t line = line_len(buf, len);
    size_t u = mlen + 1;
    while (u < line && is_ws(buf[u])) u++;      /* "GET   /x" */
    const uint8_t *uri = buf + u;
    size_t rest = line - u;

    const uint8_t *ver = bytes_find(uri, rest, (const uint8_t *)" HTTP/", 6, 0);
    size_t ulen = ver ? (size_t)(ver - uri) : rest;
    while (ulen > 0 && is_ws(uri[ulen - 1])) ulen--;
    out->uri = uri;
    out->uri_len = ulen;
    out->has_version = ver != NULL;
    return 0;
}

int http_find_header(const uint8_t *buf, size_t len, const char *name,
                     const uint8_t **val, size_t *vlen) {
    size_t nlen = strlen(name);

    /* Skip the request line. */
    size_t pos = skip_eol(buf, len, line_len(buf, len));

    while (pos < len) {
        const uint8_t *line = buf + pos;
        size_t ll = line_len(line, len - pos);
        if (ll == 0) break; /* blank line: end of headers */

        if (ll > nlen && line[nlen] == ':' &&
            bytes_startswith_nocase(line, ll, name)) {
            size_t v = nlen + 1;
            while (v < ll && is_ws(line[v])) v++;
            *val = line + v;
            *vlen = ll - v;
            return 0;
        }
        pos = skip_eol(buf, len, pos + ll);
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Percent-decoding                                                    */
/* ------------------------------------------------------------------ */

static int hex_val(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Value of the escape at in[i] ('%'), with its length in *n, or -1. */
static long escape_at(const uint8_t *in, size_t len, size_t i, size_t *n) {
    if (in[i] != '%') return -1;
    if (i + 2 < len) {
        int hi = hex_val(in[i + 1]), lo = hex_val(in[i + 2]);
        if (hi >= 0 && lo >= 0) {
            *n = 3;
            return hi << 4 | lo;
        }
    }
    if (i + 5 < len && (in[i + 1] == 'u' || in[i + 1] == 'U')) {
        long cp = 0;
        for (size_t k = 2; k < 6; k++) {
            int v = hex_val(in[i + k]);
            if (v < 0) return -1;
            cp = cp << 4 | v;
        }
        *n = 6;
        return 0x10000 | cp; /* marks %u */
    }
    return -1;
}

static int has_escape(const uint8_t *p, size_t len) {
    size_t n;
    for (size_t i = 0; i < len; i++)
        if (p[i] == '%' && escape_at(p, len, i, &n) >= 0) return 1;
    return 0;
}

/*
 * One decoding pass. %uXXXX: ASCII stays ASCII, full-width forms
 * (U+FF01..U+FF5E, which IIS maps to ASCII) become ASCII, anything else
 * is written as UTF-8. Never longer than the input.
 */
static size_t decode_pass(const uint8_t *in, size_t len, uint8_t *out, int plus,
                          unsigned *flags) {
    size_t o = 0;
    for (size_t i = 0; i < len;) {
        size_t n;
        long v = escape_at(in, len, i, &n);
        if (v < 0) {
            out[o++] = (plus && in[i] == '+') ? ' ' : in[i];
            i++;
            continue;
        }
        i += n;
        if (!(v & 0x10000)) {
            out[o++] = (uint8_t)v;
            continue;
        }
        long cp = v & 0xffff;
        *flags |= HTTP_NORM_UNICODE;
        if (cp >= 0xff01 && cp <= 0xff5e) cp -= 0xfee0;
        if (cp < 0x80) {
            out[o++] = (uint8_t)cp;
        } else if (cp < 0x800) {
            out[o++] = (uint8_t)(0xc0 | (cp >> 6));
            out[o++] = (uint8_t)(0x80 | (cp & 0x3f));
        } else {
            out[o++] = (uint8_t)(0xe0 | (cp >> 12));
            out[o++] = (uint8_t)(0x80 | ((cp >> 6) & 0x3f));
            out[o++] = (uint8_t)(0x80 | (cp & 0x3f));
        }
    }
    return o;
}

/* Fold overlong UTF-8 encodings of ASCII (C0 AF = '/') in place. */
static size_t fold_overlong(uint8_t *p, size_t len, unsigned *flags) {
    size_t o = 0;
    for (size_t i = 0; i < len;) {
        uint8_t c = p[i];
        if ((c == 0xc0 || c == 0xc1) && i + 1 < len && (p[i + 1] & 0xc0) == 0x80) {
            p[o++] = (uint8_t)(((c & 1) << 6) | (p[i + 1] & 0x3f));
            i += 2;
            *flags |= HTTP_NORM_OVERLONG_UTF8;
        } else if (c == 0xe0 && i + 2 < len && p[i + 1] >= 0x80 && p[i + 1] <= 0x81 &&
                   (p[i + 2] & 0xc0) == 0x80) {
            p[o++] = (uint8_t)(((p[i + 1] & 1) << 6) | (p[i + 2] & 0x3f));
            i += 3;
            *flags |= HTTP_NORM_OVERLONG_UTF8;
        } else {
            p[o++] = c;
            i++;
        }
    }
    return o;
}

#define MAX_DECODE_PASSES 3

/* Decode in[0..len) into out (at least len bytes). Returns the length. */
static size_t url_decode(const uint8_t *in, size_t len, uint8_t *out, int plus,
                         unsigned *flags) {
    uint8_t *tmp = out;
    size_t n = decode_pass(in, len, tmp, plus, flags);
    n = fold_overlong(tmp, n, flags);
    for (int pass = 1; pass < MAX_DECODE_PASSES && has_escape(tmp, n); pass++) {
        *flags |= HTTP_NORM_DOUBLE_ENCODED;
        n = decode_pass(tmp, n, tmp, 0, flags); /* in place: output never longer */
        n = fold_overlong(tmp, n, flags);
    }
    if (memchr(tmp, 0, n)) *flags |= HTTP_NORM_NUL;
    return n;
}

/* ------------------------------------------------------------------ */
/* Path normalization                                                  */
/* ------------------------------------------------------------------ */

/* Collapse "//", "/./" and "seg/.."; '\' counts as '/'. */
static size_t normalize_path(uint8_t *p, size_t len, unsigned *flags) {
    for (size_t i = 0; i < len; i++)
        if (p[i] == '\\') p[i] = '/';

    int absolute = len > 0 && p[0] == '/';
    size_t o = 0;           /* output written over the input, behind i */
    size_t i = 0;
    int trailing = 0;

    while (i < len) {
        while (i < len && p[i] == '/') i++;
        size_t s = i;
        while (i < len && p[i] != '/') i++;
        size_t sl = i - s;
        trailing = i < len || sl == 0;   /* ended with '/' */

        if (sl == 0) continue;
        if (sl == 1 && p[s] == '.') { trailing = 1; continue; }
        if (sl == 2 && p[s] == '.' && p[s + 1] == '.') {
            trailing = 1;
            if (o == 0) {
                *flags |= HTTP_NORM_TRAVERSAL_ROOT;
                continue;
            }
            /* Drop the last output segment (and its leading '/'). */
            while (o > 0 && p[o - 1] != '/') o--;
            if (o > 0) o--;
            continue;
        }
        if (o > 0 || absolute) p[o++] = '/';
        memmove(p + o, p + s, sl);
        o += sl;
    }
    if (trailing || (absolute && o == 0)) {
        if (o == 0 || p[o - 1] != '/') p[o++] = '/';
    }
    return o;
}

/* Bytes of an absolute-form prefix "http://authority" to skip. */
static size_t absolute_form_skip(const uint8_t *in, size_t len) {
    size_t s;
    if (bytes_startswith_nocase(in, len, "http://")) s = 7;
    else if (bytes_startswith_nocase(in, len, "https://")) s = 8;
    else return 0;
    while (s < len && in[s] != '/' && in[s] != '?') s++;
    return s;
}

size_t http_normalize_uri(const uint8_t *in, size_t len, uint8_t *out, size_t cap,
                          unsigned *flags) {
    static uint8_t path[HTTP_URI_MAX + 1], query[HTTP_URI_MAX];

    size_t skip = absolute_form_skip(in, len);
    in += skip;
    len -= skip;
    if (len > HTTP_URI_MAX) {
        len = HTTP_URI_MAX;
        *flags |= HTTP_NORM_TRUNCATED;
    }

    const uint8_t *q = memchr(in, '?', len);
    size_t plen = q ? (size_t)(q - in) : len;

    size_t pn = url_decode(in, plen, path, 0, flags);
    if (skip && (pn == 0 || path[0] != '/')) {  /* "http://host" or "http://host?q" */
        memmove(path + 1, path, pn);
        path[0] = '/';
        pn++;
    }
    pn = normalize_path(path, pn, flags);

    size_t o = pn < cap ? pn : cap;
    memcpy(out, path, o);
    if (q) {
        size_t qn = url_decode(q + 1, len - plen - 1, query, 1, flags);
        if (o < cap) out[o++] = '?';
        size_t room = cap - o;
        size_t c = qn < room ? qn : room;
        memcpy(out + o, query, c);
        o += c;
        if (c < qn) *flags |= HTTP_NORM_TRUNCATED;
    }
    if (pn > cap) *flags |= HTTP_NORM_TRUNCATED;
    return o;
}

size_t http_decode_form(const uint8_t *in, size_t len, uint8_t *out, size_t cap,
                        unsigned *flags) {
    static uint8_t tmp[65536];
    if (len > sizeof(tmp)) {
        len = sizeof(tmp);
        *flags |= HTTP_NORM_TRUNCATED;
    }
    size_t n = url_decode(in, len, tmp, 1, flags);
    if (n > cap) {
        n = cap;
        *flags |= HTTP_NORM_TRUNCATED;
    }
    memcpy(out, tmp, n);
    return n;
}

/* ------------------------------------------------------------------ */
/* Parameter pollution                                                 */
/* ------------------------------------------------------------------ */

#define HPP_MAX_PARAMS 64
#define HPP_NAME_MAX   64
#define HPP_VALUE_MAX  1024

int http_check_params(const uint8_t *query, size_t len, unsigned *flags) {
    struct { uint8_t name[HPP_NAME_MAX]; size_t len; int count, comment; } p[HPP_MAX_PARAMS];
    int np = 0;
    unsigned dummy = 0;

    for (size_t i = 0; i < len;) {
        size_t s = i;
        while (i < len && query[i] != '&') i++;
        const uint8_t *param = query + s;
        size_t plen = i - s;
        i++;
        if (plen == 0) continue;

        const uint8_t *eq = memchr(param, '=', plen);
        size_t nraw = eq ? (size_t)(eq - param) : plen;
        uint8_t name[HPP_NAME_MAX * 3], value[HPP_VALUE_MAX];
        if (nraw > sizeof(name)) nraw = sizeof(name);
        size_t nl = url_decode(param, nraw, name, 1, &dummy);
        if (nl > HPP_NAME_MAX) nl = HPP_NAME_MAX;
        size_t vraw = eq ? plen - nraw - 1 : 0;
        if (vraw > sizeof(value)) vraw = sizeof(value);
        size_t vl = eq ? url_decode(eq + 1, vraw, value, 1, &dummy) : 0;
        int comment = bytes_find(value, vl, (const uint8_t *)"/*", 2, 0) ||
                      bytes_find(value, vl, (const uint8_t *)"*/", 2, 0);

        int k;
        for (k = 0; k < np; k++)
            if (p[k].len == nl && memcmp(p[k].name, name, nl) == 0) break;
        if (k == np) {
            if (np == HPP_MAX_PARAMS) continue;
            memcpy(p[np].name, name, nl);
            p[np].len = nl;
            p[np].count = 0;
            p[np].comment = 0;
            np++;
        }
        p[k].count++;
        p[k].comment |= comment;
    }

    int dups = 0;
    for (int k = 0; k < np; k++) {
        if (p[k].count < 2) continue;
        dups++;
        if (p[k].comment) *flags |= HTTP_NORM_HPP_COMMENT;
    }
    return dups;
}

/* ------------------------------------------------------------------ */
/* Chunked transfer coding                                             */
/* ------------------------------------------------------------------ */

#define CHUNK_SIZE_MAX 0x7fffffffUL

/*
 * End of the line that starts at in[pos]: the offset just past CRLF (or
 * a bare LF / CR) in *next, and the line length in *ll. Returns 0 when
 * the line is not complete yet: no terminator, or a CR that may still
 * be followed by LF.
 */
static int full_line(const uint8_t *in, size_t len, size_t pos, size_t *ll, size_t *next) {
    size_t n = line_len(in + pos, len - pos);
    size_t e = pos + n;
    if (e >= len) return 0;
    if (in[e] == '\r') {
        if (e + 1 >= len) return 0;
        e += in[e + 1] == '\n' ? 2 : 1;
    } else {
        e++;
    }
    *ll = n;
    *next = e;
    return 1;
}

int http_dechunk(const uint8_t *in, size_t len, uint8_t *out, size_t cap,
                 size_t *outlen, size_t *consumed) {
    size_t pos = 0, o = 0, ll, next;
    *outlen = 0;
    *consumed = 0;

    for (;;) {
        /* chunk-size [; ext] CRLF */
        if (!full_line(in, len, pos, &ll, &next)) return 0;
        unsigned long size = 0;
        size_t k = 0;
        while (k < ll && hex_val(in[pos + k]) >= 0) {
            if (size > CHUNK_SIZE_MAX / 16) return -1;
            size = size * 16 + (unsigned long)hex_val(in[pos + k]);
            k++;
        }
        if (k == 0) return -1;
        while (k < ll && is_ws(in[pos + k])) k++;
        if (k < ll && in[pos + k] != ';') return -1;
        pos = next;

        if (size == 0) {
            /* trailer fields, then an empty line */
            for (;;) {
                if (!full_line(in, len, pos, &ll, &next)) return 0;
                pos = next;
                if (ll == 0) {
                    *consumed = pos;
                    return 1;
                }
            }
        }

        size_t avail = len - pos;
        size_t take = size < avail ? size : avail;
        size_t room = cap - o;
        size_t c = take < room ? take : room;
        memcpy(out + o, in + pos, c);
        o += c;
        *outlen = o;
        if (take < size) return 0;                     /* data continues */
        pos += size;
        if (!full_line(in, len, pos, &ll, &next)) return 0;
        if (ll != 0) return -1;                        /* data must end with CRLF */
        pos = next;
    }
}

/* ------------------------------------------------------------------ */
/* Request header block                                                */
/* ------------------------------------------------------------------ */

static void header_append(http_tx_t *tx, const uint8_t *p, size_t n) {
    size_t room = HTTP_HEADER_MAX - tx->header_len;
    if (n > room) n = room;
    memcpy(tx->header + tx->header_len, p, n);
    tx->header_len += n;
}

static int name_is(const uint8_t *name, size_t nl, const char *lit) {
    return strlen(lit) == nl && bytes_startswith_nocase(name, nl, lit);
}

static long parse_content_length(const uint8_t *v, size_t vl) {
    if (vl == 0 || vl > 12) return HTTP_CL_INVALID;
    long n = 0;
    for (size_t i = 0; i < vl; i++) {
        if (v[i] < '0' || v[i] > '9') return HTTP_CL_INVALID;
        n = n * 10 + (v[i] - '0');
    }
    return n;
}

static void set_host(http_tx_t *tx, const uint8_t *v, size_t vl) {
    size_t end = vl;
    if (vl > 0 && v[0] == '[') {                 /* [v6]:port */
        const uint8_t *rb = memchr(v, ']', vl);
        if (rb) end = (size_t)(rb - v) + 1;
    } else {
        const uint8_t *colon = memchr(v, ':', vl);
        if (colon) end = (size_t)(colon - v);
    }
    if (end > HTTP_HOST_MAX) end = HTTP_HOST_MAX;
    for (size_t i = 0; i < end; i++) tx->host[i] = byte_lower(v[i]);
    tx->host_len = end;
}

int http_parse_tx(const uint8_t *buf, size_t len, http_tx_t *tx) {
    http_request_t rl;
    tx->method = NULL;
    tx->method_len = tx->uri_raw_len = tx->user_agent_len = 0;
    tx->cookie_len = tx->content_type_len = 0;
    tx->uri_raw = tx->user_agent = tx->cookie = tx->content_type = NULL;
    tx->has_user_agent = tx->has_cookie = tx->chunked = tx->dup_params = 0;
    tx->content_length = HTTP_CL_NONE;
    tx->norm_flags = 0;
    tx->uri_len = tx->header_len = tx->host_len = 0;

    if (http_parse_request(buf, len, &rl) < 0) return -1;
    tx->method = rl.method;
    tx->method_len = rl.method_len;
    tx->uri_raw = rl.uri;
    tx->uri_raw_len = rl.uri_len;
    tx->uri_len = http_normalize_uri(rl.uri, rl.uri_len, tx->uri, HTTP_URI_MAX,
                                     &tx->norm_flags);
    const uint8_t *q = memchr(rl.uri, '?', rl.uri_len);
    if (q) {
        size_t qoff = (size_t)(q - rl.uri) + 1;
        tx->dup_params = http_check_params(q + 1, rl.uri_len - qoff, &tx->norm_flags);
    }

    size_t pos = skip_eol(buf, len, line_len(buf, len));
    int last_header = 0;    /* a header was written: continuation allowed */
    while (pos < len) {
        const uint8_t *line = buf + pos;
        size_t ll = line_len(line, len - pos);
        if (ll == 0) break;
        pos = skip_eol(buf, len, pos + ll);

        if (is_ws(line[0])) {                      /* obsolete line folding */
            if (!last_header) continue;
            size_t s = 0;
            while (s < ll && is_ws(line[s])) s++;
            if (tx->header_len >= 2) tx->header_len -= 2;   /* reopen the line */
            header_append(tx, (const uint8_t *)" ", 1);
            header_append(tx, line + s, ll - s);
            header_append(tx, (const uint8_t *)"\r\n", 2);
            continue;
        }

        const uint8_t *colon = memchr(line, ':', ll);
        if (!colon) { last_header = 0; continue; }
        size_t nl = (size_t)(colon - line);
        while (nl > 0 && is_ws(line[nl - 1])) nl--;
        size_t vs = (size_t)(colon - line) + 1;
        while (vs < ll && is_ws(line[vs])) vs++;
        size_t ve = ll;
        while (ve > vs && is_ws(line[ve - 1])) ve--;
        const uint8_t *v = line + vs;
        size_t vl = ve - vs;

        header_append(tx, line, nl);
        header_append(tx, (const uint8_t *)": ", 2);
        header_append(tx, v, vl);
        header_append(tx, (const uint8_t *)"\r\n", 2);
        last_header = 1;

        if (name_is(line, nl, "User-Agent") && !tx->has_user_agent) {
            tx->user_agent = v; tx->user_agent_len = vl; tx->has_user_agent = 1;
        } else if (name_is(line, nl, "Cookie") && !tx->has_cookie) {
            tx->cookie = v; tx->cookie_len = vl; tx->has_cookie = 1;
        } else if (name_is(line, nl, "Host") && tx->host_len == 0) {
            set_host(tx, v, vl);
        } else if (name_is(line, nl, "Content-Type") && !tx->content_type) {
            tx->content_type = v; tx->content_type_len = vl;
        } else if (name_is(line, nl, "Content-Length")) {
            long cl = parse_content_length(v, vl);
            if (tx->content_length == HTTP_CL_NONE) tx->content_length = cl;
            else if (tx->content_length != cl) tx->content_length = HTTP_CL_INVALID;
        } else if (name_is(line, nl, "Transfer-Encoding")) {
            if (bytes_find(v, vl, (const uint8_t *)"chunked", 7, 1)) tx->chunked = 1;
        }
    }
    return 0;
}

int http_is_form(const http_tx_t *tx) {
    return tx->content_type &&
           bytes_startswith_nocase(tx->content_type, tx->content_type_len,
                                   "application/x-www-form-urlencoded");
}
