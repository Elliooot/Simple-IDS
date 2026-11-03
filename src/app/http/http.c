#include <string.h>

#include "simpleids/bytes.h"
#include "simpleids/http.h"

static const char *const METHODS[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", NULL
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
    const uint8_t *uri = buf + mlen + 1;
    size_t rest = line - (mlen + 1);

    const uint8_t *ver = bytes_find(uri, rest, (const uint8_t *)" HTTP/", 6, 0);
    out->uri = uri;
    out->uri_len = ver ? (size_t)(ver - uri) : rest;
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
            while (v < ll && (line[v] == ' ' || line[v] == '\t')) v++;
            *val = line + v;
            *vlen = ll - v;
            return 0;
        }
        pos = skip_eol(buf, len, pos + ll);
    }
    return -1;
}
