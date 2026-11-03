#ifndef SIMPLEIDS_HTTP_H
#define SIMPLEIDS_HTTP_H

#include <stddef.h>
#include <stdint.h>

/* A view into an HTTP request held in a (non NUL-terminated) buffer. */
typedef struct {
    const uint8_t *method;
    size_t         method_len;
    const uint8_t *uri;
    size_t         uri_len;
    int            has_version; /* request line contained " HTTP/" */
} http_request_t;

/*
 * Parse the request line. Returns 0 when buf starts with a known method
 * (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT, TRACE) followed
 * by a space, -1 otherwise. Extra spaces before the URI are skipped. When
 * the request line is cut off by the end of the buffer, uri covers
 * everything that was captured.
 */
int http_parse_request(const uint8_t *buf, size_t len, http_request_t *out);

/* Could buf[0..len) be the start of a request line? (len may be short.) */
int http_maybe_request(const uint8_t *buf, size_t len);

/*
 * Find header `name` (case-insensitive) in the header block. Stops at the
 * blank line that ends the headers. Leading whitespace is skipped; the
 * value runs until CR/LF or the end of the buffer.
 * Returns 0 and sets *val / *vlen when found, -1 otherwise.
 */
int http_find_header(const uint8_t *buf, size_t len, const char *name,
                     const uint8_t **val, size_t *vlen);

/* ------------------------------------------------------------------ */
/* Normalization                                                       */
/* ------------------------------------------------------------------ */

/* What the normalizer ran into. Each one is also a common IDS evasion. */
#define HTTP_NORM_DOUBLE_ENCODED 0x01 /* %25xx: decoded more than once      */
#define HTTP_NORM_UNICODE        0x02 /* IIS-style %uXXXX                   */
#define HTTP_NORM_OVERLONG_UTF8  0x04 /* e.g. %c0%af for '/'                */
#define HTTP_NORM_TRAVERSAL_ROOT 0x08 /* ".." climbs above the root         */
#define HTTP_NORM_NUL            0x10 /* %00 in the decoded data            */
#define HTTP_NORM_HPP_COMMENT    0x20 /* duplicate parameters whose values
                                         open or close a SQL comment        */
#define HTTP_NORM_TRUNCATED      0x40 /* input longer than the output size  */

#define HTTP_URI_MAX    8192
#define HTTP_HEADER_MAX 16384
#define HTTP_HOST_MAX   256

/*
 * Normalize a request target the way a permissive server would see it:
 *   - absolute form "http://host/p" becomes "/p";
 *   - the path and the query are percent-decoded (%XX, %uXXXX, overlong
 *     UTF-8 folded to ASCII), repeatedly while new escapes appear (double
 *     encoding), and '+' in the query becomes a space;
 *   - in the path, '\' becomes '/', "//" and "/./" collapse and ".."
 *     removes the previous segment.
 * The query is not path-normalized. Writes at most cap bytes, ORs
 * HTTP_NORM_* flags into *flags and returns the output length.
 */
size_t http_normalize_uri(const uint8_t *in, size_t len, uint8_t *out, size_t cap,
                          unsigned *flags);

/* Decode an application/x-www-form-urlencoded body like a query string. */
size_t http_decode_form(const uint8_t *in, size_t len, uint8_t *out, size_t cap,
                        unsigned *flags);

/*
 * Check the raw query string for HTTP parameter pollution: the same
 * parameter given more than once. Returns the number of names that repeat
 * and sets HTTP_NORM_HPP_COMMENT when such a parameter carries "/ *" or
 * "* /" (a payload split across copies that a server joins with ',').
 */
int http_check_params(const uint8_t *query, size_t len, unsigned *flags);

/*
 * Decode a chunked body from in[0..len).
 *   returns  1  the final chunk (and trailers) were seen; *consumed is the
 *               encoded length
 *   returns  0  more data is needed; out holds what was decoded so far
 *   returns -1  malformed
 * At most cap bytes are written; *outlen is the decoded length.
 */
int http_dechunk(const uint8_t *in, size_t len, uint8_t *out, size_t cap,
                 size_t *outlen, size_t *consumed);

/* ------------------------------------------------------------------ */
/* Whole request header block                                          */
/* ------------------------------------------------------------------ */

#define HTTP_CL_NONE    (-1L)  /* no Content-Length header             */
#define HTTP_CL_INVALID (-2L)  /* unparsable or conflicting values     */

typedef struct {
    /* Views into the parsed buffer. */
    const uint8_t *method;        size_t method_len;
    const uint8_t *uri_raw;       size_t uri_raw_len;
    const uint8_t *user_agent;    size_t user_agent_len;   int has_user_agent;
    const uint8_t *cookie;        size_t cookie_len;       int has_cookie;
    const uint8_t *content_type;  size_t content_type_len;
    long           content_length;   /* bytes, or HTTP_CL_*             */
    int            chunked;          /* Transfer-Encoding has "chunked" */
    int            dup_params;       /* names that repeat in the query  */
    unsigned       norm_flags;       /* HTTP_NORM_* for the URI         */

    /* Normalized copies. */
    uint8_t uri[HTTP_URI_MAX];       size_t uri_len;
    uint8_t header[HTTP_HEADER_MAX]; size_t header_len;   /* "Name: value\r\n"... */
    uint8_t host[HTTP_HOST_MAX];     size_t host_len;     /* lower case, no port  */
} http_tx_t;

/*
 * Parse a request header block (request line through the blank line, or
 * whatever part of it was captured). Returns 0, or -1 when it does not
 * start with a request line. http_tx_t is large: keep it static.
 */
int http_parse_tx(const uint8_t *buf, size_t len, http_tx_t *tx);

/* Is the body form-urlencoded (so http_decode_form applies)? */
int http_is_form(const http_tx_t *tx);

#endif
