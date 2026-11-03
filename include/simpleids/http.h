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
 * (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH) followed by a space,
 * -1 otherwise. When the request line is cut off by the end of the
 * buffer, uri covers everything that was captured.
 */
int http_parse_request(const uint8_t *buf, size_t len, http_request_t *out);

/*
 * Find header `name` (case-insensitive) in the header block. Stops at the
 * blank line that ends the headers. Leading whitespace is skipped; the
 * value runs until CR/LF or the end of the buffer.
 * Returns 0 and sets *val / *vlen when found, -1 otherwise.
 */
int http_find_header(const uint8_t *buf, size_t len, const char *name,
                     const uint8_t **val, size_t *vlen);

#endif
