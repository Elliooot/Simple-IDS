#ifndef SIMPLEIDS_BYTES_H
#define SIMPLEIDS_BYTES_H

#include <stddef.h>
#include <stdint.h>

/*
 * Length-bounded byte helpers.
 *
 * Packet data is never NUL-terminated, so every function here takes an
 * explicit length and never reads past it.
 */

/* Read big-endian integers from a byte pointer (no alignment required). */
static inline uint16_t rd_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static inline uint32_t rd_le32(const uint8_t *p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8)  |  (uint32_t)p[0];
}

/* ASCII lower-case for a single byte; safe for any value 0-255. */
static inline uint8_t byte_lower(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + ('a' - 'A')) : c;
}

/*
 * Find needle[0..nlen) inside hay[0..hlen).
 * nocase != 0 compares ASCII letters case-insensitively.
 * Returns a pointer to the first match, or NULL.
 * An empty needle never matches (rules must have real content).
 */
const uint8_t *bytes_find(const uint8_t *hay, size_t hlen,
                          const uint8_t *needle, size_t nlen, int nocase);

/* Does buf[0..len) start with the NUL-terminated literal lit? */
int bytes_startswith(const uint8_t *buf, size_t len, const char *lit);

/* Same, ASCII case-insensitive. */
int bytes_startswith_nocase(const uint8_t *buf, size_t len, const char *lit);

#endif
