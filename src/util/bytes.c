#include <string.h>

#include "simpleids/bytes.h"

const uint8_t *bytes_find(const uint8_t *hay, size_t hlen,
                          const uint8_t *needle, size_t nlen, int nocase) {
    if (!hay || !needle || nlen == 0 || nlen > hlen) return NULL;

    size_t last = hlen - nlen;
    if (!nocase) {
        for (size_t i = 0; i <= last; i++) {
            if (hay[i] == needle[0] && memcmp(hay + i, needle, nlen) == 0)
                return hay + i;
        }
        return NULL;
    }

    uint8_t first = byte_lower(needle[0]);
    for (size_t i = 0; i <= last; i++) {
        if (byte_lower(hay[i]) != first) continue;
        size_t j = 1;
        while (j < nlen && byte_lower(hay[i + j]) == byte_lower(needle[j])) j++;
        if (j == nlen) return hay + i;
    }
    return NULL;
}

int bytes_startswith(const uint8_t *buf, size_t len, const char *lit) {
    size_t n = strlen(lit);
    return n <= len && memcmp(buf, lit, n) == 0;
}

int bytes_startswith_nocase(const uint8_t *buf, size_t len, const char *lit) {
    size_t n = strlen(lit);
    if (n > len) return 0;
    for (size_t i = 0; i < n; i++) {
        if (byte_lower(buf[i]) != byte_lower((uint8_t)lit[i])) return 0;
    }
    return 1;
}
