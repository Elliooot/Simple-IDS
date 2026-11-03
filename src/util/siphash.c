#include <fcntl.h>
#include <unistd.h>

#include "simpleids/siphash.h"

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND do {                                                   \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);       \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;                          \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;                          \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);       \
    } while (0)

static uint64_t load_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

uint64_t siphash24(const uint8_t key[16], const void *data, size_t len) {
    const uint8_t *in = data;
    uint64_t k0 = load_le64(key), k1 = load_le64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    size_t full = len - (len % 8);

    for (size_t i = 0; i < full; i += 8) {
        uint64_t m = load_le64(in + i);
        v3 ^= m;
        SIPROUND; SIPROUND;
        v0 ^= m;
    }

    uint64_t b = (uint64_t)len << 56;
    for (size_t i = 0; i < len % 8; i++) b |= (uint64_t)in[full + i] << (8 * i);

    v3 ^= b;
    SIPROUND; SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

int random_bytes(void *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) { close(fd); return -1; }
        p += n;
        len -= (size_t)n;
    }
    close(fd);
    return 0;
}
