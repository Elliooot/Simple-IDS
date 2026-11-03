#ifndef SIMPLEIDS_DIGEST_H
#define SIMPLEIDS_DIGEST_H

#include <stddef.h>
#include <stdint.h>

/*
 * Message digests needed for TLS fingerprints: JA3 is an MD5 hash and
 * JA4 uses truncated SHA-256. They identify client software, not secrets,
 * so MD5's broken collision resistance does not matter here. Small
 * self-contained implementations keep the build free of OpenSSL.
 */

#define MD5_LEN    16
#define SHA256_LEN 32

void md5(const void *data, size_t len, uint8_t out[MD5_LEN]);
void sha256(const void *data, size_t len, uint8_t out[SHA256_LEN]);

/* Lower-case hex of the first n bytes of digest into out (2n+1 bytes). */
void digest_hex(const uint8_t *digest, size_t n, char *out);

#endif
