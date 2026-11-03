#ifndef SIMPLEIDS_SIPHASH_H
#define SIMPLEIDS_SIPHASH_H

#include <stddef.h>
#include <stdint.h>

/*
 * SipHash-2-4 (Aumasson & Bernstein, 2012): a keyed hash designed for
 * hash tables that see attacker-controlled keys. Without the 128-bit key
 * an attacker cannot predict which bucket a flow lands in, so they cannot
 * craft packets that all collide into one chain (hash-flooding DoS).
 */
uint64_t siphash24(const uint8_t key[16], const void *data, size_t len);

/* Fill buf with random bytes from the OS. Returns 0, or -1 on failure. */
int random_bytes(void *buf, size_t len);

#endif
