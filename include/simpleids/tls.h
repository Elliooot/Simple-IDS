#ifndef SIMPLEIDS_TLS_H
#define SIMPLEIDS_TLS_H

#include <stddef.h>
#include <stdint.h>

#define TLS_SNI_MAX 256

/*
 * Extract the server_name (SNI) host name from a TLS ClientHello record.
 * Writes a NUL-terminated name into out (outlen bytes) and returns its
 * length, or returns -1 when the buffer is not a ClientHello, is
 * malformed or truncated, has no SNI, or the name contains bytes that
 * are not printable ASCII.
 */
int tls_extract_sni(const uint8_t *buf, size_t len, char *out, size_t outlen);

#endif
