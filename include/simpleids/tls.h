#ifndef SIMPLEIDS_TLS_H
#define SIMPLEIDS_TLS_H

#include <stddef.h>
#include <stdint.h>

#define TLS_SNI_MAX  256
#define TLS_ALPN_MAX 256
#define TLS_JA3_MAX  4096
#define TLS_JA4_LEN  36     /* t13d1516h2_8daaf6152771_e5627efa2ab1 */

/* The largest ClientHello (handshake message) we reassemble. */
#define TLS_HELLO_MAX 65536

/*
 * Extract the server_name (SNI) host name from a TLS ClientHello record.
 * Writes a NUL-terminated name into out (outlen bytes) and returns its
 * length, or returns -1 when the buffer is not a ClientHello, is
 * malformed or truncated, has no SNI, or the name contains bytes that
 * are not printable ASCII. Works on a partial record, so it is also the
 * fallback when the rest of a ClientHello never arrives.
 */
int tls_extract_sni(const uint8_t *buf, size_t len, char *out, size_t outlen);

typedef struct {
    uint16_t version;                 /* legacy_version field          */
    int      sni_present;             /* server_name extension present  */
    char     sni[TLS_SNI_MAX];        /* "" unless a valid host name    */
    size_t   sni_len;
    char     alpn[TLS_ALPN_MAX];      /* protocols joined by ','        */
    size_t   alpn_len;
    int      ech;                     /* encrypted_client_hello (0xfe0d) */
    char     ja3[TLS_JA3_MAX];        /* JA3 string                     */
    size_t   ja3_len;
    char     ja3_hash[33];            /* MD5 of the JA3 string, hex     */
    char     ja4[TLS_JA4_LEN + 1];    /* JA4 (FoxIO) fingerprint        */
} tls_hello_t;

/*
 * Parse a ClientHello from the start of a client stream. The handshake
 * message may be split over several TLS records (an evasion trick and a
 * side effect of large post-quantum key shares); they are joined first.
 *   returns  0  parsed: every field of *out is set
 *   returns  1  incomplete: more stream data is needed
 *   returns -1  not a ClientHello, malformed, or larger than TLS_HELLO_MAX
 */
int tls_parse_client_hello(const uint8_t *buf, size_t len, tls_hello_t *out);

/* GREASE values (RFC 8701) are ignored by JA3 and JA4. */
int tls_is_grease(uint16_t v);

#endif
