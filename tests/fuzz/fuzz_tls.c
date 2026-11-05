/* Fuzz target: TLS ClientHello parsing (SNI, ALPN, JA3, JA4, ECH). */
#include <string.h>

#include "fuzz.h"
#include "simpleids/tls.h"

static tls_hello_t hello;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char sni[TLS_SNI_MAX];
    int n = tls_extract_sni(data, size, sni, sizeof(sni));
    if (n >= 0 && ((size_t)n >= sizeof(sni) || strlen(sni) != (size_t)n)) __builtin_trap();
    if (tls_parse_client_hello(data, size, &hello) == 0) {
        if (strlen(hello.sni) != hello.sni_len || strlen(hello.alpn) != hello.alpn_len ||
            strlen(hello.ja3) != hello.ja3_len || strlen(hello.ja4) != TLS_JA4_LEN)
            __builtin_trap();
    }
    return 0;
}
