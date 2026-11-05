/* Fuzz target: HTTP request parsing, normalization, form and chunked
 * decoding. All of it reads one attacker-controlled buffer. */
#include "fuzz.h"
#include "simpleids/http.h"

static http_tx_t tx;
static uint8_t out[HTTP_URI_MAX];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    http_request_t req;
    const uint8_t *val;
    size_t vlen, outlen, consumed;
    unsigned flags = 0;

    (void)http_maybe_request(data, size);
    (void)http_parse_request(data, size, &req);
    (void)http_find_header(data, size, "Host", &val, &vlen);
    if (http_parse_tx(data, size, &tx) == 0) {
        if (tx.uri_len > sizeof(tx.uri) || tx.header_len > sizeof(tx.header) ||
            tx.host_len > sizeof(tx.host))
            __builtin_trap();
        (void)http_is_form(&tx);
    }
    if (http_normalize_uri(data, size, out, sizeof(out), &flags) > sizeof(out)) __builtin_trap();
    if (http_decode_form(data, size, out, sizeof(out), &flags) > sizeof(out)) __builtin_trap();
    (void)http_check_params(data, size, &flags);
    if (http_dechunk(data, size, out, sizeof(out), &outlen, &consumed) >= 0 &&
        outlen > sizeof(out))
        __builtin_trap();
    return 0;
}
