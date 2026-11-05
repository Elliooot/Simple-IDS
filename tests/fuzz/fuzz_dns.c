/* Fuzz target: DNS header and question parsing (compression pointers). */
#include <string.h>

#include "fuzz.h"
#include "simpleids/dns.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    dns_message_t m;
    if (dns_parse_message(data, size, &m) == 0) {
        if (m.nquestions < 0 || m.nquestions > DNS_MAX_QUESTIONS) __builtin_trap();
        for (int i = 0; i < m.nquestions; i++)
            if (m.q[i].name_len >= DNS_NAME_MAX || m.q[i].name[m.q[i].name_len] != '\0')
                __builtin_trap();
    }
    return 0;
}
