/* Fuzz target: the L2/L3/L4 decoder, for every supported link type. */
#include <pcap.h>

#include "fuzz.h"
#include "simpleids/decode.h"
#include "simpleids/flow.h"

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const int types[] = { DLT_EN10MB, DLT_NULL, DLT_LOOP, DLT_LINUX_SLL, DLT_RAW, 147 };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        packet_t pkt;
        if (decode_packet(types[i], data, size, &pkt) != DECODE_OK) continue;
        /* The payload view must lie inside the captured bytes. */
        if (pkt.payload_len && (pkt.payload < data || pkt.payload + pkt.payload_len > data + size))
            __builtin_trap();
        (void)flow_hash_packet(&pkt);
    }
    return 0;
}
