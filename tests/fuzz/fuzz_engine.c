/*
 * Fuzz target: the whole pipeline (decode, flow table, TCP reassembly,
 * HTTP/TLS/DNS parsing on partial data, detection, anomaly checks).
 *
 * Input format, so that a crash file replays exactly:
 *   byte 0          link type selector (Ethernet, raw IP, Linux SLL, ...)
 *   then repeated   2-byte big-endian frame length, frame bytes
 * Frames are 1 ms apart. Every input starts from a fresh engine (small
 * flow table and memcap) and is shut down at the end, so the open flows
 * are inspected one last time and nothing carries over to the next input.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <pcap.h>

#include "fuzz.h"
#include "simpleids/anomaly.h"
#include "simpleids/engine.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"
#include "simpleids/threshold.h"

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

/* A few rules of every kind, so each phase has prefilter and pcre work. */
static const char RULES[] =
    "var HTTP_SERVERS any\n"
    "alert http any any -> any any (msg:\"uri\"; http.uri; content:\"/admin\"; nocase; sid:1;)\n"
    "alert http any any -> any any (msg:\"union\"; http.uri; content:\"union\"; nocase; "
        "pcre:\"/union(?:\\s|\\/\\*.*?\\*\\/)+select/i\"; sid:2;)\n"
    "alert http any any -> any any (msg:\"hdr\"; http.header; content:\"evil\"; "
        "http.user_agent; content:\"curl\"; distance:0; sid:3;)\n"
    "alert http any any -> any any (msg:\"body\"; http.request_body; content:\"passwd\"; "
        "threshold:type limit, track by_src, count 1, seconds 60; sid:4;)\n"
    "alert http any any -> any any (msg:\"login\"; http.method; content:\"POST\"; "
        "http.uri; content:\"/login\"; detection_filter:track by_src, count 2, seconds 60; sid:5;)\n"
    "alert tls any any -> any any (msg:\"sni\"; tls.sni; content:\"evil\"; sid:6;)\n"
    "alert tls any any -> any any (msg:\"ja3\"; ja3.hash; content:\"e7d705a3286e19ea42f587b344ee6865\"; sid:7;)\n"
    "alert dns any any -> any any (msg:\"dns\"; dns.query; content:\"evil\"; endswith; sid:8;)\n"
    "alert tcp any any -> any 21 (msg:\"ftp\"; content:\"SITE EXEC\"; nocase; sid:9;)\n"
    "alert tcp any any -> any any (msg:\"raw\"; content:\"|de ad be ef|\"; "
        "pcre:\"/\\xde\\xad\\xbe\\xef.{0,8}\\x00/R\"; sid:10;)\n"
    "alert udp any any -> any any (msg:\"udp\"; content:\"ping\"; offset:2; depth:8; sid:11;)\n"
    "pass http any any -> any any (msg:\"pass\"; http.host; content:\"trusted.example\"; sid:12;)\n";

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    output_set_quiet(1);
    FILE *fp = fmemopen((void *)RULES, sizeof(RULES) - 1, "r");
    ruleset_t *rs = ruleset_new();
    int errors = 0;
    if (!fp || !rs || ruleset_load_stream(rs, fp, "fuzz_engine", &errors) <= 0 || errors ||
        ruleset_compile(rs) < 0) {
        fprintf(stderr, "fuzz_engine: the built-in rules do not load\n");
        __builtin_trap();
    }
    fclose(fp);
    rules_set_active(rs);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const int types[] = { DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL, DLT_NULL };
    if (size < 1) return 0;
    int linktype = types[data[0] % (sizeof(types) / sizeof(types[0]))];

    engine_config_t cfg;
    engine_config_defaults(&cfg);
    cfg.flow.max_flows = 16;            /* eviction is reachable */
    cfg.stream.depth = 16384;
    cfg.stream.memcap = 64 * 1024;      /* so is the memcap      */
    if (engine_init(&cfg) < 0) return 0;

    struct timeval ts = { 1700000000, 0 };
    size_t off = 1;
    while (off + 2 <= size) {
        size_t len = (size_t)data[off] << 8 | data[off + 1];
        off += 2;
        if (len > size - off) len = size - off;
        /* Its own exact-size buffer: ASan sees a read past the frame. */
        uint8_t *frame = malloc(len ? len : 1);
        if (!frame) break;
        memcpy(frame, data + off, len);
        engine_process_frame(linktype, &ts, frame, len);
        free(frame);
        off += len;
        ts.tv_usec += 1000;
        if (ts.tv_usec >= 1000000) { ts.tv_sec++; ts.tv_usec -= 1000000; }
    }

    engine_shutdown();
    threshold_free();
    anomaly_reset();
    return 0;
}
