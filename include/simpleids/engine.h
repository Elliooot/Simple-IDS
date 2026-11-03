#ifndef SIMPLEIDS_ENGINE_H
#define SIMPLEIDS_ENGINE_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#include "simpleids/decode.h"

typedef struct {
    unsigned long packets;
    unsigned long decode[DECODE_RESULT_COUNT]; /* indexed by decode_result_t */
    unsigned long truncated_payloads;
    unsigned long http_requests;
    unsigned long tls_client_hellos;
    unsigned long signature_alerts;
    unsigned long anomaly_alerts;
} engine_stats_t;

/* Decode and inspect one captured frame. */
void engine_process_frame(int linktype, const struct timeval *ts,
                          const uint8_t *data, size_t caplen);

/* Inspect an already-decoded packet. */
void engine_process_packet(const struct timeval *ts, const packet_t *pkt);

/* verbose != 0 prints a line for every clean HTTP request / TLS hello. */
void engine_set_verbose(int verbose);

const engine_stats_t *engine_stats(void);
void engine_print_stats(FILE *fp);
void engine_reset(void);

#endif
