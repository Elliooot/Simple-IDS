#ifndef SIMPLEIDS_ENGINE_H
#define SIMPLEIDS_ENGINE_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#include "simpleids/decode.h"
#include "simpleids/flow.h"
#include "simpleids/stream.h"

typedef struct {
    flow_config_t   flow;
    stream_config_t stream;
} engine_config_t;

typedef struct {
    unsigned long packets;
    unsigned long long bytes;         /* captured bytes (caplen)       */
    unsigned long decode[DECODE_RESULT_COUNT]; /* indexed by decode_result_t */
    unsigned long ipv6;
    unsigned long vlan;
    unsigned long tcp;
    unsigned long udp;
    unsigned long truncated_payloads;
    unsigned long http_requests;
    unsigned long http_bodies;        /* request bodies inspected      */
    unsigned long tls_client_hellos;
    unsigned long tls_ech;            /* hellos with encrypted SNI     */
    unsigned long dns_queries;        /* questions inspected           */
    unsigned long signature_alerts;
    unsigned long anomaly_alerts;
    unsigned long duplicate_alerts;   /* same sid again in one flow */
    unsigned long thresholded;        /* suppressed by threshold /
                                         detection_filter          */
    unsigned long passed_flows;       /* a pass rule matched       */
} engine_stats_t;

void engine_config_defaults(engine_config_t *cfg);

/* Set up the flow table and reassembly. Returns 0 or -1. */
int  engine_init(const engine_config_t *cfg);

/* End all flows (inspecting what is still buffered) and free them. */
void engine_shutdown(void);

/* Decode and inspect one captured frame. */
void engine_process_frame(int linktype, const struct timeval *ts,
                          const uint8_t *data, size_t caplen);

/* Inspect an already-decoded packet. */
void engine_process_packet(const struct timeval *ts, const packet_t *pkt);

/* verbose != 0 prints a line for every clean HTTP request, TLS hello
 * and DNS query. */
void engine_set_verbose(int verbose);

const engine_stats_t *engine_stats(void);
void engine_print_stats(FILE *fp);

/* Zero the counters (tests). */
void engine_reset_stats(void);

/* ------------------------------------------------------------------ */
/* Statistics events and latency                                      */
/* ------------------------------------------------------------------ */

/* Time every engine_process_frame() call (two monotonic clock reads per
 * packet). Off by default. */
void engine_set_latency(int on);

typedef struct {
    unsigned long count;
    double        avg_ns;
    uint64_t      p50_ns, p90_ns, p99_ns, p999_ns, max_ns;  /* p*: within 1/8 */
} engine_latency_t;

void engine_latency(engine_latency_t *out);

/* Capture counters from pcap_stats() (live capture only). */
typedef struct {
    int           valid;
    unsigned long received;   /* ps_recv: packets the kernel saw    */
    unsigned long dropped;    /* ps_drop: no room in the buffer     */
    unsigned long ifdropped;  /* ps_ifdrop: dropped by the interface */
} capture_counts_t;

/*
 * Format one EVE-style stats event (a JSON object, no newline) into buf:
 * packets and Mbit/s over the last `interval` seconds, drop rate, flows,
 * reassembly memory, peak RSS, parser and detection counters, and the
 * latency percentiles when measured. ts is the event time, uptime the
 * seconds since start. Returns the length (truncated to cap - 1).
 */
size_t engine_stats_json(char *buf, size_t cap, const struct timeval *ts, double uptime,
                         double interval, const capture_counts_t *cc);

/* Peak resident set size of the process in bytes (0 if unknown). */
uint64_t engine_peak_rss(void);

#endif
