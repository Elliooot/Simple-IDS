#ifndef SIMPLEIDS_FLOW_H
#define SIMPLEIDS_FLOW_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#include "simpleids/decode.h"
#include "simpleids/stream.h"

/*
 * Flow table: one entry per bidirectional TCP or UDP conversation, keyed
 * by the 5-tuple (both directions map to the same entry).
 *
 * - Fixed-size pool: at most max_flows entries ever exist, so the table
 *   cannot grow without bound however many flows an attacker opens.
 * - LRU list: when the pool is full the least recently active flow is
 *   evicted; idle flows also time out (timeouts depend on TCP state).
 * - Buckets are chosen with SipHash under a random per-process key, so
 *   collisions cannot be engineered from outside.
 */

enum { FLOW_TO_SERVER = 0, FLOW_TO_CLIENT = 1 };

typedef enum {
    TCP_STATE_NEW = 0,     /* first packet seen was not a SYN (or UDP) */
    TCP_STATE_SYN_SENT,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_CLOSED       /* FIN from both sides, or RST             */
} tcp_state_t;

typedef enum {
    FLOW_END_TIMEOUT = 0,
    FLOW_END_EVICTED,
    FLOW_END_REUSED,       /* new SYN on a closed 5-tuple             */
    FLOW_END_SHUTDOWN
} flow_end_t;

typedef enum {
    APP_UNKNOWN = 0,       /* not decided yet                          */
    APP_HTTP,
    APP_TLS,
    APP_DNS,
    APP_NONE               /* no parser (raw rules may still apply)    */
} app_proto_t;

#define FLOW_MAX_ALERT_SIDS 16

/* Per-flow state owned by the detection engine (src/core/engine.c). */
typedef struct {
    uint8_t  proto;            /* app_proto_t                          */
    uint8_t  done;             /* nothing more to inspect              */
    uint8_t  http_lost;        /* HTTP request tracking gave up        */
    uint8_t  overlap_alerted;
    uint32_t scan_pos;         /* stream offset scanned by rules so far */
    uint32_t seg_start;        /* start of the current gap-free region */
    uint8_t  raw_scan;         /* raw-content rules apply to the stream */
    uint8_t  parser_done;      /* the app-layer parser has finished    */
    uint8_t  http_state;       /* HTTP: 0 headers, 1 body, 2 resync    */
    uint8_t  body_chunked;     /* HTTP: current body is chunked        */
    uint8_t  body_form;        /* HTTP: body is form-urlencoded        */
    uint32_t req_start;        /* HTTP/DNS: offset of the next message */
    uint32_t hdr_scan;         /* HTTP: resume point for CRLFCRLF or
                                  for the resync search               */
    uint32_t data_end;         /* end of the data handed to parsers    */
    uint32_t body_start;       /* HTTP: first body byte                */
    uint32_t body_end;         /* HTTP: end of a Content-Length body   */
    uint8_t  nsids;
    int      sids[FLOW_MAX_ALERT_SIDS]; /* sids already alerted        */
} flow_app_t;

typedef struct flow {
    struct flow *hnext;                 /* hash chain / free list       */
    struct flow *lru_prev, *lru_next;
    uint64_t id;
    uint64_t hash;

    uint8_t  ip_version;
    uint8_t  l4proto;
    uint8_t  tcp_state;                 /* tcp_state_t                  */
    uint8_t  fin;                       /* bit per direction            */
    uint8_t  addr[2][16];               /* [0] client, [1] server       */
    uint16_t port[2];

    struct timeval first_seen, last_seen;
    unsigned long  pkts[2];
    unsigned long  bytes[2];

    stream_t   stream;                  /* client -> server data        */
    flow_app_t app;
} flow_t;

typedef struct {
    uint32_t max_flows;
    uint32_t timeout_new;          /* seconds: handshake / unknown TCP */
    uint32_t timeout_established;
    uint32_t timeout_closed;
    uint32_t timeout_udp;
} flow_config_t;

typedef struct {
    unsigned long created;
    unsigned long timed_out;
    unsigned long evicted;
    unsigned long reused;
    unsigned long active;
    unsigned long active_peak;
} flow_stats_t;

/* Called just before a flow is freed (e.g. to flush its stream). */
typedef void (*flow_end_fn)(flow_t *f, flow_end_t why);

void flow_config_defaults(flow_config_t *cfg);

/* Allocate the pool and pick a random hash key. Returns 0 or -1. */
int  flow_init(const flow_config_t *cfg, flow_end_fn on_end);

/* End every flow (FLOW_END_SHUTDOWN) and free the table. */
void flow_destroy(void);

/*
 * Find the flow for this TCP/UDP packet, creating it if needed (which
 * may evict the least recently used flow). *dir is set to FLOW_TO_SERVER
 * or FLOW_TO_CLIENT. Updates counters, TCP state and the LRU position.
 * Returns NULL only if the table was not initialised.
 */
flow_t *flow_get(const packet_t *pkt, const struct timeval *ts, int *dir);

/* End flows that have been idle longer than their timeout. */
void flow_expire(const struct timeval *now);

const flow_stats_t *flow_stats(void);

/* Bytes allocated for the flow pool and hash buckets. */
size_t flow_table_memory(void);

/* Hash of the packet's 5-tuple under the current key (for tests). */
uint64_t flow_hash_packet(const packet_t *pkt);

/* Replace the random hash key (tests only; call before flow_init). */
void flow_set_hash_key(const uint8_t key[16]);

#endif
