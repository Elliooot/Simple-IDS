#ifndef SIMPLEIDS_ANOMALY_H
#define SIMPLEIDS_ANOMALY_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Anomaly detections are reported with these fixed sids so they show up
 * in the log (and in regression tests) like signature alerts. */
#define ANOMALY_SID_RATE       900001
#define ANOMALY_SID_LONG_URL   900002
#define ANOMALY_SID_SHORT_UA   900003
#define ANOMALY_SID_BAD_UA     900004

#define ANOMALY_MAX_IPS        1024 /* rate table size (LRU eviction)  */
#define ANOMALY_RATE_WINDOW    60   /* seconds                          */
#define ANOMALY_RATE_THRESHOLD 100  /* requests per window              */
#define ANOMALY_URL_MAX        1024 /* characters                       */
#define ANOMALY_UA_MIN         4    /* characters                       */

typedef struct {
    int  sid;
    int  priority;
    char msg[128];
} anomaly_hit_t;

typedef void (*anomaly_hit_fn)(const anomaly_hit_t *hit, void *ctx);

/*
 * Run all anomaly checks on one HTTP request.
 *   now: packet timestamp (seconds), so offline pcap runs are repeatable.
 * Calls hit() once per anomaly and returns the number found.
 */
int anomaly_check(const char *src_ip, time_t now,
                  const uint8_t *payload, size_t len,
                  anomaly_hit_fn hit, void *ctx);

/* Forget all rate-tracking state (used by tests). */
void anomaly_reset(void);

/* Number of IPs currently tracked / evicted so far (for tests and stats). */
int           anomaly_tracked_ips(void);
unsigned long anomaly_evictions(void);

#endif
