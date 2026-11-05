#ifndef SIMPLEIDS_THRESHOLD_H
#define SIMPLEIDS_THRESHOLD_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * Alert rate control for rules (Suricata semantics):
 *
 *   threshold: type limit, track by_src, count N, seconds S;
 *       at most N alerts per tracked entity per S-second window
 *   threshold: type threshold, ...   an alert on every N-th match
 *   threshold: type both, ...        one alert per window, once N
 *                                    matches have been seen
 *   detection_filter: track by_src, count N, seconds S;
 *       alert on every match after the first N in the window
 *
 * Windows start at the first match and use packet time, so offline
 * pcaps behave like live traffic. State lives in a fixed-size table
 * keyed by (sid, tracked addresses) under a random SipHash key; when the
 * table is full the least recently used entry in the probe range is
 * replaced, so attackers cannot grow it.
 */

typedef enum {
    THRESHOLD_NONE = 0,
    THRESHOLD_LIMIT,
    THRESHOLD_THRESHOLD,
    THRESHOLD_BOTH,
    THRESHOLD_DETECTION_FILTER
} threshold_type_t;

typedef enum {
    TRACK_BY_SRC = 0,
    TRACK_BY_DST,
    TRACK_BY_RULE,
    TRACK_BY_BOTH
} threshold_track_t;

typedef struct {
    uint8_t  type;          /* threshold_type_t   */
    uint8_t  track;         /* threshold_track_t  */
    uint32_t count;         /* >= 1               */
    uint32_t seconds;       /* >= 1               */
} threshold_t;

typedef struct {
    unsigned long checked;
    unsigned long suppressed;
    unsigned long evicted;   /* entries replaced because the table was full */
    unsigned long entries;   /* in use                                      */
} threshold_stats_t;

#define THRESHOLD_DEFAULT_ENTRIES 65536

/* Allocate the table (rounded up to a power of two). Optional: the first
 * threshold_check() uses the default size. Returns 0 or -1. */
int threshold_init(size_t entries);

/*
 * Count one match of rule `sid` and decide whether it alerts.
 * src/dst are 16-byte addresses (IPv4 in the first 4 bytes).
 * Returns 1 to alert, 0 to suppress. A rule without a threshold
 * (type THRESHOLD_NONE) always alerts.
 */
int threshold_check(int sid, const threshold_t *t, const uint8_t src[16],
                    const uint8_t dst[16], time_t now);

const threshold_stats_t *threshold_stats(void);

/* Forget all state (tests) and free the table. */
void threshold_free(void);

#endif
