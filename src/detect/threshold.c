#include <stdlib.h>
#include <string.h>

#include "simpleids/siphash.h"
#include "simpleids/threshold.h"

#define PROBE_MAX 16

typedef struct {
    int32_t  sid;           /* 0 = free slot */
    uint8_t  type;
    uint8_t  addr[32];      /* tracked address(es), zero when unused */
    time_t   start;         /* window start                          */
    time_t   last;          /* last match, for eviction              */
    uint32_t count;
} entry_t;

static entry_t *g_table;
static size_t g_mask;
static uint8_t g_key[16];
static threshold_stats_t g_stats;

int threshold_init(size_t entries) {
    threshold_free();
    size_t n = 64;
    while (n < entries) n <<= 1;
    g_table = calloc(n, sizeof(*g_table));
    if (!g_table) return -1;
    g_mask = n - 1;
    if (random_bytes(g_key, sizeof(g_key)) < 0) memset(g_key, 0x5a, sizeof(g_key));
    return 0;
}

static void make_key(entry_t *k, int sid, const threshold_t *t,
                     const uint8_t src[16], const uint8_t dst[16]) {
    memset(k, 0, sizeof(*k));
    k->sid = sid;
    k->type = t->type;
    switch (t->track) {
    case TRACK_BY_SRC:  memcpy(k->addr, src, 16); break;
    case TRACK_BY_DST:  memcpy(k->addr, dst, 16); break;
    case TRACK_BY_BOTH: memcpy(k->addr, src, 16); memcpy(k->addr + 16, dst, 16); break;
    default: break;
    }
}

static int same_key(const entry_t *a, const entry_t *b) {
    return a->sid == b->sid && a->type == b->type && memcmp(a->addr, b->addr, 32) == 0;
}

/* Find the entry for k, or claim a free / least recently used slot. */
static entry_t *lookup(const entry_t *k, time_t now) {
    uint8_t hk[37];
    memcpy(hk, &k->sid, 4);
    hk[4] = k->type;
    memcpy(hk + 5, k->addr, 32);
    size_t h = (size_t)siphash24(g_key, hk, sizeof(hk));

    entry_t *victim = NULL;
    for (size_t i = 0; i < PROBE_MAX; i++) {
        entry_t *e = &g_table[(h + i) & g_mask];
        if (e->sid == 0) {
            if (!victim || victim->sid != 0) victim = e;
            break;
        }
        if (same_key(e, k)) return e;
        if (!victim || (victim->sid != 0 && e->last < victim->last)) victim = e;
    }
    if (victim->sid != 0) g_stats.evicted++;
    else g_stats.entries++;
    *victim = *k;
    victim->start = now;
    victim->last = now;
    victim->count = 0;
    return victim;
}

int threshold_check(int sid, const threshold_t *t, const uint8_t src[16],
                    const uint8_t dst[16], time_t now) {
    if (!t || t->type == THRESHOLD_NONE) return 1;
    if (!g_table && threshold_init(THRESHOLD_DEFAULT_ENTRIES) < 0) return 1;
    g_stats.checked++;

    entry_t k;
    make_key(&k, sid, t, src, dst);
    entry_t *e = lookup(&k, now);
    if (now - e->start >= (time_t)t->seconds) {     /* window over: restart */
        e->start = now;
        e->count = 0;
    }
    e->last = now;
    if (e->count < UINT32_MAX) e->count++;

    int alert;
    switch (t->type) {
    case THRESHOLD_LIMIT:     alert = e->count <= t->count; break;
    case THRESHOLD_THRESHOLD:
        alert = e->count >= t->count;
        if (alert) e->count = 0;
        break;
    case THRESHOLD_BOTH:      alert = e->count == t->count; break;
    case THRESHOLD_DETECTION_FILTER: alert = e->count > t->count; break;
    default:                  alert = 1; break;
    }
    if (!alert) g_stats.suppressed++;
    return alert;
}

const threshold_stats_t *threshold_stats(void) {
    return &g_stats;
}

void threshold_free(void) {
    free(g_table);
    g_table = NULL;
    g_mask = 0;
    memset(&g_stats, 0, sizeof(g_stats));
}
