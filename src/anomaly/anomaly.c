#include <stdio.h>
#include <string.h>

#include "simpleids/anomaly.h"
#include "simpleids/bytes.h"
#include "simpleids/decode.h"
#include "simpleids/http.h"
#include "simpleids/siphash.h"

/* ------------------------------------------------------------------ */
/* Request rate per source IP                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    char   ip[IP_STR_LEN];
    int    count;
    time_t window_start;
    time_t last_seen;
    int    hnext;            /* hash chain: next index + 1, 0 = end    */
    int    older, newer;     /* LRU list by last use, -1 = end         */
} ip_rate_t;

/* A power of two, twice the table size: chains stay short. */
#define RATE_BUCKETS (2 * ANOMALY_MAX_IPS)

static ip_rate_t g_rate[ANOMALY_MAX_IPS];
static int g_bucket[RATE_BUCKETS];   /* first index + 1, 0 = empty */
static int g_oldest = -1, g_newest = -1;
static int g_rate_count = 0;
static unsigned long g_evictions = 0;
static uint8_t g_key[16];
static int g_key_set;

void anomaly_reset(void) {
    memset(g_rate, 0, sizeof(g_rate));
    memset(g_bucket, 0, sizeof(g_bucket));
    g_oldest = g_newest = -1;
    g_rate_count = 0;
    g_evictions = 0;
}

int anomaly_tracked_ips(void) {
    return g_rate_count;
}

unsigned long anomaly_evictions(void) {
    return g_evictions;
}

/* Keyed (SipHash) so that sources chosen by an attacker cannot all land
 * in one chain. */
static unsigned bucket_of(const char *ip) {
    if (!g_key_set) {
        if (random_bytes(g_key, sizeof(g_key)) < 0) memset(g_key, 0x5a, sizeof(g_key));
        g_key_set = 1;
    }
    return (unsigned)siphash24(g_key, ip, strlen(ip)) & (RATE_BUCKETS - 1);
}

static void lru_unlink(int i) {
    ip_rate_t *e = &g_rate[i];
    if (e->older >= 0) g_rate[e->older].newer = e->newer; else g_oldest = e->newer;
    if (e->newer >= 0) g_rate[e->newer].older = e->older; else g_newest = e->older;
}

static void lru_push_newest(int i) {
    g_rate[i].older = g_newest;
    g_rate[i].newer = -1;
    if (g_newest >= 0) g_rate[g_newest].newer = i; else g_oldest = i;
    g_newest = i;
}

static void hash_remove(int i) {
    int *pp = &g_bucket[bucket_of(g_rate[i].ip)];
    while (*pp != i + 1) pp = &g_rate[*pp - 1].hnext;
    *pp = g_rate[i].hnext;
}

/*
 * Find or create the entry for src_ip. When the table is full, the least
 * recently seen source is reused, so new sources are always tracked (an
 * attacker cannot blind the check by filling the table). Hash lookup plus
 * an LRU list: O(1) per request instead of a scan of the whole table.
 */
static ip_rate_t *rate_entry(const char *src_ip, time_t now) {
    unsigned b = bucket_of(src_ip);
    for (int i = g_bucket[b] - 1; i >= 0; i = g_rate[i].hnext - 1) {
        if (strcmp(g_rate[i].ip, src_ip) == 0) {
            lru_unlink(i);
            lru_push_newest(i);
            return &g_rate[i];
        }
    }

    int i;
    if (g_rate_count < ANOMALY_MAX_IPS) {
        i = g_rate_count++;
    } else {
        i = g_oldest;
        lru_unlink(i);
        hash_remove(i);
        g_evictions++;
    }
    ip_rate_t *e = &g_rate[i];
    snprintf(e->ip, sizeof(e->ip), "%s", src_ip);
    e->count = 0;
    e->window_start = now;
    e->last_seen = now;
    e->hnext = g_bucket[b];
    g_bucket[b] = i + 1;
    lru_push_newest(i);
    return e;
}

static int check_rate(const char *src_ip, time_t now, anomaly_hit_t *h) {
    ip_rate_t *e = rate_entry(src_ip, now);

    if (now - e->window_start >= ANOMALY_RATE_WINDOW) {
        e->count = 0;
        e->window_start = now;
    }
    e->last_seen = now;
    e->count++;

    if (e->count == ANOMALY_RATE_THRESHOLD + 1) {
        snprintf(h->msg, sizeof(h->msg),
                 "Anomaly: rate limit exceeded (%d req/%ds)",
                 e->count, ANOMALY_RATE_WINDOW);
        return 1;
    }
    if (e->count > ANOMALY_RATE_THRESHOLD && e->count % 10 == 0) {
        snprintf(h->msg, sizeof(h->msg),
                 "Anomaly: rate still high (%d req/%ds)",
                 e->count, ANOMALY_RATE_WINDOW);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* URL length and User-Agent                                           */
/* ------------------------------------------------------------------ */

static int check_url_length(const http_request_t *req, anomaly_hit_t *h) {
    if (req->uri_len <= ANOMALY_URL_MAX) return 0;
    snprintf(h->msg, sizeof(h->msg),
             "Anomaly: abnormally long URL (%zu chars, threshold %d)",
             req->uri_len, ANOMALY_URL_MAX);
    return 1;
}

static const char *const MALICIOUS_UA[] = {
    "sqlmap", "nikto", "nmap", "acunetix",
    "masscan", "zgrab", "dirbuster", "gobuster",
    "wfuzz", "burpsuite", "havij", "pangolin",
    NULL
};

/* 0 = fine, 1 = too short, 2 = known tool */
static int check_user_agent(const uint8_t *payload, size_t len, anomaly_hit_t *h) {
    const uint8_t *ua;
    size_t ua_len;
    if (http_find_header(payload, len, "User-Agent", &ua, &ua_len) < 0) return 0;

    int shown = ua_len > 60 ? 60 : (int)ua_len;

    if (ua_len < ANOMALY_UA_MIN) {
        snprintf(h->msg, sizeof(h->msg),
                 "Anomaly: suspiciously short User-Agent (%zu chars)", ua_len);
        return 1;
    }
    for (int i = 0; MALICIOUS_UA[i]; i++) {
        if (bytes_find(ua, ua_len, (const uint8_t *)MALICIOUS_UA[i],
                       strlen(MALICIOUS_UA[i]), 1)) {
            snprintf(h->msg, sizeof(h->msg),
                     "Anomaly: attack tool User-Agent '%s' (%.*s)",
                     MALICIOUS_UA[i], shown, (const char *)ua);
            return 2;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */

int anomaly_check(const char *src_ip, time_t now,
                  const uint8_t *payload, size_t len,
                  anomaly_hit_fn hit, void *ctx) {
    int found = 0;
    anomaly_hit_t h;

    memset(&h, 0, sizeof(h));
    if (check_rate(src_ip, now, &h)) {
        h.sid = ANOMALY_SID_RATE;
        h.priority = 2;
        found++;
        if (hit) hit(&h, ctx);
    }

    http_request_t req;
    if (http_parse_request(payload, len, &req) == 0) {
        memset(&h, 0, sizeof(h));
        if (check_url_length(&req, &h)) {
            h.sid = ANOMALY_SID_LONG_URL;
            h.priority = 2;
            found++;
            if (hit) hit(&h, ctx);
        }
    }

    memset(&h, 0, sizeof(h));
    int ua = check_user_agent(payload, len, &h);
    if (ua) {
        h.sid = ua == 1 ? ANOMALY_SID_SHORT_UA : ANOMALY_SID_BAD_UA;
        h.priority = ua == 1 ? 3 : 1;
        found++;
        if (hit) hit(&h, ctx);
    }

    return found;
}
