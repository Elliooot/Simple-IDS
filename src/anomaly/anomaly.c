#include <stdio.h>
#include <string.h>

#include "simpleids/anomaly.h"
#include "simpleids/bytes.h"
#include "simpleids/decode.h"
#include "simpleids/http.h"

/* ------------------------------------------------------------------ */
/* Request rate per source IP                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    char   ip[IP_STR_LEN];
    int    count;
    time_t window_start;
    time_t last_seen;
} ip_rate_t;

static ip_rate_t g_rate[ANOMALY_MAX_IPS];
static int g_rate_count = 0;
static unsigned long g_evictions = 0;

void anomaly_reset(void) {
    memset(g_rate, 0, sizeof(g_rate));
    g_rate_count = 0;
    g_evictions = 0;
}

int anomaly_tracked_ips(void) {
    return g_rate_count;
}

unsigned long anomaly_evictions(void) {
    return g_evictions;
}

/*
 * Find or create the entry for src_ip. When the table is full, the entry
 * that has been idle the longest is reused, so new sources are always
 * tracked (an attacker cannot blind the check by filling the table).
 * Linear scan: fine for 1024 entries; a hash table comes with Phase 2.
 */
static ip_rate_t *rate_entry(const char *src_ip, time_t now) {
    int lru = 0;
    for (int i = 0; i < g_rate_count; i++) {
        if (strcmp(g_rate[i].ip, src_ip) == 0) return &g_rate[i];
        if (g_rate[i].last_seen < g_rate[lru].last_seen) lru = i;
    }

    ip_rate_t *e;
    if (g_rate_count < ANOMALY_MAX_IPS) {
        e = &g_rate[g_rate_count++];
    } else {
        e = &g_rate[lru];
        g_evictions++;
    }
    snprintf(e->ip, sizeof(e->ip), "%s", src_ip);
    e->count = 0;
    e->window_start = now;
    e->last_seen = now;
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
