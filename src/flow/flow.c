#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simpleids/flow.h"
#include "simpleids/siphash.h"

#define EXPIRE_BATCH 16 /* flows checked for timeout per packet */

static flow_config_t g_cfg;
static flow_end_fn g_on_end;
static flow_t *g_pool;
static flow_t *g_free;
static flow_t **g_buckets;
static uint64_t g_bucket_mask;
static flow_t *g_lru_head, *g_lru_tail; /* head = least recently used */
static uint64_t g_next_id;
static flow_stats_t g_stats;

static uint8_t g_key[16];
static int g_key_set;

void flow_config_defaults(flow_config_t *cfg) {
    cfg->max_flows = 65536;
    cfg->timeout_new = 30;
    cfg->timeout_established = 600;
    cfg->timeout_closed = 10;
    cfg->timeout_udp = 60;
}

void flow_set_hash_key(const uint8_t key[16]) {
    memcpy(g_key, key, sizeof(g_key));
    g_key_set = 1;
}

const flow_stats_t *flow_stats(void) {
    return &g_stats;
}

size_t flow_table_memory(void) {
    return (size_t)g_cfg.max_flows * sizeof(flow_t) +
           (size_t)(g_bucket_mask + 1) * sizeof(flow_t *);
}

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *addr;
    uint16_t port;
} endpoint_t;

static int ep_cmp(endpoint_t a, endpoint_t b, size_t alen) {
    int c = memcmp(a.addr, b.addr, alen);
    if (c) return c;
    return (int)a.port - (int)b.port;
}

/* Hash a direction-independent form of the 5-tuple. */
static uint64_t hash_tuple(uint8_t ver, uint8_t proto, endpoint_t a, endpoint_t b) {
    size_t alen = ver == 6 ? 16 : 4;
    if (ep_cmp(a, b, alen) > 0) { endpoint_t t = a; a = b; b = t; }

    uint8_t buf[2 + 2 * (16 + 2)];
    size_t n = 0;
    buf[n++] = ver;
    buf[n++] = proto;
    memcpy(buf + n, a.addr, alen); n += alen;
    buf[n++] = (uint8_t)(a.port >> 8); buf[n++] = (uint8_t)a.port;
    memcpy(buf + n, b.addr, alen); n += alen;
    buf[n++] = (uint8_t)(b.port >> 8); buf[n++] = (uint8_t)b.port;
    return siphash24(g_key, buf, n);
}

uint64_t flow_hash_packet(const packet_t *pkt) {
    endpoint_t s = { pkt->src_addr, pkt->src_port }, d = { pkt->dst_addr, pkt->dst_port };
    return hash_tuple(pkt->ip_version, pkt->l4proto, s, d);
}

/* Does f belong to pkt? Sets *dir. */
static int flow_matches(const flow_t *f, const packet_t *pkt, int *dir) {
    if (f->ip_version != pkt->ip_version || f->l4proto != pkt->l4proto) return 0;
    size_t alen = f->ip_version == 6 ? 16 : 4;
    if (f->port[0] == pkt->src_port && f->port[1] == pkt->dst_port &&
        memcmp(f->addr[0], pkt->src_addr, alen) == 0 &&
        memcmp(f->addr[1], pkt->dst_addr, alen) == 0) {
        *dir = FLOW_TO_SERVER;
        return 1;
    }
    if (f->port[0] == pkt->dst_port && f->port[1] == pkt->src_port &&
        memcmp(f->addr[0], pkt->dst_addr, alen) == 0 &&
        memcmp(f->addr[1], pkt->src_addr, alen) == 0) {
        *dir = FLOW_TO_CLIENT;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* LRU list                                                            */
/* ------------------------------------------------------------------ */

static void lru_unlink(flow_t *f) {
    if (f->lru_prev) f->lru_prev->lru_next = f->lru_next;
    else g_lru_head = f->lru_next;
    if (f->lru_next) f->lru_next->lru_prev = f->lru_prev;
    else g_lru_tail = f->lru_prev;
    f->lru_prev = f->lru_next = NULL;
}

static void lru_push_tail(flow_t *f) {
    f->lru_prev = g_lru_tail;
    f->lru_next = NULL;
    if (g_lru_tail) g_lru_tail->lru_next = f;
    else g_lru_head = f;
    g_lru_tail = f;
}

/* ------------------------------------------------------------------ */
/* Life cycle                                                          */
/* ------------------------------------------------------------------ */

int flow_init(const flow_config_t *cfg, flow_end_fn on_end) {
    flow_destroy();
    g_cfg = *cfg;
    if (g_cfg.max_flows == 0) g_cfg.max_flows = 1;
    g_on_end = on_end;

    if (!g_key_set) {
        if (random_bytes(g_key, sizeof(g_key)) < 0) {
            fprintf(stderr, "Cannot read random bytes for the flow hash key\n");
            return -1;
        }
    }

    uint64_t nb = 1;
    while (nb < g_cfg.max_flows) nb <<= 1;
    g_bucket_mask = nb - 1;

    g_pool = calloc(g_cfg.max_flows, sizeof(flow_t));
    g_buckets = calloc(nb, sizeof(flow_t *));
    if (!g_pool || !g_buckets) {
        fprintf(stderr, "Cannot allocate flow table for %u flows\n", g_cfg.max_flows);
        free(g_pool);
        free(g_buckets);
        g_pool = NULL;
        g_buckets = NULL;
        return -1;
    }

    g_free = NULL;
    for (uint32_t i = g_cfg.max_flows; i-- > 0;) {
        g_pool[i].hnext = g_free;
        g_free = &g_pool[i];
    }
    g_lru_head = g_lru_tail = NULL;
    memset(&g_stats, 0, sizeof(g_stats));
    g_next_id = 1;
    return 0;
}

static void release(flow_t *f, flow_end_t why) {
    if (g_on_end) g_on_end(f, why);
    stream_close(&f->stream);

    flow_t **pp = &g_buckets[f->hash & g_bucket_mask];
    while (*pp && *pp != f) pp = &(*pp)->hnext;
    if (*pp) *pp = f->hnext;
    lru_unlink(f);

    memset(f, 0, sizeof(*f));
    f->hnext = g_free;
    g_free = f;
    g_stats.active--;

    switch (why) {
    case FLOW_END_TIMEOUT: g_stats.timed_out++; break;
    case FLOW_END_EVICTED: g_stats.evicted++; break;
    case FLOW_END_REUSED:  g_stats.reused++; break;
    case FLOW_END_SHUTDOWN: break;
    }
}

void flow_destroy(void) {
    if (g_pool) {
        while (g_lru_head) release(g_lru_head, FLOW_END_SHUTDOWN);
    }
    free(g_pool);
    free(g_buckets);
    g_pool = NULL;
    g_buckets = NULL;
    g_free = NULL;
    g_lru_head = g_lru_tail = NULL;
}

static uint32_t timeout_of(const flow_t *f) {
    if (f->l4proto != L4_TCP) return g_cfg.timeout_udp;
    switch (f->tcp_state) {
    case TCP_STATE_ESTABLISHED: return g_cfg.timeout_established;
    case TCP_STATE_CLOSED:      return g_cfg.timeout_closed;
    default:                    return g_cfg.timeout_new;
    }
}

static int is_expired(const flow_t *f, const struct timeval *now) {
    return now->tv_sec - f->last_seen.tv_sec > (long)timeout_of(f);
}

void flow_expire(const struct timeval *now) {
    for (int i = 0; i < EXPIRE_BATCH && g_lru_head; i++) {
        if (!is_expired(g_lru_head, now)) break;
        release(g_lru_head, FLOW_END_TIMEOUT);
    }
}

static int is_service_port(uint16_t port) {
    return port < 1024 || port == 8080 || port == 8443;
}

static flow_t *create(const packet_t *pkt, const struct timeval *ts, uint64_t hash, int *dir) {
    if (!g_free) release(g_lru_head, FLOW_END_EVICTED);
    flow_t *f = g_free;
    g_free = f->hnext;
    memset(f, 0, sizeof(*f));

    /* Who is the client? A SYN tells us; otherwise guess from ports. */
    int client_is_src;
    uint8_t fl = pkt->tcp_flags;
    if (pkt->l4proto == L4_TCP && (fl & TCP_SYN))
        client_is_src = !(fl & TCP_ACK);
    else if (is_service_port(pkt->dst_port) && !is_service_port(pkt->src_port))
        client_is_src = 1;
    else if (is_service_port(pkt->src_port) && !is_service_port(pkt->dst_port))
        client_is_src = 0;
    else
        client_is_src = 1;

    size_t alen = pkt->ip_version == 6 ? 16 : 4;
    f->ip_version = pkt->ip_version;
    f->l4proto = pkt->l4proto;
    memcpy(f->addr[0], client_is_src ? pkt->src_addr : pkt->dst_addr, alen);
    memcpy(f->addr[1], client_is_src ? pkt->dst_addr : pkt->src_addr, alen);
    f->port[0] = client_is_src ? pkt->src_port : pkt->dst_port;
    f->port[1] = client_is_src ? pkt->dst_port : pkt->src_port;
    f->id = g_next_id++;
    f->hash = hash;
    f->first_seen = *ts;
    f->tcp_state = TCP_STATE_NEW;

    flow_t **b = &g_buckets[hash & g_bucket_mask];
    f->hnext = *b;
    *b = f;

    g_stats.created++;
    g_stats.active++;
    if (g_stats.active > g_stats.active_peak) g_stats.active_peak = g_stats.active;
    *dir = client_is_src ? FLOW_TO_SERVER : FLOW_TO_CLIENT;
    return f;
}

static void update_tcp_state(flow_t *f, const packet_t *pkt, int dir) {
    uint8_t fl = pkt->tcp_flags;
    if (fl & TCP_RST) {
        /* Not released at once: a spoofed RST must not make us forget a
         * connection the endpoints keep using (it just times out soon). */
        f->tcp_state = TCP_STATE_CLOSED;
        return;
    }
    if (fl & TCP_FIN) {
        f->fin |= (uint8_t)(1u << dir);
        if (f->fin == 3) f->tcp_state = TCP_STATE_CLOSED;
    }
    if (f->tcp_state == TCP_STATE_NEW && (fl & TCP_SYN) && !(fl & TCP_ACK)) {
        f->tcp_state = TCP_STATE_SYN_SENT;
    } else if (f->tcp_state != TCP_STATE_CLOSED &&
               (pkt->payload_len > 0 || (fl & TCP_ACK))) {
        if (!((fl & TCP_SYN) && f->tcp_state == TCP_STATE_SYN_SENT))
            f->tcp_state = TCP_STATE_ESTABLISHED;
    }
}

flow_t *flow_get(const packet_t *pkt, const struct timeval *ts, int *dir) {
    if (!g_pool) return NULL;

    uint64_t h = flow_hash_packet(pkt);
    flow_t *f = g_buckets[h & g_bucket_mask];
    while (f && !(f->hash == h && flow_matches(f, pkt, dir))) f = f->hnext;

    if (f) {
        int syn_only = pkt->l4proto == L4_TCP &&
                       (pkt->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN;
        if (is_expired(f, ts)) {
            release(f, FLOW_END_TIMEOUT);
            f = NULL;
        } else if (syn_only && f->tcp_state == TCP_STATE_CLOSED) {
            release(f, FLOW_END_REUSED);
            f = NULL;
        }
    }
    if (f) {
        lru_unlink(f);  /* re-appended at the tail below */
    } else {
        f = create(pkt, ts, h, dir);
    }

    f->last_seen = *ts;
    f->pkts[*dir]++;
    f->bytes[*dir] += pkt->wire_payload_len;
    if (f->l4proto == L4_TCP) update_tcp_state(f, pkt, *dir);

    lru_push_tail(f);
    return f;
}
