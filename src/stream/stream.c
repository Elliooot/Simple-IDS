#include <stdlib.h>
#include <string.h>

#include "simpleids/stream.h"

#define MIN_CAP 1024u

static stream_config_t g_cfg = {
    .depth = 65536, .memcap = 64u * 1024 * 1024, .policy = OVERLAP_FIRST,
};
static stream_stats_t g_stats;

void stream_configure(const stream_config_t *cfg) {
    g_cfg = *cfg;
    if (g_cfg.depth < 8) g_cfg.depth = 8;
    g_cfg.depth = (g_cfg.depth + 7u) & ~7u; /* whole bitmap bytes */
}

const stream_config_t *stream_get_config(void) {
    return &g_cfg;
}

const stream_stats_t *stream_stats(void) {
    return &g_stats;
}

void stream_reset_stats(void) {
    size_t used = g_stats.mem_used;
    memset(&g_stats, 0, sizeof(g_stats));
    g_stats.mem_used = g_stats.mem_peak = used;
}

/* Memory charged for a buffer of `cap` bytes: data + two bitmaps. */
static size_t mem_for(uint32_t cap) {
    return (size_t)cap + 2 * ((size_t)cap / 8);
}

static int bit(const uint8_t *map, uint32_t i) {
    return (map[i >> 3] >> (i & 7)) & 1;
}

static void set_bit(uint8_t *map, uint32_t i) {
    map[i >> 3] |= (uint8_t)(1u << (i & 7));
}

static void clear_bit(uint8_t *map, uint32_t i) {
    map[i >> 3] &= (uint8_t)~(1u << (i & 7));
}

void stream_init(stream_t *s, uint32_t first_seq) {
    stream_close(s);
    memset(s, 0, sizeof(*s));
    s->active = 1;
    s->base_seq = first_seq;
}

void stream_close(stream_t *s) {
    if (s->buf) {
        g_stats.mem_used -= mem_for(s->cap);
        free(s->buf);
        free(s->present);
        free(s->lost);
    }
    s->buf = s->present = s->lost = NULL;
    s->cap = 0;
    s->closed = 1;
}

/* Make buf cover offsets [0, need). Returns 0, or -1 over the memcap. */
static int ensure_cap(stream_t *s, uint32_t need) {
    if (need <= s->cap) return 0;

    uint32_t ncap = s->cap ? s->cap : MIN_CAP;
    while (ncap < need) ncap *= 2;
    if (ncap > g_cfg.depth) ncap = g_cfg.depth;

    size_t extra = mem_for(ncap) - mem_for(s->cap);
    if (g_stats.mem_used + extra > g_cfg.memcap) return -1;

    uint8_t *nb = realloc(s->buf, ncap);
    if (!nb) return -1;
    s->buf = nb;

    size_t old_map = s->cap / 8, new_map = ncap / 8;
    uint8_t *np = realloc(s->present, new_map);
    if (!np) return -1;
    s->present = np;
    uint8_t *nl = realloc(s->lost, new_map);
    if (!nl) return -1;
    s->lost = nl;
    memset(s->present + old_map, 0, new_map - old_map);
    memset(s->lost + old_map, 0, new_map - old_map);

    g_stats.mem_used += extra;
    if (g_stats.mem_used > g_stats.mem_peak) g_stats.mem_peak = g_stats.mem_used;
    s->cap = ncap;
    return 0;
}

void stream_insert(stream_t *s, uint32_t seq, const uint8_t *data,
                   uint32_t len, uint32_t wire_len) {
    if (!s->active || s->closed || wire_len == 0) return;
    if (len > wire_len) len = wire_len;
    g_stats.segments++;

    /* Signed distance from offset 0 handles sequence number wrap. */
    int64_t off = (int32_t)(seq - s->base_seq);
    if (off < 0) {
        /* Starts before the stream (e.g. data from before a mid-stream
         * pickup): drop the part we cannot place. */
        if (off + (int64_t)wire_len <= 0) return;
        uint32_t skip = (uint32_t)-off;
        data += skip < len ? skip : len;
        len = skip < len ? len - skip : 0;
        wire_len -= skip;
        off = 0;
    }

    uint32_t depth = g_cfg.depth;
    if (off >= depth) {
        g_stats.depth_reached++;
        return;
    }
    uint32_t o = (uint32_t)off;
    if (wire_len > depth - o) {
        wire_len = depth - o;
        if (len > wire_len) len = wire_len;
        g_stats.depth_reached++;
    }

    if (ensure_cap(s, o + wire_len) < 0) {
        g_stats.memcap_drops++;
        stream_close(s);
        return;
    }

    if (o == s->delivered) g_stats.in_order++;
    else if (o > s->delivered) g_stats.out_of_order++;

    int overlapped = 0, differs = 0;
    for (uint32_t i = 0; i < len; i++) {
        uint32_t p = o + i;
        if (bit(s->present, p)) {
            overlapped = 1;
            if (s->buf[p] != data[i]) {
                differs = 1;
                /* Delivered bytes are final; queued ones follow the policy. */
                if (p >= s->delivered && g_cfg.policy == OVERLAP_LAST)
                    s->buf[p] = data[i];
            }
        } else {
            s->buf[p] = data[i];
            set_bit(s->present, p);
            clear_bit(s->lost, p);
        }
    }
    /* Bytes cut off by the snaplen: never coming, unless resent. */
    for (uint32_t p = o + len; p < o + wire_len; p++) {
        if (!bit(s->present, p)) set_bit(s->lost, p);
    }

    if (o + wire_len > s->max_off) s->max_off = o + wire_len;

    if (overlapped) {
        g_stats.overlaps++;
        if (differs) {
            g_stats.overlap_diffs++;
            s->overlap_diff = 1;
        } else if (len == wire_len) {
            g_stats.retransmits++;
        }
    }
}

int stream_next_run(stream_t *s, int force, uint32_t *start, uint32_t *end,
                    int *gap_before) {
    if (!s->buf) return 0;

    uint32_t p = s->delivered;
    while (p < s->max_off && !bit(s->present, p)) {
        if (!force && !bit(s->lost, p)) {
            /* A hole that may still be filled: wait, unless only lost
             * bytes precede it (then we already moved p forward). */
            break;
        }
        p++;
    }
    if (p != s->delivered) {
        /* Skipped lost bytes (or, when forced, an unfilled hole). */
        s->delivered = p;
        s->gap_pending = 1;
        g_stats.gaps++;
    }
    if (p >= s->max_off || !bit(s->present, p)) return 0;

    uint32_t e = p;
    while (e < s->max_off && bit(s->present, e)) e++;

    *start = p;
    *end = e;
    *gap_before = s->gap_pending;
    s->gap_pending = 0;
    s->delivered = e;
    return 1;
}
