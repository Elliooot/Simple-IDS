#include <arpa/inet.h>
#include <string.h>

#include "simpleids/anomaly.h"
#include "simpleids/bytes.h"
#include "simpleids/engine.h"
#include "simpleids/http.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"
#include "simpleids/tls.h"

#define HTTP_MAX_HEADER  16384 /* give up waiting for CRLFCRLF after this */
#define ALERT_CONTEXT    64    /* bytes logged before a signature match   */

static engine_stats_t g_stats;
static int g_verbose = 0;

void engine_set_verbose(int verbose) {
    g_verbose = verbose;
}

const engine_stats_t *engine_stats(void) {
    return &g_stats;
}

void engine_reset_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));
    stream_reset_stats();
}

/* ------------------------------------------------------------------ */
/* Alerts                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    char ip[2][IP_STR_LEN];
} flow_names_t;

static void flow_names(const flow_t *f, flow_names_t *n) {
    int af = f->ip_version == 6 ? AF_INET6 : AF_INET;
    inet_ntop(af, f->addr[0], n->ip[0], sizeof(n->ip[0]));
    inet_ntop(af, f->addr[1], n->ip[1], sizeof(n->ip[1]));
}

static const char *app_name(const flow_t *f) {
    switch (f->app.proto) {
    case APP_HTTP: return "http";
    case APP_TLS:  return "tls";
    default:       return NULL;
    }
}

static void flow_alert(const flow_t *f, const struct timeval *ts, int sid, int priority,
                       const char *msg, alert_source_t source,
                       const uint8_t *data, size_t len, int truncated) {
    flow_names_t n;
    flow_names(f, &n);
    alert_event_t ev = {
        .ts = *ts,
        .src_ip = n.ip[0], .dst_ip = n.ip[1],
        .src_port = f->port[0], .dst_port = f->port[1],
        .flow_id = f->id, .app_proto = app_name(f),
        .sid = sid, .priority = priority, .msg = msg, .source = source,
        .data = data, .data_len = len, .truncated = truncated,
    };
    if (source == ALERT_SOURCE_ANOMALY) g_stats.anomaly_alerts++;
    else g_stats.signature_alerts++;
    output_alert(&ev);
}

/* Signature alerts fire once per flow and sid. Rescanning overlapping
 * windows of a stream would otherwise report the same match again. */
static int already_alerted(flow_t *f, int sid) {
    for (int i = 0; i < f->app.nsids; i++)
        if (f->app.sids[i] == sid) return 1;
    if (f->app.nsids < FLOW_MAX_ALERT_SIDS) f->app.sids[f->app.nsids++] = sid;
    return 0;
}

typedef struct {
    flow_t *f;
    const struct timeval *ts;
    const uint8_t *data;      /* what to log: start of data         */
    const uint8_t *data_end;  /* end of the inspected data          */
    int truncated;
} hit_ctx_t;

static void on_rule_hit(const rule_t *r, const uint8_t *match, void *vctx) {
    hit_ctx_t *c = vctx;
    if (already_alerted(c->f, r->sid)) {
        g_stats.duplicate_alerts++;
        return;
    }
    const uint8_t *from = match - c->data > ALERT_CONTEXT ? match - ALERT_CONTEXT : c->data;
    flow_alert(c->f, c->ts, r->sid, r->priority, r->msg, ALERT_SOURCE_SIGNATURE,
               from, (size_t)(c->data_end - from), c->truncated);
}

static void on_anomaly_hit(const anomaly_hit_t *h, void *vctx) {
    hit_ctx_t *c = vctx;
    flow_alert(c->f, c->ts, h->sid, h->priority, h->msg, ALERT_SOURCE_ANOMALY,
               c->data, (size_t)(c->data_end - c->data), c->truncated);
}

/* ------------------------------------------------------------------ */
/* HTTP over the reassembled client stream                             */
/* ------------------------------------------------------------------ */

static const char *const METHOD_PREFIXES[] = {
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", NULL
};

/* Could buf[0..n) be the start of a request line? (n may be short.) */
static int maybe_method(const uint8_t *buf, size_t n) {
    for (int i = 0; METHOD_PREFIXES[i]; i++) {
        size_t m = strlen(METHOD_PREFIXES[i]);
        if (memcmp(buf, METHOD_PREFIXES[i], n < m ? n : m) == 0) return 1;
    }
    return 0;
}

/* Body length to skip after the headers, or -1 if we cannot tell. */
static long request_body_len(const uint8_t *hdr, size_t len) {
    const uint8_t *v;
    size_t vlen;
    if (http_find_header(hdr, len, "Transfer-Encoding", &v, &vlen) == 0) return -1;
    if (http_find_header(hdr, len, "Content-Length", &v, &vlen) < 0) return 0;
    if (vlen == 0 || vlen > 9) return -1;
    long n = 0;
    for (size_t i = 0; i < vlen; i++) {
        if (v[i] < '0' || v[i] > '9') return -1;
        n = n * 10 + (v[i] - '0');
    }
    return n;
}

static void on_http_request(flow_t *f, const struct timeval *ts,
                            uint32_t start, uint32_t end, int truncated) {
    flow_names_t n;
    const uint8_t *req = f->stream.buf + start;
    size_t len = end - start;

    g_stats.http_requests++;
    flow_names(f, &n);
    hit_ctx_t ctx = { f, ts, req, req + len, truncated };
    int hits = anomaly_check(n.ip[0], ts->tv_sec, req, len, on_anomaly_hit, &ctx);

    if (hits == 0 && g_verbose) {
        http_request_t r;
        http_parse_request(req, len, &r);
        fprintf(output_console(), "[clean] %s:%u -> %s:%u %.*s\n",
                n.ip[0], f->port[0], n.ip[1], f->port[1],
                (int)(r.uri_len > 80 ? 80 : r.uri_len), (const char *)r.uri);
    }
}

/*
 * Split the client stream into requests: request line + headers up to
 * CRLFCRLF, then Content-Length bytes of body. Chunked bodies and gaps
 * end the tracking (a full HTTP parser is Phase 3).
 */
static void track_http_requests(flow_t *f, const struct timeval *ts, uint32_t end, int final) {
    flow_app_t *a = &f->app;
    const uint8_t *buf = f->stream.buf;
    int at_depth = end >= stream_get_config()->depth;

    while (!a->http_lost) {
        uint32_t r = a->req_start;
        if (r < a->seg_start) { a->http_lost = 1; return; }
        if (r >= end) return;

        size_t avail = end - r;
        if (avail < 8 && !final && !at_depth && maybe_method(buf + r, avail)) return;
        http_request_t req;
        if (http_parse_request(buf + r, avail, &req) < 0) { a->http_lost = 1; return; }

        uint32_t from = a->hdr_scan > r + 3 ? a->hdr_scan - 3 : r;
        const uint8_t *e = bytes_find(buf + from, end - from, (const uint8_t *)"\r\n\r\n", 4, 0);
        if (!e) {
            a->hdr_scan = end;
            if (!final && !at_depth && avail < HTTP_MAX_HEADER) return;
            on_http_request(f, ts, r, end, 1); /* incomplete request */
            a->http_lost = 1;
            return;
        }

        uint32_t hdr_end = (uint32_t)(e - buf) + 4;
        on_http_request(f, ts, r, hdr_end, 0);

        long body = request_body_len(buf + r, hdr_end - r);
        if (body < 0) { a->http_lost = 1; return; }
        a->req_start = hdr_end + (uint32_t)body;
        a->hdr_scan = a->req_start;
    }
}

static void inspect_http(flow_t *f, const struct timeval *ts, uint32_t end, int final) {
    flow_app_t *a = &f->app;
    stream_t *s = &f->stream;

    /* The stream must start with a request line, else it is not HTTP. */
    if (a->scan_pos == 0 && a->seg_start == 0) {
        if (end < 8 && !final && maybe_method(s->buf, end)) return;
        http_request_t req;
        if (http_parse_request(s->buf, end, &req) < 0) {
            a->proto = APP_NONE;
            a->done = 1;
            return;
        }
    }

    /* Rescan the last (longest content - 1) bytes so that matches across
     * segment boundaries are found, but never across a gap. */
    size_t back = rules_max_content_len();
    uint32_t from = a->scan_pos > back ? a->scan_pos - (uint32_t)(back ? back - 1 : 0) : 0;
    if (from < a->seg_start) from = a->seg_start;
    if (end > from) {
        hit_ctx_t ctx = { f, ts, s->buf + from, s->buf + end, 0 };
        rules_match(s->buf + from, end - from, "tcp", 80, on_rule_hit, &ctx);
    }
    a->scan_pos = end;

    track_http_requests(f, ts, end, final);
}

/* ------------------------------------------------------------------ */
/* TLS: SNI from the (possibly multi-segment) ClientHello              */
/* ------------------------------------------------------------------ */

static void inspect_tls(flow_t *f, const struct timeval *ts, uint32_t end, int final) {
    flow_app_t *a = &f->app;
    const uint8_t *buf = f->stream.buf;

    if (a->seg_start != 0) {        /* gap inside the ClientHello */
        a->done = 1;
        return;
    }
    if (buf[0] != 0x16) {
        a->proto = APP_NONE;
        a->done = 1;
        return;
    }

    char sni[TLS_SNI_MAX];
    int n = tls_extract_sni(buf, end, sni, sizeof(sni));
    uint32_t need = end >= 5 ? 5u + rd_be16(buf + 3) : UINT32_MAX;
    if (n < 0 && !final && end < need && end < stream_get_config()->depth)
        return;                     /* SNI may be in a later segment */

    a->done = 1;
    if (n < 0) return;

    g_stats.tls_client_hellos++;
    hit_ctx_t ctx = { f, ts, (const uint8_t *)sni, (const uint8_t *)sni + n, 0 };
    int hits = rules_match((const uint8_t *)sni, (size_t)n, "tcp", 443, on_rule_hit, &ctx);
    if (hits == 0 && g_verbose) {
        flow_names_t nm;
        flow_names(f, &nm);
        fprintf(output_console(), "[clean] TLS %s:%u -> %s:%u SNI=%s\n",
                nm.ip[0], f->port[0], nm.ip[1], f->port[1], sni);
    }
}

/* ------------------------------------------------------------------ */
/* Stream driver                                                       */
/* ------------------------------------------------------------------ */

static app_proto_t classify(uint16_t server_port) {
    switch (server_port) {
    case 80: case 8080: return APP_HTTP;
    case 443:           return APP_TLS;
    default:            return APP_NONE;
    }
}

/* Pull every newly contiguous run from the stream and inspect it. */
static void inspect_stream(flow_t *f, const struct timeval *ts, int final) {
    stream_t *s = &f->stream;
    flow_app_t *a = &f->app;
    uint32_t start, end;
    int gap;

    while (!a->done && stream_next_run(s, final, &start, &end, &gap)) {
        if (gap) a->seg_start = start;
        if (a->proto == APP_HTTP) inspect_http(f, ts, end, 0);
        else if (a->proto == APP_TLS) inspect_tls(f, ts, end, 0);
    }

    /* Nothing more will arrive: let the parsers use what they have. */
    int at_depth = s->delivered >= stream_get_config()->depth;
    if (!a->done && (final || at_depth || s->closed) && s->buf) {
        /* Bytes skipped at the very end start no new region to scan. */
        if (s->gap_pending) a->seg_start = s->delivered;
        uint32_t end_all = s->delivered;
        if (a->proto == APP_HTTP) inspect_http(f, ts, end_all, 1);
        else if (a->proto == APP_TLS) inspect_tls(f, ts, end_all, 1);
        a->done = 1;
    }
    if (a->done) stream_close(s);
}

static void on_flow_end(flow_t *f, flow_end_t why) {
    (void)why;
    if (f->stream.active && !f->app.done) inspect_stream(f, &f->last_seen, 1);
}

static void handle_tcp(flow_t *f, int dir, const struct timeval *ts, const packet_t *pkt) {
    flow_app_t *a = &f->app;
    stream_t *s = &f->stream;

    if (dir != FLOW_TO_SERVER) return; /* only client data is inspected */

    if (a->proto == APP_UNKNOWN) a->proto = (uint8_t)classify(f->port[1]);
    if (a->proto == APP_NONE || a->done) return;

    int syn = (pkt->tcp_flags & TCP_SYN) != 0;
    uint32_t data_seq = pkt->seq + (syn ? 1 : 0); /* SYN takes one seq */

    if (!s->active) {
        if (!syn && pkt->wire_payload_len == 0) return;
        stream_init(s, data_seq);
    }
    if (pkt->wire_payload_len == 0) return;

    stream_insert(s, data_seq, pkt->payload, (uint32_t)pkt->payload_len,
                  (uint32_t)pkt->wire_payload_len);

    if (s->overlap_diff && !a->overlap_alerted) {
        a->overlap_alerted = 1;
        flow_alert(f, ts, ANOMALY_SID_STREAM_OVERLAP, 2,
                   "Stream: overlapping TCP data differs (possible evasion)",
                   ALERT_SOURCE_ANOMALY, pkt->payload, pkt->payload_len, pkt->truncated);
    }

    inspect_stream(f, ts, 0);
}

void engine_process_packet(const struct timeval *ts, const packet_t *pkt) {
    if (pkt->ip_version == 6) g_stats.ipv6++;
    if (pkt->vlan_count) g_stats.vlan++;
    if (pkt->truncated) g_stats.truncated_payloads++;

    flow_expire(ts);

    int dir;
    flow_t *f = flow_get(pkt, ts, &dir);
    if (!f) return;

    if (pkt->l4proto == L4_TCP) {
        g_stats.tcp++;
        handle_tcp(f, dir, ts, pkt);
    } else {
        g_stats.udp++; /* UDP flows are tracked; DNS inspection is Phase 3 */
    }
}

void engine_process_frame(int linktype, const struct timeval *ts,
                          const uint8_t *data, size_t caplen) {
    packet_t pkt;
    g_stats.packets++;

    decode_result_t r = decode_packet(linktype, data, caplen, &pkt);
    g_stats.decode[r]++;
    if (r != DECODE_OK) return;

    engine_process_packet(ts, &pkt);
}

/* ------------------------------------------------------------------ */

void engine_config_defaults(engine_config_t *cfg) {
    flow_config_defaults(&cfg->flow);
    cfg->stream.depth = 65536;
    cfg->stream.memcap = 64u * 1024 * 1024;
    cfg->stream.policy = OVERLAP_FIRST;
}

int engine_init(const engine_config_t *cfg) {
    stream_configure(&cfg->stream);
    return flow_init(&cfg->flow, on_flow_end);
}

void engine_shutdown(void) {
    flow_destroy();
}

void engine_print_stats(FILE *fp) {
    const engine_stats_t *s = &g_stats;
    const flow_stats_t *fs = flow_stats();
    const stream_stats_t *ss = stream_stats();

    fprintf(fp, "\n======== SimpleIDS Statistics ========\n");
    fprintf(fp, "  Packets captured    : %lu\n", s->packets);
    fprintf(fp, "  Decoded TCP / UDP   : %lu / %lu (IPv6 %lu, VLAN %lu)\n",
            s->tcp, s->udp, s->ipv6, s->vlan);
    for (int i = 1; i < DECODE_RESULT_COUNT; i++) {
        if (s->decode[i])
            fprintf(fp, "  Skipped (%s): %lu\n", decode_result_str((decode_result_t)i), s->decode[i]);
    }
    if (s->truncated_payloads)
        fprintf(fp, "  Truncated payloads  : %lu\n", s->truncated_payloads);
    fprintf(fp, "  Flows               : %lu created, peak %lu, %lu timed out, %lu evicted\n",
            fs->created, fs->active_peak, fs->timed_out, fs->evicted);
    fprintf(fp, "  TCP segments        : %lu (%lu out of order, %lu retransmitted)\n",
            ss->segments, ss->out_of_order, ss->retransmits);
    if (ss->overlaps || ss->gaps || ss->depth_reached || ss->memcap_drops)
        fprintf(fp, "  Stream events       : %lu overlaps (%lu differing), %lu gaps, "
                    "%lu past depth, %lu memcap drops\n",
                ss->overlaps, ss->overlap_diffs, ss->gaps, ss->depth_reached, ss->memcap_drops);
    fprintf(fp, "  Reassembly memory   : peak %.1f MiB of %.1f MiB\n",
            (double)ss->mem_peak / 1048576.0, (double)stream_get_config()->memcap / 1048576.0);
    fprintf(fp, "  HTTP requests       : %lu\n", s->http_requests);
    fprintf(fp, "  TLS ClientHellos    : %lu\n", s->tls_client_hellos);
    fprintf(fp, "  Signature alerts    : %lu\n", s->signature_alerts);
    fprintf(fp, "  Anomaly alerts      : %lu\n", s->anomaly_alerts);
    fprintf(fp, "=======================================\n");
}
