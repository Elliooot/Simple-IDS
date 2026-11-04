#include <arpa/inet.h>
#include <string.h>

#include "simpleids/anomaly.h"
#include "simpleids/bytes.h"
#include "simpleids/dns.h"
#include "simpleids/engine.h"
#include "simpleids/http.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"
#include "simpleids/tls.h"

#define HTTP_MAX_HEADER  16384 /* give up waiting for CRLFCRLF after this */
#define HTTP_BODY_MAX    65536 /* request body bytes inspected            */
#define ALERT_CONTEXT    64    /* bytes logged before a signature match   */
#define DNS_PORT         53

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

static const char *app_name_of(app_proto_t p) {
    switch (p) {
    case APP_HTTP: return "http";
    case APP_TLS:  return "tls";
    case APP_DNS:  return "dns";
    default:       return NULL;
    }
}

static unsigned long alert_total(void) {
    return g_stats.signature_alerts + g_stats.anomaly_alerts;
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
        .flow_id = f->id, .app_proto = app_name_of((app_proto_t)f->app.proto),
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

/* An engine-level anomaly that fires at most once per flow. */
static void flow_anomaly(flow_t *f, const struct timeval *ts, int sid, int priority,
                         const char *msg, const uint8_t *data, size_t len, int truncated) {
    if (already_alerted(f, sid)) {
        g_stats.duplicate_alerts++;
        return;
    }
    flow_alert(f, ts, sid, priority, msg, ALERT_SOURCE_ANOMALY, data, len, truncated);
}

/* Run the rules of one sticky buffer. */
static void match_buffer(flow_t *f, const struct timeval *ts, rule_buffer_t b,
                         const void *data, size_t len, int truncated) {
    const uint8_t *p = data ? data : (const uint8_t *)"";
    hit_ctx_t ctx = { f, ts, p, p + len, truncated };
    rules_match_buffer(b, p, len, f->port[1], on_rule_hit, &ctx);
}

/* ------------------------------------------------------------------ */
/* Raw-content rules over the reassembled stream                       */
/* ------------------------------------------------------------------ */

/* Rescan the last (longest content - 1) bytes so that matches across
 * segment boundaries are found, but never across a gap. */
static void raw_scan(flow_t *f, const struct timeval *ts, uint32_t end) {
    flow_app_t *a = &f->app;
    stream_t *s = &f->stream;
    size_t back = rules_max_content_len();
    uint32_t from = a->scan_pos > back ? a->scan_pos - (uint32_t)(back ? back - 1 : 0) : 0;
    if (from < a->seg_start) from = a->seg_start;
    if (end > from) {
        hit_ctx_t ctx = { f, ts, s->buf + from, s->buf + end, 0 };
        rules_match(s->buf + from, end - from, "tcp", app_name_of((app_proto_t)a->proto),
                    f->port[1], on_rule_hit, &ctx);
    }
    a->scan_pos = end;
}

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */

static http_tx_t g_tx;                     /* the request being inspected */
static uint8_t g_body[HTTP_BODY_MAX];      /* de-chunked body             */
static uint8_t g_body_norm[HTTP_BODY_MAX]; /* URL-decoded form body       */

static const struct {
    unsigned flag;
    int      sid;
    const char *msg;
} NORM_EVENTS[] = {
    { HTTP_NORM_TRAVERSAL_ROOT, ANOMALY_SID_HTTP_TRAVERSAL,
      "HTTP: directory traversal above the web root" },
    { HTTP_NORM_DOUBLE_ENCODED, ANOMALY_SID_HTTP_DOUBLE_ENCODING,
      "HTTP: double URL encoding" },
    { HTTP_NORM_UNICODE, ANOMALY_SID_HTTP_U_ENCODING,
      "HTTP: IIS %u Unicode encoding" },
    { HTTP_NORM_OVERLONG_UTF8, ANOMALY_SID_HTTP_OVERLONG_UTF8,
      "HTTP: overlong UTF-8 encoding" },
    { HTTP_NORM_HPP_COMMENT, ANOMALY_SID_HTTP_HPP,
      "HTTP: parameter pollution splitting a SQL comment" },
    { HTTP_NORM_NUL, ANOMALY_SID_HTTP_NUL,
      "HTTP: NUL byte after URL decoding" },
};

static void norm_events(flow_t *f, const struct timeval *ts, unsigned flags,
                        const uint8_t *data, size_t len, int truncated) {
    for (size_t i = 0; i < sizeof(NORM_EVENTS) / sizeof(NORM_EVENTS[0]); i++)
        if (flags & NORM_EVENTS[i].flag)
            flow_anomaly(f, ts, NORM_EVENTS[i].sid, 2, NORM_EVENTS[i].msg, data, len, truncated);
}

/* Inspect one request header block; leaves the parsed request in g_tx. */
static int on_http_request(flow_t *f, const struct timeval *ts,
                           uint32_t start, uint32_t end, int truncated) {
    const uint8_t *req = f->stream.buf + start;
    size_t len = end - start;
    unsigned long before = alert_total();
    flow_names_t n;

    if (http_parse_tx(req, len, &g_tx) < 0) return -1;
    g_stats.http_requests++;
    flow_names(f, &n);

    hit_ctx_t ctx = { f, ts, req, req + len, truncated };
    anomaly_check(n.ip[0], ts->tv_sec, req, len, on_anomaly_hit, &ctx);
    norm_events(f, ts, g_tx.norm_flags, g_tx.uri_raw, g_tx.uri_raw_len, truncated);

    match_buffer(f, ts, RULE_BUF_HTTP_METHOD, g_tx.method, g_tx.method_len, truncated);
    match_buffer(f, ts, RULE_BUF_HTTP_URI_RAW, g_tx.uri_raw, g_tx.uri_raw_len, truncated);
    match_buffer(f, ts, RULE_BUF_HTTP_URI, g_tx.uri, g_tx.uri_len, truncated);
    match_buffer(f, ts, RULE_BUF_HTTP_HEADER, g_tx.header, g_tx.header_len, truncated);
    if (g_tx.has_user_agent)
        match_buffer(f, ts, RULE_BUF_HTTP_USER_AGENT, g_tx.user_agent, g_tx.user_agent_len,
                     truncated);
    if (g_tx.host_len)
        match_buffer(f, ts, RULE_BUF_HTTP_HOST, g_tx.host, g_tx.host_len, truncated);
    if (g_tx.has_cookie)
        match_buffer(f, ts, RULE_BUF_HTTP_COOKIE, g_tx.cookie, g_tx.cookie_len, truncated);

    if (alert_total() == before && g_verbose) {
        fprintf(output_console(), "[clean] %s:%u -> %s:%u %.*s %.*s\n",
                n.ip[0], f->port[0], n.ip[1], f->port[1],
                (int)g_tx.method_len, (const char *)g_tx.method,
                (int)(g_tx.uri_len > 80 ? 80 : g_tx.uri_len), (const char *)g_tx.uri);
    }
    return 0;
}

static void inspect_body(flow_t *f, const struct timeval *ts, const uint8_t *data,
                         size_t len, int truncated) {
    if (len == 0) return;
    g_stats.http_bodies++;
    if (f->app.body_form) {
        unsigned flags = 0;
        /* Form parameters are polluted the same way as query ones. */
        http_check_params(data, len, &flags);
        size_t n = http_decode_form(data, len, g_body_norm, sizeof(g_body_norm), &flags);
        norm_events(f, ts, flags & ~(unsigned)HTTP_NORM_TRUNCATED, data, len, truncated);
        data = g_body_norm;
        len = n;
    }
    match_buffer(f, ts, RULE_BUF_HTTP_REQUEST_BODY, data, len, truncated);
}

enum { HTTP_ST_HEADERS = 0, HTTP_ST_BODY = 1, HTTP_ST_RESYNC = 2 };

/* Data was lost: look for the next request line after the gap. */
static void http_resync(flow_app_t *a) {
    a->http_state = HTTP_ST_RESYNC;
    a->hdr_scan = a->seg_start;
}

/*
 * The body of the current request. Returns 1 when it has been inspected
 * and the next request starts at req_start, 0 to wait (or after a
 * truncated body, which also starts a resync).
 */
static int track_http_body(flow_t *f, const struct timeval *ts, uint32_t end, int last) {
    flow_app_t *a = &f->app;
    const uint8_t *buf = f->stream.buf;
    uint32_t start = a->body_start;

    if (!a->body_chunked) {
        uint32_t stop = end < a->body_end ? end : a->body_end;
        if (stop < a->body_end && !last) return 0;
        size_t n = stop - start;
        inspect_body(f, ts, buf + start, n > HTTP_BODY_MAX ? HTTP_BODY_MAX : n,
                     stop < a->body_end || n > HTTP_BODY_MAX);
        if (stop < a->body_end) {
            a->http_state = HTTP_ST_RESYNC;
            a->hdr_scan = end;
            return 0;
        }
        a->req_start = a->hdr_scan = a->body_end;
        return 1;
    }

    size_t outlen, consumed;
    int r = http_dechunk(buf + start, end - start, g_body, sizeof(g_body), &outlen, &consumed);
    if (r == 0 && !last) return 0;
    inspect_body(f, ts, g_body, outlen, r != 1);
    if (r < 0) { a->http_lost = 1; return 0; }
    if (r == 0) {
        a->http_state = HTTP_ST_RESYNC;
        a->hdr_scan = end;
        return 0;
    }
    a->req_start = a->hdr_scan = start + (uint32_t)consumed;
    return 1;
}

/*
 * Resync: candidates are the start of the current region and every line
 * start in it. Returns 1 when a request line was found at req_start.
 */
static int track_http_resync(flow_t *f, uint32_t end, int last) {
    flow_app_t *a = &f->app;
    const uint8_t *buf = f->stream.buf;
    uint32_t p = a->hdr_scan > a->seg_start ? a->hdr_scan : a->seg_start;

    for (; p < end; p++) {
        if (p != a->seg_start && buf[p - 1] != '\n') continue;
        size_t avail = end - p;
        if (!http_maybe_request(buf + p, avail)) continue;
        if (avail < 8 && !last) {
            a->hdr_scan = p;          /* decide when more data arrives */
            return 0;
        }
        http_request_t req;
        if (http_parse_request(buf + p, avail, &req) == 0) {
            a->req_start = a->hdr_scan = p;
            a->http_state = HTTP_ST_HEADERS;
            return 1;
        }
    }
    a->hdr_scan = end;
    return 0;
}

/*
 * Split the client stream into requests: request line + headers up to
 * CRLFCRLF, then a Content-Length or chunked body. `last` means no more
 * data follows in this region (end of flow, depth reached, or a gap):
 * an incomplete request is then inspected as it is. After a gap the
 * parser resyncs on the next request line; data that is not HTTP at a
 * request boundary ends the tracking.
 */
static void track_http(flow_t *f, const struct timeval *ts, uint32_t end, int last) {
    flow_app_t *a = &f->app;
    const uint8_t *buf = f->stream.buf;
    if (end >= stream_get_config()->depth) last = 1;

    while (!a->http_lost) {
        if (a->http_state == HTTP_ST_RESYNC) {
            if (!track_http_resync(f, end, last)) return;
            continue;
        }
        if (a->http_state == HTTP_ST_BODY) {
            if (a->body_start < a->seg_start) { http_resync(a); continue; }
            if (!track_http_body(f, ts, end, last)) return;
            a->http_state = HTTP_ST_HEADERS;
            continue;
        }

        uint32_t r = a->req_start;
        if (r < a->seg_start) { http_resync(a); continue; }
        if (r >= end) return;

        size_t avail = end - r;
        if (avail < 8 && !last && http_maybe_request(buf + r, avail)) return;
        http_request_t req;
        if (http_parse_request(buf + r, avail, &req) < 0) { a->http_lost = 1; return; }

        uint32_t from = a->hdr_scan > r + 3 ? a->hdr_scan - 3 : r;
        const uint8_t *e = bytes_find(buf + from, end - from, (const uint8_t *)"\r\n\r\n", 4, 0);
        if (!e) {
            a->hdr_scan = end;
            if (!last && avail < HTTP_MAX_HEADER) return;
            on_http_request(f, ts, r, end, 1); /* incomplete request */
            a->http_state = HTTP_ST_RESYNC;
            return;
        }

        uint32_t hdr_end = (uint32_t)(e - buf) + 4;
        if (on_http_request(f, ts, r, hdr_end, 0) < 0) { a->http_lost = 1; return; }

        long cl = g_tx.content_length;
        if (!g_tx.chunked && cl == HTTP_CL_INVALID) { a->http_lost = 1; return; }
        a->body_chunked = (uint8_t)g_tx.chunked;
        a->body_form = (uint8_t)http_is_form(&g_tx);
        a->body_start = hdr_end;
        if (a->body_chunked || cl > 0) {
            uint64_t be = (uint64_t)hdr_end + (uint64_t)(cl > 0 ? cl : 0);
            a->body_end = be > UINT32_MAX ? UINT32_MAX : (uint32_t)be;
            a->http_state = HTTP_ST_BODY;
        } else {
            a->req_start = a->hdr_scan = hdr_end;
        }
    }
}

/* ------------------------------------------------------------------ */
/* TLS                                                                 */
/* ------------------------------------------------------------------ */

static tls_hello_t g_hello;

static void inspect_tls(flow_t *f, const struct timeval *ts, uint32_t end, int final) {
    flow_app_t *a = &f->app;
    const uint8_t *buf = f->stream.buf;

    if (a->seg_start != 0) {        /* gap inside the ClientHello */
        a->parser_done = 1;
        return;
    }

    int r = tls_parse_client_hello(buf, end, &g_hello);
    if (r == 1 && !final && end < stream_get_config()->depth)
        return;                     /* the hello continues in a later segment */
    a->parser_done = 1;

    unsigned long before = alert_total();
    const char *sni = NULL;
    if (r == 0) {
        g_stats.tls_client_hellos++;
        tls_hello_t *h = &g_hello;
        if (h->sni_len) {
            sni = h->sni;
            match_buffer(f, ts, RULE_BUF_TLS_SNI, h->sni, h->sni_len, 0);
        }
        if (h->alpn_len) match_buffer(f, ts, RULE_BUF_TLS_ALPN, h->alpn, h->alpn_len, 0);
        match_buffer(f, ts, RULE_BUF_JA3_HASH, h->ja3_hash, strlen(h->ja3_hash), 0);
        match_buffer(f, ts, RULE_BUF_JA3_STRING, h->ja3, h->ja3_len, 0);
        match_buffer(f, ts, RULE_BUF_JA4_HASH, h->ja4, strlen(h->ja4), 0);
        if (h->ech) {
            g_stats.tls_ech++;
            flow_anomaly(f, ts, ANOMALY_SID_TLS_ECH, 3,
                         "TLS: Encrypted ClientHello in use (SNI shown is the public name)",
                         (const uint8_t *)h->sni, h->sni_len, 0);
        }
    } else {
        /* Incomplete or malformed: the SNI may still be readable. */
        static char partial[TLS_SNI_MAX];
        int n = tls_extract_sni(buf, end, partial, sizeof(partial));
        if (n < 0) return;
        g_stats.tls_client_hellos++;
        sni = partial;
        match_buffer(f, ts, RULE_BUF_TLS_SNI, partial, (size_t)n, 1);
    }

    if (alert_total() == before && g_verbose) {
        flow_names_t nm;
        flow_names(f, &nm);
        fprintf(output_console(), "[clean] TLS %s:%u -> %s:%u SNI=%s JA4=%s\n",
                nm.ip[0], f->port[0], nm.ip[1], f->port[1], sni ? sni : "-",
                r == 0 ? g_hello.ja4 : "-");
    }
}

/* ------------------------------------------------------------------ */
/* DNS                                                                 */
/* ------------------------------------------------------------------ */

#define DNS_LONG_NAME  100  /* characters: typical of DNS tunneling      */
#define DNS_LONG_LABEL 50

static void inspect_dns_message(flow_t *f, const struct timeval *ts,
                                const uint8_t *msg, size_t len, int truncated) {
    dns_message_t m;
    if (dns_parse_message(msg, len, &m) < 0 || m.response) return;

    for (int i = 0; i < m.nquestions; i++) {
        const dns_question_t *q = &m.q[i];
        unsigned long before = alert_total();
        g_stats.dns_queries++;
        match_buffer(f, ts, RULE_BUF_DNS_QUERY, q->name, q->name_len, truncated);
        if (q->name_len > DNS_LONG_NAME || q->longest_label > DNS_LONG_LABEL)
            flow_anomaly(f, ts, ANOMALY_SID_DNS_LONG_NAME, 2,
                         "DNS: unusually long query name (possible tunneling)",
                         (const uint8_t *)q->name, q->name_len, truncated);
        if (alert_total() == before && g_verbose) {
            flow_names_t nm;
            flow_names(f, &nm);
            fprintf(output_console(), "[clean] DNS %s:%u -> %s:%u %s type %u\n",
                    nm.ip[0], f->port[0], nm.ip[1], f->port[1], q->name, q->qtype);
        }
    }
}

/* DNS over TCP: each message is preceded by a 2-byte length. */
static void inspect_dns_tcp(flow_t *f, const struct timeval *ts, uint32_t end) {
    flow_app_t *a = &f->app;
    const uint8_t *buf = f->stream.buf;
    for (;;) {
        uint32_t r = a->req_start;
        if (r < a->seg_start) { a->parser_done = 1; return; }
        if (r + 2 > end) return;
        uint32_t mlen = rd_be16(buf + r);
        if (mlen == 0) { a->parser_done = 1; return; }
        if (r + 2 + mlen > end) return;
        inspect_dns_message(f, ts, buf + r + 2, mlen, 0);
        a->req_start = r + 2 + mlen;
    }
}

/* ------------------------------------------------------------------ */
/* Stream driver                                                       */
/* ------------------------------------------------------------------ */

/*
 * Application-layer detection by content, not port: HTTP on 443 or TLS
 * on 8080 is still parsed. Returns APP_UNKNOWN while too few bytes are
 * available to decide.
 */
static app_proto_t probe(const flow_t *f, const uint8_t *buf, uint32_t n, int final) {
    if (f->port[1] == DNS_PORT) return APP_DNS;
    if (n == 0) return final ? APP_NONE : APP_UNKNOWN;
    if (buf[0] == 0x16) {
        if (n < 2) return final ? APP_NONE : APP_UNKNOWN;
        return buf[1] == 0x03 ? APP_TLS : APP_NONE;
    }
    if (http_maybe_request(buf, n)) {
        http_request_t req;
        if (http_parse_request(buf, n, &req) == 0) return APP_HTTP;
        return final ? APP_NONE : APP_UNKNOWN;
    }
    return APP_NONE;
}

static void dispatch(flow_t *f, const struct timeval *ts, uint32_t end, int final) {
    flow_app_t *a = &f->app;

    if (a->proto == APP_UNKNOWN) {
        if (a->seg_start != 0) {
            a->proto = APP_NONE;            /* no start of stream to look at */
        } else {
            app_proto_t p = probe(f, f->stream.buf, end, final);
            if (p == APP_UNKNOWN) return;
            a->proto = (uint8_t)p;
        }
        a->raw_scan = (uint8_t)rules_any_raw("tcp", app_name_of((app_proto_t)a->proto),
                                             f->port[1]);
        if (a->proto == APP_NONE && !a->raw_scan) {
            a->done = 1;
            return;
        }
    }


    if (a->raw_scan) raw_scan(f, ts, end);
    if (!a->parser_done) {
        switch (a->proto) {
        case APP_HTTP: track_http(f, ts, end, final); break;
        case APP_TLS:  inspect_tls(f, ts, end, final); break;
        case APP_DNS:  inspect_dns_tcp(f, ts, end); break;
        default:       a->parser_done = 1; break;
        }
        if (a->http_lost) a->parser_done = 1;
    }
    /* Raw rules keep the stream alive; otherwise a finished parser ends it. */
    if (a->parser_done && !a->raw_scan) a->done = 1;
}

/*
 * Pull every newly contiguous run from the stream and inspect it. Before
 * a gap, the region in front of it is flushed (parsers see `last`), so a
 * request cut off by lost bytes is still inspected.
 */
static void inspect_stream(flow_t *f, const struct timeval *ts, int final) {
    stream_t *s = &f->stream;
    flow_app_t *a = &f->app;
    uint32_t start, end;
    int gap;

    while (!a->done && stream_next_run(s, final, &start, &end, &gap)) {
        if (gap) {
            if (a->data_end > a->seg_start) dispatch(f, ts, a->data_end, 1);
            if (a->done) break;
            a->seg_start = start;
        }
        dispatch(f, ts, end, 0);
        a->data_end = end;
    }

    /* Nothing more will arrive: let the parsers use what they have. */
    int at_depth = s->delivered >= stream_get_config()->depth;
    if (!a->done && (final || at_depth || s->closed) && s->buf) {
        dispatch(f, ts, a->data_end, 1);
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
    if (a->done) return;

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

static void handle_udp(flow_t *f, int dir, const struct timeval *ts, const packet_t *pkt) {
    int dns = dir == FLOW_TO_SERVER && f->port[1] == DNS_PORT;
    if (dns && f->app.proto == APP_UNKNOWN) f->app.proto = APP_DNS;

    if (pkt->payload_len) {
        hit_ctx_t ctx = { f, ts, pkt->payload, pkt->payload + pkt->payload_len, pkt->truncated };
        rules_match(pkt->payload, pkt->payload_len, "udp", dns ? "dns" : NULL,
                    pkt->dst_port, on_rule_hit, &ctx);
    }
    if (dns) inspect_dns_message(f, ts, pkt->payload, pkt->payload_len, pkt->truncated);
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
        g_stats.udp++;
        handle_udp(f, dir, ts, pkt);
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
    fprintf(fp, "  HTTP requests       : %lu (%lu bodies)\n", s->http_requests, s->http_bodies);
    fprintf(fp, "  TLS ClientHellos    : %lu (%lu with ECH)\n", s->tls_client_hellos, s->tls_ech);
    fprintf(fp, "  DNS queries         : %lu\n", s->dns_queries);
    fprintf(fp, "  Signature alerts    : %lu\n", s->signature_alerts);
    fprintf(fp, "  Anomaly alerts      : %lu\n", s->anomaly_alerts);
    fprintf(fp, "=======================================\n");
}
