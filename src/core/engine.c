#include <arpa/inet.h>
#include <string.h>

#include "simpleids/anomaly.h"
#include "simpleids/bytes.h"
#include "simpleids/dns.h"
#include "simpleids/engine.h"
#include "simpleids/http.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"
#include "simpleids/threshold.h"
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
    rules_reset_stats();
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

static void flow_alert(const flow_t *f, const struct timeval *ts, const rule_t *rule,
                       int sid, int priority, const char *msg, alert_source_t source,
                       const uint8_t *data, size_t len, int truncated) {
    flow_names_t n;
    flow_names(f, &n);
    alert_event_t ev = {
        .ts = *ts,
        .src_ip = n.ip[0], .dst_ip = n.ip[1],
        .src_port = f->port[0], .dst_port = f->port[1],
        .flow_id = f->id, .app_proto = app_name_of((app_proto_t)f->app.proto),
        .proto = f->l4proto == L4_UDP ? "UDP" : "TCP",
        .sid = sid, .priority = priority, .msg = msg, .source = source,
        .rev = rule ? rule->rev : 0,
        .category = rule && rule->classtype[0] ? rule->classtype : NULL,
        .action = rule ? rule_action_name((rule_action_t)rule->action) : NULL,
        .data = data, .data_len = len, .truncated = truncated,
    };
    if (source == ALERT_SOURCE_ANOMALY) g_stats.anomaly_alerts++;
    else g_stats.signature_alerts++;
    output_alert(&ev);
}

/* Once per flow and sid: used for anomalies and for raw stream rules,
 * where rescanning overlapping windows would report one match again.
 * Rules on parsed messages fire once per message instead. */
static int already_alerted(flow_t *f, int sid) {
    for (int i = 0; i < f->app.nsids; i++)
        if (f->app.sids[i] == sid) return 1;
    if (f->app.nsids < FLOW_MAX_ALERT_SIDS) f->app.sids[f->app.nsids++] = sid;
    return 0;
}

typedef struct {
    flow_t *f;
    const struct timeval *ts;
    const uint8_t *data;      /* anomalies: what to log             */
    const uint8_t *data_end;
    int truncated;
    const rule_input_t *in;   /* signatures: the inspected buffers  */
    int once_per_flow;        /* raw stream rules                   */
    int *msg_sids;            /* once per message (DNS questions)   */
    int *nmsg_sids;
} hit_ctx_t;

#define MSG_SIDS_MAX 32

/* Already alerted for this message? Records sid otherwise. */
static int seen_in_message(hit_ctx_t *c, int sid) {
    if (!c->msg_sids) return 0;
    for (int i = 0; i < *c->nmsg_sids; i++)
        if (c->msg_sids[i] == sid) return 1;
    if (*c->nmsg_sids < MSG_SIDS_MAX) c->msg_sids[(*c->nmsg_sids)++] = sid;
    return 0;
}

static void on_rule_hit(const rule_t *r, rule_buffer_t b, size_t off, void *vctx) {
    hit_ctx_t *c = vctx;
    flow_t *f = c->f;
    if (r->action == RULE_ACTION_PASS) {
        if (!f->app.passed) g_stats.passed_flows++;
        f->app.passed = 1;
        return;
    }
    if ((c->once_per_flow && already_alerted(f, r->sid)) || seen_in_message(c, r->sid)) {
        g_stats.duplicate_alerts++;
        return;
    }
    if (!threshold_check(r->sid, &r->threshold, f->addr[0], f->addr[1], c->ts->tv_sec)) {
        g_stats.thresholded++;
        return;
    }
    const uint8_t *buf = c->in->buf[b];
    size_t len = c->in->len[b];
    size_t from = off > ALERT_CONTEXT ? off - ALERT_CONTEXT : 0;
    if (from > len) from = len;
    flow_alert(f, c->ts, r, r->sid, r->priority, r->msg, ALERT_SOURCE_SIGNATURE,
               buf + from, len - from, c->truncated);
}

static void on_anomaly_hit(const anomaly_hit_t *h, void *vctx) {
    hit_ctx_t *c = vctx;
    flow_alert(c->f, c->ts, NULL, h->sid, h->priority, h->msg, ALERT_SOURCE_ANOMALY,
               c->data, (size_t)(c->data_end - c->data), c->truncated);
}

/* An engine-level anomaly that fires at most once per flow. */
static void flow_anomaly(flow_t *f, const struct timeval *ts, int sid, int priority,
                         const char *msg, const uint8_t *data, size_t len, int truncated) {
    if (already_alerted(f, sid)) {
        g_stats.duplicate_alerts++;
        return;
    }
    flow_alert(f, ts, NULL, sid, priority, msg, ALERT_SOURCE_ANOMALY, data, len, truncated);
}

/* ------------------------------------------------------------------ */
/* Rule inputs                                                         */
/* ------------------------------------------------------------------ */

static uint8_t rule_app(app_proto_t p) {
    switch (p) {
    case APP_HTTP: return RULE_PROTO_HTTP;
    case APP_TLS:  return RULE_PROTO_TLS;
    case APP_DNS:  return RULE_PROTO_DNS;
    default:       return RULE_PROTO_IP;
    }
}

/*
 * flow:established. TCP: every data-carrying state except a bare SYN
 * (a stream picked up mid-way counts, as in Suricata's midstream mode).
 * UDP: the server has answered at least once.
 */
static int flow_established(const flow_t *f) {
    if (f->l4proto == L4_UDP) return f->pkts[FLOW_TO_CLIENT] > 0;
    return f->tcp_state != TCP_STATE_SYN_SENT;
}

static void input_init(rule_input_t *in, const flow_t *f) {
    memset(in, 0, sizeof(*in));
    in->l4 = f->l4proto == L4_UDP ? RULE_PROTO_UDP : RULE_PROTO_TCP;
    in->app = rule_app((app_proto_t)f->app.proto);
    in->established = (uint8_t)flow_established(f);
    in->src = f->addr[0];
    in->dst = f->addr[1];
    in->ip_version = f->ip_version;
    in->sport = f->port[0];
    in->dport = f->port[1];
}

static void input_set(rule_input_t *in, rule_buffer_t b, const void *data, size_t len) {
    in->buf[b] = data ? data : (const uint8_t *)"";
    in->len[b] = len;
}

/* Evaluate one phase for a flow (nothing once a pass rule matched). */
static void eval_phase_ex(flow_t *f, const struct timeval *ts, rule_phase_t phase,
                          const rule_input_t *in, int truncated, int once_per_flow,
                          int *msg_sids, int *nmsg_sids) {
    if (f->app.passed) return;
    hit_ctx_t ctx = { f, ts, NULL, NULL, truncated, in, once_per_flow, msg_sids, nmsg_sids };
    rules_eval(rules_active(), phase, in, on_rule_hit, &ctx);
}

static void eval_phase(flow_t *f, const struct timeval *ts, rule_phase_t phase,
                       const rule_input_t *in, int truncated, int once_per_flow) {
    eval_phase_ex(f, ts, phase, in, truncated, once_per_flow, NULL, NULL);
}

/* ------------------------------------------------------------------ */
/* Raw-content rules over the reassembled stream                       */
/* ------------------------------------------------------------------ */

/* Rescan enough of the already-scanned data that a match crossing a
 * segment boundary is found (the longest raw content minus one, or the
 * whole region for multi-condition rules), but never across a gap. */
static void raw_scan(flow_t *f, const struct timeval *ts, uint32_t end) {
    flow_app_t *a = &f->app;
    stream_t *s = &f->stream;
    size_t back = rules_raw_span(rules_active());
    uint32_t from = a->seg_start;
    if (back != SIZE_MAX && a->scan_pos > back)
        from = a->scan_pos - (uint32_t)(back ? back - 1 : 0);
    if (from < a->seg_start) from = a->seg_start;
    if (end > from) {
        rule_input_t in;
        input_init(&in, f);
        input_set(&in, RULE_BUF_RAW, s->buf + from, end - from);
        eval_phase(f, ts, RULE_PHASE_TCP_STREAM, &in, 0, 1);
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

/* Rule input with every buffer of the request in g_tx. */
static void http_input(rule_input_t *in, const flow_t *f) {
    input_init(in, f);
    input_set(in, RULE_BUF_HTTP_METHOD, g_tx.method, g_tx.method_len);
    input_set(in, RULE_BUF_HTTP_URI_RAW, g_tx.uri_raw, g_tx.uri_raw_len);
    input_set(in, RULE_BUF_HTTP_URI, g_tx.uri, g_tx.uri_len);
    input_set(in, RULE_BUF_HTTP_HEADER, g_tx.header, g_tx.header_len);
    if (g_tx.has_user_agent)
        input_set(in, RULE_BUF_HTTP_USER_AGENT, g_tx.user_agent, g_tx.user_agent_len);
    if (g_tx.host_len) input_set(in, RULE_BUF_HTTP_HOST, g_tx.host, g_tx.host_len);
    if (g_tx.has_cookie) input_set(in, RULE_BUF_HTTP_COOKIE, g_tx.cookie, g_tx.cookie_len);
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

    hit_ctx_t ctx = { f, ts, req, req + len, truncated, NULL, 0, NULL, NULL };
    anomaly_check(n.ip[0], ts->tv_sec, req, len, on_anomaly_hit, &ctx);
    norm_events(f, ts, g_tx.norm_flags, g_tx.uri_raw, g_tx.uri_raw_len, truncated);

    rule_input_t in;
    http_input(&in, f);
    eval_phase(f, ts, RULE_PHASE_HTTP_REQUEST, &in, truncated, 0);

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
    /* Body rules may also use the request's header buffers. g_tx may
     * hold another flow's request by now, so parse this one again. */
    const flow_app_t *a = &f->app;
    if (a->body_start <= a->req_start ||
        http_parse_tx(f->stream.buf + a->req_start, a->body_start - a->req_start, &g_tx) < 0)
        return;
    if (f->app.body_form) {
        unsigned flags = 0;
        /* Form parameters are polluted the same way as query ones. */
        http_check_params(data, len, &flags);
        size_t n = http_decode_form(data, len, g_body_norm, sizeof(g_body_norm), &flags);
        norm_events(f, ts, flags & ~(unsigned)HTTP_NORM_TRUNCATED, data, len, truncated);
        data = g_body_norm;
        len = n;
    }
    rule_input_t in;
    http_input(&in, f);
    input_set(&in, RULE_BUF_HTTP_REQUEST_BODY, data, len);
    eval_phase(f, ts, RULE_PHASE_HTTP_BODY, &in, truncated, 0);
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
    rule_input_t in;
    input_init(&in, f);
    if (r == 0) {
        g_stats.tls_client_hellos++;
        tls_hello_t *h = &g_hello;
        if (h->sni_len) {
            sni = h->sni;
            input_set(&in, RULE_BUF_TLS_SNI, h->sni, h->sni_len);
        }
        if (h->alpn_len) input_set(&in, RULE_BUF_TLS_ALPN, h->alpn, h->alpn_len);
        input_set(&in, RULE_BUF_JA3_HASH, h->ja3_hash, strlen(h->ja3_hash));
        input_set(&in, RULE_BUF_JA3_STRING, h->ja3, h->ja3_len);
        input_set(&in, RULE_BUF_JA4_HASH, h->ja4, strlen(h->ja4));
        eval_phase(f, ts, RULE_PHASE_TLS_HELLO, &in, 0, 0);
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
        input_set(&in, RULE_BUF_TLS_SNI, partial, (size_t)n);
        eval_phase(f, ts, RULE_PHASE_TLS_HELLO, &in, 1, 0);
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

    /* One alert per rule and message, however many questions match. */
    int msg_sids[MSG_SIDS_MAX], nmsg_sids = 0;

    for (int i = 0; i < m.nquestions; i++) {
        const dns_question_t *q = &m.q[i];
        unsigned long before = alert_total();
        g_stats.dns_queries++;
        rule_input_t in;
        input_init(&in, f);
        input_set(&in, RULE_BUF_DNS_QUERY, q->name, q->name_len);
        eval_phase_ex(f, ts, RULE_PHASE_DNS_QUERY, &in, truncated, 0, msg_sids, &nmsg_sids);
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
        rule_input_t in;
        input_init(&in, f);
        a->raw_scan = (uint8_t)rules_raw_applies(rules_active(), RULE_PHASE_TCP_STREAM, &in);
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
        flow_alert(f, ts, NULL, ANOMALY_SID_STREAM_OVERLAP, 2,
                   "Stream: overlapping TCP data differs (possible evasion)",
                   ALERT_SOURCE_ANOMALY, pkt->payload, pkt->payload_len, pkt->truncated);
    }

    inspect_stream(f, ts, 0);
}

static void handle_udp(flow_t *f, int dir, const struct timeval *ts, const packet_t *pkt) {
    int dns = dir == FLOW_TO_SERVER && f->port[1] == DNS_PORT;
    if (dns && f->app.proto == APP_UNKNOWN) f->app.proto = APP_DNS;

    /* Raw UDP rules see each client -> server payload once. */
    if (pkt->payload_len && dir == FLOW_TO_SERVER) {
        rule_input_t in;
        input_init(&in, f);
        input_set(&in, RULE_BUF_RAW, pkt->payload, pkt->payload_len);
        eval_phase(f, ts, RULE_PHASE_UDP, &in, pkt->truncated, 0);
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
    const rules_stats_t *rst = rules_stats();
    fprintf(fp, "  Rule evaluations    : %lu (%lu candidates after prefilter, %lu matches)\n",
            rst->evaluations, rst->candidates, rst->matches);
    if (rst->pcre_limit || rst->backtrack_limit)
        fprintf(fp, "  Rule limits hit     : %lu pcre match limit, %lu backtracking budget\n",
                rst->pcre_limit, rst->backtrack_limit);
    if (s->thresholded || s->passed_flows)
        fprintf(fp, "  Suppressed          : %lu by threshold, %lu flows passed\n",
                s->thresholded, s->passed_flows);
    fprintf(fp, "  Signature alerts    : %lu\n", s->signature_alerts);
    fprintf(fp, "  Anomaly alerts      : %lu\n", s->anomaly_alerts);
    fprintf(fp, "=======================================\n");
}
