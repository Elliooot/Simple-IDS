#include <string.h>

#include "simpleids/anomaly.h"
#include "simpleids/engine.h"
#include "simpleids/http.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"
#include "simpleids/tls.h"

static engine_stats_t g_stats;
static int g_verbose = 0;

void engine_set_verbose(int verbose) {
    g_verbose = verbose;
}

const engine_stats_t *engine_stats(void) {
    return &g_stats;
}

void engine_reset(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}

/* Context handed to the rule / anomaly callbacks. */
typedef struct {
    const struct timeval *ts;
    const packet_t *pkt;
    const uint8_t *data;
    size_t data_len;
} hit_ctx_t;

static void on_rule_hit(const rule_t *r, void *vctx) {
    const hit_ctx_t *c = vctx;
    alert_event_t ev = {
        .ts = *c->ts, .pkt = c->pkt,
        .sid = r->sid, .priority = r->priority, .msg = r->msg,
        .source = ALERT_SOURCE_SIGNATURE,
        .data = c->data, .data_len = c->data_len,
    };
    g_stats.signature_alerts++;
    output_alert(&ev);
}

static void on_anomaly_hit(const anomaly_hit_t *h, void *vctx) {
    const hit_ctx_t *c = vctx;
    alert_event_t ev = {
        .ts = *c->ts, .pkt = c->pkt,
        .sid = h->sid, .priority = h->priority, .msg = h->msg,
        .source = ALERT_SOURCE_ANOMALY,
        .data = c->data, .data_len = c->data_len,
    };
    g_stats.anomaly_alerts++;
    output_alert(&ev);
}

static void inspect_http(const struct timeval *ts, const packet_t *pkt) {
    http_request_t req;
    if (http_parse_request(pkt->payload, pkt->payload_len, &req) < 0) return;

    g_stats.http_requests++;
    hit_ctx_t ctx = { ts, pkt, pkt->payload, pkt->payload_len };

    /* HTTP rules are written for port 80; 8080 uses the same set. */
    int n = rules_match(pkt->payload, pkt->payload_len, "tcp", 80, on_rule_hit, &ctx);
    n += anomaly_check(pkt->src_ip, ts->tv_sec, pkt->payload, pkt->payload_len,
                       on_anomaly_hit, &ctx);

    if (n == 0 && g_verbose) {
        fprintf(output_console(), "[clean] %s:%u -> %s:%u %.*s\n",
                pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port,
                (int)(req.uri_len > 80 ? 80 : req.uri_len), (const char *)req.uri);
    }
}

static void inspect_tls(const struct timeval *ts, const packet_t *pkt) {
    char sni[TLS_SNI_MAX];
    int n = tls_extract_sni(pkt->payload, pkt->payload_len, sni, sizeof(sni));
    if (n < 0) return;

    g_stats.tls_client_hellos++;
    hit_ctx_t ctx = { ts, pkt, (const uint8_t *)sni, (size_t)n };
    int hits = rules_match((const uint8_t *)sni, (size_t)n, "tcp", 443, on_rule_hit, &ctx);

    if (hits == 0 && g_verbose) {
        fprintf(output_console(), "[clean] TLS %s:%u -> %s:%u SNI=%s\n",
                pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port, sni);
    }
}

void engine_process_packet(const struct timeval *ts, const packet_t *pkt) {
    if (pkt->payload_len == 0) return;
    if (pkt->truncated) g_stats.truncated_payloads++;

    switch (pkt->dst_port) {
    case 80:
    case 8080:
        inspect_http(ts, pkt);
        break;
    case 443:
        inspect_tls(ts, pkt);
        break;
    default:
        break;
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

void engine_print_stats(FILE *fp) {
    const engine_stats_t *s = &g_stats;
    fprintf(fp, "\n======== SimpleIDS Statistics ========\n");
    fprintf(fp, "  Packets captured    : %lu\n", s->packets);
    fprintf(fp, "  Decoded (IPv4/TCP)  : %lu\n", s->decode[DECODE_OK]);
    for (int i = 1; i < DECODE_RESULT_COUNT; i++) {
        if (s->decode[i])
            fprintf(fp, "  Skipped (%s): %lu\n",
                    decode_result_str((decode_result_t)i), s->decode[i]);
    }
    if (s->truncated_payloads)
        fprintf(fp, "  Truncated payloads  : %lu\n", s->truncated_payloads);
    fprintf(fp, "  HTTP requests       : %lu\n", s->http_requests);
    fprintf(fp, "  TLS ClientHellos    : %lu\n", s->tls_client_hellos);
    fprintf(fp, "  Signature alerts    : %lu\n", s->signature_alerts);
    fprintf(fp, "  Anomaly alerts      : %lu\n", s->anomaly_alerts);
    fprintf(fp, "=======================================\n");
}
