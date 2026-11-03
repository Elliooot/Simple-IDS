#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "simpleids/output.h"

#define PAYLOAD_LOG_MAX     256 /* source bytes of payload kept in the JSON log */
#define PAYLOAD_CONSOLE_MAX 120
#define MSG_JSON_MAX        (128 * 6 + 1)

static FILE *g_log = NULL;
static int g_log_is_stdout = 0;
static int g_quiet = 0;
static unsigned long g_alerts = 0;

FILE *output_console(void) {
    return g_log_is_stdout ? stderr : stdout;
}

void output_set_quiet(int quiet) {
    g_quiet = quiet;
}

unsigned long output_alert_count(void) {
    return g_alerts;
}

int output_open(const char *path) {
    output_close();
    g_alerts = 0;
    if (!path) return 0;

    if (strcmp(path, "-") == 0) {
        g_log = stdout;
        g_log_is_stdout = 1;
        return 0;
    }

    if (strcmp(path, OUTPUT_DEFAULT_LOG) == 0) {
        /* Create logs/ next to where we run (the repo root). */
        if (mkdir("logs", 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "Cannot create log directory 'logs': %s\n", strerror(errno));
            return -1;
        }
    }

    g_log = fopen(path, "a");
    if (!g_log) {
        fprintf(stderr, "Cannot open log file %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

void output_close(void) {
    if (g_log && !g_log_is_stdout) fclose(g_log);
    else if (g_log) fflush(g_log);
    g_log = NULL;
    g_log_is_stdout = 0;
}

size_t json_escape(char *dst, size_t dstlen, const uint8_t *src, size_t srclen) {
    static const char hex[] = "0123456789abcdef";
    size_t o = 0, i;

    if (dstlen == 0) return 0;
    for (i = 0; i < srclen; i++) {
        uint8_t c = src[i];
        char tmp[7];
        size_t n;

        if (c == '"' || c == '\\') {
            tmp[0] = '\\'; tmp[1] = (char)c; n = 2;
        } else if (c == '\n') {
            tmp[0] = '\\'; tmp[1] = 'n'; n = 2;
        } else if (c == '\r') {
            tmp[0] = '\\'; tmp[1] = 'r'; n = 2;
        } else if (c == '\t') {
            tmp[0] = '\\'; tmp[1] = 't'; n = 2;
        } else if (c < 0x20 || c >= 0x7f) {
            /* Control characters, DEL and non-ASCII bytes: \u00XX keeps
             * the output pure ASCII, hence always valid UTF-8 / JSON. */
            memcpy(tmp, "\\u00", 4);
            tmp[4] = hex[c >> 4];
            tmp[5] = hex[c & 0x0f];
            n = 6;
        } else {
            tmp[0] = (char)c; n = 1;
        }

        if (o + n >= dstlen) break; /* keep room for NUL; never split an escape */
        memcpy(dst + o, tmp, n);
        o += n;
    }
    dst[o] = '\0';
    return i;
}

void format_timestamp(const struct timeval *tv, char *buf, size_t buflen) {
    time_t sec = tv->tv_sec;
    struct tm tm;
    gmtime_r(&sec, &tm);
    char base[32];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(buf, buflen, "%s.%06ldZ", base, (long)tv->tv_usec);
}

/* Printable preview for the console: one line, non-printables as '.' */
static void console_preview(char *dst, size_t dstlen, const uint8_t *src, size_t len) {
    size_t n = len < dstlen - 1 ? len : dstlen - 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = src[i];
        dst[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    dst[n] = '\0';
}

/* "1.2.3.4:80" or "[2001:db8::1]:80" */
static void fmt_endpoint(char *buf, size_t len, const char *ip, uint16_t port) {
    if (strchr(ip, ':')) snprintf(buf, len, "[%s]:%u", ip, port);
    else snprintf(buf, len, "%s:%u", ip, port);
}

void output_alert(const alert_event_t *ev) {
    char ts[40];
    const char *src_name = ev->source == ALERT_SOURCE_ANOMALY ? "anomaly" : "signature";

    g_alerts++;
    format_timestamp(&ev->ts, ts, sizeof(ts));

    if (!g_quiet) {
        FILE *con = output_console();
        char prev[PAYLOAD_CONSOLE_MAX + 1], src[64], dst[64];
        console_preview(prev, sizeof(prev), ev->data, ev->data_len);
        fmt_endpoint(src, sizeof(src), ev->src_ip, ev->src_port);
        fmt_endpoint(dst, sizeof(dst), ev->dst_ip, ev->dst_port);
        fprintf(con, "[ALERT] %s SID:%d P%d | %s\n", ts, ev->sid, ev->priority, ev->msg);
        fprintf(con, "        %s -> %s\n", src, dst);
        if (prev[0]) fprintf(con, "        %s\n", prev);
    }

    if (g_log) {
        char msg[MSG_JSON_MAX];
        char payload[PAYLOAD_LOG_MAX * 6 + 1];
        char app[32] = "";
        size_t plen = ev->data_len < PAYLOAD_LOG_MAX ? ev->data_len : PAYLOAD_LOG_MAX;

        json_escape(msg, sizeof(msg), (const uint8_t *)ev->msg, strlen(ev->msg));
        json_escape(payload, sizeof(payload), ev->data, plen);
        if (ev->app_proto) snprintf(app, sizeof(app), "\"app_proto\":\"%s\",", ev->app_proto);

        fprintf(g_log,
                "{\"timestamp\":\"%s\",\"flow_id\":%llu,\"event_type\":\"alert\","
                "\"src_ip\":\"%s\",\"src_port\":%u,"
                "\"dest_ip\":\"%s\",\"dest_port\":%u,\"proto\":\"TCP\",%s"
                "\"alert\":{\"sid\":%d,\"priority\":%d,\"source\":\"%s\",\"msg\":\"%s\"},"
                "\"payload\":\"%s\",\"payload_truncated\":%s}\n",
                ts, (unsigned long long)ev->flow_id,
                ev->src_ip, ev->src_port, ev->dst_ip, ev->dst_port, app,
                ev->sid, ev->priority, src_name, msg,
                payload, (plen < ev->data_len || ev->truncated) ? "true" : "false");
        fflush(g_log);
    }
}
