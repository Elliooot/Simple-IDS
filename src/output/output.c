#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "simpleids/output.h"

#define PAYLOAD_LOG_MAX     256 /* source bytes of payload kept in the JSON log */
#define PAYLOAD_CONSOLE_MAX 120
#define RULE_CATEGORY_JSON_MAX 96
#define MSG_JSON_MAX        (128 * 6 + 1)

static FILE *g_log = NULL;
static int g_log_is_stdout = 0;
static int g_quiet = 0;
static unsigned long g_alerts = 0;

/* Log rotation: path, bytes in the current file, limits. */
static char g_path[1024];
static uint64_t g_size, g_next_rotate;
static uint64_t g_max_size;
static unsigned g_max_files = 5;
static output_stats_t g_ostats;

FILE *output_console(void) {
    return g_log_is_stdout ? stderr : stdout;
}

void output_set_quiet(int quiet) {
    g_quiet = quiet;
}

unsigned long output_alert_count(void) {
    return g_alerts;
}

static void reset_rotation_point(void) {
    g_next_rotate = g_max_size ? g_size + (g_size < g_max_size ? g_max_size - g_size : g_max_size)
                               : 0;
}

/* (Re)open g_path for appending and learn its current size. */
static int open_path(void) {
    g_log = fopen(g_path, "a");
    if (!g_log) return -1;
    struct stat st;
    g_size = fstat(fileno(g_log), &st) == 0 ? (uint64_t)st.st_size : 0;
    reset_rotation_point();
    return 0;
}

void output_set_rotation(uint64_t max_size, unsigned max_files) {
    g_max_size = max_size;
    g_max_files = max_files ? max_files : 1;
    reset_rotation_point();
}

/*
 * ids.log -> ids.log.1 -> ... -> ids.log.N (the oldest is removed), then
 * start a new ids.log. When a rename fails (e.g. no write permission on
 * the directory after dropping privileges), keep appending to the same
 * file and try again after another max_size bytes.
 */
static void rotate(void) {
    char from[sizeof(g_path) + 16], to[sizeof(g_path) + 16];
    fflush(g_log);
    snprintf(to, sizeof(to), "%s.%u", g_path, g_max_files);
    if (unlink(to) < 0 && errno != ENOENT) goto failed;
    for (unsigned i = g_max_files - 1; i >= 1; i--) {
        snprintf(from, sizeof(from), "%s.%u", g_path, i);
        snprintf(to, sizeof(to), "%s.%u", g_path, i + 1);
        if (rename(from, to) < 0 && errno != ENOENT) goto failed;
    }
    snprintf(to, sizeof(to), "%s.1", g_path);
    if (rename(g_path, to) < 0) goto failed;
    fclose(g_log);
    if (open_path() < 0) {
        fprintf(stderr, "Cannot reopen log file %s after rotation: %s (logging stopped)\n",
                g_path, strerror(errno));
        g_ostats.rotate_errors++;
        return;
    }
    g_ostats.rotations++;
    return;
failed:
    if (!g_ostats.rotate_errors++)
        fprintf(stderr, "Cannot rotate log file %s: %s (still writing to it)\n", g_path,
                strerror(errno));
    g_next_rotate = g_size + g_max_size;
}

/* Count bytes written; rotate once the file has grown past the limit. */
static void written(int n) {
    if (n < 0) {
        g_ostats.write_errors++;
        return;
    }
    g_size += (uint64_t)n;
    if (g_max_size && !g_log_is_stdout && g_size >= g_next_rotate) rotate();
}

const output_stats_t *output_stats(void) {
    g_ostats.log_bytes = g_size;
    return &g_ostats;
}

int output_reopen(void) {
    if (!g_log || g_log_is_stdout) return 0;
    /* Open the new file first: if that fails, keep the old one. */
    FILE *old = g_log;
    uint64_t old_size = g_size;
    if (open_path() < 0) {
        fprintf(stderr, "Cannot reopen log file %s: %s (still writing to the old one)\n",
                g_path, strerror(errno));
        g_log = old;
        g_size = old_size;
        reset_rotation_point();
        return -1;
    }
    fclose(old);
    return 0;
}

int output_log_chown(uid_t uid, gid_t gid) {
    if (!g_log || g_log_is_stdout) return 0;
    return fchown(fileno(g_log), uid, gid);
}

int output_has_log(void) {
    return g_log != NULL;
}

void output_event(const char *json_line) {
    if (!g_log) return;
    written(fprintf(g_log, "%s\n", json_line));
    if (g_log) fflush(g_log);
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
    if (strlen(path) >= sizeof(g_path)) {
        fprintf(stderr, "Log file name too long\n");
        return -1;
    }
    snprintf(g_path, sizeof(g_path), "%s", path);

    if (strcmp(path, OUTPUT_DEFAULT_LOG) == 0) {
        /* Create logs/ next to where we run (the repo root). */
        if (mkdir("logs", 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "Cannot create log directory 'logs': %s\n", strerror(errno));
            return -1;
        }
    }

    if (open_path() < 0) {
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
        char app[32] = "", cat[RULE_CATEGORY_JSON_MAX] = "";
        size_t plen = ev->data_len < PAYLOAD_LOG_MAX ? ev->data_len : PAYLOAD_LOG_MAX;

        json_escape(msg, sizeof(msg), (const uint8_t *)ev->msg, strlen(ev->msg));
        json_escape(payload, sizeof(payload), ev->data, plen);
        if (ev->app_proto) snprintf(app, sizeof(app), "\"app_proto\":\"%s\",", ev->app_proto);
        if (ev->category) {
            char esc[RULE_CATEGORY_JSON_MAX - 16];
            json_escape(esc, sizeof(esc), (const uint8_t *)ev->category, strlen(ev->category));
            snprintf(cat, sizeof(cat), "\"category\":\"%s\",", esc);
        }

        int n = fprintf(g_log,
                "{\"timestamp\":\"%s\",\"flow_id\":%llu,\"event_type\":\"alert\","
                "\"src_ip\":\"%s\",\"src_port\":%u,"
                "\"dest_ip\":\"%s\",\"dest_port\":%u,\"proto\":\"%s\",%s"
                "\"alert\":{\"action\":\"%s\",\"sid\":%d,\"rev\":%d,\"priority\":%d,%s"
                "\"source\":\"%s\",\"msg\":\"%s\"},"
                "\"payload\":\"%s\",\"payload_truncated\":%s}\n",
                ts, (unsigned long long)ev->flow_id,
                ev->src_ip, ev->src_port, ev->dst_ip, ev->dst_port,
                ev->proto ? ev->proto : "TCP", app,
                ev->action ? ev->action : "alert", ev->sid, ev->rev, ev->priority, cat,
                src_name, msg,
                payload, (plen < ev->data_len || ev->truncated) ? "true" : "false");
        fflush(g_log);
        written(n);
    }
}
