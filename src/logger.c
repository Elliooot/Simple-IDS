#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/logger.h"

static FILE *log_fp = NULL;
static int total = 0;
static int total_alert = 0;

static const char *level_str[] = { "INFO", "WARN", "ALERT" };

int logger_init(const char *filename) {
    if (filename) {
        log_fp = fopen(filename, "a");
        if (!log_fp) {
            fprintf(stderr, "Cannot open log file: %s\n", filename);
            return -1;
        }

        printf("Logging to: %s\n", filename);
    }
    return 0;
}

void logger_close() {
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

void logger_write(log_level_t level, const char *src_ip, int src_port,
                  int dst_port, int sid, const char *msg, const char *payload) {
    // Get Timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);

    total++;
    if (level == LOG_LEVEL_ALERT) total_alert++;

    // Screan output
    if (level == LOG_LEVEL_ALERT) {
        printf("[%s] [%s] SID:%d | %s\n", ts, level_str[level], sid, msg);
        printf("         From: %s:%d -> port %d\n", src_ip, src_port, dst_port);
        if (payload && payload[0])
            printf("         %.120s\n\n", payload);
    } else {
        printf("[%s] [%s] %s\n", ts, level_str[level], msg);
    }

    // File output (JSON)
    if (log_fp) {
        char safe_payload[256] = "";
        if (payload) {
            int j = 0;
            for (int i = 0; payload[i] && j < 250; i++) {
                if (payload[i] == '"' || payload[i] == '\\') safe_payload[j++] = '\\';
                if (payload[i] == '\r' || payload[i] == '\n') break;
                safe_payload[j++] = payload[i];
            }
            safe_payload[j] = '\0';
        }

        fprintf(log_fp,
            "{\"time\":\"%s\",\"level\":\"%s\","
            "\"src\":\"%s:%d\",\"dst_port\":%d,"
            "\"sid\":%d,\"msg\":\"%s\","
            "\"payload\":\"%s\"}\n",
            ts, level_str[level],
            src_ip, src_port, dst_port,
            sid, msg, safe_payload);
        fflush(log_fp);
    }
}

void logger_print_stats() {
    printf("\n======== SimpleIDS Statistics ========\n");
    printf("  Total events logged : %d\n", total);
    printf("  Alerts              : %d\n", total_alert);
    printf("  Clean               : %d\n", total - total_alert);
    printf("=======================================\n");
}