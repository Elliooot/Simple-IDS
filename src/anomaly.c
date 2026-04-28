#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "../include/anomaly.h"

static char *strcasestr_custom(const char *haystack, const char *needle) {
    if (!*needle) return (char *) haystack;
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char) *needle)) {
            const char *h = haystack, *n = needle;
            while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
                h++; n++;
            }
            if (!*n) return (char *)haystack;
        }
    }
    return NULL;
}

// Rate Limit
#define MAX_IPS         1024
#define RATE_WINDOW_SEC 60 // Statistics window: 60 seconds
#define RATE_THRESHOLD  100 // More than 100 requests per minute = exception

typedef struct {
    char ip[16];
    int count;
    time_t window_start;
}ip_rate_t;

static ip_rate_t rate_table[MAX_IPS];
static int rate_count = 0;

// Find or create a rate record for a specific IP address
static ip_rate_t *get_rate_entry(const char *src_ip) {
    time_t now = time(NULL);

    for (int i = 0; i < rate_count; i++) {
        if (strcmp(rate_table[i].ip, src_ip) == 0) {
            // Reset if it exceeds the window size
            if (now - rate_table[i].window_start >= RATE_WINDOW_SEC) {
                rate_table[i].count = 0;
                rate_table[i].window_start = now;
            }
            return &rate_table[i];
        }
    }

    // New IP
    if (rate_count < MAX_IPS) {
        strncpy(rate_table[rate_count].ip, src_ip, 15);
        rate_table[rate_count].ip[15] = '\0';
        rate_table[rate_count].count = 0;
        rate_table[rate_count].window_start = now;
        return &rate_table[rate_count++];
    }

    return NULL; // Table's fulled
}

static int check_rate(const char *src_ip) {
    ip_rate_t *entry = get_rate_entry(src_ip);
    if (!entry) return 0;

    entry->count++;

    if (entry->count == RATE_THRESHOLD + 1) {
        printf("[ANOMALY] Rate limit exceeded: %s (%d req/%ds)\n",
                src_ip, entry->count, RATE_WINDOW_SEC);
        return 1;
    }
    if (entry->count > RATE_THRESHOLD && entry->count % 10 == 0) {
        printf("[ANOMALY] Rate sill high: %s (%d req\n)",
                src_ip, entry->count);
        return 1;
    }
    return 0;
}

// URL Length Anomaly
#define URL_LEN_THRESHOLD 1024

static int check_url_length(const char *payload) {
    const char *uri_start = NULL;

    if (strncmp(payload, "GET ", 4) == 0) uri_start = payload + 4;
    else if (strncmp(payload, "POST ", 5) == 0) uri_start = payload + 5;
    else if (strncmp(payload, "PUT ", 4) == 0) uri_start = payload + 4;
    else if (strncmp(payload, "DELETE ", 7) == 0) uri_start = payload + 7;
    else return 0;

    const char *uri_end = strstr(uri_start, " HTTP");
    if (!uri_end) return 0;

    int uri_len = (int) (uri_end - uri_start);
    if (uri_len > URL_LEN_THRESHOLD) {
        printf("[ANOMALY] Abnormally long URL: %d chars (threshold: %d)\n",
               uri_len, URL_LEN_THRESHOLD);
        return 1;
    }
    return 0;
}

// User-Agent Anomaly
static const char *MALICIOUS_UA[] = {
    "sqlmap", "nikto", "nmap", "acunetix",
    "masscan", "zgrab", "dirbuster", "gobuster",
    "wfuzz", "burpsuite", "havij", "pangolin",
    NULL
};

static int check_user_agent(const char *payload) {
    const char *ua_start = strstr(payload, "User-Agent: ");
    if (!ua_start) return 0;

    ua_start += 12;
    const char *ua_end = strstr(ua_start, "\r\n");
    if (!ua_end) return 0;

    int ua_len = (int)(ua_end - ua_start);

    if (ua_len < 4) {
        printf("[ANOMALY] Suspiciously short User-Agent: %.*s\n", ua_len, ua_start);
        return 1;
    }

    for (int i = 0; MALICIOUS_UA[i] != NULL; i++) {
        if (strcasestr_custom(ua_start, MALICIOUS_UA[i])) {
            printf("[ANOMALY] Malicious User-Agent detected: %.*s\n",
                   ua_len, ua_start);
            return 1;
        }
    }

    return 0;
}

// Public Interface
int anomaly_check(const char *src_ip, const char *payload, int payload_len) {
    int anomalies = 0;

    // 1. Rate Check
    anomalies += check_rate(src_ip);

    // 2. URL Length
    anomalies += check_url_length(payload);

    // 3. User-Agent
    anomalies += check_user_agent(payload);

    return anomalies;
}