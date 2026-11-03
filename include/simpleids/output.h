#ifndef SIMPLEIDS_OUTPUT_H
#define SIMPLEIDS_OUTPUT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#include "simpleids/decode.h"

#define OUTPUT_DEFAULT_LOG "logs/ids.log"

typedef enum {
    ALERT_SOURCE_SIGNATURE = 0,
    ALERT_SOURCE_ANOMALY   = 1
} alert_source_t;

typedef struct {
    struct timeval ts;          /* packet (or flow end) timestamp       */
    const char    *src_ip;      /* client side for flow-based alerts    */
    const char    *dst_ip;
    uint16_t       src_port;
    uint16_t       dst_port;
    uint64_t       flow_id;     /* 0 when not tied to a flow            */
    const char    *app_proto;   /* "http", "tls" or NULL                */
    int            sid;
    int            priority;
    const char    *msg;
    alert_source_t source;
    const uint8_t *data;        /* inspected data (stream bytes or SNI) */
    size_t         data_len;
    int            truncated;   /* data is incomplete (snaplen / gap)   */
} alert_event_t;

/*
 * Open the JSON Lines alert log.
 *   path == NULL : no log file
 *   path == "-"  : JSON goes to stdout and human output to stderr
 * The parent directory of OUTPUT_DEFAULT_LOG is created when needed.
 * Returns 0, or -1 (with a message on stderr) when the file cannot be
 * opened.
 */
int  output_open(const char *path);
void output_close(void);

/* quiet != 0 suppresses the per-alert lines on the console. */
void output_set_quiet(int quiet);

/* Stream for human-readable messages (stdout, or stderr with "-"). */
FILE *output_console(void);

/* Write one alert to the console and to the JSON log. */
void output_alert(const alert_event_t *ev);

unsigned long output_alert_count(void);

/*
 * JSON-escape src[0..srclen) into dst (dstlen bytes, always
 * NUL-terminated). Quotes, backslashes and every byte outside printable
 * ASCII are escaped, so the result is valid JSON and valid UTF-8 even
 * for binary payloads. Stops early rather than splitting an escape.
 * Returns the number of source bytes consumed.
 */
size_t json_escape(char *dst, size_t dstlen, const uint8_t *src, size_t srclen);

/* Format tv as an ISO-8601 UTC timestamp with microseconds. */
void format_timestamp(const struct timeval *tv, char *buf, size_t buflen);

#endif
