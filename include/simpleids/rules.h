#ifndef SIMPLEIDS_RULES_H
#define SIMPLEIDS_RULES_H

#include <stddef.h>
#include <stdint.h>

#define RULE_MSG_MAX      128
#define RULE_CONTENT_MAX  256
#define RULE_PROTO_MAX    8

/*
 * Where a rule's content is matched. RULE_BUF_RAW is the reassembled TCP
 * stream (or the UDP payload); the others are "sticky buffers" filled by
 * the application-layer parsers. A buffer keyword in a rule (e.g.
 * http.uri;) must come before the content it applies to.
 */
typedef enum {
    RULE_BUF_RAW = 0,
    RULE_BUF_HTTP_METHOD,       /* http.method                         */
    RULE_BUF_HTTP_URI,          /* http.uri: decoded + path-normalized */
    RULE_BUF_HTTP_URI_RAW,      /* http.uri.raw: as sent                */
    RULE_BUF_HTTP_HEADER,       /* http.header: "Name: value\r\n" lines */
    RULE_BUF_HTTP_USER_AGENT,   /* http.user_agent                     */
    RULE_BUF_HTTP_HOST,         /* http.host: lower case, no port       */
    RULE_BUF_HTTP_COOKIE,       /* http.cookie                         */
    RULE_BUF_HTTP_REQUEST_BODY, /* http.request_body: de-chunked;
                                   URL-decoded for form posts          */
    RULE_BUF_TLS_SNI,           /* tls.sni                             */
    RULE_BUF_TLS_ALPN,          /* tls.alpn: protocols joined by ','   */
    RULE_BUF_JA3_HASH,          /* ja3.hash: 32 hex digits             */
    RULE_BUF_JA3_STRING,        /* ja3.string                          */
    RULE_BUF_JA4_HASH,          /* ja4.hash: e.g. t13d1516h2_..._...   */
    RULE_BUF_DNS_QUERY,         /* dns.query: dotted name              */
    RULE_BUF_COUNT
} rule_buffer_t;

typedef struct {
    int      sid;
    int      priority;
    char     msg[RULE_MSG_MAX];
    char     protocol[RULE_PROTO_MAX]; /* tcp, udp, ip, http, tls, dns     */
    int      dst_port;                 /* 0 = any                         */
    rule_buffer_t buffer;
    uint8_t  content[RULE_CONTENT_MAX];/* raw bytes after unescaping       */
    size_t   content_len;              /* always > 0 for a loaded rule     */
    int      nocase;
    int      startswith;               /* match must start the buffer      */
    int      endswith;                 /* match must end the buffer        */
    int      dotprefix;                /* match against "." + buffer        */
} rule_t;

/* Keyword of a buffer ("http.uri"), or "raw". */
const char *rule_buffer_name(rule_buffer_t b);

/*
 * Parse one line of a rules file.
 *   returns  1  a rule was parsed into *out
 *   returns  0  blank line or comment
 *   returns -1  syntax error; a description is written into err
 *
 * Supported syntax (a subset of Snort/Suricata):
 *   alert <tcp|udp|ip|http|tls|dns> <src> <sport> -> <dst> <any|port> (options)
 * Options: content:"..." (required, exactly one), msg:"...", sid:N
 * (required), nocase, startswith, endswith, priority:N, a sticky buffer
 * keyword before the content (http.uri, tls.sni, dns.query, ...; it must
 * fit the protocol), dotprefix after the buffer keyword, and the ignored
 * metadata keywords rev, classtype, reference, metadata.
 * Inside quoted strings, \" \\ and \; are escapes. In content, |41 42|
 * is a run of hex bytes (write a literal pipe as |7C|).
 */
int rule_parse(const char *line, rule_t *out, char *err, size_t errlen);

/*
 * Load every rule from a file into the global rule set.
 * Lines that fail to parse, or reuse a sid that is already loaded, are
 * reported on stderr and skipped. Returns the number of rules loaded
 * from this file, or -1 if the file cannot be opened.
 * *errors (if not NULL) receives the number of skipped lines.
 */
int rules_load_file(const char *path, int *errors);

/* Called once per rule that matches; match points at the first match. */
typedef void (*rule_hit_fn)(const rule_t *rule, const uint8_t *match, void *ctx);

/*
 * Run every raw-content rule that applies to this traffic over buf[0..len).
 *   l4:  "tcp" or "udp"; app: "http", "tls", "dns" or NULL.
 * A rule applies when its protocol is "ip", l4 or app, and its port is
 * any or dst_port. Calls hit() for each matching rule and returns the
 * number of matches.
 */
int rules_match(const uint8_t *buf, size_t len, const char *l4, const char *app,
                int dst_port, rule_hit_fn hit, void *ctx);

/*
 * Run every rule that uses sticky buffer `which` over buf[0..len). The
 * buffer implies the protocol; the port is still checked. `match` passed
 * to hit() always points into buf.
 */
int rules_match_buffer(rule_buffer_t which, const uint8_t *buf, size_t len,
                       int dst_port, rule_hit_fn hit, void *ctx);

/* Does any loaded raw-content rule apply to (l4, app, dst_port)? */
int rules_any_raw(const char *l4, const char *app, int dst_port);

/* Add an already-parsed rule (used by the loader and by tests).
 * Returns 0, or -1 when the sid is a duplicate or memory runs out. */
int rules_add(const rule_t *rule);

int  rules_count(void);

/* Longest content of any loaded raw rule (0 when none): a match can span
 * at most this many bytes, which bounds how far back a stream rescan goes. */
size_t rules_max_content_len(void);
void rules_free(void);

#endif
