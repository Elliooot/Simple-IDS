#ifndef SIMPLEIDS_RULES_H
#define SIMPLEIDS_RULES_H

#include <stddef.h>
#include <stdint.h>

#include "simpleids/threshold.h"

/*
 * Rule language v2: a practical subset of Suricata (docs/ROADMAP.md §4.2).
 *
 *   alert http $EXTERNAL_NET any -> $HOME_NET any (
 *       msg:"SQLi UNION in URI"; flow:to_server,established;
 *       http.uri; content:"union"; nocase; content:"select"; distance:0; within:20;
 *       pcre:"/union\s+(all\s+)?select/i";
 *       classtype:web-application-attack; sid:2002; rev:2;)
 *
 * Header:  alert | pass | drop (drop alerts until IPS mode exists);
 *          protocol tcp, udp, ip, http, tls, dns; addresses and ports
 *          as any, a value, a list [a,b], a negation !x, a CIDR or a port
 *          range (1024:, :1023, 80:90), or a variable ($HOME_NET);
 *          direction -> or <> (either way round).
 * Payload: content (several per rule, !content negates, |41 42| hex),
 *          nocase, offset, depth, distance, within, startswith, endswith,
 *          fast_pattern; pcre:"/re/flags" (flags i s m x and R =
 *          relative to the previous match); sticky buffers (http.uri,
 *          tls.sni, ...; several per rule) and dotprefix.
 * Other:   flow (to_server, established, not_established, stateless,
 *          to_client), threshold, detection_filter, msg, sid, rev,
 *          priority, classtype, reference, metadata.
 *
 * A rule file may also define variables: "var NAME VALUE" (ipvar and
 * portvar are accepted too). A long rule may continue on the next line
 * after a trailing backslash.
 */

#define RULE_MSG_MAX        128
#define RULE_CONTENT_MAX    256   /* bytes of one content                */
#define RULE_PCRE_MAX       1024  /* characters of one pcre              */
#define RULE_MATCH_MAX      16    /* content + pcre conditions per rule  */
#define RULE_CLASSTYPE_MAX  48
#define RULE_LINE_MAX       8192  /* one rule, continuation lines joined */
#define RULE_VAR_MAX        64    /* variables per ruleset               */

/*
 * Where a condition is matched. RULE_BUF_RAW is the reassembled TCP
 * stream (or the UDP payload); the others are "sticky buffers" filled by
 * the application-layer parsers. A buffer keyword applies to the content
 * and pcre options that follow it.
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

typedef enum {
    RULE_ACTION_ALERT = 0,
    RULE_ACTION_DROP,           /* alerts; blocking is Phase 6 (IPS)    */
    RULE_ACTION_PASS            /* a match stops rule inspection of the
                                   flow (anomaly checks continue)      */
} rule_action_t;

typedef enum {
    RULE_PROTO_IP = 0,
    RULE_PROTO_TCP,
    RULE_PROTO_UDP,
    RULE_PROTO_HTTP,
    RULE_PROTO_TLS,
    RULE_PROTO_DNS,
    RULE_PROTO_COUNT
} rule_proto_t;

/*
 * When a rule is evaluated. Raw rules run over stream data or UDP
 * payloads; sticky-buffer rules run once per parsed message, with every
 * buffer of that message available at once.
 */
typedef enum {
    RULE_PHASE_TCP_STREAM = 0,  /* raw rules, reassembled TCP data      */
    RULE_PHASE_UDP,             /* raw rules, one UDP payload           */
    RULE_PHASE_HTTP_REQUEST,    /* request line + headers               */
    RULE_PHASE_HTTP_BODY,       /* rules that use http.request_body
                                   (header buffers are available too)  */
    RULE_PHASE_TLS_HELLO,
    RULE_PHASE_DNS_QUERY,       /* once per question                    */
    RULE_PHASE_COUNT
} rule_phase_t;

typedef enum { RULE_MATCH_CONTENT = 0, RULE_MATCH_PCRE } rule_match_type_t;

/* One content or pcre condition. */
typedef struct {
    uint8_t  type;              /* rule_match_type_t                    */
    uint8_t  buffer;            /* rule_buffer_t                        */
    uint8_t  negated;
    uint8_t  nocase;
    uint8_t  startswith, endswith;
    uint8_t  dotprefix;         /* match against "." + buffer           */
    uint8_t  fast_pattern;      /* chosen for the prefilter by the rule */
    uint8_t  relative;          /* distance/within, or pcre R           */
    uint8_t  has_offset, has_depth, has_distance, has_within;
    uint8_t  backtrack;         /* a later condition is relative to it  */
    int32_t  offset, depth, distance, within;
    uint8_t *data;              /* content bytes, or the pcre source    */
    size_t   len;
    void    *re;                /* compiled pcre2_code                  */
} rule_match_t;

typedef struct {
    uint8_t version;            /* 4 or 6                               */
    uint8_t prefix;             /* bits                                 */
    uint8_t addr[16];
} rule_cidr_t;

typedef struct {
    rule_cidr_t *pos, *neg;     /* no pos entries = any                 */
    uint16_t     npos, nneg;
} rule_addrs_t;

typedef struct {
    uint16_t lo, hi;
} rule_port_range_t;

typedef struct {
    rule_port_range_t *pos, *neg;
    uint16_t           npos, nneg;
} rule_ports_t;

enum {
    RULE_FLOW_TO_SERVER      = 1 << 0,
    RULE_FLOW_TO_CLIENT      = 1 << 1,
    RULE_FLOW_ESTABLISHED    = 1 << 2,
    RULE_FLOW_NOT_ESTABLISHED = 1 << 3,
    RULE_FLOW_STATELESS      = 1 << 4
};

typedef struct {
    int      sid;
    int      rev;
    int      priority;
    uint8_t  action;            /* rule_action_t                        */
    uint8_t  proto;             /* rule_proto_t                         */
    uint8_t  bidirectional;     /* <>                                   */
    uint8_t  flow;              /* RULE_FLOW_* bits                     */
    uint8_t  phase;             /* rule_phase_t (sticky-buffer rules)   */
    uint8_t  raw_tcp, raw_udp;  /* raw rule: applies to TCP / UDP data  */
    int8_t   fast_pattern;      /* index into m[], -1 when none         */
    int8_t   first_positive;    /* index of the first positive match    */
    char     msg[RULE_MSG_MAX];
    char     classtype[RULE_CLASSTYPE_MAX];
    rule_addrs_t src, dst;
    rule_ports_t sport, dport;
    rule_match_t m[RULE_MATCH_MAX];
    uint8_t  nm;
    uint32_t buffers;           /* bit per rule_buffer_t used           */
    threshold_t threshold;      /* threshold or detection_filter        */
    int      line;              /* where it was loaded from (lint)      */
    const char *file;
} rule_t;

typedef struct ruleset ruleset_t;

const char *rule_buffer_name(rule_buffer_t b);
const char *rule_proto_name(rule_proto_t p);
const char *rule_phase_name(rule_phase_t p);
const char *rule_action_name(rule_action_t a);

/* Default priority of a classtype (Suricata classification.config), or
 * -1 when the classtype is unknown. */
int rule_classtype_priority(const char *classtype);

/* ------------------------------------------------------------------ */
/* Variables                                                           */
/* ------------------------------------------------------------------ */

/*
 * Process-wide variable definitions (e.g. from the command line) copied
 * into every new ruleset. Built-in defaults: HOME_NET, EXTERNAL_NET,
 * HTTP_SERVERS, DNS_SERVERS = any; HTTP_PORTS = any (HTTP is detected on
 * every port). Returns 0, or -1 on a bad name or too many variables.
 */
int  rules_define_var(const char *name, const char *value);
void rules_clear_vars(void);

/* ------------------------------------------------------------------ */
/* Parsing and rulesets                                                */
/* ------------------------------------------------------------------ */

ruleset_t *ruleset_new(void);
void ruleset_free(ruleset_t *rs);

/* Define a variable in this ruleset (overrides the global value). */
int ruleset_set_var(ruleset_t *rs, const char *name, const char *value);

/*
 * Parse one rule. Variables are resolved in rs (NULL: global ones).
 *   returns  1  a rule was parsed into *out (release it with rule_free
 *               unless it is handed to ruleset_add)
 *   returns  0  blank line or comment
 *   returns -1  syntax error; a description is written into err
 * Inside quoted strings, \" \\ \; and \/ (pcre) are escapes. In content,
 * |41 42| is a run of hex bytes (write a literal pipe as |7C|).
 */
int rule_parse(ruleset_t *rs, const char *line, rule_t *out, char *err, size_t errlen);
void rule_free(rule_t *r);

/* Move a parsed rule into the set. Returns 0, or -1 when the sid is a
 * duplicate or memory runs out (the rule is then left to the caller). */
int ruleset_add(ruleset_t *rs, rule_t *r);

/*
 * Load a rules file into rs: rules, variable definitions, comments,
 * continuation lines. Lines that fail are reported on stderr
 * ("file:line: reason") and skipped. Returns the number of rules loaded,
 * or -1 if the file cannot be opened. *errors receives the number of
 * skipped lines.
 */
int ruleset_load_file(ruleset_t *rs, const char *path, int *errors);

/* Group rules by phase and build the prefilters. Must be called once
 * after loading and before matching. Returns 0 or -1 (out of memory). */
int ruleset_compile(ruleset_t *rs);

int ruleset_count(const ruleset_t *rs);
const rule_t *ruleset_rule(const ruleset_t *rs, int i);
const rule_t *ruleset_find(const ruleset_t *rs, int sid);

/*
 * Performance and semantic warnings for a compiled set (--test-rules):
 * rules without a usable fast pattern, very short fast patterns, raw
 * rules that scan every TCP stream, flow:to_client, drop actions.
 * Calls warn() once per warning and returns the number of warnings.
 */
typedef void (*rule_warn_fn)(const rule_t *r, const char *msg, void *ctx);
int ruleset_lint(const ruleset_t *rs, rule_warn_fn warn, void *ctx);

typedef struct {
    unsigned rules;
    unsigned prefiltered;       /* rules with a fast pattern           */
    unsigned always;            /* rules evaluated every time           */
    unsigned patterns;
    unsigned states;
    size_t   memory;
} rule_phase_info_t;

void ruleset_phase_info(const ruleset_t *rs, rule_phase_t p, rule_phase_info_t *out);

/* The set used by the engine. Swapping is atomic for a single-threaded
 * caller: call it between packets. Returns the previous set. */
ruleset_t *rules_set_active(ruleset_t *rs);
ruleset_t *rules_active(void);

/* ------------------------------------------------------------------ */
/* Matching                                                            */
/* ------------------------------------------------------------------ */

/* What is being inspected. Data always flows client -> server. */
typedef struct {
    uint8_t        l4;           /* RULE_PROTO_TCP or RULE_PROTO_UDP   */
    uint8_t        app;          /* RULE_PROTO_HTTP/TLS/DNS, or IP     */
    uint8_t        established;  /* see engine.c                       */
    const uint8_t *src, *dst;    /* 16 bytes; IPv4 in the first 4      */
    uint8_t        ip_version;
    uint16_t       sport, dport;
    const uint8_t *buf[RULE_BUF_COUNT];  /* NULL: not present          */
    size_t         len[RULE_BUF_COUNT];
} rule_input_t;

/* A rule matched. The match position is the first positive condition's
 * match in buffer `b` (0 when the rule has none). */
typedef void (*rule_hit_fn)(const rule_t *r, rule_buffer_t b, size_t match_off, void *ctx);

/*
 * Evaluate the rules of one phase: prefilter every available buffer,
 * then verify the candidates in load order, pass rules first. A
 * matching pass rule is reported and ends the evaluation. Returns the
 * number of matching rules.
 */
int rules_eval(const ruleset_t *rs, rule_phase_t phase, const rule_input_t *in,
               rule_hit_fn hit, void *ctx);

/* Does any raw rule of this phase apply to the input's protocols,
 * addresses and ports (regardless of content)? */
int rules_raw_applies(const ruleset_t *rs, rule_phase_t phase, const rule_input_t *in);

/* How far back a raw stream rescan must reach so that a match spanning
 * a segment boundary is found: the longest raw content when every raw
 * TCP rule is a single content, SIZE_MAX otherwise (rescan the whole
 * gap-free region). 0 without raw TCP rules. */
size_t rules_raw_span(const ruleset_t *rs);

typedef struct {
    unsigned long evaluations;   /* rules_eval calls                   */
    unsigned long candidates;    /* rules verified after the prefilter */
    unsigned long matches;
    unsigned long pcre_limit;    /* pcre stopped by its match limit    */
    unsigned long backtrack_limit;
} rules_stats_t;

const rules_stats_t *rules_stats(void);
void rules_reset_stats(void);

#endif
