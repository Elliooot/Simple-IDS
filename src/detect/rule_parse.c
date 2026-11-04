#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "ruleset_int.h"

#define TOKEN_MAX    1024
#define KEYWORD_MAX  32
#define VAR_DEPTH    8      /* nested variable references            */
#define LIST_MAX     256    /* addresses or port ranges in one set   */

/* ------------------------------------------------------------------ */
/* Names                                                               */
/* ------------------------------------------------------------------ */

/* Sticky buffers: keyword and the protocol a rule using it must declare. */
static const struct {
    const char  *name;
    rule_proto_t proto;
} BUFFERS[RULE_BUF_COUNT] = {
    [RULE_BUF_RAW]               = { "raw",               RULE_PROTO_IP },
    [RULE_BUF_HTTP_METHOD]       = { "http.method",       RULE_PROTO_HTTP },
    [RULE_BUF_HTTP_URI]          = { "http.uri",          RULE_PROTO_HTTP },
    [RULE_BUF_HTTP_URI_RAW]      = { "http.uri.raw",      RULE_PROTO_HTTP },
    [RULE_BUF_HTTP_HEADER]       = { "http.header",       RULE_PROTO_HTTP },
    [RULE_BUF_HTTP_USER_AGENT]   = { "http.user_agent",   RULE_PROTO_HTTP },
    [RULE_BUF_HTTP_HOST]         = { "http.host",         RULE_PROTO_HTTP },
    [RULE_BUF_HTTP_COOKIE]       = { "http.cookie",       RULE_PROTO_HTTP },
    [RULE_BUF_HTTP_REQUEST_BODY] = { "http.request_body", RULE_PROTO_HTTP },
    [RULE_BUF_TLS_SNI]           = { "tls.sni",           RULE_PROTO_TLS },
    [RULE_BUF_TLS_ALPN]          = { "tls.alpn",          RULE_PROTO_TLS },
    [RULE_BUF_JA3_HASH]          = { "ja3.hash",          RULE_PROTO_TLS },
    [RULE_BUF_JA3_STRING]        = { "ja3.string",        RULE_PROTO_TLS },
    [RULE_BUF_JA4_HASH]          = { "ja4.hash",          RULE_PROTO_TLS },
    [RULE_BUF_DNS_QUERY]         = { "dns.query",         RULE_PROTO_DNS },
};

static const char *const PROTO_NAMES[RULE_PROTO_COUNT] = {
    "ip", "tcp", "udp", "http", "tls", "dns"
};

static const char *const PHASE_NAMES[RULE_PHASE_COUNT] = {
    "tcp-stream", "udp", "http-request", "http-body", "tls-hello", "dns-query"
};

const char *rule_buffer_name(rule_buffer_t b) {
    return (unsigned)b < RULE_BUF_COUNT ? BUFFERS[b].name : "?";
}

const char *rule_proto_name(rule_proto_t p) {
    return (unsigned)p < RULE_PROTO_COUNT ? PROTO_NAMES[p] : "?";
}

const char *rule_phase_name(rule_phase_t p) {
    return (unsigned)p < RULE_PHASE_COUNT ? PHASE_NAMES[p] : "?";
}

const char *rule_action_name(rule_action_t a) {
    switch (a) {
    case RULE_ACTION_ALERT: return "alert";
    case RULE_ACTION_DROP:  return "drop";
    case RULE_ACTION_PASS:  return "pass";
    }
    return "?";
}

static int find_buffer(const char *kw) {
    for (int i = 1; i < RULE_BUF_COUNT; i++)
        if (strcmp(kw, BUFFERS[i].name) == 0) return i;
    return -1;
}

/* Suricata's classification.config: name and default priority. */
static const struct {
    const char *name;
    int priority;
} CLASSTYPES[] = {
    { "not-suspicious", 3 },          { "unknown", 3 },
    { "bad-unknown", 2 },             { "attempted-recon", 2 },
    { "successful-recon-limited", 2 }, { "successful-recon-largescale", 2 },
    { "attempted-dos", 2 },           { "successful-dos", 2 },
    { "attempted-user", 1 },          { "unsuccessful-user", 1 },
    { "successful-user", 1 },         { "attempted-admin", 1 },
    { "successful-admin", 1 },        { "rpc-portmap-decode", 2 },
    { "shellcode-detect", 1 },        { "string-detect", 3 },
    { "suspicious-filename-detect", 2 }, { "suspicious-login", 2 },
    { "system-call-detect", 2 },      { "tcp-connection", 4 },
    { "trojan-activity", 1 },         { "unusual-client-port-connection", 2 },
    { "network-scan", 3 },            { "denial-of-service", 2 },
    { "non-standard-protocol", 2 },   { "protocol-command-decode", 3 },
    { "web-application-activity", 2 }, { "web-application-attack", 1 },
    { "misc-activity", 3 },           { "misc-attack", 2 },
    { "icmp-event", 3 },              { "inappropriate-content", 1 },
    { "policy-violation", 1 },        { "default-login-attempt", 2 },
    { "targeted-activity", 1 },       { "exploit-kit", 1 },
    { "external-ip-check", 2 },       { "domain-c2", 1 },
    { "credential-theft", 1 },        { "social-engineering", 2 },
    { "coin-mining", 2 },             { "command-and-control", 1 },
};

int rule_classtype_priority(const char *classtype) {
    for (size_t i = 0; i < sizeof(CLASSTYPES) / sizeof(CLASSTYPES[0]); i++)
        if (strcmp(classtype, CLASSTYPES[i].name) == 0) return CLASSTYPES[i].priority;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Variables                                                           */
/* ------------------------------------------------------------------ */

static const rule_var_t DEFAULT_VARS[] = {
    { "HOME_NET", "any" },
    { "EXTERNAL_NET", "any" },
    { "HTTP_SERVERS", "$HOME_NET" },
    { "DNS_SERVERS", "$HOME_NET" },
    { "HTTP_PORTS", "any" },
};

static rule_var_t g_vars[RULE_VAR_MAX];
static int g_nvars;

static int valid_var_name(const char *name) {
    size_t n = strlen(name);
    if (n == 0 || n >= RULE_VAR_NAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_'))
            return 0;
    }
    return 1;
}

static int set_var(rule_var_t *vars, int *n, const char *name, const char *value) {
    if (!valid_var_name(name) || strlen(value) >= RULE_VAR_VALUE_MAX || value[0] == '\0')
        return -1;
    int i;
    for (i = 0; i < *n; i++)
        if (strcmp(vars[i].name, name) == 0) break;
    if (i == *n) {
        if (*n == RULE_VAR_MAX) return -1;
        (*n)++;
    }
    snprintf(vars[i].name, sizeof(vars[i].name), "%s", name);
    snprintf(vars[i].value, sizeof(vars[i].value), "%s", value);
    return 0;
}

int rules_define_var(const char *name, const char *value) {
    return set_var(g_vars, &g_nvars, name, value);
}

void rules_clear_vars(void) {
    g_nvars = 0;
}

int ruleset_set_var(ruleset_t *rs, const char *name, const char *value) {
    return set_var(rs->vars, &rs->nvars, name, value);
}

const char *ruleset_var(const ruleset_t *rs, const char *name) {
    if (rs)
        for (int i = 0; i < rs->nvars; i++)
            if (strcmp(rs->vars[i].name, name) == 0) return rs->vars[i].value;
    for (int i = 0; i < g_nvars; i++)
        if (strcmp(g_vars[i].name, name) == 0) return g_vars[i].value;
    for (size_t i = 0; i < sizeof(DEFAULT_VARS) / sizeof(DEFAULT_VARS[0]); i++)
        if (strcmp(DEFAULT_VARS[i].name, name) == 0) return DEFAULT_VARS[i].value;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Parsing helpers. Every copy is bounded by the destination size.     */
/* ------------------------------------------------------------------ */

__attribute__((format(printf, 3, 4)))
static void set_err(char *err, size_t errlen, const char *fmt, ...) {
    if (!err || errlen == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static int is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void skip_ws(const char **p) {
    while (is_space(**p)) (*p)++;
}

/* Copy the next header token into buf. Spaces inside [...] belong to the
 * token. Returns 0, or -1 if missing, unbalanced or too long. */
static int next_token(const char **p, char *buf, size_t bufsize) {
    skip_ws(p);
    size_t n = 0;
    int depth = 0;
    while (**p && (depth > 0 || (!is_space(**p) && **p != '('))) {
        char c = *(*p)++;
        if (c == '[') depth++;
        else if (c == ']' && --depth < 0) return -1;
        if (n + 1 >= bufsize) return -1;
        buf[n++] = c;
    }
    buf[n] = '\0';
    return n > 0 && depth == 0 ? 0 : -1;
}

/* Parse a decimal integer in [min, max]; an optional leading '-'. */
static int parse_int(const char *s, long min, long max, long *out) {
    int neg = 0;
    while (is_space(*s)) s++;
    if (*s == '-') { neg = 1; s++; }
    size_t len = 0;
    long v = 0;
    while (s[len] >= '0' && s[len] <= '9') {
        if (len >= 10) return -1;
        v = v * 10 + (s[len] - '0');
        len++;
    }
    const char *e = s + len;
    while (is_space(*e)) e++;
    if (len == 0 || *e != '\0') return -1;
    if (neg) v = -v;
    if (v < min || v > max) return -1;
    *out = v;
    return 0;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

typedef enum { Q_TEXT = 0, Q_CONTENT, Q_PCRE } quote_mode_t;

/*
 * Parse a quoted string starting at the opening quote. Escapes \" \\ \;
 * always; Q_CONTENT adds |xx xx| byte runs; Q_PCRE keeps every other
 * backslash sequence as it is (\s, \d, \/ ... belong to the regex).
 * Writes at most cap bytes into out. Returns 0 or -1 (err set).
 */
static int parse_quoted(const char **p, uint8_t *out, size_t cap, size_t *outlen,
                        quote_mode_t mode, char *err, size_t errlen) {
    const char *s = *p;
    size_t n = 0;
    int in_hex = 0;

    if (*s != '"') {
        set_err(err, errlen, "expected '\"'");
        return -1;
    }
    s++;

    for (;;) {
        char c = *s;
        if (c == '\0' || c == '\n' || c == '\r') {
            set_err(err, errlen, "unterminated string");
            return -1;
        }
        if (in_hex) {
            if (c == '|') { in_hex = 0; s++; continue; }
            if (c == ' ') { s++; continue; }
            int hi = hex_val(s[0]), lo = hex_val(s[1]);
            if (hi < 0 || lo < 0) {
                set_err(err, errlen, "bad hex byte in |...|");
                return -1;
            }
            if (n >= cap) goto too_long;
            out[n++] = (uint8_t)(hi << 4 | lo);
            s += 2;
            continue;
        }
        if (c == '"') { s++; break; }
        if (c == '|' && mode == Q_CONTENT) { in_hex = 1; s++; continue; }
        if (c == '\\') {
            char e = s[1];
            if (e == '"' || e == ';' || (e == '\\' && mode != Q_PCRE)) {
                c = e;
                s++;
            } else if (mode == Q_PCRE && e != '\0') {
                if (n + 2 > cap) goto too_long;
                out[n++] = '\\';
                out[n++] = (uint8_t)e;
                s += 2;
                continue;
            } else {
                set_err(err, errlen, "unsupported escape '\\%c'", e ? e : '0');
                return -1;
            }
        }
        if (n >= cap) goto too_long;
        out[n++] = (uint8_t)c;
        s++;
    }
    if (in_hex) {
        set_err(err, errlen, "unterminated |...| hex block");
        return -1;
    }
    *outlen = n;
    *p = s;
    return 0;

too_long:
    set_err(err, errlen, "string longer than %zu bytes", cap);
    return -1;
}

/* Read an unquoted option value up to ';' or ')' (trailing spaces trimmed). */
static int parse_bare(const char **p, char *buf, size_t bufsize) {
    const char *s = *p;
    size_t n = 0;
    while (*s && *s != ';' && *s != ')') {
        if (n + 1 >= bufsize) return -1;
        buf[n++] = *s++;
    }
    while (n > 0 && is_space(buf[n - 1])) n--;
    buf[n] = '\0';
    *p = s;
    return 0;
}

/* Split s at top-level commas (not inside [...]); calls fn on each part. */
typedef int (*part_fn)(const char *part, size_t len, void *ctx);

static int split_list(const char *s, size_t len, part_fn fn, void *ctx) {
    size_t start = 0;
    int depth = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i < len && s[i] == '[') depth++;
        else if (i < len && s[i] == ']') depth--;
        else if (i == len || (s[i] == ',' && depth == 0)) {
            if (fn(s + start, i - start, ctx) < 0) return -1;
            start = i + 1;
        }
    }
    return 0;
}

/* Trim spaces from [s, s+len). */
static void trim(const char **s, size_t *len) {
    while (*len && is_space(**s)) { (*s)++; (*len)--; }
    while (*len && is_space((*s)[*len - 1])) (*len)--;
}

/* ------------------------------------------------------------------ */
/* Addresses and ports                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    const ruleset_t *rs;
    int   is_port;
    int   neg;
    int   depth;
    int   any_pos;
    void *set;          /* rule_addrs_t * or rule_ports_t * */
    char *err;
    size_t errlen;
} set_ctx_t;

static int push(void **arr, uint16_t *n, size_t elem, const void *v) {
    if (*n >= LIST_MAX) return -1;
    void *a = realloc(*arr, (size_t)(*n + 1) * elem);
    if (!a) return -1;
    memcpy((uint8_t *)a + (size_t)*n * elem, v, elem);
    *arr = a;
    (*n)++;
    return 0;
}

static int parse_set_item(const char *s, size_t len, void *vctx);

static int parse_set(set_ctx_t *c, const char *s, size_t len) {
    trim(&s, &len);
    if (len == 0) {
        set_err(c->err, c->errlen, "empty %s", c->is_port ? "port" : "address");
        return -1;
    }
    if (s[0] == '!') {
        if (c->neg) {
            set_err(c->err, c->errlen, "double negation is not supported");
            return -1;
        }
        c->neg = 1;
        int r = parse_set(c, s + 1, len - 1);
        c->neg = 0;
        return r;
    }
    if (s[0] == '[') {
        if (s[len - 1] != ']') {
            set_err(c->err, c->errlen, "unbalanced '['");
            return -1;
        }
        return split_list(s + 1, len - 2, parse_set_item, c);
    }
    if (s[0] == '$') {
        char name[RULE_VAR_NAME_MAX];
        if (len - 1 >= sizeof(name)) {
            set_err(c->err, c->errlen, "variable name too long");
            return -1;
        }
        memcpy(name, s + 1, len - 1);
        name[len - 1] = '\0';
        const char *v = ruleset_var(c->rs, name);
        if (!v) {
            set_err(c->err, c->errlen, "undefined variable $%s", name);
            return -1;
        }
        if (c->depth >= VAR_DEPTH) {
            set_err(c->err, c->errlen, "variables nested too deeply at $%s", name);
            return -1;
        }
        c->depth++;
        int r = parse_set(c, v, strlen(v));
        c->depth--;
        return r;
    }
    if (len == 3 && memcmp(s, "any", 3) == 0) {
        if (c->neg) {
            set_err(c->err, c->errlen, "'!any' matches nothing");
            return -1;
        }
        c->any_pos = 1;
        return 0;
    }

    char tok[64];
    if (len >= sizeof(tok)) {
        set_err(c->err, c->errlen, "%s too long", c->is_port ? "port" : "address");
        return -1;
    }
    memcpy(tok, s, len);
    tok[len] = '\0';

    if (c->is_port) {
        rule_port_range_t pr;
        long lo, hi;
        char *colon = strchr(tok, ':');
        if (!colon) {
            if (parse_int(tok, 1, 65535, &lo) < 0) goto bad_port;
            hi = lo;
        } else {
            *colon = '\0';
            if (tok[0] == '\0') lo = 0;
            else if (parse_int(tok, 0, 65535, &lo) < 0) goto bad_port;
            if (colon[1] == '\0') hi = 65535;
            else if (parse_int(colon + 1, 0, 65535, &hi) < 0) goto bad_port;
            if (lo > hi) goto bad_port;
        }
        pr.lo = (uint16_t)lo;
        pr.hi = (uint16_t)hi;
        rule_ports_t *ps = c->set;
        if (push(c->neg ? (void **)&ps->neg : (void **)&ps->pos,
                 c->neg ? &ps->nneg : &ps->npos, sizeof(pr), &pr) < 0) {
            set_err(c->err, c->errlen, "too many ports");
            return -1;
        }
        return 0;
    bad_port:
        set_err(c->err, c->errlen, "bad port '%.*s'", (int)len, s);
        return -1;
    }

    rule_cidr_t cidr;
    memset(&cidr, 0, sizeof(cidr));
    long prefix = -1;
    char *slash = strchr(tok, '/');
    if (slash) {
        *slash = '\0';
        if (parse_int(slash + 1, 0, 128, &prefix) < 0) goto bad_addr;
    }
    if (inet_pton(AF_INET, tok, cidr.addr) == 1) {
        cidr.version = 4;
        if (prefix > 32) goto bad_addr;
        cidr.prefix = (uint8_t)(prefix < 0 ? 32 : prefix);
    } else if (inet_pton(AF_INET6, tok, cidr.addr) == 1) {
        cidr.version = 6;
        cidr.prefix = (uint8_t)(prefix < 0 ? 128 : prefix);
    } else {
        goto bad_addr;
    }
    rule_addrs_t *as = c->set;
    if (push(c->neg ? (void **)&as->neg : (void **)&as->pos,
             c->neg ? &as->nneg : &as->npos, sizeof(cidr), &cidr) < 0) {
        set_err(c->err, c->errlen, "too many addresses");
        return -1;
    }
    return 0;
bad_addr:
    set_err(c->err, c->errlen, "bad address '%.*s'", (int)len, s);
    return -1;
}

static int parse_set_item(const char *s, size_t len, void *vctx) {
    return parse_set(vctx, s, len);
}

static int parse_addrs(const ruleset_t *rs, const char *s, rule_addrs_t *out,
                       char *err, size_t errlen) {
    set_ctx_t c = { rs, 0, 0, 0, 0, out, err, errlen };
    if (parse_set(&c, s, strlen(s)) < 0) return -1;
    if (c.any_pos) {                    /* "any" among the positives */
        free(out->pos);
        out->pos = NULL;
        out->npos = 0;
    }
    return 0;
}

static int parse_ports(const ruleset_t *rs, const char *s, rule_ports_t *out,
                       char *err, size_t errlen) {
    set_ctx_t c = { rs, 1, 0, 0, 0, out, err, errlen };
    if (parse_set(&c, s, strlen(s)) < 0) return -1;
    if (c.any_pos) {
        free(out->pos);
        out->pos = NULL;
        out->npos = 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* pcre                                                                */
/* ------------------------------------------------------------------ */

#define PCRE_FLAG_RELATIVE 0x100   /* R: not a PCRE2 option */

int rule_pcre_compile(rule_match_t *m, int flags, char *err, size_t errlen) {
    int ec;
    PCRE2_SIZE eo;
    uint32_t opts = 0;
    if (flags & 0x01) opts |= PCRE2_CASELESS;
    if (flags & 0x02) opts |= PCRE2_DOTALL;
    if (flags & 0x04) opts |= PCRE2_MULTILINE;
    if (flags & 0x08) opts |= PCRE2_EXTENDED;
    pcre2_code *re = pcre2_compile((PCRE2_SPTR)m->data, m->len, opts, &ec, &eo, NULL);
    if (!re) {
        PCRE2_UCHAR msg[160];
        pcre2_get_error_message(ec, msg, sizeof(msg));
        set_err(err, errlen, "pcre: %s at offset %zu", (const char *)msg, (size_t)eo);
        return -1;
    }
    (void)pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);   /* falls back if unavailable */
    m->re = re;
    return 0;
}

void rule_pcre_free(rule_match_t *m) {
    if (m->re) pcre2_code_free(m->re);
    m->re = NULL;
}

/* "/regex/flags" -> m->data = regex, flags as bits. */
static int parse_pcre(const uint8_t *s, size_t len, rule_match_t *m, char *err, size_t errlen) {
    if (len < 2 || s[0] != '/') {
        set_err(err, errlen, "pcre must look like \"/regex/flags\"");
        return -1;
    }
    size_t close = len - 1;
    while (close > 0 && s[close] != '/') close--;
    if (close == 0) {
        set_err(err, errlen, "pcre has no closing '/'");
        return -1;
    }
    int flags = 0;
    for (size_t i = close + 1; i < len; i++) {
        switch (s[i]) {
        case 'i': flags |= 0x01; break;
        case 's': flags |= 0x02; break;
        case 'm': flags |= 0x04; break;
        case 'x': flags |= 0x08; break;
        case 'R': flags |= PCRE_FLAG_RELATIVE; break;
        default:
            set_err(err, errlen, "unsupported pcre flag '%c' (use a sticky buffer "
                    "instead of U/H/P/...)", s[i]);
            return -1;
        }
    }
    m->len = close - 1;
    m->data = malloc(m->len + 1);
    if (!m->data) {
        set_err(err, errlen, "out of memory");
        return -1;
    }
    memcpy(m->data, s + 1, m->len);
    m->data[m->len] = '\0';
    m->relative = (flags & PCRE_FLAG_RELATIVE) != 0;
    m->nocase = (flags & 0x01) != 0;
    if (rule_pcre_compile(m, flags, err, errlen) < 0) {
        free(m->data);
        m->data = NULL;
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* flow, threshold, detection_filter                                   */
/* ------------------------------------------------------------------ */

static int parse_flow(const char *v, uint8_t *flow, char *err, size_t errlen) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", v);
    for (char *save = NULL, *t = strtok_r(buf, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        const char *s = t;
        size_t n = strlen(t);
        trim(&s, &n);
        if (n == 9 && memcmp(s, "to_server", 9) == 0) *flow |= RULE_FLOW_TO_SERVER;
        else if (n == 11 && memcmp(s, "from_client", 11) == 0) *flow |= RULE_FLOW_TO_SERVER;
        else if (n == 9 && memcmp(s, "to_client", 9) == 0) *flow |= RULE_FLOW_TO_CLIENT;
        else if (n == 11 && memcmp(s, "from_server", 11) == 0) *flow |= RULE_FLOW_TO_CLIENT;
        else if (n == 11 && memcmp(s, "established", 11) == 0) *flow |= RULE_FLOW_ESTABLISHED;
        else if (n == 15 && memcmp(s, "not_established", 15) == 0)
            *flow |= RULE_FLOW_NOT_ESTABLISHED;
        else if (n == 9 && memcmp(s, "stateless", 9) == 0) *flow |= RULE_FLOW_STATELESS;
        else {
            set_err(err, errlen, "unsupported flow option '%.*s'", (int)n, s);
            return -1;
        }
    }
    if ((*flow & RULE_FLOW_TO_SERVER) && (*flow & RULE_FLOW_TO_CLIENT)) {
        set_err(err, errlen, "flow cannot be both to_server and to_client");
        return -1;
    }
    if ((*flow & RULE_FLOW_ESTABLISHED) && (*flow & RULE_FLOW_NOT_ESTABLISHED)) {
        set_err(err, errlen, "flow cannot be both established and not_established");
        return -1;
    }
    return 0;
}

/* "type limit, track by_src, count 1, seconds 60" */
static int parse_threshold(const char *v, int is_df, threshold_t *t, char *err, size_t errlen) {
    char buf[256];
    int have_type = is_df, have_track = 0, have_count = 0, have_seconds = 0;
    snprintf(buf, sizeof(buf), "%s", v);
    if (is_df) t->type = THRESHOLD_DETECTION_FILTER;

    for (char *save = NULL, *it = strtok_r(buf, ",", &save); it; it = strtok_r(NULL, ",", &save)) {
        char key[16], val[32];
        if (sscanf(it, " %15s %31s", key, val) != 2) {
            set_err(err, errlen, "expected 'name value' pairs");
            return -1;
        }
        long n;
        if (strcmp(key, "type") == 0 && !is_df) {
            if (strcmp(val, "limit") == 0) t->type = THRESHOLD_LIMIT;
            else if (strcmp(val, "threshold") == 0) t->type = THRESHOLD_THRESHOLD;
            else if (strcmp(val, "both") == 0) t->type = THRESHOLD_BOTH;
            else { set_err(err, errlen, "unknown threshold type '%s'", val); return -1; }
            have_type = 1;
        } else if (strcmp(key, "track") == 0) {
            if (strcmp(val, "by_src") == 0) t->track = TRACK_BY_SRC;
            else if (strcmp(val, "by_dst") == 0) t->track = TRACK_BY_DST;
            else if (strcmp(val, "by_rule") == 0) t->track = TRACK_BY_RULE;
            else if (strcmp(val, "by_both") == 0) t->track = TRACK_BY_BOTH;
            else { set_err(err, errlen, "unknown track '%s'", val); return -1; }
            have_track = 1;
        } else if (strcmp(key, "count") == 0 && parse_int(val, 1, 1000000, &n) == 0) {
            t->count = (uint32_t)n;
            have_count = 1;
        } else if (strcmp(key, "seconds") == 0 && parse_int(val, 1, 86400, &n) == 0) {
            t->seconds = (uint32_t)n;
            have_seconds = 1;
        } else {
            set_err(err, errlen, "bad %s setting '%s %s'",
                    is_df ? "detection_filter" : "threshold", key, val);
            return -1;
        }
    }
    if (!have_type || !have_track || !have_count || !have_seconds) {
        set_err(err, errlen, "%s needs %strack, count and seconds",
                is_df ? "detection_filter" : "threshold", is_df ? "" : "type, ");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Rules                                                               */
/* ------------------------------------------------------------------ */

void rule_free(rule_t *r) {
    for (int i = 0; i < r->nm; i++) {
        rule_pcre_free(&r->m[i]);
        free(r->m[i].data);
        r->m[i].data = NULL;
    }
    r->nm = 0;
    free(r->src.pos); free(r->src.neg);
    free(r->dst.pos); free(r->dst.neg);
    free(r->sport.pos); free(r->sport.neg);
    free(r->dport.pos); free(r->dport.neg);
    memset(&r->src, 0, sizeof(r->src));
    memset(&r->dst, 0, sizeof(r->dst));
    memset(&r->sport, 0, sizeof(r->sport));
    memset(&r->dport, 0, sizeof(r->dport));
}

static int is_raw_proto(rule_proto_t p, int tcp) {
    switch (p) {
    case RULE_PROTO_IP:   return 1;
    case RULE_PROTO_TCP:  return tcp;
    case RULE_PROTO_UDP:  return !tcp;
    case RULE_PROTO_HTTP:
    case RULE_PROTO_TLS:  return tcp;
    case RULE_PROTO_DNS:  return 1;
    default:              return 0;
    }
}

/* Checks that need the whole rule; picks the phase and fast pattern. */
static int finish_rule(rule_t *r, char *err, size_t errlen) {
    if (r->nm == 0) {
        set_err(err, errlen, "rule has no content or pcre option");
        return -1;
    }
    int raw = 0, sticky = 0, body = 0;
    for (int i = 0; i < r->nm; i++) {
        rule_match_t *m = &r->m[i];
        if (m->buffer == RULE_BUF_RAW) raw = 1;
        else sticky = 1;
        if (m->buffer == RULE_BUF_HTTP_REQUEST_BODY) body = 1;
        r->buffers |= 1u << m->buffer;

        if (m->type == RULE_MATCH_CONTENT) {
            if (m->startswith && (m->has_offset || m->has_depth || m->relative)) {
                set_err(err, errlen, "startswith cannot be combined with offset, depth, "
                        "distance or within");
                return -1;
            }
            if (m->relative && (m->has_offset || m->has_depth)) {
                set_err(err, errlen, "distance/within cannot be combined with offset/depth "
                        "on the same content");
                return -1;
            }
            if (m->has_depth && (size_t)m->depth < m->len) {
                set_err(err, errlen, "depth %d is shorter than its content", m->depth);
                return -1;
            }
            if (m->has_within && (size_t)m->within < m->len) {
                set_err(err, errlen, "within %d is shorter than its content", m->within);
                return -1;
            }
        }
        /* Remember that the previous condition in this buffer is a
         * backtracking point for this relative one. */
        if (m->relative) {
            for (int j = i - 1; j >= 0; j--) {
                if (r->m[j].buffer != m->buffer || r->m[j].negated) continue;
                r->m[j].backtrack = 1;
                break;
            }
        }
    }
    if (raw && sticky) {
        set_err(err, errlen, "a rule cannot mix raw content with sticky buffers");
        return -1;
    }
    if (raw) {
        r->raw_tcp = (uint8_t)is_raw_proto((rule_proto_t)r->proto, 1);
        r->raw_udp = (uint8_t)is_raw_proto((rule_proto_t)r->proto, 0);
        r->phase = r->raw_tcp ? RULE_PHASE_TCP_STREAM : RULE_PHASE_UDP;
    } else {
        switch (r->proto) {
        case RULE_PROTO_HTTP: r->phase = body ? RULE_PHASE_HTTP_BODY : RULE_PHASE_HTTP_REQUEST; break;
        case RULE_PROTO_TLS:  r->phase = RULE_PHASE_TLS_HELLO; break;
        default:              r->phase = RULE_PHASE_DNS_QUERY; break;
        }
    }

    /* Fast pattern: the one the rule names, else the longest positive
     * content. Dotprefix contents lose their leading '.' (the buffer
     * itself does not have it). */
    r->fast_pattern = -1;
    r->first_positive = -1;
    size_t best = 0;
    for (int i = 0; i < r->nm; i++) {
        rule_match_t *m = &r->m[i];
        if (m->negated) continue;
        if (r->first_positive < 0) r->first_positive = (int8_t)i;
        if (m->type != RULE_MATCH_CONTENT) continue;
        size_t usable = m->len - (m->dotprefix && m->data[0] == '.' ? 1 : 0);
        if (usable == 0) continue;
        if (m->fast_pattern) {
            r->fast_pattern = (int8_t)i;
            break;
        }
        if (usable > best) {
            best = usable;
            r->fast_pattern = (int8_t)i;
        }
    }

    if (r->threshold.type == THRESHOLD_NONE && r->threshold.count) {
        set_err(err, errlen, "internal: threshold without type");
        return -1;
    }
    if (r->priority == 0) {
        int p = r->classtype[0] ? rule_classtype_priority(r->classtype) : -1;
        r->priority = p > 0 ? p : 2;
    }
    if (!r->msg[0]) snprintf(r->msg, sizeof(r->msg), "sid %d", r->sid);
    return 0;
}

/* Parse state while reading options. */
typedef struct {
    int buffer;          /* current sticky buffer                     */
    int dotprefix;       /* dotprefix given for the current buffer     */
    int have_sid;
    int have_threshold, have_df;
} opt_state_t;

static rule_match_t *last_match(rule_t *r) {
    return r->nm ? &r->m[r->nm - 1] : NULL;
}

static int parse_option(ruleset_t *rs, rule_t *r, opt_state_t *st, const char *kw,
                        int has_value, const char **pp, char *err, size_t errlen) {
    (void)rs;
    const char *p = *pp;
    char sub[160];
    int rc = 0;

    if (strcmp(kw, "content") == 0 || strcmp(kw, "pcre") == 0) {
        int is_pcre = kw[0] == 'p';
        if (!has_value) { set_err(err, errlen, "%s needs a value", kw); return -1; }
        if (r->nm == RULE_MATCH_MAX) {
            set_err(err, errlen, "more than %d content/pcre options", RULE_MATCH_MAX);
            return -1;
        }
        rule_match_t *m = &r->m[r->nm];
        memset(m, 0, sizeof(*m));
        if (*p == '!') { m->negated = 1; p++; skip_ws(&p); }
        m->buffer = (uint8_t)st->buffer;
        m->dotprefix = (uint8_t)st->dotprefix;

        uint8_t tmp[RULE_PCRE_MAX];
        size_t tl;
        size_t cap = is_pcre ? RULE_PCRE_MAX : RULE_CONTENT_MAX;
        if (parse_quoted(&p, tmp, cap, &tl, is_pcre ? Q_PCRE : Q_CONTENT, sub, sizeof(sub)) < 0) {
            set_err(err, errlen, "%s: %s", kw, sub);
            return -1;
        }
        if (is_pcre) {
            m->type = RULE_MATCH_PCRE;
            if (parse_pcre(tmp, tl, m, sub, sizeof(sub)) < 0) {
                set_err(err, errlen, "%s", sub);
                return -1;
            }
        } else {
            if (tl == 0) { set_err(err, errlen, "content must not be empty"); return -1; }
            m->type = RULE_MATCH_CONTENT;
            m->data = malloc(tl);
            if (!m->data) { set_err(err, errlen, "out of memory"); return -1; }
            memcpy(m->data, tmp, tl);
            m->len = tl;
        }
        r->nm++;
    } else if (strcmp(kw, "nocase") == 0 || strcmp(kw, "startswith") == 0 ||
               strcmp(kw, "endswith") == 0 || strcmp(kw, "fast_pattern") == 0) {
        rule_match_t *m = last_match(r);
        if (has_value) { set_err(err, errlen, "%s takes no value", kw); return -1; }
        if (!m || m->type != RULE_MATCH_CONTENT) {
            set_err(err, errlen, "%s must follow a content", kw);
            return -1;
        }
        if (kw[0] == 'n') m->nocase = 1;
        else if (kw[0] == 's') m->startswith = 1;
        else if (kw[0] == 'e') m->endswith = 1;
        else {
            if (m->negated) { set_err(err, errlen, "fast_pattern cannot be a negated content"); return -1; }
            for (int i = 0; i + 1 < r->nm; i++)
                if (r->m[i].fast_pattern) { set_err(err, errlen, "only one fast_pattern per rule"); return -1; }
            m->fast_pattern = 1;
        }
    } else if (strcmp(kw, "offset") == 0 || strcmp(kw, "depth") == 0 ||
               strcmp(kw, "distance") == 0 || strcmp(kw, "within") == 0) {
        rule_match_t *m = last_match(r);
        char val[32];
        long v;
        int is_distance = kw[0] == 'd' && kw[1] == 'i';
        long min = (kw[0] == 'o' || is_distance) ? (is_distance ? -65535 : 0) : 1;
        if (!m || m->type != RULE_MATCH_CONTENT) {
            set_err(err, errlen, "%s must follow a content", kw);
            return -1;
        }
        if (!has_value || parse_bare(&p, val, sizeof(val)) < 0 || parse_int(val, min, 65535, &v) < 0) {
            set_err(err, errlen, "bad %s value", kw);
            return -1;
        }
        if (kw[0] == 'o') { m->offset = (int32_t)v; m->has_offset = 1; }
        else if (kw[0] == 'w') { m->within = (int32_t)v; m->has_within = 1; m->relative = 1; }
        else if (is_distance) { m->distance = (int32_t)v; m->has_distance = 1; m->relative = 1; }
        else { m->depth = (int32_t)v; m->has_depth = 1; }
    } else if (find_buffer(kw) > 0) {
        int b = find_buffer(kw);
        if (has_value) { set_err(err, errlen, "%s takes no value", kw); return -1; }
        if (r->proto != BUFFERS[b].proto) {
            set_err(err, errlen, "buffer '%s' needs protocol '%s', not '%s'",
                    kw, PROTO_NAMES[BUFFERS[b].proto], PROTO_NAMES[r->proto]);
            return -1;
        }
        st->buffer = b;
        st->dotprefix = 0;
    } else if (strcmp(kw, "dotprefix") == 0) {
        if (has_value) { set_err(err, errlen, "dotprefix takes no value"); return -1; }
        if (st->buffer == RULE_BUF_RAW) {
            set_err(err, errlen, "dotprefix must follow a buffer keyword, before content");
            return -1;
        }
        for (int i = 0; i < r->nm; i++)
            if (r->m[i].buffer == st->buffer) {
                set_err(err, errlen, "dotprefix must follow a buffer keyword, before content");
                return -1;
            }
        st->dotprefix = 1;
    } else if (strcmp(kw, "msg") == 0) {
        size_t mlen;
        if (!has_value) { set_err(err, errlen, "msg needs a value"); return -1; }
        if (parse_quoted(&p, (uint8_t *)r->msg, sizeof(r->msg) - 1, &mlen, Q_TEXT,
                         sub, sizeof(sub)) < 0) {
            set_err(err, errlen, "msg: %s", sub);
            return -1;
        }
        r->msg[mlen] = '\0';
    } else if (strcmp(kw, "sid") == 0 || strcmp(kw, "priority") == 0 || strcmp(kw, "rev") == 0) {
        char val[32];
        long v;
        long max = kw[0] == 's' ? 2147483647L : kw[0] == 'p' ? 255 : 65535;
        if (!has_value || parse_bare(&p, val, sizeof(val)) < 0 || parse_int(val, 1, max, &v) < 0) {
            set_err(err, errlen, "bad %s value", kw);
            return -1;
        }
        if (kw[0] == 's') { r->sid = (int)v; st->have_sid = 1; }
        else if (kw[0] == 'p') r->priority = (int)v;
        else r->rev = (int)v;
    } else if (strcmp(kw, "classtype") == 0) {
        char val[RULE_CLASSTYPE_MAX];
        if (!has_value || parse_bare(&p, val, sizeof(val)) < 0 || !val[0]) {
            set_err(err, errlen, "bad classtype value");
            return -1;
        }
        if (rule_classtype_priority(val) < 0) {
            set_err(err, errlen, "unknown classtype '%s'", val);
            return -1;
        }
        snprintf(r->classtype, sizeof(r->classtype), "%s", val);
    } else if (strcmp(kw, "flow") == 0) {
        char val[128];
        if (!has_value || parse_bare(&p, val, sizeof(val)) < 0) {
            set_err(err, errlen, "bad flow value");
            return -1;
        }
        rc = parse_flow(val, &r->flow, err, errlen);
    } else if (strcmp(kw, "threshold") == 0 || strcmp(kw, "detection_filter") == 0) {
        int is_df = kw[0] == 'd';
        char val[256];
        if (!has_value || parse_bare(&p, val, sizeof(val)) < 0) {
            set_err(err, errlen, "bad %s value", kw);
            return -1;
        }
        if (st->have_threshold || st->have_df) {
            set_err(err, errlen, "only one threshold or detection_filter per rule");
            return -1;
        }
        if (is_df) st->have_df = 1; else st->have_threshold = 1;
        rc = parse_threshold(val, is_df, &r->threshold, err, errlen);
    } else if (strcmp(kw, "reference") == 0 || strcmp(kw, "metadata") == 0) {
        char val[512];
        if (*p == '"') {
            uint8_t tmp[512];
            size_t tl;
            if (parse_quoted(&p, tmp, sizeof(tmp), &tl, Q_TEXT, sub, sizeof(sub)) < 0) {
                set_err(err, errlen, "%s: %s", kw, sub);
                return -1;
            }
        } else if (!has_value || parse_bare(&p, val, sizeof(val)) < 0) {
            set_err(err, errlen, "%s value too long", kw);
            return -1;
        }
    } else {
        set_err(err, errlen, "unsupported option '%s'", kw);
        return -1;
    }
    *pp = p;
    return rc;
}

int rule_parse(ruleset_t *rs, const char *line, rule_t *out, char *err, size_t errlen) {
    const char *p = line;
    char action[16], proto[16], src[TOKEN_MAX], sport[TOKEN_MAX];
    char arrow[8], dst[TOKEN_MAX], dport[TOKEN_MAX];
    opt_state_t st = { RULE_BUF_RAW, 0, 0, 0, 0 };

    if (err && errlen) err[0] = '\0';
    memset(out, 0, sizeof(*out));

    skip_ws(&p);
    if (*p == '\0' || *p == '#') return 0;

    if (next_token(&p, action, sizeof(action)) < 0 ||
        next_token(&p, proto, sizeof(proto)) < 0 ||
        next_token(&p, src, sizeof(src)) < 0 ||
        next_token(&p, sport, sizeof(sport)) < 0 ||
        next_token(&p, arrow, sizeof(arrow)) < 0 ||
        next_token(&p, dst, sizeof(dst)) < 0 ||
        next_token(&p, dport, sizeof(dport)) < 0) {
        set_err(err, errlen, "malformed rule header (missing or overlong field)");
        return -1;
    }

    if (strcmp(action, "alert") == 0) out->action = RULE_ACTION_ALERT;
    else if (strcmp(action, "drop") == 0) out->action = RULE_ACTION_DROP;
    else if (strcmp(action, "pass") == 0) out->action = RULE_ACTION_PASS;
    else {
        set_err(err, errlen, "unsupported action '%s'", action);
        return -1;
    }
    int pi;
    for (pi = 0; pi < RULE_PROTO_COUNT; pi++)
        if (strcmp(proto, PROTO_NAMES[pi]) == 0) break;
    if (pi == RULE_PROTO_COUNT) {
        set_err(err, errlen, "unsupported protocol '%s'", proto);
        return -1;
    }
    out->proto = (uint8_t)pi;
    if (strcmp(arrow, "<>") == 0) {
        out->bidirectional = 1;
    } else if (strcmp(arrow, "->") != 0) {
        set_err(err, errlen, "expected '->' or '<>', got '%s'", arrow);
        return -1;
    }

    char sub[160];
    if (parse_addrs(rs, src, &out->src, sub, sizeof(sub)) < 0 ||
        parse_addrs(rs, dst, &out->dst, sub, sizeof(sub)) < 0) {
        set_err(err, errlen, "source/destination: %s", sub);
        goto fail;
    }
    if (parse_ports(rs, sport, &out->sport, sub, sizeof(sub)) < 0) {
        set_err(err, errlen, "source port: %s", sub);
        goto fail;
    }
    if (parse_ports(rs, dport, &out->dport, sub, sizeof(sub)) < 0) {
        set_err(err, errlen, "destination port: %s", sub);
        goto fail;
    }

    skip_ws(&p);
    if (*p != '(') {
        set_err(err, errlen, "expected '(' before options");
        goto fail;
    }
    p++;

    for (;;) {
        skip_ws(&p);
        if (*p == ')') {
            p++;
            skip_ws(&p);
            if (*p != '\0') {
                set_err(err, errlen, "unexpected text after ')'");
                goto fail;
            }
            break;
        }
        if (*p == '\0') {
            set_err(err, errlen, "missing ')'");
            goto fail;
        }

        char kw[KEYWORD_MAX];
        size_t kn = 0;
        while ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '.') {
            if (kn + 1 >= sizeof(kw)) {
                set_err(err, errlen, "option keyword too long");
                goto fail;
            }
            kw[kn++] = *p++;
        }
        kw[kn] = '\0';
        if (kn == 0) {
            set_err(err, errlen, "expected option keyword near '%.10s'", p);
            goto fail;
        }

        skip_ws(&p);
        int has_value = 0;
        if (*p == ':') {
            has_value = 1;
            p++;
            skip_ws(&p);
        }
        if (parse_option(rs, out, &st, kw, has_value, &p, err, errlen) < 0) goto fail;

        skip_ws(&p);
        if (*p == ';') {
            p++;
        } else if (*p != ')') {
            set_err(err, errlen, "expected ';' after option '%s'", kw);
            goto fail;
        }
    }

    if (!st.have_sid) {
        set_err(err, errlen, "rule has no sid");
        goto fail;
    }
    if (finish_rule(out, err, errlen) < 0) goto fail;
    return 1;

fail:
    rule_free(out);
    return -1;
}
