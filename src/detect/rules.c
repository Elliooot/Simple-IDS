#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simpleids/bytes.h"
#include "simpleids/rules.h"

#define TOKEN_MAX    64
#define KEYWORD_MAX  32
#define LINE_MAX_LEN 4096

static rule_t *g_rules = NULL;
static int g_count = 0;
static int g_cap = 0;

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

/* Copy the next whitespace-delimited header token into buf.
 * Returns 0, or -1 if missing or longer than bufsize-1. */
static int next_token(const char **p, char *buf, size_t bufsize) {
    skip_ws(p);
    size_t n = 0;
    while (**p && !is_space(**p) && **p != '(') {
        if (n + 1 >= bufsize) return -1;
        buf[n++] = *(*p)++;
    }
    buf[n] = '\0';
    return n > 0 ? 0 : -1;
}

/* Parse a positive decimal int made only of digits. */
static int parse_uint(const char *s, size_t len, long max, long *out) {
    if (len == 0 || len > 10) return -1;
    long v = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v < 1 || v > max) return -1;
    *out = v;
    return 0;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Parse a quoted string starting at the opening quote. Handles the
 * escapes \" \\ \; and, when hex is set, |xx xx| byte runs.
 * Writes at most cap bytes into out. Returns 0 or -1 (err set).
 */
static int parse_quoted(const char **p, uint8_t *out, size_t cap,
                        size_t *outlen, int hex, char *err, size_t errlen) {
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
        if (c == '|' && hex) { in_hex = 1; s++; continue; }
        if (c == '\\') {
            char e = s[1];
            if (e != '"' && e != '\\' && e != ';') {
                set_err(err, errlen, "unsupported escape '\\%c'", e ? e : '0');
                return -1;
            }
            c = e;
            s++;
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

int rule_parse(const char *line, rule_t *out, char *err, size_t errlen) {
    const char *p = line;
    char action[TOKEN_MAX], src[TOKEN_MAX], sport[TOKEN_MAX];
    char arrow[TOKEN_MAX], dst[TOKEN_MAX], dport[TOKEN_MAX];
    int have_content = 0, have_sid = 0, have_msg = 0;

    if (err && errlen) err[0] = '\0';
    memset(out, 0, sizeof(*out));
    out->priority = 2;

    skip_ws(&p);
    if (*p == '\0' || *p == '#') return 0;

    if (next_token(&p, action, sizeof(action)) < 0 ||
        next_token(&p, out->protocol, sizeof(out->protocol)) < 0 ||
        next_token(&p, src, sizeof(src)) < 0 ||
        next_token(&p, sport, sizeof(sport)) < 0 ||
        next_token(&p, arrow, sizeof(arrow)) < 0 ||
        next_token(&p, dst, sizeof(dst)) < 0 ||
        next_token(&p, dport, sizeof(dport)) < 0) {
        set_err(err, errlen, "malformed rule header (missing or overlong field)");
        return -1;
    }

    if (strcmp(action, "alert") != 0) {
        set_err(err, errlen, "unsupported action '%s'", action);
        return -1;
    }
    if (strcmp(out->protocol, "tcp") != 0 && strcmp(out->protocol, "ip") != 0) {
        set_err(err, errlen, "unsupported protocol '%s'", out->protocol);
        return -1;
    }
    if (strcmp(arrow, "->") != 0) {
        set_err(err, errlen, "expected '->', got '%s'", arrow);
        return -1;
    }
    if (strcmp(dport, "any") == 0) {
        out->dst_port = 0;
    } else {
        long v;
        if (parse_uint(dport, strlen(dport), 65535, &v) < 0) {
            set_err(err, errlen, "bad destination port '%s'", dport);
            return -1;
        }
        out->dst_port = (int)v;
    }

    skip_ws(&p);
    if (*p != '(') {
        set_err(err, errlen, "expected '(' before options");
        return -1;
    }
    p++;

    for (;;) {
        skip_ws(&p);
        if (*p == ')') {
            p++;
            skip_ws(&p);
            if (*p != '\0') {
                set_err(err, errlen, "unexpected text after ')'");
                return -1;
            }
            break;
        }
        if (*p == '\0') {
            set_err(err, errlen, "missing ')'");
            return -1;
        }

        char kw[KEYWORD_MAX];
        size_t kn = 0;
        while ((*p >= 'a' && *p <= 'z') || *p == '_' || *p == '.') {
            if (kn + 1 >= sizeof(kw)) {
                set_err(err, errlen, "option keyword too long");
                return -1;
            }
            kw[kn++] = *p++;
        }
        kw[kn] = '\0';
        if (kn == 0) {
            set_err(err, errlen, "expected option keyword near '%.10s'", p);
            return -1;
        }

        skip_ws(&p);
        int has_value = 0;
        if (*p == ':') {
            has_value = 1;
            p++;
            skip_ws(&p);
        }

        if (strcmp(kw, "content") == 0) {
            if (!has_value) { set_err(err, errlen, "content needs a value"); return -1; }
            if (have_content) {
                set_err(err, errlen, "multiple content options are not supported yet");
                return -1;
            }
            char sub[96];
            if (parse_quoted(&p, out->content, sizeof(out->content),
                             &out->content_len, 1, sub, sizeof(sub)) < 0) {
                set_err(err, errlen, "content: %s", sub);
                return -1;
            }
            if (out->content_len == 0) {
                set_err(err, errlen, "content must not be empty");
                return -1;
            }
            have_content = 1;
        } else if (strcmp(kw, "msg") == 0) {
            if (!has_value) { set_err(err, errlen, "msg needs a value"); return -1; }
            size_t mlen;
            char sub[96];
            if (parse_quoted(&p, (uint8_t *)out->msg, sizeof(out->msg) - 1,
                             &mlen, 0, sub, sizeof(sub)) < 0) {
                set_err(err, errlen, "msg: %s", sub);
                return -1;
            }
            out->msg[mlen] = '\0';
            have_msg = 1;
        } else if (strcmp(kw, "sid") == 0 || strcmp(kw, "priority") == 0) {
            char val[TOKEN_MAX];
            long v;
            int is_sid = kw[0] == 's';
            if (!has_value || parse_bare(&p, val, sizeof(val)) < 0 ||
                parse_uint(val, strlen(val), is_sid ? 2147483647L : 255, &v) < 0) {
                set_err(err, errlen, "bad %s value", kw);
                return -1;
            }
            if (is_sid) { out->sid = (int)v; have_sid = 1; }
            else        { out->priority = (int)v; }
        } else if (strcmp(kw, "nocase") == 0) {
            if (has_value) { set_err(err, errlen, "nocase takes no value"); return -1; }
            out->nocase = 1;
        } else if (strcmp(kw, "rev") == 0 || strcmp(kw, "classtype") == 0 ||
                   strcmp(kw, "reference") == 0 || strcmp(kw, "metadata") == 0) {
            char val[256];
            if (*p == '"') {
                uint8_t tmp[256];
                size_t tl;
                char sub[96];
                if (parse_quoted(&p, tmp, sizeof(tmp), &tl, 0, sub, sizeof(sub)) < 0) {
                    set_err(err, errlen, "%s: %s", kw, sub);
                    return -1;
                }
            } else if (parse_bare(&p, val, sizeof(val)) < 0) {
                set_err(err, errlen, "%s value too long", kw);
                return -1;
            }
        } else {
            set_err(err, errlen, "unsupported option '%s'", kw);
            return -1;
        }

        skip_ws(&p);
        if (*p == ';') {
            p++;
        } else if (*p != ')') {
            set_err(err, errlen, "expected ';' after option '%s'", kw);
            return -1;
        }
    }

    if (!have_content) {
        set_err(err, errlen, "rule has no content option");
        return -1;
    }
    if (!have_sid) {
        set_err(err, errlen, "rule has no sid");
        return -1;
    }
    if (!have_msg) snprintf(out->msg, sizeof(out->msg), "sid %d", out->sid);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Rule set                                                            */
/* ------------------------------------------------------------------ */

int rules_add(const rule_t *rule) {
    for (int i = 0; i < g_count; i++) {
        if (g_rules[i].sid == rule->sid) return -1;
    }
    if (g_count == g_cap) {
        int ncap = g_cap ? g_cap * 2 : 64;
        rule_t *n = realloc(g_rules, (size_t)ncap * sizeof(*n));
        if (!n) return -1;
        g_rules = n;
        g_cap = ncap;
    }
    g_rules[g_count++] = *rule;
    return 0;
}

int rules_load_file(const char *path, int *errors) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open rules file %s: %s\n", path, strerror(errno));
        return -1;
    }

    char line[LINE_MAX_LEN];
    int line_num = 0, loaded = 0, bad = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        size_t n = strlen(line);
        if (n == sizeof(line) - 1 && line[n - 1] != '\n' && !feof(fp)) {
            /* Overlong line: report it and discard the rest. */
            int c;
            while ((c = fgetc(fp)) != EOF && c != '\n') {}
            fprintf(stderr, "%s:%d: line longer than %d bytes, skipped\n",
                    path, line_num, LINE_MAX_LEN - 1);
            bad++;
            continue;
        }

        rule_t r;
        char err[160];
        int rc = rule_parse(line, &r, err, sizeof(err));
        if (rc == 0) continue;
        if (rc < 0) {
            fprintf(stderr, "%s:%d: %s, skipped\n", path, line_num, err);
            bad++;
            continue;
        }
        if (rules_add(&r) < 0) {
            fprintf(stderr, "%s:%d: duplicate sid %d (or out of memory), skipped\n",
                    path, line_num, r.sid);
            bad++;
            continue;
        }
        loaded++;
    }

    fclose(fp);
    if (errors) *errors = bad;
    return loaded;
}

int rules_match(const uint8_t *buf, size_t len, const char *protocol,
                int dst_port, rule_hit_fn hit, void *ctx) {
    int matches = 0;
    for (int i = 0; i < g_count; i++) {
        const rule_t *r = &g_rules[i];
        if (strcmp(r->protocol, "ip") != 0 && strcmp(r->protocol, protocol) != 0)
            continue;
        if (r->dst_port != 0 && r->dst_port != dst_port)
            continue;
        if (bytes_find(buf, len, r->content, r->content_len, r->nocase)) {
            matches++;
            if (hit) hit(r, ctx);
        }
    }
    return matches;
}

int rules_count(void) {
    return g_count;
}

void rules_free(void) {
    free(g_rules);
    g_rules = NULL;
    g_count = g_cap = 0;
}
