#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "simpleids/bytes.h"
#include "ruleset_int.h"

/*
 * Rule evaluation.
 *
 * Each phase keeps its rules in load order plus one Aho-Corasick
 * automaton per buffer holding the rules' fast patterns. Evaluating a
 * phase runs the automata over the available buffers, collects the
 * rules whose fast pattern occurred (plus the few without one), and
 * verifies only those: header (protocol, addresses, ports, flow), then
 * the content/pcre conditions in order, backtracking over earlier
 * occurrences when a later relative condition fails (Suricata does the
 * same; "union ... select" must find the "union" that is close enough).
 */

#define DOTPREFIX_MAX     1024     /* names longer than this are not dotted */
#define BACKTRACK_BUDGET  4096     /* occurrences tried per rule evaluation */
#define PCRE_MATCH_LIMIT  10000
#define PCRE_DEPTH_LIMIT  2000

static ruleset_t *g_active;
static rules_stats_t g_stats;

const rules_stats_t *rules_stats(void) {
    return &g_stats;
}

void rules_reset_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}

ruleset_t *rules_set_active(ruleset_t *rs) {
    ruleset_t *old = g_active;
    g_active = rs;
    return old;
}

ruleset_t *rules_active(void) {
    return g_active;
}

/* ------------------------------------------------------------------ */
/* Ruleset storage                                                     */
/* ------------------------------------------------------------------ */

ruleset_t *ruleset_new(void) {
    return calloc(1, sizeof(ruleset_t));
}

static void free_compiled(ruleset_t *rs) {
    for (int p = 0; p < RULE_PHASE_COUNT; p++) {
        phase_data_t *ph = &rs->ph[p];
        free(ph->idx);
        free(ph->always);
        for (int b = 0; b < RULE_BUF_COUNT; b++) mpm_free(ph->mpm[b]);
        memset(ph, 0, sizeof(*ph));
    }
    free(rs->mark);
    free(rs->cand);
    rs->mark = NULL;
    rs->cand = NULL;
    if (rs->match_data) pcre2_match_data_free(rs->match_data);
    if (rs->match_ctx) pcre2_match_context_free(rs->match_ctx);
    rs->match_data = rs->match_ctx = NULL;
    rs->compiled = 0;
}

void ruleset_free(ruleset_t *rs) {
    if (!rs) return;
    if (g_active == rs) g_active = NULL;
    free_compiled(rs);
    for (int i = 0; i < rs->n; i++) rule_free(&rs->rules[i]);
    free(rs->rules);
    for (int i = 0; i < rs->nfiles; i++) free(rs->files[i]);
    free(rs->files);
    free(rs);
}

int ruleset_count(const ruleset_t *rs) {
    return rs ? rs->n : 0;
}

const rule_t *ruleset_rule(const ruleset_t *rs, int i) {
    return i >= 0 && i < rs->n ? &rs->rules[i] : NULL;
}

const rule_t *ruleset_find(const ruleset_t *rs, int sid) {
    for (int i = 0; i < rs->n; i++)
        if (rs->rules[i].sid == sid) return &rs->rules[i];
    return NULL;
}

int ruleset_add(ruleset_t *rs, rule_t *r) {
    if (rs->compiled) return -1;
    if (ruleset_find(rs, r->sid)) return -1;
    if (rs->n == rs->cap) {
        int ncap = rs->cap ? rs->cap * 2 : 64;
        rule_t *n = realloc(rs->rules, (size_t)ncap * sizeof(*n));
        if (!n) return -1;
        rs->rules = n;
        rs->cap = ncap;
    }
    rs->rules[rs->n++] = *r;
    memset(r, 0, sizeof(*r));          /* ownership moved */
    return 0;
}

static const char *keep_path(ruleset_t *rs, const char *path) {
    char **n = realloc(rs->files, (size_t)(rs->nfiles + 1) * sizeof(*n));
    if (!n) return NULL;
    rs->files = n;
    char *copy = strdup(path);
    if (!copy) return NULL;
    rs->files[rs->nfiles++] = copy;
    return copy;
}

/* "var NAME VALUE" (also ipvar / portvar). Returns 1 if the line is a
 * variable definition, -1 if it is a malformed one, 0 otherwise. */
static int parse_var_line(ruleset_t *rs, const char *line, char *err, size_t errlen) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    size_t kw;
    if (strncmp(p, "var", 3) == 0) kw = 3;
    else if (strncmp(p, "ipvar", 5) == 0 || strncmp(p, "portvar", 7) == 0) kw = p[0] == 'i' ? 5 : 7;
    else return 0;
    if (p[kw] != ' ' && p[kw] != '\t') return 0;
    p += kw;

    char name[RULE_VAR_NAME_MAX + 1], value[RULE_VAR_VALUE_MAX];
    while (*p == ' ' || *p == '\t') p++;
    size_t n = 0;
    while (*p && *p != ' ' && *p != '\t') {
        if (n + 1 >= sizeof(name)) { snprintf(err, errlen, "variable name too long"); return -1; }
        name[n++] = *p++;
    }
    name[n] = '\0';
    while (*p == ' ' || *p == '\t') p++;
    size_t vl = strlen(p);
    while (vl && (p[vl - 1] == ' ' || p[vl - 1] == '\t' || p[vl - 1] == '\r' || p[vl - 1] == '\n'))
        vl--;
    if (vl == 0 || vl >= sizeof(value)) {
        snprintf(err, errlen, "variable %s needs a value (at most %zu characters)",
                 name, sizeof(value) - 1);
        return -1;
    }
    memcpy(value, p, vl);
    value[vl] = '\0';
    if (ruleset_set_var(rs, name, value) < 0) {
        snprintf(err, errlen, "bad variable definition '%s'", name);
        return -1;
    }
    return 1;
}

int ruleset_load_file(ruleset_t *rs, const char *path, int *errors) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open rules file %s: %s\n", path, strerror(errno));
        return -1;
    }
    const char *kept = keep_path(rs, path);

    static char line[RULE_LINE_MAX];
    static char phys[RULE_LINE_MAX];
    int line_num = 0, start_line = 0, loaded = 0, bad = 0;
    size_t ll = 0;
    int skipping = 0;           /* an overlong logical line is being dropped */

    for (;;) {
        int eof = fgets(phys, sizeof(phys), fp) == NULL;
        size_t n = eof ? 0 : strlen(phys);
        if (!eof) {
            line_num++;
            if (n == sizeof(phys) - 1 && phys[n - 1] != '\n' && !feof(fp)) {
                /* Drain the rest of the physical line, remembering whether it
                 * ends in a backslash (the logical line then goes on). */
                int c, last = phys[n - 1];
                while ((c = fgetc(fp)) != EOF && c != '\n')
                    if (c != '\r') last = c;
                phys[0] = '\0';
                n = 0;
                if (!skipping) {
                    fprintf(stderr, "%s:%d: line longer than %d bytes, skipped\n",
                            path, line_num, RULE_LINE_MAX - 1);
                    bad++;
                }
                skipping = last == '\\';
                ll = 0;
                if (c == EOF) break;
                continue;
            }
            while (n && (phys[n - 1] == '\n' || phys[n - 1] == '\r')) phys[--n] = '\0';
        }
        int cont = !eof && n && phys[n - 1] == '\\';
        if (cont) phys[--n] = '\0';
        if (skipping) {                 /* rest of an overlong rule */
            if (!cont) skipping = 0;
            if (eof) break;
            continue;
        }
        if (ll == 0) start_line = line_num;
        if (ll + n + 1 >= sizeof(line)) {
            fprintf(stderr, "%s:%d: rule longer than %d bytes, skipped\n",
                    path, start_line, RULE_LINE_MAX - 1);
            bad++;
            ll = 0;
            skipping = cont;
            if (eof) break;
            continue;
        }
        memcpy(line + ll, phys, n);
        ll += n;
        line[ll] = '\0';
        if (cont) {
            line[ll++] = ' ';
            line[ll] = '\0';
            continue;
        }
        if (ll == 0 && eof) break;

        char err[200];
        int rc = parse_var_line(rs, line, err, sizeof(err));
        if (rc == 0) {
            rule_t r;
            rc = rule_parse(rs, line, &r, err, sizeof(err));
            if (rc == 1) {
                r.file = kept;
                r.line = start_line;
                if (ruleset_add(rs, &r) < 0) {
                    fprintf(stderr, "%s:%d: duplicate sid %d (or out of memory), skipped\n",
                            path, start_line, r.sid);
                    rule_free(&r);
                    bad++;
                } else {
                    loaded++;
                }
            } else if (rc < 0) {
                fprintf(stderr, "%s:%d: %s, skipped\n", path, start_line, err);
                bad++;
            }
        } else if (rc < 0) {
            fprintf(stderr, "%s:%d: %s, skipped\n", path, start_line, err);
            bad++;
        }
        ll = 0;
        if (eof) break;
    }

    fclose(fp);
    if (errors) *errors = bad;
    return loaded;
}

/* ------------------------------------------------------------------ */
/* Compile                                                             */
/* ------------------------------------------------------------------ */

static int push_int(int **arr, int *n, int v) {
    int *a = realloc(*arr, (size_t)(*n + 1) * sizeof(int));
    if (!a) return -1;
    a[(*n)++] = v;
    *arr = a;
    return 0;
}

static int add_to_phase(ruleset_t *rs, rule_phase_t p, int i) {
    phase_data_t *ph = &rs->ph[p];
    const rule_t *r = &rs->rules[i];
    if (push_int(&ph->idx, &ph->n, i) < 0) return -1;
    if (r->fast_pattern < 0) return push_int(&ph->always, &ph->nalways, i);

    const rule_match_t *m = &r->m[r->fast_pattern];
    const uint8_t *pat = m->data;
    size_t len = m->len;
    if (m->dotprefix && pat[0] == '.') { pat++; len--; }
    if (!ph->mpm[m->buffer] && !(ph->mpm[m->buffer] = mpm_new())) return -1;
    return mpm_add(ph->mpm[m->buffer], pat, len, (uint32_t)i);
}

int ruleset_compile(ruleset_t *rs) {
    if (rs->compiled) return 0;
    rs->raw_span = 0;
    for (int i = 0; i < rs->n; i++) {
        const rule_t *r = &rs->rules[i];
        int raw = r->raw_tcp || r->raw_udp;
        if (raw) {
            if (r->raw_tcp && add_to_phase(rs, RULE_PHASE_TCP_STREAM, i) < 0) goto oom;
            if (r->raw_udp && add_to_phase(rs, RULE_PHASE_UDP, i) < 0) goto oom;
            if (r->raw_tcp) {
                const rule_match_t *m = &r->m[0];
                size_t span = (r->nm == 1 && m->type == RULE_MATCH_CONTENT && !m->negated)
                              ? m->len : SIZE_MAX;
                if (span > rs->raw_span) rs->raw_span = span;
            }
        } else if (add_to_phase(rs, (rule_phase_t)r->phase, i) < 0) {
            goto oom;
        }
    }
    for (int p = 0; p < RULE_PHASE_COUNT; p++)
        for (int b = 0; b < RULE_BUF_COUNT; b++)
            if (rs->ph[p].mpm[b] && mpm_build(rs->ph[p].mpm[b]) < 0) goto oom;

    rs->mark = calloc((size_t)(rs->n ? rs->n : 1), sizeof(*rs->mark));
    rs->cand = malloc((size_t)(rs->n ? rs->n : 1) * sizeof(*rs->cand));
    rs->match_data = pcre2_match_data_create(32, NULL);
    rs->match_ctx = pcre2_match_context_create(NULL);
    if (!rs->mark || !rs->cand || !rs->match_data || !rs->match_ctx) goto oom;
    pcre2_set_match_limit(rs->match_ctx, PCRE_MATCH_LIMIT);
    pcre2_set_depth_limit(rs->match_ctx, PCRE_DEPTH_LIMIT);
    rs->gen = 0;
    rs->compiled = 1;
    return 0;

oom:
    free_compiled(rs);
    return -1;
}

void ruleset_phase_info(const ruleset_t *rs, rule_phase_t p, rule_phase_info_t *out) {
    memset(out, 0, sizeof(*out));
    const phase_data_t *ph = &rs->ph[p];
    out->rules = (unsigned)ph->n;
    out->always = (unsigned)ph->nalways;
    out->prefiltered = (unsigned)(ph->n - ph->nalways);
    for (int b = 0; b < RULE_BUF_COUNT; b++) {
        if (!ph->mpm[b]) continue;
        out->patterns += mpm_pattern_count(ph->mpm[b]);
        out->states += mpm_state_count(ph->mpm[b]);
        out->memory += mpm_memory(ph->mpm[b]);
    }
}

size_t rules_raw_span(const ruleset_t *rs) {
    return rs ? rs->raw_span : 0;
}

/* ------------------------------------------------------------------ */
/* Header                                                              */
/* ------------------------------------------------------------------ */

static int cidr_match(const rule_cidr_t *c, const uint8_t *a, int ver) {
    if (c->version != ver) return 0;
    unsigned bits = c->prefix, i = 0;
    for (; bits >= 8; bits -= 8, i++)
        if (c->addr[i] != a[i]) return 0;
    if (bits) {
        uint8_t mask = (uint8_t)(0xff << (8 - bits));
        if ((c->addr[i] & mask) != (a[i] & mask)) return 0;
    }
    return 1;
}

static int addrs_match(const rule_addrs_t *s, const uint8_t *a, int ver) {
    int ok = s->npos == 0;
    for (int i = 0; !ok && i < s->npos; i++) ok = cidr_match(&s->pos[i], a, ver);
    for (int i = 0; ok && i < s->nneg; i++) ok = !cidr_match(&s->neg[i], a, ver);
    return ok;
}

static int ports_match(const rule_ports_t *s, uint16_t port) {
    int ok = s->npos == 0;
    for (int i = 0; !ok && i < s->npos; i++) ok = port >= s->pos[i].lo && port <= s->pos[i].hi;
    for (int i = 0; ok && i < s->nneg; i++) ok = !(port >= s->neg[i].lo && port <= s->neg[i].hi);
    return ok;
}

static int header_match(const rule_t *r, const rule_input_t *in) {
    switch (r->proto) {
    case RULE_PROTO_IP:  break;
    case RULE_PROTO_TCP: if (in->l4 != RULE_PROTO_TCP) return 0; break;
    case RULE_PROTO_UDP: if (in->l4 != RULE_PROTO_UDP) return 0; break;
    default:             if (in->app != r->proto) return 0; break;
    }
    if (r->flow & RULE_FLOW_TO_CLIENT) return 0;          /* never inspected */
    if ((r->flow & RULE_FLOW_ESTABLISHED) && !in->established) return 0;
    if ((r->flow & RULE_FLOW_NOT_ESTABLISHED) && in->established) return 0;

    static const uint8_t zero[16];
    const uint8_t *src = in->src ? in->src : zero, *dst = in->dst ? in->dst : zero;
    int v = in->ip_version;
    if (addrs_match(&r->src, src, v) && addrs_match(&r->dst, dst, v) &&
        ports_match(&r->sport, in->sport) && ports_match(&r->dport, in->dport))
        return 1;
    return r->bidirectional &&
           addrs_match(&r->src, dst, v) && addrs_match(&r->dst, src, v) &&
           ports_match(&r->sport, in->dport) && ports_match(&r->dport, in->sport);
}

int rules_raw_applies(const ruleset_t *rs, rule_phase_t phase, const rule_input_t *in) {
    if (!rs || !rs->compiled) return 0;
    const phase_data_t *ph = &rs->ph[phase];
    for (int i = 0; i < ph->n; i++)
        if (header_match(&rs->rules[ph->idx[i]], in)) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Conditions                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    const ruleset_t    *rs;
    const rule_input_t *in;
    const uint8_t      *dot[RULE_BUF_COUNT];  /* "." + buffer, lazily */
    size_t              dot_len[RULE_BUF_COUNT];
    int                 budget;
    size_t              hit_off;
} eval_t;

static uint8_t g_dotbuf[RULE_BUF_COUNT][DOTPREFIX_MAX + 1];

/* The bytes a condition sees; dotted is set when they are "." + buffer. */
static const uint8_t *view(eval_t *e, const rule_match_t *m, size_t *len, int *dotted) {
    const rule_input_t *in = e->in;
    *dotted = 0;
    const uint8_t *d = in->buf[m->buffer];
    if (!d) return NULL;
    *len = in->len[m->buffer];
    if (!m->dotprefix || *len > DOTPREFIX_MAX) return d;
    if (!e->dot[m->buffer]) {
        uint8_t *b = g_dotbuf[m->buffer];
        b[0] = '.';
        if (*len) memcpy(b + 1, d, *len);
        e->dot[m->buffer] = b;
        e->dot_len[m->buffer] = *len + 1;
    }
    *dotted = 1;
    *len = e->dot_len[m->buffer];
    return e->dot[m->buffer];
}

/* Search window [lo, hi) for a content: the match must lie inside it. */
static int content_window(const rule_match_t *m, size_t len, size_t prev,
                          size_t *lo, size_t *hi) {
    long a = 0, b = (long)len;
    if (m->startswith) b = (long)m->len < b ? (long)m->len : b;
    if (m->has_offset) a = m->offset;
    if (m->has_depth && a + m->depth < b) b = a + m->depth;
    if (m->relative) {
        long base = (long)prev;
        a = base + (m->has_distance ? m->distance : 0);
        if (a < 0) a = 0;
        if (m->has_within) {
            long w = base + (m->has_distance ? m->distance : 0) + m->within;
            if (w < b) b = w;
        }
    }
    if (m->endswith) {
        if (b < (long)len) return 0;
        long e = (long)len - (long)m->len;
        if (e > a) a = e;
    }
    if (a < 0 || b < a || b - a < (long)m->len) return 0;
    *lo = (size_t)a;
    *hi = (size_t)b;
    return 1;
}

/* pcre match from `start` in subj[0..len); fills so/eo. */
static int pcre_at(eval_t *e, const rule_match_t *m, const uint8_t *subj, size_t len,
                   size_t start, size_t *so, size_t *eo) {
    pcre2_match_data *md = e->rs->match_data;
    int rc = pcre2_match(m->re, subj, len, start, 0, md, e->rs->match_ctx);
    if (rc < 0) {
        if (rc == PCRE2_ERROR_MATCHLIMIT || rc == PCRE2_ERROR_DEPTHLIMIT ||
            rc == PCRE2_ERROR_JIT_STACKLIMIT)
            g_stats.pcre_limit++;
        return 0;
    }
    PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
    *so = ov[0];
    *eo = ov[1];
    return 1;
}

static int eval_from(eval_t *e, const rule_t *r, int i, const size_t *prev);

/* Continue with condition i+1 after condition i matched [at, end). */
static int advance(eval_t *e, const rule_t *r, int i, const size_t *prev, size_t end) {
    size_t next[RULE_BUF_COUNT];
    memcpy(next, prev, sizeof(next));
    next[r->m[i].buffer] = end;
    return eval_from(e, r, i + 1, next);
}

static int eval_from(eval_t *e, const rule_t *r, int i, const size_t *prev) {
    if (i == r->nm) return 1;
    const rule_match_t *m = &r->m[i];
    size_t len;
    int dotted;
    const uint8_t *d = view(e, m, &len, &dotted);
    if (!d) return 0;                         /* buffer not present */
    size_t pv = prev[m->buffer];

    if (m->type == RULE_MATCH_CONTENT) {
        size_t lo, hi;
        if (!content_window(m, len, pv, &lo, &hi))
            return m->negated ? eval_from(e, r, i + 1, prev) : 0;
        if (m->negated) {
            if (bytes_find(d + lo, hi - lo, m->data, m->len, m->nocase)) return 0;
            return eval_from(e, r, i + 1, prev);
        }
        for (size_t pos = lo;;) {
            if (--e->budget < 0) {
                g_stats.backtrack_limit++;
                return 0;
            }
            const uint8_t *f = bytes_find(d + pos, hi - pos, m->data, m->len, m->nocase);
            if (!f) return 0;
            size_t at = (size_t)(f - d);
            if (advance(e, r, i, prev, at + m->len)) {
                if (i == r->first_positive) e->hit_off = dotted ? (at ? at - 1 : 0) : at;
                return 1;
            }
            if (!m->backtrack) return 0;
            pos = at + 1;
            if (hi - pos < m->len) return 0;
        }
    }

    /* pcre: relative ones see the buffer from the previous match on. */
    size_t base = m->relative ? (pv < len ? pv : len) : 0;
    const uint8_t *subj = d + base;
    size_t slen = len - base, so, eo;
    if (m->negated) {
        if (pcre_at(e, m, subj, slen, 0, &so, &eo)) return 0;
        return eval_from(e, r, i + 1, prev);
    }
    for (size_t start = 0; start <= slen;) {
        if (--e->budget < 0) {
            g_stats.backtrack_limit++;
            return 0;
        }
        if (!pcre_at(e, m, subj, slen, start, &so, &eo)) return 0;
        if (advance(e, r, i, prev, base + eo)) {
            if (i == r->first_positive) {
                size_t at = base + so;
                e->hit_off = dotted ? (at ? at - 1 : 0) : at;
            }
            return 1;
        }
        if (!m->backtrack) return 0;
        start = so + 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Phase evaluation                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    ruleset_t *rs;
    int        ncand;
} cand_ctx_t;

#define CAND_ALERT_BIT 0x40000000   /* sorts pass rules before the others */

static void add_candidate(ruleset_t *rs, int *ncand, int idx) {
    if (rs->mark[idx] == rs->gen) return;
    rs->mark[idx] = rs->gen;
    int key = idx | (rs->rules[idx].action == RULE_ACTION_PASS ? 0 : CAND_ALERT_BIT);
    rs->cand[(*ncand)++] = key;
}

static void on_mpm(uint32_t id, size_t end, void *vctx) {
    (void)end;
    cand_ctx_t *c = vctx;
    add_candidate(c->rs, &c->ncand, (int)id);
}

static int cmp_int(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

int rules_eval(const ruleset_t *crs, rule_phase_t phase, const rule_input_t *in,
               rule_hit_fn hit, void *ctx) {
    ruleset_t *rs = (ruleset_t *)crs;        /* scratch state only */
    if (!rs || !rs->compiled || (unsigned)phase >= RULE_PHASE_COUNT) return 0;
    phase_data_t *ph = &rs->ph[phase];
    if (ph->n == 0) return 0;
    g_stats.evaluations++;

    if (++rs->gen == 0) {
        memset(rs->mark, 0, (size_t)rs->n * sizeof(*rs->mark));
        rs->gen = 1;
    }
    cand_ctx_t c = { rs, 0 };
    for (int b = 0; b < RULE_BUF_COUNT; b++)
        if (ph->mpm[b] && in->buf[b]) mpm_search(ph->mpm[b], in->buf[b], in->len[b], on_mpm, &c);
    for (int i = 0; i < ph->nalways; i++) add_candidate(rs, &c.ncand, ph->always[i]);
    if (c.ncand > 1) qsort(rs->cand, (size_t)c.ncand, sizeof(int), cmp_int);
    g_stats.candidates += (unsigned long)c.ncand;

    int matches = 0;
    for (int k = 0; k < c.ncand; k++) {
        const rule_t *r = &rs->rules[rs->cand[k] & ~CAND_ALERT_BIT];
        if (!header_match(r, in)) continue;
        eval_t e = { rs, in, { 0 }, { 0 }, BACKTRACK_BUDGET, 0 };
        size_t prev[RULE_BUF_COUNT] = { 0 };
        if (!eval_from(&e, r, 0, prev)) continue;
        matches++;
        g_stats.matches++;
        rule_buffer_t b = r->first_positive >= 0 ? (rule_buffer_t)r->m[r->first_positive].buffer
                                                 : (rule_buffer_t)r->m[0].buffer;
        if (hit) hit(r, b, e.hit_off, ctx);
        if (r->action == RULE_ACTION_PASS) break;
    }
    return matches;
}

/* ------------------------------------------------------------------ */
/* Lint                                                                */
/* ------------------------------------------------------------------ */

int ruleset_lint(const ruleset_t *rs, rule_warn_fn warn, void *ctx) {
    int n = 0;
    char msg[200];
#define WARN(...) do { snprintf(msg, sizeof(msg), __VA_ARGS__); if (warn) warn(r, msg, ctx); n++; } while (0)
    for (int i = 0; i < rs->n; i++) {
        const rule_t *r = &rs->rules[i];
        const char *ph = (r->raw_tcp || r->raw_udp) ? (r->raw_tcp ? "TCP stream" : "UDP packet")
                                                    : rule_phase_name((rule_phase_t)r->phase);
        if (r->fast_pattern < 0) {
            WARN("no content to prefilter on: verified on every %s inspection", ph);
        } else {
            const rule_match_t *m = &r->m[r->fast_pattern];
            size_t l = m->len - (m->dotprefix && m->data[0] == '.' ? 1 : 0);
            if (l < 3)
                WARN("fast pattern is only %zu byte%s: the prefilter selects this rule often",
                     l, l == 1 ? "" : "s");
        }
        if (r->raw_tcp && (r->proto == RULE_PROTO_IP || r->proto == RULE_PROTO_TCP) &&
            r->dport.npos == 0)
            WARN("raw rule on any port: every TCP stream is kept for reassembly and scanned");
        if (r->flow & RULE_FLOW_TO_CLIENT)
            WARN("flow:to_client never matches: only client-to-server data is inspected");
        if (r->action == RULE_ACTION_DROP)
            WARN("drop acts as alert: there is no IPS mode yet (Phase 6)");
        if (strncmp(r->msg, "sid ", 4) == 0)
            WARN("rule has no msg");
        for (int k = 0; k < r->nm; k++) {
            if (r->m[k].type == RULE_MATCH_PCRE && !r->m[k].relative && r->fast_pattern < 0) {
                WARN("pcre without a content anchor runs on every %s inspection", ph);
                break;
            }
        }
    }
#undef WARN
    return n;
}
