#include <stdlib.h>
#include <string.h>

#include "simpleids/mpm.h"

typedef struct {
    uint8_t *bytes;
    size_t   len;
    uint32_t id;
} mpm_pattern_t;

typedef struct {
    uint32_t state;
    uint32_t id;
} mpm_output_t;

struct mpm {
    mpm_pattern_t *pats;
    uint32_t       npats, cap;
    int            built;

    uint8_t   cls[256];       /* byte -> input class (case folded)       */
    uint32_t  nclass;
    uint32_t  nstates;
    int32_t  *next;           /* nstates x nclass, complete DFA          */
    uint32_t *out_start;      /* per state: first entry in out_ids       */
    uint32_t *out_count;      /* per state: patterns ending here         */
    uint32_t *out_ids;
    int32_t  *dict;           /* nearest suffix state with outputs, -1   */
};

static uint8_t lower(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

mpm_t *mpm_new(void) {
    return calloc(1, sizeof(mpm_t));
}

int mpm_add(mpm_t *m, const uint8_t *pat, size_t len, uint32_t id) {
    if (m->built || len == 0) return -1;
    if (m->npats == m->cap) {
        uint32_t ncap = m->cap ? m->cap * 2 : 16;
        mpm_pattern_t *n = realloc(m->pats, ncap * sizeof(*n));
        if (!n) return -1;
        m->pats = n;
        m->cap = ncap;
    }
    uint8_t *copy = malloc(len);
    if (!copy) return -1;
    for (size_t i = 0; i < len; i++) copy[i] = lower(pat[i]);
    m->pats[m->npats++] = (mpm_pattern_t){ copy, len, id };
    return 0;
}

static int cmp_output(const void *a, const void *b) {
    const mpm_output_t *x = a, *y = b;
    if (x->state != y->state) return x->state < y->state ? -1 : 1;
    return x->id < y->id ? -1 : x->id > y->id;
}

int mpm_build(mpm_t *m) {
    if (m->built) return 0;

    /* Alphabet: every (lower-cased) byte used by a pattern gets a class. */
    uint8_t used_class[256] = { 0 };
    uint32_t nclass = 1;                         /* class 0: unused bytes */
    size_t total = 0;
    for (uint32_t p = 0; p < m->npats; p++) {
        total += m->pats[p].len;
        for (size_t i = 0; i < m->pats[p].len; i++) {
            uint8_t b = m->pats[p].bytes[i];
            if (!used_class[b]) used_class[b] = (uint8_t)nclass++;
        }
    }
    for (int b = 0; b < 256; b++) m->cls[b] = used_class[lower((uint8_t)b)];
    m->nclass = nclass;

    size_t maxstates = total + 1;
    int32_t *next = malloc(maxstates * nclass * sizeof(*next));
    mpm_output_t *outs = malloc((m->npats ? m->npats : 1) * sizeof(*outs));
    uint32_t *queue = malloc(maxstates * sizeof(*queue));
    int32_t *fail = malloc(maxstates * sizeof(*fail));
    int32_t *dict = malloc(maxstates * sizeof(*dict));
    uint32_t *out_count = calloc(maxstates, sizeof(*out_count));
    if (!next || !outs || !queue || !fail || !dict || !out_count) goto oom;
    for (size_t i = 0; i < maxstates * nclass; i++) next[i] = -1;

    /* Trie. */
    uint32_t nstates = 1;
    for (uint32_t p = 0; p < m->npats; p++) {
        uint32_t s = 0;
        for (size_t i = 0; i < m->pats[p].len; i++) {
            int32_t *t = &next[(size_t)s * nclass + m->cls[m->pats[p].bytes[i]]];
            if (*t < 0) *t = (int32_t)nstates++;
            s = (uint32_t)*t;
        }
        outs[p] = (mpm_output_t){ s, m->pats[p].id };
        out_count[s]++;
    }

    /* Failure links breadth-first, filling in the missing transitions so
     * the table becomes a DFA (a state's row is complete before any
     * deeper state reads it). */
    uint32_t qh = 0, qt = 0;
    fail[0] = 0;
    dict[0] = -1;
    for (uint32_t c = 0; c < nclass; c++) {
        int32_t u = next[c];
        if (u < 0) {
            next[c] = 0;
        } else {
            fail[u] = 0;
            dict[u] = -1;
            queue[qt++] = (uint32_t)u;
        }
    }
    while (qh < qt) {
        uint32_t r = queue[qh++];
        for (uint32_t c = 0; c < nclass; c++) {
            int32_t *t = &next[(size_t)r * nclass + c];
            int32_t via_fail = next[(size_t)fail[r] * nclass + c];
            if (*t < 0) {
                *t = via_fail;
            } else {
                int32_t u = *t;
                fail[u] = via_fail;
                dict[u] = out_count[via_fail] ? via_fail : dict[via_fail];
                queue[qt++] = (uint32_t)u;
            }
        }
    }

    /* Outputs grouped by state. */
    qsort(outs, m->npats, sizeof(*outs), cmp_output);
    uint32_t *out_start = calloc(nstates, sizeof(*out_start));
    uint32_t *out_ids = malloc((m->npats ? m->npats : 1) * sizeof(*out_ids));
    if (!out_start || !out_ids) {
        free(out_start);
        free(out_ids);
        goto oom;
    }
    for (uint32_t i = 0; i < m->npats; i++) {
        out_ids[i] = outs[i].id;
        if (i == 0 || outs[i].state != outs[i - 1].state) out_start[outs[i].state] = i;
    }

    int32_t *shrunk = realloc(next, (size_t)nstates * nclass * sizeof(*next));
    m->next = shrunk ? shrunk : next;
    m->nstates = nstates;
    m->out_start = out_start;
    m->out_ids = out_ids;
    m->out_count = out_count;
    m->dict = dict;
    m->built = 1;
    free(outs);
    free(queue);
    free(fail);
    for (uint32_t p = 0; p < m->npats; p++) free(m->pats[p].bytes);
    free(m->pats);
    m->pats = NULL;
    m->cap = 0;
    return 0;

oom:
    free(next);
    free(outs);
    free(queue);
    free(fail);
    free(dict);
    free(out_count);
    return -1;
}

static size_t report(const mpm_t *m, int32_t s, size_t end, mpm_match_fn cb, void *ctx) {
    size_t n = 0;
    for (; s > 0; s = m->dict[s]) {
        uint32_t c = m->out_count[s];
        const uint32_t *ids = m->out_ids + m->out_start[s];
        for (uint32_t i = 0; i < c; i++) {
            if (cb) cb(ids[i], end, ctx);
            n++;
        }
    }
    return n;
}

size_t mpm_search(const mpm_t *m, const uint8_t *buf, size_t len, mpm_match_fn cb, void *ctx) {
    if (!m->built || m->npats == 0) return 0;
    size_t n = 0;
    int32_t s = 0;
    const int32_t *next = m->next;
    const uint32_t nclass = m->nclass;
    for (size_t i = 0; i < len; i++) {
        s = next[(size_t)s * nclass + m->cls[buf[i]]];
        if (m->out_count[s] || m->dict[s] >= 0) n += report(m, s, i + 1, cb, ctx);
    }
    return n;
}

uint32_t mpm_pattern_count(const mpm_t *m) {
    return m->npats;
}

uint32_t mpm_state_count(const mpm_t *m) {
    return m->nstates;
}

size_t mpm_memory(const mpm_t *m) {
    if (!m->built) return 0;
    return (size_t)m->nstates * m->nclass * sizeof(int32_t) +
           (size_t)m->nstates * (2 * sizeof(uint32_t) + sizeof(int32_t)) +
           (size_t)m->npats * sizeof(uint32_t);
}

void mpm_free(mpm_t *m) {
    if (!m) return;
    for (uint32_t p = 0; m->pats && p < m->npats; p++) free(m->pats[p].bytes);
    free(m->pats);
    free(m->next);
    free(m->out_start);
    free(m->out_count);
    free(m->out_ids);
    free(m->dict);
    free(m);
}
