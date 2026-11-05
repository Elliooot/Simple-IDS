#ifndef SIMPLEIDS_RULESET_INT_H
#define SIMPLEIDS_RULESET_INT_H

/* Internals shared by rule_parse.c and detect.c. */

#include "simpleids/mpm.h"
#include "simpleids/rules.h"

#define RULE_VAR_NAME_MAX  32
#define RULE_VAR_VALUE_MAX 512

typedef struct {
    char name[RULE_VAR_NAME_MAX];
    char value[RULE_VAR_VALUE_MAX];
} rule_var_t;

typedef struct {
    int    *idx;                    /* rules of this phase, load order   */
    int     n;
    int    *always;                 /* no fast pattern: always verified  */
    int     nalways;
    mpm_t  *mpm[RULE_BUF_COUNT];    /* fast patterns per buffer          */
} phase_data_t;

struct ruleset {
    rule_t     *rules;
    int         n, cap;
    rule_var_t  vars[RULE_VAR_MAX];
    int         nvars;
    char      **files;              /* paths that rule_t.file points to  */
    int         nfiles;

    int           compiled;
    phase_data_t ph[RULE_PHASE_COUNT];
    uint32_t     *mark;             /* candidate dedupe, by generation   */
    uint32_t      gen;
    int          *cand;
    size_t        raw_span;
    void         *match_data;       /* pcre2_match_data *                */
    void         *match_ctx;        /* pcre2_match_context *             */
};

/* Look up a variable: the ruleset's own, then the global ones, then the
 * built-in defaults. Returns NULL when undefined. */
const char *ruleset_var(const ruleset_t *rs, const char *name);

/* Compile / free a pcre condition (rule_parse.c). */
int  rule_pcre_compile(rule_match_t *m, int flags, char *err, size_t errlen);
void rule_pcre_free(rule_match_t *m);

#endif
