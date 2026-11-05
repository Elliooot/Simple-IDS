#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simpleids/config.h"
#include "simpleids/output.h"
#include "simpleids/settings.h"

/* Limits shared with the rule parser's variable table. */
#define VAR_NAME_MAX  32
#define VAR_VALUE_MAX 512

__attribute__((format(printf, 3, 4)))
static int fail(char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

void settings_defaults(settings_t *s) {
    memset(s, 0, sizeof(*s));
    snprintf(s->log, sizeof(s->log), "%s", OUTPUT_DEFAULT_LOG);
    s->log_max_files = 5;
    s->sandbox = 1;
    engine_config_defaults(&s->engine);
}

int settings_parse_size(const char *s, unsigned long long max, unsigned long long *out) {
    char *end;
    if (*s < '0' || *s > '9') return -1;         /* no sign, no spaces */
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s) return -1;
    unsigned long long mul = 1;
    switch (*end) {
    case 'k': case 'K': mul = 1024ULL; end++; break;
    case 'm': case 'M': mul = 1024ULL * 1024; end++; break;
    case 'g': case 'G': mul = 1024ULL * 1024 * 1024; end++; break;
    default: break;
    }
    if (*end != '\0' || (mul > 1 && v > max / mul)) return -1;
    v *= mul;
    if (v > max) return -1;
    *out = v;
    return 0;
}

/* Printable text (tab allowed): no control bytes, no DEL. */
static int printable(const char *v) {
    for (const unsigned char *p = (const unsigned char *)v; *p; p++)
        if ((*p < 0x20 && *p != '\t') || *p == 0x7f) return 0;
    return 1;
}

/* User / group / interface names: [A-Za-z0-9._-]+ (also numeric ids). */
static int name_chars(const char *v) {
    if (!*v) return 0;
    for (const char *p = v; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' || *p == '-'))
            return 0;
    return 1;
}

static int parse_bool(const char *v, int *out) {
    static const char *const yes[] = { "yes", "true", "on", "1" };
    static const char *const no[] = { "no", "false", "off", "0" };
    for (size_t i = 0; i < 4; i++) {
        if (strcmp(v, yes[i]) == 0) { *out = 1; return 0; }
        if (strcmp(v, no[i]) == 0) { *out = 0; return 0; }
    }
    return -1;
}

static int set_str(char *dst, size_t cap, const char *key, const char *v, char *err,
                   size_t errlen) {
    if (strlen(v) >= cap) return fail(err, errlen, "%s: value too long (max %zu)", key, cap - 1);
    if (!printable(v)) return fail(err, errlen, "%s: control characters in value", key);
    memcpy(dst, v, strlen(v) + 1);
    return 0;
}

typedef enum { K_STR, K_NAME, K_BOOL, K_SIZE, K_U32, K_SECONDS, K_PATHS, K_OVERLAP,
               K_LOG } key_type_t;

typedef struct {
    const char *key;
    key_type_t  type;
    size_t      off;      /* offset in settings_t */
    size_t      size;     /* string buffer size   */
    unsigned long long min, max;
} key_def_t;

#define F(field) offsetof(settings_t, field), sizeof(((settings_t *)0)->field)
#define E(field) offsetof(settings_t, engine.field), sizeof(((settings_t *)0)->engine.field)

static const key_def_t KEYS[] = {
    { "capture.interface",           K_NAME,    F(interface),         0, 0 },
    { "capture.file",                K_STR,     F(file),              0, 0 },
    { "capture.filter",              K_STR,     F(filter),            0, 0 },
    { "rules.path",                  K_PATHS,   0, 0,                 0, 0 },
    { "output.log",                  K_LOG,     F(log),               0, 0 },
    { "output.quiet",                K_BOOL,    F(quiet),             0, 0 },
    { "output.verbose",              K_BOOL,    F(verbose),           0, 0 },
    { "output.log-max-size",         K_SIZE,    F(log_max_size),      0, 1ULL << 40 },
    { "output.log-max-files",        K_U32,     F(log_max_files),     1, 100 },
    { "output.stats-interval",       K_SECONDS, F(stats_interval),    0, 86400 },
    { "engine.max-flows",            K_SIZE,    E(flow.max_flows),    1, 50000000 },
    { "engine.stream-depth",         K_SIZE,    E(stream.depth),      1, 1ULL << 30 },
    { "engine.stream-memcap",        K_SIZE,    E(stream.memcap),     1, SIZE_MAX },
    { "engine.overlap",              K_OVERLAP, E(stream.policy),     0, 0 },
    { "engine.measure-latency",      K_BOOL,    F(latency),           0, 0 },
    { "engine.timeout-new",          K_SECONDS, E(flow.timeout_new),  1, 86400 },
    { "engine.timeout-established",  K_SECONDS, E(flow.timeout_established), 1, 86400 },
    { "engine.timeout-closed",       K_SECONDS, E(flow.timeout_closed), 1, 86400 },
    { "engine.timeout-udp",          K_SECONDS, E(flow.timeout_udp),  1, 86400 },
    { "security.user",               K_NAME,    F(user),              0, 0 },
    { "security.group",              K_NAME,    F(group),             0, 0 },
    { "security.sandbox",            K_BOOL,    F(sandbox),           0, 0 },
};

/* Store v into an unsigned field of 4 or 8 bytes. */
static void put_uint(void *p, size_t size, unsigned long long v) {
    if (size == sizeof(uint32_t)) { uint32_t x = (uint32_t)v; memcpy(p, &x, sizeof(x)); }
    else { uint64_t x = v; memcpy(p, &x, sizeof(x)); }
}

static int set_var_key(settings_t *s, const char *name, const char *v, char *err,
                       size_t errlen) {
    size_t n = strlen(name);
    if (n == 0 || n >= VAR_NAME_MAX)
        return fail(err, errlen, "vars: name must be 1-%d characters", VAR_NAME_MAX - 1);
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_'))
            return fail(err, errlen, "vars: bad variable name '%s'", name);
    }
    if (!*v || strlen(v) >= VAR_VALUE_MAX || !printable(v))
        return fail(err, errlen, "vars.%s: value must be 1-%d printable characters", name,
                    VAR_VALUE_MAX - 1);
    int i;
    for (i = 0; i < s->nvars; i++)
        if (strcmp(s->vars[i].name, name) == 0) break;
    if (i == s->nvars) {
        if (s->nvars == SETTINGS_MAX_VARS)
            return fail(err, errlen, "vars: too many variables (max %d)", SETTINGS_MAX_VARS);
        s->nvars++;
    }
    snprintf(s->vars[i].name, sizeof(s->vars[i].name), "%s", name);
    snprintf(s->vars[i].value, sizeof(s->vars[i].value), "%s", v);
    return 0;
}

int settings_set(settings_t *s, const char *key, const char *v, char *err, size_t errlen) {
    if (strncmp(key, "vars.", 5) == 0) return set_var_key(s, key + 5, v, err, errlen);

    const key_def_t *k = NULL;
    for (size_t i = 0; i < sizeof(KEYS) / sizeof(KEYS[0]); i++)
        if (strcmp(KEYS[i].key, key) == 0) { k = &KEYS[i]; break; }
    if (!k) return fail(err, errlen, "unknown setting '%s'", key);

    char *field = (char *)s + k->off;
    unsigned long long n;
    int b;
    switch (k->type) {
    case K_STR:
        if (set_str(field, k->size, key, v, err, errlen) < 0) return -1;
        if (strcmp(key, "capture.filter") == 0) s->filter_set = 1;
        return 0;
    case K_LOG:
        if (!*v) return fail(err, errlen, "%s: empty (use 'none' for no log)", key);
        return set_str(field, k->size, key, strcmp(v, "none") == 0 ? "" : v, err, errlen);
    case K_NAME:
        if (strlen(v) >= k->size || (*v && !name_chars(v)))
            return fail(err, errlen, "%s: '%s' is not a valid name", key, v);
        memcpy(field, v, strlen(v) + 1);
        return 0;
    case K_BOOL:
        if (parse_bool(v, &b) < 0) return fail(err, errlen, "%s: expected yes or no", key);
        memcpy(field, &b, sizeof(b));
        return 0;
    case K_SIZE:
    case K_SECONDS:
    case K_U32:
        if (settings_parse_size(v, k->max, &n) < 0 || n < k->min ||
            (k->type != K_SIZE && strspn(v, "0123456789") != strlen(v)))
            return fail(err, errlen, "%s: '%s' is not a number in %llu..%llu%s", key, v,
                        k->min, k->max, k->type == K_SIZE ? " (K/M/G allowed)" : "");
        if (k->size == sizeof(uint32_t) && n > UINT32_MAX)
            return fail(err, errlen, "%s: too large", key);
        put_uint(field, k->size, n);
        return 0;
    case K_PATHS:
        if (s->nrule_paths == SETTINGS_MAX_RULES)
            return fail(err, errlen, "%s: too many rule paths (max %d)", key, SETTINGS_MAX_RULES);
        if (!*v) return fail(err, errlen, "%s: empty path", key);
        if (set_str(s->rule_paths[s->nrule_paths], SETTINGS_PATH_MAX, key, v, err, errlen) < 0)
            return -1;
        s->nrule_paths++;
        return 0;
    case K_OVERLAP: {
        overlap_policy_t p;
        if (strcmp(v, "first") == 0) p = OVERLAP_FIRST;
        else if (strcmp(v, "last") == 0) p = OVERLAP_LAST;
        else return fail(err, errlen, "%s: expected first or last", key);
        memcpy(field, &p, sizeof(p));
        return 0;
    }
    }
    return fail(err, errlen, "unknown setting '%s'", key);
}

static int is_blank(char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

int settings_parse(settings_t *s, const char *name, const uint8_t *buf, size_t len,
                   settings_error_fn report, void *ctx) {
    char section[SETTINGS_NAME_MAX] = "";
    char line[SETTINGS_LINE_MAX];
    char msg[SETTINGS_LINE_MAX + 128];
    int errors = 0, lineno = 0;

#define REPORT(...) do {                                   \
        snprintf(msg, sizeof(msg), __VA_ARGS__);              \
        if (report) report(name, lineno, msg, ctx);           \
        errors++;                                             \
    } while (0)

    if (len > SETTINGS_FILE_MAX) {
        REPORT("file larger than %d bytes", SETTINGS_FILE_MAX);
        return errors;
    }
    for (size_t pos = 0; pos < len;) {
        const uint8_t *nl = memchr(buf + pos, '\n', len - pos);
        size_t end = nl ? (size_t)(nl - buf) : len;
        size_t n = end - pos;
        lineno++;
        if (n >= sizeof(line)) {
            REPORT("line longer than %d bytes", SETTINGS_LINE_MAX - 1);
            pos = end + 1;
            continue;
        }
        memcpy(line, buf + pos, n);
        line[n] = '\0';
        pos = end + 1;
        if (memchr(line, '\0', n)) {
            REPORT("NUL byte in line");
            continue;
        }

        /* Trim. */
        char *p = line;
        while (is_blank(*p)) p++;
        size_t l = strlen(p);
        while (l && is_blank(p[l - 1])) p[--l] = '\0';
        if (l == 0 || *p == '#' || *p == ';') continue;

        if (*p == '[') {
            if (p[l - 1] != ']' || l < 3 || l - 2 >= sizeof(section)) {
                REPORT("malformed section header");
                section[0] = '\1';      /* keys below it are errors too */
                continue;
            }
            memcpy(section, p + 1, l - 2);
            section[l - 2] = '\0';
            if (strcmp(section, "capture") && strcmp(section, "rules") &&
                strcmp(section, "vars") && strcmp(section, "output") &&
                strcmp(section, "engine") && strcmp(section, "security")) {
                REPORT("unknown section [%s]", section);
                section[0] = '\1';
            }
            continue;
        }

        char *eq = strchr(p, '=');
        if (!eq) {
            REPORT("expected key = value");
            continue;
        }
        char *kend = eq;
        while (kend > p && is_blank(kend[-1])) kend--;
        *kend = '\0';
        char *v = eq + 1;
        while (is_blank(*v)) v++;
        size_t vl = strlen(v);
        if (vl >= 2 && v[0] == '"' && v[vl - 1] == '"') {
            v[vl - 1] = '\0';
            v++;
        }
        if (section[0] == '\1') continue;           /* already reported */
        if (!section[0]) {
            REPORT("'%s' outside of a [section]", p);
            continue;
        }
        if (!*p) {
            REPORT("missing key before '='");
            continue;
        }

        char key[SETTINGS_NAME_MAX * 2 + 2], err[SETTINGS_LINE_MAX + 64];
        if ((size_t)snprintf(key, sizeof(key), "%s.%s", section, p) >= sizeof(key)) {
            REPORT("key too long");
            continue;
        }
        if (settings_set(s, key, v, err, sizeof(err)) < 0) REPORT("%s", err);
    }
#undef REPORT
    return errors;
}

int settings_load_file(settings_t *s, const char *path, settings_error_fn report, void *ctx) {
    FILE *fp = fopen(path, "rb");
    char msg[256];
    if (!fp) {
        snprintf(msg, sizeof(msg), "cannot open: %s", strerror(errno));
        if (report) report(path, 0, msg, ctx);
        return -1;
    }
    uint8_t *buf = malloc(SETTINGS_FILE_MAX + 1);
    size_t n = buf ? fread(buf, 1, SETTINGS_FILE_MAX + 1, fp) : 0;
    int rc;
    if (!buf || ferror(fp)) {
        snprintf(msg, sizeof(msg), "cannot read: %s", buf ? strerror(errno) : "out of memory");
        if (report) report(path, 0, msg, ctx);
        rc = -1;
    } else {
        rc = settings_parse(s, path, buf, n, report, ctx);
    }
    free(buf);
    fclose(fp);
    return rc;
}
