#ifndef SIMPLEIDS_SETTINGS_H
#define SIMPLEIDS_SETTINGS_H

/*
 * Run-time settings: compile-time defaults, then the config file (-c),
 * then command-line options, each overriding the one before.
 *
 * Config file format (an INI subset):
 *
 *   # comment            ; comment too (whole lines only)
 *   [section]
 *   key = value          value runs to the end of the line, trimmed;
 *                        "double quotes" around it are removed
 *
 * Every key has a dotted name, section.key (e.g. engine.max-flows), and
 * command-line options set the same names, so both are validated by
 * settings_set(). Unknown sections and keys are errors: a typo must not
 * silently leave a default in place. The file is untrusted input: lines
 * longer than SETTINGS_LINE_MAX and files larger than SETTINGS_FILE_MAX
 * are rejected.
 */

#include <stddef.h>
#include <stdint.h>

#include "simpleids/engine.h"

#define SETTINGS_LINE_MAX  4096
#define SETTINGS_FILE_MAX  (1024 * 1024)
#define SETTINGS_PATH_MAX  1024
#define SETTINGS_MAX_RULES 64
#define SETTINGS_MAX_VARS  32
#define SETTINGS_NAME_MAX  64

typedef struct {
    char name[SETTINGS_NAME_MAX];
    char value[SETTINGS_PATH_MAX];
} settings_var_t;

typedef struct {
    /* [capture] */
    char interface[SETTINGS_NAME_MAX];   /* "" = default                  */
    char file[SETTINGS_PATH_MAX];        /* pcap to read; "" = live       */
    char filter[SETTINGS_PATH_MAX];
    int  filter_set;                     /* filter given (even if empty)  */

    /* [rules] */
    char rule_paths[SETTINGS_MAX_RULES][SETTINGS_PATH_MAX];
    int  nrule_paths;                    /* 0 = default rule directories  */

    /* [vars] */
    settings_var_t vars[SETTINGS_MAX_VARS];
    int  nvars;

    /* [output] */
    char     log[SETTINGS_PATH_MAX];     /* "" = no log, "-" = stdout     */
    int      quiet;
    int      verbose;
    uint64_t log_max_size;               /* rotate past this; 0 = never   */
    unsigned log_max_files;              /* rotated files kept            */
    unsigned stats_interval;             /* seconds between stats events
                                            (and one at exit); 0 = none,
                                            but SIGUSR1 still writes one  */

    /* [engine] */
    engine_config_t engine;
    int  latency;                        /* time every packet             */

    /* [security] */
    char user[SETTINGS_NAME_MAX];        /* drop to this user; "" = stay  */
    char group[SETTINGS_NAME_MAX];       /* "" = the user's group         */
    int  sandbox;                        /* seccomp / macOS sandbox       */
} settings_t;

void settings_defaults(settings_t *s);

/*
 * Set one value by its dotted name ("engine.max-flows", "vars.HOME_NET").
 * rules.path appends a path. Returns 0, or -1 with a reason in err.
 */
int settings_set(settings_t *s, const char *key, const char *value, char *err, size_t errlen);

/* Report one problem: name is the file name, line its line number. */
typedef void (*settings_error_fn)(const char *name, int line, const char *msg, void *ctx);

/*
 * Parse config text buf[0..len) (need not be NUL-terminated) into s.
 * Every error is reported through err (if not NULL); parsing continues
 * after an error so that all of them are listed. Returns the number of
 * errors (0 = success).
 */
int settings_parse(settings_t *s, const char *name, const uint8_t *buf, size_t len,
                   settings_error_fn err, void *ctx);

/* Read and parse a file. Returns the number of errors, or -1 if the file
 * cannot be read (reported through err). */
int settings_load_file(settings_t *s, const char *path, settings_error_fn err, void *ctx);

/* Parse "64K", "1M", "1048576" (K/M/G suffixes). Returns 0 or -1. */
int settings_parse_size(const char *s, unsigned long long max, unsigned long long *out);

#endif
