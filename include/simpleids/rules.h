#ifndef SIMPLEIDS_RULES_H
#define SIMPLEIDS_RULES_H

#include <stddef.h>
#include <stdint.h>

#define RULE_MSG_MAX      128
#define RULE_CONTENT_MAX  256
#define RULE_PROTO_MAX    8

typedef struct {
    int      sid;
    int      priority;
    char     msg[RULE_MSG_MAX];
    char     protocol[RULE_PROTO_MAX]; /* "tcp" or "ip"                   */
    int      dst_port;                 /* 0 = any                         */
    uint8_t  content[RULE_CONTENT_MAX];/* raw bytes after unescaping       */
    size_t   content_len;              /* always > 0 for a loaded rule     */
    int      nocase;
} rule_t;

/*
 * Parse one line of a rules file.
 *   returns  1  a rule was parsed into *out
 *   returns  0  blank line or comment
 *   returns -1  syntax error; a description is written into err
 *
 * Supported syntax (a subset of Snort/Suricata):
 *   alert <tcp|ip> <src> <sport> -> <dst> <any|port> (options)
 * Options: content:"..." (required, exactly one), msg:"...", sid:N
 * (required), nocase, priority:N, and the ignored metadata keywords rev,
 * classtype, reference, metadata.
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
 * Run every enabled rule for (protocol, dst_port) over buf[0..len).
 * Calls hit() for each matching rule and returns the number of matches.
 */
int rules_match(const uint8_t *buf, size_t len, const char *protocol,
                int dst_port, rule_hit_fn hit, void *ctx);

/* Add an already-parsed rule (used by the loader and by tests).
 * Returns 0, or -1 when the sid is a duplicate or memory runs out. */
int rules_add(const rule_t *rule);

int  rules_count(void);

/* Longest content of any loaded rule (0 when none): a match can span at
 * most this many bytes, which bounds how far back a stream rescan goes. */
size_t rules_max_content_len(void);
void rules_free(void);

#endif
