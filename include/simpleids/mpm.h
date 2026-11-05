#ifndef SIMPLEIDS_MPM_H
#define SIMPLEIDS_MPM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Multi-pattern matcher: Aho-Corasick, case-insensitive (ASCII).
 *
 * Used as a prefilter: every rule contributes one "fast pattern", one
 * pass over a buffer finds every rule whose fast pattern occurs, and only
 * those rules are verified in full. Matching is case-insensitive so that
 * nocase and case-sensitive patterns share one automaton; the full
 * verification afterwards enforces case where the rule asks for it.
 *
 * The automaton is a complete DFA over a compressed alphabet: bytes that
 * occur in no pattern share one input class, so the transition table is
 * (states x classes) rather than (states x 256).
 */

typedef struct mpm mpm_t;

/* Called for every occurrence; end is the offset just past the match. */
typedef void (*mpm_match_fn)(uint32_t id, size_t end, void *ctx);

mpm_t *mpm_new(void);

/* Add a pattern (len >= 1) reported as id. Returns 0, or -1 when out of
 * memory or after mpm_build(). The same bytes may be added with
 * several ids; each id is then reported. */
int mpm_add(mpm_t *m, const uint8_t *pat, size_t len, uint32_t id);

/* Build the automaton. Returns 0 or -1 (out of memory). */
int mpm_build(mpm_t *m);

/* Report every pattern occurring in buf[0..len). Returns the number of
 * occurrences reported. Requires mpm_build(). */
size_t mpm_search(const mpm_t *m, const uint8_t *buf, size_t len, mpm_match_fn cb, void *ctx);

uint32_t mpm_pattern_count(const mpm_t *m);
uint32_t mpm_state_count(const mpm_t *m);
size_t   mpm_memory(const mpm_t *m);

void mpm_free(mpm_t *m);

#endif
