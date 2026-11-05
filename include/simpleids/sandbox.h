#ifndef SIMPLEIDS_SANDBOX_H
#define SIMPLEIDS_SANDBOX_H

/*
 * Least privilege, applied once the capture device, the rules and the log
 * are open (src/core/main.c):
 *
 * 1. priv_drop(): leave root for an unprivileged user (setgroups, setgid,
 *    setuid, in that order) and check that root cannot be regained. The
 *    capture handle stays usable: the kernel checked permissions when it
 *    was opened.
 *
 * 2. sandbox_enter(): restrict what the process can still ask the kernel.
 *    Linux: a seccomp-BPF allowlist. What is left is reading packets,
 *    memory management, reading rule files (SIGHUP reload), writing and
 *    rotating the log, and signals. Creating sockets, connecting,
 *    exec, fork/clone, ptrace and everything else not on the list stops
 *    the process with a message naming the system call. macOS: a
 *    sandbox_init() profile denying network access, exec and fork.
 *    Builds with sanitizers skip it (LeakSanitizer needs ptrace and clone).
 */

#include <stddef.h>
#include <sys/types.h>

/* Resolve user and group names (or numeric ids). group may be NULL or
 * "": the user's primary group. Returns 0, or -1 with a reason in err. */
int priv_resolve(const char *user, const char *group, uid_t *uid, gid_t *gid,
                 char *err, size_t errlen);

/* Switch to uid/gid for good. Returns 0, or -1 with a reason in err. */
int priv_drop(uid_t uid, gid_t gid, char *err, size_t errlen);

/*
 * Enter the sandbox. Returns 1 when it is in force, 0 when this platform
 * or build has none (err says why), -1 when installing it failed.
 */
int sandbox_enter(char *err, size_t errlen);

/* A short description of the active sandbox ("seccomp-bpf, 64 system
 * calls allowed"), or "none". */
const char *sandbox_describe(void);

#endif
