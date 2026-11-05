#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "simpleids/sandbox.h"

#if defined(__SANITIZE_ADDRESS__) || defined(SIMPLEIDS_FUZZING)
#define SANITIZER_BUILD 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SANITIZER_BUILD 1
#endif
#endif

static char g_desc[96] = "none";

const char *sandbox_describe(void) {
    return g_desc;
}

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

/* A decimal id, the whole string. */
static int numeric_id(const char *s, unsigned long *out) {
    char *end;
    if (!*s || *s < '0' || *s > '9') return 0;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || *end || v > 0x7fffffffUL) return 0;
    *out = v;
    return 1;
}

int priv_resolve(const char *user, const char *group, uid_t *uid, gid_t *gid,
                 char *err, size_t errlen) {
    unsigned long id;
    struct passwd *pw = numeric_id(user, &id) ? getpwuid((uid_t)id) : getpwnam(user);
    if (pw) {
        *uid = pw->pw_uid;
        *gid = pw->pw_gid;
    } else if (numeric_id(user, &id)) {
        *uid = (uid_t)id;              /* an id without a passwd entry */
        *gid = (gid_t)id;
    } else {
        return fail(err, errlen, "unknown user '%s'", user);
    }
    if (group && *group) {
        struct group *gr = numeric_id(group, &id) ? getgrgid((gid_t)id) : getgrnam(group);
        if (gr) *gid = gr->gr_gid;
        else if (numeric_id(group, &id)) *gid = (gid_t)id;
        else return fail(err, errlen, "unknown group '%s'", group);
    }
    return 0;
}

int priv_drop(uid_t uid, gid_t gid, char *err, size_t errlen) {
    if (geteuid() != 0) {
        if (uid == geteuid() && gid == getegid()) return 0;    /* nothing to do */
        return fail(err, errlen, "only root can switch to another user");
    }
    /* Supplementary groups first (root's would survive setgid), then the
     * group, then the user: after setuid we could not change groups. */
    if (setgroups(1, &gid) < 0) return fail(err, errlen, "setgroups: %s", strerror(errno));
    if (setgid(gid) < 0) return fail(err, errlen, "setgid(%u): %s", (unsigned)gid, strerror(errno));
    if (setuid(uid) < 0) return fail(err, errlen, "setuid(%u): %s", (unsigned)uid, strerror(errno));
    if (uid != 0 && (setuid(0) == 0 || seteuid(0) == 0))
        return fail(err, errlen, "root privileges could be regained after setuid");
    if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid)
        return fail(err, errlen, "ids did not change as expected");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Linux: seccomp-BPF                                                  */
/* ------------------------------------------------------------------ */
#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <termios.h>

#if defined(__x86_64__)
#define SB_ARCH AUDIT_ARCH_X86_64
#else
#define SB_ARCH AUDIT_ARCH_AARCH64
#endif

#ifndef SANITIZER_BUILD
/* Everything the packet loop, a rule reload and log rotation need. */
static const int ALLOWED[] = {
    /* I/O on descriptors that are already open (capture, log, stdio) */
    __NR_read, __NR_write, __NR_readv, __NR_writev, __NR_pread64, __NR_lseek,
    __NR_close, __NR_fstat, __NR_fcntl, __NR_ppoll, __NR_pselect6,
    __NR_recvfrom, __NR_recvmsg, __NR_getsockopt,
    __NR_setsockopt,        /* pcap_close() tears down the packet ring */
#ifdef __NR_poll
    __NR_poll,
#endif
#ifdef __NR_select
    __NR_select,
#endif
    /* Rule files (SIGHUP reload: open, glob a directory, stat) */
    __NR_openat, __NR_getdents64, __NR_newfstatat, __NR_faccessat,
#ifdef __NR_statx
    __NR_statx,
#endif
#ifdef __NR_open
    __NR_open,
#endif
#ifdef __NR_stat
    __NR_stat, __NR_lstat,
#endif
#ifdef __NR_access
    __NR_access,
#endif
#ifdef __NR_faccessat2
    __NR_faccessat2,
#endif
    /* Log rotation */
    __NR_renameat, __NR_unlinkat,
#ifdef __NR_renameat2
    __NR_renameat2,
#endif
#ifdef __NR_rename
    __NR_rename, __NR_unlink,
#endif
    /* Memory (malloc, PCRE2 JIT on reload) */
    __NR_brk, __NR_mmap, __NR_munmap, __NR_mremap, __NR_mprotect, __NR_madvise,
    /* Time, randomness, resource usage */
    __NR_clock_gettime, __NR_gettimeofday, __NR_getrusage, __NR_getrandom,
    __NR_clock_nanosleep,
    /* Signals, threads' futexes, exit */
    __NR_rt_sigaction, __NR_rt_sigprocmask, __NR_rt_sigreturn, __NR_sigaltstack,
    __NR_restart_syscall, __NR_futex, __NR_sched_yield, __NR_getpid, __NR_gettid,
    __NR_tgkill, __NR_exit, __NR_exit_group,
};

static void on_sigsys(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)uc;
    char msg[96] = "SimpleIDS: sandbox blocked system call ";
    size_t n = strlen(msg);
    char digits[16];
    int d = 0;
    unsigned v = (unsigned)si->si_syscall;
    do { digits[d++] = (char)('0' + v % 10); v /= 10; } while (v && d < 15);
    while (d) msg[n++] = digits[--d];
    memcpy(msg + n, ", exiting\n", 10);
    n += 10;
    ssize_t w = write(STDERR_FILENO, msg, n);
    (void)w;
    _exit(128 + SIGSYS);
}
#endif

int sandbox_enter(char *err, size_t errlen) {
#ifdef SANITIZER_BUILD
    fail(err, errlen, "not used in sanitizer builds");
    return 0;
#else
    enum { N = sizeof(ALLOWED) / sizeof(ALLOWED[0]) };
    struct sock_filter f[2 * N + 16];
    size_t i = 0;

#define STMT(c, k)        (f[i++] = (struct sock_filter)BPF_STMT((c), (k)))
#define JUMP(c, k, t, e)  (f[i++] = (struct sock_filter)BPF_JUMP((c), (k), (t), (e)))
    STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, SB_ARCH, 1, 0);
    STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    /* x32 system calls share the arch value; refuse them all. */
    JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1);
    STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif
    for (size_t k = 0; k < N; k++) {
        JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ALLOWED[k], 0, 1);
        STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        if (i + 8 > sizeof(f) / sizeof(f[0])) return fail(err, errlen, "filter too large");
    }
    /* ioctl only for isatty() (stdio asks TCGETS on first output). */
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 3);
    STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1]));
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCGETS, 0, 1);
    STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP);
#undef STMT
#undef JUMP

    /* Already a 2-instruction loop for N entries: the filter must fit the
     * kernel's limit (BPF_MAXINSNS = 4096) with room to spare. */
    struct sock_fprog prog = { (unsigned short)i, f };

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSYS, &sa, NULL) < 0)
        return fail(err, errlen, "sigaction(SIGSYS): %s", strerror(errno));
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return fail(err, errlen, "PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) < 0)
        return fail(err, errlen, "seccomp: %s", strerror(errno));
    snprintf(g_desc, sizeof(g_desc), "seccomp-bpf (%zu system calls allowed)", (size_t)N + 1);
    return 1;
#endif
}

/* ------------------------------------------------------------------ */
/* macOS: sandbox_init with an SBPL profile                            */
/* ------------------------------------------------------------------ */
#elif defined(__APPLE__)

#ifndef SANITIZER_BUILD
/* Declared here rather than through <sandbox.h>, which marks the API as
 * deprecated. It is still what Chrome and Apple's own daemons use. */
int  sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
void sandbox_free_error(char *errorbuf);

/* Everything stays allowed except network access, exec and fork: the
 * capture device is already open, and logs and rules are plain files. */
static const char PROFILE[] =
    "(version 1)"
    "(allow default)"
    "(deny network*)"
    "(deny process-exec*)"
    "(deny process-fork)";
#endif

int sandbox_enter(char *err, size_t errlen) {
#ifdef SANITIZER_BUILD
    fail(err, errlen, "not used in sanitizer builds");
    return 0;
#else
    char *ebuf = NULL;
    if (sandbox_init(PROFILE, 0, &ebuf) != 0) {
        fail(err, errlen, "sandbox_init: %s", ebuf ? ebuf : "failed");
        if (ebuf) sandbox_free_error(ebuf);
        return -1;
    }
    snprintf(g_desc, sizeof(g_desc), "macOS sandbox (no network, exec or fork)");
    return 1;
#endif
}

#else

int sandbox_enter(char *err, size_t errlen) {
    fail(err, errlen, "no sandbox on this platform");
    return 0;
}

#endif
