/*
 * Privilege dropping and the sandbox. Both are irreversible, so every
 * check runs in a forked child and reports through its exit status.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "simpleids/sandbox.h"
#include "test.h"

#define SKIP 77

/* Run fn in a child; return its exit status, or 1000 + signal. */
static int in_child(int (*fn)(void)) {
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Quiet the SIGSYS message: the parent checks the status. */
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) { dup2(fd, STDERR_FILENO); close(fd); }
        _exit(fn());
    }
    int st;
    if (waitpid(pid, &st, 0) < 0) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1000 + WTERMSIG(st);
}

static int enter(void) {
    char err[128];
    int rc = sandbox_enter(err, sizeof(err));
    return rc == 1 ? 0 : rc == 0 ? SKIP : 2;
}

/* Allowed: what the packet loop, a rule reload and log rotation do. */
static int child_allowed(void) {
    char dir[] = "/tmp/simpleids-sbx-XXXXXX";
    if (!mkdtemp(dir)) return 3;
    char a[64], b[64];
    snprintf(a, sizeof(a), "%s/log", dir);
    snprintf(b, sizeof(b), "%s/log.1", dir);
    int rc = enter();
    if (rc) return rc;
    FILE *f = fopen(a, "a");                 /* open, write */
    if (!f || fprintf(f, "{\"x\":1}\n") < 0 || fclose(f) != 0) return 4;
    if (rename(a, b) < 0) return 5;          /* rotation */
    f = fopen(b, "r");                       /* rule file read */
    char line[16];
    if (!f || !fgets(line, sizeof(line), f) || fclose(f) != 0) return 6;
    void *p = malloc(64 << 20);              /* big allocation: mmap */
    if (!p) return 7;
    memset(p, 1, 64 << 20);
    free(p);
    if (unlink(b) < 0) return 8;
    printf("%s", "");                        /* stdio isatty check */
    return 0;
}

static int child_socket(void) {
    int rc = enter();
    if (rc) return rc;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    return s >= 0 ? 0 : 42;       /* Linux: killed before returning */
}

static int child_exec(void) {
    int rc = enter();
    if (rc) return rc;
    char *argv[] = { "true", NULL };
    execv("/usr/bin/true", argv);
    execv("/bin/true", argv);
    return 42;                    /* exec refused (macOS: EPERM) */
}

static void test_sandbox_allows_normal_work(void) {
    int st = in_child(child_allowed);
    if (st == SKIP) { printf("     (skipped: no sandbox in this build)\n"); return; }
    CHECK_EQ_INT(st, 0);
}

static void test_sandbox_blocks_socket_and_exec(void) {
    int st = in_child(child_socket);
    if (st == SKIP) { printf("     (skipped: no sandbox in this build)\n"); return; }
#ifdef __linux__
    CHECK_EQ_INT(st, 128 + SIGSYS);      /* stopped by the SIGSYS handler */
    CHECK_EQ_INT(in_child(child_exec), 128 + SIGSYS);
#else
    (void)st;                            /* macOS allows socket(), not exec */
    CHECK_EQ_INT(in_child(child_exec), 42);
#endif
}

static void test_priv_resolve(void) {
    uid_t u;
    gid_t g;
    char err[128];
    CHECK_EQ_INT(priv_resolve("0", NULL, &u, &g, err, sizeof(err)), 0);
    CHECK_EQ_INT(u, 0);
    CHECK_EQ_INT(priv_resolve("root", "", &u, &g, err, sizeof(err)), 0);
    CHECK_EQ_INT(u, 0);
    CHECK_EQ_INT(priv_resolve("4242", "4343", &u, &g, err, sizeof(err)), 0);
    CHECK_EQ_INT(u, 4242);
    CHECK_EQ_INT(g, 4343);
    CHECK_EQ_INT(priv_resolve("no-such-user-zz", NULL, &u, &g, err, sizeof(err)), -1);
    CHECK(strstr(err, "no-such-user-zz") != NULL);
    CHECK_EQ_INT(priv_resolve("0", "no-such-group-zz", &u, &g, err, sizeof(err)), -1);
}

static int child_drop(void) {
    char err[128];
    if (priv_drop(4242, 4343, err, sizeof(err)) < 0) return 2;
    if (getuid() != 4242 || geteuid() != 4242 || getgid() != 4343) return 3;
    if (setuid(0) == 0) return 4;
    gid_t groups[4];
    int n = getgroups(4, groups);
    if (n != 1 || groups[0] != 4343) return 5;
    return 0;
}

static void test_priv_drop(void) {
    char err[128];
    if (geteuid() != 0) {
        /* Not root: switching user must fail, staying the same is a no-op. */
        CHECK_EQ_INT(priv_drop(0, 0, err, sizeof(err)), -1);
        CHECK_EQ_INT(priv_drop(geteuid(), getegid(), err, sizeof(err)), 0);
        return;
    }
    CHECK_EQ_INT(in_child(child_drop), 0);
}

const test_case_t sandbox_tests[] = {
    TEST(test_sandbox_allows_normal_work),
    TEST(test_sandbox_blocks_socket_and_exec),
    TEST(test_priv_resolve),
    TEST(test_priv_drop),
    TEST_END
};
