#include <errno.h>
#include <getopt.h>
#include <glob.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "simpleids/config.h"
#include "simpleids/engine.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"
#include "simpleids/sandbox.h"
#include "simpleids/settings.h"
#include "simpleids/threshold.h"

static pcap_t *g_handle = NULL;
static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_reload = 0;
static volatile sig_atomic_t g_stats_now = 0;
static settings_t g_set;

/* Stats clock: packet time when reading a file (reproducible), wall
 * clock when capturing live. */
static int g_live;
static int g_clock_started;
static struct timeval g_start, g_last_stats, g_now;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
    if (g_handle) pcap_breakloop(g_handle);
}

/* SIGHUP: reload the rules (and reopen the log) between two packets. */
static void on_hup(int sig) {
    (void)sig;
    g_reload = 1;
    if (g_handle) pcap_breakloop(g_handle);
}

/* SIGUSR1: write a stats event now. */
static void on_usr1(int sig) {
    (void)sig;
    g_stats_now = 1;
    if (g_handle) pcap_breakloop(g_handle);
}

static void reload_rules(void);
static void maybe_stats(const struct timeval *ts);

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    int linktype = *(const int *)user;
    if (g_reload) reload_rules();   /* a packet that was already being read */
    /* caplen, not len: only caplen bytes were actually captured. */
    engine_process_frame(linktype, &h->ts, bytes, h->caplen);
    if (!g_live) maybe_stats(&h->ts);
}

static void usage(const char *prog) {
    settings_t d;
    settings_defaults(&d);
    fprintf(stderr,
        "Usage: %s [-c CONFIG] [-i IFACE | -r FILE.pcap] [-R RULES]... [-l LOG] [-f FILTER]\n"
        "          [-q] [-v] [-u USER] [-g GROUP] [--no-sandbox] [--OPTION VALUE]...\n"
        "       %s [-c CONFIG] --test-rules [-R RULES]... [--var NAME=VALUE]...\n"
        "\n"
        "  -c FILE    read settings from an INI config file (etc/simpleids.conf);\n"
        "             command-line options override it\n"
        "  -i IFACE   capture live on IFACE (default: %s; needs root)\n"
        "  -r FILE    read packets from a pcap file instead (no root needed)\n"
        "  -R RULES   load a rules file, or every *.rules file in a directory;\n"
        "             repeatable, replaces the config file's (default: %s)\n"
        "  -l LOG     JSON Lines log (default: %s)\n"
        "             '-' writes JSON to stdout, 'none' disables the log\n"
        "  -f FILTER  BPF capture filter (default: '%s', also inside VLAN tags\n"
        "             on Ethernet); -f '' captures everything\n"
        "  -q         do not print alerts on the console\n"
        "  -v         also print clean HTTP requests / TLS hellos\n"
        "  -u USER    after opening the capture and the log, switch to USER\n"
        "  -g GROUP   ... and GROUP (default: USER's primary group)\n"
        "  -h         show this help\n"
        "\n"
        "  --no-sandbox         do not enter the seccomp (Linux) / sandbox (macOS) jail\n"
        "  --max-flows N        flow table size; the least recently used flow is\n"
        "                       evicted when full (default %u)\n"
        "  --stream-depth SIZE  bytes reassembled per TCP stream (default %uK)\n"
        "  --stream-memcap SIZE total reassembly memory (default %zuM)\n"
        "  --overlap POLICY     which bytes win when queued TCP segments overlap:\n"
        "                       first (default) or last\n"
        "  --log-max-size SIZE  rotate the log at this size (default: never)\n"
        "  --log-max-files N    rotated logs kept: LOG.1 .. LOG.N (default %u)\n"
        "  --stats-interval S   write a stats event to the log every S seconds\n"
        "                       (packet time with -r) and at exit\n"
        "  --measure-latency    time every packet; the stats event and the summary\n"
        "                       report percentiles\n"
        "  SIZE accepts K, M and G suffixes.\n"
        "  --var NAME=VALUE     define a rule variable, e.g. --var HOME_NET=[10.0.0.0/8]\n"
        "  --test-rules         check the rules (syntax, duplicate sids, performance\n"
        "                       warnings) and exit: 0 when they load without errors\n"
        "\n"
        "SIGHUP reloads the rule files (if any rule fails to load, the rules in\n"
        "use are kept) and reopens the log. SIGUSR1 writes a stats event.\n"
        "A single positional argument is treated as the interface.\n",
        prog, prog, DEFAULT_IFACE, DEFAULT_RULES_DESC, OUTPUT_DEFAULT_LOG, BPF_FILTER,
        d.engine.flow.max_flows, d.engine.stream.depth / 1024,
        d.engine.stream.memcap / (1024 * 1024), d.log_max_files);
}

/* Add path to the list: a directory adds every *.rules file in it (in
 * name order), anything else is taken as a file. Returns -1 on errors. */
static int expand_rule_path(const char *path, char ***list, int *n) {
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        char pattern[4096];
        glob_t g;
        snprintf(pattern, sizeof(pattern), "%s/*.rules", path);
        if (glob(pattern, 0, NULL, &g) != 0) {
            fprintf(stderr, "No rule files match %s\n", pattern);
            return -1;
        }
        for (size_t i = 0; i < g.gl_pathc; i++) {
            char **l = realloc(*list, (size_t)(*n + 1) * sizeof(**list));
            char *dup = strdup(g.gl_pathv[i]);
            if (!l || !dup) { free(dup); if (l) *list = l; globfree(&g); return -1; }
            *list = l;
            (*list)[(*n)++] = dup;
        }
        globfree(&g);
        return 0;
    }
    char **l = realloc(*list, (size_t)(*n + 1) * sizeof(**list));
    char *dup = strdup(path);
    if (!l || !dup) { free(dup); if (l) *list = l; return -1; }
    *list = l;
    (*list)[(*n)++] = dup;
    return 0;
}

/*
 * Load and compile the configured files and directories, or the default
 * rule directories. *errors receives the number of skipped lines. Returns
 * NULL when a file cannot be opened, nothing loads, or memory runs out.
 */
static ruleset_t *build_ruleset(int *errors, int report) {
    static const char *const defaults[] = DEFAULT_RULE_DIRS;
    char **files = NULL;
    int nfiles = 0, ok = 1;
    *errors = 0;

    if (g_set.nrule_paths == 0) {
        for (size_t i = 0; ok && i < sizeof(defaults) / sizeof(defaults[0]); i++)
            ok = expand_rule_path(defaults[i], &files, &nfiles) == 0;
        if (!ok)
            fprintf(stderr, "Cannot load the default rules %s (run from the repo root, "
                            "or use -R)\n", DEFAULT_RULES_DESC);
    } else {
        for (int i = 0; ok && i < g_set.nrule_paths; i++)
            ok = expand_rule_path(g_set.rule_paths[i], &files, &nfiles) == 0;
    }

    ruleset_t *rs = ok ? ruleset_new() : NULL;
    for (int i = 0; rs && i < nfiles; i++) {
        int e = 0;
        int n = ruleset_load_file(rs, files[i], &e);
        if (n < 0) {
            ruleset_free(rs);
            rs = NULL;
            break;
        }
        if (report)
            fprintf(stderr, "Loaded %d rule(s) from %s%s\n", n, files[i],
                    e ? " (some lines skipped, see above)" : "");
        *errors += e;
    }
    for (int i = 0; i < nfiles; i++) free(files[i]);
    free(files);
    if (!rs) return NULL;

    if (ruleset_count(rs) == 0) {
        fprintf(stderr, "No rules loaded\n");
        ruleset_free(rs);
        return NULL;
    }
    if (ruleset_compile(rs) < 0) {
        fprintf(stderr, "Out of memory compiling the rules\n");
        ruleset_free(rs);
        return NULL;
    }
    return rs;
}

/* Build a complete new set first, then swap: either every rule of the
 * new files is in use, or (on any error) the old set stays. The log is
 * reopened too, for an external logrotate. */
static void reload_rules(void) {
    g_reload = 0;
    output_reopen();
    int errors;
    ruleset_t *cur = rules_active();
    ruleset_t *rs = build_ruleset(&errors, 0);
    if (!rs || errors) {
        fprintf(stderr, "Rule reload failed (%d error%s, see above): keeping the %d rules in use\n",
                errors, errors == 1 ? "" : "s", ruleset_count(cur));
        ruleset_free(rs);
        return;
    }
    ruleset_free(rules_set_active(rs));
    fprintf(stderr, "Reloaded %d rules\n", ruleset_count(rs));
}

static double tv_diff(const struct timeval *a, const struct timeval *b) {
    return (double)(a->tv_sec - b->tv_sec) + (double)(a->tv_usec - b->tv_usec) / 1e6;
}

static void write_stats(const struct timeval *ts) {
    capture_counts_t cc = { 0, 0, 0, 0 };
    struct pcap_stat ps;
    if (g_live && g_handle && pcap_stats(g_handle, &ps) == 0) {
        cc.valid = 1;
        cc.received = ps.ps_recv;
        cc.dropped = ps.ps_drop;
        cc.ifdropped = ps.ps_ifdrop;
    }
    static char buf[4096];
    engine_stats_json(buf, sizeof(buf), ts, tv_diff(ts, &g_start), tv_diff(ts, &g_last_stats), &cc);
    g_last_stats = *ts;
    if (output_has_log()) output_event(buf);
    else fprintf(stderr, "%s\n", buf);
}

/* Called after every packet (file) or loop wake-up (live). */
static void maybe_stats(const struct timeval *ts) {
    g_now = *ts;
    if (!g_clock_started) {
        g_start = g_last_stats = *ts;
        g_clock_started = 1;
    }
    if (g_stats_now) {
        g_stats_now = 0;
        write_stats(ts);
    } else if (g_set.stats_interval && tv_diff(ts, &g_last_stats) >= (double)g_set.stats_interval) {
        write_stats(ts);
    }
}

static void print_warning(const rule_t *r, const char *msg, void *ctx) {
    (void)ctx;
    fprintf(stdout, "%s:%d: sid %d: warning: %s\n", r->file ? r->file : "?", r->line, r->sid, msg);
}

/* --test-rules: load, report, exit status 0 only without errors. */
static int test_rules(void) {
    int errors;
    ruleset_t *rs = build_ruleset(&errors, 1);
    if (!rs) return 1;
    int warnings = ruleset_lint(rs, print_warning, NULL);

    printf("\n%-14s %6s %8s %7s %9s %8s %9s\n", "phase", "rules", "prefilt", "always",
           "patterns", "states", "memory");
    for (int p = 0; p < RULE_PHASE_COUNT; p++) {
        rule_phase_info_t pi;
        ruleset_phase_info(rs, (rule_phase_t)p, &pi);
        if (!pi.rules) continue;
        printf("%-14s %6u %8u %7u %9u %8u %8.1fK\n", rule_phase_name((rule_phase_t)p),
               pi.rules, pi.prefiltered, pi.always, pi.patterns, pi.states,
               (double)pi.memory / 1024.0);
    }
    printf("\n%d rules, %d error%s, %d warning%s\n", ruleset_count(rs), errors,
           errors == 1 ? "" : "s", warnings, warnings == 1 ? "" : "s");
    ruleset_free(rs);
    return errors ? 1 : 0;
}

static pcap_t *open_capture(const char *iface, const char *file, char *errbuf) {
    if (file) return pcap_open_offline(file, errbuf);

    pcap_t *h = pcap_create(iface, errbuf);
    if (!h) return NULL;
    pcap_set_snaplen(h, SNAPLEN);
    pcap_set_promisc(h, 1);
    pcap_set_timeout(h, 1000);
    int rc = pcap_activate(h);
    if (rc < 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", pcap_geterr(h));
        pcap_close(h);
        return NULL;
    }
    return h;
}

enum { OPT_MAX_FLOWS = 256, OPT_DEPTH, OPT_MEMCAP, OPT_OVERLAP, OPT_VAR, OPT_TEST_RULES,
       OPT_NO_SANDBOX, OPT_LOG_MAX_SIZE, OPT_LOG_MAX_FILES, OPT_STATS_INTERVAL,
       OPT_LATENCY };

static const struct option LONG_OPTS[] = {
    { "config",          required_argument, NULL, 'c' },
    { "max-flows",       required_argument, NULL, OPT_MAX_FLOWS },
    { "stream-depth",    required_argument, NULL, OPT_DEPTH },
    { "stream-memcap",   required_argument, NULL, OPT_MEMCAP },
    { "overlap",         required_argument, NULL, OPT_OVERLAP },
    { "var",             required_argument, NULL, OPT_VAR },
    { "test-rules",      no_argument,       NULL, OPT_TEST_RULES },
    { "user",            required_argument, NULL, 'u' },
    { "group",           required_argument, NULL, 'g' },
    { "no-sandbox",      no_argument,       NULL, OPT_NO_SANDBOX },
    { "log-max-size",    required_argument, NULL, OPT_LOG_MAX_SIZE },
    { "log-max-files",   required_argument, NULL, OPT_LOG_MAX_FILES },
    { "stats-interval",  required_argument, NULL, OPT_STATS_INTERVAL },
    { "measure-latency", no_argument,       NULL, OPT_LATENCY },
    { "help",            no_argument,       NULL, 'h' },
    { NULL, 0, NULL, 0 }
};
#define SHORT_OPTS "c:i:r:R:l:f:u:g:qvh"

/* The default filter, also matched inside one or two VLAN tags. The
 * untagged part must come first: each "vlan" shifts later offsets. */
static void build_filter(char *buf, size_t len, const char *base, int linktype) {
    if (linktype == DLT_EN10MB)
        snprintf(buf, len, "(%s) or (vlan and (%s)) or (vlan and (%s))", base, base, base);
    else
        snprintf(buf, len, "%s", base);
}

static void config_error(const char *name, int line, const char *msg, void *ctx) {
    (void)ctx;
    if (line) fprintf(stderr, "%s:%d: %s\n", name, line, msg);
    else fprintf(stderr, "%s: %s\n", name, msg);
}

/* The config file named by -c / --config, found before the other options
 * are applied (they override it). Skips the values of other options. */
static const char *find_config(int argc, char **argv) {
    const char *cfg = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--") == 0) break;
        if (strcmp(a, "-c") == 0 || strcmp(a, "--config") == 0) {
            if (i + 1 < argc) cfg = argv[++i];
        } else if (strncmp(a, "--config=", 9) == 0) {
            cfg = a + 9;
        } else if (strncmp(a, "-c", 2) == 0) {
            cfg = a + 2;
        } else if (a[0] == '-' && a[1] != '-' && a[1] && !a[2] &&
                   strchr(SHORT_OPTS, a[1]) && strchr(SHORT_OPTS, a[1])[1] == ':') {
            i++;                                      /* "-R value" */
        } else if (a[0] == '-' && a[1] == '-' && !strchr(a, '=')) {
            for (const struct option *o = LONG_OPTS; o->name; o++)
                if (o->has_arg == required_argument && strcmp(a + 2, o->name) == 0) { i++; break; }
        }
    }
    return cfg;
}

/* Apply one command-line option to the settings, exit status on error. */
static int set_opt(const char *key, const char *value) {
    char err[512];
    if (settings_set(&g_set, key, value, err, sizeof(err)) < 0) {
        fprintf(stderr, "%s\n", err);
        return -1;
    }
    return 0;
}

static int set_var_opt(const char *arg) {
    char key[96];
    const char *eq = strchr(arg, '=');
    if (!eq || eq == arg || (size_t)(eq - arg) + 6 > sizeof(key)) {
        fprintf(stderr, "Bad --var '%s' (NAME=VALUE)\n", arg);
        return -1;
    }
    snprintf(key, sizeof(key), "vars.%.*s", (int)(eq - arg), arg);
    return set_opt(key, eq + 1);
}

/* Leave root, then enter the sandbox. Returns 0 or an exit status. */
static int lock_down(void) {
    char err[256];
    if (g_set.user[0]) {
        uid_t uid;
        gid_t gid;
        if (priv_resolve(g_set.user, g_set.group, &uid, &gid, err, sizeof(err)) < 0) {
            fprintf(stderr, "Cannot drop privileges: %s\n", err);
            return 1;
        }
        if (geteuid() == 0 && output_log_chown(uid, gid) < 0)
            fprintf(stderr, "Warning: cannot hand the log file to uid %u: %s\n",
                    (unsigned)uid, strerror(errno));
        if (priv_drop(uid, gid, err, sizeof(err)) < 0) {
            fprintf(stderr, "Cannot drop privileges: %s\n", err);
            return 1;
        }
        fprintf(stderr, "Running as %s (uid %u, gid %u)\n", g_set.user, (unsigned)uid,
                (unsigned)gid);
    } else if (geteuid() == 0 && g_live) {
        fprintf(stderr, "Warning: running as root; use -u USER to drop privileges "
                        "after the capture is open\n");
    }
    if (g_set.sandbox) {
        int rc = sandbox_enter(err, sizeof(err));
        if (rc < 0) {
            fprintf(stderr, "Cannot enter the sandbox: %s (use --no-sandbox to run without)\n",
                    err);
            return 1;
        }
        if (rc > 0) fprintf(stderr, "Sandbox: %s\n", sandbox_describe());
        else fprintf(stderr, "Sandbox: none (%s)\n", err);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int check_rules = 0, cli_rules = 0, opt;
    settings_defaults(&g_set);

    const char *cfg_path = find_config(argc, argv);
    if (cfg_path) {
        int e = settings_load_file(&g_set, cfg_path, config_error, NULL);
        if (e != 0) {
            if (e > 0) fprintf(stderr, "%s: %d error%s\n", cfg_path, e, e == 1 ? "" : "s");
            return 1;
        }
    }

    while ((opt = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1) {
        int rc = 0;
        switch (opt) {
        case 'c': break;                                   /* already read */
        case 'f': rc = set_opt("capture.filter", optarg); break;
        case 'i': rc = set_opt("capture.interface", optarg); break;
        case 'r': rc = set_opt("capture.file", optarg); break;
        case 'R':
            if (!cli_rules++) g_set.nrule_paths = 0;       /* -R replaces the config's */
            rc = set_opt("rules.path", optarg);
            break;
        case 'l': rc = set_opt("output.log", optarg); break;
        case 'q': rc = set_opt("output.quiet", "yes"); break;
        case 'v': rc = set_opt("output.verbose", "yes"); break;
        case 'u': rc = set_opt("security.user", optarg); break;
        case 'g': rc = set_opt("security.group", optarg); break;
        case OPT_NO_SANDBOX: rc = set_opt("security.sandbox", "no"); break;
        case OPT_MAX_FLOWS: rc = set_opt("engine.max-flows", optarg); break;
        case OPT_DEPTH: rc = set_opt("engine.stream-depth", optarg); break;
        case OPT_MEMCAP: rc = set_opt("engine.stream-memcap", optarg); break;
        case OPT_OVERLAP: rc = set_opt("engine.overlap", optarg); break;
        case OPT_LATENCY: rc = set_opt("engine.measure-latency", "yes"); break;
        case OPT_LOG_MAX_SIZE: rc = set_opt("output.log-max-size", optarg); break;
        case OPT_LOG_MAX_FILES: rc = set_opt("output.log-max-files", optarg); break;
        case OPT_STATS_INTERVAL: rc = set_opt("output.stats-interval", optarg); break;
        case OPT_VAR: rc = set_var_opt(optarg); break;
        case OPT_TEST_RULES: check_rules = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
        if (rc < 0) return 1;
    }
    if (optind < argc) {
        if (optind + 1 < argc) { usage(argv[0]); return 1; }
        if (set_opt("capture.interface", argv[optind]) < 0) return 1;
    }
    for (int i = 0; i < g_set.nvars; i++) {
        if (rules_define_var(g_set.vars[i].name, g_set.vars[i].value) < 0) {
            fprintf(stderr, "Bad variable %s\n", g_set.vars[i].name);
            return 1;
        }
    }
    if (check_rules) return test_rules();

    const char *file = g_set.file[0] ? g_set.file : NULL;
    const char *iface = g_set.interface[0] ? g_set.interface : NULL;
    if (iface && file) {
        fprintf(stderr, "Use either -i or -r, not both\n");
        return 1;
    }
    if (!iface && !file) iface = DEFAULT_IFACE;
    g_live = file == NULL;
    const char *log_path = g_set.log[0] ? g_set.log : NULL;

    if (output_open(log_path) < 0) return 1;
    output_set_rotation(g_set.log_max_size, g_set.log_max_files);
    output_set_quiet(g_set.quiet);
    engine_set_verbose(g_set.verbose);
    engine_set_latency(g_set.latency);
    FILE *con = output_console();

    int rule_errors;
    ruleset_t *rs = build_ruleset(&rule_errors, 1);
    if (!rs) {
        output_close();
        return 1;
    }
    rules_set_active(rs);

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    g_handle = open_capture(iface, file, errbuf);
    if (!g_handle) {
        fprintf(stderr, "Cannot open %s %s: %s\n", file ? "file" : "device",
                file ? file : iface, errbuf);
        ruleset_free(rules_set_active(NULL));
        output_close();
        return 2;
    }

    int linktype = pcap_datalink(g_handle);
    const char *ltname = pcap_datalink_val_to_name(linktype);

    char fexpr[SETTINGS_PATH_MAX + 64];
    if (g_set.filter_set) snprintf(fexpr, sizeof(fexpr), "%s", g_set.filter);
    else build_filter(fexpr, sizeof(fexpr), BPF_FILTER, linktype);

    if (fexpr[0]) {
        struct bpf_program fp;
        if (pcap_compile(g_handle, &fp, fexpr, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
            pcap_setfilter(g_handle, &fp) < 0) {
            fprintf(stderr, "Cannot install filter '%s': %s\n", fexpr, pcap_geterr(g_handle));
            pcap_close(g_handle);
            ruleset_free(rules_set_active(NULL));
            output_close();
            return 2;
        }
        pcap_freecode(&fp);
    }

    if (engine_init(&g_set.engine) < 0) {
        pcap_close(g_handle);
        ruleset_free(rules_set_active(NULL));
        output_close();
        return 1;
    }

    fprintf(con, "%s %s (link type %s), %d rules, log: %s\n",
            file ? "Reading" : "Listening on", file ? file : iface,
            ltname ? ltname : "?", ruleset_count(rules_active()),
            log_path ? log_path : "(none)");
    fprintf(con, "Memory budget: flow table %.1f MiB (%u flows) + reassembly %.1f MiB "
                 "(depth %u bytes/stream, overlap policy: %s)\n",
            (double)flow_table_memory() / 1048576.0, g_set.engine.flow.max_flows,
            (double)g_set.engine.stream.memcap / 1048576.0, g_set.engine.stream.depth,
            g_set.engine.stream.policy == OVERLAP_LAST ? "last" : "first");
    fflush(con);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    /* SA_RESTART: a blocking read (e.g. -r from a FIFO) resumes after a
     * reload instead of failing with EINTR. */
    sa.sa_handler = on_hup;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);

    /* Everything that needs privileges is open: capture, rules, log. */
    int status = lock_down();
    if (status) {
        engine_shutdown();
        pcap_close(g_handle);
        ruleset_free(rules_set_active(NULL));
        output_close();
        return status;
    }

    int rc;
    if (g_live) {
        gettimeofday(&g_now, NULL);
        maybe_stats(&g_now);
    }
    for (;;) {
        if (g_live) {
            /* Returns at least every read timeout (1 s), so stats events
             * keep coming on a quiet link. */
            rc = pcap_dispatch(g_handle, -1, packet_handler, (u_char *)&linktype);
            gettimeofday(&g_now, NULL);
            maybe_stats(&g_now);
            if (rc >= 0 && !g_stop) {
                if (g_reload) reload_rules();
                continue;
            }
        } else {
            rc = pcap_loop(g_handle, -1, packet_handler, (u_char *)&linktype);
        }
        if (rc == PCAP_ERROR_BREAK && !g_stop) {
            if (g_reload) reload_rules();
            if (g_stats_now && g_clock_started) maybe_stats(&g_now);
            continue;
        }
        break;
    }
    if (rc == PCAP_ERROR) {
        fprintf(stderr, "Capture error: %s\n", pcap_geterr(g_handle));
        status = 2;
    }

    engine_shutdown(); /* inspects whatever the open flows still buffer */
    if (g_set.stats_interval && g_clock_started) write_stats(&g_now);
    engine_print_stats(con);

    pcap_close(g_handle);
    g_handle = NULL;
    ruleset_free(rules_set_active(NULL));
    threshold_free();
    output_close();
    return status;
}
