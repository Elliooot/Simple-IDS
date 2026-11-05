#include <errno.h>
#include <getopt.h>
#include <glob.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "simpleids/config.h"
#include "simpleids/engine.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"
#include "simpleids/threshold.h"

#define MAX_RULE_FILES 64

static pcap_t *g_handle = NULL;
static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_reload = 0;
static char **g_rule_files;
static int g_nrule_files;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
    if (g_handle) pcap_breakloop(g_handle);
}

/* SIGHUP: reload the rules between two packets. */
static void on_hup(int sig) {
    (void)sig;
    g_reload = 1;
    if (g_handle) pcap_breakloop(g_handle);
}

static void reload_rules(void);

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    int linktype = *(const int *)user;
    if (g_reload) reload_rules();   /* a packet that was already being read */
    /* caplen, not len: only caplen bytes were actually captured. */
    engine_process_frame(linktype, &h->ts, bytes, h->caplen);
}

static void usage(const char *prog) {
    engine_config_t d;
    engine_config_defaults(&d);
    fprintf(stderr,
        "Usage: %s [-i IFACE | -r FILE.pcap] [-R RULES]... [-l LOG] [-f FILTER] [-q] [-v]\n"
        "          [--max-flows N] [--stream-depth SIZE] [--stream-memcap SIZE]\n"
        "          [--overlap first|last] [--var NAME=VALUE]...\n"
        "       %s --test-rules [-R RULES]... [--var NAME=VALUE]...\n"
        "\n"
        "  -i IFACE   capture live on IFACE (default: %s; needs root)\n"
        "  -r FILE    read packets from a pcap file instead (no root needed)\n"
        "  -R RULES   load a rules file, or every *.rules file in a directory;\n"
        "             repeatable (default: %s)\n"
        "  -l LOG     JSON Lines alert log (default: %s)\n"
        "             '-' writes JSON to stdout, 'none' disables the log\n"
        "  -f FILTER  BPF capture filter (default: '%s', also inside VLAN tags\n"
        "             on Ethernet); -f '' captures everything\n"
        "  -q         do not print alerts on the console\n"
        "  -v         also print clean HTTP requests / TLS hellos\n"
        "  -h         show this help\n"
        "\n"
        "  --max-flows N        flow table size; the least recently used flow is\n"
        "                       evicted when full (default %u)\n"
        "  --stream-depth SIZE  bytes reassembled per TCP stream (default %uK)\n"
        "  --stream-memcap SIZE total reassembly memory (default %zuM)\n"
        "  --overlap POLICY     which bytes win when queued TCP segments overlap:\n"
        "                       first (default) or last\n"
        "  SIZE accepts K, M and G suffixes.\n"
        "  --var NAME=VALUE     define a rule variable, e.g. --var HOME_NET=[10.0.0.0/8]\n"
        "  --test-rules         check the rules (syntax, duplicate sids, performance\n"
        "                       warnings) and exit: 0 when they load without errors\n"
        "\n"
        "SIGHUP reloads the rule files; if any rule fails to load, the rules in\n"
        "use are kept. A single positional argument is treated as the interface.\n",
        prog, prog, DEFAULT_IFACE, DEFAULT_RULES_DESC, OUTPUT_DEFAULT_LOG, BPF_FILTER,
        d.flow.max_flows, d.stream.depth / 1024, d.stream.memcap / (1024 * 1024));
}

/* "64K", "1M", "1048576" -> bytes. Returns 0, or -1 if malformed. */
static int parse_size(const char *s, unsigned long long max, unsigned long long *out) {
    char *end;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s) return -1;
    switch (*end) {
    case 'k': case 'K': v *= 1024ULL; end++; break;
    case 'm': case 'M': v *= 1024ULL * 1024; end++; break;
    case 'g': case 'G': v *= 1024ULL * 1024 * 1024; end++; break;
    default: break;
    }
    if (*end != '\0' || v == 0 || v > max) return -1;
    *out = v;
    return 0;
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
 * Load and compile the given files and directories, or the default rule
 * directories. *errors receives the number of skipped lines. Returns NULL
 * when a file cannot be opened, nothing loads, or memory runs out.
 */
static ruleset_t *build_ruleset(char **paths, int npaths, int *errors, int report) {
    static const char *const defaults[] = DEFAULT_RULE_DIRS;
    char **files = NULL;
    int nfiles = 0, ok = 1;
    *errors = 0;

    if (npaths == 0) {
        for (size_t i = 0; ok && i < sizeof(defaults) / sizeof(defaults[0]); i++)
            ok = expand_rule_path(defaults[i], &files, &nfiles) == 0;
        if (!ok)
            fprintf(stderr, "Cannot load the default rules %s (run from the repo root, "
                            "or use -R)\n", DEFAULT_RULES_DESC);
    } else {
        for (int i = 0; ok && i < npaths; i++)
            ok = expand_rule_path(paths[i], &files, &nfiles) == 0;
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
 * new files is in use, or (on any error) the old set stays. */
static void reload_rules(void) {
    g_reload = 0;
    int errors;
    ruleset_t *cur = rules_active();
    ruleset_t *rs = build_ruleset(g_rule_files, g_nrule_files, &errors, 0);
    if (!rs || errors) {
        fprintf(stderr, "Rule reload failed (%d error%s, see above): keeping the %d rules in use\n",
                errors, errors == 1 ? "" : "s", ruleset_count(cur));
        ruleset_free(rs);
        return;
    }
    ruleset_free(rules_set_active(rs));
    fprintf(stderr, "Reloaded %d rules\n", ruleset_count(rs));
}

static void print_warning(const rule_t *r, const char *msg, void *ctx) {
    (void)ctx;
    fprintf(stdout, "%s:%d: sid %d: warning: %s\n", r->file ? r->file : "?", r->line, r->sid, msg);
}

/* --test-rules: load, report, exit status 0 only without errors. */
static int test_rules(char **files, int nfiles) {
    int errors;
    ruleset_t *rs = build_ruleset(files, nfiles, &errors, 1);
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

enum { OPT_MAX_FLOWS = 256, OPT_DEPTH, OPT_MEMCAP, OPT_OVERLAP, OPT_VAR, OPT_TEST_RULES };

static const struct option LONG_OPTS[] = {
    { "max-flows",     required_argument, NULL, OPT_MAX_FLOWS },
    { "stream-depth",  required_argument, NULL, OPT_DEPTH },
    { "stream-memcap", required_argument, NULL, OPT_MEMCAP },
    { "overlap",       required_argument, NULL, OPT_OVERLAP },
    { "var",           required_argument, NULL, OPT_VAR },
    { "test-rules",    no_argument,       NULL, OPT_TEST_RULES },
    { "help",          no_argument,       NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

/* The default filter, also matched inside one or two VLAN tags. The
 * untagged part must come first: each "vlan" shifts later offsets. */
static void build_filter(char *buf, size_t len, const char *base, int linktype) {
    if (linktype == DLT_EN10MB)
        snprintf(buf, len, "(%s) or (vlan and (%s)) or (vlan and (%s))", base, base, base);
    else
        snprintf(buf, len, "%s", base);
}

int main(int argc, char *argv[]) {
    const char *iface = NULL, *file = NULL, *filter = NULL;
    const char *log_path = OUTPUT_DEFAULT_LOG;
    char *rule_files[MAX_RULE_FILES];
    int nrule_files = 0, quiet = 0, verbose = 0, check_rules = 0, opt;
    unsigned long long v;
    engine_config_t cfg;
    engine_config_defaults(&cfg);

    while ((opt = getopt_long(argc, argv, "i:r:R:l:f:qvh", LONG_OPTS, NULL)) != -1) {
        switch (opt) {
        case 'f': filter = optarg; break;
        case OPT_MAX_FLOWS:
            if (parse_size(optarg, 50000000ULL, &v) < 0) {
                fprintf(stderr, "Bad --max-flows '%s'\n", optarg);
                return 1;
            }
            cfg.flow.max_flows = (uint32_t)v;
            break;
        case OPT_DEPTH:
            if (parse_size(optarg, 1ULL << 30, &v) < 0) {
                fprintf(stderr, "Bad --stream-depth '%s' (max 1G)\n", optarg);
                return 1;
            }
            cfg.stream.depth = (uint32_t)v;
            break;
        case OPT_MEMCAP:
            if (parse_size(optarg, (unsigned long long)SIZE_MAX, &v) < 0) {
                fprintf(stderr, "Bad --stream-memcap '%s'\n", optarg);
                return 1;
            }
            cfg.stream.memcap = (size_t)v;
            break;
        case OPT_OVERLAP:
            if (strcmp(optarg, "first") == 0) cfg.stream.policy = OVERLAP_FIRST;
            else if (strcmp(optarg, "last") == 0) cfg.stream.policy = OVERLAP_LAST;
            else {
                fprintf(stderr, "Bad --overlap '%s' (first or last)\n", optarg);
                return 1;
            }
            break;
        case OPT_VAR: {
            char name[64];
            const char *eq = strchr(optarg, '=');
            size_t nl = eq ? (size_t)(eq - optarg) : 0;
            if (!eq || nl == 0 || nl >= sizeof(name)) {
                fprintf(stderr, "Bad --var '%s' (NAME=VALUE)\n", optarg);
                return 1;
            }
            memcpy(name, optarg, nl);
            name[nl] = '\0';
            if (rules_define_var(name, eq + 1) < 0) {
                fprintf(stderr, "Bad --var '%s'\n", optarg);
                return 1;
            }
            break;
        }
        case OPT_TEST_RULES: check_rules = 1; break;
        case 'i': iface = optarg; break;
        case 'r': file = optarg; break;
        case 'R':
            if (nrule_files == MAX_RULE_FILES) {
                fprintf(stderr, "Too many -R options (max %d)\n", MAX_RULE_FILES);
                return 1;
            }
            rule_files[nrule_files++] = optarg;
            break;
        case 'l': log_path = strcmp(optarg, "none") == 0 ? NULL : optarg; break;
        case 'q': quiet = 1; break;
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    if (optind < argc) {
        if (iface || optind + 1 < argc) { usage(argv[0]); return 1; }
        iface = argv[optind];
    }
    if (check_rules) return test_rules(rule_files, nrule_files);
    g_rule_files = rule_files;
    g_nrule_files = nrule_files;
    if (iface && file) {
        fprintf(stderr, "Use either -i or -r, not both\n");
        return 1;
    }
    if (!iface && !file) iface = DEFAULT_IFACE;

    if (output_open(log_path) < 0) return 1;
    output_set_quiet(quiet);
    engine_set_verbose(verbose);
    FILE *con = output_console();

    int rule_errors;
    ruleset_t *rs = build_ruleset(rule_files, nrule_files, &rule_errors, 1);
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

    char fexpr[512];
    if (filter) snprintf(fexpr, sizeof(fexpr), "%s", filter);
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

    if (engine_init(&cfg) < 0) {
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
            (double)flow_table_memory() / 1048576.0, cfg.flow.max_flows,
            (double)cfg.stream.memcap / 1048576.0, cfg.stream.depth,
            cfg.stream.policy == OVERLAP_LAST ? "last" : "first");
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

    int rc;
    for (;;) {
        rc = pcap_loop(g_handle, -1, packet_handler, (u_char *)&linktype);
        if (rc == PCAP_ERROR_BREAK && !g_stop) {
            if (g_reload) reload_rules();
            continue;
        }
        break;
    }
    int status = 0;
    if (rc == PCAP_ERROR) {
        fprintf(stderr, "Capture error: %s\n", pcap_geterr(g_handle));
        status = 2;
    }

    engine_shutdown(); /* inspects whatever the open flows still buffer */
    engine_print_stats(con);

    pcap_close(g_handle);
    g_handle = NULL;
    ruleset_free(rules_set_active(NULL));
    threshold_free();
    output_close();
    return status;
}
