#include <errno.h>
#include <glob.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "simpleids/config.h"
#include "simpleids/engine.h"
#include "simpleids/output.h"
#include "simpleids/rules.h"

#define MAX_RULE_FILES 64

static pcap_t *g_handle = NULL;

static void on_signal(int sig) {
    (void)sig;
    if (g_handle) pcap_breakloop(g_handle);
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    int linktype = *(const int *)user;
    /* caplen, not len: only caplen bytes were actually captured. */
    engine_process_frame(linktype, &h->ts, bytes, h->caplen);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-i IFACE | -r FILE.pcap] [-R RULES]... [-l LOG] [-q] [-v]\n"
        "\n"
        "  -i IFACE   capture live on IFACE (default: %s; needs root)\n"
        "  -r FILE    read packets from a pcap file instead (no root needed)\n"
        "  -R RULES   load a rules file; repeatable (default: %s)\n"
        "  -l LOG     JSON Lines alert log (default: %s)\n"
        "             '-' writes JSON to stdout, 'none' disables the log\n"
        "  -q         do not print alerts on the console\n"
        "  -v         also print clean HTTP requests / TLS hellos\n"
        "  -h         show this help\n"
        "\n"
        "A single positional argument is treated as the interface (as before).\n",
        prog, DEFAULT_IFACE, DEFAULT_RULES_GLOB, OUTPUT_DEFAULT_LOG);
}

/* Load the given files, or every file matching DEFAULT_RULES_GLOB. */
static int load_rules(char **files, int nfiles) {
    int total_errors = 0;
    glob_t g;
    int used_glob = 0;

    if (nfiles == 0) {
        int rc = glob(DEFAULT_RULES_GLOB, 0, NULL, &g);
        if (rc != 0) {
            fprintf(stderr, "No rule files match %s (run from the repo root, or use -R)\n",
                    DEFAULT_RULES_GLOB);
            return -1;
        }
        files = g.gl_pathv;
        nfiles = (int)g.gl_pathc;
        used_glob = 1;
    }

    for (int i = 0; i < nfiles; i++) {
        int errors = 0;
        int n = rules_load_file(files[i], &errors);
        if (n < 0) {
            if (used_glob) globfree(&g);
            return -1;
        }
        fprintf(stderr, "Loaded %d rule(s) from %s%s\n", n, files[i],
                errors ? " (some lines skipped, see above)" : "");
        total_errors += errors;
    }

    if (used_glob) globfree(&g);
    if (rules_count() == 0) {
        fprintf(stderr, "No rules loaded\n");
        return -1;
    }
    return total_errors;
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

int main(int argc, char *argv[]) {
    const char *iface = NULL, *file = NULL;
    const char *log_path = OUTPUT_DEFAULT_LOG;
    char *rule_files[MAX_RULE_FILES];
    int nrule_files = 0, quiet = 0, verbose = 0, opt;

    while ((opt = getopt(argc, argv, "i:r:R:l:qvh")) != -1) {
        switch (opt) {
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
    if (iface && file) {
        fprintf(stderr, "Use either -i or -r, not both\n");
        return 1;
    }
    if (!iface && !file) iface = DEFAULT_IFACE;

    if (output_open(log_path) < 0) return 1;
    output_set_quiet(quiet);
    engine_set_verbose(verbose);
    FILE *con = output_console();

    if (load_rules(rule_files, nrule_files) < 0) {
        output_close();
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    g_handle = open_capture(iface, file, errbuf);
    if (!g_handle) {
        fprintf(stderr, "Cannot open %s %s: %s\n", file ? "file" : "device",
                file ? file : iface, errbuf);
        rules_free();
        output_close();
        return 2;
    }

    int linktype = pcap_datalink(g_handle);
    const char *ltname = pcap_datalink_val_to_name(linktype);

    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, BPF_FILTER, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_handle, &fp) < 0) {
        fprintf(stderr, "Cannot install filter '%s': %s\n", BPF_FILTER, pcap_geterr(g_handle));
        pcap_close(g_handle);
        rules_free();
        output_close();
        return 2;
    }
    pcap_freecode(&fp);

    fprintf(con, "%s %s (link type %s), %d rules, log: %s\n",
            file ? "Reading" : "Listening on", file ? file : iface,
            ltname ? ltname : "?", rules_count(),
            log_path ? log_path : "(none)");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int rc = pcap_loop(g_handle, -1, packet_handler, (u_char *)&linktype);
    int status = 0;
    if (rc == PCAP_ERROR) {
        fprintf(stderr, "Capture error: %s\n", pcap_geterr(g_handle));
        status = 2;
    }

    engine_print_stats(con);

    pcap_close(g_handle);
    g_handle = NULL;
    rules_free();
    output_close();
    return status;
}
