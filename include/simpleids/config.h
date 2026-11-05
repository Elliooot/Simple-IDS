#ifndef SIMPLEIDS_CONFIG_H
#define SIMPLEIDS_CONFIG_H

/* Compile-time defaults; the config file (-c, include/simpleids/settings.h)
 * and the command line override most of them at run time. */

/* Loopback interface name differs per OS (B12). */
#ifdef __APPLE__
#define DEFAULT_IFACE "lo0"
#else
#define DEFAULT_IFACE "lo"
#endif

/* Rule directories loaded when no -R is given: every *.rules file in
 * each, in name order. rules/ holds the core set, rules/crs/ the library
 * grouped by OWASP CRS category. */
#define DEFAULT_RULE_DIRS  { "rules", "rules/crs" }
#define DEFAULT_RULES_DESC "rules/*.rules rules/crs/*.rules"
#define BPF_FILTER         "tcp port 80 or tcp port 443 or tcp port 8080 or port 53"
#define SNAPLEN            65535

#endif
