#ifndef SIMPLEIDS_CONFIG_H
#define SIMPLEIDS_CONFIG_H

/* Compile-time defaults. A config file arrives in Phase 5. */

/* Loopback interface name differs per OS (B12). */
#ifdef __APPLE__
#define DEFAULT_IFACE "lo0"
#else
#define DEFAULT_IFACE "lo"
#endif

#define DEFAULT_RULES_GLOB "rules/*.rules"
#define BPF_FILTER         "tcp port 80 or tcp port 443 or tcp port 8080 or port 53"
#define SNAPLEN            65535

#endif
