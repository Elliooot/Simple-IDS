#define _DEFAULT_SOURCE
#define __FAVOR_BSD

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "../include/rules.h"
#include "../include/logger.h"
#include "../include/anomaly.h"

// typedef unsigned char u_char;

// static pcap_t *global_handle = NULL;
// static pcap_if_t *global_alldevs = NULL;

// Simplified SNI extraction
const char* extract_sni(const char *payload, int len){
    static char sni[256];

    // TLS ClientHello Structure：
    // [0]    = 0x16 (Handshake)
    // [1][2] = TLS version
    // [3][4] = Record length
    // [5]    = 0x01 (ClientHello)
    // [6-8]  = Handshake length
    // [9][10]= ClientHello version
    // [11-42]= Random (32 bytes)
    // [43]   = Session ID length

    if (len < 44) return NULL;

    // Verify if it's TLS Handshake + ClientHello
    if ((unsigned char)payload[0] != 0x16) return NULL;
    if ((unsigned char)payload[5] != 0x01) return NULL;

    int pos = 43;

    // Skip Session ID
    if (pos >= len) return NULL;
    int session_id_len = (unsigned char)payload[pos];
    pos += 1 + session_id_len;

    // Skip Cipher Suites
    if (pos + 2 > len) return NULL;
    int cipher_suites_len = ((unsigned char)payload[pos] << 8) | (unsigned char)payload[pos+1];
    pos += 2 + cipher_suites_len;

    // Skip Compression Methods
    if (pos + 1 > len) return NULL;
    int compression_len = (unsigned char)payload[pos];
    pos += 1 + compression_len;

    // The Start of Extentions
    if (pos + 2 > len) return NULL;
    int extentions_len = ((unsigned char)payload[pos] << 8) | (unsigned char)payload[pos+1];
    pos += 2;
    
    int extentions_end = pos + extentions_len;

    // Looking for SNI extension (0x00 0x00 = server_name type)
    while (pos + 4 <= extentions_end && pos + 4 <= len){
        int ext_type = ((unsigned char)payload[pos] << 8) | (unsigned char)payload[pos+1];
        int ext_len = ((unsigned char)payload[pos+2] << 8) | (unsigned char)payload[pos+3];
        pos += 4;

        if (ext_type == 0x0000) { // SNI extention
            // SNI list length (2 bytes) + type (1) + name length (2) + name
            if (pos + 5 > len) return NULL;

            int name_type = (unsigned char)payload[pos+2];
            if (name_type != 0x00) return NULL; // host_name type

            int name_len = ((unsigned char)payload[pos+3] << 8) | (unsigned char)payload[pos+4];
            if (name_len <= 0 || name_len >= 256) return NULL;
            if (pos + 5 + name_len > len) return NULL;

            strncpy(sni, payload + pos + 5, name_len);
            sni[name_len] = '\0';
            return sni;
        }

        pos += ext_len;
    }
    
    return NULL;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
    // Skip Ethernet header (14 bytes)
    struct ip *ip_header = (struct ip *)(packet + 14);

    // Check the protocol field in the IP header to see if it is TCP
    if(ip_header->ip_p != IPPROTO_TCP) return;

    int ip_header_len = ip_header->ip_hl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len);

    // Get current port
    int dst_port = ntohs(tcp->th_dport);
    
    // Detect HTTP (port 80) only
    if(dst_port != 80 && dst_port != 443) return;

    // Get payload
    int tcp_len = tcp->th_off * 4;
    const char *payload = (char *)(packet + 14 + ip_header_len + tcp_len);
    int payload_len = header->len - (14 + ip_header_len + tcp_len);

    if(payload_len <= 0) return;

    // HTTP
    if(dst_port == 80){
        // Check if it's HTTP request
        if(strncmp(payload, "GET ", 4) != 0 &&
            strncmp(payload, "POST ", 5) != 0 &&
            strncmp(payload, "PUT ", 4) != 0 &&
            strncmp(payload, "DELETE ", 7) != 0 &&
            strncmp(payload, "HEAD ", 5) != 0 &&
            strncmp(payload, "OPTIONS ", 8) != 0){
                return;
        }

        // --- Detect Attack ---
        // 1. Signiture Comparison
        int sig_matches = match_packet(payload, payload_len, "tcp", dst_port);

        // 2. Anomaly Detection
        int ano_matches = anomaly_check(
            inet_ntoa(ip_header->ip_src), payload, payload_len);

        int total = sig_matches + ano_matches;

        if (total > 0) {
            logger_write(LOG_LEVEL_ALERT,
                inet_ntoa(ip_header->ip_src),
                ntohs(tcp->th_sport),
                dst_port,
                /* sid is returned from match_packet */ 0,
                "Attack detected",
                payload);
            printf("    Request: %.200s\n\n", payload);
        } else {
            printf("    Clean request\n\n");
        }

        
    }

    // HTTPS TLS ClientHello Check
    if(dst_port == 443){
        // To ensure if it is TLS Handshake
        if (payload_len < 6 ||
            (unsigned char)payload[0] != 0x16 ||
            (unsigned char)payload[1] != 0x03) {
            return;
        }

        // TLS Handshake prefixes: 0x16 (Handshake) 0x03 (SSL version)
        const char *sni = extract_sni(payload, payload_len);
        if (sni) {
            printf("HTTPS Connection to: %s (from %s)\n",
                   sni, inet_ntoa(ip_header->ip_src));

            // Compare https rules
            int matches = match_packet(sni, strlen(sni), "tcp", dst_port);
            if (matches > 0) {
                printf("    %d rule(s) matched\n\n", matches);
            }
        }
    }
}

int main(int argc, char *argv[]){
    pcap_t *handle;                 // Session Handle
    char *dev;                      // Device to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];  // Error String
    struct bpf_program fp;          // The compiled filter
    char filter_exp[] = "tcp port 80 or tcp port 443";     // The filter expression
    bpf_u_int32 mask;               // Subnet mask
    bpf_u_int32 net;                // The IP

    // List all available devices first
    pcap_if_t *alldevs;
    pcap_if_t *d;
    
    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 2;
    }
    
    printf("Available network interfaces:\n");
    int i = 0;
    for(d = alldevs; d != NULL; d = d->next) {
        printf("  %d. %s", ++i, d->name);
        printf(d->description ? " (%s)\n" : " (No description)\n",
               d->description ? d->description : "");
    }
    
    // Use first available device or specify manually
    if(alldevs == NULL) {
        fprintf(stderr, "No devices found\n");
        return 2;
    }
    
    dev = alldevs->name;
    printf("\nUsing device: %s\n", dev);
    
    // Find the properties for the device
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // Open the session in promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    printf("Opened device successfully\n");

    // Compile and apply the filter
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        return 2;
    }

    // Set the filter
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freealldevs(alldevs);
        return 2;
    }

    if(load_rules("../rules/http-attacks.rules") < 0) return 1;
    if(load_rules("../rules/https-attacks.rules") < 0) return 1;

    logger_init("../logs/ids.log"); // NULL = not writing file

    printf("Monitoring with %d rules...\n\n", get_rule_count());
    printf("💡 Tip: In another terminal, run:\n");
    printf("   curl \"http://httpbin.org/get?test=<script>alert(1)</script>\"\n");
    printf("   curl \"http://httpbin.org/get?id=' OR 1=1--\"\n\n");    
    
    pcap_loop(handle, 0, packet_handler, NULL);

    logger_print_stats();
    logger_close();
    
    // Cleanup
    free_rules();
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}