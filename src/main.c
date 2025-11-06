#define _DEFAULT_SOURCE
#define __FAVOR_BSD

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

typedef unsigned char u_char;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
    // Skip Ethernet header (14 bytes)
    struct ip *ip_header = (struct ip *)(packet + 14);

    // Check the protocol field in the IP header to see if it is TCP
    if(ip_header->ip_p != IPPROTO_TCP) return;

    int ip_header_len = ip_header->ip_hl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len);
    
    // Detect HTTP (port 80) only
    if(ntohs(tcp->th_dport) != 80) return;

    // Get payload
    int tcp_len = tcp->th_off * 4;
    const char *payload = (char *)(packet + 14 + ip_header_len + tcp_len);
    int payload_len = header->len - (14 + ip_header_len + tcp_len);

    if(payload_len <= 0) return;

    // --- Detect Attack ---

    // Check if HTTP request
    if(strncmp(payload, "GET ", 4) != 0 && strncmp(payload, "POST ", 5) != 0) return;

    printf("HTTP Request from: %s\n", inet_ntoa(ip_header->ip_src));

    // SQL Injection
    if(strstr(payload, "' OR 1=1") || strstr(payload, "UNION SELECT")){
        printf("    [ALERT] SQL Injection detected!\n");
    }

    // XSS
    if(strstr(payload, "<script>") || strstr(payload, "javascript:")){
        printf("    [ALERT] XSS attempt detected!\n");
    }

    // Path traversal
    if(strstr(payload, "../")){
        printf("    [ALERT] Path traversal detected!\n");
    }

    // Scanner
    if(strstr(payload, "sqlmap") || strstr(payload, "nikto")){
        printf("    [ALERT] Attack tool detected!\n");
    }

    printf("    Request: %.200s\n\n", payload);
}

int main(int argc, char *argv[]){
    pcap_t *handle;                 // Session Handle
    char *dev;                      // Device to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];  // Error String
    struct bpf_program fp;          // The compiled filter
    char filter_exp[] = "tcp";     // The filter expression
    bpf_u_int32 mask;               // Subnet mask
    bpf_u_int32 net;                // The IP
    struct pcap_pkthdr header;      // The header that pcap gives us
    const u_char *packet;    // The actual packet

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
        printf("%d. %s", ++i, d->name);
        if(d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
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

    printf("Capturing TCP packets...\n");
    printf("Tip: Open a browser to generate traffic\n\n");
    
    
    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}