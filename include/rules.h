#ifndef RULES_H
#define RULES_H

#define MAX_RULES 1000
#define MAX_CONTENT_LEN 256

typedef enum{
    RULE_TYPE_CONTENT
} rule_type_t;

typedef struct{
    int enabled;
    int sid;
    char msg[128];
    char protocol[8];
    int dst_port;

    rule_type_t type;
    char content[MAX_CONTENT_LEN];
    int nocase; // whether ignore case

    int priority;
} detection_rule_t;

int load_rules(const char *filename);
int match_packet(const char *payload, int payload_len, const char *protocol, int dst_port);

void free_rules();
int get_rule_count();

#endif