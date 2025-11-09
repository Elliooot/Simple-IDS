#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rules.h"

static detection_rule_t rules[MAX_RULES];
static int rule_count = 0;

// Case-insensitive string search
static char *strcasestr_custom(const char *haystack, const char *needle){
    if(!*needle) return (char *)haystack;

    for(; *haystack; haystack++){
        if(tolower(*haystack) == tolower(*needle)){
            const char *h = haystack;
            const char *n = needle;

            while(*h && *n && tolower(*h) == tolower(*n)){
                h++;
                n++;
            }

            if(!*n) return (char *)haystack;
        }
    }
    return NULL;
}

int load_rules(const char *filename){
    FILE *fp = fopen(filename, "r");
    if(!fp){
        fprint(stderr, "Cannot open rules file:%s\n", filename);
        return -1;
    }

    char line[512];
    int line_num = 0;

    while(fgets(line, sizeof(line), fp) && rule_count < MAX_RULES){
        line_num++;

        // Skip annotations and blank lines
        if(line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        detection_rule_t *r = &rules[rule_count];
        r->enabled = 1;
        r->type = RULE_TYPE_CONTENT;
        r->nocase = 0;
        r->dst_port = 0;
        r->priority = 2; // default priority level

        // Parsing format: alert tcp any any -> any 80 (content:"<script>"; msg:"XSS"; sid:1001; nocase;)
        char action[16], src[32], dst[32];
        int src_port, dst_port;
        char options[256];

        int parsed = sscanf(line, "%s %s %s %d -> %s %d (%[^)])",
                            action, r->protocol, src, &src_port,
                            dst, &dst_port, options);
        
        if(parsed < 7){
            fprintf(stderr, "Line %d: Parse error, skipping...\n", line_num);
            continue;
        }

        r->dst_port = (dst_port == 0) ? 0 : dst_port;

        // Parse options
        char *content_start = strstr(options, "content:\""); // Find String 'content:"'
        if(content_start){
            content_start += 9; // Skip 'content:"'
            char *content_end = strchr(content_start, '"');
            if(content_end){
                int len = content_end - content_start;
                if(len < MAX_CONTENT_LEN){
                    strncpy(r->content, content_start, len);
                    r->content[len] = '\0';
                }
            }
        }

        char *msg_start = strstr(options, "msg:\"");
        if(msg_start){
            msg_start += 5;
            char *msg_end = strchr(msg_start, '"');
            if(msg_end){
                int len = msg_end - msg_start;
                if(len < 128){
                    strncpy(r->msg, msg_start, len);
                    r->msg[len] = '\0';
                }
            }
        }

        char *sid_start = strstr(options, "sid:\"");
        if(sid_start){
            sscanf(sid_start, "sid:%d", &r->sid);
        }

        // nocase option
        if(strstr(options, "nocase")){
            r->nocase = 1;
        }

        // priority option
        char *priority_start = strstr(options, "priority:");
        if(priority_start){
            sscanf(priority_start, "priority:%d", &r->priority);
        }

        rule_count++;
    }

    fclose(fp);
    printf("Loaded %d rules from %s\n", rule_count, filename);
    return rule_count;
}