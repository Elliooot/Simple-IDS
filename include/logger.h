#ifdef LOGGER_H
#define LOGGER_H

typedef enum {
    LOG_LEVEL_INFO = 0,
    LOG_LEVEL_WARN = 1,
    LOG_LEVEL_ALERT = 2
} log_level_t;

// Init logger (filename = NULL means not writing to file)
int logger_init(const char *filename);
void logger_close();

// Record an event
void logger_write(log_level_t level, const char *src_ip, int src_port,
                  int dst_port, int sid, const char *msg, const char *payload);

// Print Stats
void logger_print_stats();

#endif