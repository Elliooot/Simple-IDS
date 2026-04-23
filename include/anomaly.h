#ifndef ANOMALY_H
#define ANOMALY_H

// Automatically detect all anomalies on a single call
// Return the number of anomalies detected (0 = normal)
int anomaly_check(const char *src_ip, const char *payload, int payload_len);

#endif