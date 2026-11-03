#ifndef SIMPLEIDS_STREAM_H
#define SIMPLEIDS_STREAM_H

#include <stddef.h>
#include <stdint.h>

/*
 * TCP stream reassembly for one direction of a connection.
 *
 * Data is stored by *stream offset* (bytes since the first sequence
 * number), so out-of-order segments are written straight to their final
 * position and a bitmap records which bytes are present. Only offsets
 * below the configured depth are kept, and every allocation is charged
 * against one global memcap, so memory use has a hard upper bound.
 *
 * The consumer pulls contiguous runs with stream_next_run(). Bytes it has
 * been given ("delivered") never change again, just like data a real TCP
 * stack has handed to the application.
 */

typedef enum {
    OVERLAP_FIRST = 0, /* bytes already queued win (BSD, Windows-like)  */
    OVERLAP_LAST  = 1  /* the newest bytes win (some Linux / Solaris)   */
} overlap_policy_t;

typedef struct {
    uint32_t         depth;   /* bytes reassembled per stream          */
    size_t           memcap;  /* total bytes for all stream buffers    */
    overlap_policy_t policy;  /* for overlaps in not-yet-delivered data */
} stream_config_t;

typedef struct {
    unsigned long segments;       /* segments with payload             */
    unsigned long in_order;
    unsigned long out_of_order;
    unsigned long retransmits;    /* fully overlapping, identical data  */
    unsigned long overlaps;       /* segments overlapping stored bytes  */
    unsigned long overlap_diffs;  /* ... where the bytes differed       */
    unsigned long gaps;           /* holes skipped                      */
    unsigned long depth_reached;  /* segments (partly) beyond depth     */
    unsigned long memcap_drops;   /* streams stopped by the memcap      */
    size_t        mem_used;
    size_t        mem_peak;
} stream_stats_t;

typedef struct {
    uint8_t  active;       /* has a base sequence number              */
    uint8_t  closed;       /* stopped: no more data is stored         */
    uint8_t  overlap_diff; /* overlapping data differed at least once */
    uint8_t  gap_pending;  /* next run follows a gap                  */
    uint32_t base_seq;     /* sequence number of offset 0             */
    uint32_t delivered;    /* offsets below this were handed out      */
    uint32_t max_off;      /* highest stored (or lost) offset + 1     */
    uint32_t cap;          /* allocated size of buf                   */
    uint8_t *buf;          /* buf[offset]                             */
    uint8_t *present;      /* bitmap: byte received                   */
    uint8_t *lost;         /* bitmap: byte known missing (snaplen)    */
} stream_t;

void stream_configure(const stream_config_t *cfg);
const stream_config_t *stream_get_config(void);
const stream_stats_t *stream_stats(void);
void stream_reset_stats(void);

/* Start a stream whose first data byte has sequence number first_seq. */
void stream_init(stream_t *s, uint32_t first_seq);

/*
 * Store one segment.
 *   seq       sequence number of the first payload byte
 *   data/len  captured payload bytes
 *   wire_len  payload length on the wire; bytes beyond len were cut off
 *             by the snaplen and are marked lost (they will never arrive)
 */
void stream_insert(stream_t *s, uint32_t seq, const uint8_t *data,
                   uint32_t len, uint32_t wire_len);

/*
 * Get the next contiguous run of undelivered data as stream offsets
 * [*start, *end); the bytes are s->buf[*start .. *end).
 * *gap_before is set when bytes were skipped before this run.
 * Lost (snaplen) bytes are always skipped. With force != 0 (connection
 * ended), holes that might still be filled are skipped as well.
 * Returns 1 when a run was produced, 0 when nothing is ready.
 */
int stream_next_run(stream_t *s, int force, uint32_t *start, uint32_t *end,
                    int *gap_before);

/* Free the buffers and stop storing data for this stream. */
void stream_close(stream_t *s);

#endif
