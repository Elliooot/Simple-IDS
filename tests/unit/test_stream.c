#include "simpleids/stream.h"
#include "test.h"

static void configure(uint32_t depth, size_t memcap, overlap_policy_t policy) {
    stream_config_t cfg = { depth, memcap, policy };
    stream_configure(&cfg);
    stream_reset_stats();
}

/* Insert from an exact-size heap copy (ASan checks the reads). */
static void put(stream_t *s, uint32_t seq, const char *data) {
    size_t n;
    uint8_t *b = exact_buf(data, &n);
    stream_insert(s, seq, b, (uint32_t)n, (uint32_t)n);
    free(b);
}

/* Concatenate all runs currently available into out. */
static int drain(stream_t *s, int force, char *out, size_t outlen, int *gaps) {
    uint32_t a, b;
    int gap, runs = 0;
    size_t n = strlen(out);
    while (stream_next_run(s, force, &a, &b, &gap)) {
        if (gap && gaps) (*gaps)++;
        if (gap && n + 1 < outlen) out[n++] = '|';
        for (uint32_t i = a; i < b && n + 1 < outlen; i++) out[n++] = (char)s->buf[i];
        runs++;
    }
    out[n] = '\0';
    return runs;
}

static void test_stream_in_order(void) {
    configure(1024, 1 << 20, OVERLAP_FIRST);
    stream_t s;
    memset(&s, 0, sizeof(s));
    char out[64] = "";
    stream_init(&s, 100);
    put(&s, 100, "GET ");
    CHECK_EQ_INT(drain(&s, 0, out, sizeof(out), NULL), 1);
    put(&s, 104, "/x");                    /* starts at the next undelivered byte */
    CHECK_EQ_INT(drain(&s, 0, out, sizeof(out), NULL), 1);
    CHECK_EQ_STR(out, "GET /x");
    CHECK_EQ_INT(stream_stats()->in_order, 2);
    CHECK_EQ_INT(stream_stats()->out_of_order, 0);
    stream_close(&s);
    CHECK_EQ_INT(stream_stats()->mem_used, 0);
}

static void test_stream_out_of_order(void) {
    configure(1024, 1 << 20, OVERLAP_FIRST);
    stream_t s;
    memset(&s, 0, sizeof(s));
    char out[64] = "";
    stream_init(&s, 0);
    put(&s, 6, "t>");
    put(&s, 4, "ip");
    CHECK_EQ_INT(drain(&s, 0, out, sizeof(out), NULL), 0); /* hole at 0 */
    put(&s, 0, "<scr");
    CHECK_EQ_INT(drain(&s, 0, out, sizeof(out), NULL), 1);
    CHECK_EQ_STR(out, "<script>");
    CHECK_EQ_INT(stream_stats()->out_of_order, 2);
    stream_close(&s);
}

static void test_stream_retransmit_identical(void) {
    configure(1024, 1 << 20, OVERLAP_FIRST);
    stream_t s;
    memset(&s, 0, sizeof(s));
    char out[64] = "";
    stream_init(&s, 0);
    put(&s, 0, "abcd");
    put(&s, 0, "abcd");
    put(&s, 2, "cdef");                    /* repacketized: overlap is identical */
    drain(&s, 0, out, sizeof(out), NULL);
    CHECK_EQ_STR(out, "abcdef");
    CHECK_EQ_INT(stream_stats()->overlaps, 2);
    CHECK_EQ_INT(stream_stats()->retransmits, 2);
    CHECK_EQ_INT(stream_stats()->overlap_diffs, 0);
    CHECK_EQ_INT(s.overlap_diff, 0);
    stream_close(&s);
}

/* Queued (not yet delivered) overlaps follow the configured policy. */
static void overlap_case(overlap_policy_t policy, const char *expect) {
    configure(1024, 1 << 20, policy);
    stream_t s;
    memset(&s, 0, sizeof(s));
    char out[64] = "";
    stream_init(&s, 0);
    put(&s, 4, "XXXX");
    put(&s, 4, "ipt>");
    put(&s, 0, "<scr");
    drain(&s, 0, out, sizeof(out), NULL);
    CHECK_EQ_STR(out, expect);
    CHECK_EQ_INT(s.overlap_diff, 1);
    CHECK_EQ_INT(stream_stats()->overlap_diffs, 1);
    stream_close(&s);
}

static void test_stream_overlap_first(void) {
    overlap_case(OVERLAP_FIRST, "<scrXXXX");
}

static void test_stream_overlap_last(void) {
    overlap_case(OVERLAP_LAST, "<script>");
}

/* Delivered bytes are final under either policy. */
static void test_stream_delivered_is_immutable(void) {
    for (int pol = 0; pol < 2; pol++) {
        configure(1024, 1 << 20, (overlap_policy_t)pol);
        stream_t s;
        memset(&s, 0, sizeof(s));
        char out[64] = "";
        stream_init(&s, 0);
        put(&s, 0, "AAAA");
        drain(&s, 0, out, sizeof(out), NULL);
        put(&s, 0, "BBBBCC");          /* rewrites delivered bytes */
        drain(&s, 0, out, sizeof(out), NULL);
        CHECK_EQ_STR(out, "AAAACC");
        CHECK_EQ_INT(s.overlap_diff, 1);
        stream_close(&s);
    }
}

static void test_stream_gap_needs_force(void) {
    configure(1024, 1 << 20, OVERLAP_FIRST);
    stream_t s;
    memset(&s, 0, sizeof(s));
    char out[64] = "";
    int gaps = 0;
    stream_init(&s, 0);
    put(&s, 0, "ab");
    put(&s, 5, "fg");
    drain(&s, 0, out, sizeof(out), &gaps);
    CHECK_EQ_STR(out, "ab");               /* waits: hole may be filled */
    drain(&s, 1, out, sizeof(out), &gaps);
    CHECK_EQ_STR(out, "ab|fg");            /* forced: hole skipped */
    CHECK_EQ_INT(gaps, 1);
    CHECK_EQ_INT(stream_stats()->gaps, 1);
    stream_close(&s);
}

/* Bytes cut off by the snaplen are lost for good: skipped at once. */
static void test_stream_snaplen_loss(void) {
    configure(1024, 1 << 20, OVERLAP_FIRST);
    stream_t s;
    memset(&s, 0, sizeof(s));
    char out[64] = "";
    int gaps = 0;
    stream_init(&s, 0);
    uint8_t seg[] = { 'a', 'b', 'c' };
    stream_insert(&s, 0, seg, 3, 10);      /* 7 bytes never captured */
    put(&s, 10, "XYZ");
    drain(&s, 0, out, sizeof(out), &gaps);
    CHECK_EQ_STR(out, "abc|XYZ");
    CHECK_EQ_INT(gaps, 1);
    stream_close(&s);
}

static void test_stream_depth(void) {
    configure(16, 1 << 20, OVERLAP_FIRST);
    stream_t s;
    memset(&s, 0, sizeof(s));
    char out[64] = "";
    stream_init(&s, 0);
    put(&s, 0, "0123456789");
    put(&s, 10, "ABCDEFGHIJ");             /* only 6 bytes fit */
    put(&s, 30, "beyond");
    drain(&s, 0, out, sizeof(out), NULL);
    CHECK_EQ_STR(out, "0123456789ABCDEF");
    CHECK_EQ_INT(stream_stats()->depth_reached, 2);
    CHECK(s.cap <= 16);
    stream_close(&s);
}

static void test_stream_memcap(void) {
    configure(4096, 2000, OVERLAP_FIRST);  /* one 1 KiB buffer costs 1280 */
    stream_t a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    stream_init(&a, 0);
    stream_init(&b, 0);
    put(&a, 0, "first");
    put(&b, 0, "second");                  /* over the memcap */
    CHECK(a.buf != NULL);
    CHECK(b.buf == NULL);
    CHECK_EQ_INT(b.closed, 1);
    CHECK_EQ_INT(stream_stats()->memcap_drops, 1);
    CHECK(stream_stats()->mem_used <= 2000);
    put(&a, 2000, "far");                  /* growing a is refused too */
    CHECK_EQ_INT(a.closed, 1);
    CHECK_EQ_INT(stream_stats()->mem_used, 0);
    stream_close(&b);
}

/* Data before the first byte and around the 2^32 sequence wrap. */
static void test_stream_seq_edges(void) {
    configure(1024, 1 << 20, OVERLAP_FIRST);
    stream_t s;
    memset(&s, 0, sizeof(s));
    char out[64] = "";
    stream_init(&s, 0xfffffffeu);
    put(&s, 0xfffffffcu, "xxab");          /* first 2 bytes predate the stream */
    put(&s, 0x00000000u, "cd");            /* wrapped */
    drain(&s, 0, out, sizeof(out), NULL);
    CHECK_EQ_STR(out, "abcd");
    put(&s, 0xfffffff0u, "old");           /* entirely before: ignored */
    CHECK_EQ_INT(s.overlap_diff, 0);
    stream_close(&s);
}

const test_case_t stream_tests[] = {
    TEST(test_stream_in_order),
    TEST(test_stream_out_of_order),
    TEST(test_stream_retransmit_identical),
    TEST(test_stream_overlap_first),
    TEST(test_stream_overlap_last),
    TEST(test_stream_delivered_is_immutable),
    TEST(test_stream_gap_needs_force),
    TEST(test_stream_snaplen_loss),
    TEST(test_stream_depth),
    TEST(test_stream_memcap),
    TEST(test_stream_seq_edges),
    TEST_END
};
