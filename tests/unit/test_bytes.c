#include "simpleids/bytes.h"
#include "test.h"

/* B1: searching must stay inside [0, len) even without a NUL. */
static void test_find_does_not_read_past_len(void) {
    size_t n;
    uint8_t *buf = exact_buf("GET /?x=<scr", &n);
    CHECK(bytes_find(buf, n, (const uint8_t *)"<script>", 8, 0) == NULL);
    CHECK(bytes_find(buf, n, (const uint8_t *)"<SCR", 4, 1) == buf + 8);
    free(buf);
}

static void test_find_basic(void) {
    const uint8_t hay[] = "abcabcd";
    CHECK(bytes_find(hay, 7, (const uint8_t *)"abcd", 4, 0) == hay + 3);
    CHECK(bytes_find(hay, 7, (const uint8_t *)"ABCD", 4, 0) == NULL);
    CHECK(bytes_find(hay, 7, (const uint8_t *)"ABCD", 4, 1) == hay + 3);
    CHECK(bytes_find(hay, 3, (const uint8_t *)"abcd", 4, 0) == NULL);
    CHECK(bytes_find(hay, 7, (const uint8_t *)"", 0, 0) == NULL);
}

/* B9: case folding must be defined for bytes >= 0x80. */
static void test_find_nocase_high_bytes(void) {
    const uint8_t hay[] = { 0xff, 0x80, 0xc9, 'S', 'C', 'R', 'I', 'P', 'T', 0xe9 };
    CHECK(bytes_find(hay, sizeof(hay), (const uint8_t *)"script", 6, 1) == hay + 3);
    const uint8_t hi[] = { 0xc9 };
    CHECK(bytes_find(hay, sizeof(hay), hi, 1, 1) == hay + 2);
    const uint8_t lo[] = { 0xe9 };
    /* Only ASCII letters fold: 0xC9 and 0xE9 stay distinct. */
    CHECK(bytes_find(hay, 3, lo, 1, 1) == NULL);
}

/* Embedded NUL bytes must not end the search early. */
static void test_find_across_nul(void) {
    const uint8_t hay[] = { 'G', 'E', 'T', 0, '<', 's', 'c', 'r', 'i', 'p', 't', '>' };
    CHECK(bytes_find(hay, sizeof(hay), (const uint8_t *)"<script>", 8, 0) == hay + 4);
}

static void test_startswith(void) {
    size_t n;
    uint8_t *buf = exact_buf("GET", &n);
    CHECK(bytes_startswith(buf, n, "GET"));
    CHECK(!bytes_startswith(buf, n, "GET "));
    CHECK(bytes_startswith_nocase(buf, n, "get"));
    free(buf);
}

static void test_read_be_unaligned(void) {
    uint8_t raw[8] = { 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0 };
    CHECK_EQ_INT(rd_be16(raw + 1), 0x1234);
    CHECK_EQ_INT(rd_be32(raw + 1), 0x12345678);
    CHECK_EQ_INT(rd_le32(raw + 1), 0x78563412);
}

const test_case_t bytes_tests[] = {
    TEST(test_find_does_not_read_past_len),
    TEST(test_find_basic),
    TEST(test_find_nocase_high_bytes),
    TEST(test_find_across_nul),
    TEST(test_startswith),
    TEST(test_read_be_unaligned),
    TEST_END
};
