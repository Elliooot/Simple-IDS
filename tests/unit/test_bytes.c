#include "simpleids/bytes.h"
#include "simpleids/digest.h"
#include "simpleids/siphash.h"
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

/* Reference vectors from the SipHash paper (key 00..0f). */
static void test_siphash_vectors(void) {
    uint8_t key[16], msg[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i, msg[i] = (uint8_t)i;
    CHECK(siphash24(key, msg, 0) == 0x726fdb47dd0e0e31ULL);
    CHECK(siphash24(key, msg, 1) == 0x74f839c593dc67fdULL);
    CHECK(siphash24(key, msg, 8) == 0x93f5f5799a932462ULL);
    CHECK(siphash24(key, msg, 15) == 0xa129ca6149be45e5ULL);
}

static void test_random_bytes(void) {
    uint8_t a[16] = { 0 }, b[16] = { 0 };
    CHECK_EQ_INT(random_bytes(a, sizeof(a)), 0);
    CHECK_EQ_INT(random_bytes(b, sizeof(b)), 0);
    CHECK(memcmp(a, b, sizeof(a)) != 0);
}

/* RFC 1321 / FIPS 180-4 vectors, plus lengths around the padding edge. */
static void test_digests(void) {
    static const struct { const char *in, *md5, *sha; } v[] = {
        { "", "d41d8cd98f00b204e9800998ecf8427e",
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "900150983cd24fb0d6963f7d28e17f72",
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "8215ef0796a20bcaaae116d3876c664a",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        size_t n;
        uint8_t *in = exact_buf(v[i].in, &n), d[32];
        char hex[65];
        md5(in, n, d);
        digest_hex(d, MD5_LEN, hex);
        CHECK_EQ_STR(hex, v[i].md5);
        sha256(in, n, d);
        digest_hex(d, SHA256_LEN, hex);
        CHECK_EQ_STR(hex, v[i].sha);
        free(in);
    }
}

const test_case_t bytes_tests[] = {
    TEST(test_find_does_not_read_past_len),
    TEST(test_find_basic),
    TEST(test_find_nocase_high_bytes),
    TEST(test_find_across_nul),
    TEST(test_startswith),
    TEST(test_read_be_unaligned),
    TEST(test_siphash_vectors),
    TEST(test_random_bytes),
    TEST(test_digests),
    TEST_END
};
