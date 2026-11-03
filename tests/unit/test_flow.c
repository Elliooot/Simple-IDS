#include "simpleids/flow.h"
#include "test.h"

static int g_ended;
static flow_end_t g_last_why;

static void on_end(flow_t *f, flow_end_t why) {
    (void)f;
    g_ended++;
    g_last_why = why;
}

static void init(uint32_t max) {
    flow_config_t cfg;
    flow_config_defaults(&cfg);
    cfg.max_flows = max;
    g_ended = 0;
    flow_init(&cfg, on_end);
}

static packet_t pkt4(uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport, uint8_t flags) {
    packet_t p;
    memset(&p, 0, sizeof(p));
    p.ip_version = 4;
    p.l4proto = L4_TCP;
    p.src_addr[0] = (uint8_t)(src >> 24); p.src_addr[1] = (uint8_t)(src >> 16);
    p.src_addr[2] = (uint8_t)(src >> 8);  p.src_addr[3] = (uint8_t)src;
    p.dst_addr[0] = (uint8_t)(dst >> 24); p.dst_addr[1] = (uint8_t)(dst >> 16);
    p.dst_addr[2] = (uint8_t)(dst >> 8);  p.dst_addr[3] = (uint8_t)dst;
    p.src_port = sport;
    p.dst_port = dport;
    p.tcp_flags = flags;
    return p;
}

static packet_t reverse(packet_t p) {
    packet_t r = p;
    memcpy(r.src_addr, p.dst_addr, 16);
    memcpy(r.dst_addr, p.src_addr, 16);
    r.src_port = p.dst_port;
    r.dst_port = p.src_port;
    return r;
}

static struct timeval at(long sec) {
    struct timeval tv = { sec, 0 };
    return tv;
}

static void test_flow_bidirectional(void) {
    init(16);
    packet_t syn = pkt4(0x0a000002, 40000, 0x0a000001, 80, TCP_SYN);
    packet_t synack = reverse(syn);
    synack.tcp_flags = TCP_SYN | TCP_ACK;
    struct timeval t = at(100);
    int d1, d2;

    flow_t *f1 = flow_get(&syn, &t, &d1);
    CHECK(f1 != NULL);
    CHECK_EQ_INT(d1, FLOW_TO_SERVER);
    CHECK_EQ_INT(f1->tcp_state, TCP_STATE_SYN_SENT);
    CHECK_EQ_INT(f1->port[0], 40000);
    CHECK_EQ_INT(f1->port[1], 80);

    flow_t *f2 = flow_get(&synack, &t, &d2);
    CHECK(f2 == f1);
    CHECK_EQ_INT(d2, FLOW_TO_CLIENT);
    CHECK_EQ_INT(flow_stats()->created, 1);
    CHECK_EQ_INT(f1->pkts[0], 1);
    CHECK_EQ_INT(f1->pkts[1], 1);

    /* Same hash in both directions. */
    CHECK(flow_hash_packet(&syn) == flow_hash_packet(&synack));
    flow_destroy();
    CHECK_EQ_INT(g_ended, 1);
    CHECK_EQ_INT(g_last_why, FLOW_END_SHUTDOWN);
}

/* Without a SYN, the side using a service port is the server. */
static void test_flow_orientation_midstream(void) {
    init(16);
    packet_t resp = pkt4(0x0a000001, 80, 0x0a000002, 40000, TCP_ACK | TCP_PSH);
    struct timeval t = at(1);
    int dir;
    flow_t *f = flow_get(&resp, &t, &dir);
    CHECK_EQ_INT(dir, FLOW_TO_CLIENT);
    CHECK_EQ_INT(f->port[1], 80);

    /* SYN-ACK first: its destination is the client. */
    packet_t sa = pkt4(0x0a000001, 5555, 0x0a000002, 6666, TCP_SYN | TCP_ACK);
    f = flow_get(&sa, &t, &dir);
    CHECK_EQ_INT(dir, FLOW_TO_CLIENT);
    CHECK_EQ_INT(f->port[0], 6666);
    flow_destroy();
}

/* The pool never grows: the least recently used flow is evicted. */
static void test_flow_lru_eviction(void) {
    init(3);
    struct timeval t = at(10);
    int dir;
    packet_t a = pkt4(0x01010101, 1, 0x0a000001, 80, TCP_ACK);
    packet_t b = pkt4(0x02020202, 2, 0x0a000001, 80, TCP_ACK);
    packet_t c = pkt4(0x03030303, 3, 0x0a000001, 80, TCP_ACK);
    packet_t d = pkt4(0x04040404, 4, 0x0a000001, 80, TCP_ACK);

    flow_t *fa = flow_get(&a, &t, &dir);
    flow_get(&b, &t, &dir);
    flow_get(&c, &t, &dir);
    flow_get(&a, &t, &dir);           /* a is now most recently used */
    flow_get(&d, &t, &dir);           /* evicts b */
    CHECK_EQ_INT(flow_stats()->evicted, 1);
    CHECK_EQ_INT(g_last_why, FLOW_END_EVICTED);
    CHECK_EQ_INT(flow_stats()->active, 3);

    uint64_t id_a = fa->id;
    CHECK(flow_get(&a, &t, &dir)->id == id_a);  /* a survived */
    flow_get(&b, &t, &dir);                     /* b comes back as new */
    CHECK_EQ_INT(flow_stats()->created, 5);
    CHECK(flow_stats()->active_peak <= 3);
    flow_destroy();
}

static void test_flow_timeouts(void) {
    init(16);
    int dir;
    struct timeval t0 = at(1000);
    packet_t syn = pkt4(0x0a000002, 40000, 0x0a000001, 80, TCP_SYN);
    flow_get(&syn, &t0, &dir);

    /* Handshake-only flows time out after timeout_new (30 s). */
    struct timeval t1 = at(1000 + 31);
    flow_expire(&t1);
    CHECK_EQ_INT(flow_stats()->timed_out, 1);
    CHECK_EQ_INT(flow_stats()->active, 0);

    /* Established flows live longer. */
    packet_t data = pkt4(0x0a000002, 40001, 0x0a000001, 80, TCP_ACK | TCP_PSH);
    data.payload_len = 1;
    flow_get(&data, &t1, &dir);
    struct timeval t2 = at(1000 + 31 + 500);
    flow_expire(&t2);
    CHECK_EQ_INT(flow_stats()->active, 1);

    /* A lookup of an expired flow starts a fresh one. */
    struct timeval t3 = at(1000 + 31 + 700);
    flow_get(&data, &t3, &dir);
    CHECK_EQ_INT(flow_stats()->timed_out, 2);
    CHECK_EQ_INT(flow_stats()->created, 3);
    flow_destroy();
}

static void test_flow_fin_rst_and_reuse(void) {
    init(16);
    int dir;
    struct timeval t = at(5);
    packet_t syn = pkt4(0x0a000002, 40000, 0x0a000001, 80, TCP_SYN);
    flow_t *f = flow_get(&syn, &t, &dir);
    packet_t fin = pkt4(0x0a000002, 40000, 0x0a000001, 80, TCP_FIN | TCP_ACK);
    flow_get(&fin, &t, &dir);
    CHECK(f->tcp_state != TCP_STATE_CLOSED);
    packet_t fin2 = reverse(fin);
    flow_get(&fin2, &t, &dir);
    CHECK_EQ_INT(f->tcp_state, TCP_STATE_CLOSED);

    /* A new SYN on the closed 5-tuple starts a new connection. */
    uint64_t old = f->id;
    flow_t *g = flow_get(&syn, &t, &dir);
    CHECK(g->id != old);
    CHECK_EQ_INT(flow_stats()->reused, 1);

    /* RST closes, but the flow stays until its (short) timeout. */
    packet_t rst = pkt4(0x0a000001, 80, 0x0a000002, 40000, TCP_RST);
    flow_get(&rst, &t, &dir);
    CHECK_EQ_INT(g->tcp_state, TCP_STATE_CLOSED);
    CHECK_EQ_INT(flow_stats()->active, 1);
    struct timeval later = at(5 + 11);
    flow_expire(&later);
    CHECK_EQ_INT(flow_stats()->active, 0);
    flow_destroy();
}

static void test_flow_ipv6_and_udp_are_distinct(void) {
    init(16);
    int dir;
    struct timeval t = at(1);
    packet_t tcp = pkt4(0x0a000002, 5000, 0x0a000001, 53, TCP_ACK);
    packet_t udp = tcp;
    udp.l4proto = L4_UDP;
    packet_t v6 = tcp;
    v6.ip_version = 6; /* same first 4 address bytes, different family */

    flow_get(&tcp, &t, &dir);
    flow_get(&udp, &t, &dir);
    flow_get(&v6, &t, &dir);
    CHECK_EQ_INT(flow_stats()->created, 3);
    flow_destroy();
}

/* The bucket depends on a secret key: another key, another hash. */
static void test_flow_hash_is_keyed(void) {
    packet_t p = pkt4(0x0a000002, 40000, 0x0a000001, 80, TCP_SYN);
    uint8_t k1[16] = { 1 }, k2[16] = { 2 };
    flow_set_hash_key(k1);
    uint64_t h1 = flow_hash_packet(&p);
    flow_set_hash_key(k2);
    uint64_t h2 = flow_hash_packet(&p);
    CHECK(h1 != h2);
    flow_set_hash_key(k1);
    CHECK(flow_hash_packet(&p) == h1);
}

const test_case_t flow_tests[] = {
    TEST(test_flow_bidirectional),
    TEST(test_flow_orientation_midstream),
    TEST(test_flow_lru_eviction),
    TEST(test_flow_timeouts),
    TEST(test_flow_fin_rst_and_reuse),
    TEST(test_flow_ipv6_and_udp_are_distinct),
    TEST(test_flow_hash_is_keyed),
    TEST_END
};
