#!/usr/bin/env python3
"""
Generate the regression pcaps in tests/pcaps/ together with their
*.expected.json files.

Only the Python standard library is used, so CI needs nothing extra.
Run from anywhere:  python3 tests/regression/gen_pcaps.py
Output is deterministic (fixed timestamps, ports and TLS randoms).
"""

import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # tests/
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "evasion"))

from cases import (ANOMALY_CASES, CLEAN_CASES, SIGNATURE_CASES,  # noqa: E402
                   SID_RATE, HttpCase)
from evasion_cases import CASES as EVASION_CASES  # noqa: E402
from evasion_cases import BASE_PORT as EVASION_PORT  # noqa: E402

OUT_DIR = os.path.join(os.path.dirname(HERE), "pcaps")

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113

T0 = 1_700_000_000  # 2023-11-14T22:13:20Z

CLIENT = "10.0.0.2"
SERVER = "10.0.0.1"


# --------------------------------------------------------------------------
# Packet building
# --------------------------------------------------------------------------

def ip_aton(s):
    return bytes(int(x) for x in s.split("."))


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_segment(src, dst, sport, dport, payload, seq=1000, flags=0x18):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 5 << 4, flags, 65535, 0, 0)
    pseudo = ip_aton(src) + ip_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    csum = checksum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", csum) + hdr[18:] + payload


def ipv4(src, dst, l4, proto=6, frag=0x4000):
    total = 20 + len(l4)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, frag, 64, proto, 0,
                      ip_aton(src), ip_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + l4


def ipv4_tcp(src, dst, sport, dport, payload):
    return ipv4(src, dst, tcp_segment(src, dst, sport, dport, payload))


def ipv6_tcp(sport, dport, payload):
    src = bytes.fromhex("fd000000000000000000000000000002")
    dst = bytes.fromhex("fd000000000000000000000000000001")
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 1, 5 << 4, 0x18, 65535, 0, 0) + payload
    return struct.pack("!IHBB", 6 << 28, len(tcp), 6, 64) + src + dst + tcp


def ether(l3, ethertype=0x0800):
    return bytes.fromhex("020000000001") + bytes.fromhex("020000000002") + \
        struct.pack("!H", ethertype) + l3


def null_loop(l3):
    return struct.pack("<I", 2) + l3  # AF_INET, little-endian host


def linux_sll(l3):
    return struct.pack("!HHH8sH", 0, 772, 6, bytes(8), 0x0800) + l3


def http_frame(case, sport, src=CLIENT, wrap=ether):
    return wrap(ipv4_tcp(src, SERVER, sport, case.port, case.request()))


def vlan_ether(l3, ethertype, tags):
    """Ethernet frame with VLAN tags, outermost first: [(tpid, vid), ...]."""
    frame = bytes.fromhex("020000000001") + bytes.fromhex("020000000002")
    for tpid, vid in tags:
        frame += struct.pack("!HH", tpid, vid)
    return frame + struct.pack("!H", ethertype) + l3


def ip6_aton(s):
    import ipaddress
    return ipaddress.IPv6Address(s).packed


def ipv6_packet(src, dst, next_header, l4, ext=b""):
    """ext: pre-built extension headers (their next-header fields set)."""
    payload = ext + l4
    return struct.pack("!IHBB", 6 << 28, len(payload), next_header, 64) + \
        ip6_aton(src) + ip6_aton(dst) + payload


def tcp_hdr(sport, dport, seq, ack, flags, payload):
    return struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                       5 << 4, flags, 65535, 0, 0) + payload


SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04


class Conn:
    """A TCP connection that produces frames with correct sequence numbers.

    Payload offsets are relative to the first data byte, so tests can send
    any byte range in any order (out of order, overlapping, missing).
    """

    def __init__(self, cport, client=CLIENT, server=SERVER, sport=80,
                 isn=1000, sisn=5000, v6=False, wrap=None):
        self.c, self.s, self.cp, self.sp = client, server, cport, sport
        self.isn, self.sisn, self.v6 = isn, sisn, v6
        self.wrap = wrap

    def _frame(self, to_server, seq, ack, flags, payload=b""):
        src, dst = (self.c, self.s) if to_server else (self.s, self.c)
        sp, dp = (self.cp, self.sp) if to_server else (self.sp, self.cp)
        if self.v6:
            l3 = ipv6_packet(src, dst, 6, tcp_hdr(sp, dp, seq, ack, flags, payload))
            etype = 0x86DD
        else:
            l3 = ipv4(src, dst, tcp_hdr(sp, dp, seq, ack, flags, payload))
            etype = 0x0800
        return self.wrap(l3, etype) if self.wrap else ether(l3, etype)

    def handshake(self):
        return [self._frame(True, self.isn, 0, SYN),
                self._frame(False, self.sisn, self.isn + 1, SYN | ACK),
                self._frame(True, self.isn + 1, self.sisn + 1, ACK)]

    def data(self, offset, payload, flags=PSH | ACK):
        return self._frame(True, self.isn + 1 + offset, self.sisn + 1, flags, payload)

    def fin(self, offset):
        return self._frame(True, self.isn + 1 + offset, self.sisn + 1, FIN | ACK)


# --------------------------------------------------------------------------
# TLS ClientHello
# --------------------------------------------------------------------------

def tls_ext(ext_type, data):
    return struct.pack("!HH", ext_type, len(data)) + data


def sni_ext(name):
    entry = b"\x00" + struct.pack("!H", len(name)) + name
    return tls_ext(0, struct.pack("!H", len(entry)) + entry)


def client_hello(exts, ext_len_delta=0):
    body = b"\x03\x03" + bytes(range(32))           # version + random
    body += b"\x20" + bytes(range(32, 64))          # session id
    suites = b"\x13\x01\x13\x02\xc0\x2f"
    body += struct.pack("!H", len(suites)) + suites
    body += b"\x01\x00"                              # compression: null
    ext_blob = b"".join(exts)
    body += struct.pack("!H", len(ext_blob) + ext_len_delta) + ext_blob
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


SUPPORTED_VERSIONS = tls_ext(43, b"\x02\x03\x04")


# --------------------------------------------------------------------------
# pcap writing
# --------------------------------------------------------------------------

def write_pcap(name, linktype, packets, snaplen=65535):
    """packets: list of (timestamp_float, frame_bytes)."""
    path = os.path.join(OUT_DIR, name + ".pcap")
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            incl = min(len(frame), snaplen)
            f.write(struct.pack("<IIII", sec, usec, incl, len(frame)))
            f.write(frame[:incl])
    return path


def write_expected(name, description, alerts, bugs=(), args=()):
    alerts = sorted(alerts, key=lambda a: (a["src_ip"], a["src_port"], a["sid"]))
    doc = {"description": description, "bugs": list(bugs), "alerts": alerts}
    if args:
        doc["args"] = list(args)
    with open(os.path.join(OUT_DIR, name + ".expected.json"), "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def alert(sid, sport, dport=80, src=CLIENT):
    return {"sid": sid, "src_ip": src, "src_port": sport, "dest_port": dport}


def emit(name, description, packets, alerts, linktype=LINKTYPE_ETHERNET,
         snaplen=65535, bugs=(), args=()):
    write_pcap(name, linktype, packets, snaplen)
    write_expected(name, description, alerts, bugs, args)
    print(f"  {name}.pcap: {len(packets)} packets, {len(alerts)} expected alerts")


def http_case_set(name, description, cases, base_port, bugs=()):
    packets, alerts = [], []
    for i, case in enumerate(cases):
        sport = base_port + i
        packets.append((T0 + i, http_frame(case, sport)))
        alerts += [alert(sid, sport, case.port) for sid in case.sids]
    emit(name, description, packets, alerts, bugs=bugs)


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

def gen_http_sets():
    http_case_set("http_clean", "Benign requests must not alert", CLEAN_CASES, 30000)
    http_case_set("http_signatures", "One request per signature rule (incl. B5 escapes)",
                  SIGNATURE_CASES, 40000, bugs=["B5", "B7", "B9"])
    http_case_set("http_anomaly", "URL length and User-Agent anomalies",
                  ANOMALY_CASES, 50000)


def gen_rate():
    """10.0.0.9 sends 120 requests in 30 s -> alerts at #101, #110, #120.
    10.0.0.10 sends 100, waits 61 s (new window), sends 100 more -> none."""
    packets, alerts = [], []
    case = HttpCase("rate", "/", set(), user_agent=None)
    for i in range(120):
        sport = 20000 + i
        packets.append((T0 + i * 0.25, http_frame(case, sport, src="10.0.0.9")))
        if i + 1 in (101, 110, 120):
            alerts.append(alert(SID_RATE, sport, src="10.0.0.9"))
    for i in range(200):
        t = T0 + 40 + i * 0.25 + (61 if i >= 100 else 0)
        packets.append((t, http_frame(case, 21000 + i, src="10.0.0.10")))
    packets.sort(key=lambda p: p[0])
    emit("http_rate", "Per-IP request rate over a 60 s window (uses packet time)",
         packets, alerts)


def gen_rate_table_full():
    """1024 distinct sources fill the rate table, then a new source sends
    101 requests. Before the B8 fix the new source was never tracked."""
    packets, alerts = [], []
    case = HttpCase("rate", "/", set(), user_agent=None)
    for i in range(1024):
        src = f"10.1.{i // 256}.{i % 256}"
        packets.append((T0 + i * 0.01, http_frame(case, 10000, src=src)))
    for i in range(101):
        sport = 11000 + i
        packets.append((T0 + 20 + i * 0.1, http_frame(case, sport, src="10.2.0.1")))
    alerts.append(alert(SID_RATE, 11100, src="10.2.0.1"))
    emit("b8_rate_table_full", "New source is still rate-limited after the IP table fills",
         packets, alerts, bugs=["B8"])


def gen_tls():
    packets, alerts = [], []

    def add(sport, record, sids=()):
        packets.append((T0 + len(packets), ether(ipv4_tcp(CLIENT, SERVER, sport, 443, record))))
        alerts.extend(alert(s, sport, 443) for s in sids)

    add(44300, client_hello([sni_ext(b"malicious.com"), SUPPORTED_VERSIONS]), {7001})
    add(44301, client_hello([SUPPORTED_VERSIONS, sni_ext(b"www.phishing.net")]), {7002})
    add(44302, client_hello([sni_ext(b"MALICIOUS.COM")]), {7001})            # nocase
    add(44303, client_hello([sni_ext(b"example.com"), SUPPORTED_VERSIONS]))   # clean
    add(44304, client_hello([SUPPORTED_VERSIONS]))                            # no SNI
    # Malformed: extensions length claims more than is present.
    add(44305, client_hello([sni_ext(b"malicious.com")], ext_len_delta=400))
    # Truncated: record cut in the middle of the cipher suites.
    add(44306, client_hello([sni_ext(b"malicious.com")])[:80])
    # SNI with a control byte is rejected rather than logged.
    add(44307, client_hello([sni_ext(b"malicious.com\x07")]))
    # Extension length larger than the extensions block.
    bad = bytearray(client_hello([sni_ext(b"malicious.com")]))
    bad[-len(sni_ext(b"malicious.com")) + 2:-len(sni_ext(b"malicious.com")) + 4] = b"\xff\xff"
    add(44308, bytes(bad))
    # Not TLS at all on 443: recognized as HTTP by its content (Phase 3).
    add(44309, b"GET /<script> HTTP/1.1\r\n\r\n", {1001})
    # Large ClientHello (e.g. post-quantum key share) split across TCP
    # segments: the first segment still carries the SNI.
    big = client_hello([sni_ext(b"malicious.com"), tls_ext(51, bytes(1500))])
    add(44310, big[:200], {7001})
    # Same, but the SNI sits in the second segment: needs reassembly.
    late = client_hello([SUPPORTED_VERSIONS, tls_ext(51, bytes(1400)),
                         sni_ext(b"phishing.net")])
    c = Conn(44311, sport=443)
    for frame in c.handshake() + [c.data(0, late[:1000]), c.data(1000, late[1000:])]:
        packets.append((T0 + len(packets), frame))
    alerts.append(alert(7002, 44311, 443))

    emit("tls_sni", "SNI extraction: matches, nocase, and malformed ClientHellos",
         packets, alerts)


def gen_linktypes():
    case = HttpCase("Script tag", "/?x=<script>", {1001})
    for name, lt, wrap in (("linktype_null", LINKTYPE_NULL, null_loop),
                           ("linktype_sll", LINKTYPE_LINUX_SLL, linux_sll),
                           ("linktype_raw", LINKTYPE_RAW, lambda x: x)):
        emit(name, f"Decoding with link type {lt}",
             [(T0, http_frame(case, 45000, wrap=wrap))],
             [alert(1001, 45000)], linktype=lt)


def gen_b1_stale_buffer():
    """A big malicious packet followed by a short clean one. libpcap reuses
    its read buffer, so code that runs strstr() past payload_len finds the
    old <script> and blames the second packet."""
    big = HttpCase("big", "/a", {1012},       # <script> in a header: sid 1012
                   extra_headers="X-Pad: " + "A" * 300 + "<script>\r\n")
    small = b"GET /b HTTP/1.1\r\n\r\n"
    packets = [
        (T0, http_frame(big, 46000)),
        (T0 + 1, ether(ipv4_tcp("10.0.0.3", SERVER, 46001, 80, small))),
    ]
    emit("b1_stale_buffer", "Matching must stop at payload_len (no NUL terminator)",
         packets, [alert(1012, 46000)], bugs=["B1"])


def gen_b2_truncated():
    """Captured with snaplen 128: only bytes inside the capture may match."""
    hidden = HttpCase("hidden", "/x", set(),
                      extra_headers="X-Pad: " + "A" * 200 + "<script>\r\n")
    visible = HttpCase("visible", "/?x=<script>", {1001},
                       extra_headers="X-Pad: " + "B" * 300 + "\r\n")
    packets = [(T0, http_frame(hidden, 47000)), (T0 + 1, http_frame(visible, 47001))]
    emit("b2_truncated", "Payload length comes from caplen, not the on-wire length",
         packets, [alert(1001, 47001)], snaplen=128, bugs=["B2"])


def gen_b6_non_ipv4():
    """IPv6 must be decoded as IPv6 (Phase 1.5 skipped it, Phase 2 decodes
    it), never parsed as IPv4; a frame whose ethertype says IPv4 but whose
    version nibble is 6 is rejected."""
    req = b"GET /?x=<script> HTTP/1.1\r\n\r\n"
    packets = [
        (T0, ether(ipv6_tcp(48000, 80, req), ethertype=0x86DD)),
        (T0 + 1, ether(ipv4_tcp(CLIENT, SERVER, 48001, 80, req))),
        # Ethertype says IPv4 but the version nibble is 6.
        (T0 + 2, ether(b"\x60" + ipv4_tcp(CLIENT, SERVER, 48002, 80, req)[1:])),
    ]
    alerts = [alert(1001, 48000, src="fd00::2"), alert(1001, 48001)]
    emit("b6_non_ipv4", "IPv6 and IPv4 are each decoded by their own rules",
         packets, alerts, bugs=["B6", "B13"])


def gen_b10_json():
    """Quotes, backslashes, control and high bytes must yield valid JSON."""
    payload = (b'GET /?x="<script>"\\\x01\x1f\x7f\xff\xfe HTTP/1.1\r\n'
               b'User-Agent: sqlmap "quoted" \\ ua\x02\r\n\r\n')
    packets = [(T0, ether(ipv4_tcp(CLIENT, SERVER, 49000, 80, payload)))]
    alerts = [alert(1001, 49000), alert(5001, 49000), alert(900004, 49000)]
    emit("b10_json_escape", "Alert log stays valid JSON for hostile payloads",
         packets, alerts, bugs=["B10"])


# --------------------------------------------------------------------------
# Phase 2: flows, reassembly, IPv6, VLAN
# --------------------------------------------------------------------------

REQ_TAIL = b" HTTP/1.1\r\nHost: t\r\nUser-Agent: TestClient/1.0\r\n\r\n"


class Timeline:
    """Collects frames with increasing timestamps."""

    def __init__(self, start=T0):
        self.t, self.packets = start, []

    def add(self, *frames, step=0.01):
        for f in frames:
            self.packets.append((self.t, f))
            self.t += step


def gen_stream_split():
    """Acceptance test: <script> split into 3 segments, sent out of order."""
    tl, alerts = Timeline(), []
    parts = [b"GET /?x=<scr", b"ip", b"t>" + REQ_TAIL]
    offs = [0, len(parts[0]), len(parts[0]) + len(parts[1])]

    for cport, order in ((51000, (2, 0, 1)), (51001, (1, 2, 0)), (51002, (0, 1, 2))):
        c = Conn(cport)
        tl.add(*c.handshake())
        tl.add(*[c.data(offs[i], parts[i]) for i in order])
        alerts.append(alert(1001, cport))

    # Mid-stream pickup (no handshake seen), split in order.
    c = Conn(51003)
    tl.add(*[c.data(offs[i], parts[i]) for i in (0, 1, 2)])
    alerts.append(alert(1001, 51003))

    # A 1100-character URL split over two segments: only the whole request
    # line is long enough to be an anomaly.
    req = b"GET /?q=" + b"A" * 1092 + REQ_TAIL
    c = Conn(51004)
    tl.add(*c.handshake(), c.data(0, req[:600]), c.data(600, req[600:]))
    alerts.append(alert(900002, 51004))

    # The scanner name split across segments inside the User-Agent header.
    req = b"GET / HTTP/1.1\r\nHost: t\r\nUser-Agent: sqlmap/1.7\r\n\r\n"
    cut = req.index(b"map")
    c = Conn(51005)
    tl.add(*c.handshake(), c.data(cut, req[cut:]), c.data(0, req[:cut]))
    alerts += [alert(5001, 51005), alert(900004, 51005)]

    emit("stream_split_ooo", "Signatures split across out-of-order TCP segments",
         tl.packets, alerts)


def gen_stream_retransmit():
    tl, alerts = Timeline(), []

    # Identical retransmission: one alert, not two.
    req = b"GET /?x=<script>" + REQ_TAIL
    c = Conn(52000)
    tl.add(*c.handshake(), c.data(0, req), c.data(0, req))
    alerts.append(alert(1001, 52000))

    # Retransmission that rewrites bytes the receiver already accepted. A
    # real TCP stack keeps the original, so no XSS alert, but the
    # inconsistency itself is reported.
    req = b"GET /?x=AAAAAAAA" + REQ_TAIL
    c = Conn(52001)
    tl.add(*c.handshake(), c.data(0, req), c.data(8, b"<script>"))
    alerts.append(alert(900005, 52001))

    # Keep-alive: two requests on one connection. Rules on parsed requests
    # fire once per request (Phase 4, as in Suricata), anomalies too.
    r1 = b"GET /?x=<script>" + REQ_TAIL
    r2 = b"GET /?y=<script> HTTP/1.1\r\nHost: t\r\nUser-Agent: X\r\n\r\n"
    c = Conn(52002)
    tl.add(*c.handshake(), c.data(0, r1), c.data(len(r1), r2))
    alerts += [alert(1001, 52002), alert(1001, 52002), alert(900003, 52002)]

    # POST with a body: the next request starts after Content-Length bytes.
    body = b"GET /looks-like-a-request-but-is-body"
    r1 = b"POST /f HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body) + body
    r2 = b"GET / HTTP/1.1\r\nUser-Agent: Nikto\r\n\r\n"
    c = Conn(52003)
    tl.add(*c.handshake(), c.data(0, r1), c.data(len(r1), r2))
    alerts += [alert(5002, 52003), alert(900004, 52003)]

    emit("stream_retransmit", "Retransmissions, rewritten data and keep-alive requests",
         tl.packets, alerts)


def gen_stream_overlap():
    """Queued segments overlap with different bytes: which ones the target
    keeps depends on its OS, so the policy is configurable."""
    head = b"GET /?x="
    seg_a = b"<scrXXXX" + REQ_TAIL       # offset 8
    seg_b = b"ipt>"                      # offset 12, overlaps "XXXX"
    for policy, sids in (("first", [900005]), ("last", [900005, 1001])):
        tl = Timeline()
        c = Conn(53000)
        tl.add(*c.handshake(), c.data(8, seg_a), c.data(12, seg_b), c.data(0, head))
        emit(f"stream_overlap_{policy}",
             f"Overlapping queued segments with --overlap {policy}",
             tl.packets, [alert(s, 53000) for s in sids], args=["--overlap", policy])


def gen_stream_gap():
    """A lost segment: data on both sides is inspected separately, so the
    pieces around the hole never combine into a false match. The request
    cut by the hole is inspected as far as it goes, and the HTTP parser
    resyncs on the next request line after the hole."""
    tl = Timeline()
    c = Conn(54000)
    seg0 = b"GET /?x=<scr"                              # [0, 12)
    lost = b"XYZ"                                       # [12, 15) never sent
    seg2 = (b"ipt> HTTP/1.1\r\nX: y\r\n\r\n"             # [15, ...)
            b"GET /?f=../x HTTP/1.1\r\nHost: t\r\n\r\n")
    tl.add(*c.handshake(), c.data(0, seg0), c.data(len(seg0) + len(lost), seg2))
    emit("stream_gap", "No match across a hole; data after it is still inspected",
         tl.packets, [alert(4001, 54000)])


def gen_vlan():
    tl, alerts = Timeline(), []
    req = b"GET /?x=<script>" + REQ_TAIL

    variants = [
        (55000, None, False),                                  # untagged
        (55001, [(0x8100, 100)], False),                       # 802.1Q
        (55002, [(0x88A8, 200), (0x8100, 100)], False),        # QinQ
        (55003, [(0x8100, 100)], True),                        # 802.1Q + IPv6
    ]
    for cport, tags, v6 in variants:
        wrap = (lambda l3, et, t=tags: vlan_ether(l3, et, t)) if tags else None
        kw = {"client": "fd00::2", "server": "fd00::1"} if v6 else {}
        c = Conn(cport, v6=v6, wrap=wrap, **kw)
        tl.add(*c.handshake(), c.data(0, req))
        alerts.append(alert(1001, cport, src="fd00::2" if v6 else CLIENT))
    emit("vlan", "802.1Q and QinQ tagged traffic (default BPF filter included)",
         tl.packets, alerts)


def gen_ipv6():
    tl, alerts = Timeline(), []
    parts = [b"GET /?x=<scr", b"ipt>" + REQ_TAIL]
    c = Conn(56000, client="2001:db8::2", server="2001:db8::1", v6=True)
    tl.add(*c.handshake(), c.data(len(parts[0]), parts[1]), c.data(0, parts[0]))
    alerts.append(alert(1001, 56000, src="2001:db8::2"))

    # Extension headers before TCP: hop-by-hop (0) -> destination options (60).
    req = b"GET /?x=<script>" + REQ_TAIL
    tcp = tcp_hdr(56001, 80, 1, 1, PSH | ACK, req)
    ext = bytes([60, 0, 1, 4, 0, 0, 0, 0]) + bytes([6, 0, 1, 4, 0, 0, 0, 0])
    tl.add(ether(ipv6_packet("2001:db8::2", "2001:db8::1", 0, tcp, ext), 0x86DD))
    alerts.append(alert(1001, 56001, src="2001:db8::2"))

    # A non-first fragment carries no TCP header: skipped, never parsed.
    frag = bytes([6, 0]) + struct.pack("!HI", (8 << 3), 0x1234)
    tl.add(ether(ipv6_packet("2001:db8::2", "2001:db8::1", 44, req, frag), 0x86DD))

    # libpcap's "tcp port 80" cannot see past IPv6 extension headers, so
    # this pcap is read without a capture filter.
    emit("ipv6", "IPv6 with reassembly, extension headers and fragments",
         tl.packets, alerts, args=["-f", ""])


# --------------------------------------------------------------------------
# Phase 3: request bodies, DNS, TLS fingerprints
# --------------------------------------------------------------------------

def gen_http_bodies():
    tl, alerts = Timeline(), []

    def post(cport, raw, sids, parts=None):
        c = Conn(cport)
        tl.add(*c.handshake())
        cuts = parts or [len(raw)]
        off = 0
        for cut in cuts:
            tl.add(c.data(off, raw[off:cut]))
            off = cut
        alerts.extend(alert(s, cport) for s in sids)

    body = b"comment=<script>alert(1)</script>"
    post(58000, b"POST /c HTTP/1.1\r\nHost: t\r\nUser-Agent: TestClient/1.0\r\n"
         b"Content-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(body) + body, {1011})

    # Chunked, the keywords split across chunks and across TCP segments,
    # with a chunk extension and a trailer.
    req = (b"POST /q HTTP/1.1\r\nHost: t\r\nUser-Agent: TestClient/1.0\r\n"
           b"Transfer-Encoding: chunked\r\n\r\n"
           b"6;ext=1\r\nq=1 UN\r\n9\r\nION SELEC\r\n3\r\nT 1\r\n0\r\nX-Trailer: y\r\n\r\n")
    post(58001, req, {2012}, parts=[len(req) - 40, len(req)])

    # Form-encoded body: decoded before matching.
    body = b"user=%27+OR+1%3D1--&pass=x"
    post(58002, b"POST /login HTTP/1.1\r\nHost: t\r\nUser-Agent: TestClient/1.0\r\n"
         b"Content-Type: application/x-www-form-urlencoded\r\n"
         b"Content-Length: %d\r\n\r\n" % len(body) + body, {2011})

    # Keep-alive: a body that looks like a request is not parsed as one
    # (no 4001); the real next request's body is inspected (3011).
    b1 = b"GET /?f=../x HTTP/1.1\r\n\r\n"
    b2 = b"cmd=/bin/sh"
    req = (b"POST /a HTTP/1.1\r\nHost: t\r\nUser-Agent: TestClient/1.0\r\n"
           b"Content-Length: %d\r\n\r\n" % len(b1) + b1 +
           b"POST /b HTTP/1.1\r\nHost: t\r\nUser-Agent: TestClient/1.0\r\n"
           b"Content-Length: %d\r\n\r\n" % len(b2) + b2)
    post(58003, req, {3011})

    # A clean body must stay clean.
    body = b"name=alice&msg=hello+world"
    post(58004, b"POST /f HTTP/1.1\r\nHost: t\r\nUser-Agent: TestClient/1.0\r\n"
         b"Content-Type: application/x-www-form-urlencoded\r\n"
         b"Content-Length: %d\r\n\r\n" % len(body) + body, set())

    emit("http_bodies", "Request bodies: Content-Length, chunked, form decoding, keep-alive",
         tl.packets, alerts)


def udp_frame(sport, dport, payload, src=CLIENT, dst=SERVER):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ether(ipv4(src, dst, udp, proto=17))


def dns_query(name, qid=0x4242, qtype=1, response=False):
    msg = struct.pack("!HHHHHH", qid, 0x8180 if response else 0x0100, 1, 0, 0, 0)
    for label in name.split(".") if name else []:
        msg += bytes([len(label)]) + label.encode()
    return msg + b"\0" + struct.pack("!HH", qtype, 1)


def gen_dns():
    tl, alerts = Timeline(), []

    def udp(sport, msg, sids=(), dport=53):
        tl.add(udp_frame(sport, dport, msg))
        alerts.extend(alert(s, sport, dport) for s in sids)

    udp(59000, dns_query("www.malicious.com"), {8001})
    udp(59001, dns_query("MALICIOUS.COM"), {8001})               # nocase
    udp(59002, dns_query("notmalicious.com"))                    # dotprefix
    udp(59003, dns_query("login.phishing.net", qtype=28), {8002})
    udp(59004, dns_query("abcdefghij234567.onion"), {8003})
    udp(59005, dns_query("home.duckdns.org"), {8004})
    udp(59006, dns_query("www.malicious.com", response=True))   # responses skipped
    udp(59007, dns_query("www.malicious.com"), dport=5353)       # not DNS port 53
    # Tunneling-like names: one 60-byte label, and a 120-byte name.
    udp(59008, dns_query("a" * 60 + ".t.example.com", qtype=16), {900020})
    udp(59009, dns_query(".".join(["b" * 30] * 4) + ".example.com"), {900020})
    # Compression pointer in the question (unusual but legal): second
    # question "x" + pointer to the first name.
    msg = bytearray(dns_query("phishing.net"))
    msg[4:6] = b"\x00\x02"
    msg += b"\x01x\xc0\x0c" + struct.pack("!HH", 1, 1)
    udp(59010, bytes(msg), {8002})
    # Malformed: label runs past the end.
    udp(59011, dns_query("www.malicious.com")[:20])

    # DNS over TCP: two length-prefixed queries, the second one split
    # across segments.
    m1 = dns_query("example.com")
    m2 = dns_query("c2.duckdns.org", qid=7)
    stream = struct.pack("!H", len(m1)) + m1 + struct.pack("!H", len(m2)) + m2
    c = Conn(59100, sport=53)
    cut = len(m1) + 2 + 7
    tl.add(*c.handshake(), c.data(0, stream[:cut]), c.data(cut, stream[cut:]))
    alerts.append(alert(8004, 59100, 53))

    emit("dns", "DNS queries over UDP and TCP: domain rules and long-name anomaly",
         tl.packets, alerts)


GREASE = 0x0A0A


def hello_full(sni=None, alpn=(), ech=False, records=1):
    """A ClientHello with GREASE values, groups, point formats, ALPN and
    signature algorithms. Returns (record bytes, ja3 string, ja4)."""
    import hashlib

    suites = [GREASE, 0x1301, 0x1302, 0xC02F]
    exts = [(0x1A1A, b"")]
    if sni:
        exts.append((0, sni_ext(sni)[4:]))
    groups = [0x2A2A, 29, 23]
    exts.append((10, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", g) for g in groups)))
    exts.append((11, b"\x01\x00"))
    if alpn:
        lst = b"".join(bytes([len(p)]) + p for p in alpn)
        exts.append((16, struct.pack("!H", len(lst)) + lst))
    sigs = [0x0403, 0x0804, 0x0401]
    exts.append((13, struct.pack("!H", 2 * len(sigs)) + b"".join(struct.pack("!H", s) for s in sigs)))
    exts.append((43, b"\x06" + struct.pack("!HHH", 0x3A3A, 0x0304, 0x0303)))
    if ech:
        exts.append((0xFE0D, b"\x00\x00\x01\x00\x01\x42\x00\x00\x00\x00"))

    body = b"\x03\x03" + bytes(range(32)) + b"\x00"
    body += struct.pack("!H", 2 * len(suites)) + b"".join(struct.pack("!H", s) for s in suites)
    body += b"\x01\x00"
    blob = b"".join(struct.pack("!HH", t, len(d)) + d for t, d in exts)
    body += struct.pack("!H", len(blob)) + blob
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    # Split the handshake message over `records` TLS records.
    step = -(-len(hs) // records)
    rec = b"".join(b"\x16\x03\x01" + struct.pack("!H", len(hs[i:i + step])) + hs[i:i + step]
                   for i in range(0, len(hs), step))

    # Independent JA3 / JA4 computation, to cross-check src/app/tls/tls.c.
    def grease(v):
        return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)
    cs = [s for s in suites if not grease(s)]
    et = [t for t, _ in exts if not grease(t)]
    ja3 = "771,%s,%s,%s,0" % ("-".join(map(str, cs)), "-".join(map(str, et)),
                              "-".join(str(g) for g in groups if not grease(g)))
    first = alpn[0].decode() if alpn else ""
    a = "t13%s%02d%02d%s" % ("d" if sni else "i", len(cs), len(et),
                             first[0] + first[-1] if first else "00")
    b = hashlib.sha256(",".join("%04x" % s for s in sorted(cs)).encode()).hexdigest()[:12]
    c_in = ",".join("%04x" % t for t in sorted(et) if t not in (0, 16))
    c_in += "_" + ",".join("%04x" % s for s in sigs)
    c = hashlib.sha256(c_in.encode()).hexdigest()[:12]
    return rec, ja3, f"{a}_{b}_{c}"


def gen_tls_fingerprint():
    """JA3/JA4/ALPN rules from a rules file written next to the pcap. The
    expected fingerprints are computed here in Python, independently of
    the C code, so a wrong fingerprint shows up as a missing alert."""
    import hashlib

    tl, alerts = Timeline(), []
    rec, ja3, ja4 = hello_full(b"api.example.org", (b"h2", b"http/1.1"))
    ja3_md5 = hashlib.md5(ja3.encode()).hexdigest()
    rules_path = os.path.join(OUT_DIR, "tls_fingerprint.rules")
    with open(rules_path, "w") as f:
        f.write("# Written by tests/regression/gen_pcaps.py for tls_fingerprint.pcap\n")
        f.write(f"# JA3 string: {ja3}\n")
        for sid, buf, content, extra in (
                (7101, "ja3.hash", ja3_md5, ""),
                (7102, "ja4.hash", ja4, ""),
                (7103, "tls.alpn", "h2,http/1.1", " startswith; endswith;"),
                (7104, "ja3.string", ja3.split(",")[0] + "," + ja3.split(",")[1] + ",", " startswith;"),
        ):
            f.write(f'alert tls any any -> any any (msg:"test {buf}"; {buf}; content:"{content}";'
                    f'{extra} sid:{sid}; priority:3;)\n')

    def conn(cport, record, sids, segments=1):
        c = Conn(cport, sport=443)
        tl.add(*c.handshake())
        step = -(-len(record) // segments)
        for off in range(0, len(record), step):
            tl.add(c.data(off, record[off:off + step]))
        alerts.extend(alert(s, cport, 443) for s in sids)

    every = {7101, 7102, 7103, 7104}
    conn(44400, rec, every)
    # Same hello over 3 TLS records and 4 TCP segments.
    rec3, ja3_3, ja4_3 = hello_full(b"api.example.org", (b"h2", b"http/1.1"), records=3)
    assert (ja3_3, ja4_3) == (ja3, ja4)
    conn(44401, rec3, every, segments=4)
    # A different SNI changes neither JA3 nor JA4 (SNI is excluded from JA4_c).
    conn(44402, hello_full(b"other.example.net", (b"h2", b"http/1.1"))[0], every)
    # No SNI: JA4 says 'i' and drops one extension; JA3 loses extension 0.
    conn(44403, hello_full(None, (b"h2", b"http/1.1"))[0], {7103, 7104})
    # ECH (extension 0xfe0d): different fingerprints, informational alert.
    conn(44404, hello_full(b"cover.example.org", (b"h2",), ech=True)[0], {7104, 900030})

    emit("tls_fingerprint", "JA3, JA4, ALPN and ECH from reassembled ClientHellos",
         tl.packets, alerts, args=["-R", "tests/pcaps/tls_fingerprint.rules"])


def gen_flow_eviction():
    """With room for only 2 flows, a third evicts the least recently used.
    The evicted flow is inspected before it is dropped."""
    tl, alerts = Timeline(), []
    a, b, c = Conn(57000), Conn(57001), Conn(57002)
    long_req = b"GET /?q=" + b"B" * 1100     # request line never completes
    tl.add(*a.handshake(), a.data(0, long_req))
    tl.add(*b.handshake(), b.data(0, b"GET /?x=<script>" + REQ_TAIL))
    tl.add(*c.handshake())                   # evicts A: its partial request
    alerts.append(alert(900002, 57000))      # is checked on the way out
    alerts.append(alert(1001, 57001))
    emit("flow_eviction", "Bounded flow table: LRU eviction flushes the evicted flow",
         tl.packets, alerts, args=["--max-flows", "2"])


def gen_evasion():
    """tests/evasion/evasion_cases.py: one connection per case. Documented
    misses expect only their extra sids; report.py turns the same run into
    per-category detection rates."""
    tl, alerts = Timeline(), []
    for i, case in enumerate(EVASION_CASES):
        c = Conn(EVASION_PORT + i)
        tl.add(*c.handshake(), c.data(0, case.request()))
        alerts += [alert(sid, EVASION_PORT + i) for sid in sorted(case.expected())]
    emit("evasion", "Evasion test set: URL encoding, mixed case, path obfuscation, HPP",
         tl.packets, alerts)


RULES_V2 = r"""# Written by tests/regression/gen_pcaps.py for rules_v2.pcap
# Rule language v2 end to end; run with --var HOME_NET=[10.0.0.0/24].
var TRUSTED_SCANNERS [10.0.9.0/24]
alert http any any -> $HOME_NET any (msg:"v2 pcre: UNION SELECT with any whitespace"; \
    http.uri; content:"union"; nocase; pcre:"/union\s+select/i"; sid:100;)
alert http any any -> !$HOME_NET any (msg:"v2 variables: never matches, HOME_NET is the server"; \
    http.uri; content:"union"; nocase; sid:106;)
alert http any any -> any any (msg:"v2 relative: quote within 10 bytes of id="; \
    http.uri; content:"id="; content:"'"; distance:0; within:10; sid:101;)
alert http any any -> any any (msg:"v2 detection_filter: login brute force"; \
    http.method; content:"POST"; startswith; endswith; http.uri; content:"/login"; \
    http.request_body; content:"password="; \
    detection_filter:track by_src, count 3, seconds 60; sid:102;)
alert http any any -> any any (msg:"v2 threshold: noisy scanner, once a minute"; \
    http.user_agent; content:"scanbot"; threshold:type limit, track by_src, count 1, seconds 60; sid:103;)
pass http $TRUSTED_SCANNERS any -> any any (msg:"v2 pass: our own scanner"; \
    http.user_agent; content:"scanbot"; sid:104;)
alert tcp any any -> any 21 (msg:"v2 raw: FTP SITE EXEC"; flow:established; \
    content:"SITE"; startswith; content:"EXEC"; nocase; distance:1; within:5; sid:105;)
"""


def gen_rules_v2():
    """Rule language v2 end to end: pcre, relative content, variables,
    detection_filter, threshold, pass, raw TCP rules with flow."""
    tl, alerts = Timeline(), []
    rules_path = os.path.join(OUT_DIR, "rules_v2.rules")
    with open(rules_path, "w") as f:
        f.write(RULES_V2)

    def conn(cport, payload, sids=(), client=CLIENT, sport=80):
        c = Conn(cport, client=client, sport=sport)
        tl.add(*c.handshake())
        tl.add(c.data(0, payload))
        alerts.extend(alert(s, cport, sport, client) for s in sids)

    def get(target, ua="TestClient/1.0"):
        return f"GET {target} HTTP/1.1\r\nHost: t\r\nUser-Agent: {ua}\r\n\r\n".encode()

    def login(n):
        body = f"user=admin&password=guess{n}".encode()
        return (b"POST /login HTTP/1.1\r\nHost: t\r\nUser-Agent: TestClient/1.0\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body) + body)

    conn(61000, get("/?q=1%09UNION%0aSELECT%202"), {100})
    conn(61001, get("/item?id=5'--"), {101})
    conn(61002, get("/item?id=5&comment=hello+it's"))          # quote too far away

    # Brute force: the 4th and 5th login from one source alert; another
    # source with two attempts stays below the count.
    for i in range(5):
        conn(61010 + i, login(i), {102} if i >= 3 else (), client="10.0.0.7")
    for i in range(2):
        conn(61015 + i, login(i), client="10.0.0.8")

    # limit: three scanner requests, one alert.
    for i in range(3):
        conn(61020 + i, get("/", ua="scanbot/2.0"), {103} if i == 0 else (), client="10.0.0.20")

    # pass: the trusted scanner's flow is not inspected any more, even for
    # a later request that would match sid 100.
    c = Conn(61030, client="10.0.9.5")
    first, second = get("/", ua="scanbot/2.0"), get("/?q=union select 1", ua="scanbot/2.0")
    tl.add(*c.handshake())
    tl.add(c.data(0, first), c.data(len(first), second))

    # Raw TCP rule on port 21: EXEC must follow SITE within the window.
    conn(61040, b"SITE EXEC /bin/id\r\n", {105}, sport=21)
    conn(61041, b"SITE CHMOD 777 EXEC\r\n", sport=21)

    emit("rules_v2", "Rule language v2: pcre, distance/within, variables, threshold, "
         "detection_filter, pass, raw TCP with flow", tl.packets, alerts,
         args=["-R", "tests/pcaps/rules_v2.rules", "--var", "HOME_NET=[10.0.0.0/24]", "-f", ""])


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f"Writing pcaps to {OUT_DIR}")
    gen_http_sets()
    gen_rate()
    gen_rate_table_full()
    gen_tls()
    gen_linktypes()
    gen_b1_stale_buffer()
    gen_b2_truncated()
    gen_b6_non_ipv4()
    gen_b10_json()
    gen_stream_split()
    gen_stream_retransmit()
    gen_stream_overlap()
    gen_stream_gap()
    gen_vlan()
    gen_ipv6()
    gen_flow_eviction()
    gen_http_bodies()
    gen_dns()
    gen_tls_fingerprint()
    gen_evasion()
    gen_rules_v2()


if __name__ == "__main__":
    main()
