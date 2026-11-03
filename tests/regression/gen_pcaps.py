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

from cases import (ANOMALY_CASES, CLEAN_CASES, SIGNATURE_CASES,  # noqa: E402
                   SID_RATE, HttpCase)

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
    # Not TLS at all on 443.
    add(44309, b"GET /<script> HTTP/1.1\r\n\r\n")
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
    big = HttpCase("big", "/a", {1001},
                   extra_headers="X-Pad: " + "A" * 300 + "<script>\r\n")
    small = b"GET /b HTTP/1.1\r\n\r\n"
    packets = [
        (T0, http_frame(big, 46000)),
        (T0 + 1, ether(ipv4_tcp("10.0.0.3", SERVER, 46001, 80, small))),
    ]
    emit("b1_stale_buffer", "Matching must stop at payload_len (no NUL terminator)",
         packets, [alert(1001, 46000)], bugs=["B1"])


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

    # Keep-alive: two requests on one connection. The signature fires once
    # per flow; anomalies are checked for every request.
    r1 = b"GET /?x=<script>" + REQ_TAIL
    r2 = b"GET /?y=<script> HTTP/1.1\r\nHost: t\r\nUser-Agent: X\r\n\r\n"
    c = Conn(52002)
    tl.add(*c.handshake(), c.data(0, r1), c.data(len(r1), r2))
    alerts += [alert(1001, 52002), alert(900003, 52002)]

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
    pieces around the hole never combine into a false match."""
    tl = Timeline()
    c = Conn(54000)
    seg0 = b"GET /?x=<scr"                              # [0, 12)
    lost = b"XYZ"                                       # [12, 15) never sent
    seg2 = b"ipt> HTTP/1.1\r\nX: ../\r\n\r\n"            # [15, ...)
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


if __name__ == "__main__":
    main()
