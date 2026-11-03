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


def write_expected(name, description, alerts, bugs=()):
    alerts = sorted(alerts, key=lambda a: (a["src_ip"], a["src_port"], a["sid"]))
    doc = {"description": description, "bugs": list(bugs), "alerts": alerts}
    with open(os.path.join(OUT_DIR, name + ".expected.json"), "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def alert(sid, sport, dport=80, src=CLIENT):
    return {"sid": sid, "src_ip": src, "src_port": sport, "dest_port": dport}


def emit(name, description, packets, alerts, linktype=LINKTYPE_ETHERNET,
         snaplen=65535, bugs=()):
    write_pcap(name, linktype, packets, snaplen)
    write_expected(name, description, alerts, bugs)
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
    """An IPv6 packet must be skipped (IPv6 decoding is Phase 2), not parsed
    as IPv4; the IPv4 packet after it must still be inspected."""
    req = b"GET /?x=<script> HTTP/1.1\r\n\r\n"
    packets = [
        (T0, ether(ipv6_tcp(48000, 80, req), ethertype=0x86DD)),
        (T0 + 1, ether(ipv4_tcp(CLIENT, SERVER, 48001, 80, req))),
        # Ethertype says IPv4 but the version nibble is 6.
        (T0 + 2, ether(b"\x60" + ipv4_tcp(CLIENT, SERVER, 48002, 80, req)[1:])),
    ]
    emit("b6_non_ipv4", "Only real IPv4 is decoded; others are counted and skipped",
         packets, [alert(1001, 48001)], bugs=["B6", "B13"])


def gen_b10_json():
    """Quotes, backslashes, control and high bytes must yield valid JSON."""
    payload = (b'GET /?x="<script>"\\\x01\x1f\x7f\xff\xfe HTTP/1.1\r\n'
               b'User-Agent: sqlmap "quoted" \\ ua\x02\r\n\r\n')
    packets = [(T0, ether(ipv4_tcp(CLIENT, SERVER, 49000, 80, payload)))]
    alerts = [alert(1001, 49000), alert(5001, 49000), alert(900004, 49000)]
    emit("b10_json_escape", "Alert log stays valid JSON for hostile payloads",
         packets, alerts, bugs=["B10"])


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


if __name__ == "__main__":
    main()
