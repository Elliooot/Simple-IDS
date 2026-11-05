#!/usr/bin/env python3
"""
Build the seed corpora for the fuzz targets from what the repository
already has: the regression pcaps (frames, and the HTTP/TLS/DNS payloads
in them), the rule-library samples, the rule files and the sample config.

Usage: python3 tests/fuzz/make_seeds.py OUTDIR
Writes OUTDIR/<target>/<sha1> files; the output is deterministic.
"""

import glob
import hashlib
import os
import struct
import sys
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tests", "rules"))
sys.path.insert(0, os.path.join(ROOT, "tests", "regression"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

MAX_PER_TARGET = 400
ENGINE_MAX = 60000            # bytes per engine seed

# fuzz_engine's link type selector (byte 0) for each pcap link type.
ENGINE_LINK = {1: 0, 101: 1, 12: 1, 113: 2, 0: 3}


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = struct.unpack("<I", data[:4])[0]
    end = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off, frames = 24, []
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(end + "IIII", data[off:off + 16])
        frames.append(data[off + 16:off + 16 + incl])
        off += 16 + incl
    return linktype, frames


def l3_of(linktype, frame):
    """(ethertype-ish version, l3 bytes) or None."""
    if linktype == 1:
        et, off = struct.unpack(">H", frame[12:14])[0], 14
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:
            et, off = struct.unpack(">H", frame[off + 2:off + 4])[0], off + 4
        return frame[off:] if et in (0x0800, 0x86DD) else None
    if linktype in (101, 12):
        return frame
    if linktype == 113:
        return frame[16:]
    if linktype == 0:
        return frame[4:]
    return None


def l4_of(l3):
    """(proto, sport, dport, payload, flow key) or None."""
    if not l3:
        return None
    if l3[0] >> 4 == 4:
        ihl = (l3[0] & 15) * 4
        proto, src, dst, l4 = l3[9], l3[12:16], l3[16:20], l3[ihl:]
    elif l3[0] >> 4 == 6 and len(l3) >= 40:
        proto, src, dst, l4 = l3[6], l3[8:24], l3[24:40], l3[40:]
    else:
        return None
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack(">HH", l4[:4])
        doff = (l4[12] >> 4) * 4
        return 6, sport, dport, l4[doff:], (src, dst, sport, dport)
    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack(">HH", l4[:4])
        return 17, sport, dport, l4[8:], (src, dst, sport, dport)
    return None


class Corpus:
    def __init__(self):
        self.items = OrderedDict()

    def add(self, target, data):
        if not data:
            return
        d = self.items.setdefault(target, OrderedDict())
        if len(d) < MAX_PER_TARGET:
            d.setdefault(hashlib.sha1(data).hexdigest(), data)

    def write(self, outdir):
        for target, d in self.items.items():
            path = os.path.join(outdir, target)
            os.makedirs(path, exist_ok=True)
            for name, data in d.items():
                with open(os.path.join(path, name), "wb") as f:
                    f.write(data)
            print(f"  {target:<8} {len(d):4} seeds")


def from_pcaps(c):
    for path in sorted(glob.glob(os.path.join(ROOT, "tests", "pcaps", "*.pcap"))):
        linktype, frames = read_pcap(path)
        streams = OrderedDict()
        engine = bytearray([ENGINE_LINK.get(linktype, 0)])
        for fr in frames:
            c.add("decode", fr)
            if len(engine) + 2 + len(fr) <= ENGINE_MAX:
                engine += struct.pack(">H", len(fr)) + fr
            l4 = l4_of(l3_of(linktype, fr))
            if not l4 or not l4[3]:
                continue
            proto, sport, dport, payload, key = l4
            if proto == 17:
                if 53 in (sport, dport):
                    c.add("dns", payload)
                continue
            streams.setdefault(key, bytearray()).extend(payload)
        c.add("engine", bytes(engine))
        for (src, dst, sport, dport), data in streams.items():
            data = bytes(data)
            if data[:1] == b"\x16":
                c.add("tls", data)
            elif dport == 53:
                c.add("dns", data[2:])
            elif dport in (80, 8080) or data[:4].isalpha():
                c.add("http", data)


def from_samples(c):
    from samples import CLEAN, SAMPLES          # noqa: E402
    from test_library import http_request       # noqa: E402
    from gen_pcaps import client_hello, dns_query, sni_ext   # noqa: E402
    for s in list(SAMPLES) + list(CLEAN):
        if s.dns is not None:
            c.add("dns", dns_query(s.dns))
        elif s.sni is not None:
            c.add("tls", client_hello([sni_ext(s.sni.encode())]))
        else:
            c.add("http", http_request(s))


def from_rules(c):
    files = sorted(glob.glob(os.path.join(ROOT, "rules", "*.rules")) +
                   glob.glob(os.path.join(ROOT, "rules", "crs", "*.rules")) +
                   glob.glob(os.path.join(ROOT, "tests", "pcaps", "*.rules")))
    for path in files:
        with open(path, "rb") as f:
            text = f.read()
        c.add("rules", text[:20000])
        for line in text.splitlines():
            if line.strip() and not line.startswith(b"#"):
                c.add("rules", line + b"\n")


def from_configs(c):
    for path in sorted(glob.glob(os.path.join(ROOT, "etc", "*.conf")) +
                       glob.glob(os.path.join(ROOT, "tests", "cli", "*.conf"))):
        with open(path, "rb") as f:
            c.add("config", f.read())
    c.add("config", b"[engine]\nmax-flows = 1000\n[vars]\nHOME_NET = [10.0.0.0/8]\n")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    c = Corpus()
    from_pcaps(c)
    from_samples(c)
    from_rules(c)
    from_configs(c)
    c.write(sys.argv[1])


if __name__ == "__main__":
    main()
