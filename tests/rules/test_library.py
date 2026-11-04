#!/usr/bin/env python3
"""
Rule library test: every rule in rules/crs/ fires on its sample request,
and a corpus of ordinary traffic raises no alert at all.

The samples (tests/rules/samples.py) are written into one pcap, one TCP
connection (or DNS query) per request, and run through SimpleIDS with
the default rules (rules/ and rules/crs/). Checks:
  * every library sid has a sample, and every sample sid exists;
  * each sample raises its sid;
  * the clean corpus (and tests/cases.py CLEAN_CASES) raises nothing.

Usage: python3 tests/rules/test_library.py [--bin ./SimpleIDS] [--verbose]
       --verbose also lists the other sids each sample raised.
Exit status 0 when every check passes.
"""

import argparse
import glob
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from collections import defaultdict
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "tests", "regression"))

from cases import CLEAN_CASES  # noqa: E402
from gen_pcaps import (SERVER, T0, client_hello, dns_query, ether,  # noqa: E402
                       ipv4_tcp, sni_ext, udp_frame)
from samples import BROWSER_UA, CLEAN, FORM, SAMPLES  # noqa: E402

SAMPLE_PORT = 20000
CLEAN_PORT = 40000


def http_request(s):
    target = s.uri or "/app"
    if s.q is not None:
        target += ("&" if "?" in target else "?") + "q=" + quote(s.q, safe="")
    body = None
    ctype = s.ctype
    if s.form is not None:
        body = ("x=" + quote(s.form, safe="")).encode()
        ctype = ctype or FORM
    elif s.body is not None:
        body = s.body if isinstance(s.body, bytes) else s.body.encode("utf-8")
    method = s.method or ("POST" if body is not None else "GET")

    lines = [f"{method} {target} HTTP/1.1", "Host: shop.example"]
    if s.ua is not None:
        lines.append(f"User-Agent: {s.ua}")
    if s.cookie is not None:
        lines.append(f"Cookie: {s.cookie}")
    if s.headers:
        lines.extend(s.headers.split("\r\n"))
    # Framing headers given by the sample win; never add a Content-Length
    # next to a Transfer-Encoding (that is itself request smuggling).
    has_cl = re.search(r"^(?:content-length|transfer-encoding)\s*:", s.headers, re.I | re.M)
    if body is not None:
        if ctype:
            lines.append(f"Content-Type: {ctype}")
        if not has_cl:
            lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
    return head + (body or b"")


def client_ip(n):
    """Each sample gets its own client address, so per-source logic (the
    request-rate anomaly, by_src thresholds) sees one client per sample."""
    return f"10.{100 + n // 65536}.{n // 256 % 256}.{n % 256}"


def frames(s, sport, src):
    if s.dns is not None:
        return [udp_frame(sport, 53, dns_query(s.dns), src=src)]
    if s.sni is not None:
        hello = client_hello([sni_ext(s.sni.encode())])
        return [ether(ipv4_tcp(src, SERVER, sport, 443, hello))]
    return [ether(ipv4_tcp(src, SERVER, sport, 80, http_request(s)))]


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(packets):
            f.write(struct.pack("<IIII", T0 + i // 1000, (i % 1000) * 1000, len(frame), len(frame)))
            f.write(frame)


def library_sids():
    sids = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "rules", "crs", "*.rules"))):
        for n, line in enumerate(open(path, encoding="utf-8"), 1):
            m = re.search(r"\bsid:(\d+);", line)
            if m and not line.lstrip().startswith("#"):
                sids[int(m.group(1))] = f"{os.path.relpath(path, ROOT)}:{n}"
    return sids


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bin", default=os.path.join(ROOT, "SimpleIDS"))
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    binary = os.path.abspath(args.bin)
    errors = []

    lib = library_sids()
    sampled = [s.sid for s in SAMPLES]
    dups = sorted({x for x in sampled if sampled.count(x) > 1})
    if dups:
        errors.append(f"sids with more than one sample: {dups}")
    for sid in sorted(set(lib) - set(sampled)):
        errors.append(f"sid {sid} ({lib[sid]}) has no sample in tests/rules/samples.py")
    for sid in sorted(set(sampled) - set(lib)):
        errors.append(f"sample for sid {sid}, which is not in rules/crs/")

    packets, owner = [], {}
    port = SAMPLE_PORT
    for i, s in enumerate(SAMPLES):
        for _ in range(s.repeat):
            owner[port] = ("sample", i)
            packets += frames(s, port, client_ip(i))
            port += 1
    clean = list(CLEAN)
    clean += [type(CLEAN[0])(0, uri=c.path, method=c.method,
                             ua=c.user_agent if c.user_agent is not None else BROWSER_UA,
                             headers=c.extra_headers.strip("\r\n"))
              for c in CLEAN_CASES]
    port = CLEAN_PORT
    for i, s in enumerate(clean):
        owner[port] = ("clean", i)
        packets += frames(s, port, client_ip(len(SAMPLES) + i))
        port += 1

    fired = defaultdict(set)
    with tempfile.TemporaryDirectory(prefix="simpleids-lib-") as tmp:
        pcap = os.path.join(tmp, "library.pcap")
        log = os.path.join(tmp, "alerts.json")
        write_pcap(pcap, packets)
        proc = subprocess.run([binary, "-r", pcap, "-l", log, "-q"], cwd=ROOT,
                              capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            print(proc.stderr)
            print(f"SimpleIDS exited with status {proc.returncode}")
            return 1
        with open(log) as f:
            for line in f:
                ev = json.loads(line)
                if "alert" in ev and ev["src_port"] in owner:
                    fired[owner[ev["src_port"]]].add(ev["alert"]["sid"])

    hit = 0
    for i, s in enumerate(SAMPLES):
        got = fired[("sample", i)]
        if s.sid in got:
            hit += 1
            if args.verbose and got - {s.sid}:
                print(f"  {s.sid}: also {sorted(got - {s.sid})}")
        else:
            errors.append(f"sid {s.sid} did not fire on its sample (got {sorted(got)})")
    noisy = 0
    for i, s in enumerate(clean):
        got = fired[("clean", i)]
        if got:
            noisy += 1
            what = s.dns or s.sni or s.uri or ""
            if s.q is not None:
                what += f" q={s.q!r}"
            errors.append(f"false positive on clean request {what!r}: {sorted(got)}")

    print(f"library: {len(lib)} rules, {hit}/{len(SAMPLES)} samples detected, "
          f"{len(clean) - noisy}/{len(clean)} clean requests quiet")
    for e in errors:
        print(f"  FAIL {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
