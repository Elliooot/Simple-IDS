#!/usr/bin/env python3
"""
pcap regression runner.

For every tests/pcaps/NAME.pcap, runs
    SimpleIDS -r NAME.pcap -l <tmp log> -q
and checks that
  * the process exits with status 0 (sanitizer reports make it fail),
  * every log line is valid JSON with the expected fields (B10),
  * the multiset of (sid, src_ip, src_port, dest_port) equals the
    "alerts" list in NAME.expected.json.

Usage: python3 tests/regression/run.py [--bin ./SimpleIDS] [NAME ...]
Run from the repo root (rules are loaded from rules/*.rules).
"""

import argparse
import glob
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PCAP_DIR = os.path.join(os.path.dirname(HERE), "pcaps")
REPO = os.path.dirname(os.path.dirname(HERE))

REQUIRED_FIELDS = ("timestamp", "event_type", "src_ip", "src_port",
                   "dest_ip", "dest_port", "proto", "alert", "payload")


def key(a):
    return (a["sid"], a["src_ip"], a["src_port"], a["dest_port"])


def run_one(binary, pcap, expected):
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "alerts.json")
        proc = subprocess.run([binary, "-r", pcap, "-l", log, "-q"] + expected.get("args", []),
                              cwd=REPO, capture_output=True, text=True)
        errors = []
        if proc.returncode != 0:
            errors.append(f"exit status {proc.returncode}\n{proc.stderr.strip()}")
            return errors

        got = []
        with open(log, "rb") as f:
            for n, raw in enumerate(f, 1):
                try:
                    text = raw.decode("ascii")
                    ev = json.loads(text)
                except (UnicodeDecodeError, json.JSONDecodeError) as e:
                    errors.append(f"log line {n} is not valid ASCII JSON: {e}: {raw[:120]!r}")
                    continue
                missing = [k for k in REQUIRED_FIELDS if k not in ev]
                if missing:
                    errors.append(f"log line {n} lacks fields {missing}")
                    continue
                got.append({"sid": ev["alert"]["sid"], "src_ip": ev["src_ip"],
                            "src_port": ev["src_port"], "dest_port": ev["dest_port"]})

        want = sorted(key(a) for a in expected["alerts"])
        have = sorted(key(a) for a in got)
        if want != have:
            missing = [k for k in want if k not in have or want.count(k) > have.count(k)]
            extra = [k for k in have if k not in want or have.count(k) > want.count(k)]
            fmt = "(sid, src_ip, src_port, dest_port)"
            if missing:
                errors.append(f"missing alerts {fmt}: {sorted(set(missing))}")
            if extra:
                errors.append(f"unexpected alerts {fmt}: {sorted(set(extra))}")
        return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="./SimpleIDS")
    ap.add_argument("names", nargs="*", help="pcap names to run (default: all)")
    args = ap.parse_args()

    binary = os.path.abspath(os.path.join(REPO, args.bin)) \
        if not os.path.isabs(args.bin) else args.bin
    if not os.access(binary, os.X_OK):
        print(f"binary not found: {binary} (run make first)")
        return 2

    pcaps = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))
    if args.names:
        pcaps = [p for p in pcaps if os.path.basename(p)[:-5] in args.names]
    if not pcaps:
        print("no pcaps found (run make pcaps)")
        return 2

    failed = 0
    for pcap in pcaps:
        name = os.path.basename(pcap)[:-5]
        with open(pcap[:-5] + ".expected.json") as f:
            expected = json.load(f)
        errors = run_one(binary, pcap, expected)
        bugs = f" [{', '.join(expected.get('bugs', []))}]" if expected.get("bugs") else ""
        if errors:
            failed += 1
            print(f"FAIL {name}{bugs}")
            for e in errors:
                print("     " + e.replace("\n", "\n     "))
        else:
            print(f"ok   {name}{bugs} ({len(expected['alerts'])} alerts)")

    print(f"\n{len(pcaps) - failed}/{len(pcaps)} pcap regression tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
