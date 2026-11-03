#!/usr/bin/env python3
"""
Live smoke test: send real HTTP requests over loopback and verify, from
SimpleIDS's JSON log, that each one raised exactly the expected alerts.

1. Start any HTTP server on the port (it only has to accept connections):
       python3 -m http.server 8000 --bind 127.0.0.1
2. Start SimpleIDS on the loopback interface with a log file:
       sudo ./SimpleIDS -i lo -l /tmp/ids-live.json        # macOS: -i lo0
   SimpleIDS only inspects ports 80 / 8080 / 443, so with port 8000 use
   a server on 8080 instead, or run the server on 80 as root.
3. Run:
       python3 tests/live/test_live.py --port 8080 --log /tmp/ids-live.json

The test matches log entries to requests by client source port, so other
traffic in the log does not matter. Exit status 0 = all cases passed.
"""

import argparse
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cases import ALL_CASES, SID_RATE, HttpCase  # noqa: E402

RED, GREEN, YELLOW, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[0m"


def send(host, port, payload):
    """Send one request; return the client source port, or None."""
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            src_port = s.getsockname()[1]
            s.sendall(payload)
            try:
                while s.recv(4096):
                    pass
            except (socket.timeout, ConnectionResetError):
                pass
            return src_port
    except OSError as e:
        print(f"{YELLOW}  connection to {host}:{port} failed: {e}{RESET}")
        return None


def read_alerts(path, offset):
    """Return {src_port: [sid, ...]} for log lines after offset."""
    by_port = {}
    with open(path, "rb") as f:
        f.seek(offset)
        for n, raw in enumerate(f, 1):
            try:
                ev = json.loads(raw.decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise SystemExit(f"{RED}log line {n} is not valid JSON: {e}{RESET}")
            by_port.setdefault(ev["src_port"], []).append(ev["alert"]["sid"])
    return by_port


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=80,
                    help="HTTP server port SimpleIDS watches (80 or 8080)")
    ap.add_argument("--log", required=True, help="SimpleIDS JSON log (-l)")
    ap.add_argument("--rate", action="store_true",
                    help="also send 120 rapid requests to trigger the rate anomaly")
    ap.add_argument("--wait", type=float, default=1.5,
                    help="seconds to wait for SimpleIDS to write the log")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        print(f"log file {args.log} does not exist: is SimpleIDS running with -l?")
        return 2
    offset = os.path.getsize(args.log)

    if send(args.host, args.port, HttpCase("preflight", "/", set()).request()) is None:
        print("Start an HTTP server first (see the top of this file).")
        return 2

    sent = []
    for case in ALL_CASES:
        if case.port != 80:      # 8080-only cases are covered by the pcap tests
            continue
        sport = send(args.host, args.port, case.request(args.host))
        if sport is not None:
            sent.append((case, sport))
        time.sleep(0.02)

    rate_ports = []
    if args.rate:
        req = HttpCase("rate", "/", set(), user_agent=None).request(args.host)
        for _ in range(120):
            p = send(args.host, args.port, req)
            if p:
                rate_ports.append(p)

    time.sleep(args.wait)
    alerts = read_alerts(args.log, offset)

    failed = 0
    for case, sport in sent:
        got = set(alerts.get(sport, [])) - {SID_RATE}
        if got == case.sids:
            print(f"  {GREEN}ok{RESET}   {case.desc:<36} {sorted(got) or 'clean'}")
        else:
            failed += 1
            print(f"  {RED}FAIL{RESET} {case.desc:<36} expected {sorted(case.sids)}, "
                  f"got {sorted(got)}")

    if args.rate:
        rate_hits = sum(1 for p in rate_ports if SID_RATE in alerts.get(p, []))
        if rate_hits >= 1:
            print(f"  {GREEN}ok{RESET}   rate anomaly fired {rate_hits} time(s)")
        else:
            failed += 1
            print(f"  {RED}FAIL{RESET} rate anomaly did not fire")

    total = len(sent) + (1 if args.rate else 0)
    print(f"\n{total - failed}/{total} live checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
