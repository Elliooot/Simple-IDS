#!/usr/bin/env python3
"""
Command-line behaviour that the pcap regression tests cannot cover:

  * --test-rules: exit status, error and warning reports, --var
  * SIGHUP reload: packets are fed through a FIFO (-r FIFO) so the test
    decides exactly which packets arrive before and after each reload.
    A good file replaces the rules in use; a file with any error leaves
    the old rules in place.
  * The config file (-c): values, precedence of command-line options,
    file:line errors; log rotation; stats events (also on SIGUSR1);
    --measure-latency; the sandbox notice.

Usage: python3 tests/cli/test_cli.py [--bin ./SimpleIDS]
Exit status 0 when every check passes.
"""

import argparse
import json
import os
import queue
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tests", "regression"))
from gen_pcaps import CLIENT, SERVER, T0, ether, ipv4_tcp  # noqa: E402

TIMEOUT = 20
failures = []


def check(cond, what):
    print(f"  {'ok  ' if cond else 'FAIL'} {what}")
    if not cond:
        failures.append(what)


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


# --------------------------------------------------------------------------
# --test-rules
# --------------------------------------------------------------------------

def run_test_rules(binary, files, extra=()):
    args = [binary, "--test-rules"] + [a for f in files for a in ("-R", f)] + list(extra)
    p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=TIMEOUT)
    return p.returncode, p.stdout, p.stderr


def test_rules_checker(binary, tmp):
    print("--test-rules")
    rc, out, err = run_test_rules(binary, [])
    check(rc == 0, "the shipped rules load without errors (exit 0)")
    check(" 0 errors" in out, "summary line reports 0 errors")

    good = os.path.join(tmp, "good.rules")
    write(good, 'alert tcp any any -> $HOME_NET 21 (msg:"x"; content:"ab"; sid:1;)\n'
                'alert http any any -> any any (msg:"y"; http.uri; pcre:"/a+b/"; sid:2;)\n')
    rc, out, err = run_test_rules(binary, [good])
    check(rc == 0, "warnings alone do not fail the check")
    check("sid 1: warning: fast pattern is only 2 bytes" in out, "short fast pattern warning")
    check("sid 2: warning: no content to prefilter on" in out, "pcre-only rule warning")
    check("2 rules, 0 errors, 3 warnings" in out, "summary counts rules and warnings")

    bad = os.path.join(tmp, "bad.rules")
    write(bad, 'alert tcp any any -> any 21 (msg:"x"; content:"user"; sid:1;)\n'
               'alert tcp any any -> any 21 (msg:"x"; content:"pass"; sid:1;)\n'
               'alert foo any any -> any 21 (content:"x"; sid:3;)\n'
               'alert tcp any any -> $NOPE 21 (content:"x"; sid:4;)\n')
    rc, out, err = run_test_rules(binary, [bad])
    check(rc == 1, "errors make the check fail (exit 1)")
    check(f"{bad}:2: duplicate sid 1" in err, "duplicate sid reported with file:line")
    check(f"{bad}:3:" in err and "foo" in err, "unknown protocol reported")
    check(f"{bad}:4:" in err and "NOPE" in err, "undefined variable reported")
    check("1 rules, 3 errors" in out, "summary counts errors")

    rc, out, err = run_test_rules(binary, [bad], ["--var", "NOPE=10.0.0.0/8"])
    check("NOPE" not in err and "2 errors" in out, "--var defines a missing variable")

    rc, out, err = run_test_rules(binary, [os.path.join(tmp, "missing.rules")])
    check(rc == 1 and "Cannot open rules file" in err, "a missing file fails the check")


# --------------------------------------------------------------------------
# SIGHUP reload
# --------------------------------------------------------------------------

PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def record(n, uri, sport):
    frame = ether(ipv4_tcp(CLIENT, SERVER, sport, 80,
                           f"GET {uri} HTTP/1.1\r\nHost: x\r\n\r\n".encode()))
    return struct.pack("<IIII", T0 + n, 0, len(frame), len(frame)) + frame


def reader(stream, q):
    for line in stream:
        q.put(line.rstrip("\n"))
    q.put(None)


def wait_for(q, pred, what):
    """Collect lines until pred(line) is true; return the lines seen."""
    seen = []
    try:
        while True:
            line = q.get(timeout=TIMEOUT)
            if line is None:
                break
            seen.append(line)
            if pred(line):
                return seen
    except queue.Empty:
        pass
    check(False, f"{what} (timed out; got {seen})")
    return None


def alert_sid(line):
    try:
        return json.loads(line)["alert"]["sid"]
    except (ValueError, KeyError, TypeError):
        return None


def test_reload(binary, tmp):
    print("SIGHUP reload")
    rules = os.path.join(tmp, "reload.rules")
    fifo = os.path.join(tmp, "packets.fifo")
    os.mkfifo(fifo)
    write(rules, 'alert http any any -> any any (msg:"one"; http.uri; content:"/one"; sid:1;)\n')

    proc = subprocess.Popen([binary, "-r", fifo, "-R", rules, "-l", "-", "-q"], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out_q, err_q = queue.Queue(), queue.Queue()
    threading.Thread(target=reader, args=(proc.stdout, out_q), daemon=True).start()
    threading.Thread(target=reader, args=(proc.stderr, err_q), daemon=True).start()
    try:
        fd = os.open(fifo, os.O_WRONLY)
        n = 0

        def send(uri):
            nonlocal n
            n += 1
            os.write(fd, record(n, uri, 40000 + n))

        os.write(fd, PCAP_HEADER)
        send("/one")
        check(wait_for(out_q, lambda l: alert_sid(l) == 1, "alert from the first rules")
              is not None, "first rule set alerts (sid 1)")

        # 1. A good file replaces the rules. The reload happens before the
        #    next packet is processed, so both requests see the new set.
        write(rules, 'alert http any any -> any any (msg:"two"; http.uri; content:"/two"; sid:2;)\n'
                     'alert http any any -> any any (msg:"one"; http.uri; content:"/one"; sid:11;)\n')
        proc.send_signal(signal.SIGHUP)
        send("/one")
        send("/two")
        check(wait_for(err_q, lambda l: l.startswith("Reloaded 2 rules"), "reload message")
              is not None, "stderr reports 'Reloaded 2 rules'")
        got = wait_for(out_q, lambda l: alert_sid(l) == 2, "alert from the reloaded rules")
        sids = sorted(alert_sid(l) for l in (got or []) if alert_sid(l))
        check(sids == [2, 11], f"new rules in use: sids {sids} == [2, 11]")

        # 2. A file with one bad line is rejected as a whole.
        write(rules, 'alert http any any -> any any (msg:"three"; http.uri; content:"/three"; sid:3;)\n'
                     'alert http any any -> any any (msg:"broken"; http.uri; content:"x"; bogus; sid:4;)\n')
        proc.send_signal(signal.SIGHUP)
        send("/three")
        send("/two")
        check(wait_for(err_q, lambda l: l.startswith("Rule reload failed"), "failure message")
              is not None, "stderr reports 'Rule reload failed'")
        got = wait_for(out_q, lambda l: alert_sid(l) == 2, "alert from the kept rules")
        sids = sorted(alert_sid(l) for l in (got or []) if alert_sid(l))
        check(sids == [2], f"old rules kept: sids {sids} == [2]")

        # 3. A missing file is rejected too.
        os.unlink(rules)
        proc.send_signal(signal.SIGHUP)
        send("/two")
        check(wait_for(err_q, lambda l: l.startswith("Rule reload failed"), "failure message")
              is not None, "a missing rule file keeps the old rules")
        check(wait_for(out_q, lambda l: alert_sid(l) == 2, "alert after failed reload")
              is not None, "old rules still alert")

        os.close(fd)
        rc = proc.wait(timeout=TIMEOUT)
        check(rc == 0, f"exits cleanly at end of input (status {rc})")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# --------------------------------------------------------------------------
# Config file, rotation, stats
# --------------------------------------------------------------------------

def attack_pcap(path, n, step=1):
    """n HTTP requests with an XSS in the URI, `step` seconds apart."""
    with open(path, "wb") as f:
        f.write(PCAP_HEADER)
        for i in range(n):
            frame = ether(ipv4_tcp(CLIENT, SERVER, 30000 + i, 80,
                                   f"GET /?q=<script>{i}</script> HTTP/1.1\r\nHost: x\r\n\r\n"
                                   .encode()))
            f.write(struct.pack("<IIII", T0 + i * step, 0, len(frame), len(frame)) + frame)


def run(binary, args):
    return subprocess.run([binary] + args, cwd=ROOT, capture_output=True, text=True,
                          timeout=TIMEOUT)


def events(path, kind):
    out = []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                ev = json.loads(line)
                if ev.get("event_type") == kind:
                    out.append(ev)
    return out


def test_config(binary, tmp):
    print("config file")
    pcap = os.path.join(tmp, "attacks.pcap")
    attack_pcap(pcap, 6)
    rules = os.path.join(tmp, "home.rules")
    write(rules, 'alert http any any -> $WEB any (msg:"xss"; http.uri; content:"<script>"; '
                 'sid:5001;)\n')
    log = os.path.join(tmp, "cfg.log")
    conf = os.path.join(tmp, "good.conf")
    write(conf, f"""# test config
[capture]
file = {pcap}
filter = ""
[rules]
path = {rules}
[vars]
WEB = [{SERVER}]
[output]
log = {log}
quiet = yes
[engine]
max-flows = 1K
""")
    p = run(binary, ["-c", conf])
    check(p.returncode == 0, "a valid config file runs")
    if p.returncode:
        print(p.stderr)
    sids = [e["alert"]["sid"] for e in events(log, "alert")]
    check(sids.count(5001) == 6, "rules path, variables and log come from the config")
    check("(1024 flows)" in p.stdout, "engine.max-flows = 1K applied")

    log2 = os.path.join(tmp, "cli.log")
    p = run(binary, ["-c", conf, "-l", log2, "--var", "WEB=[10.9.9.9]"])
    check(not events(log2, "alert"), "command-line -l and --var override the config")
    p = run(binary, ["-c", conf, "-l", log2, "-R", "rules"])
    check(any(e["alert"]["sid"] != 5001 for e in events(log2, "alert")) and
          not any(e["alert"]["sid"] == 5001 for e in events(log2, "alert")),
          "-R replaces the config's rule paths")

    bad = os.path.join(tmp, "bad.conf")
    write(bad, "[engine]\nmax-flows = lots\n[output]\nqiet = yes\n[sekurity]\n")
    p = run(binary, ["-c", bad, "-r", pcap])
    check(p.returncode == 1, "a config file with errors refuses to start (exit 1)")
    check(f"{bad}:2: engine.max-flows" in p.stderr and f"{bad}:4: unknown setting 'output.qiet'"
          in p.stderr and f"{bad}:5: unknown section [sekurity]" in p.stderr and
          "3 errors" in p.stderr, "every config error is reported with file:line")
    p = run(binary, ["-c", os.path.join(tmp, "missing.conf"), "-r", pcap])
    check(p.returncode == 1 and "cannot open" in p.stderr, "a missing config file fails")
    p = run(binary, ["--max-flows", "0", "-r", pcap])
    check(p.returncode == 1 and "engine.max-flows" in p.stderr,
          "command-line values go through the same validation")
    p = run(binary, ["-c", "etc/simpleids.conf", "--test-rules"])
    check(p.returncode == 0, "the shipped etc/simpleids.conf is valid")


def test_rotation_and_stats(binary, tmp):
    print("log rotation, stats")
    pcap = os.path.join(tmp, "many.pcap")
    attack_pcap(pcap, 40, step=1)
    d = os.path.join(tmp, "rot")
    os.makedirs(d)
    log = os.path.join(d, "ids.log")
    p = run(binary, ["-r", pcap, "-R", "rules", "-q", "-l", log, "--log-max-size", "4K",
                     "--log-max-files", "2", "--stats-interval", "10", "--measure-latency"])
    check(p.returncode == 0, "run with rotation, stats and latency")
    names = sorted(os.listdir(d))
    check(names == ["ids.log", "ids.log.1", "ids.log.2"], f"rotated files kept: {names}")
    check(all(os.path.getsize(os.path.join(d, n)) < 4096 + 2048 for n in names),
          "every file stays near the size limit")
    stats = []
    for n in names:
        stats += events(os.path.join(d, n), "stats")
    up = sorted(e["stats"]["uptime"] for e in stats)
    check(len(stats) >= 2 and up[-1] == 39.0, f"stats every 10 s of packet time and at exit {up}")
    last = max(stats, key=lambda e: e["stats"]["uptime"])["stats"]
    check(last["capture"]["packets"] == 40 and last["app"]["http_requests"] == 40,
          "stats count packets and requests")
    check(last["log"]["rotations"] >= 2, "stats report log rotations")
    check(last["latency_ns"]["packets"] == 40 and last["latency_ns"]["p50"] > 0,
          "latency percentiles in the stats event")
    check(last["memory"]["rss_peak_bytes"] > 0, "peak RSS in the stats event")
    check("Latency per packet" in p.stdout and "Peak memory" in p.stdout,
          "latency and peak memory in the summary")
    check("Sandbox:" in p.stderr, "the sandbox state is reported")

    # SIGUSR1 writes a stats event even without --stats-interval.
    fifo = os.path.join(tmp, "usr1.fifo")
    os.mkfifo(fifo)
    log = os.path.join(tmp, "usr1.log")
    proc = subprocess.Popen([binary, "-r", fifo, "-R", "rules", "-q", "-l", log], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    q = queue.Queue()
    threading.Thread(target=reader, args=(proc.stderr, q), daemon=True).start()
    with open(fifo, "wb", buffering=0) as w:
        w.write(PCAP_HEADER + record(0, "/a", 31000))
        wait_for(q, lambda l: l.startswith("Sandbox:"), "startup")
        time.sleep(0.5)              # the first packet is read
        proc.send_signal(signal.SIGUSR1)
        time.sleep(0.5)
        w.write(record(1, "/b", 31001))
    proc.wait(timeout=TIMEOUT)
    st = events(log, "stats")
    check(len(st) == 1 and st[0]["stats"]["capture"]["packets"] >= 1,
          "SIGUSR1 writes one stats event")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bin", default=os.path.join(ROOT, "SimpleIDS"))
    args = ap.parse_args()
    binary = os.path.abspath(args.bin)
    with tempfile.TemporaryDirectory(prefix="simpleids-cli-") as tmp:
        test_rules_checker(binary, tmp)
        test_reload(binary, tmp)
        test_config(binary, tmp)
        test_rotation_and_stats(binary, tmp)
    if failures:
        print(f"\n{len(failures)} CLI check(s) failed")
        return 1
    print("\nAll CLI checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
