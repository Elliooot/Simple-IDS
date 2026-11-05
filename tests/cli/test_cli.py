#!/usr/bin/env python3
"""
Command-line behaviour that the pcap regression tests cannot cover:

  * --test-rules: exit status, error and warning reports, --var
  * SIGHUP reload: packets are fed through a FIFO (-r FIFO) so the test
    decides exactly which packets arrive before and after each reload.
    A good file replaces the rules in use; a file with any error leaves
    the old rules in place.

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


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bin", default=os.path.join(ROOT, "SimpleIDS"))
    args = ap.parse_args()
    binary = os.path.abspath(args.bin)
    with tempfile.TemporaryDirectory(prefix="simpleids-cli-") as tmp:
        test_rules_checker(binary, tmp)
        test_reload(binary, tmp)
    if failures:
        print(f"\n{len(failures)} CLI check(s) failed")
        return 1
    print("\nAll CLI checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
