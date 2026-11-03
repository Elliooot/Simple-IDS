#!/usr/bin/env python3
"""
Evasion detection-rate report (Phase 3 acceptance).

Runs SimpleIDS on tests/pcaps/evasion.pcap and, per category, counts the
cases whose attack sids all fired. Fails when
  * the overall rate is below 95%,
  * a case is missed without a `known_miss` reason, or
  * a case with a `known_miss` reason is detected (the note is stale).

Usage: python3 tests/evasion/report.py [--bin ./SimpleIDS] [--markdown FILE]
Run from the repo root. --markdown also writes the table and the list of
documented misses (docs/EVASION.md is produced this way).
"""

import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PCAP = os.path.join(REPO, "tests", "pcaps", "evasion.pcap")
sys.path.insert(0, HERE)

from evasion_cases import BASE_PORT, CASES, CATEGORIES  # noqa: E402

THRESHOLD = 0.95


def run(binary):
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "alerts.json")
        proc = subprocess.run([binary, "-r", PCAP, "-l", log, "-q"],
                              cwd=REPO, capture_output=True, text=True)
        if proc.returncode != 0:
            sys.exit(f"SimpleIDS exited with {proc.returncode}\n{proc.stderr}")
        fired = collections.defaultdict(set)
        with open(log) as f:
            for line in f:
                ev = json.loads(line)
                fired[ev["src_port"] - BASE_PORT].add(ev["alert"]["sid"])
        return fired


def markdown(rows, total, detected, misses):
    out = ["# 規避測試集結果", "",
           "由 `python3 tests/evasion/report.py --markdown docs/EVASION.md` 產生，"
           "案例定義在 `tests/evasion/evasion_cases.py`，封包在 `tests/pcaps/evasion.pcap`。",
           "",
           "一個案例的所有攻擊 sid 都觸發才算偵測到；正規化異常（雙重編碼等）"
           "由回歸測試另外驗證，不影響偵測率。`make test` 會在偵測率低於 95%、"
           "出現沒有記錄原因的漏報、或已記錄的漏報其實已被偵測到時失敗。",
           "",
           "| 類別 | 案例數 | 偵測 | 偵測率 |", "|---|---:|---:|---:|"]
    for name, n, d in rows:
        out.append(f"| {name} | {n} | {d} | {100 * d / n:.1f}% |")
    out.append(f"| **合計** | **{total}** | **{detected}** | **{100 * detected / total:.1f}%** |")
    out += ["", "## 已知漏報", ""]
    for c in misses:
        out += [f"### {CATEGORIES[c.category]}：{c.desc}", "",
                f"- 請求：`{c.method} {c.target}`" +
                (f"，body `{c.body.decode('latin-1')}`" if c.body else ""),
                f"- 應觸發：{', '.join(str(s) for s in sorted(c.attack))}",
                f"- 原因：{c.known_miss}", ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="./SimpleIDS")
    ap.add_argument("--markdown", metavar="FILE")
    args = ap.parse_args()
    binary = args.bin if os.path.isabs(args.bin) else os.path.join(REPO, args.bin)

    fired = run(binary)
    stats = collections.OrderedDict((k, [0, 0]) for k in CATEGORIES)
    errors, misses = [], []
    for i, case in enumerate(CASES):
        hit = case.attack <= fired.get(i, set())
        stats[case.category][0] += 1
        stats[case.category][1] += hit
        label = f"[{case.category}] {case.desc} ({case.method} {case.target})"
        if not hit and not case.known_miss:
            errors.append(f"undocumented miss: {label}: want {sorted(case.attack)}, "
                          f"got {sorted(fired.get(i, set()))}")
        elif hit and case.known_miss:
            errors.append(f"documented miss is now detected, update the note: {label}")
        if not hit:
            misses.append(case)

    rows = [(CATEGORIES[k], n, d) for k, (n, d) in stats.items()]
    total = sum(n for _, n, _ in rows)
    detected = sum(d for _, _, d in rows)
    for name, n, d in rows:
        print(f"  {name:<26} {d:>3}/{n:<3} {100 * d / n:6.1f}%")
    rate = detected / total
    print(f"  {'total':<26} {detected:>3}/{total:<3} {100 * rate:6.1f}%  (required >= "
          f"{100 * THRESHOLD:.0f}%)")
    for c in misses:
        print(f"  known miss: [{c.category}] {c.desc}")

    if rate < THRESHOLD:
        errors.append(f"detection rate {100 * rate:.1f}% is below {100 * THRESHOLD:.0f}%")
    for e in errors:
        print("FAIL " + e)

    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write(markdown(rows, total, detected, misses) + "\n")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
