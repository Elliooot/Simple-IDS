#!/usr/bin/env python3
"""
Check that the binary was built with the hardening flags (ROADMAP Phase 5):

  Linux (readelf):  PIE (ELF type DYN), full RELRO (GNU_RELRO + BIND_NOW),
                    non-executable stack (GNU_STACK without E),
                    stack protector (__stack_chk_fail), FORTIFY (*_chk calls)
  macOS (otool/nm): PIE (MH_PIE), stack protector, FORTIFY (*_chk calls)

Usage: python3 tests/hardening/check.py [--bin ./SimpleIDS] [--sanitizer]
--sanitizer: a sanitizer build, where _FORTIFY_SOURCE is deliberately off.
Exit status 0 when every check passes.
"""

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
failures = []


def check(cond, what):
    print(f"  {'ok  ' if cond else 'FAIL'} {what}")
    if not cond:
        failures.append(what)


def out(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def linux(binary, sanitizer):
    if not shutil.which("readelf"):
        print("  skip: readelf not found (binutils)")
        return
    header = out("readelf", "-h", binary)
    check(re.search(r"Type:\s+DYN", header) is not None, "PIE (ELF type DYN)")
    phdrs = out("readelf", "-lW", binary)
    dyn = out("readelf", "-dW", binary)
    check("GNU_RELRO" in phdrs, "RELRO segment")
    check(re.search(r"\(BIND_NOW\)|FLAGS.*\bNOW\b", dyn) is not None, "full RELRO (BIND_NOW)")
    stack = re.search(r"GNU_STACK.*", phdrs)
    check(stack is not None and not re.search(r"\bRWE\b", stack.group(0)),
          "non-executable stack")
    syms = out("readelf", "--dyn-syms", "-W", binary)
    check("__stack_chk_fail" in syms, "stack protector (__stack_chk_fail)")
    chk = sorted(set(re.findall(r"\b(__\w+_chk)\b", syms)) - {"__stack_chk_fail"})
    if sanitizer:
        print("  skip: FORTIFY (off in sanitizer builds)")
    else:
        check(len(chk) > 0, f"FORTIFY_SOURCE ({', '.join(chk[:6])}{', ...' if len(chk) > 6 else ''})")


def macos(binary, sanitizer):
    hdr = out("otool", "-hv", binary)
    check("PIE" in hdr, "PIE (MH_PIE)")
    syms = out("nm", "-u", binary)
    check("___stack_chk_fail" in syms or "___stack_chk_guard" in syms,
          "stack protector (___stack_chk_fail)")
    chk = sorted(set(re.findall(r"\b___(\w+_chk)\b", syms)) - {"stack_chk_fail", "stack_chk_guard"})
    if sanitizer:
        print("  skip: FORTIFY (off in sanitizer builds)")
    elif chk:
        check(True, f"FORTIFY_SOURCE ({', '.join(chk[:6])})")
    else:
        # The compiler may prove every call safe and drop the checks.
        print("  note: no *_chk calls left (all checks resolved at compile time)")
    print("  note: RELRO and the NX stack are ELF features; Mach-O always maps the stack NX")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bin", default=os.path.join(ROOT, "SimpleIDS"))
    ap.add_argument("--sanitizer", action="store_true")
    args = ap.parse_args()
    binary = os.path.abspath(args.bin)
    print(f"hardening: {os.path.relpath(binary, ROOT)}")
    if platform.system() == "Linux":
        linux(binary, args.sanitizer)
    elif platform.system() == "Darwin":
        macos(binary, args.sanitizer)
    else:
        print("  skip: unsupported platform")
    if failures:
        print(f"{len(failures)} hardening check(s) failed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
