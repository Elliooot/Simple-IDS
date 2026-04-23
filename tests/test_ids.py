#!/usr/bin/env python3
"""
SimpleIDS Test Suite
Usage: python3 tests/test_ids.py
"""

import socket
import sys
import time

HOST = "localhost"
PORT = 8080

# ANSI Color
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

def send_raw_http(path, host=HOST, port=PORT, method="GET",
                  user_agent="TestClient/1.0", extra_headers=""):
    """Send HTTP requests directly using sockets, to get fully control over the content"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))

        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Connection: close\r\n"
            f"{extra_headers}"
            f"\r\n"
        )

        s.sendall(request.encode("utf-8", errors="ignore"))

        # Read response before closing to reduce server-side BrokenPipe logs
        try:
            while s.recv(1024):
                pass
        except socket.timeout:
            pass
        except ConnectionResetError:
            pass

        return True, ""
    except ConnectionRefusedError:
        return False, "connection refused"
    except socket.timeout:
        return False, "timeout"
    except OSError as e:
        return False, str(e)
    finally:
        if s:
            s.close()

def run_test(desc, path, expect_alert, **kwargs):
    """Execute a test case"""
    print(f"  {'%-45s' % desc}", end="")
    ok, reason = send_raw_http(path, **kwargs)

    if not ok:
        print(f"{YELLOW}[CONN FAILED: {reason}]{RESET}")
        return

    if expect_alert:
        print(f"{RED}→ should ALERT{RESET}")
    else:
        print(f"{GREEN}→ should be clean{RESET}")

    time.sleep(0.2)

# ============================================================
print()
print("=" * 55)
print("   SimpleIDS Test Suite")
print("=" * 55)
print()

# Preflight check to avoid flooding all cases with connection failures
ok, reason = send_raw_http("/")
if not ok:
    print(f"{YELLOW}[Preflight] Cannot connect to {HOST}:{PORT} ({reason}){RESET}")
    print(f"{YELLOW}Start a local HTTP service first, then rerun tests.{RESET}")
    print()
    sys.exit(1)

# ===== Normal Request =====
print(f"{YELLOW}[ Normal Requests ]{RESET}")
run_test("Normal homepage",        "/",                         expect_alert=False)
run_test("Normal search",          "/search?q=hello+world",     expect_alert=False)
run_test("Normal login",           "/login?user=john",          expect_alert=False)
print()

# ===== XSS =====
print(f"{YELLOW}[ XSS Attacks ]{RESET}")
run_test("Script tag",             "/?x=<script>alert(1)</script>",   expect_alert=True)
run_test("javascript: protocol",   "/?href=javascript:alert(1)",      expect_alert=True)
run_test("onerror handler",        "/?img=<img onerror=alert(1)>",    expect_alert=True)
print()

# ===== SQL Injection =====
print(f"{YELLOW}[ SQL Injection ]{RESET}")
run_test("Classic OR bypass",      "/?id=' OR 1=1--",                 expect_alert=True)
run_test("UNION SELECT",           "/?id=1 UNION SELECT * FROM users",expect_alert=True)
run_test("DROP TABLE",             "/?q=DROP TABLE users--",          expect_alert=True)
run_test("exec()",                 "/?q=exec(xp_cmdshell 'dir')",     expect_alert=True)
print()

# ===== Command Injection =====
print(f"{YELLOW}[ Command Injection ]{RESET}")
run_test("cmd.exe",                "/?cmd=cmd.exe /c whoami",         expect_alert=True)
run_test("/bin/sh",                "/?cmd=/bin/sh -c id",             expect_alert=True)
run_test("Shell variable $(",      "/?x=$(whoami)",                   expect_alert=True)
run_test("rm -rf",                 "/?x=; rm -rf /tmp/test",          expect_alert=True)
print()

# ===== Path Traversal =====
print(f"{YELLOW}[ Path Traversal ]{RESET}")
run_test("Directory climbing",     "/?f=../../../etc/passwd",         expect_alert=True)
run_test("/etc/passwd direct",     "/?f=/etc/passwd",                 expect_alert=True)
run_test("Windows System32",       "/?f=C:\\Windows\\System32",       expect_alert=True)
print()

# ===== User-Agent Attack Tools =====
print(f"{YELLOW}[ Scanner Detection ]{RESET}")
run_test("sqlmap User-Agent",      "/",  expect_alert=True,  user_agent="sqlmap/1.7.8")
run_test("nikto User-Agent",       "/",  expect_alert=True,  user_agent="Nikto/2.1.5")
run_test("Normal Chrome UA",       "/",  expect_alert=False,
         user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0")
print()

# ===== Anomaly URL Length =====
print(f"{YELLOW}[ Anomaly: URL Length ]{RESET}")
long_url = "/?q=" + "A" * 2000
run_test("Normal URL length",      "/?q=hello",                       expect_alert=False)
run_test("Abnormally long URL",    long_url,                          expect_alert=True)
print()

# ===== Rate Test =====
print(f"{YELLOW}[ Anomaly: Rate Limiting ]{RESET}")
print(f"  Sending 120 rapid requests to trigger rate alert...")
for i in range(120):
    send_raw_http("/")
print(f"  {RED}→ should have triggered rate alert after 100 req{RESET}")
print()

print("=" * 55)
print("  Done! Check your SimpleIDS terminal for alerts.")
print("=" * 55)
print()