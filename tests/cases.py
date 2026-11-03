"""
Shared HTTP test cases.

Used by tests/regression/gen_pcaps.py (to build pcaps and their expected
alerts) and by tests/live/test_live.py (to send the same requests over a
real socket). Each case lists the exact set of sids it must trigger with
the rules in rules/*.rules; an empty set means "must stay clean".
"""

from dataclasses import dataclass, field

# Anomaly sids (include/simpleids/anomaly.h)
SID_RATE = 900001
SID_LONG_URL = 900002
SID_SHORT_UA = 900003
SID_BAD_UA = 900004

DEFAULT_UA = "TestClient/1.0"


@dataclass
class HttpCase:
    desc: str
    path: str
    sids: set
    method: str = "GET"
    user_agent: str = DEFAULT_UA
    extra_headers: str = ""
    port: int = 80
    tags: set = field(default_factory=set)

    def request(self, host="testserver"):
        req = f"{self.method} {self.path} HTTP/1.1\r\nHost: {host}\r\n"
        if self.user_agent is not None:
            req += f"User-Agent: {self.user_agent}\r\n"
        req += self.extra_headers
        req += "Connection: close\r\n\r\n"
        return req.encode("latin-1")


CLEAN_CASES = [
    HttpCase("Normal homepage", "/", set()),
    HttpCase("Normal search", "/search?q=hello+world", set()),
    HttpCase("Normal login", "/login?user=john", set()),
    HttpCase("Normal short URL", "/?q=hello", set()),
    HttpCase("Normal Chrome UA", "/", set(),
             user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"),
    # sid 4003 has no nocase, so upper case must not match.
    HttpCase("Case-sensitive rule stays quiet", "/?f=/ETC/PASSWD", set()),
    HttpCase("HEAD request", "/status", set(), method="HEAD"),
]

SIGNATURE_CASES = [
    # XSS
    HttpCase("Script tag", "/?x=<script>alert(1)</script>", {1001}),
    HttpCase("Script tag, mixed case", "/?x=<ScRiPt>alert(1)</sCrIpT>", {1001}),
    HttpCase("javascript: protocol", "/?href=javascript:alert(1)", {1002}),
    HttpCase("onerror handler", "/?img=<img onerror=alert(1)>", {1003}),
    # SQL injection
    HttpCase("Classic OR bypass", "/?id=' OR 1=1--", {2001}),
    HttpCase("UNION SELECT", "/?id=1 UNION SELECT * FROM users", {2002}),
    HttpCase("DROP TABLE", "/?q=DROP TABLE users--", {2003}),
    HttpCase("exec()", "/?q=exec(xp_cmdshell 'dir')", {2004}),
    # Command injection
    HttpCase("cmd.exe", "/?cmd=cmd.exe /c whoami", {3001}),
    HttpCase("/bin/sh", "/?cmd=/bin/sh -c id", {3002}),
    HttpCase("Shell substitution $(", "/?x=$(whoami)", {3003}),
    HttpCase("rm -rf", "/?x=; rm -rf /tmp/test", {3004}),
    # Path traversal (4002 and 4004 never fired before the B5 fix)
    HttpCase("Directory climbing", "/?f=../../../etc/passwd", {4001, 4003}),
    HttpCase("Windows-style climbing", "/?f=..\\..\\boot.ini", {4002}, tags={"B5"}),
    HttpCase("/etc/passwd direct", "/?f=/etc/passwd", {4003}),
    HttpCase("Windows System32", "/?f=C:\\Windows\\System32", {4004}, tags={"B5"}),
    # Scanners: rule + User-Agent anomaly
    HttpCase("sqlmap User-Agent", "/", {5001, SID_BAD_UA}, user_agent="sqlmap/1.7.8"),
    HttpCase("Nikto User-Agent", "/", {5002, SID_BAD_UA}, user_agent="Nikto/2.1.5"),
    HttpCase("Nmap NSE User-Agent", "/", {5003, SID_BAD_UA},
             user_agent="Mozilla/5.0 (compatible; Nmap Scripting Engine)"),
    # File upload
    HttpCase("PHP upload", "/upload", {6001}, method="POST",
             extra_headers="Content-Type: application/x-php\r\nContent-Length: 0\r\n"),
    HttpCase("PHP file in URL", "/index.php?id=1", {6002}),
    # Port 8080 uses the port-80 rule set
    HttpCase("Script tag on 8080", "/?x=<script>", {1001}, port=8080),
]

ANOMALY_CASES = [
    HttpCase("Abnormally long URL", "/?q=" + "A" * 2000, {SID_LONG_URL}),
    HttpCase("URL just under the limit", "/?q=" + "A" * 1020, set()),
    HttpCase("Very short User-Agent", "/", {SID_SHORT_UA}, user_agent="X"),
]

ALL_CASES = CLEAN_CASES + SIGNATURE_CASES + ANOMALY_CASES
