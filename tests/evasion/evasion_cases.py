"""
Evasion test set (Phase 3).

Every case is one attack, rewritten the way an attacker would to slip past
a naive substring IDS: URL encoding, mixed case, path obfuscation and HTTP
parameter pollution. A case counts as detected when every sid in `attack`
fires for its connection.

`extra` lists further sids the case must raise (normalization anomalies
such as double encoding); they are checked by the regression run but do
not decide detection. A case the engine cannot catch yet carries a
`known_miss` reason: the regression pcap then expects no attack alert, and
tests/evasion/report.py fails if an undocumented miss appears, if a
documented miss starts being detected (stale note), or if the rate drops
below 95%.

Used by tests/regression/gen_pcaps.py (evasion.pcap) and report.py.
Case i is sent from client port BASE_PORT + i.
"""

from dataclasses import dataclass, field

# Anomaly sids (include/simpleids/anomaly.h)
TRAVERSAL = 900010
DOUBLE = 900011
U_ENC = 900012
OVERLONG = 900013
HPP = 900014
NUL = 900015
BAD_UA = 900004

BASE_PORT = 60000
UA = "TestClient/1.0"
FORM = "application/x-www-form-urlencoded"

CATEGORIES = {
    "url-encoding": "URL encoding",
    "mixed-case": "Mixed case",
    "path": "Path obfuscation",
    "hpp": "HTTP parameter pollution",
}


@dataclass
class EvasionCase:
    category: str
    desc: str
    target: str
    attack: set
    extra: set = field(default_factory=set)
    method: str = "GET"
    headers: list = field(default_factory=list)   # [(name, value)]
    body: bytes = b""
    chunks: list = None                             # chunked body pieces
    user_agent: str = UA
    known_miss: str = ""

    def request(self):
        lines = [f"{self.method} {self.target} HTTP/1.1", "Host: testserver"]
        if self.user_agent is not None:
            lines.append(f"User-Agent: {self.user_agent}")
        lines += [f"{n}: {v}" for n, v in self.headers]
        body = self.body
        if self.chunks is not None:
            lines.append("Transfer-Encoding: chunked")
            body = b"".join(b"%x\r\n%s\r\n" % (len(c), c) for c in self.chunks) + b"0\r\n\r\n"
        elif body:
            lines.append(f"Content-Length: {len(body)}")
        lines.append("Connection: close")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body

    def expected(self):
        """Sids the regression pcap expects for this case."""
        return set(self.extra) | (set() if self.known_miss else set(self.attack))


def form(category, desc, body, attack, extra=(), **kw):
    return EvasionCase(category, desc, "/submit", set(attack), set(extra), method="POST",
                       headers=[("Content-Type", FORM)], body=body, **kw)


# known_miss reasons end up in docs/EVASION.md, which is in Chinese.
CASES = [
    # ------------------------------------------------------------------
    # URL encoding
    # ------------------------------------------------------------------
    EvasionCase("url-encoding", "Percent-encoded angle brackets", "/?x=%3Cscript%3Ealert(1)", {1001}),
    EvasionCase("url-encoding", "Lower-case hex digits", "/?x=%3cscript%3e", {1001}),
    EvasionCase("url-encoding", "Every character encoded",
                "/?x=%3C%73%63%72%69%70%74%3E", {1001}),
    EvasionCase("url-encoding", "Double encoding", "/?x=%253Cscript%253E", {1001}, {DOUBLE}),
    EvasionCase("url-encoding", "Triple encoding", "/?x=%25253Cscript%25253E", {1001}, {DOUBLE}),
    EvasionCase("url-encoding", "Nested encoding of the hex digits (%%33C)",
                "/?x=%%33Cscript%%33E", {1001}, {DOUBLE}),
    EvasionCase("url-encoding", "IIS %u encoding", "/?x=%u003Cscript%u003E", {1001}, {U_ENC}),
    EvasionCase("url-encoding", "%u full-width brackets",
                "/?x=%uFF1Cscript%uFF1E", {1001}, {U_ENC}),
    EvasionCase("url-encoding", "Overlong UTF-8 '<' (C0 BC)",
                "/?x=%C0%BCscript%C0%BE", {1001}, {OVERLONG}),
    EvasionCase("url-encoding", "Three-byte overlong UTF-8 '<' (E0 80 BC)",
                "/?x=%E0%80%BCscript%E0%80%BE", {1001}, {OVERLONG}),
    EvasionCase("url-encoding", "Encoded colon in javascript:", "/?u=javascript%3Aalert(1)", {1002}),
    EvasionCase("url-encoding", "Encoded quote and spaces in OR bypass",
                "/?id=%27%20OR%201%3D1--", {2001}),
    EvasionCase("url-encoding", "'+' as space in UNION SELECT", "/?id=1+UNION+SELECT+1,2", {2002}),
    EvasionCase("url-encoding", "%20 in DROP TABLE", "/?q=1;DROP%20TABLE%20users", {2003}),
    EvasionCase("url-encoding", "Encoded parenthesis in exec(", "/?q=exec%28xp_cmdshell%29", {2004}),
    EvasionCase("url-encoding", "Encoded dot in cmd.exe", "/?c=cmd%2Eexe", {3001}),
    EvasionCase("url-encoding", "Encoded slashes in /bin/sh", "/?c=%2Fbin%2Fsh", {3002}),
    EvasionCase("url-encoding", "Encoded $( substitution", "/?c=%24%28id%29", {3003}),
    EvasionCase("url-encoding", "Encoded /etc/passwd in the query",
                "/?f=%2F%65%74%63%2F%70%61%73%73%77%64", {4003}),
    EvasionCase("url-encoding", "NUL byte before the payload", "/?x=%00<script>", {1001}, {NUL}),
    form("url-encoding", "Form body, percent-encoded", b"c=%3Cscript%3E", {1011}),
    form("url-encoding", "Form body, '+' as space", b"q=1+UNION+SELECT+2", {2012}),
    EvasionCase("url-encoding", "Chunked body splits the payload",
                "/upload", {1011}, method="POST", chunks=[b"x=<scr", b"ipt>"]),
    # Phase 4: rule 2002 uses PCRE2, so any whitespace or inline comment
    # between the keywords matches (these two were known misses in Phase 3).
    EvasionCase("url-encoding", "Encoded tab between UNION and SELECT",
                "/?id=1%09UNION%09SELECT%091", {2002}),
    EvasionCase("url-encoding", "Encoded newline between UNION and SELECT",
                "/?id=1%0aUNION%0aSELECT%0a1", {2002}),
    EvasionCase("url-encoding", "Inline comments between UNION and SELECT",
                "/?id=1/**/UNION/**/SELECT/**/1", {2002}),
    EvasionCase("url-encoding", "UNION ALL SELECT with encoded tabs",
                "/?id=1%09UNION%09ALL%09SELECT%091", {2002}),

    # ------------------------------------------------------------------
    # Mixed case
    # ------------------------------------------------------------------
    EvasionCase("mixed-case", "Script tag", "/?x=<ScRiPt>", {1001}),
    EvasionCase("mixed-case", "javascript: protocol", "/?u=JaVaScRiPt:alert(1)", {1002}),
    EvasionCase("mixed-case", "Event handler", "/?i=<img%20OnErRoR=alert(1)>", {1003}),
    EvasionCase("mixed-case", "OR bypass", "/?id='%20oR%201=1", {2001}),
    EvasionCase("mixed-case", "UNION SELECT", "/?id=1%20UnIoN%20sElEcT%201", {2002}),
    EvasionCase("mixed-case", "DROP TABLE", "/?q=dRoP%20tAbLe%20t", {2003}),
    EvasionCase("mixed-case", "EXEC(", "/?q=ExEc(x)", {2004}),
    EvasionCase("mixed-case", "CMD.EXE", "/?c=CMD.EXE", {3001}),
    EvasionCase("mixed-case", "rm -rf", "/?c=x;%20RM%20-RF%20/", {3004}),
    EvasionCase("mixed-case", "Windows System32 path", "/?f=c:\\wInDoWs\\SyStEm32", {4004}),
    EvasionCase("mixed-case", "Encoded and mixed case together", "/?x=%3cScRiPt%3E", {1001}),
    EvasionCase("mixed-case", "Scanner name in a lower-case header name",
                "/", {5001}, {BAD_UA}, user_agent=None,
                headers=[("user-agent", "SQLMap/1.7")]),
    EvasionCase("mixed-case", "Scanner name in upper case", "/", {5002}, {BAD_UA},
                user_agent="Mozilla/5.0 (NIKTO)"),
    EvasionCase("mixed-case", "Header name in upper case",
                "/", {1012}, headers=[("X-FORWARDED-FOR", "<SCRIPT>")]),
    form("mixed-case", "Form body", b"c=%3CsCrIpT%3E", {1011}),

    # ------------------------------------------------------------------
    # Path obfuscation
    # ------------------------------------------------------------------
    EvasionCase("path", "Self references", "/./etc/./passwd", {4003}),
    EvasionCase("path", "Repeated slashes", "//etc//passwd", {4003}),
    EvasionCase("path", "Backslashes", "\\etc\\passwd", {4003}),
    EvasionCase("path", "Parent references inside the root", "/var/www/../../etc/passwd", {4003}),
    EvasionCase("path", "Climb above the root", "/../../../../etc/passwd", {4003}, {TRAVERSAL}),
    EvasionCase("path", "Encoded slash in ..%2f", "/a/..%2f..%2f..%2fetc/passwd",
                {4003}, {TRAVERSAL}),
    EvasionCase("path", "Encoded dots", "/%2e%2e/%2e%2e/etc/passwd", {4003}, {TRAVERSAL}),
    EvasionCase("path", "Half-encoded dots", "/.%2e/.%2e/etc/passwd", {4003}, {TRAVERSAL}),
    EvasionCase("path", "Double-encoded dots", "/%252e%252e/%252e%252e/etc/passwd",
                {4003}, {TRAVERSAL, DOUBLE}),
    EvasionCase("path", "Encoded backslash", "/x/..%5c..%5c..%5cetc%5cpasswd",
                {4003}, {TRAVERSAL}),
    EvasionCase("path", "Overlong UTF-8 slash (C0 AF)", "/..%c0%af..%c0%afetc%c0%afpasswd",
                {4003}, {TRAVERSAL, OVERLONG}),
    EvasionCase("path", "%u full-width slash", "/..%uff0f..%uff0fetc%uff0fpasswd",
                {4003}, {TRAVERSAL, U_ENC}),
    EvasionCase("path", "Absolute-form request target", "http://testserver/x/../etc/passwd",
                {4003}),
    EvasionCase("path", "NUL byte to cut a file extension", "/etc/passwd%00.jpg", {4003}, {NUL}),
    EvasionCase("path", "Shell path with self references", "/./bin/./sh", {3002}),
    EvasionCase("path", "Shell path with repeated slashes", "/bin//sh", {3002}),
    EvasionCase("path", "Traversal to the shell from cgi-bin",
                "/cgi-bin/.%2e/.%2e/.%2e/bin/sh", {3002}, {TRAVERSAL}),
    EvasionCase("path", "Windows path with forward slashes", "/c:/windows/system32/cmd.exe",
                {3001, 4005}),
    EvasionCase("path", "Windows path with encoded backslashes",
                "/..%5c..%5cWindows%5cSystem32%5cconfig", {4005}, {TRAVERSAL}),
    EvasionCase("path", "Traversal in the query", "/?file=../../etc/passwd", {4001, 4003}),
    EvasionCase("path", "Encoded traversal in the query", "/?file=..%2f..%2fetc%2fpasswd",
                {4001, 4003}),
    EvasionCase("path", "Filter-bypass dots in the query (....//)", "/?f=....//....//etc/passwd",
                {4001, 4003}),
    EvasionCase("path", "Windows traversal in the query", "/?f=..\\..\\boot.ini", {4002}),
    EvasionCase("path", "Tomcat path parameter (..;/)", "/app/..;/..;/etc/passwd", {4003}),

    # ------------------------------------------------------------------
    # HTTP parameter pollution. Since Phase 4 the split-comment cases also
    # raise 2002/2012: before joining, "UNION/*&id=*/SELECT" already reads
    # as UNION, a comment, SELECT.
    # ------------------------------------------------------------------
    EvasionCase("hpp", "SQL comment split across duplicate parameters (ASP.NET joins with ',')",
                "/?id=1%20UNION/*&id=*/SELECT%201", {HPP}, {2002}),
    EvasionCase("hpp", "Split comment, encoded", "/?id=1%20UNION%2F*&id=*%2FSELECT%201", {HPP},
                {2002}),
    EvasionCase("hpp", "Split comment across three copies",
                "/?q=1%20UNION/*&q=*/SELECT/*&q=*/1", {HPP}, {2002}),
    EvasionCase("hpp", "Encoded parameter names", "/?%69d=1%20UNION/*&i%64=*/SELECT", {HPP}, {2002}),
    EvasionCase("hpp", "Attack in the second copy (PHP keeps the last)",
                "/?id=1&id=1'%20OR%201=1--", {2001}),
    EvasionCase("hpp", "Attack in the first copy (JSP keeps the first)",
                "/?x=<script>&x=safe", {1001}),
    form("hpp", "Split comment in a form body", b"id=1+UNION/*&id=*/SELECT+1", {HPP}, {2012}),
    form("hpp", "Attack in the second form copy", b"c=ok&c=%3Cscript%3E", {1011}),
    EvasionCase("hpp", "Split comment across query and body (ASP.NET Request.Params)",
                "/submit?id=1%20UNION/*", {HPP}, method="POST",
                headers=[("Content-Type", FORM)], body=b"id=*/SELECT+1",
                known_miss="重複參數只在 query 內或 form body 內各自計算，不會跨兩者合併。"
                           "要合併必須把 query 參數保存在 transaction 狀態裡，"
                           "等 body（可能晚很多個封包才到）到齊再比對。"),
]

assert all(c.category in CATEGORIES for c in CASES)
