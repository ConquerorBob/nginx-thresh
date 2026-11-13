# sentinel

nginx access log in, a ranked list of hostile requests out. The crate is `nginx-sentinel`; the binary it builds is `sentinel`.

I run a few small servers. Every request they get is already in an nginx access log, which is great until I try to read it. `grep` for `../` returns a page of noise from my own asset paths, and the one request that actually tried `/etc/passwd` is buried in the middle. I wrote sentinel to do the boring part: parse the log into typed entries, run a rule set over the parts an attacker controls, correlate hits by source IP, and print the handful of requests worth looking at first.

This is for anyone who runs nginx and wants a quick read on what hit them without standing up a log pipeline. It is one binary with no config file, and it makes no network calls.

## Install

Linux and macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/ConquerorBob/nginx-sentinel/main/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/ConquerorBob/nginx-sentinel/main/install.ps1 | iex
```

The script picks the archive for Linux x86_64 or arm64, macOS Intel or Apple Silicon, or Windows x86_64. It checks the SHA-256, puts the binary in `~/.local/bin` (`%LOCALAPPDATA%\sentinel\bin` on Windows), and tells you if that directory is not on your PATH. Set `SENTINEL_VERSION=v0.1.0` to pin a release or `SENTINEL_INSTALL_DIR` to choose another directory. The archives and checksums are also on the [releases page](https://github.com/ConquerorBob/nginx-sentinel/releases).

## Build from source

Rust 1.80 or newer is the only build requirement.

```bash
cargo build --release
./target/release/sentinel
```

With no path argument, sentinel prints its banner and asks for a log path. It accepts quotes around the path and expands a leading `~/`. If you already know the path, pass it directly:

```bash
sentinel /var/log/nginx/access.log
```

Here is a real run against the demo log. The ASCII banner and live progress bar are not part of this block; the numbers and rows are untouched.

```bash
./target/release/sentinel demo/access-demo.log --no-color --top 10
```

```
  ────────────────────────────────────────────────────────────────────────────────────────────
  EXECUTIVE SUMMARY
  ────────────────────────────────────────────────────────────────────────────────────────────

  Log file     demo/access-demo.log  ·  112.37 MiB
  Lines        600,219 scanned  ·  3 malformed
  Execution    569.91 ms  ·  8 workers
  Throughput   1.05M/s
  Threats      381 suspicious events  ·  9 unique offending IPs
  Severity     CRITICAL 304 (>=8) · HIGH 45 (6-7.99) · MEDIUM 32 (<6)

  CATEGORY BREAKDOWN

  Reconnaissance            218  ████████████████████████████████████████
  Sensitive File Access      54  ██████████
  Path Traversal             28  █████
  SQL Injection              17  ███
  Webshell                   14  ███
  Local File Inclusion       14  ███
  XSS                        13  ██
  SSRF                       10  ██
  Log4Shell                   8  █
  Command Injection           4  █
  Brute Force                 1  █

  TOP THREATS

  RANK SCORE  TIMESTAMP            SOURCE IP        CATEGORY              STATUS
  #1   28.13  2026-11-12 02:25:00  45.13.2.9        SQL Injection            200
    ↳ POST /product?id=1%20UNION%20SELECT%20username,password%20FROM%20users
      UNION SELECT injection (SQLI-001) · pattern union_select in '/product?id=1 union select use…

  #2   26.44  2026-11-12 02:25:07  45.13.2.9        SQL Injection            200
    ↳ GET /product?id=1%27%20OR%20%271%27=%271
      Quoted OR tautology (SQLI-004) · pattern quoted_or_tautology in '/product?id=1' or '1'='… ·…

  #3   22.50  2026-11-12 02:30:00  91.240.118.22    Command Injection        500
    ↳ GET /api/ping?host=127.0.0.1%3Bcat%20/etc/passwd
      Shell metacharacter followed by a command (CMDI-001) · pattern shell_metachar_command in '/…

  #4   22.50  2026-11-12 02:28:00  185.220.101.7    Local File Inclusion     404
    ↳ GET /../../../../etc/passwd
      Direct access to /etc (LFI-003) · pattern etc_passwd in '/../../../../etc/passwd' · base 9.…

  #5   22.50  2026-11-12 02:28:04  185.220.101.7    Local File Inclusion     403
    ↳ GET /%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
      Direct access to /etc (LFI-003) · pattern etc_passwd in '/../../../etc/passwd' · base 9.00 …

  #6   22.50  2026-11-12 02:28:09  185.220.101.7    Local File Inclusion     404
    ↳ GET /%252e%252e%252f%252e%252e%252fetc%252fpasswd
      Direct access to /etc (LFI-003) · pattern etc_passwd in '/../../etc/passwd' · base 9.00 · m…

  #7   22.50  2026-11-12 02:28:13  185.220.101.7    Local File Inclusion     403
    ↳ GET /download?file=../../../etc/shadow
      Include-style parameter with a sensitive path (LFI-002) · pattern file_param_traversal in '…

  #8   22.50  2026-11-12 02:28:18  185.220.101.7    Local File Inclusion     404
    ↳ GET /download?file=..%2f..%2f..%2fetc%2fpasswd
      Include-style parameter with a sensitive path (LFI-002) · pattern file_param_traversal in '…

  #9   22.50  2026-11-12 02:28:22  185.220.101.7    Local File Inclusion     403
    ↳ GET /?page=php://filter/convert.base64-encode/resource=index
      PHP stream wrapper (LFI-001) · pattern php_wrapper in '/?page=php://filter/convert.bas… · b…

  #10  22.50  2026-11-12 02:28:27  185.220.101.7    Local File Inclusion     404
    ↳ GET /?page=../../../../proc/self/environ
      Include-style parameter with a sensitive path (LFI-002) · pattern file_param_traversal in '…

  ────────────────────────────────────────────────────────────────────────────────────────────
  ◆ sentinel v0.1.0 · analysis complete
  Rerun with --top N to inspect more.
```

`Lines 600,219 scanned · 3 malformed` means the reader got through the whole 112.37 MiB file and only three lines did not match a supported layout.

`Execution 569.91 ms · 8 workers` and `1.05M/s` are from this machine. A one-thread run of the same file took 2.78 s at 215.8K/s, with the same 381 events in the same order.

The worker count is the number that actually ran, not the one I asked for. This box reports 12 CPUs, so sentinel asks for 12 threads, but the file splits into eight 16 MiB chunks. Eight workers is all the work there is, even though `--help` caps the automatic count at 16.

`381 suspicious events · 9 unique offending IPs` counts rule hits, not requests. One URL can trip three rules, and each stateful detector adds one event per offending IP when it fires. Nine source IPs produced all 381. The `TOP THREATS` list collapses multiple hits from the same log line into one row so you see distinct requests instead of the same payload three times.

`CRITICAL 304 (>=8) · HIGH 45 (6-7.99) · MEDIUM 32 (<6)` is the final score split. Rank #1 at 28.13 is SQLI-001 on a 200: severity 9 times 1.25 is 11.25, then a 2.50 multiplier because that IP tripped eleven or more distinct rules inside 300 seconds. That is the multiplier cap, and 11.25 times 2.50 rounds to 28.13. Rank #2 is the same arithmetic at a 2.35 multiplier: 11.25 times 2.35 rounds to 26.44.

Each detail line starts with the rule name and ID, then the evidence excerpt, then `base`, `multiplier` and the boost reason when they fit in the 92-column panel. The long SQL excerpt on row #1 pushes the score fields off the right edge. The ranking is unaffected; that is only the display cutting at a fixed width.

If nothing fires, the top list is replaced by a single all-clear panel; the summary still prints the line count and timing.

Do not read the score as a probability. A 26 means the request is several times more interesting than the 8.0 rows below it, not that there is a 26 percent chance of compromise.

## Demo log

Generate the demo file before pointing sentinel at your own logs:

```bash
python3 scripts/gen_demo_log.py
```

It writes `demo/access-demo.log`: 600,219 lines, 112.4 MiB, 600,000 benign requests and 216 hostile requests from 9 source IPs, plus three malformed lines. The generator uses a fixed seed, so you get the same file every time. The scripted traffic covers SQLi, path traversal and LFI, command injection, Log4Shell, a Nikto-style scan, a login brute force with 45 failures, XSS, SSRF, webshell probes and TRACE/PROPFIND/CONNECT requests.

Most of the file is ordinary shopping traffic, and only nine IPs are hostile, so the report stays short. I use it to sanity-check rule changes without pointing the scanner at production.

## What it catches

There are 139 rules across 11 families, plus three stateful detectors.

| Family | Rules | Looks for | Severity |
| --- | ---: | --- | --- |
| Command injection | 15 | `;cat /etc/passwd`, `$(id)`, shell binaries, `certutil`, PHP exec functions | 9-10 |
| Log4Shell | 11 | `${jndi:ldap://...}` in the target, User-Agent or Referer, nested lookups, encoded forms | 9-10 |
| Webshell | 10 | `c99.php`, `r57.php`, `eval(base64_decode(...))`, `?cmd=whoami`, upload params | 9 |
| Local file inclusion | 11 | `php://filter`, `data://`, `?file=../../etc/passwd`, `/proc/self`, remote includes | 8-9 |
| SQL injection | 20 | `UNION SELECT`, `OR 1=1`, `SLEEP(5)`, `INTO OUTFILE`, `1'`, `1--`, comment-split keywords | 3-9 |
| Path traversal | 12 | `../`, `..\`, `..;/`, `%2e%2e%2f`, overlong UTF-8, encoded paths into `/etc` or `/proc`, traversal in headers | 5-9 |
| SSRF | 9 | `169.254.169.254`, loopback and private hosts, `file://`, internal ports, fetch params | 2-9 |
| XSS | 13 | `<script>`, `onerror=`, pointer and touch handlers, `javascript:`, SVG onload | 4-6 |
| Sensitive file access | 16 | `.env`, `.git/config`, `.ssh/id_rsa`, SQL dumps, framework configs, backups | 2-6 |
| Reconnaissance | 14 | `/server-status`, `/actuator/env`, `/graphql`, scanner user agents, odd HTTP methods | 2-4 |
| Malformed request | 8 | Null bytes, CRLF injection, bad protocol or method tokens, targets over 4 KB | 3-6 |

The low end of the SQLi, traversal, SSRF and XSS ranges is a handful of low-confidence rules for bare probes and header values. The high end is the shapes that are hard to explain as normal browsing.

BF-001 is the brute-force detector. It fires when one IP has `--threshold` failed logins in a window (20 by default). Both 401 and 403 count, but only when the path names a login surface: `login`, `signin`, `wp-login`, `admin`, `token`, `oauth` and a few more. A 401 on `/api/orders` is usually an expired token, not a password guess. Severity is 6 plus peak divided by threshold, capped at 9.

AUTH-001 covers that expired-token case. It fires on a burst of 401s from one IP on paths without a login hint, at the same threshold and window, and it stays at severity 4. It tells you a client is broken or poking at API auth without pushing the event into the critical tier.

SCAN-001 is the enumeration detector. It fires when one IP hits at least `max(--threshold, 25)` distinct 404/403 paths in a window. At the default threshold that is 25 paths. Static asset extensions such as `.css`, `.js`, images and fonts are excluded, because a 403 burst on those is more often signed-URL expiry or hotlink protection than a directory walk. Severity is fixed at 5.

SSRF-001 used to be the noisy one. It is base severity 2 now and only fires when a fetch-shaped parameter carries an absolute URL whose host is an IP literal or a dotless internal name. `?url=https://checkout.example.com/pay` is clean. SSRF-003, SSRF-004, SSRF-005 and SSRF-009 keep their 7 to 9 weights for loopback, private ranges, cloud metadata and host parameters aimed inward. SSRF-006, SSRF-007 and SSRF-008 cover dangerous schemes, internal service ports and obfuscated loopback at 8.

WEBSHELL-004 also got narrower. It needs a command-looking value after `?cmd=`, so `?cmd=download` and `?cmd=add-to-cart` stay clean. Log4Shell has a rule for the nested `${${lower:j}ndi:...}` bypass, and SQLi matches a comment-stripped copy of the target, so `UN/**/ION SEL/**/ECT` reads as `union select`.

The dashboard prints the rule ID and rule name on each detail line. [docs/detections.md](docs/detections.md) has a section per family with representative IDs, examples, and the stateful detectors in more detail.

## How scoring works

```
base  = min(rule severity x status modifier, 12.5)
final = round2(base x contextual multiplier)
```

| Status | Modifier | Why |
| --- | ---: | --- |
| 2xx | 1.25 | The request reached the app and may have worked |
| 3xx | 1.10 | It got past routing, then redirected |
| 4xx | 1.00 | Neutral; the app rejected it |
| 5xx | 0.90 | It probably broke before doing damage |
| anything else | 1.00 | No signal |

Rule severity is 1 to 10 and lives in the rule definition. The base cap at 12.5 stops one severity-10 hit on a 200 from running away with the ranking.

Context is per source IP and per time window. For each event, sentinel looks forward `--window` seconds (300 by default) and counts distinct rule IDs from the same IP in that range. Two distinct rules give 1.15, three give 1.30, and each extra adds 0.15, up to a cap of 2.5. Repeats of the same rule do not stack. Ten identical SQLi attempts from one IP still get 1.0; ten different attack types get 2.35.

The window looks forward from each event, not backward. Early events in a burst see the rest of the burst and get the full multiplier. The last event in the burst sees only itself. That is why the top two SQLi rows in the demo carry 2.50 and 2.35 multipliers instead of one shared number. It also means the first hit from a noisy IP tends to rank highest, which is the row I want to read first.

The worked example from the demo output: rank #1 is SQLI-001, severity 9, status 200. `9 x 1.25 = 11.25`. The IP had at least 11 distinct rules within 300 seconds, so `1 + 0.15 x 10 = 2.50`, and 2.50 is the cap. `11.25 x 2.50 = 28.125`, rounded to 28.13. Rank #2 is `11.25 x 2.35 = 26.4375`, rounded to 26.44.

Sorting is by final score, then rule severity, then timestamp, line number, source IP and rule ID. The same input produces the same order every run.

## How it works

### Reading the file

The reader splits the file into 16 MiB chunks by default. A pool of workers claims chunks through an atomic counter. Each worker seeks to its range, skips the partial first line when the chunk starts mid-line, and reads through the newline that ends the range, so no line is parsed twice or cut in half. Line numbers are rebased to the whole file. Memory is bounded by chunk size plus retained events, which is why the 112 MiB demo peaks around 25.6 MiB of RSS and a multi-GB log does not scale memory with file size.

The actual worker count is `--threads` capped by the number of chunks, so a smaller file can use fewer threads than you asked for. The dashboard reports the workers that ran.

### Parsing

The parser is a hand-written cursor over bytes, not a regex. It accepts the stock `combined` and `common` layouts, both with an optional vhost prefix, bare or bracketed IPv6, escaped quotes, `-` placeholders and trailing fields such as request time or upstream. JSON lines that start with `{` go through a small fallback that reads `remote_addr`, `status`, `request` (or the method/URI/protocol fields), `time_local`, `time_iso8601` and the usual header names. A line over 1 MiB is rejected before it gets buffered.

Each accepted line becomes a `LogEntry` with source IP, timestamp, method, target, protocol, status, byte count, referer, user agent, host and the raw line. Rules work on struct fields.

### Rules and state

Every regex rule compiles once at startup into four aggregate `RegexSet`s: raw target, decoded target, User-Agent, Referer. Each line gets a handful of set scans. Individual regexes only run for rules that already matched, to grab the evidence excerpt. The target is percent-decoded once before matching, and a second pass runs only when another decode changes the string. That catches `%252e%252e%252f` without paying for a second decode on every clean line. A third matching pass runs a comment-stripped copy of the target when the request carried a `/*...*/` block, which is how `UN/**/ION SEL/**/ECT` turns into `union select`.

After the line pass, 401/403/404 responses go through three stateful detectors. That is where a run of failed logins becomes one brute-force event, a burst of non-login 401s becomes one auth-failure event, and a walk through dozens of paths becomes one scan event.

The dashboard is assembled last: headline counts, the category histogram, and the top N distinct requests with timestamp, source IP, category, status, raw payload, rule and evidence. Multiple rule hits on one log line collapse to one row in that list so a single hostile URL does not fill the screen.

### Measured on the demo

112.37 MiB and 600,219 lines took 617.45 ms of scan time with 8 workers, 972.1K lines/s, and 25.6 MiB max RSS according to `/usr/bin/time -v`. One worker took 2.78 s at 215.8K/s and produced identical results. These are single runs on a machine that was also doing other work, so treat them as a rough shape, not a benchmark.

## Flags

| Flag | Default | What it does |
| --- | --- | --- |
| `LOG_PATH` | prompt | Access log to scan. Optional; when omitted sentinel asks |
| `--threads N` | auto, 1-16 | Parser workers. Accepts 1-64 |
| `--top N` | 10 | Ranked rows on the dashboard. Accepts 1-100 |
| `--window SECS` | 300 | Correlation and stateful window. Accepts 1-86400 |
| `--threshold N` | 20 | Failed logins per window for BF-001 and AUTH-001. SCAN-001 uses `max(N, 25)`. Accepts 1-1,000,000 |
| `--chunk-mb N` | 16 | Read chunk size in MiB. Accepts 1-1024; the effective minimum is 1 MiB |
| `--max-events N` | 250000 | Hard cap on stored threat events. Accepts 1-5,000,000 |
| `--no-color` | off | Disable ANSI colors. Colors also drop out when output is not a TTY |
| `-h`, `--help` | | Print usage |
| `-V`, `--version` | | Print version |

The progress bar goes to stderr and hides itself when that stream is not a TTY. Redirected output is just the dashboard.

## Limits

- It is a heuristic scanner. The rules match shapes and keywords, not intent. A crafted payload can get past them, and normal traffic can trip them. Run it on your own logs before trusting the output.
- It reads access logs only. No request bodies, no response bodies, no error log. SQLi or command injection that only appears in a POST body is invisible unless the same payload also shows up in the URL.
- It does not tail. It scans a file from beginning to end and exits. Point it at a rotated file, or run it from cron, but do not expect it to follow a live log.
- There are caps. 250,000 events by default, plus fixed retention budgets of 400,000 auth-failure records (401/403) and 100,000 404 probe records. When any of them binds, the dashboard prints a warning above the category breakdown. `--max-events` is a hard cap, and the code reserves room for stateful summary events before per-line hits, so a very low value can leave you with only the brute-force, auth-burst and scan rows.
- `--max-events 2` against the demo keeps BF-001 and SCAN-001 and drops the SQLi rows. That is the intended trade: the summaries cover many requests at once, and a truncated per-line list is easy to reproduce by raising the cap.
- SSRF-002 still tags scheme-relative `//host` values, but only in fetch-shaped parameters and at severity 3. Protocol-relative checkout or OAuth links in `next` or `return_url` are no longer treated as SSRF. SSRF-001 is informational now, and it still tags a fetch parameter aimed at an internal IP literal. This version has no per-rule disable flag.
- Correlation needs timestamps. A line with an unparseable timestamp still gets checked, but it cannot join a window and will not receive a multiplier.
- Lines over 1 MiB count as malformed instead of being buffered.
- Exit status is about the scan, not the findings. A completed scan returns 0 even when the dashboard is full of CRITICAL rows; non-zero means it could not scan: bad arguments, a missing or unreadable file, or a parser failure. A cron job has to parse the output or check the event count if it wants to alert.
- It is not a WAF or an IDS replacement: it reads history rather than blocking or rate-limiting traffic, and it knows nothing about IP reputation.

## Tests

```bash
cargo test --release
```

When I last ran it: 178 unit tests and 18 integration tests passed, 0 failed, 1 ignored. The ignored test is a throughput smoke test. Run it with `cargo test --release -- --ignored --nocapture` if you want to see it. The suite covers the parser layouts, chunk boundaries across threads, deterministic ranking, the scoring math, rule metadata, dashboard rendering, the truncation notice and the CLI end to end.

## License

MIT. Copyright (c) 2026 ConquerorBob. See [LICENSE](LICENSE).
