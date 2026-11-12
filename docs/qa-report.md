# nginx-sentinel — QA & security review

> Historical review. This was run against the build before the reader, cap and detection fixes landed. The defects below were fixed afterward; see the current README and `docs/validation-after.md` for current behaviour. Kept for the audit trail.

**Reviewer:** independent QA subagent (read-only except this file)
**Date:** 2026-11-12 12:22 MST
**Binary:** `sentinel 0.1.0`, `target/release/sentinel` sha256 `6f41ea61149e64c98f0fdc9bdefb0fe219e0755c995d35f96a529473fb32a2e3`
**Tree reviewed:** `src/*.rs` sha256 `24b60a7bb128c901c4be292a4f42d86a154f6c2a0a6cc8ad3b905a368726d9f9`
(line numbers below were verified against that tree; `tests/integration.rs`, `README.md`, `LICENSE`, `docs/` were added/changed by other agents during this review — see §10)

**Environment:** Linux 7.0.0-42-generic, i5-13420H (8 cores / 12 threads), 31 GiB RAM. Load average 4.0–4.7 during measurements because other agents were building/testing concurrently; absolute timings are therefore approximate, relative comparisons are consistent.

## Verdict

**Pass with findings.** The build is healthy: `cargo check` and `cargo clippy` have zero errors, 166 tests pass (149 unit + 17 integration), there are no reachable panics, no `unsafe`, no shell-outs, no network calls, and log-controlled fields cannot inject terminal escapes. Chunked parsing is correct at boundaries and deterministic across 1–64 threads on untruncated inputs; throughput is ~1.0 M lines/s (8–12 threads) at ~23 MiB RSS on the 112 MiB demo.

Three defects affect trust in the output when caps are hit:

1. truncation is **never** reported to the user (the budget flags are written but dropped before they reach `ScanOutcome`);
2. the 500 k auth-failure budget is first-come-first-served over **all** 401/403/404 responses, so a 404 flood can evict the 401 burst and the tool prints “No suspicious activity detected”;
3. `--max-events` is not a hard cap — stateful BF/SCAN events are appended after the cap.

Memory is bounded by record **count**, not bytes: measured ~1.0 KiB RSS per retained event, so a 14 MiB hostile log consumes ~251 MiB (18× amplification). Terminal injection through the dashboard is correctly blocked; the only unsanitized path is a hostile **filename** in fatal/prompt error strings (operator-supplied, low).

---

## 1. Build health

| Command | Result |
|---|---|
| `cargo check --all-targets --message-format short` | **ok**, 0 errors, 8 dead-code warnings (bin), 3 in test cfg (1 duplicate) |
| `cargo clippy --all-targets --message-format short` | **ok**, 0 errors, **12 unique warnings** (8 dead-code + 4 style), 7 in test cfg (5 duplicates); integration target clean |
| `cargo test --release` | **166 passed, 0 failed, 2 ignored** — unit `149 passed; 1 ignored`, integration `17 passed; 1 ignored`, 0.53 s + 0.65 s |
| `cargo test` (debug) | same 166 passed, 0 failed, 2 ignored |
| `cargo test --release -- --ignored` | unit throughput bench passes; integration `max_events_reports_truncation_notice` **FAILS** (known product bug, see F1) |
| `cargo test --release -- --ignored --nocapture` (bench) | `inspect short lines: 497,152 lines/s`; `inspect long lines (1.2 KB): 43,484 lines/s` (single-thread, engine only) |

### Warning classification

All 12 clippy warnings are dead code or style; **none is a defect or a hint of a bug**:

| Kind | Locations |
|---|---|
| dead code (8) | `src/model/entry.rs:18` `body_bytes`, `host`; `:26` `request_line`, `query`, `is_success`; `src/model/threat.rs:19` `Category::Other` never constructed; `:41` `Category::all`; `:77` `timestamp_raw`, `user_agent`; `src/parser/reader.rs:43` `NoopProgress`; `:57` `bytes_read`; `src/scoring/mod.rs:45` `base_score`, `reasons` |
| style (4) | `src/detection/bruteforce.rs:206` needless lifetime; `src/detection/misc.rs:119` `map_or` → `is_some_and`; `src/detection/rule.rs:332` `iter().any` → `contains`; `src/parser/parse.rs:130` `?` operator |

Two dead items are worth acting on rather than silencing: `ThreatEvent.user_agent`/`timestamp_raw` are cloned for every event and never read (memory cost, see F4), and `ScoredEvent.reasons` is computed by the scorer but never displayed, so a `x2.35` multiplier has no explanation (F9). `Category::Other`/`all()` and the `LogEntry` helpers are reasonable public-ish API; keep with `#[allow(dead_code)]` or remove.

Reproduce:
```bash
cargo check --all-targets --message-format short
cargo clippy --all-targets --message-format short
cargo test --release
cargo test --release -- --ignored            # 1 expected failure: truncation notice
```

---

## 2. Findings (severity-ranked)

| ID | Severity | Finding |
|---|---|---|
| F1 | **High** | Truncation is never surfaced: `events_truncated`/`failures_truncated` are set on atomics and never copied into `ScanOutcome` |
| F2 | **High** | Failure budget is first-come over all 401/403/404 records; 404 floods can silently evict brute-force 401s |
| F3 | Medium | `--max-events` is not a hard cap: BF-001/SCAN-001 events are added after the cap |
| F4 | Medium | Memory is count-capped, not byte-capped: ~1.0 KiB RSS per retained event; 14 MiB hostile log → ~251 MiB RSS |
| F5 | Low | Terminal escapes from a hostile **filename** reach stderr via fatal/prompt errors (dashboard/log fields are safe) |
| F6 | Low | Cap-bound retention is scheduling-dependent: same log gives 20 vs 21 unique IPs, and BF detection flips between 1 and 12 threads |
| F7 | Low | Unicode bidi/format characters (U+202E, zero-width) bypass `sanitize` (visual spoofing, not command execution) |
| F8 | Low | Dashboard says “N workers” = requested threads, not actual workers (`--chunk-mb 1024` shows 12 while one runs) |
| F9 | Info | 12 clippy warnings; boost `reasons` computed but never rendered |
| F10 | Info | `colored 2.2.0` is **MPL-2.0**, project is MIT; no third-party notice |

### F1 — Truncation is silently swallowed (High)

`Budgets::reserve_event` / `reserve_failure` store `true` into `events_truncated` / `failures_truncated` (`src/parser/reader.rs:97-113`, atomics created at `:162-163`, wired at `:164-171`). Those atomics are **never read again**. `ScanOutcome.events_truncated` is only set by the defensive trim at `src/parser/reader.rs:246-254`, whose condition (`outcome.events.len() > cfg.max_events`) cannot be true because workers already stopped pushing at exactly `max_events`. `main` then feeds the always-false flags to the dashboard (`src/main.rs:130`), so the warning branch at `src/ui/dashboard.rs:71-80` is dead.

This is independently documented by the concurrent integration test `max_events_reports_truncation_notice` (`tests/integration.rs:710-736`, `#[ignore = "product bug: reader.rs never propagates events_truncated to ScanOutcome"]`) and admitted in README “Limits” (“this version does not flag that truncation on the dashboard”).

Repro (120-line fixture; cap 2, so 2 of ~28 rule events retained):
```bash
./target/release/sentinel tests/fixtures/attack_mix.log --no-color --max-events 2
# actual:   Threats      4 suspicious events  ·  4 unique offending IPs
# expected: same, plus "! Event or auth-failure storage cap reached — rerun with a higher --max-events…"
./target/release/sentinel demo/access-demo.log --no-color --max-events 5 | grep -c 'storage cap'
# 0
```
Failure side: a 520,000-line 401 log retains exactly 500,000 failures (BF evidence says `500000 failed logins`), drops 20,000, and prints no notice:
```bash
# 520k x 401 /login, one IP
./target/release/sentinel /tmp/qa/mem/fails.log --no-color --threads 1 | grep 'failed logins'
# Authentication brute force (BF-001) · 500000 failed logins in 300s (peak window)
```

Fix sketch (not applied): before returning from `scan_file_with_floor`, do
`outcome.events_truncated |= events_truncated.load(Ordering::Relaxed);` and the same for failures; also set the flag if the post-stateful total exceeds the cap (F3). Un-ignore the integration test once fixed.

### F2 — 404 flood evicts 401 brute-force evidence (High)

`FAILURE_CAP` is 500,000 (`src/parser/reader.rs:21`) and every 401/403/404 with a timestamp reserves a slot in scan order (`:393-410`). There is no priority for 401s, no per-IP fairness, and the cap is not configurable. On a 404-heavy site (image/CDN traffic easily produces hundreds of thousands of 404s), the budget fills with irrelevant records; later login failures are dropped, so BF-001 disappears without any indication (SCAN-001 only sees the 403/404 records that made the cut).

Verified end-to-end with 500,000 benign 404s followed by 60 `POST /login` 401s:
```bash
{ yes '24.114.1.5 - - [10/Oct/2000:13:55:36 -0700] "GET /missing.png HTTP/1.1" 404 0 "-" "Mozilla/5.0"' | head -n 500000
  yes '203.0.113.77 - - [10/Oct/2000:13:55:36 -0700] "POST /login HTTP/1.1" 401 59 "-" "python-requests/2.31.0"' | head -n 60
} > /tmp/404_then_401.log

./target/release/sentinel /tmp/404_then_401.log --no-color --threads 1
#   Threats      0 suspicious events  ·  0 unique offending IPs
#   │ ✓  No suspicious activity detected.                      │

# same 60 x 401 moved to the front of the file:
./target/release/sentinel /tmp/401_then_404.log --no-color --threads 1
#   Threats      1 ...
#   #1 ... Brute Force  401
#      Authentication brute force (BF-001) · 60 failed logins in 300s (peak window)
```
With 12 threads the same “404s first” file *does* report BF because the tail chunk wins the reservation race — see F6. So the miss is deterministic with `--threads 1` and scheduling-dependent at defaults; either way a security signal can vanish based on file order.

Recommended policy: reserve 401s (and 403s on login-looking paths) before generic 404s — e.g. a second pass or two counters — or expose `--max-failures`, or cap per-IP records. At minimum warn when the failure budget is exhausted (needs F1 fixed).

### F3 — `--max-events` is not a hard cap (Medium)

Stateful events are appended **after** the scan cap: `src/main.rs:70-75` does `let mut events = outcome.events; events.extend(engine.detect_bruteforce(...))`. With one BF event and one SCAN event per offending IP, the dashboard total can exceed the cap by up to `2 × unique IPs` (bounded by the 500 k failure set). The help text calls it a “Hard cap on stored threat events” (`src/cli.rs:166`), which is false.

Repro:
```bash
./target/release/sentinel demo/access-demo.log --no-color --max-events 5 | grep '^  Threats'
#   Threats      7 suspicious events  ·  3 unique offending IPs     (5 rule hits + BF + SCAN)
./target/release/sentinel tests/fixtures/attack_mix.log --no-color --max-events 2 | grep '^  Threats'
#   Threats      4 suspicious events  ·  4 unique offending IPs     (2 + BF + SCAN)
```
Fix: apply the budget after the stateful pass too (truncate or count BF/SCAN against the remainder) and adjust the help/README wording.

### F4 — Count cap does not bound memory (Medium)

The caps bound **record counts** (`--max-events` 250 k, `FAILURE_CAP` 500 k), not bytes. Each retained `ThreatEvent` clones the whole line (`raw`), `path`, `method` and `user_agent` (`src/parser/reader.rs:374-389`); a line that trips N rules stores N copies of `raw`. Every `AuthFailure` likewise clones `raw`/`path`/`user_agent` (`:397-406`). Main additionally materialises `boosts`, `scored`, a `(IpAddr,u64)` HashSet for top dedup, and keeps all `ChunkResult`s pooled until the end (`:174`, `:205-217`).

Measured with `/usr/bin/time -f '%M'` (12 threads unless noted):

| Input | Flags | Events | RSS |
|---|---|---|---|
| demo 112.4 MiB, benign-heavy | default | 379 | 23.2 MiB |
| demo | `--max-events 5` | 7 | 22.8 MiB |
| demo | `--threads 64 --chunk-mb 1` | 379 | 119.3 MiB |
| dense 14.3 MiB, 120 k hostile lines | `--max-events 5` | 5 | 10.0 MiB |
| dense | `--max-events 5 000` | 5 000 | 15.4 MiB |
| dense | `--max-events 50 000` | 50 000 | 57.8 MiB |
| dense | `--max-events 100 000` | 100 000 | 105.9 MiB |
| dense | default (250 k) | 250 000 | **250.6 MiB** |
| 520 k x 401, 52.1 MiB | default or `--max-events 1` | 1 (+500 k failures) | **202.5 MiB** |
| 500 k x 404 + 60 x 401, 45 MiB | default | 1 | 203.7 MiB |

The slope is linear: **≈0.97 KiB RSS per retained event** on 118-byte log lines (250 k events ≈ 250 MiB) and **≈0.39 KiB per retained failure** (500 k ≈ 200 MiB). Worker buffers add ~1.5 MiB each (1 MiB `BufReader` at `src/parser/reader.rs:307` plus stack/allocator): 1 thread = 13.9 MiB, 12 = 30.2 MiB, 64 = 119.3 MiB.

Consequence: a 1 GiB hostile log with ~1 KiB lines and several hits per line can reach the 250 k event cap and sit at ~250 MiB–1 GiB RSS; `--max-events 5000000` permits multi-GB heaps. It is a bounded DoS (not a leak), but the bound is count-based and undocumented in those terms. Recommendations: store `Arc<str>`/offsets instead of cloning `raw` per event; drop `user_agent`/`timestamp_raw` if unused; add a byte budget (e.g. stop retaining evidence after N bytes) or a lower default cap; consider per-IP caps. README, “How it works → Reading the file” (“memory is bounded by chunk size…”, at time of review) is inaccurate — chunk size does not allocate a chunk buffer; retention and worker buffers dominate.

### F5 — Escape injection through filenames in error paths (Low)

All log-controlled fields are sanitised before rendering: `sanitize` replaces every `char::is_control()` with a space (`src/ui/dashboard.rs:505-512`), applied to the path (`:97`), payload (`:306-325`) and evidence (`:348`). Verified with ESC/OSC/BEL in path, User-Agent, Referer, raw request, JSON `\u001b`, and the filename itself: **0 ESC and 0 BEL bytes** in stdout/stderr with `--no-color`; with `CLICOLOR_FORCE=1` all 168 ESC sequences were well-formed SGR (`ESC[…m`), none from data. A filename containing `\n` is collapsed to one line. Details in §5.

The gap is error text: `main` formats a path directly (`src/main.rs:51-54` → `eprintln!` at `:21`) and the prompt does the same (`src/ui/prompt.rs:130-150`). A directory named with `ESC]0;…BEL` prints the raw sequence to stderr:
```bash
d=$'/tmp/dir\x1b]0;PWNED\x07'; mkdir -p "$d"
./target/release/sentinel "$d" --no-color 2>&1 | xxd | grep -c '1b 5d 30 3b'
# 1  (raw ESC ] 0 ; in stderr)
```
Impact is low (the path is operator-supplied; the log content itself is safe), but a scanner run over attacker-influenced directory names should not emit OSC. Fix: run the same control-character replacement over paths in `fatal:` and prompt errors (or quote/escape them).

### F6 — Cap-bound output depends on scheduling (Low)

`reserve_event`/`reserve_failure` use `fetch_add` on a global counter (`src/parser/reader.rs:98,107`), so **which** records survive when a cap binds is determined by worker completion order, not file order. `main`’s top-list dedup and totals then depend on that subset.

Evidence:
* Synthetic 12 MiB / 12-chunk file, 60 hostile lines per chunk, `--chunk-mb 1 --threads 12 --max-events 100`, 20 runs: two distinct results, **20 vs 21 unique offending IPs** (event count always 100).
* The F2 file: `--threads 1` → 0 events (BF missed), `--threads 12` → 1 event (BF found), six runs stable at 12.

Repro for the first bullet (12 blocks of 60 hostile lines, padded to 1 MiB each):
```bash
for i in $(seq 20); do
  ./target/release/sentinel /tmp/qa/cap/cap.log --no-color --threads 12 \
    --chunk-mb 1 --max-events 100 | grep '^  Threats'
done | sort -u
# two distinct lines: "... 100 suspicious events · 20 unique offending IPs"
#                      "... 100 suspicious events · 21 unique offending IPs"
```

Untruncated runs are fully deterministic (see §6), so this only affects capped runs — but those are exactly the runs where a missed threat matters. Fix: reserve in chunk/line order (buffer per-chunk hits then merge in index order and apply the cap), or document that capped output is a sample.

### F7 — Unicode format characters pass sanitization (Low)

`sanitize` only checks `char::is_control()` (Unicode category Cc). Format characters such as U+202E RIGHT-TO-LEFT OVERRIDE, U+200B ZERO WIDTH SPACE and U+2066–U+2069 isolates are not replaced, so a payload can visually reorder or hide text on the terminal (Trojan-Source style spoofing). No escape sequence is executed. Repro: a path containing `\u202e` renders as `passwd\u202egnp.exe`. Fix: also replace `ch.is_control() || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200b}'..='\u{200f}')`.

### F8 — “workers” count is requested, not actual (Low)

`DashboardView.threads` is `opts.threads` (`src/main.rs:127`), while the reader clamps to `min(threads, chunk_count)` (`src/parser/reader.rs:157`). `--chunk-mb 1024` on the 112 MiB demo produces one chunk → one worker, but the dashboard says `12 workers`; wall time 2.42–2.48 s (single-thread speed) vs 0.60 s with 12 workers. Repro:
```bash
/usr/bin/time -f '%e s' ./target/release/sentinel demo/access-demo.log --no-color --chunk-mb 1024
# dashboard: "Execution 2.42 s · 12 workers"; effective workers = 1
```
Fix: return `worker_count` in `ScanOutcome` and display that (or “12 requested, 7 active”).

### F9 — Dead code / missing rationale (Info)

See §1. Besides the clippy noise, `scored.reasons` (e.g. “10 distinct rules within 300s from 45.13.2.9”, `src/scoring/mod.rs:69`) is never rendered; `detail_line` builds only rule name/id, multiplier and evidence (`src/ui/dashboard.rs:328-355`). Either show the reason or delete the field. `Category::Other` is never constructed, so the `Other` arm in the dashboard match is unreachable in practice.

### F10 — Dependency licence (Info)

`Cargo.toml:6` declares MIT and `LICENSE` is MIT, but `colored v2.2.0` is **MPL-2.0** (`~/.cargo/registry/src/*/colored-2.2.0/Cargo.toml:34`), not MIT/Apache. MPL-2.0 is file-level copyleft; linking is generally acceptable, but binary distribution should include the MPL notice/source for `colored`. Everything else resolved locally is MIT/Apache-2.0/Unlicense/Zlib/BSD. Add `THIRD_PARTY_LICENSES` or swap `colored` for an MIT/Apache crate (e.g. `owo-colors`, `anstyle`).

---

## 3. Robustness / edge-case matrix

All runs used `--no-color`, `--threads 4` unless noted; no command hung (5 s `timeout`).

| Case | Fixture | Result |
|---|---|---|
| missing file | `/tmp/.../missing.log` | exit 1, `fatal: No such file or directory (os error 2)` |
| directory | `/tmp/.../adir` | exit 1, `fatal: … is not a regular file` |
| permission denied | file `chmod 000` (uid 1000) | exit 1, `fatal: Permission denied (os error 13)` |
| empty file | 0 bytes | exit 0, `Lines 0 scanned · 0 malformed`, all-clear panel |
| blank lines only | `\n\n\n\n` | exit 0, 0 lines |
| no trailing newline | 2 valid lines | exit 0, 2 lines, 0 malformed |
| CRLF | 2 valid lines with `\r\n` | exit 0, 2 lines, 0 malformed |
| CR-only (classic Mac) | 2 records separated by `\r` | exit 0, **1** line, 0 malformed (whole file treated as one record; unsupported, undercounts) |
| line > 1 MiB | 1,048,676-byte line + valid line | exit 0, 2 lines, 1 malformed |
| binary bytes | NUL/0xFF/invalid UTF-8 + valid line | exit 0, 3 lines, 2 malformed, no panic |
| symlink → regular file | `link_ok` | accepted, 2 lines (metadata follows symlinks) |
| symlink → `/dev/zero` | `link_dev` | exit 1, not a regular file |
| symlink → directory | `link_dir` | exit 1, not a regular file |
| FIFO | `mkfifo` | exit 1 immediately, not a regular file (no open/block) |
| 3 MiB single line between valid lines | `bigline.log` | exit 0, 4 lines, 1 malformed, identical across 1/12 threads and 1/2/16 MiB chunks |
| prompt, stdin EOF | `</dev/null`, no path arg | exit 1, `fatal: no log path provided`, no hang |
| prompt, bad path then EOF | pipe `"/nope\n"` | one `✗ no such file` then fatal `no log path provided` |
| prompt, quoted path with spaces | `"/tmp/qa/space name.log"` | accepted, scanned |
| prompt, `~/…` | `"~/nginx-sentinel/demo/access-demo.log"` | expanded, scanned |
| broken pipe / closed stdout | `| head -1`, `>&-` | exit 0, no panic (banner/dashboard ignore write errors; Rust std handles closed fd 0–2) |
| hostile filename | ESC/BEL + `\n` in name | dashboard renders one line, 0 ESC/BEL (error path differs, F5) |

Parser total-ness: the only non-test panic-capable sites are `RegexSet::new`/`Regex::new` `.expect` on static rule patterns and the progress-template `.expect` (`src/detection/rule.rs:251,255`, `src/ui/progress.rs:35`) — all startup fail-fast on compile-time constants, covered by every test run. No `unwrap()` on user data, no `unsafe` in `src/`, no slicing that can hit a non-char boundary (all slices are anchored on ASCII delimiters or guarded by `is_char_boundary`/`get`).

## 4. CLI validation

All invalid inputs exit 1 with a clear `fatal:` message; no panic, no hang. Tested:

| Flag | Values tried | Behaviour |
|---|---|---|
| `--threads` | 0, -1, 65, 999999999999999999999, `abc`, missing value (next arg was the path) | rejected, 0/65 by range, negatives/huge/non-numeric by parse, missing value reports the consumed path |
| `--top` | 0, 101, -5 | rejected; `--top 100` renders exactly 100 rows |
| `--window` | 0, 86401, -1, `1e3` | rejected; `--window 1` removes BF/SCAN events (379→377) |
| `--threshold` | 0, 1000001, -2 | rejected; `--threshold 1000` removes BF/SCAN (379→377) |
| `--chunk-mb` | 0, 1025, -1 | rejected |
| `--max-events` | 0, 5000001, -9 | rejected |
| unknown | `--bogus`, `-x`, `--no-color=true`, `--` | `fatal: unknown option …` (for `--no-color=true` the `=true` suffix is lost in the message) |
| extra args | `path extra.log` | `fatal: unexpected extra argument "extra.log"` |
| inline values | `--threads=4 --top=3` | accepted |
| `-` | `-` | treated as a filename → NotFound (no stdin support) |
| path starting with `-` | `-x.log` | impossible without `./`; no `--` end-of-options separator |

Notes: help says `--threads` default “auto, max 16” while explicit values up to 64 are accepted — consistent with `Options::default().clamp(1,16)` but easy to misread. `fatal: No such file or directory` does not echo the path (the prompt’s errors do), which is a small UX regression for mistyped paths.

## 5. Terminal / ANSI injection (detail)

Craft file (`/tmp/qa/ansi/evil.log`) contained five lines:
1. raw `ESC[31m` + `ESC]0;PWNED BEL` in the request target, with `../../etc/passwd` so rules fire;
2. nginx-escaped `\x1b[32m\x1b]0;T2\x07` in the target (exercises `unescape`);
3. OSC in Referer and User-Agent on an XSS line;
4. `ESC[2J ESC[H` (clear-screen) in the request target;
5. JSON line with `\u001b` in `request` and `http_user_agent`.

Also scanned a copy whose **filename** was `evil ESC ]0;FILENAME BEL .log`, and a filename containing a newline.

Results (`--no-color`, stdout+stderr captured separately):
* stdout ESC = 0, BEL = 0; stderr ESC = 0, BEL = 0.
* Filename with newline: `Log file /tmp/qa/name/line1 line2 [31m.log` — one line, ESC replaced by space.
* With `CLICOLOR_FORCE=1`: 168 ESC bytes, **all** matched `ESC\[[0-9;]*m` (SGR), 0 OSC/other sequences. No data-controlled escape survived.
* Only exception: fatal/prompt error strings that interpolate the path (F5) — one ESC and one BEL observed on stderr for a directory named with `ESC]0;ERR BEL`.

Evidence artefacts (ephemeral): `/tmp/qa/ansi/evil.log`, `/tmp/qa/ansi/evil.stdout.bin`, `/tmp/qa/name/`.

## 6. Determinism

* Demo log, `--threads 1,2,4,8,12 --chunk-mb 8`: `Lines 600,219 · 3 malformed`, `Threats 379 · 9 unique IPs` in all runs; full output identical after removing the `Execution`/`Throughput` lines (`diff` empty, same SHA-256). Top-10 ordering identical.
* Synthetic 4.1 MiB mixed log (12,000 lines, hostile every 37/53/71), `--chunk-mb 1/2/16`, `--threads 1/3/8/12`: identical normalized output hash `2e8dcde1e95bf83d`.
* 3.1 MiB file with one 3 MiB line spanning chunks + valid lines: identical hash `75e7023d7cc0a34d` across 1/12 threads and 1/2/16 MiB chunks; `4 lines, 1 malformed` every time.
* The declared total order (`final_score` desc, severity desc, timestamp asc/none last, line asc, IP asc, rule id asc; `src/scoring/mod.rs:107-120`) is genuinely total: no duplicate `(line, rule_id)` pairs exist, so `sort_by` is deterministic. `context::boosts` iterates a `HashMap` but writes results by input index, so iteration order does not leak.
* **Caveat:** capped runs are not deterministic (F6). Untruncated determinism does not extend to `--max-events`/failure-cap saturation.

## 7. Performance (demo log, 112.37 MiB, 600,219 lines)

3 runs each, median; `/usr/bin/time -f '%e %U %S %M'`; load average ~4.1–4.3 (other agents active). `--chunk-mb 8`:

| Threads | Wall | User | Sys | RSS | Lines/s | Speed-up |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2.56 s | 2.49 s | 0.06 s | 13.9 MiB | 234,461 | 1.00× |
| 4 | 0.99 s | 3.30 s | 0.08 s | 18.3 MiB | 606,282 | 2.59× |
| 8 | 0.60 s | 3.70 s | 0.11 s | 24.1 MiB | 1,000,365 | 4.27× |
| 12 | 0.60 s | 4.14 s | 0.12 s | 30.2 MiB | 1,000,365 | 4.27× |

Default flags (12 threads, 16 MiB chunks), 3 runs: 0.66–0.71 s (median 0.70 s), 857 k lines/s, RSS 23.2 MiB. The machine is 8 cores/12 threads, so 8 workers saturate; 12 adds ~10 % CPU for no wall gain.

Chunk sweep (12 threads, medians): 1 MiB 0.58 s, 2 MiB 0.55 s, 4 MiB 0.57 s, 8 MiB 0.62 s, 16 MiB 0.60 s, **32 MiB 0.96 s** (only 4 chunks for 12 workers). Default 16 MiB is fine for large logs but under-parallelises medium files: effective workers = `min(threads, ceil(size/chunk))`, so a 50 MiB log uses 4 workers and `--chunk-mb 1024` uses one (2.48 s). Consider auto-sizing the chunk to `max(1 MiB, size / (threads*2))`.

Long-line throughput (single thread, includes ~60 ms startup): 8.6 MiB of 900 KiB traversal lines 0.93 s (9.6 MB/s), 8.6 MiB of 900 KiB benign lines 0.42 s (21.6 MB/s), 10.3 MiB of short benign lines 0.28 s (39.1 MB/s, 360 k lines/s). Regex behaviour is linear — a 900 KiB line with `../` repeated, `%2e` repeated, or a long `a` run each took 0.13–0.19 s including startup; no exponential backtracking (the `regex` crate is linear-time by construction, and the engine uses `RegexSet` + individual `Regex::find` only on hits). There is no ReDoS path.

Two easy engine optimisations (not defects): `Matcher::scan` calls `set.is_match(haystack)` and then `set.matches(haystack)`, scanning each scope twice (`src/detection/rule.rs:319-323`); use `matches()` once and `matched_any()`. `InspectionContext::new` always percent-decodes and lowercases twice plus extracts the query (`src/detection/rule.rs:189-196`); fast-path when the target contains no `%`/`+`. Neither changes results.

## 8. Memory-cap mechanism (from code)

* `scan_file_with_floor` validates the path, takes `metadata.len()`, and splits the file into `chunk_bytes` ranges (`src/parser/reader.rs:132-157`). Each worker opens the file, seeks to its range (skipping a leading partial line unless the previous byte is `\n`), and reads lines with a 1 MiB `BufReader` (`:286-351`, `:432-456`). Only one line is buffered at a time; a line over 1 MiB is counted malformed and discarded (`:327-333`).
* Retention is governed by two global `AtomicU64` counters and two `AtomicBool` flags (`:159-171`). `reserve_event`/`reserve_failure` do `fetch_add` and return true only for the first `max_events`/`FAILURE_CAP` reservations, so the **sum across workers** cannot exceed the counts even though each worker accumulates into its own `ChunkResult` (`:97-113`, `:370-410`).
* All `ChunkResult`s are collected into `results: Vec<Option<ChunkResult>>` (`:174`) and then moved into one `ScanOutcome` (`:224-244`); there is no streaming aggregation, so peak memory holds every retained event/failure plus per-chunk `Vec` overhead. `main` then builds `boosts`, `scored`, the top-dedup `HashSet` and the top list (`src/main.rs:77-118`).
* Therefore memory ≈ `baseline (~8–10 MiB, regex automata) + workers × ~1.5 MiB + retained_events × ~1 KiB + retained_failures × ~0.4 KiB`. The demo (1,106 failures, 379 events) lands at 23.2 MiB. The count caps make this finite, but not small: 250 k events ≈ 240 MiB of event storage, 500 k failures ≈ 190 MiB, and both can be live at once (worst case ~430 MiB plus the log's own page cache). `--max-events 5000000` allows ~5 GiB. This is a memory-exhaustion risk for an adversary-controlled log, not a leak: all records are dropped at process exit.

Truncation is **not** reported (F1), so a user cannot tell a 250 k-event run from a complete one.

## 9. Demo artifact & dependency review

**Generator** (`scripts/gen_demo_log.py`): Python stdlib only (`argparse`, `random`, `datetime`, `os`); no `socket`/`urllib`/`requests`, no `subprocess`, no `remove`/`rmtree`; fixed seed 1337; writes only `--out` (default `demo/access-demo.log`) and `os.makedirs` its parent. Regenerating to `/tmp/qa/regen.log` produced a byte-identical file:
```
f1d862eee7253f791fce352b7ba40160a50cd6844eee0084623265f47e1675e4  demo/access-demo.log
f1d862eee7253f791fce352b7ba40160a50cd6844eee0084623265f47e1675e4  /tmp/qa/regen.log
600,219 lines, 112.4 MiB, 216 hostile requests, 9 source IPs, 3 malformed
```
Per-IP hostile counts match the generator: 12, 9, 8, 120, 46, 5, 5, 8, 3.

**`.gitignore`**: `/target` and `/demo/*.log` — covers the demo log. There is **no `.git` directory** in `/home/seun/nginx-sentinel` (`git status` → `fatal: not a git repository`), so `git check-ignore` could not be run; the ignore status is inferred from the file only. `tests/fixtures/*.log` are intentionally not ignored.

**Dependencies** (`Cargo.lock`): 4 direct deps — `chrono 0.4.45`, `colored 2.2.0`, `indicatif 0.17.11`, `regex 1.13.1`. 61 locked packages, of which **19 compile on Linux** (root + 18); the rest are target-gated Windows/wasm/android crates pulled by `chrono`/`console`/`indicatif`. `cargo tree -d` reports no duplicate versions; 61/61 registry packages have checksums; no `source = "git…"` or path dependencies; no build script in this crate. `cc`/`find-msvc-tools` are not in the host graph (target-only). No supply-chain red flags. `cargo audit` is not installed (`error: no such command: audit`) and was skipped; given the small, current, heavily used dependency set, a CI `cargo audit`/`cargo deny` job is still worthwhile.

Licences of locally resolvable packages: 13 MIT OR Apache-2.0, 3 MIT, 2 Unlicense OR MIT, 2 Apache-2.0 OR MIT, 1 MPL-2.0 (`colored`). The 40 packages without local sources are Windows/wasm/android target crates plus a few host build deps (all standard MIT/Apache projects). See F10 for the MPL notice.

## 10. Recommended fixes (priority order)

1. **Propagate truncation flags** (F1): after the scan, `outcome.events_truncated |= events_truncated.load(Relaxed)` and the same for failures; also set it when the post-stateful total exceeds the cap. Un-ignore `max_events_reports_truncation_notice` (`tests/integration.rs:718`). This is a ~3-line fix with an existing test.
2. **Make `--max-events` a true cap** (F3): apply the budget after `detect_bruteforce`, or count BF/SCAN events against the remaining slots; update the help string and README.
3. **Fix failure-budget policy** (F2): reserve 401s (and login-path 403s) before generic 404s, or add a per-IP cap, or expose `--max-failures`; at minimum log/warn when the budget is full and document the eviction order.
4. **Reduce per-record memory** (F4): store `Arc<str>`/`(chunk,offset)` instead of cloning `raw` per event, drop `user_agent`/`timestamp_raw` if they stay unused, and/or add a byte budget. Consider lowering the 5 M `--max-events` ceiling.
5. **Sanitize paths in errors** (F5): reuse the dashboard’s control-character replacement for `fatal:` and prompt messages.
6. **Deterministic capped retention** (F6): merge per-chunk results in index order and apply the cap there, or document that capped output is a scheduling-dependent sample.
7. **Clean up warnings** (F9): `#[allow(dead_code)]` with a reason for retained API, delete the rest, apply the four clippy suggestions, and either render `scored.reasons` or remove it.
8. **Licence notice** (F10): add `THIRD_PARTY_LICENSES` mentioning `colored` MPL-2.0, or replace `colored` with an MIT/Apache crate.
9. **Performance polish**: single `RegexSet::matches` call per scope; skip the second decode when no `%` remains; auto-size chunks for medium files; display actual worker count; add `--` end-of-options if paths starting with `-` matter.
10. **Minor correctness/UX**: `+` should decode to space only in the query, not the path (`src/detection/rule.rs:434-437`); CR-only logs are one record; `fatal: No such file…` should name the path.

## 11. What was actually run vs inferred

**Run and observed:** every command in §1–§9; `cargo check/clippy/test` (debug and release, with `--ignored`); all CLI validation cases; the full edge-case matrix; prompt EOF/quoted/`~` cases; ANSI probes with and without `CLICOLOR_FORCE`; `--max-events` sweeps and RSS measurements via `/usr/bin/time`; thread and chunk sweeps; 3 MiB single-line and 4.1 MiB boundary determinism comparisons; 20-run cap-nondeterminism probe; demo regeneration + SHA-256; licence metadata from the local cargo registry; `cargo tree -d`; lockfile checksum/git-source scan; source grep for process/network/unsafe/panic sites.

**Inferred, not measured:** worst-case RSS for multi-GB hostile logs (extrapolated from the measured ~1 KiB/event and ~0.4 KiB/failure slopes); `results` vector growth for absurdly large sparse files (`O(chunks)`; a 1 PB sparse file would allocate ~80 GB before reading); TOCTOU between `metadata()` and per-chunk `File::open` (a path swapped to a FIFO could block a worker); licence obligations; `cargo audit` results (tool absent); git-ignore enforcement (no `.git`).

**Concurrent activity:** other agents added `tests/integration.rs` (+17 tests, now green except the intentionally ignored product-bug test), `README.md`, `LICENSE`, `docs/detections.md` and `docs/validation-report.md` during this review. Test counts and line numbers reflect the tree at 12:22 MST; `src/` was not modified by me (`docs/qa-report.md` is the only file written).
