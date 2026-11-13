use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;

use crate::detection::RuleEngine;
use crate::model::entry::{AuthFailure, LogEntry};
use crate::model::threat::{RuleHit, ThreatEvent};

use super::parse::{parse_line, MAX_LINE_BYTES};

/// Production floor for `ScanConfig::chunk_bytes`: tiny chunks would create
/// more scheduling overhead than parse work.
const MIN_CHUNK_BYTES: u64 = 1024 * 1024;
const READER_CAPACITY: usize = 1024 * 1024;
const MAX_WORKERS: usize = 64;
/// Fixed retention caps for 401/403/404 records, independent of `max_events`.
/// 401/403 records are kept separately from 404 probes so a flood of missing
/// assets cannot evict the auth failures the brute-force detector needs.
const AUTH_FAILURE_CAP: usize = 400_000;
const PROBE_FAILURE_CAP: usize = 100_000;
const FAILURE_CAP: usize = AUTH_FAILURE_CAP + PROBE_FAILURE_CAP;

/// Knobs for the parallel scan.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Maximum worker threads.
    pub threads: usize,
    /// Byte size of one read chunk; larger chunks mean fewer, longer tasks.
    pub chunk_bytes: u64,
    /// Hard cap on retained threat events; extra hits set `events_truncated`.
    pub max_events: usize,
}

/// Callback used by the reader to drive a live progress display. Must be
/// cheap and thread-safe: `add_bytes` is called from every worker.
pub trait ProgressSink: Send + Sync {
    fn set_total(&self, total_bytes: u64);
    fn add_bytes(&self, delta: u64);
    fn finished(&self);
}

/// Silent progress sink for tests and library use.
#[allow(dead_code)]
pub struct NoopProgress;

impl ProgressSink for NoopProgress {
    fn set_total(&self, _total_bytes: u64) {}
    fn add_bytes(&self, _delta: u64) {}
    fn finished(&self) {}
}

#[derive(Debug, Clone)]
pub struct ScanOutcome {
    /// Every non-empty line the scanner attempted to parse.
    pub total_lines: u64,
    /// Lines that did not match any supported access-log layout.
    pub malformed_lines: u64,
    /// Bytes accounted for by the scan; equal to the file size.
    #[allow(dead_code)]
    pub bytes_read: u64,
    /// Worker threads that actually participated in the scan.
    pub workers: usize,
    pub events: Vec<ThreatEvent>,
    /// 401/403/404 responses retained for stateful brute-force / scan analysis.
    pub auth_failures: Vec<AuthFailure>,
    pub events_truncated: bool,
    pub failures_truncated: bool,
}

/// Scan an nginx access log at maximum practical throughput.
///
/// Implementation requirements (kept here as the contract):
/// - Read the file in `chunk_bytes` byte ranges processed by `threads` workers.
/// - Each range starts on a line boundary *logically*: workers skip a leading
///   partial line (unless the range starts at byte 0 or right after a newline)
///   and fully process a trailing line that starts inside their range.
/// - Returned events/failures carry line numbers rebased to the whole file.
/// - Memory stays bounded by chunk size; only parsed entries, rule hits and
///   capped failure records are retained.
pub fn scan_file(
    path: &Path,
    cfg: &ScanConfig,
    engine: &RuleEngine,
    progress: &dyn ProgressSink,
) -> io::Result<ScanOutcome> {
    scan_file_with_floor(path, cfg, engine, progress, MIN_CHUNK_BYTES)
}

/// Shared per-scan reservation counters. Every retained record consumes one
/// slot from a global budget, so concurrent workers cannot collectively exceed
/// the memory cap regardless of read order.
struct Budgets<'a> {
    max_events: u64,
    max_auth_failures: u64,
    max_probe_failures: u64,
    event_slots: &'a AtomicU64,
    auth_slots: &'a AtomicU64,
    probe_slots: &'a AtomicU64,
    events_truncated: &'a AtomicBool,
    failures_truncated: &'a AtomicBool,
}

impl Budgets<'_> {
    fn reserve_event(&self) -> bool {
        if self.event_slots.fetch_add(1, Ordering::Relaxed) < self.max_events {
            true
        } else {
            self.events_truncated.store(true, Ordering::Relaxed);
            false
        }
    }

    fn reserve_failure(&self, status: u16) -> bool {
        // 404s are probe noise; 401/403 are the records the auth detector
        // depends on. Separate counters keep one class from starving the other.
        let (slots, max) = if status == 404 {
            (self.probe_slots, self.max_probe_failures)
        } else {
            (self.auth_slots, self.max_auth_failures)
        };
        if slots.fetch_add(1, Ordering::Relaxed) < max {
            true
        } else {
            self.failures_truncated.store(true, Ordering::Relaxed);
            false
        }
    }
}

#[derive(Debug, Default)]
struct ChunkResult {
    lines: u64,
    malformed: u64,
    events: Vec<ThreatEvent>,
    failures: Vec<AuthFailure>,
    error: Option<io::Error>,
}

fn scan_file_with_floor(
    path: &Path,
    cfg: &ScanConfig,
    engine: &RuleEngine,
    progress: &dyn ProgressSink,
    min_chunk_bytes: u64,
) -> io::Result<ScanOutcome> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let size = metadata.len();
    progress.set_total(size);
    if size == 0 {
        return Ok(empty_outcome(size));
    }

    let chunk_bytes = cfg.chunk_bytes.max(min_chunk_bytes).max(1);
    let threads = cfg.threads.clamp(1, MAX_WORKERS);
    let chunks_total = size.div_ceil(chunk_bytes);
    if chunks_total == 0 {
        return Ok(empty_outcome(size));
    }
    let chunk_count = usize::try_from(chunks_total).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "log file is too large to scan on this platform",
        )
    })?;
    let worker_count = threads.min(chunk_count).max(1);

    let next_chunk = AtomicU64::new(0);
    let event_slots = AtomicU64::new(0);
    let auth_slots = AtomicU64::new(0);
    let probe_slots = AtomicU64::new(0);
    let events_truncated = AtomicBool::new(false);
    let failures_truncated = AtomicBool::new(false);
    let budgets = Budgets {
        max_events: cfg.max_events.max(1) as u64,
        max_auth_failures: AUTH_FAILURE_CAP as u64,
        max_probe_failures: PROBE_FAILURE_CAP as u64,
        event_slots: &event_slots,
        auth_slots: &auth_slots,
        probe_slots: &probe_slots,
        events_truncated: &events_truncated,
        failures_truncated: &failures_truncated,
    };

    let (tx, rx) = mpsc::channel::<(u64, ChunkResult)>();
    let mut results: Vec<Option<ChunkResult>> = (0..chunk_count).map(|_| None).collect();
    let mut closed_early = false;

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let tx = tx.clone();
            let next_chunk = &next_chunk;
            let budgets = &budgets;
            scope.spawn(move || loop {
                let index = next_chunk.fetch_add(1, Ordering::Relaxed);
                if index >= chunks_total {
                    break;
                }
                let start = index * chunk_bytes;
                let end = (start + chunk_bytes).min(size);
                let result = match catch_unwind(AssertUnwindSafe(|| {
                    process_chunk(path, start, end, engine, progress, budgets)
                })) {
                    Ok(result) => result,
                    Err(_) => ChunkResult {
                        error: Some(io::Error::other("parser worker panicked")),
                        ..ChunkResult::default()
                    },
                };
                if tx.send((index, result)).is_err() {
                    break;
                }
            });
        }
        drop(tx);

        for _ in 0..chunks_total {
            match rx.recv() {
                Ok((index, result)) => {
                    if let Some(slot) = results.get_mut(index as usize) {
                        *slot = Some(result);
                    }
                }
                Err(_) => {
                    closed_early = true;
                    break;
                }
            }
        }
    });

    if closed_early {
        return Err(io::Error::other("parser worker panicked"));
    }

    let mut outcome = empty_outcome(size);
    outcome.workers = worker_count;
    let mut base_lines = 0u64;
    for slot in results {
        let Some(mut chunk) = slot else {
            return Err(io::Error::other("parser worker panicked"));
        };
        if let Some(error) = chunk.error.take() {
            return Err(error);
        }
        for event in &mut chunk.events {
            event.line_no = event.line_no.saturating_add(base_lines);
        }
        for failure in &mut chunk.failures {
            failure.line_no = failure.line_no.saturating_add(base_lines);
        }
        outcome.total_lines += chunk.lines;
        outcome.malformed_lines += chunk.malformed;
        outcome.events.extend(chunk.events);
        outcome.auth_failures.extend(chunk.failures);
        base_lines += chunk.lines;
    }

    // Workers set these atomics when a budget is exhausted; copy them into the
    // outcome before the defensive trims so the dashboard can actually warn.
    outcome.events_truncated = events_truncated.load(Ordering::Relaxed);
    outcome.failures_truncated = failures_truncated.load(Ordering::Relaxed);

    // Defensive trim; workers already reserve against these budgets.
    if outcome.events.len() > cfg.max_events {
        outcome.events.truncate(cfg.max_events);
        outcome.events_truncated = true;
    }
    if outcome.auth_failures.len() > FAILURE_CAP {
        outcome.auth_failures.truncate(FAILURE_CAP);
        outcome.failures_truncated = true;
    }

    Ok(outcome)
}

fn empty_outcome(size: u64) -> ScanOutcome {
    ScanOutcome {
        total_lines: 0,
        malformed_lines: 0,
        bytes_read: size,
        workers: 0,
        events: Vec::new(),
        auth_failures: Vec::new(),
        events_truncated: false,
        failures_truncated: false,
    }
}

fn process_chunk(
    path: &Path,
    start: u64,
    end: u64,
    engine: &RuleEngine,
    progress: &dyn ProgressSink,
    budgets: &Budgets<'_>,
) -> ChunkResult {
    let mut result = ChunkResult::default();
    if let Err(error) = read_chunk(path, start, end, engine, progress, budgets, &mut result) {
        result.error = Some(error);
    }
    result
}

fn read_chunk(
    path: &Path,
    start: u64,
    end: u64,
    engine: &RuleEngine,
    progress: &dyn ProgressSink,
    budgets: &Budgets<'_>,
    result: &mut ChunkResult,
) -> io::Result<()> {
    let mut file = File::open(path)?;

    // Decide whether the byte before this range belongs to a line that a
    // previous chunk already owns.
    let mut skip_partial = false;
    if start > 0 {
        file.seek(SeekFrom::Start(start - 1))?;
        let mut previous = [0u8; 1];
        file.read_exact(&mut previous)?;
        skip_partial = previous[0] != b'\n';
    }
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::with_capacity(READER_CAPACITY, file);

    let span = end - start;
    let mut pos = start;
    let mut reported = 0u64;
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);

    if skip_partial {
        let skipped = read_line_capped(&mut reader, &mut buf, MAX_LINE_BYTES)?;
        pos = pos.saturating_add(skipped as u64);
        report_progress(progress, &mut reported, pos, start, span);
    }

    while pos < end {
        let consumed = read_line_capped(&mut reader, &mut buf, MAX_LINE_BYTES)?;
        if consumed == 0 {
            break;
        }
        pos = pos.saturating_add(consumed as u64);

        if consumed > MAX_LINE_BYTES {
            // Over-long line: counted, never buffered in full, never parsed.
            result.lines += 1;
            result.malformed += 1;
            report_progress(progress, &mut reported, pos, start, span);
            continue;
        }

        let text = String::from_utf8_lossy(&buf);
        let line = text.trim();
        if !line.is_empty() {
            result.lines += 1;
            let line_no = result.lines;
            match parse_line(line, line_no) {
                Some(entry) => process_entry(&entry, engine, budgets, result),
                None => result.malformed += 1,
            }
        }

        report_progress(progress, &mut reported, pos, start, span);
    }

    report_progress(progress, &mut reported, pos, start, span);
    Ok(())
}

fn process_entry(
    entry: &LogEntry,
    engine: &RuleEngine,
    budgets: &Budgets<'_>,
    result: &mut ChunkResult,
) {
    let hits = engine.inspect(entry);
    record_hits(entry, &hits, budgets, result);
    record_auth_failure(entry, budgets, result);
}

fn record_hits(
    entry: &LogEntry,
    hits: &[RuleHit],
    budgets: &Budgets<'_>,
    result: &mut ChunkResult,
) {
    for hit in hits {
        if !budgets.reserve_event() {
            continue;
        }
        result.events.push(ThreatEvent {
            line_no: entry.line_no,
            timestamp: entry.timestamp,
            timestamp_raw: entry.timestamp_raw.clone(),
            source_ip: entry.source_ip,
            category: hit.category,
            rule_id: hit.rule_id,
            rule_name: hit.rule_name,
            severity: hit.severity,
            evidence: hit.evidence.clone(),
            method: entry.method.clone(),
            path: entry.path.clone(),
            status: entry.status,
            user_agent: entry.user_agent.clone(),
            raw: entry.raw.clone(),
        });
    }
}

fn record_auth_failure(entry: &LogEntry, budgets: &Budgets<'_>, result: &mut ChunkResult) {
    if matches!(entry.status, 401 | 403 | 404) {
        if let Some(timestamp) = entry.timestamp {
            if budgets.reserve_failure(entry.status) {
                result.failures.push(AuthFailure {
                    line_no: entry.line_no,
                    source_ip: entry.source_ip,
                    timestamp,
                    status: entry.status,
                    method: entry.method.clone(),
                    path: entry.path.clone(),
                    user_agent: entry.user_agent.clone(),
                    raw: entry.raw.clone(),
                });
            }
        }
    }
}

/// Report progress for one chunk. `target` is clamped to the chunk's own byte
/// range, so the sum of `add_bytes` over all chunks equals the file size even
/// when a line spans several ranges.
fn report_progress(
    progress: &dyn ProgressSink,
    reported: &mut u64,
    pos: u64,
    start: u64,
    span: u64,
) {
    let target = pos.saturating_sub(start).min(span);
    if target > *reported {
        progress.add_bytes(target - *reported);
        *reported = target;
    }
}

/// Read one line, keeping at most `limit` bytes in `buf` while still consuming
/// the rest of an over-long line. Returns the number of bytes consumed,
/// including the trailing newline when present.
fn read_line_capped<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> io::Result<usize> {
    buf.clear();
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(total);
        }
        let newline = available.iter().position(|&byte| byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if buf.len() < limit {
            let room = limit - buf.len();
            buf.extend_from_slice(&available[..room.min(take)]);
        }
        reader.consume(take);
        total = total.saturating_add(take);
        if newline.is_some() {
            return Ok(total);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::parse::MAX_LINE_BYTES;
    use super::*;

    const TS: &str = "10/Oct/2000:13:55:36 -0700";

    struct CountingSink {
        total: AtomicU64,
        bytes: AtomicU64,
        set_total_calls: AtomicU64,
        finished: AtomicBool,
    }

    impl CountingSink {
        fn new() -> Self {
            Self {
                total: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                set_total_calls: AtomicU64::new(0),
                finished: AtomicBool::new(false),
            }
        }
    }

    impl ProgressSink for CountingSink {
        fn set_total(&self, total_bytes: u64) {
            self.total.store(total_bytes, Ordering::SeqCst);
            self.set_total_calls.fetch_add(1, Ordering::SeqCst);
        }

        fn add_bytes(&self, delta: u64) {
            self.bytes.fetch_add(delta, Ordering::SeqCst);
        }

        fn finished(&self) {
            self.finished.store(true, Ordering::SeqCst);
        }
    }

    fn unique_temp_path(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "thresh-parser-{tag}-{}-{nanos}-{sequence}.log",
            std::process::id()
        ))
    }

    fn small_config(threads: usize, chunk_bytes: u64) -> ScanConfig {
        ScanConfig {
            threads,
            chunk_bytes,
            max_events: 250_000,
        }
    }

    /// Build a log with blank, malformed and valid lines of widely varying
    /// length. Returns content plus the expected counters.
    fn build_mixed_log() -> (String, u64, u64, Vec<(u64, u16)>) {
        let mut content = String::new();
        let mut total = 0u64;
        let mut malformed = 0u64;
        let mut failures: Vec<(u64, u16)> = Vec::new();

        for i in 0..200u64 {
            match i % 10 {
                0 => content.push('\n'),
                3 | 7 => {
                    content.push_str(&format!("this line is definitely not nginx {i}\n"));
                    total += 1;
                    malformed += 1;
                }
                _ => {
                    let status = match i % 3 {
                        0 => 404u16,
                        1 => 200u16,
                        _ => 403u16,
                    };
                    let ua_len = if i == 25 { 5000 } else { (i % 41) as usize };
                    let ua = "u".repeat(ua_len);
                    let path = format!("/item/{i}?q={}", "x".repeat((i % 29) as usize));
                    content.push_str(&format!(
                        "10.0.0.{} - - [{TS}] \"GET {path} HTTP/1.1\" {status} {} \"-\" \"{ua}\"\n",
                        (i % 250) + 1,
                        i * 7
                    ));
                    total += 1;
                    if matches!(status, 401 | 403 | 404) {
                        failures.push((total, status));
                    }
                }
            }
        }
        (content, total, malformed, failures)
    }

    #[test]
    fn empty_file_yields_empty_outcome() {
        let path = unique_temp_path("empty");
        std::fs::write(&path, b"").expect("write temp file");
        let sink = CountingSink::new();
        let engine = RuleEngine::new();
        let outcome = scan_file(&path, &small_config(4, 97), &engine, &sink).expect("scan");
        let _ = std::fs::remove_file(&path);

        assert_eq!(outcome.total_lines, 0);
        assert_eq!(outcome.malformed_lines, 0);
        assert_eq!(outcome.bytes_read, 0);
        assert!(outcome.events.is_empty());
        assert!(outcome.auth_failures.is_empty());
        assert_eq!(sink.total.load(Ordering::SeqCst), 0);
        assert_eq!(sink.bytes.load(Ordering::SeqCst), 0);
        assert_eq!(sink.set_total_calls.load(Ordering::SeqCst), 1);
        assert!(!sink.finished.load(Ordering::SeqCst));
    }

    #[test]
    fn multi_chunk_scan_counts_and_orders_correctly() {
        let (content, expected_total, expected_malformed, expected_failures) = build_mixed_log();
        let path = unique_temp_path("mixed");
        std::fs::write(&path, content.as_bytes()).expect("write temp file");
        let file_size = std::fs::metadata(&path).expect("metadata").len();

        let sink = CountingSink::new();
        let engine = RuleEngine::new();
        // Floor of 1 byte exposes the chunk-boundary logic; production floors
        // at 1 MiB, which a test file of this size would never cross.
        let outcome =
            scan_file_with_floor(&path, &small_config(8, 97), &engine, &sink, 1).expect("scan");
        let _ = std::fs::remove_file(&path);

        assert_eq!(outcome.total_lines, expected_total);
        assert_eq!(outcome.malformed_lines, expected_malformed);
        assert_eq!(outcome.bytes_read, file_size);
        assert_eq!(sink.total.load(Ordering::SeqCst), file_size);
        assert_eq!(sink.bytes.load(Ordering::SeqCst), file_size);
        assert_eq!(sink.set_total_calls.load(Ordering::SeqCst), 1);
        assert!(!sink.finished.load(Ordering::SeqCst));
        assert!(!outcome.events_truncated);
        assert!(!outcome.failures_truncated);

        let observed: Vec<(u64, u16)> = outcome
            .auth_failures
            .iter()
            .map(|failure| (failure.line_no, failure.status))
            .collect();
        assert_eq!(observed, expected_failures);
        assert!(outcome
            .auth_failures
            .iter()
            .all(|failure| failure.timestamp.to_string().contains("2000")));

        if engine.rule_count() == 0 {
            assert!(outcome.events.is_empty());
        }
    }

    #[test]
    fn thread_count_does_not_change_results() {
        let (content, expected_total, expected_malformed, expected_failures) = build_mixed_log();
        let path = unique_temp_path("threads");
        std::fs::write(&path, content.as_bytes()).expect("write temp file");
        let engine = RuleEngine::new();
        let single_sink = CountingSink::new();
        let parallel_sink = CountingSink::new();

        let single = scan_file_with_floor(&path, &small_config(1, 97), &engine, &single_sink, 1)
            .expect("single-thread scan");
        let parallel =
            scan_file_with_floor(&path, &small_config(16, 97), &engine, &parallel_sink, 1)
                .expect("parallel scan");
        let _ = std::fs::remove_file(&path);

        assert_eq!(single.total_lines, expected_total);
        assert_eq!(parallel.total_lines, expected_total);
        assert_eq!(single.malformed_lines, expected_malformed);
        assert_eq!(parallel.malformed_lines, expected_malformed);
        assert_eq!(
            single
                .auth_failures
                .iter()
                .map(|failure| (failure.line_no, failure.status))
                .collect::<Vec<_>>(),
            expected_failures
        );
        assert_eq!(
            single
                .auth_failures
                .iter()
                .map(|failure| (failure.line_no, failure.status))
                .collect::<Vec<_>>(),
            parallel
                .auth_failures
                .iter()
                .map(|failure| (failure.line_no, failure.status))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            single_sink.bytes.load(Ordering::SeqCst),
            parallel_sink.bytes.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn public_scan_file_handles_small_files() {
        let (content, expected_total, expected_malformed, _) = build_mixed_log();
        let path = unique_temp_path("public");
        std::fs::write(&path, content.as_bytes()).expect("write temp file");
        let file_size = std::fs::metadata(&path).expect("metadata").len();
        let sink = CountingSink::new();
        let engine = RuleEngine::new();

        let outcome = scan_file(&path, &small_config(4, 97), &engine, &sink).expect("scan");
        let _ = std::fs::remove_file(&path);

        assert_eq!(outcome.total_lines, expected_total);
        assert_eq!(outcome.malformed_lines, expected_malformed);
        assert_eq!(outcome.bytes_read, file_size);
        assert_eq!(sink.bytes.load(Ordering::SeqCst), file_size);
    }

    #[test]
    fn overlong_lines_are_malformed_without_being_parsed() {
        let mut content = String::new();
        content.push_str(&"a".repeat(MAX_LINE_BYTES + 64));
        content.push('\n');
        content.push_str(&format!(
            "93.184.216.34 - - [{TS}] \"GET / HTTP/1.1\" 200 1 \"-\" \"curl/8.5.0\"\n"
        ));
        let path = unique_temp_path("overlong");
        std::fs::write(&path, content.as_bytes()).expect("write temp file");
        let file_size = std::fs::metadata(&path).expect("metadata").len();
        let sink = CountingSink::new();
        let engine = RuleEngine::new();

        // 64 KiB chunks keep the test fast while still putting many range
        // boundaries inside the over-long line.
        let outcome = scan_file_with_floor(&path, &small_config(4, 64 * 1024), &engine, &sink, 1)
            .expect("scan");
        let _ = std::fs::remove_file(&path);

        assert_eq!(outcome.total_lines, 2);
        assert_eq!(outcome.malformed_lines, 1);
        assert_eq!(outcome.bytes_read, file_size);
        assert_eq!(sink.bytes.load(Ordering::SeqCst), file_size);
    }

    #[test]
    fn crlf_file_and_missing_final_newline_are_tolerated() {
        let mut content = String::new();
        for i in 0..5u16 {
            content.push_str(&format!(
                "93.184.216.34 - - [{TS}] \"GET /{i} HTTP/1.1\" 200 {i} \"-\" \"curl/8.5.0\"\r\n"
            ));
        }
        content.push_str(&format!(
            "93.184.216.34 - - [{TS}] \"GET /last HTTP/1.1\" 404 9 \"-\" \"curl/8.5.0\""
        ));
        let path = unique_temp_path("crlf");
        std::fs::write(&path, content.as_bytes()).expect("write temp file");
        let sink = CountingSink::new();
        let engine = RuleEngine::new();

        let outcome =
            scan_file_with_floor(&path, &small_config(3, 61), &engine, &sink, 1).expect("scan");
        let _ = std::fs::remove_file(&path);

        assert_eq!(outcome.total_lines, 6);
        assert_eq!(outcome.malformed_lines, 0);
        assert_eq!(outcome.auth_failures.len(), 1);
        assert_eq!(outcome.auth_failures[0].line_no, 6);
        assert_eq!(outcome.auth_failures[0].path, "/last");
    }

    #[test]
    fn hits_are_converted_to_events_and_capped() {
        use crate::model::threat::Category;

        let line = format!(
            r#"93.184.216.34 - - [{TS}] "GET /admin?id=1 HTTP/1.1" 403 12 "https://ref/" "Mozilla/5.0""#
        );
        let entry = parse_line(&line, 9).expect("parse");
        let hits = vec![
            RuleHit {
                rule_id: "TEST-1",
                rule_name: "First hit",
                category: Category::SqlInjection,
                severity: 7,
                evidence: "union select".to_string(),
            },
            RuleHit {
                rule_id: "TEST-2",
                rule_name: "Second hit",
                category: Category::PathTraversal,
                severity: 5,
                evidence: "../".to_string(),
            },
        ];

        let event_slots = AtomicU64::new(0);
        let auth_slots = AtomicU64::new(0);
        let probe_slots = AtomicU64::new(0);
        let events_truncated = AtomicBool::new(false);
        let failures_truncated = AtomicBool::new(false);
        let budgets = Budgets {
            max_events: 1,
            max_auth_failures: 10,
            max_probe_failures: 10,
            event_slots: &event_slots,
            auth_slots: &auth_slots,
            probe_slots: &probe_slots,
            events_truncated: &events_truncated,
            failures_truncated: &failures_truncated,
        };

        let mut result = ChunkResult::default();
        record_hits(&entry, &hits, &budgets, &mut result);

        assert_eq!(result.events.len(), 1);
        assert!(events_truncated.load(Ordering::SeqCst));
        let event = &result.events[0];
        assert_eq!(event.line_no, 9);
        assert_eq!(event.category, Category::SqlInjection);
        assert_eq!(event.rule_id, "TEST-1");
        assert_eq!(event.rule_name, "First hit");
        assert_eq!(event.severity, 7);
        assert_eq!(event.evidence, "union select");
        assert_eq!(event.source_ip, entry.source_ip);
        assert_eq!(event.method, "GET");
        assert_eq!(event.path, "/admin?id=1");
        assert_eq!(event.status, 403);
        assert_eq!(event.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(event.raw, line);
        assert_eq!(
            event.timestamp.map(|timestamp| timestamp.timestamp()),
            entry.timestamp.map(|timestamp| timestamp.timestamp())
        );
    }

    #[test]
    fn auth_failures_need_timestamp_and_respect_budget() {
        let line =
            format!(r#"93.184.216.34 - - [{TS}] "POST /login HTTP/1.1" 401 0 "-" "curl/8.5.0""#);
        let entry = parse_line(&line, 3).expect("parse");

        let event_slots = AtomicU64::new(0);
        let auth_slots = AtomicU64::new(0);
        let probe_slots = AtomicU64::new(0);
        let events_truncated = AtomicBool::new(false);
        let failures_truncated = AtomicBool::new(false);
        let budgets = Budgets {
            max_events: 10,
            max_auth_failures: 1,
            max_probe_failures: 1,
            event_slots: &event_slots,
            auth_slots: &auth_slots,
            probe_slots: &probe_slots,
            events_truncated: &events_truncated,
            failures_truncated: &failures_truncated,
        };

        let mut result = ChunkResult::default();
        record_auth_failure(&entry, &budgets, &mut result);
        record_auth_failure(&entry, &budgets, &mut result);
        assert_eq!(result.failures.len(), 1);
        assert!(failures_truncated.load(Ordering::SeqCst));
        assert_eq!(result.failures[0].line_no, 3);
        assert_eq!(result.failures[0].status, 401);
        assert_eq!(result.failures[0].path, "/login");

        let success = parse_line(
            &format!(r#"93.184.216.34 - - [{TS}] "GET / HTTP/1.1" 200 1"#),
            4,
        )
        .expect("parse");
        let mut result = ChunkResult::default();
        record_auth_failure(&success, &budgets, &mut result);
        assert!(result.failures.is_empty());

        let no_timestamp = parse_line(
            r#"93.184.216.34 - - [10/Foo/2000:99:99:99 +0000] "GET / HTTP/1.1" 404 1"#,
            5,
        )
        .expect("parse");
        let mut result = ChunkResult::default();
        record_auth_failure(&no_timestamp, &budgets, &mut result);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn probe_flood_does_not_starve_auth_failure_budget() {
        let missing = parse_line(
            &format!(r#"93.184.216.34 - - [{TS}] "GET /missing.png HTTP/1.1" 404 0 "-" "curl/8.5.0""#),
            1,
        )
        .expect("parse");
        let login = parse_line(
            &format!(r#"203.0.113.77 - - [{TS}] "POST /login HTTP/1.1" 401 0 "-" "curl/8.5.0""#),
            2,
        )
        .expect("parse");

        let event_slots = AtomicU64::new(0);
        let auth_slots = AtomicU64::new(0);
        let probe_slots = AtomicU64::new(0);
        let events_truncated = AtomicBool::new(false);
        let failures_truncated = AtomicBool::new(false);
        let budgets = Budgets {
            max_events: 10,
            max_auth_failures: 1,
            max_probe_failures: 1,
            event_slots: &event_slots,
            auth_slots: &auth_slots,
            probe_slots: &probe_slots,
            events_truncated: &events_truncated,
            failures_truncated: &failures_truncated,
        };

        let mut result = ChunkResult::default();
        record_auth_failure(&missing, &budgets, &mut result);
        record_auth_failure(&missing, &budgets, &mut result);
        assert_eq!(result.failures.len(), 1);
        assert!(failures_truncated.load(Ordering::SeqCst));

        record_auth_failure(&login, &budgets, &mut result);
        assert_eq!(result.failures.len(), 2);
        assert_eq!(result.failures[1].status, 401);
        assert_eq!(result.failures[1].path, "/login");
    }

    fn next_rand(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state >> 33
    }

    /// Differential check: the chunked scanner must agree with a sequential
    /// reference on every counter, every failure line number and the exact
    /// number of bytes reported to the progress sink.
    #[test]
    fn randomized_chunkings_match_reference() {
        let mut rng = 0x0bad_c0de_dead_beefu64;
        for case in 0..4u32 {
            let mut content = String::new();
            let mut expected_total = 0u64;
            let mut expected_malformed = 0u64;
            let mut expected_failures: Vec<(u64, u16)> = Vec::new();
            let line_count = 60 + next_rand(&mut rng) % 25;

            for _ in 0..line_count {
                let roll = next_rand(&mut rng) % 100;
                if roll < 7 {
                    content.push('\n');
                    continue;
                }
                if roll < 18 {
                    content.push_str(&format!(
                        "junk {:x} {}\n",
                        next_rand(&mut rng),
                        "q".repeat((next_rand(&mut rng) % 40) as usize)
                    ));
                    expected_total += 1;
                    expected_malformed += 1;
                    continue;
                }
                if roll < 26 {
                    let len = 600 + (next_rand(&mut rng) % 2400) as usize;
                    content.push_str(&"z".repeat(len));
                    content.push('\n');
                    expected_total += 1;
                    expected_malformed += 1;
                    continue;
                }
                let status = [200u16, 401, 403, 404][(next_rand(&mut rng) % 4) as usize];
                let user_agent = "u".repeat((next_rand(&mut rng) % 120) as usize);
                content.push_str(&format!(
                    "10.{}.{}.{} - - [{TS}] \"GET /p/{}?x={} HTTP/1.1\" {status} {} \"-\" \"{user_agent}\"\n",
                    next_rand(&mut rng) % 250,
                    next_rand(&mut rng) % 250,
                    next_rand(&mut rng) % 250,
                    next_rand(&mut rng) % 1000,
                    next_rand(&mut rng) % 1000,
                    next_rand(&mut rng) % 5000,
                ));
                expected_total += 1;
                if matches!(status, 401 | 403 | 404) {
                    expected_failures.push((expected_total, status));
                }
            }
            if next_rand(&mut rng) % 2 == 0 && content.ends_with('\n') {
                content.pop();
            }

            let path = unique_temp_path(&format!("random-{case}"));
            std::fs::write(&path, content.as_bytes()).expect("write temp file");
            let size = content.len() as u64;
            let engine = RuleEngine::new();

            for chunk_bytes in [97u64, 1024, 4096] {
                for threads in [1usize, 4] {
                    let sink = CountingSink::new();
                    let outcome = scan_file_with_floor(
                        &path,
                        &small_config(threads, chunk_bytes),
                        &engine,
                        &sink,
                        1,
                    )
                    .expect("scan");

                    assert_eq!(
                        outcome.total_lines, expected_total,
                        "case {case} chunk {chunk_bytes} threads {threads}"
                    );
                    assert_eq!(
                        outcome.malformed_lines, expected_malformed,
                        "case {case} chunk {chunk_bytes} threads {threads}"
                    );
                    assert_eq!(outcome.bytes_read, size);
                    assert_eq!(
                        sink.bytes.load(Ordering::SeqCst),
                        size,
                        "progress sum must equal file size (case {case} chunk {chunk_bytes})"
                    );
                    let observed: Vec<(u64, u16)> = outcome
                        .auth_failures
                        .iter()
                        .map(|failure| (failure.line_no, failure.status))
                        .collect();
                    assert_eq!(
                        observed, expected_failures,
                        "case {case} chunk {chunk_bytes} threads {threads}"
                    );
                }
            }

            let _ = std::fs::remove_file(&path);
        }
    }

    #[test]
    fn missing_file_reports_io_error() {
        let path = unique_temp_path("missing");
        let engine = RuleEngine::new();
        let error = scan_file(&path, &small_config(2, 97), &engine, &NoopProgress)
            .expect_err("missing file must fail");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn directory_path_is_rejected() {
        let engine = RuleEngine::new();
        let error = scan_file(
            &std::env::temp_dir(),
            &small_config(2, 97),
            &engine,
            &NoopProgress,
        )
        .expect_err("directory must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
