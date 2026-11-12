//! Executive-summary dashboard rendered after a scan completes.
//!
//! The layout is deliberately narrow (<= 100 columns) and text-first: a
//! two-column summary, a category histogram and the ranked critical threats
//! with their raw request payloads. All colours come from `colored`; when the
//! output is redirected the ANSI sequences disappear automatically.

use std::io::{self, Write};
use std::time::Duration;

use colored::{ColoredString, Colorize};

use crate::model::threat::{Category, ThreatEvent};
use crate::scoring::ScoredEvent;

/// Width of the full-width horizontal rules, excluding the two-space margin.
const RULE_WIDTH: usize = 92;
/// Width of the summary's key column.
const LABEL_WIDTH: usize = 12;
/// Width of a category label in the breakdown table.
const CATEGORY_LABEL_WIDTH: usize = 22;
/// Maximum length of a category histogram bar.
const CATEGORY_BAR_WIDTH: usize = 40;
/// Maximum characters reserved for the log path in the summary.
const PATH_WIDTH: usize = 56;
/// Maximum characters for a request payload line (plus a six-column indent).
const PAYLOAD_WIDTH: usize = 92;
/// Maximum characters for the rule/evidence detail line.
const DETAIL_WIDTH: usize = 92;
/// Right-aligned HTTP status column.
const STATUS_WIDTH: usize = 6;

/// Everything the dashboard needs; assembled by `main` after scoring.
pub struct DashboardView<'a> {
    pub log_path: &'a str,
    pub file_size: u64,
    pub total_lines: u64,
    pub malformed_lines: u64,
    pub elapsed: Duration,
    pub threads: usize,
    pub total_events: usize,
    pub unique_ips: usize,
    pub truncated: bool,
    pub top: &'a [ScoredEvent],
    pub category_counts: &'a [(Category, usize)],
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
}

/// Render the dashboard to stdout. Write failures (for example a closed pipe)
/// are intentionally ignored so `sentinel | head` exits quietly.
pub fn render_dashboard(view: &DashboardView<'_>) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let _ = render_to(&mut out, view);
    let _ = out.flush();
}

/// Render the dashboard into any writer. Kept separate from stdout so tests
/// can capture the output without touching the terminal.
fn render_to<W: Write>(out: &mut W, view: &DashboardView<'_>) -> io::Result<()> {
    writeln!(out)?;
    writeln!(out, "  {}", rule())?;
    writeln!(out, "  {}", "EXECUTIVE SUMMARY".bold().cyan())?;
    writeln!(out, "  {}", rule())?;
    writeln!(out)?;

    write_summary(out, view)?;

    if view.truncated {
        writeln!(
            out,
            "  {} {}",
            "!".yellow().bold(),
            "Event or auth-failure storage cap reached — rerun with a higher --max-events for full coverage."
                .yellow()
        )?;
        writeln!(out)?;
    }

    write_categories(out, view)?;
    write_top_threats(out, view)?;
    write_footer(out)?;
    Ok(())
}

fn rule() -> ColoredString {
    "─".repeat(RULE_WIDTH).dimmed()
}

/// Two-column key/value block covering the scan's headline numbers.
fn write_summary<W: Write>(out: &mut W, view: &DashboardView<'_>) -> io::Result<()> {
    let label = |text: &str| pad_right(text, LABEL_WIDTH).dimmed();
    let separator = || "·".dimmed();

    let log_path = truncate_middle(&sanitize(view.log_path), PATH_WIDTH);
    writeln!(
        out,
        "  {} {}  {}  {}",
        label("Log file"),
        log_path.bold(),
        separator(),
        human_bytes(view.file_size)
    )?;

    let malformed = if view.malformed_lines > 0 {
        format!("{} malformed", commafy(view.malformed_lines)).yellow()
    } else {
        format!("{} malformed", commafy(view.malformed_lines)).dimmed()
    };
    writeln!(
        out,
        "  {} {} {}  {}  {}",
        label("Lines"),
        commafy(view.total_lines).bold(),
        "scanned".dimmed(),
        separator(),
        malformed
    )?;

    writeln!(
        out,
        "  {} {}  {}  {} workers",
        label("Execution"),
        human_duration(view.elapsed).bold(),
        separator(),
        view.threads
    )?;

    let throughput = if view.elapsed.as_secs_f64() > 0.0 {
        view.total_lines as f64 / view.elapsed.as_secs_f64()
    } else {
        0.0
    };
    writeln!(
        out,
        "  {} {}",
        label("Throughput"),
        human_rate(throughput).cyan()
    )?;

    writeln!(
        out,
        "  {} {} {}  {}  {} {}",
        label("Threats"),
        commafy(view.total_events as u64).bold(),
        "suspicious events".dimmed(),
        separator(),
        commafy(view.unique_ips as u64).bold(),
        "unique offending IPs".dimmed()
    )?;

    let severity = format!(
        "{} {} {} {} {} {} {} {} {} {} {}",
        "CRITICAL".red().bold(),
        commafy(view.critical_count as u64).red(),
        "(>=8)".dimmed(),
        separator(),
        "HIGH".yellow().bold(),
        commafy(view.high_count as u64).yellow(),
        "(6-7.99)".dimmed(),
        separator(),
        "MEDIUM".white().bold(),
        commafy(view.medium_count as u64),
        "(<6)".dimmed()
    );
    writeln!(out, "  {} {}", label("Severity"), severity)?;
    writeln!(out)?;
    Ok(())
}

/// Category histogram, preserving the caller's sort order and hiding empty
/// categories.
fn write_categories<W: Write>(out: &mut W, view: &DashboardView<'_>) -> io::Result<()> {
    let visible: Vec<(Category, usize)> = view
        .category_counts
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(category, count)| (*category, *count))
        .collect();

    if visible.is_empty() {
        return Ok(());
    }

    let max = visible.iter().map(|(_, count)| *count).max().unwrap_or(0);

    writeln!(out, "  {}", "CATEGORY BREAKDOWN".bold().cyan())?;
    writeln!(out)?;

    for (category, count) in visible {
        let width = if max == 0 {
            0
        } else {
            (((count as f64 / max as f64) * CATEGORY_BAR_WIDTH as f64).round() as usize).max(1)
        };
        let bar = "█".repeat(width);
        let count = pad_left(&commafy(count as u64), 6);
        writeln!(
            out,
            "  {} {}  {}",
            pad_right(category.label(), CATEGORY_LABEL_WIDTH),
            count.bold(),
            tint(bar, category_tier(category))
        )?;
    }

    writeln!(out)?;
    Ok(())
}

/// Ranked threat list, or a green all-clear panel when nothing ranked.
fn write_top_threats<W: Write>(out: &mut W, view: &DashboardView<'_>) -> io::Result<()> {
    if view.top.is_empty() {
        return write_empty_panel(out);
    }

    writeln!(out, "  {}", "TOP THREATS".bold().cyan())?;
    writeln!(out)?;

    let header = format!(
        "{} {}  {}  {}  {}  {}",
        pad_right("RANK", 4),
        pad_right("SCORE", 5),
        pad_right("TIMESTAMP", 19),
        pad_right("SOURCE IP", 15),
        pad_right("CATEGORY", 20),
        pad_right("STATUS", STATUS_WIDTH),
    );
    writeln!(out, "  {}", header.dimmed())?;

    for (index, scored) in view.top.iter().enumerate() {
        write_top_entry(out, index + 1, scored)?;
        if index + 1 < view.top.len() {
            writeln!(out)?;
        }
    }
    Ok(())
}

fn write_top_entry<W: Write>(out: &mut W, rank: usize, scored: &ScoredEvent) -> io::Result<()> {
    let event = &scored.event;

    let rank_cell = pad_right(&format!("#{rank}"), 4);
    let score_cell = pad_right(&format!("{:.2}", scored.final_score), 5);
    let timestamp = event
        .timestamp
        .map(|ts| ts.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "-".to_string());
    let timestamp_cell = pad_right(&timestamp, 19);
    let ip_cell = pad_right(&event.source_ip.to_string(), 15);
    let category_cell = pad_right(event.category.label(), 20);

    writeln!(
        out,
        "  {} {}  {}  {}  {}  {}",
        rank_cell.dimmed(),
        tint(score_cell, score_tier(scored.final_score)),
        timestamp_cell,
        ip_cell.cyan(),
        category_cell,
        status_cell(event.status)
    )?;

    let payload = truncate_chars(&request_payload(event), PAYLOAD_WIDTH);
    writeln!(out, "    {} {}", "↳".cyan(), payload.dimmed())?;

    let detail = detail_line(scored);
    if !detail.is_empty() {
        writeln!(out, "      {}", truncate_chars(&detail, DETAIL_WIDTH).dimmed())?;
    }

    Ok(())
}

fn write_empty_panel<W: Write>(out: &mut W) -> io::Result<()> {
    const INNER: usize = 58;
    let body = pad_right(" ✓  No suspicious activity detected.", INNER);

    writeln!(out, "  {}", format!("┌{}┐", "─".repeat(INNER)).green())?;
    writeln!(out, "  {}", format!("│{body}│").green())?;
    writeln!(out, "  {}", format!("└{}┘", "─".repeat(INNER)).green())?;
    Ok(())
}

fn write_footer<W: Write>(out: &mut W) -> io::Result<()> {
    writeln!(out)?;
    writeln!(out, "  {}", rule())?;
    writeln!(
        out,
        "  {} {} · analysis complete",
        "◆".cyan(),
        format!("sentinel v{}", env!("CARGO_PKG_VERSION")).bold()
    )?;
    writeln!(
        out,
        "  {}",
        "Rerun with --top N to inspect more.".dimmed()
    )?;
    Ok(())
}

/// Raw request payload shown under a ranked entry, sanitised for terminal
/// safety. Falls back to the original log line when the parser had no path.
fn request_payload(event: &ThreatEvent) -> String {
    let method = sanitize(&event.method);
    let path = sanitize(&event.path);
    let raw = sanitize(&event.raw);

    let rendered = if path.trim().is_empty() {
        raw
    } else if method.trim().is_empty() {
        path
    } else {
        format!("{} {}", method.trim(), path)
    };

    let rendered = rendered.trim();
    if rendered.is_empty() {
        "-".to_string()
    } else {
        rendered.to_string()
    }
}

/// `rule_name (rule_id) · multiplier xN · evidence` when those pieces exist.
fn detail_line(scored: &ScoredEvent) -> String {
    let event = &scored.event;
    let mut parts: Vec<String> = Vec::with_capacity(3);

    if !event.rule_name.trim().is_empty() {
        if event.rule_id.trim().is_empty() {
            parts.push(event.rule_name.trim().to_string());
        } else {
            parts.push(format!(
                "{} ({})",
                event.rule_name.trim(),
                event.rule_id.trim()
            ));
        }
    }

    let evidence = sanitize(&event.evidence);
    let evidence = evidence.trim();
    if !evidence.is_empty() {
        parts.push(truncate_chars(evidence, 56));
    }

    if scored.base_score > 0.0 {
        parts.push(format!("base {:.2}", scored.base_score));
    }

    if scored.multiplier > 1.0 + f64::EPSILON {
        parts.push(format!("multiplier x{:.2}", scored.multiplier));
    }

    if let Some(reason) = scored.reasons.first() {
        let reason = sanitize(reason);
        let reason = reason.trim();
        if !reason.is_empty() {
            parts.push(truncate_chars(reason, 44));
        }
    }

    parts.join(" · ")
}

#[derive(Clone, Copy)]
enum Tier {
    Critical,
    High,
    Low,
}

fn score_tier(score: f64) -> Tier {
    if score >= 8.0 {
        Tier::Critical
    } else if score >= 6.0 {
        Tier::High
    } else {
        Tier::Low
    }
}

fn category_tier(category: Category) -> Tier {
    use Category::*;
    match category {
        CommandInjection | Log4Shell | Webshell | LocalFileInclusion => Tier::Critical,
        SqlInjection | PathTraversal | Ssrf | BruteForce => Tier::High,
        CrossSiteScripting | SensitiveFileAccess | Reconnaissance | MalformedRequest | Other => {
            Tier::Low
        }
    }
}

fn tint(text: String, tier: Tier) -> ColoredString {
    match tier {
        Tier::Critical => text.red().bold(),
        Tier::High => text.yellow(),
        Tier::Low => text.white(),
    }
}

fn status_cell(status: u16) -> ColoredString {
    let text = if status == 0 {
        "-".to_string()
    } else {
        status.to_string()
    };
    let padded = pad_left(&text, STATUS_WIDTH);
    match status {
        500..=599 => padded.red().bold(),
        400..=499 => padded.yellow(),
        200..=399 => padded.green(),
        _ => padded.dimmed(),
    }
}

/// Format a byte count using binary units, e.g. `5.50 GiB`.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

/// Insert thousands separators, e.g. `1,234,567`.
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

/// Humanised throughput, e.g. `2.75M/s` or `674.6K/s`.
fn human_rate(per_second: f64) -> String {
    let value = if per_second.is_finite() && per_second > 0.0 {
        per_second
    } else {
        0.0
    };

    if value >= 1_000_000_000.0 {
        format!("{:.2}G/s", value / 1_000_000_000.0)
    } else if value >= 1_000_000.0 {
        format!("{:.2}M/s", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}K/s", value / 1_000.0)
    } else {
        format!("{value:.0}/s")
    }
}

/// Millisecond precision under a second, two-decimal seconds under a minute,
/// then compact `2m 05s` / `1h 02m 03s` forms.
fn human_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds < 1.0 {
        format!("{:.2} ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{seconds:.2} s")
    } else if seconds < 3600.0 {
        let minutes = (seconds / 60.0).floor() as u64;
        let secs = (seconds % 60.0).floor() as u64;
        format!("{minutes}m {secs:02}s")
    } else {
        let hours = (seconds / 3600.0).floor() as u64;
        let minutes = ((seconds % 3600.0) / 60.0).floor() as u64;
        let secs = (seconds % 60.0).floor() as u64;
        format!("{hours}h {minutes:02}m {secs:02}s")
    }
}

/// Character-count truncation with an ellipsis; never splits UTF-8.
fn truncate_chars(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if input.chars().count() <= max_chars {
        return input.to_string();
    }

    let mut out: String = input.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

/// Keep both ends of a long path so the filename stays visible.
fn truncate_middle(input: &str, max_chars: usize) -> String {
    let total = input.chars().count();
    if total <= max_chars || max_chars < 8 {
        return truncate_chars(input, max_chars);
    }

    let head = max_chars / 2 - 1;
    let tail = max_chars - head - 1;
    let mut out: String = input.chars().take(head).collect();
    out.push('…');
    out.extend(input.chars().skip(total - tail));
    out
}

/// Replace control characters with spaces so hostile log payloads cannot move
/// the cursor, recolour the terminal or inject escape sequences.
fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn pad_right(input: &str, width: usize) -> String {
    let len = input.chars().count();
    if len >= width {
        input.to_string()
    } else {
        let mut out = String::with_capacity(width);
        out.push_str(input);
        out.extend(std::iter::repeat(' ').take(width - len));
        out
    }
}

fn pad_left(input: &str, width: usize) -> String {
    let len = input.chars().count();
    if len >= width {
        input.to_string()
    } else {
        let mut out = String::with_capacity(width);
        out.extend(std::iter::repeat(' ').take(width - len));
        out.push_str(input);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    use chrono::DateTime;

    /// Remove SGR escape sequences so assertions work whether `colored` is
    /// active (TTY / CLICOLOR_FORCE) or disabled (normal test capture).
    fn strip_ansi(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut in_escape = false;
        for ch in input.chars() {
            if in_escape {
                if ch.is_ascii_alphabetic() {
                    in_escape = false;
                }
            } else if ch == '\u{1b}' {
                in_escape = true;
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn threat(
        ip: &str,
        category: Category,
        timestamp: Option<&str>,
        path: &str,
        status: u16,
    ) -> ThreatEvent {
        ThreatEvent {
            line_no: 42,
            timestamp: timestamp.map(|raw| DateTime::parse_from_rfc3339(raw).unwrap()),
            timestamp_raw: "12/Nov/2026:03:14:07 +0000".to_string(),
            source_ip: ip.parse::<IpAddr>().unwrap(),
            category,
            rule_id: "CMD-001",
            rule_name: "shell_metachar",
            severity: 9,
            evidence: "path contains shell metacharacters".to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            status,
            user_agent: None,
            raw: format!("{ip} - - \"GET {path} HTTP/1.1\" {status} 512"),
        }
    }

    fn scored(event: ThreatEvent, final_score: f64, multiplier: f64) -> ScoredEvent {
        ScoredEvent {
            event,
            base_score: final_score,
            multiplier,
            final_score,
            reasons: Vec::new(),
        }
    }

    #[test]
    fn formats_bytes_with_binary_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.00 KiB");
        assert_eq!(human_bytes(1_048_576), "1.00 MiB");
        assert_eq!(human_bytes(5_905_580_032), "5.50 GiB");
    }

    #[test]
    fn formats_thousands_separators() {
        assert_eq!(commafy(0), "0");
        assert_eq!(commafy(999), "999");
        assert_eq!(commafy(1_000), "1,000");
        assert_eq!(commafy(1_234_567), "1,234,567");
    }

    #[test]
    fn formats_rates() {
        assert_eq!(human_rate(0.0), "0/s");
        assert_eq!(human_rate(999.0), "999/s");
        assert_eq!(human_rate(674_500.0), "674.5K/s");
        assert_eq!(human_rate(2_750_000.0), "2.75M/s");
        assert_eq!(human_rate(1_500_000_000.0), "1.50G/s");
        assert_eq!(human_rate(f64::NAN), "0/s");
    }

    #[test]
    fn formats_durations() {
        assert_eq!(human_duration(Duration::from_micros(4_200)), "4.20 ms");
        assert_eq!(human_duration(Duration::from_millis(1_830)), "1.83 s");
        assert_eq!(human_duration(Duration::from_secs(125)), "2m 05s");
        assert_eq!(
            human_duration(Duration::from_secs(3_723)),
            "1h 02m 03s"
        );
    }

    #[test]
    fn truncates_by_chars_not_bytes() {
        assert_eq!(truncate_chars("abcdef", 4), "abc…");
        assert_eq!(truncate_chars("abc", 3), "abc");
        assert_eq!(truncate_chars("abcdef", 0), "");
        assert_eq!(truncate_chars("ééééé", 3), "éé…");
        assert_eq!(truncate_chars("ééééé", 3).chars().count(), 3);
    }

    #[test]
    fn truncates_middle_keeping_filename() {
        let path = "/srv/logs/nginx/production/site.example.com/extra/access.log";
        let shortened = truncate_middle(path, 30);
        assert!(shortened.chars().count() <= 30);
        assert!(shortened.starts_with("/srv/logs"));
        assert!(shortened.ends_with("access.log"));
    }

    #[test]
    fn truncates_long_unicode_without_panicking() {
        let path = format!("/srv/{}", "é".repeat(100));
        let shortened = truncate_middle(&path, 40);
        assert_eq!(shortened.chars().count(), 40);
        assert!(shortened.starts_with("/srv/"));
    }

    #[test]
    fn sanitizes_control_characters() {
        assert_eq!(sanitize("a\nb\tc\u{1b}[31m"), "a b c [31m");
        assert_eq!(sanitize("héllo"), "héllo");
        assert_eq!(sanitize("del\u{7f}ete"), "del ete");
    }

    #[test]
    fn pads_by_display_character_count() {
        assert_eq!(pad_right("abc", 5), "abc  ");
        assert_eq!(pad_left("abc", 5), "  abc");
        assert_eq!(pad_right("abcdef", 3), "abcdef");
        assert_eq!(pad_right("é", 2), "é ");
    }

    #[test]
    fn renders_summary_and_ranked_threats() {
        let mut brute = threat("198.51.100.7", Category::BruteForce, None, "", 401);
        brute.method = "POST".to_string();
        brute.raw =
            "198.51.100.7 - - \"POST /admin/login HTTP/1.1\" 401 88".to_string();

        let top = vec![
            scored(
                threat(
                    "203.0.113.9",
                    Category::CommandInjection,
                    Some("2026-11-12T03:14:07+00:00"),
                    "/index.php?cmd=;cat%20/etc/passwd",
                    403,
                ),
                9.8,
                1.8,
            ),
            scored(brute, 6.4, 1.0),
        ];
        let categories = vec![
            (Category::CommandInjection, 3usize),
            (Category::BruteForce, 2usize),
            (Category::Webshell, 0usize),
        ];
        let view = DashboardView {
            log_path: "/var/log/nginx/access.log",
            file_size: 5_905_580_032,
            total_lines: 1_234_567,
            malformed_lines: 23,
            elapsed: Duration::from_millis(1_830),
            threads: 8,
            total_events: 412,
            unique_ips: 37,
            truncated: true,
            top: &top,
            category_counts: &categories,
            critical_count: 12,
            high_count: 84,
            medium_count: 316,
        };

        let mut buffer = Vec::new();
        render_to(&mut buffer, &view).unwrap();
        let rendered = strip_ansi(&String::from_utf8(buffer).unwrap());

        for needle in [
            "EXECUTIVE SUMMARY",
            "5.50 GiB",
            "1,234,567",
            "23 malformed",
            "1.83 s",
            "8 workers",
            "412",
            "37",
            "CRITICAL 12",
            "CATEGORY BREAKDOWN",
            "TOP THREATS",
        ] {
            assert!(rendered.contains(needle), "missing {needle:?} in:\n{rendered}");
        }

        assert!(rendered.contains("9.80"));
        assert!(rendered.contains("2026-11-12 03:14:07"));
        assert!(rendered.contains("203.0.113.9"));
        assert!(rendered.contains("Command Injection"));
        assert!(rendered.contains("/index.php?cmd=;cat%20/etc/passwd"));
        assert!(rendered.contains("198.51.100.7"));
        assert!(rendered.contains("Brute Force"));
        assert!(rendered.contains("HIGH 84"));
        assert!(rendered.contains("MEDIUM 316"));
        assert!(rendered.contains("POST /admin/login"), "missing raw fallback payload");
        assert!(rendered.contains("shell_metachar (CMD-001)"));
        assert!(rendered.contains("multiplier x1.80"));
        assert!(rendered.contains("--max-events"));
        assert!(!rendered.contains("No suspicious activity detected."));
        assert!(!rendered.contains("Webshell"), "zero categories must be hidden");

        let breakdown = rendered
            .split("CATEGORY BREAKDOWN")
            .nth(1)
            .expect("category section")
            .split("TOP THREATS")
            .next()
            .expect("top threats section");
        let command = breakdown.find("Command Injection").expect("command row");
        let brute = breakdown.find("Brute Force").expect("brute-force row");
        assert!(command < brute, "category order must be preserved");

        assert!(rendered.contains(&format!("sentinel v{}", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn renders_clean_panel_when_no_threats() {
        let top: Vec<ScoredEvent> = Vec::new();
        let categories: Vec<(Category, usize)> = Vec::new();
        let view = DashboardView {
            log_path: "/var/log/nginx/access.log",
            file_size: 0,
            total_lines: 0,
            malformed_lines: 0,
            elapsed: Duration::from_micros(0),
            threads: 4,
            total_events: 0,
            unique_ips: 0,
            truncated: false,
            top: &top,
            category_counts: &categories,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
        };

        let mut buffer = Vec::new();
        render_to(&mut buffer, &view).unwrap();
        let rendered = strip_ansi(&String::from_utf8(buffer).unwrap());

        assert!(rendered.contains("EXECUTIVE SUMMARY"));
        assert!(rendered.contains("No suspicious activity detected."));
        assert!(!rendered.contains("TOP THREATS"));
        assert!(!rendered.contains("CATEGORY BREAKDOWN"));
        assert!(!rendered.contains("--max-events"));
    }
}
