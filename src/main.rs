mod cli;
mod detection;
mod model;
mod parser;
mod scoring;
mod ui;

use std::collections::{HashMap, HashSet};
use std::process::ExitCode;
use std::time::Instant;

use detection::RuleEngine;
use model::threat::Category;
use parser::reader::{scan_file, ProgressSink, ScanConfig};
use scoring::{score_and_rank, ScoringConfig};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("\n  fatal: {}", sanitize_error(&err.to_string()));
            ExitCode::FAILURE
        }
    }
}

/// Keep operator-supplied paths and OS error text from emitting terminal
/// control sequences on the error path.
fn sanitize_error(message: &str) -> String {
    message
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let opts = match cli::parse_args(std::env::args().skip(1))? {
        cli::CliAction::Run(opts) => opts,
        cli::CliAction::Help => {
            cli::print_help();
            return Ok(());
        }
        cli::CliAction::Version => {
            println!("thresh {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
    };

    if opts.no_color {
        colored::control::set_override(false);
    }

    ui::banner::print_banner();

    let path = match opts.path.clone() {
        Some(path) => path,
        None => ui::prompt::prompt_log_path()?,
    };

    let metadata = std::fs::metadata(&path)?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()).into());
    }
    let file_size = metadata.len();

    let progress = ui::progress::TerminalProgress::new(file_size);

    let engine = RuleEngine::new();
    let scan_cfg = ScanConfig {
        threads: opts.threads,
        chunk_bytes: opts.chunk_bytes,
        max_events: opts.max_events,
    };

    let started = Instant::now();
    let outcome = scan_file(&path, &scan_cfg, &engine, &progress)?;
    progress.finished();

    let mut events = outcome.events;
    let mut brute = engine.detect_bruteforce(
        &outcome.auth_failures,
        opts.window_secs,
        opts.bf_threshold,
    );
    let mut truncated = outcome.events_truncated || outcome.failures_truncated;

    // `--max-events` is a hard cap. Stateful summaries are rare and high value,
    // so keep room for them first and let per-line rule hits absorb the trim.
    let max_events = opts.max_events.max(1);
    if brute.len() >= max_events {
        if brute.len() > max_events {
            truncated = true;
        }
        if !events.is_empty() {
            truncated = true;
        }
        brute.truncate(max_events);
        events.clear();
    } else {
        let remaining = max_events - brute.len();
        if events.len() > remaining {
            events.truncate(remaining);
            truncated = true;
        }
    }
    events.append(&mut brute);

    let scored = score_and_rank(
        events,
        &ScoringConfig {
            window_secs: opts.window_secs,
            ..ScoringConfig::default()
        },
    );
    let elapsed = started.elapsed();

    let unique_ips = scored
        .iter()
        .map(|s| s.event.source_ip)
        .collect::<HashSet<_>>()
        .len();

    let mut counts: HashMap<Category, usize> = HashMap::new();
    let mut critical_count = 0usize;
    let mut high_count = 0usize;
    let mut medium_count = 0usize;
    for event in &scored {
        *counts.entry(event.event.category).or_insert(0) += 1;
        if event.final_score >= 8.0 {
            critical_count += 1;
        } else if event.final_score >= 6.0 {
            high_count += 1;
        } else {
            medium_count += 1;
        }
    }
    let mut category_counts: Vec<(Category, usize)> = counts.into_iter().collect();
    category_counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // The dashboard shows one row per distinct request: several rules can fire
    // on the same log line, and repeating that payload in the top list crowds
    // out other threats. Event totals and category counts stay per-rule.
    let mut seen_requests = HashSet::new();
    let top: Vec<scoring::ScoredEvent> = scored
        .iter()
        .filter(|s| seen_requests.insert((s.event.source_ip, s.event.line_no)))
        .take(opts.top)
        .cloned()
        .collect();
    let display_path = path.display().to_string();

    let view = ui::dashboard::DashboardView {
        log_path: &display_path,
        file_size,
        total_lines: outcome.total_lines,
        malformed_lines: outcome.malformed_lines,
        elapsed,
        threads: outcome.workers,
        total_events: scored.len(),
        unique_ips,
        truncated,
        top: &top,
        category_counts: &category_counts,
        critical_count,
        high_count,
        medium_count,
    };
    ui::dashboard::render_dashboard(&view);

    Ok(())
}
