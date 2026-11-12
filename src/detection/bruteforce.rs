//! Stateful detector for brute-force login attempts, non-login authentication
//! failure bursts and enumeration / vulnerability scanning bursts.
//!
//! Contract: called once after parsing with every 401/403/404 response that
//! carried a timestamp. Returns at most one event per offending IP for auth
//! brute force, at most one for a non-login authentication burst and at most
//! one for scanning, sorted by source IP. The input is never mutated and every
//! loop is bounded, so this cannot panic on adversarial logs.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::model::entry::AuthFailure;
use crate::model::threat::{Category, ThreatEvent};

/// Path fragments that indicate an authentication surface. Both 401 and 403
/// responses need one of these to count as a login failure: a 401 on an API
/// endpoint is normally an expired token, not a password guess.
const LOGIN_HINTS: &[&str] = &[
    "login",
    "log-in",
    "signin",
    "sign-in",
    "auth",
    "session",
    "wp-login",
    "wp-admin",
    "admin",
    "api/token",
    "token",
    "oauth",
];

/// Page assets. A 403 burst on these is usually signed-URL expiry or hotlink
/// protection, not endpoint enumeration.
const STATIC_ASSET_EXTENSIONS: &[&str] = &[
    "css", "js", "mjs", "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "bmp", "ico", "woff",
    "woff2", "ttf", "otf", "eot", "map",
];

const BF_RULE_ID: &str = "BF-001";
const BF_RULE_NAME: &str = "Authentication brute force";
const AUTH_RULE_ID: &str = "AUTH-001";
const AUTH_RULE_NAME: &str = "Authentication failure burst";
const AUTH_RULE_SEVERITY: u8 = 4;
const SCAN_RULE_ID: &str = "SCAN-001";
const SCAN_RULE_NAME: &str = "Directory and endpoint enumeration";

/// Minimum number of distinct 404/403 paths used by the enumeration detector,
/// regardless of how low the login threshold is configured.
const SCAN_MIN_DISTINCT: usize = 25;

pub fn detect(failures: &[AuthFailure], window_secs: u64, threshold: u32) -> Vec<ThreatEvent> {
    if failures.is_empty() {
        return Vec::new();
    }

    let threshold = threshold.max(1);
    let window = i64::try_from(window_secs).unwrap_or(i64::MAX);
    // Enumeration is calibrated independently of the login threshold: the
    // documented floor is 25 distinct paths, never `2 * --threshold`.
    let scan_threshold = threshold.max(SCAN_MIN_DISTINCT as u32) as usize;

    let mut by_ip: BTreeMap<IpAddr, Vec<&AuthFailure>> = BTreeMap::new();
    for failure in failures {
        by_ip.entry(failure.source_ip).or_default().push(failure);
    }

    let mut events = Vec::new();
    for (ip, records) in &by_ip {
        if let Some(event) = auth_event(records, window, window_secs, threshold, *ip) {
            events.push(event);
        }
        if let Some(event) = auth_burst_event(records, window, window_secs, threshold, *ip) {
            events.push(event);
        }
        if let Some(event) = scan_event(records, window, window_secs, scan_threshold, *ip) {
            events.push(event);
        }
    }
    events
}

/// Peak number of login failures inside one window. Returns `(peak, start)`
/// where `start` indexes the first record of the earliest peak window.
fn auth_event(
    records: &[&AuthFailure],
    window: i64,
    window_secs: u64,
    threshold: u32,
    ip: IpAddr,
) -> Option<ThreatEvent> {
    let mut auth: Vec<&AuthFailure> = records
        .iter()
        .copied()
        .filter(|failure| is_login_failure(failure))
        .collect();

    if auth.len() < threshold as usize {
        return None;
    }
    auth.sort_by_key(|failure| (failure.epoch_secs(), failure.line_no));

    let (peak, start) = peak_count(&auth, window)?;
    if peak < threshold as usize {
        return None;
    }

    let peak32 = u32::try_from(peak).unwrap_or(u32::MAX);
    let severity = (6 + peak32 / threshold).min(9) as u8;
    Some(build_event(
        auth[start],
        ip,
        Category::BruteForce,
        BF_RULE_ID,
        BF_RULE_NAME,
        severity,
        format!("{peak} failed logins in {window_secs}s (peak window)"),
    ))
}

/// Peak number of 401 responses on non-login paths inside one window.
///
/// An expired-token client hitting many API endpoints is a real operational
/// problem but not an online password guess, so it is reported separately at
/// low severity instead of inflating BF-001. Plain 403s are authorization
/// denials, not authentication failures, and are left to the scan detector.
fn auth_burst_event(
    records: &[&AuthFailure],
    window: i64,
    window_secs: u64,
    threshold: u32,
    ip: IpAddr,
) -> Option<ThreatEvent> {
    let mut failures: Vec<&AuthFailure> = records
        .iter()
        .copied()
        .filter(|failure| failure.status == 401 && !is_login_path(failure))
        .collect();

    if failures.len() < threshold as usize {
        return None;
    }
    failures.sort_by_key(|failure| (failure.epoch_secs(), failure.line_no));

    let (peak, start) = peak_count(&failures, window)?;
    if peak < threshold as usize {
        return None;
    }

    Some(build_event(
        failures[start],
        ip,
        Category::BruteForce,
        AUTH_RULE_ID,
        AUTH_RULE_NAME,
        AUTH_RULE_SEVERITY,
        format!("{peak} failed authentication responses in {window_secs}s from non-login endpoints"),
    ))
}

/// Peak number of distinct 404/403 paths inside one window. Returns
/// `(peak, start)` where `start` indexes the record at the peak window start.
fn scan_event(
    records: &[&AuthFailure],
    window: i64,
    window_secs: u64,
    threshold: usize,
    ip: IpAddr,
) -> Option<ThreatEvent> {
    let mut enumerating: Vec<&AuthFailure> = records
        .iter()
        .copied()
        .filter(|failure| matches!(failure.status, 403 | 404))
        .filter(|failure| !is_static_asset(&failure.path))
        .collect();

    if enumerating.len() < threshold {
        return None;
    }
    enumerating.sort_by_key(|failure| (failure.epoch_secs(), failure.line_no));

    let (peak, start) = peak_distinct(&enumerating, window)?;
    if peak < threshold {
        return None;
    }

    Some(build_event(
        enumerating[start],
        ip,
        Category::Reconnaissance,
        SCAN_RULE_ID,
        SCAN_RULE_NAME,
        5,
        format!("{peak} distinct 404/403 paths in {window_secs}s (peak window)"),
    ))
}

/// A 401/403 response: authentication or authorization was refused.
fn is_auth_response(failure: &AuthFailure) -> bool {
    matches!(failure.status, 401 | 403)
}

/// Login guess: refused authentication on a path that names an auth surface.
fn is_login_failure(failure: &AuthFailure) -> bool {
    is_auth_response(failure) && is_login_path(failure)
}

fn is_login_path(failure: &AuthFailure) -> bool {
    let path = failure.path.to_ascii_lowercase();
    LOGIN_HINTS.iter().any(|hint| path.contains(hint))
}

/// Whether the path names a page asset rather than an endpoint.
fn is_static_asset(path: &str) -> bool {
    let key = path.split(['?', '#']).next().unwrap_or(path);
    let file = key.rsplit('/').next().unwrap_or(key);
    match file.rsplit_once('.') {
        Some((_, extension)) => STATIC_ASSET_EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known)),
        None => false,
    }
}

/// Two-pointer sliding window over records sorted by epoch. `window` is
/// inclusive: records whose timestamps differ by at most `window` seconds are
/// in the same window.
fn peak_count(records: &[&AuthFailure], window: i64) -> Option<(usize, usize)> {
    if records.is_empty() {
        return None;
    }
    let mut left = 0usize;
    let mut best = 0usize;
    let mut best_start = 0usize;
    for right in 0..records.len() {
        while left < right && records[right].epoch_secs() - records[left].epoch_secs() > window {
            left += 1;
        }
        let count = right - left + 1;
        if count > best {
            best = count;
            best_start = left;
        }
    }
    Some((best, best_start))
}

/// Two-pointer sliding window tracking how many distinct paths are inside it.
fn peak_distinct(records: &[&AuthFailure], window: i64) -> Option<(usize, usize)> {
    if records.is_empty() {
        return None;
    }
    let mut counts: HashMap<&str, u32> = HashMap::new();
    let mut left = 0usize;
    let mut best = 0usize;
    let mut best_start = 0usize;
    for right in 0..records.len() {
        *counts.entry(path_key(records[right])).or_insert(0) += 1;
        while left < right && records[right].epoch_secs() - records[left].epoch_secs() > window {
            let key = path_key(records[left]);
            if let Some(count) = counts.get_mut(key) {
                *count -= 1;
                if *count == 0 {
                    counts.remove(key);
                }
            }
            left += 1;
        }
        if counts.len() > best {
            best = counts.len();
            best_start = left;
        }
    }
    Some((best, best_start))
}

/// Enumeration counts distinct endpoints, so the query string is ignored.
fn path_key(failure: &AuthFailure) -> &str {
    failure
        .path
        .split(['?', '#'])
        .next()
        .unwrap_or(failure.path.as_str())
}

fn build_event(
    failure: &AuthFailure,
    ip: IpAddr,
    category: Category,
    rule_id: &'static str,
    rule_name: &'static str,
    severity: u8,
    evidence: String,
) -> ThreatEvent {
    ThreatEvent {
        line_no: failure.line_no,
        timestamp: Some(failure.timestamp),
        timestamp_raw: failure.timestamp.to_rfc3339(),
        source_ip: ip,
        category,
        rule_id,
        rule_name,
        severity,
        evidence,
        method: failure.method.clone(),
        path: failure.path.clone(),
        status: failure.status,
        user_agent: failure.user_agent.clone(),
        raw: failure.raw.clone(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, FixedOffset, TimeZone};

    use super::*;

    fn at(epoch: i64) -> DateTime<FixedOffset> {
        FixedOffset::east_opt(0)
            .expect("utc offset")
            .timestamp_opt(epoch, 0)
            .single()
            .expect("valid timestamp")
    }

    fn failure(line_no: u64, ip: &str, status: u16, path: &str, epoch: i64) -> AuthFailure {
        AuthFailure {
            line_no,
            source_ip: ip.parse().expect("valid address"),
            timestamp: at(epoch),
            status,
            method: "POST".to_string(),
            path: path.to_string(),
            user_agent: Some("curl/8.4.0".to_string()),
            raw: format!("{ip} - - [{epoch}] \"POST {path} HTTP/1.1\" {status}"),
        }
    }

    fn login_failures(count: usize, ip: &str, status: u16, base: i64) -> Vec<AuthFailure> {
        (0..count)
            .map(|i| {
                failure(
                    i as u64 + 1,
                    ip,
                    status,
                    "/wp-login.php",
                    base + i as i64,
                )
            })
            .collect()
    }

    #[test]
    fn thirty_login_failures_trigger_one_bruteforce_event() {
        let failures = login_failures(30, "198.51.100.5", 401, 1_700_000_000);
        let events = detect(&failures, 60, 20);

        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        let event = &events[0];
        assert_eq!(event.rule_id, "BF-001");
        assert_eq!(event.rule_name, "Authentication brute force");
        assert_eq!(event.category, Category::BruteForce);
        assert_eq!(event.severity, 7);
        assert!(
            event.evidence.contains("30 failed logins in 60s"),
            "unexpected evidence: {}",
            event.evidence
        );
        assert_eq!(event.source_ip.to_string(), "198.51.100.5");
        assert_eq!(event.status, 401);
        assert_eq!(event.method, "POST");
        assert_eq!(event.path, "/wp-login.php");
    }

    #[test]
    fn five_login_failures_do_not_trigger() {
        let failures = login_failures(5, "198.51.100.5", 401, 1_700_000_000);
        assert!(detect(&failures, 60, 20).is_empty());
    }

    #[test]
    fn failures_spread_beyond_the_window_do_not_trigger() {
        let failures: Vec<AuthFailure> = (0..30)
            .map(|i| {
                failure(
                    i as u64 + 1,
                    "198.51.100.5",
                    401,
                    "/login",
                    1_700_000_000 + i as i64 * 600,
                )
            })
            .collect();
        assert!(detect(&failures, 60, 20).is_empty());
    }

    #[test]
    fn severity_grows_with_the_peak_and_is_capped() {
        let failures = login_failures(100, "198.51.100.5", 401, 1_700_000_000);
        let events = detect(&failures, 60, 20);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, 9);
    }

    #[test]
    fn forty_distinct_404_paths_trigger_a_scan_event() {
        let failures: Vec<AuthFailure> = (0..40)
            .map(|i| {
                failure(
                    i as u64 + 1,
                    "203.0.113.77",
                    404,
                    &format!("/probe/{}", i),
                    1_700_000_000 + i as i64,
                )
            })
            .collect();

        let events = detect(&failures, 60, 20);
        assert_eq!(events.len(), 1, "expected one scan event: {events:?}");
        let event = &events[0];
        assert_eq!(event.rule_id, "SCAN-001");
        assert_eq!(event.rule_name, "Directory and endpoint enumeration");
        assert_eq!(event.category, Category::Reconnaissance);
        assert_eq!(event.severity, 5);
        assert!(
            event.evidence.contains("40 distinct 404/403 paths in 60s"),
            "unexpected evidence: {}",
            event.evidence
        );
    }

    #[test]
    fn scan_threshold_is_at_least_twenty_five_distinct_paths() {
        let paths = |count: usize| -> Vec<AuthFailure> {
            (0..count)
                .map(|i| {
                    failure(
                        i as u64 + 1,
                        "203.0.113.77",
                        404,
                        &format!("/probe/{}", i),
                        1_700_000_000 + i as i64,
                    )
                })
                .collect()
        };
        // threshold 5 => effective distinct-path threshold is 25.
        assert!(detect(&paths(24), 60, 5).is_empty());
        assert_eq!(detect(&paths(25), 60, 5).len(), 1);
    }

    /// Regression for the report's FN-7: at the default `--threshold 20` the
    /// old `2 * threshold` calibration needed 40 distinct paths.
    #[test]
    fn thirty_distinct_404_paths_fire_at_defaults() {
        let failures: Vec<AuthFailure> = (0..30)
            .map(|i| {
                failure(
                    i as u64 + 1,
                    "203.0.113.80",
                    404,
                    &format!("/probe/{}", i),
                    1_700_000_000 + i as i64,
                )
            })
            .collect();

        let events = detect(&failures, 30, 20);
        assert_eq!(events.len(), 1, "expected one scan event: {events:?}");
        assert_eq!(events[0].rule_id, "SCAN-001");
        assert!(
            events[0].evidence.contains("30 distinct 404/403 paths"),
            "unexpected evidence: {}",
            events[0].evidence
        );
    }

    /// Regression for the report's FP-5: a 403 burst on static assets is
    /// signed-URL / hotlink policy, not enumeration.
    #[test]
    fn distinct_403_static_assets_do_not_trigger_scan() {
        let failures: Vec<AuthFailure> = (0..40)
            .map(|i| {
                failure(
                    i as u64 + 1,
                    "203.0.113.90",
                    403,
                    &format!("/assets/private/{}.jpg", i),
                    1_700_000_000 + i as i64,
                )
            })
            .collect();

        let events = detect(&failures, 60, 20);
        assert!(
            !events.iter().any(|event| event.rule_id == "SCAN-001"),
            "static-asset 403 burst must not be enumeration: {events:?}"
        );
    }

    #[test]
    fn distinct_403_api_paths_still_trigger_scan() {
        let failures: Vec<AuthFailure> = (0..45)
            .map(|i| {
                failure(
                    i as u64 + 1,
                    "203.0.113.91",
                    403,
                    &format!("/api/v1/private/{}", i),
                    1_700_000_000 + i as i64,
                )
            })
            .collect();

        let events = detect(&failures, 60, 20);
        let scan = events
            .iter()
            .find(|event| event.rule_id == "SCAN-001")
            .expect("45 distinct API paths should be enumeration");
        assert!(
            scan.evidence.contains("45 distinct 404/403 paths"),
            "unexpected evidence: {}",
            scan.evidence
        );
    }

    #[test]
    fn unrelated_403s_on_normal_paths_do_not_trigger_auth_events() {
        let failures: Vec<AuthFailure> = (0..30)
            .map(|i| {
                failure(
                    i as u64 + 1,
                    "198.51.100.9",
                    403,
                    "/assets/app.css",
                    1_700_000_000 + i as i64,
                )
            })
            .collect();

        let events = detect(&failures, 60, 20);
        // A repeated 403 on one normal path is neither a login guess nor
        // enumeration, so it should not become an event at all.
        assert!(
            events.is_empty(),
            "unexpected events for repeated 403s: {events:?}"
        );
    }

    /// Regression for the report's FP-4: an expired-token client hitting many
    /// API endpoints is not a password-guessing attack.
    #[test]
    fn api_401_burst_is_low_severity_auth_failure_not_bruteforce() {
        let failures: Vec<AuthFailure> = (0..25)
            .map(|i| {
                failure(
                    i as u64 + 1,
                    "198.51.100.44",
                    401,
                    &format!("/api/v1/orders/{}", i),
                    1_700_000_000 + i as i64,
                )
            })
            .collect();

        let events = detect(&failures, 300, 20);
        assert_eq!(events.len(), 1, "expected one event: {events:?}");
        let event = &events[0];
        assert_eq!(event.rule_id, "AUTH-001");
        assert_eq!(event.rule_name, "Authentication failure burst");
        assert_eq!(event.category, Category::BruteForce);
        assert_eq!(event.severity, 4);
        assert!(
            event.evidence.contains("25 failed authentication responses in 300s"),
            "unexpected evidence: {}",
            event.evidence
        );
        assert!(
            event.evidence.contains("non-login endpoints"),
            "unexpected evidence: {}",
            event.evidence
        );
    }

    #[test]
    fn login_401_burst_still_reports_bruteforce_not_auth_burst() {
        let failures = login_failures(25, "198.51.100.44", 401, 1_700_000_000);
        let events = detect(&failures, 300, 20);
        assert_eq!(events.len(), 1, "expected one event: {events:?}");
        assert_eq!(events[0].rule_id, "BF-001");
        assert_eq!(events[0].severity, 7);
    }

    #[test]
    fn a_403_on_a_login_path_is_treated_as_an_auth_failure() {
        let failures: Vec<AuthFailure> = (0..30)
            .map(|i| {
                failure(
                    i as u64 + 1,
                    "198.51.100.9",
                    403,
                    "/wp-login.php",
                    1_700_000_000 + i as i64,
                )
            })
            .collect();

        let events = detect(&failures, 60, 20);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].rule_id, "BF-001");
    }

    #[test]
    fn even_spread_failures_report_the_first_record_of_the_peak_window() {
        let mut failures = vec![failure(1, "198.51.100.5", 401, "/login", 1_699_999_900)];
        for i in 0..30 {
            failures.push(failure(
                i as u64 + 2,
                "198.51.100.5",
                401,
                "/login",
                1_700_000_000 + i as i64,
            ));
        }

        let events = detect(&failures, 60, 20);
        assert_eq!(events.len(), 1);
        // The lone older failure falls outside the window, so the peak window
        // starts at the second record.
        assert_eq!(events[0].line_no, 2);
        assert_eq!(events[0].timestamp.map(|ts| ts.timestamp()), Some(1_700_000_000));
    }

    #[test]
    fn multiple_ips_produce_sorted_events() {
        let mut failures = login_failures(30, "203.0.113.4", 401, 1_700_000_000);
        failures.extend(login_failures(30, "198.51.100.9", 401, 1_700_000_000));

        let events = detect(&failures, 60, 20);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].source_ip.to_string(), "198.51.100.9");
        assert_eq!(events[1].source_ip.to_string(), "203.0.113.4");
    }

    #[test]
    fn empty_or_degenerate_input_never_panics() {
        assert!(detect(&[], 60, 20).is_empty());
        assert!(detect(&[], 0, 0).is_empty());

        let one = vec![failure(1, "198.51.100.5", 401, "/login", 1_700_000_000)];
        assert!(detect(&one, 0, 0).iter().all(|event| event.severity <= 9));
        assert!(detect(&one, u64::MAX, 1).len() <= 2);
    }
}
