//! Helpers shared by the detection unit tests. Compiled only under `cfg(test)`.

#![allow(dead_code)]

use std::sync::OnceLock;

use crate::model::entry::LogEntry;
use crate::model::threat::{Category, RuleHit};

use super::RuleEngine;

pub const DEFAULT_UA: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/// One engine for the whole test binary: rule compilation is expensive.
pub fn engine() -> &'static RuleEngine {
    static ENGINE: OnceLock<RuleEngine> = OnceLock::new();
    ENGINE.get_or_init(RuleEngine::new)
}

/// Default request: `GET <path>` from a public address with 200 and a browser UA.
pub fn entry(path: &str) -> LogEntry {
    entry_full("GET", path, DEFAULT_UA, 200)
}

/// Same as [`entry`] with a custom user agent.
pub fn entry_ua(path: &str, user_agent: &str) -> LogEntry {
    entry_full("GET", path, user_agent, 200)
}

pub fn entry_full(method: &str, path: &str, user_agent: &str, status: u16) -> LogEntry {
    LogEntry {
        line_no: 1,
        source_ip: "203.0.113.10".parse().expect("valid test address"),
        timestamp: None,
        timestamp_raw: "-".to_string(),
        method: method.to_string(),
        path: path.to_string(),
        protocol: "HTTP/1.1".to_string(),
        status,
        body_bytes: 512,
        referer: None,
        user_agent: Some(user_agent.to_string()),
        host: Some("example.com".to_string()),
        raw: format!("{method} {path} HTTP/1.1"),
    }
}

pub fn hits(entry: &LogEntry) -> Vec<RuleHit> {
    engine().inspect(entry)
}

pub fn ids(entry: &LogEntry) -> Vec<&'static str> {
    hits(entry).into_iter().map(|hit| hit.rule_id).collect()
}

pub fn assert_hit(entry: &LogEntry, rule_id: &str) {
    let found = hits(entry);
    assert!(
        found.iter().any(|hit| hit.rule_id == rule_id),
        "expected rule {rule_id} for path {:?}, got {:?}",
        entry.path,
        found
            .iter()
            .map(|hit| (hit.rule_id, hit.evidence.as_str()))
            .collect::<Vec<_>>()
    );
}

pub fn assert_no_hit(entry: &LogEntry, rule_id: &str) {
    let found = hits(entry);
    assert!(
        !found.iter().any(|hit| hit.rule_id == rule_id),
        "did not expect rule {rule_id} for path {:?}",
        entry.path
    );
}

pub fn assert_clean(entry: &LogEntry) {
    let found = hits(entry);
    assert!(
        found.is_empty(),
        "expected no hits for {:?}, got {:?}",
        entry.path,
        found
            .iter()
            .map(|hit| (hit.rule_id, hit.evidence.as_str()))
            .collect::<Vec<_>>()
    );
}

/// Assert that no rule from `category` fired, without constraining the other
/// families (a payload may legitimately trip unrelated informational rules).
pub fn assert_no_category(entry: &LogEntry, category: Category) {
    let found = hits(entry);
    assert!(
        !found.iter().any(|hit| hit.category == category),
        "did not expect a {:?} event for {:?}, got {:?}",
        category,
        entry.path,
        found
            .iter()
            .map(|hit| (hit.rule_id, hit.evidence.as_str()))
            .collect::<Vec<_>>()
    );
}
