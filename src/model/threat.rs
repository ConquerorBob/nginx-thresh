use std::net::IpAddr;

use chrono::{DateTime, FixedOffset};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    CommandInjection,
    Log4Shell,
    Webshell,
    LocalFileInclusion,
    SqlInjection,
    PathTraversal,
    Ssrf,
    BruteForce,
    CrossSiteScripting,
    SensitiveFileAccess,
    Reconnaissance,
    MalformedRequest,
    Other,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::CommandInjection => "Command Injection",
            Category::Log4Shell => "Log4Shell",
            Category::Webshell => "Webshell",
            Category::LocalFileInclusion => "Local File Inclusion",
            Category::SqlInjection => "SQL Injection",
            Category::PathTraversal => "Path Traversal",
            Category::Ssrf => "SSRF",
            Category::BruteForce => "Brute Force",
            Category::CrossSiteScripting => "XSS",
            Category::SensitiveFileAccess => "Sensitive File Access",
            Category::Reconnaissance => "Reconnaissance",
            Category::MalformedRequest => "Malformed Request",
            Category::Other => "Other",
        }
    }

    #[allow(dead_code)]
    pub fn all() -> &'static [Category] {
        &[
            Category::CommandInjection,
            Category::Log4Shell,
            Category::Webshell,
            Category::LocalFileInclusion,
            Category::SqlInjection,
            Category::PathTraversal,
            Category::Ssrf,
            Category::BruteForce,
            Category::CrossSiteScripting,
            Category::SensitiveFileAccess,
            Category::Reconnaissance,
            Category::MalformedRequest,
            Category::Other,
        ]
    }
}

/// A single rule hit produced by the detection engine for one log entry.
#[derive(Debug, Clone)]
pub struct RuleHit {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub category: Category,
    /// Base severity weight 1..=10 assigned by the rule author.
    pub severity: u8,
    /// Short human-readable reason, e.g. "path contains ../ after one decode".
    pub evidence: String,
}

/// A suspicious event tied back to the exact log line that produced it.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ThreatEvent {
    pub line_no: u64,
    pub timestamp: Option<DateTime<FixedOffset>>,
    pub timestamp_raw: String,
    pub source_ip: IpAddr,
    pub category: Category,
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub severity: u8,
    pub evidence: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub user_agent: Option<String>,
    pub raw: String,
}
