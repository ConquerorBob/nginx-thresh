use std::net::IpAddr;

use chrono::{DateTime, FixedOffset};

/// One successfully parsed nginx access-log line.
///
/// Some fields are retained for API completeness even when the dashboard and
/// rule engine do not read them yet.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// 1-based line number inside the file.
    pub line_no: u64,
    pub source_ip: IpAddr,
    pub timestamp: Option<DateTime<FixedOffset>>,
    pub timestamp_raw: String,
    pub method: String,
    /// Request target, including the query string.
    pub path: String,
    pub protocol: String,
    pub status: u16,
    pub body_bytes: u64,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    pub host: Option<String>,
    pub raw: String,
}

#[allow(dead_code)]
impl LogEntry {
    pub fn request_line(&self) -> String {
        format!("{} {} {}", self.method, self.path, self.protocol)
    }

    pub fn path_only(&self) -> &str {
        self.path
            .split(['?', '#'])
            .next()
            .unwrap_or(self.path.as_str())
    }

    pub fn query(&self) -> Option<&str> {
        self.path
            .split_once('?')
            .map(|(_, rest)| rest.split('#').next().unwrap_or(rest))
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// A 401/403/404 response kept aside for stateful analysis (brute force and
/// enumeration/scan detection). Only responses with a parsed timestamp are
/// recorded.
#[derive(Debug, Clone)]
pub struct AuthFailure {
    pub line_no: u64,
    pub source_ip: IpAddr,
    pub timestamp: DateTime<FixedOffset>,
    pub status: u16,
    pub method: String,
    pub path: String,
    pub user_agent: Option<String>,
    pub raw: String,
}

impl AuthFailure {
    pub fn epoch_secs(&self) -> i64 {
        self.timestamp.timestamp()
    }
}
