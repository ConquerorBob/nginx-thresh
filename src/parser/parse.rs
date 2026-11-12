//! Line-oriented parsing of nginx `access_log` records.
//!
//! Supported layouts, in match order:
//!
//! 1. the stock `combined` format
//!    `$remote_addr - $remote_user [$time_local] "$request" $status
//!     $body_bytes_sent "$http_referer" "$http_user_agent"`
//! 2. the stock `common` format (same, without referer/user-agent),
//! 3. the same two layouts with a leading virtual-host token,
//!    e.g. `www.example.com 93.184.216.34 - - [...] "GET / HTTP/1.1" ...`,
//! 4. flat JSON log lines (a lightweight, dependency-free fallback).
//!
//! All layouts accept optional trailing fields (request time, upstream,
//! `X-Forwarded-For`, ...). Parsing is total: malformed input returns `None`
//! and never panics.
//!
//! The layout scanner is hand-written rather than regex-based because the
//! regex crate's capture extraction costs several microseconds per line, while
//! a structural scan of this fixed grammar costs a few hundred nanoseconds.

use std::borrow::Cow;
use std::cell::RefCell;
use std::net::IpAddr;

use chrono::{DateTime, FixedOffset};

use crate::model::entry::LogEntry;

/// Longest line the parser will consider. The reader rejects longer lines as
/// malformed instead of buffering them in full.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

const NGINX_TIME_FORMAT: &str = "%d/%b/%Y:%H:%M:%S %z";

/// Parse one trimmed access-log line.
///
/// `line_no` is stored verbatim in the resulting entry; the reader later
/// rebases it to whole-file numbering. Returns `None` when the line matches no
/// supported layout or carries an invalid source address.
pub fn parse_line(raw_line: &str, line_no: u64) -> Option<LogEntry> {
    let line = raw_line.trim();
    if line.is_empty() {
        return None;
    }
    // Standard layout first, then the virtual-host variant, exactly like two
    // ordered patterns would be tried.
    if let Some(entry) = parse_layout(line, line_no, false) {
        return Some(entry);
    }
    if let Some(entry) = parse_layout(line, line_no, true) {
        return Some(entry);
    }
    if line.starts_with('{') {
        return parse_json(line, line_no);
    }
    None
}

/// Byte cursor over one log line. Field boundaries are ASCII, so slicing is
/// always done at ASCII offsets and stays on UTF-8 char boundaries even when a
/// quoted field contains multi-byte text.
struct Cursor<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Consume a run of spaces; reports whether at least one was present.
    fn skip_spaces(&mut self) -> bool {
        let start = self.pos;
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
        self.pos > start
    }

    /// A whitespace-free token, e.g. the address, ident, user, status or byte
    /// count. Does not consume the following separator.
    fn token(&mut self) -> Option<&'a str> {
        let start = self.pos;
        while matches!(self.peek(), Some(byte) if byte != b' ') {
            self.pos += 1;
        }
        if self.pos == start {
            None
        } else {
            Some(&self.text[start..self.pos])
        }
    }

    fn expect(&mut self, byte: u8) -> Option<()> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    /// Capture up to (and consume) `terminator`, used for `[time_local]`.
    fn until(&mut self, terminator: u8) -> Option<&'a str> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte == terminator {
                let slice = &self.text[start..self.pos];
                self.pos += 1;
                return Some(slice);
            }
            self.pos += 1;
        }
        None
    }

    /// Capture a double-quoted field, honouring backslash escapes. The closing
    /// quote is always an ASCII byte, hence always a char boundary.
    fn quoted(&mut self) -> Option<&'a str> {
        self.expect(b'"')?;
        let start = self.pos;
        while let Some(byte) = self.peek() {
            match byte {
                b'\\' => {
                    // Skip the escaped byte. A dangling backslash at end of
                    // line simply means no closing quote follows.
                    self.pos += 2;
                }
                b'"' => {
                    let slice = &self.text[start..self.pos];
                    self.pos += 1;
                    return Some(slice);
                }
                _ => self.pos += 1,
            }
        }
        None
    }
}

fn parse_layout(line: &str, line_no: u64, has_host: bool) -> Option<LogEntry> {
    let mut cursor = Cursor::new(line);

    let host = if has_host {
        let host = cursor.token()?;
        if !cursor.skip_spaces() {
            return None;
        }
        Some(host)
    } else {
        None
    };

    let remote_addr = cursor.token()?;
    if !cursor.skip_spaces() {
        return None;
    }
    let _ident = cursor.token()?;
    if !cursor.skip_spaces() {
        return None;
    }
    let _remote_user = cursor.token()?;
    if !cursor.skip_spaces() {
        return None;
    }
    cursor.expect(b'[')?;
    let time_local = cursor.until(b']')?;
    if !cursor.skip_spaces() {
        return None;
    }
    let request_raw = cursor.quoted()?;
    if !cursor.skip_spaces() {
        return None;
    }
    let status_raw = cursor.token()?;
    if !cursor.skip_spaces() {
        return None;
    }
    let bytes_raw = cursor.token()?;

    let source_ip = parse_ip(remote_addr)?;
    if status_raw.len() != 3 || !status_raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let status: u16 = status_raw.parse().ok()?;

    let timestamp_raw = time_local.to_string();
    let timestamp = parse_timestamp_cached(&timestamp_raw);
    let request = unescape_cow(request_raw);
    let (method, path, protocol) = split_request(&request);
    let body_bytes = parse_byte_count(bytes_raw);

    // Referer and user-agent are only recognised as a pair; anything else
    // after the byte count is an optional trailing field and is ignored.
    let mut referer = None;
    let mut user_agent = None;
    if cursor.skip_spaces() && cursor.peek() == Some(b'"') {
        if let Some(first) = cursor.quoted() {
            if cursor.skip_spaces() && cursor.peek() == Some(b'"') {
                if let Some(second) = cursor.quoted() {
                    referer = optional_field(first);
                    user_agent = optional_field(second);
                }
            }
        }
    }

    Some(LogEntry {
        line_no,
        source_ip,
        timestamp,
        timestamp_raw,
        method,
        path,
        protocol,
        status,
        body_bytes,
        referer,
        user_agent,
        host: host.and_then(optional_field),
        raw: line.to_string(),
    })
}

fn parse_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    // Some shippers bracket IPv6 literals; the address itself is what matters.
    let candidate = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed);
    candidate.parse().ok()
}

fn parse_timestamp(raw: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_str(raw, NGINX_TIME_FORMAT).ok()
}

thread_local! {
    /// `$time_local` has one-second resolution, so a busy log repeats the same
    /// timestamp string on many consecutive lines. Remembering the last result
    /// avoids chrono's month-name lookup per line while keeping identical
    /// semantics (an exact string match is required for a hit).
    static LAST_TIMESTAMP: RefCell<Option<(String, Option<DateTime<FixedOffset>>)>> =
        const { RefCell::new(None) };
}

fn parse_timestamp_cached(raw: &str) -> Option<DateTime<FixedOffset>> {
    LAST_TIMESTAMP.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some((cached_raw, cached_value)) = slot.as_ref() {
            if cached_raw == raw {
                return *cached_value;
            }
        }
        let value = parse_timestamp(raw);
        *slot = Some((raw.to_string(), value));
        value
    })
}

fn parse_byte_count(raw: &str) -> u64 {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return 0;
    }
    trimmed.parse().unwrap_or(0)
}

/// Empty and `-` placeholder fields become `None`, without allocating.
fn optional_field(raw: &str) -> Option<String> {
    if raw.is_empty() || raw == "-" {
        None
    } else {
        Some(unescape(raw))
    }
}

/// Split a request line into method, target and protocol. Degenerate requests
/// (a single token, or the `-` placeholder) become `-` fields rather than
/// failing the whole entry.
fn split_request(request: &str) -> (String, String, String) {
    let request = request.trim();
    if request.is_empty() || request == "-" {
        return ("-".to_string(), "-".to_string(), "-".to_string());
    }
    let mut parts = request.split_ascii_whitespace();
    let Some(method) = parts.next() else {
        return ("-".to_string(), "-".to_string(), "-".to_string());
    };
    let Some(target) = parts.next() else {
        return (method.to_string(), "-".to_string(), "-".to_string());
    };
    let Some(protocol) = parts.next() else {
        return (method.to_string(), target.to_string(), "-".to_string());
    };

    // Requests with more than three tokens have their middle tokens folded
    // back into the target, with the last token as the protocol. That only
    // allocates when such a request actually occurs.
    let mut protocol = protocol;
    let mut folded: Option<String> = None;
    for part in parts {
        match folded.as_mut() {
            Some(path) => {
                path.push(' ');
                path.push_str(protocol);
            }
            None => {
                let mut path = String::from(target);
                path.push(' ');
                path.push_str(protocol);
                folded = Some(path);
            }
        }
        protocol = part;
    }

    match folded {
        Some(path) => (method.to_string(), path, protocol.to_string()),
        None => (method.to_string(), target.to_string(), protocol.to_string()),
    }
}

/// Undo nginx's `escape=` encoding: `\"`, `\\`, `\n`, `\r`, `\t` and `\xHH`.
/// Unknown escapes are preserved verbatim. Invalid UTF-8 is replaced lossily so
/// binary junk in a log line cannot panic or be dropped silently.
fn unescape(input: &str) -> String {
    if !input.contains('\\') {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'"' => {
                    out.push(b'"');
                    i += 2;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                }
                b'x' if i + 3 < bytes.len() => {
                    match (hex_value(bytes[i + 2]), hex_value(bytes[i + 3])) {
                        (Some(high), Some(low)) => {
                            out.push((high << 4) | low);
                            i += 4;
                        }
                        _ => {
                            out.push(b'\\');
                            i += 1;
                        }
                    }
                }
                _ => {
                    out.push(b'\\');
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Borrowed when the field needs no unescaping, which is the common case.
fn unescape_cow(input: &str) -> Cow<'_, str> {
    if input.contains('\\') {
        Cow::Owned(unescape(input))
    } else {
        Cow::Borrowed(input)
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// JSON fallback
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum JsonValue {
    Str(String),
    Num(String),
    Other,
}

fn parse_json(line: &str, line_no: u64) -> Option<LogEntry> {
    let fields = parse_json_object(line)?;

    let source_ip = parse_ip(json_str(&fields, "remote_addr")?)?;
    let status = u16::try_from(json_u64(&fields, "status")?).ok()?;

    let (timestamp_raw, timestamp) = match json_str(&fields, "time_local") {
        Some(raw) => (raw.to_string(), parse_timestamp(raw)),
        None => match json_str(&fields, "time_iso8601") {
            Some(raw) => (raw.to_string(), parse_rfc3339(raw)),
            None => match json_str(&fields, "time") {
                Some(raw) => (
                    raw.to_string(),
                    parse_timestamp(raw).or_else(|| parse_rfc3339(raw)),
                ),
                None => (String::new(), None),
            },
        },
    };

    let request = match json_str(&fields, "request") {
        Some(request) => request.to_string(),
        None => {
            let method = json_str(&fields, "request_method").unwrap_or("-");
            let target = json_str(&fields, "request_uri").unwrap_or("-");
            let protocol = json_str(&fields, "server_protocol").unwrap_or("-");
            if method == "-" && target == "-" {
                "-".to_string()
            } else {
                format!("{method} {target} {protocol}")
            }
        }
    };
    let (method, path, protocol) = split_request(&request);

    let body_bytes = json_u64(&fields, "body_bytes_sent").unwrap_or(0);
    let referer = json_str(&fields, "http_referer").and_then(json_optional_field);
    let user_agent = json_str(&fields, "http_user_agent").and_then(json_optional_field);
    let host = json_str(&fields, "host")
        .or_else(|| json_str(&fields, "server_name"))
        .and_then(json_optional_field);

    Some(LogEntry {
        line_no,
        source_ip,
        timestamp,
        timestamp_raw,
        method,
        path,
        protocol,
        status,
        body_bytes,
        referer,
        user_agent,
        host,
        raw: line.to_string(),
    })
}

fn parse_rfc3339(raw: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(raw).ok()
}

fn json_optional_field(value: &str) -> Option<String> {
    if value.is_empty() || value == "-" {
        None
    } else {
        Some(value.to_string())
    }
}

fn json_field<'a>(fields: &'a [(String, JsonValue)], name: &str) -> Option<&'a JsonValue> {
    fields
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn json_str<'a>(fields: &'a [(String, JsonValue)], name: &str) -> Option<&'a str> {
    match json_field(fields, name)? {
        JsonValue::Str(value) => Some(value.as_str()),
        _ => None,
    }
}

fn json_u64(fields: &[(String, JsonValue)], name: &str) -> Option<u64> {
    match json_field(fields, name)? {
        JsonValue::Num(raw) => raw.parse().ok(),
        JsonValue::Str(raw) => {
            let trimmed = raw.trim();
            if trimmed == "-" {
                Some(0)
            } else {
                trimmed.parse().ok()
            }
        }
        _ => None,
    }
}

fn parse_json_object(input: &str) -> Option<Vec<(String, JsonValue)>> {
    let bytes = input.as_bytes();
    let mut pos = skip_json_ws(bytes, 0);
    if bytes.get(pos) != Some(&b'{') {
        return None;
    }
    pos += 1;
    let mut fields = Vec::new();
    loop {
        pos = skip_json_ws(bytes, pos);
        match *bytes.get(pos)? {
            b'}' => return Some(fields),
            b'"' => {
                let (key, next) = parse_json_string(bytes, pos)?;
                pos = skip_json_ws(bytes, next);
                if bytes.get(pos) != Some(&b':') {
                    return None;
                }
                pos = skip_json_ws(bytes, pos + 1);
                let (value, next) = parse_json_value(bytes, pos)?;
                fields.push((key, value));
                pos = skip_json_ws(bytes, next);
                match *bytes.get(pos)? {
                    b',' => pos += 1,
                    b'}' => return Some(fields),
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
}

fn skip_json_ws(bytes: &[u8], mut pos: usize) -> usize {
    while matches!(bytes.get(pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        pos += 1;
    }
    pos
}

fn parse_json_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut pos = start + 1;
    while let Some(&byte) = bytes.get(pos) {
        match byte {
            b'"' => return Some((out, pos + 1)),
            b'\\' => {
                let escape = *bytes.get(pos + 1)?;
                match escape {
                    b'"' => {
                        out.push('"');
                        pos += 2;
                    }
                    b'\\' => {
                        out.push('\\');
                        pos += 2;
                    }
                    b'/' => {
                        out.push('/');
                        pos += 2;
                    }
                    b'b' => {
                        out.push('\u{8}');
                        pos += 2;
                    }
                    b'f' => {
                        out.push('\u{c}');
                        pos += 2;
                    }
                    b'n' => {
                        out.push('\n');
                        pos += 2;
                    }
                    b'r' => {
                        out.push('\r');
                        pos += 2;
                    }
                    b't' => {
                        out.push('\t');
                        pos += 2;
                    }
                    b'u' => {
                        let digits = bytes.get(pos + 2..pos + 6)?;
                        let text = std::str::from_utf8(digits).ok()?;
                        let code = u16::from_str_radix(text, 16).ok()?;
                        out.push(char::from_u32(u32::from(code)).unwrap_or('\u{fffd}'));
                        pos += 6;
                    }
                    _ => return None,
                }
            }
            _ => {
                let rest = std::str::from_utf8(&bytes[pos..]).ok()?;
                let ch = rest.chars().next()?;
                out.push(ch);
                pos += ch.len_utf8();
            }
        }
    }
    None
}

fn parse_json_value(bytes: &[u8], start: usize) -> Option<(JsonValue, usize)> {
    match *bytes.get(start)? {
        b'"' => {
            let (value, next) = parse_json_string(bytes, start)?;
            Some((JsonValue::Str(value), next))
        }
        b't' => {
            expect_json_literal(bytes, start, b"true")?;
            Some((JsonValue::Other, start + 4))
        }
        b'f' => {
            expect_json_literal(bytes, start, b"false")?;
            Some((JsonValue::Other, start + 5))
        }
        b'n' => {
            expect_json_literal(bytes, start, b"null")?;
            Some((JsonValue::Other, start + 4))
        }
        b'{' | b'[' => {
            let next = skip_json_compound(bytes, start)?;
            Some((JsonValue::Other, next))
        }
        _ => {
            let mut end = start;
            while let Some(&byte) = bytes.get(end) {
                if matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                    end += 1;
                } else {
                    break;
                }
            }
            if end == start {
                return None;
            }
            let raw = std::str::from_utf8(&bytes[start..end]).ok()?;
            Some((JsonValue::Num(raw.to_string()), end))
        }
    }
}

fn expect_json_literal(bytes: &[u8], start: usize, literal: &[u8]) -> Option<()> {
    if bytes.get(start..start + literal.len()) == Some(literal) {
        Some(())
    } else {
        None
    }
}

/// Skip a nested object/array without interpreting it. Only used for fields we
/// do not read, so structural tolerance is enough.
fn skip_json_compound(bytes: &[u8], start: usize) -> Option<usize> {
    let open = *bytes.get(start)?;
    let close = match open {
        b'{' => b'}',
        b'[' => b']',
        _ => return None,
    };
    let mut depth: i32 = 0;
    let mut pos = start;
    while let Some(&byte) = bytes.get(pos) {
        match byte {
            b'"' => {
                let (_, next) = parse_json_string(bytes, pos)?;
                pos = next;
            }
            b if b == open => {
                depth += 1;
                pos += 1;
            }
            b if b == close => {
                depth -= 1;
                pos += 1;
                if depth == 0 {
                    return Some(pos);
                }
            }
            _ => pos += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: &str = "10/Oct/2000:13:55:36 -0700";

    fn combined() -> String {
        format!(
            r#"93.184.216.34 - frank [{TS}] "GET /index.html?q=1 HTTP/1.1" 200 612 "https://example.com/start" "Mozilla/5.0 (X11; Linux x86_64)""#
        )
    }

    #[test]
    fn combined_parses_every_field() {
        let entry = parse_line(&combined(), 7).expect("combined line must parse");
        assert_eq!(entry.line_no, 7);
        assert_eq!(entry.source_ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/index.html?q=1");
        assert_eq!(entry.protocol, "HTTP/1.1");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.body_bytes, 612);
        assert_eq!(entry.referer.as_deref(), Some("https://example.com/start"));
        assert_eq!(
            entry.user_agent.as_deref(),
            Some("Mozilla/5.0 (X11; Linux x86_64)")
        );
        assert_eq!(entry.host, None);
        assert_eq!(entry.timestamp_raw, TS);
        assert!(entry.timestamp.is_some());
        assert_eq!(entry.raw, combined());
        assert_eq!(entry.path_only(), "/index.html");
        assert_eq!(entry.query(), Some("q=1"));
    }

    #[test]
    fn common_without_referer_or_user_agent() {
        let line = format!(r#"93.184.216.34 - - [{TS}] "POST /login HTTP/1.1" 401 0"#);
        let entry = parse_line(&line, 1).expect("common line must parse");
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.status, 401);
        assert_eq!(entry.body_bytes, 0);
        assert_eq!(entry.referer, None);
        assert_eq!(entry.user_agent, None);
    }

    #[test]
    fn common_with_extra_trailing_fields() {
        let line = format!(
            r#"93.184.216.34 - - [{TS}] "GET / HTTP/1.1" 200 5 0.004 10.0.0.9:8080 "203.0.113.5""#
        );
        let entry = parse_line(&line, 1).expect("common + trailing fields must parse");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.body_bytes, 5);
        assert_eq!(entry.referer, None);
        assert_eq!(entry.user_agent, None);
    }

    #[test]
    fn combined_with_extra_trailing_fields() {
        let line = format!(
            r#"93.184.216.34 - - [{TS}] "GET / HTTP/1.1" 200 5 "-" "curl/8.5.0" 0.004 10.0.0.9:8080 "203.0.113.5""#
        );
        let entry = parse_line(&line, 1).expect("combined + trailing fields must parse");
        assert_eq!(entry.user_agent.as_deref(), Some("curl/8.5.0"));
    }

    #[test]
    fn vhost_combined_sets_host() {
        let line = format!(
            r#"www.example.com 93.184.216.34 - - [{TS}] "GET / HTTP/1.1" 200 612 "-" "curl/8.5.0""#
        );
        let entry = parse_line(&line, 3).expect("vhost combined line must parse");
        assert_eq!(entry.host.as_deref(), Some("www.example.com"));
        assert_eq!(entry.source_ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(entry.status, 200);
    }

    #[test]
    fn vhost_common_layout() {
        let line = format!(r#"api.example.com 93.184.216.34 - - [{TS}] "GET /v1 HTTP/1.1" 204 0"#);
        let entry = parse_line(&line, 1).expect("vhost common line must parse");
        assert_eq!(entry.host.as_deref(), Some("api.example.com"));
        assert_eq!(entry.status, 204);
        assert_eq!(entry.user_agent, None);
    }

    #[test]
    fn ipv6_source_address() {
        let line = format!(r#"2001:db8::1 - - [{TS}] "GET / HTTP/1.1" 200 1 "-" "curl/8.5.0""#);
        let entry = parse_line(&line, 1).expect("IPv6 line must parse");
        assert_eq!(entry.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert!(entry.source_ip.is_ipv6());

        let bracketed =
            format!(r#"[2001:db8::2] - - [{TS}] "GET / HTTP/1.1" 200 1 "-" "curl/8.5.0""#);
        let entry = parse_line(&bracketed, 2).expect("bracketed IPv6 line must parse");
        assert_eq!(entry.source_ip, "2001:db8::2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn dash_placeholders_become_empty_fields() {
        let line = format!(r#"93.184.216.34 - - [{TS}] "-" 400 - "-" "-""#);
        let entry = parse_line(&line, 1).expect("placeholder line must parse");
        assert_eq!(entry.method, "-");
        assert_eq!(entry.path, "-");
        assert_eq!(entry.protocol, "-");
        assert_eq!(entry.body_bytes, 0);
        assert_eq!(entry.referer, None);
        assert_eq!(entry.user_agent, None);
    }

    #[test]
    fn escaped_quotes_inside_fields() {
        let line = format!(
            r#"93.184.216.34 - - [{TS}] "GET /?q=\"><script>alert(1)</script> HTTP/1.1" 200 12 "-" "Mozilla \"X\"""#
        );
        let entry = parse_line(&line, 1).expect("escaped-quote line must parse");
        assert_eq!(entry.path, r#"/?q="><script>alert(1)</script>"#);
        assert_eq!(entry.user_agent.as_deref(), Some(r#"Mozilla "X""#));
        assert_eq!(entry.status, 200);
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert!(parse_line("this is definitely not an access log", 1).is_none());
        assert!(parse_line("", 1).is_none());
        assert!(parse_line("   ", 1).is_none());
        assert!(parse_line(
            r#"93.184.216.34 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 20x 5"#,
            1
        )
        .is_none());
    }

    #[test]
    fn non_ip_remote_addr_is_rejected() {
        let line = format!(r#"localhost - - [{TS}] "GET / HTTP/1.1" 200 1 "-" "curl/8.5.0""#);
        assert!(parse_line(&line, 1).is_none());

        let vhost_with_bad_addr =
            format!(r#"www.example.com not-an-ip - - [{TS}] "GET / HTTP/1.1" 200 1"#);
        assert!(parse_line(&vhost_with_bad_addr, 1).is_none());
    }

    #[test]
    fn crlf_and_surrounding_whitespace_are_tolerated() {
        let line = format!("{}  \r", combined());
        let entry = parse_line(&line, 1).expect("CRLF line must parse");
        assert_eq!(entry.raw, combined());
        assert_eq!(entry.status, 200);

        let padded = format!("   {}   ", combined());
        assert!(parse_line(&padded, 2).is_some());
    }

    #[test]
    fn invalid_timestamp_keeps_entry_with_none() {
        let line = r#"93.184.216.34 - - [10/Foo/2000:99:99:99 +0000] "GET / HTTP/1.1" 200 1 "-" "curl/8.5.0""#;
        let entry = parse_line(line, 1).expect("entry must survive a bad timestamp");
        assert!(entry.timestamp.is_none());
        assert_eq!(entry.timestamp_raw, "10/Foo/2000:99:99:99 +0000");
        assert_eq!(entry.status, 200);
    }

    #[test]
    fn request_without_protocol_and_multi_token_target() {
        let two = format!(r#"93.184.216.34 - - [{TS}] "GET /old-style" 200 1"#);
        let entry = parse_line(&two, 1).expect("two-token request must parse");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/old-style");
        assert_eq!(entry.protocol, "-");

        let multi = format!(r#"93.184.216.34 - - [{TS}] "GET /a b HTTP/1.1" 200 1"#);
        let entry = parse_line(&multi, 1).expect("multi-token target must parse");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/a b");
        assert_eq!(entry.protocol, "HTTP/1.1");
    }

    #[test]
    fn json_lines_are_parsed() {
        let line = r#"{"remote_addr":"203.0.113.7","time_local":"10/Oct/2000:13:55:36 -0700","request":"GET /api?x=1 HTTP/1.1","status":404,"body_bytes_sent":17,"http_referer":"-","http_user_agent":"curl/8.5.0","host":"api.example.com","extra":{"a":[1,2,{"b":"}"}]}}"#;
        let entry = parse_line(line, 4).expect("JSON line must parse");
        assert_eq!(entry.line_no, 4);
        assert_eq!(entry.source_ip, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/api?x=1");
        assert_eq!(entry.status, 404);
        assert_eq!(entry.body_bytes, 17);
        assert_eq!(entry.referer, None);
        assert_eq!(entry.user_agent.as_deref(), Some("curl/8.5.0"));
        assert_eq!(entry.host.as_deref(), Some("api.example.com"));
        assert!(entry.timestamp.is_some());
    }

    #[test]
    fn json_iso8601_time_and_numeric_strings() {
        let line = r#"{"remote_addr":"203.0.113.7","time_iso8601":"2000-10-10T13:55:36+00:00","request":"GET / HTTP/1.1","status":"200","body_bytes_sent":"9","http_user_agent":"-","host":"-","ignored":[true,false,null,1.5e3]}"#;
        let entry = parse_line(line, 1).expect("ISO JSON line must parse");
        assert!(entry.timestamp.is_some());
        assert_eq!(entry.status, 200);
        assert_eq!(entry.body_bytes, 9);
        assert_eq!(entry.user_agent, None);
        assert_eq!(entry.host, None);
    }

    #[test]
    fn json_without_source_address_is_malformed() {
        let line = r#"{"request":"GET / HTTP/1.1","status":200}"#;
        assert!(parse_line(line, 1).is_none());
    }

    #[test]
    fn unescape_handles_control_and_hex_escapes() {
        assert_eq!(unescape(r#"a\"b"#), r#"a"b"#);
        assert_eq!(unescape(r"a\\b"), r"a\b");
        assert_eq!(unescape(r"a\nb"), "a\nb");
        assert_eq!(unescape(r"a\x41b"), "aAb");
        assert_eq!(unescape(r"a\qb"), r"a\qb");
    }
}
