//! Shared rule plumbing.
//!
//! Everything expensive (regex compilation) happens once in
//! [`Matcher::new`]; per line the engine only runs a handful of aggregate
//! [`RegexSet`]s against pre-computed views of the request. Individual
//! [`Regex`] objects are kept alongside each set purely to locate the match
//! offset when producing an evidence excerpt, and are only touched when a
//! rule already fired.

use regex::{Regex, RegexSet};

use crate::model::entry::LogEntry;
use crate::model::threat::{Category, RuleHit};

/// Hard cap on the length of an evidence excerpt, in `char`s.
pub const MAX_EXCERPT_CHARS: usize = 120;

/// Which pre-computed view of the request a pattern is matched against.
///
/// All haystacks are lowercase, so patterns never need `(?i)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Scope {
    /// Raw request target, still percent-encoded.
    RawPath = 0,
    /// Path + query, percent-decoded once (and twice for the double-decode
    /// pass) and lowercased.
    Target = 1,
    /// `User-Agent`, lowercased.
    UserAgent = 2,
    /// `Referer`, lowercased.
    Referer = 3,
}

pub(crate) const SCOPE_COUNT: usize = 4;

impl Scope {
    pub(crate) const ALL: [Scope; SCOPE_COUNT] = [
        Scope::RawPath,
        Scope::Target,
        Scope::UserAgent,
        Scope::Referer,
    ];
}

/// A regex-backed check plus the scope it applies to.
#[derive(Clone, Copy, Debug)]
pub struct Pattern {
    pub scope: Scope,
    /// Short machine-friendly label used in evidence strings, e.g.
    /// `traversal_dotdot`.
    pub slug: &'static str,
    /// Pattern written for a lowercase haystack.
    pub regex: &'static str,
}

/// How a rule decides whether it fired.
#[derive(Clone, Copy, Debug)]
pub enum Detector {
    Pattern(Pattern),
    /// Implemented by a hand-written check in the owning family module.
    Custom,
}

/// Static metadata for one detection rule.
#[derive(Clone, Copy, Debug)]
pub struct RuleSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub category: Category,
    /// Base severity, 1..=10.
    pub severity: u8,
    pub detector: Detector,
}

impl RuleSpec {
    /// Rule matched against the decoded target.
    pub const fn target(
        id: &'static str,
        name: &'static str,
        slug: &'static str,
        category: Category,
        severity: u8,
        regex: &'static str,
    ) -> Self {
        Self::with_scope(id, name, slug, category, severity, regex, Scope::Target)
    }

    /// Rule matched against the still-encoded request target.
    pub const fn raw(
        id: &'static str,
        name: &'static str,
        slug: &'static str,
        category: Category,
        severity: u8,
        regex: &'static str,
    ) -> Self {
        Self::with_scope(id, name, slug, category, severity, regex, Scope::RawPath)
    }

    /// Rule matched against the `User-Agent`.
    pub const fn user_agent(
        id: &'static str,
        name: &'static str,
        slug: &'static str,
        category: Category,
        severity: u8,
        regex: &'static str,
    ) -> Self {
        Self::with_scope(id, name, slug, category, severity, regex, Scope::UserAgent)
    }

    /// Rule matched against the `Referer`.
    pub const fn referer(
        id: &'static str,
        name: &'static str,
        slug: &'static str,
        category: Category,
        severity: u8,
        regex: &'static str,
    ) -> Self {
        Self::with_scope(id, name, slug, category, severity, regex, Scope::Referer)
    }

    const fn with_scope(
        id: &'static str,
        name: &'static str,
        slug: &'static str,
        category: Category,
        severity: u8,
        regex: &'static str,
        scope: Scope,
    ) -> Self {
        Self {
            id,
            name,
            category,
            severity,
            detector: Detector::Pattern(Pattern { scope, slug, regex }),
        }
    }

    /// Rule whose logic lives in the family's `check` function.
    pub const fn custom(
        id: &'static str,
        name: &'static str,
        category: Category,
        severity: u8,
    ) -> Self {
        Self {
            id,
            name,
            category,
            severity,
            detector: Detector::Custom,
        }
    }

    /// Build a [`RuleHit`] carrying this rule's metadata.
    pub fn hit(&self, evidence: impl Into<String>) -> RuleHit {
        RuleHit {
            rule_id: self.id,
            rule_name: self.name,
            category: self.category,
            severity: self.severity,
            evidence: evidence.into(),
        }
    }
}

/// Pre-computed views of one log entry, built once per line and shared by all
/// rules. Decoding happens here so individual rules stay cheap.
pub struct InspectionContext<'a> {
    pub entry: &'a LogEntry,
    /// Raw request target, lowercased.
    pub path_lower: String,
    /// Path + query, percent-decoded once, lowercased.
    pub target_decoded: String,
    /// Path + query, percent-decoded twice, lowercased. Catches double
    /// encoding such as `%252e%252e%252f`.
    pub target_double_decoded: String,
    /// SQL comment-stripped variant of [`Self::target_decoded`], built only
    /// when the target contains a block comment. `un/**/ion sel/**/ect`
    /// normalises to `union select`, so keyword rules see the statement the
    /// backend would execute.
    pub target_normalized: Option<String>,
    /// Decoded query string only (after the first `?`), lowercased.
    pub query_decoded: String,
    pub ua_lower: String,
    pub referer_lower: String,
    /// Percent-decoded variants, scanned only when decoding changes the value.
    /// Referer URLs and some agents arrive percent-encoded; matching the raw
    /// header would miss `%3Cscript%3E` and friends.
    pub ua_decoded: String,
    pub referer_decoded: String,
}

impl<'a> InspectionContext<'a> {
    pub fn new(entry: &'a LogEntry) -> Self {
        let path_lower = entry.path.to_ascii_lowercase();
        let target_decoded = lower_ascii(percent_decode(&path_lower));
        let target_double_decoded = lower_ascii(percent_decode(&target_decoded));
        let target_normalized = if target_decoded.contains("/*") {
            Some(normalize_sql_comments(&target_decoded))
        } else {
            None
        };
        let query_decoded = target_decoded
            .split_once('?')
            .map(|(_, query)| query.to_string())
            .unwrap_or_default();
        let ua_lower = entry
            .user_agent
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let referer_lower = entry
            .referer
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let ua_decoded = lower_ascii(percent_decode(&ua_lower));
        let referer_decoded = lower_ascii(percent_decode(&referer_lower));
        Self {
            entry,
            path_lower,
            target_decoded,
            target_double_decoded,
            target_normalized,
            query_decoded,
            ua_lower,
            referer_lower,
            ua_decoded,
            referer_decoded,
        }
    }

    /// Whether the double-decoded target differs from the single-decoded one,
    /// i.e. whether a second matching pass is worth running.
    pub fn has_double_encoding(&self) -> bool {
        self.target_double_decoded != self.target_decoded
    }

    /// Comment-stripped target, when the request carried a block comment.
    pub fn sql_normalized(&self) -> Option<&str> {
        self.target_normalized.as_deref()
    }
}

/// Aggregate matcher: one [`RegexSet`] per [`Scope`], holding every pattern
/// for that scope.
///
/// Patterns must avoid large bounded repetitions (`[^x]{0,200}`): they expand
/// the automaton by orders of magnitude and make a set scan hundreds of
/// microseconds per line. Unbounded classes (`[^x]*`) are equivalent here and
/// keep every scan in the sub-microsecond range.
pub struct Matcher {
    specs: Vec<RuleSpec>,
    sets: Vec<ScopeIndex>,
}

struct ScopeIndex {
    scope: Scope,
    set: RegexSet,
    /// `spec_indices[i]` is the index into `Matcher::specs` for pattern `i`.
    spec_indices: Vec<usize>,
    /// Same order as the set; only used to locate matches for evidence.
    regexes: Vec<Regex>,
}

impl ScopeIndex {
    fn new(scope: Scope, entries: Vec<(usize, &'static str)>) -> Self {
        debug_assert!(!entries.is_empty());
        let patterns: Vec<&str> = entries.iter().map(|(_, pattern)| *pattern).collect();
        let set =
            RegexSet::new(&patterns).expect("static detection patterns must be valid regexes");
        let regexes = patterns
            .iter()
            .map(|pattern| {
                Regex::new(pattern).expect("static detection patterns must be valid regexes")
            })
            .collect();
        let spec_indices = entries.iter().map(|(index, _)| *index).collect();
        Self {
            scope,
            set,
            spec_indices,
            regexes,
        }
    }
}

impl Matcher {
    pub fn new(families: &[&[RuleSpec]]) -> Self {
        let mut specs: Vec<RuleSpec> = Vec::new();
        for family in families {
            specs.extend_from_slice(family);
        }

        let mut buckets: [Vec<(usize, &'static str)>; SCOPE_COUNT] = Default::default();
        for (index, spec) in specs.iter().enumerate() {
            if let Detector::Pattern(pattern) = spec.detector {
                buckets[pattern.scope as usize].push((index, pattern.regex));
            }
        }

        let mut sets: Vec<ScopeIndex> = Vec::new();
        for scope in Scope::ALL {
            let entries = std::mem::take(&mut buckets[scope as usize]);
            if entries.is_empty() {
                continue;
            }
            sets.push(ScopeIndex::new(scope, entries));
        }

        Self { specs, sets }
    }

    #[allow(dead_code)]
    pub fn spec_count(&self) -> usize {
        self.specs.len()
    }

    /// Number of regex-backed patterns across every aggregate set.
    #[cfg(test)]
    pub fn pattern_count(&self) -> usize {
        self.sets.iter().map(|set| set.spec_indices.len()).sum()
    }

    /// Run every pattern registered for `scope` against `haystack`, appending
    /// hits to `out`. `seen` holds rule ids already reported for this entry so
    /// a rule fires at most once per line (the double-decode pass overlaps the
    /// single-decode one).
    pub fn scan(
        &self,
        haystack: &str,
        scope: Scope,
        out: &mut Vec<RuleHit>,
        seen: &mut Vec<&'static str>,
    ) {
        if haystack.is_empty() {
            return;
        }
        for index in &self.sets {
            if index.scope != scope || !index.set.is_match(haystack) {
                continue;
            }
            for pattern_index in index.set.matches(haystack).iter() {
                let spec_index = match index.spec_indices.get(pattern_index) {
                    Some(spec_index) => *spec_index,
                    None => continue,
                };
                let spec = match self.specs.get(spec_index) {
                    Some(spec) => spec,
                    None => continue,
                };
                if seen.contains(&spec.id) {
                    continue;
                }
                seen.push(spec.id);
                let slug = match spec.detector {
                    Detector::Pattern(pattern) => pattern.slug,
                    Detector::Custom => spec.id,
                };
                let evidence = match index.regexes.get(pattern_index) {
                    Some(regex) => match regex.find(haystack) {
                        Some(found) => format!(
                            "pattern {} in '{}'",
                            slug,
                            excerpt_window(haystack, found.start())
                        ),
                        None => format!("pattern {} in '{}'", slug, excerpt(haystack)),
                    },
                    None => format!("pattern {} in '{}'", slug, excerpt(haystack)),
                };
                out.push(spec.hit(evidence));
            }
        }
    }
}

/// Build an excerpt that starts at the beginning of the input.
pub fn excerpt(input: &str) -> String {
    excerpt_window(input, 0)
}

/// Build an excerpt of at most [`MAX_EXCERPT_CHARS`] characters, centred a
/// little before `match_start` so the interesting part stays visible.
///
/// Control characters (decoded `%00`, `%0a`, ...) are replaced with `.` so
/// evidence never corrupts terminal output.
pub fn excerpt_window(input: &str, match_start: usize) -> String {
    let cleaned = sanitize(input);
    let total = cleaned.chars().count();
    if total <= MAX_EXCERPT_CHARS {
        return cleaned;
    }

    let mut safe_start = match_start.min(input.len());
    if !input.is_char_boundary(safe_start) {
        safe_start = 0;
    }
    let match_char = input[..safe_start].chars().count();

    let mut start = match_char.saturating_sub(24);
    let mut budget = MAX_EXCERPT_CHARS;
    if start > 0 {
        budget -= 3;
    }
    if start + budget < total {
        budget -= 3;
    }
    if start + budget > total {
        start = total.saturating_sub(budget);
    }

    let body: String = cleaned.chars().skip(start).take(budget).collect();
    let prefix = if start > 0 { "..." } else { "" };
    let suffix = if start + budget < total { "..." } else { "" };
    format!("{prefix}{body}{suffix}")
}

/// Lowercase in place when a percent-escape decoded to an uppercase ASCII
/// byte. Encoded payloads such as `%53ELECT` would otherwise slip past the
/// lowercase patterns; the check is free for the common all-lowercase case.
fn lower_ascii(mut text: String) -> String {
    if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        text.make_ascii_lowercase();
    }
    text
}

/// Replace control characters so evidence strings stay printable.
fn sanitize(input: &str) -> String {
    if !input.chars().any(|ch| ch.is_control()) {
        return input.to_string();
    }
    input
        .chars()
        .map(|ch| if ch.is_control() { '.' } else { ch })
        .collect()
}

/// Minimal percent-decoder. `+` maps to a space (query semantics). Invalid
/// escapes are passed through untouched. Operates on bytes so binary payloads
/// do not panic; the result is lossy UTF-8.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((high << 4) | low);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Avoid the extra copy `from_utf8_lossy` would force on every line.
    match String::from_utf8(out) {
        Ok(decoded) => decoded,
        Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
    }
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Keywords that end a token in SQL, so an inline comment after them is a
/// separator rather than part of a split word. Used by
/// [`normalize_sql_comments`] to tell `un/**/ion` (rejoin) from
/// `union/**/select` (separate).
const SQL_BREAK_KEYWORDS: &[&str] = &[
    "union",
    "select",
    "insert",
    "update",
    "delete",
    "from",
    "where",
    "order",
    "group",
    "having",
    "and",
    "or",
    "into",
    "waitfor",
];

/// Build the SQL comment-stripped view of a decoded request target.
///
/// Ordinary block comments are removed, which rejoins keywords split as
/// `un/**/ion`; when removal would join a complete keyword with a following
/// word (`union/**/select`) a single space is inserted instead, because the
/// comment acted as whitespace there. MySQL versioned comments (`/*!50000...*/`)
/// keep their executable payload. Whitespace runs collapse to one space so
/// `/*!50000union*/  select` still reads as `union select`.
fn normalize_sql_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut copied = 0usize;
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'/' && bytes[i + 1] == b'*' {
            out.push_str(&input[copied..i]);
            let body_start = i + 2;
            let body_end = input[body_start..]
                .find("*/")
                .map(|offset| body_start + offset);
            let body = match body_end {
                Some(end) => &input[body_start..end],
                None => &input[body_start..],
            };
            match body_end {
                Some(end) => i = end + 2,
                None => i = bytes.len(),
            }
            if let Some(payload) = body.strip_prefix('!') {
                // Versioned comment: the digits encode a minimum version and
                // the rest is live SQL.
                out.push_str(payload.trim_start_matches(|ch: char| ch.is_ascii_digit()));
            } else if joins_a_keyword(&out, input.get(i..)) && !out.ends_with(' ') {
                out.push(' ');
            }
            copied = i;
            continue;
        }
        i += 1;
    }
    out.push_str(&input[copied.min(input.len())..]);
    collapse_whitespace(&out)
}

/// Whether `left` ends with a complete SQL keyword and `right` starts with a
/// word character, i.e. whether a removed comment separated two tokens.
fn joins_a_keyword(left: &str, right: Option<&str>) -> bool {
    let next_is_word = right
        .and_then(|tail| tail.chars().next())
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    if !next_is_word {
        return false;
    }
    let word_start = left
        .char_indices()
        .rev()
        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || *ch == '_'))
        .map_or(0, |(index, ch)| index + ch.len_utf8());
    SQL_BREAK_KEYWORDS.contains(&&left[word_start..])
}

fn collapse_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut pending_space = false;
    for ch in input.chars() {
        if ch.is_ascii_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_handles_escapes_and_plus() {
        assert_eq!(percent_decode("a%2fb"), "a/b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%252e"), "%2e");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn excerpt_is_capped_and_printable() {
        let long = format!("{}{}", "a".repeat(200), "evil");
        let out = excerpt_window(&long, 200);
        assert!(out.chars().count() <= MAX_EXCERPT_CHARS);
        assert!(out.contains("evil"));

        let with_nul = "abc\0def";
        assert_eq!(excerpt(with_nul), "abc.def");
    }

    #[test]
    fn excerpt_keeps_short_input_untouched() {
        assert_eq!(excerpt("/../../etc/passwd"), "/../../etc/passwd");
        assert_eq!(excerpt(""), "");
    }

    #[test]
    fn excerpt_window_is_char_boundary_safe() {
        // Multi-byte input: 200 x 'é' then a marker.
        let input = format!("{}{}", "é".repeat(200), "tail");
        let out = excerpt_window(&input, input.len());
        assert!(out.chars().count() <= MAX_EXCERPT_CHARS);
        assert!(out.ends_with("tail"));
    }

    #[test]
    fn matcher_reports_pattern_count() {
        let matcher = Matcher::new(&[&[
            RuleSpec::target("T-1", "one", "one", Category::Other, 5, r"aaa"),
            RuleSpec::raw("T-2", "two", "two", Category::Other, 5, r"bbb"),
            RuleSpec::custom("T-3", "three", Category::Other, 5),
        ]]);
        assert_eq!(matcher.spec_count(), 3);
        assert_eq!(matcher.pattern_count(), 2);
    }

    #[test]
    fn sql_comments_are_stripped_and_keywords_rejoined() {
        // Comments inside a keyword are removed entirely.
        assert_eq!(
            normalize_sql_comments("?id=1 un/**/ion sel/**/ect"),
            "?id=1 union select"
        );
        // A comment after a complete keyword acts as whitespace.
        assert_eq!(
            normalize_sql_comments("?id=1 union/**/select 1"),
            "?id=1 union select 1"
        );
        // MySQL versioned comments keep their executable payload.
        assert_eq!(
            normalize_sql_comments("?id=1 /*!50000union*/  select 1"),
            "?id=1 union select 1"
        );
        assert_eq!(normalize_sql_comments("?q=a/*unclosed"), "?q=a");
        assert_eq!(normalize_sql_comments("?q=plain"), "?q=plain");
    }

    #[test]
    fn context_only_builds_the_normalized_view_for_comments() {
        let plain = crate::model::entry::LogEntry {
            line_no: 1,
            source_ip: "203.0.113.1".parse().expect("valid address"),
            timestamp: None,
            timestamp_raw: "-".to_string(),
            method: "GET".to_string(),
            path: "/?id=1+union+select+1".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            body_bytes: 0,
            referer: None,
            user_agent: None,
            host: None,
            raw: String::new(),
        };
        assert!(InspectionContext::new(&plain).sql_normalized().is_none());

        let mut commented = plain;
        commented.path = "/?id=1+un/**/ion".to_string();
        let ctx = InspectionContext::new(&commented);
        assert_eq!(ctx.sql_normalized(), Some("/?id=1 union"));
    }
}
