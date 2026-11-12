//! Rule-based threat detection.
//!
//! [`RuleEngine`] compiles every rule's regex once and then inspects log
//! entries concurrently from parser worker threads. Per line the work is a
//! handful of aggregate [`rule::Matcher`] scans (one per request view) plus a
//! few cheap hand-written checks, so the engine holds no mutable state and is
//! `Send + Sync`.

pub mod bruteforce;
pub mod cmdi;
pub mod lfi;
pub mod log4shell;
pub mod misc;
pub mod recon;
pub mod rule;
pub mod sensitive;
pub mod sqli;
pub mod ssrf;
#[cfg(test)]
pub(crate) mod test_util;
pub mod traversal;
pub mod webshell;
pub mod xss;

use crate::model::entry::{AuthFailure, LogEntry};
use crate::model::threat::{RuleHit, ThreatEvent};

use self::rule::{InspectionContext, Matcher, RuleSpec, Scope};

/// Hand-written check that cannot be expressed as a single regex.
type CheckFn = fn(&InspectionContext<'_>) -> Vec<RuleHit>;

/// Rule metadata for every family, in reporting order.
const FAMILIES: &[&[RuleSpec]] = &[
    cmdi::SPECS,
    log4shell::SPECS,
    webshell::SPECS,
    lfi::SPECS,
    sqli::SPECS,
    traversal::SPECS,
    ssrf::SPECS,
    xss::SPECS,
    sensitive::SPECS,
    recon::SPECS,
    misc::SPECS,
];

/// Manual family checks, run after the regex pass.
const CHECKS: &[CheckFn] = &[sensitive::check, recon::check, misc::check];

/// Aggregated rule engine. Construction compiles every rule's patterns once;
/// `inspect` is then called concurrently from parser worker threads.
pub struct RuleEngine {
    matcher: Matcher,
}

impl RuleEngine {
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        {
            let specs: Vec<RuleSpec> = FAMILIES
                .iter()
                .flat_map(|family| family.iter().copied())
                .collect();
            debug_assert!(ids_are_unique(&specs), "duplicate detection rule id");
        }
        Self {
            matcher: Matcher::new(FAMILIES),
        }
    }

    /// Inspect one parsed log line.
    ///
    /// Cheap by construction: no regex is compiled here, the only per-line
    /// allocations are the pre-computed [`InspectionContext`] strings, and hit
    /// storage allocates only when a rule fires.
    pub fn inspect(&self, entry: &LogEntry) -> Vec<RuleHit> {
        let ctx = InspectionContext::new(entry);
        let mut hits = Vec::new();
        let mut seen: Vec<&'static str> = Vec::new();

        self.matcher
            .scan(&ctx.path_lower, Scope::RawPath, &mut hits, &mut seen);
        self.matcher
            .scan(&ctx.target_decoded, Scope::Target, &mut hits, &mut seen);
        if ctx.has_double_encoding() {
            self.matcher
                .scan(&ctx.target_double_decoded, Scope::Target, &mut hits, &mut seen);
        }
        if let Some(normalized) = ctx.sql_normalized() {
            self.matcher
                .scan(normalized, Scope::Target, &mut hits, &mut seen);
        }
        self.matcher
            .scan(&ctx.ua_lower, Scope::UserAgent, &mut hits, &mut seen);
        if ctx.ua_decoded != ctx.ua_lower {
            self.matcher
                .scan(&ctx.ua_decoded, Scope::UserAgent, &mut hits, &mut seen);
        }
        self.matcher
            .scan(&ctx.referer_lower, Scope::Referer, &mut hits, &mut seen);
        if ctx.referer_decoded != ctx.referer_lower {
            self.matcher
                .scan(&ctx.referer_decoded, Scope::Referer, &mut hits, &mut seen);
        }

        for check in CHECKS {
            hits.extend(check(&ctx));
        }
        hits
    }

    /// Stateful post-pass over the retained 401/403/404 responses. Returns one
    /// brute-force event and/or one enumeration event per offending source IP,
    /// sorted by IP.
    pub fn detect_bruteforce(
        &self,
        failures: &[AuthFailure],
        window_secs: u64,
        threshold: u32,
    ) -> Vec<ThreatEvent> {
        if failures.is_empty() {
            return Vec::new();
        }
        bruteforce::detect(failures, window_secs, threshold)
    }

    /// Number of distinct detection rules known to the engine. Reporting
    /// surfaces read this; it is part of the frozen engine API.
    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.matcher.spec_count()
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Compile-time check that the engine can be shared across parser threads.
#[allow(dead_code)]
fn _rule_engine_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RuleEngine>();
    assert_send_sync::<RuleSpec>();
}

#[cfg(any(test, debug_assertions))]
fn ids_are_unique(specs: &[RuleSpec]) -> bool {
    let mut ids: Vec<&'static str> = specs.iter().map(|spec| spec.id).collect();
    ids.sort_unstable();
    ids.windows(2).all(|pair| pair[0] != pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::threat::Category;

    fn all_specs() -> Vec<RuleSpec> {
        FAMILIES
            .iter()
            .flat_map(|family| family.iter().copied())
            .collect()
    }

    #[test]
    fn engine_exposes_at_least_fifty_rules() {
        let engine = RuleEngine::new();
        assert!(
            engine.rule_count() >= 50,
            "expected >= 50 rules, got {}",
            engine.rule_count()
        );
        assert_eq!(engine.rule_count(), all_specs().len());
    }

    #[test]
    fn rule_metadata_is_consistent() {
        let specs = all_specs();
        assert!(ids_are_unique(&specs), "rule ids must be unique");

        for spec in &specs {
            assert!(
                (1..=10).contains(&spec.severity),
                "rule {} has severity {}",
                spec.id,
                spec.severity
            );
            assert!(!spec.name.is_empty(), "rule {} has no name", spec.id);
            assert!(
                spec.id.contains('-') && spec.id.len() >= 5,
                "rule id {} is not prefixed",
                spec.id
            );
        }

        for (family, prefix) in [
            (cmdi::SPECS, "CMDI-"),
            (log4shell::SPECS, "LOG4SHELL-"),
            (webshell::SPECS, "WEBSHELL-"),
            (lfi::SPECS, "LFI-"),
            (sqli::SPECS, "SQLI-"),
            (traversal::SPECS, "TRAV-"),
            (ssrf::SPECS, "SSRF-"),
            (xss::SPECS, "XSS-"),
            (sensitive::SPECS, "SENS-"),
            (recon::SPECS, "RECON-"),
        ] {
            assert!(!family.is_empty(), "{prefix} family is empty");
            for spec in family {
                assert!(
                    spec.id.starts_with(prefix),
                    "rule {} does not start with {prefix}",
                    spec.id
                );
            }
        }
    }

    #[test]
    fn every_attack_category_has_rules() {
        let specs = all_specs();
        for category in [
            Category::CommandInjection,
            Category::Log4Shell,
            Category::Webshell,
            Category::LocalFileInclusion,
            Category::SqlInjection,
            Category::PathTraversal,
            Category::Ssrf,
            Category::CrossSiteScripting,
            Category::SensitiveFileAccess,
            Category::Reconnaissance,
            Category::MalformedRequest,
        ] {
            assert!(
                specs.iter().any(|spec| spec.category == category),
                "no rule for {:?}",
                category
            );
        }
    }

    #[test]
    fn clean_request_produces_no_hits() {
        let entry = test_util::entry("/api/v1/articles?page=2");
        assert!(RuleEngine::new().inspect(&entry).is_empty());
    }

    #[test]
    fn one_line_can_produce_several_hits() {
        let entry = test_util::entry("/download?file=../../etc/passwd");
        let hits = RuleEngine::new().inspect(&entry);
        assert!(hits.len() >= 2, "expected combined hits, got {hits:?}");
        assert!(hits.iter().any(|hit| hit.rule_id == "TRAV-001"));
        assert!(hits.iter().any(|hit| hit.rule_id == "LFI-002"));
    }

    #[test]
    fn evidence_is_short_and_names_a_pattern() {
        let entry = test_util::entry(&format!("/{}%00", "a".repeat(400)));
        for hit in RuleEngine::new().inspect(&entry) {
            assert!(!hit.evidence.is_empty());
            assert!(hit.evidence.contains(" in '"), "bad evidence: {}", hit.evidence);
            let excerpt = hit
                .evidence
                .rsplit_once(" in '")
                .map(|(_, tail)| tail)
                .unwrap_or("");
            assert!(
                excerpt.chars().count() <= rule::MAX_EXCERPT_CHARS + 1,
                "excerpt too long: {excerpt}"
            );
        }
    }

    #[test]
    fn engine_survives_hostile_input() {
        let engine = RuleEngine::new();
        let repeated_dots = "../".repeat(200);
        let long_name = "a".repeat(9000);
        for path in [
            "",
            "/",
            "%",
            "%zz",
            "%00%0d%0a",
            "/\u{fffd}\u{1f600}",
            repeated_dots.as_str(),
            long_name.as_str(),
        ] {
            let entry = test_util::entry(path);
            let hits = engine.inspect(&entry);
            assert!(hits.iter().all(|hit| (1..=10).contains(&hit.severity)));
        }
    }

    #[test]
    fn realistic_benign_traffic_is_clean() {
        let paths = [
            "/",
            "/index.html",
            "/about-us",
            "/contact",
            "/blog/2024/05/understanding-path-traversal",
            "/wp-content/uploads/2024/05/hero.jpg",
            "/wp-json/wp/v2/posts?per_page=10",
            "/api/v1/articles?page=2&sort=asc",
            "/api/v1/users/42",
            "/products?category=books&page=2&sort=price",
            "/search?q=select+a+size+from+the+list",
            "/search?q=union+station+coffee",
            "/assets/js/app.min.js?v=3.6.0",
            "/favicon.ico",
            "/robots.txt",
            "/sitemap.xml",
            "/download?file=manual.pdf",
            "/user/profile?tab=security",
            "/checkout/cart",
            "/img/logo.svg",
        ];
        let agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Version/17.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "curl/8.4.0",
            "python-requests/2.31.0",
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
        ];
        let engine = RuleEngine::new();
        for path in paths {
            for agent in agents {
                let entry = test_util::entry_ua(path, agent);
                let hits = engine.inspect(&entry);
                assert!(
                    hits.is_empty(),
                    "false positive on {path:?} with UA {agent:?}: {:?}",
                    hits.iter()
                        .map(|hit| (hit.rule_id, hit.evidence.as_str()))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn rule_engine_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RuleEngine>();
    }

    #[test]
    #[ignore = "throughput smoke test; run with --release --ignored --nocapture"]
    fn bench_inspect_throughput() {
        let engine = RuleEngine::new();
        for (label, width) in [("short lines", 0usize), ("long lines", 1_200)] {
            let entries: Vec<_> = (0..10_000)
                .map(|i| {
                    let path = if width == 0 {
                        format!("/api/v1/articles/{i}?page=2&sort=asc")
                    } else {
                        format!("/api/v1/articles/{i}/{}?page=2", "x".repeat(width))
                    };
                    test_util::entry(&path)
                })
                .collect();
            let started = std::time::Instant::now();
            let mut hits = 0usize;
            for entry in &entries {
                hits += engine.inspect(entry).len();
            }
            let elapsed = started.elapsed();
            println!(
                "inspect {label}: {:.0} lines/s ({elapsed:?}, {hits} hits)",
                entries.len() as f64 / elapsed.as_secs_f64()
            );
        }
    }
}
