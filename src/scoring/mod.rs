//! Severity scoring, contextual boosting and ranking.
//!
//! The pipeline stays allocation-light so it remains cheap on logs with
//! hundreds of thousands of rule hits:
//!
//! 1. every event receives a base score from its rule severity, adjusted by
//!    the HTTP status (`2xx` hits weigh more: the attack may have succeeded);
//! 2. events are grouped per source IP and correlated inside a forward time
//!    window; several distinct rules from one IP in a short burst raise the
//!    score;
//! 3. all events are sorted by composite score with deterministic tie-breaks.

mod context;

use std::cmp::Ordering;

use crate::model::threat::ThreatEvent;

/// Highest base score a single event can reach before contextual boosting.
const BASE_SCORE_CAP: f64 = 12.5;

/// Tunables for severity scoring and contextual boosting.
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    /// Window used to correlate an IP's distinct rules, in seconds.
    pub window_secs: u64,
    /// Ceiling for the contextual multiplier.
    pub max_multiplier: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            window_secs: 300,
            max_multiplier: 2.5,
        }
    }
}

/// A threat event plus its computed severity and ranking metadata.
#[derive(Debug, Clone)]
pub struct ScoredEvent {
    pub event: ThreatEvent,
    /// Severity after the HTTP-status modifier, before contextual boosting.
    pub base_score: f64,
    /// Contextual multiplier (1.0 when the IP shows no correlated activity).
    pub multiplier: f64,
    /// Final composite score, rounded to two decimals.
    pub final_score: f64,
    /// Human-readable explanations for any boost, e.g. "3 distinct rules
    /// within 300s from 45.13.2.9".
    pub reasons: Vec<String>,
}

/// Score every event, apply contextual boosting, then sort descending by
/// composite threat score.
///
/// Ordering is total and deterministic: `final_score` desc, then rule
/// `severity` desc, then `timestamp` asc (events without a timestamp last),
/// then `line_no` asc, then `source_ip` asc, then `rule_id` asc. Events are
/// never deduplicated: each one is scored on its own.
pub fn score_and_rank(events: Vec<ThreatEvent>, cfg: &ScoringConfig) -> Vec<ScoredEvent> {
    let boosts = context::boosts(&events, cfg);
    let mut scored = Vec::with_capacity(events.len());

    for (event, boost) in events.into_iter().zip(boosts) {
        let base_score = compute_base_score(&event);
        let final_score = round2(base_score * boost.multiplier);
        let reasons: Vec<String> = boost.reason.into_iter().collect();
        scored.push(ScoredEvent {
            event,
            base_score,
            multiplier: boost.multiplier,
            final_score,
            reasons,
        });
    }

    scored.sort_by(rank_order);
    scored
}

/// HTTP status modifier: attacks that appear to have succeeded weigh more,
/// server errors weigh slightly less (the request likely never reached the
/// application).
fn status_modifier(status: u16) -> f64 {
    match status {
        200..=299 => 1.25,
        300..=399 => 1.10,
        400..=499 => 1.00,
        500..=599 => 0.90,
        _ => 1.00,
    }
}

/// Base score: rule severity adjusted by the status modifier, capped so a
/// single event cannot dominate the ranking on its own.
fn compute_base_score(event: &ThreatEvent) -> f64 {
    (f64::from(event.severity) * status_modifier(event.status)).min(BASE_SCORE_CAP)
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// Total order used to rank scored events: best threat first.
fn rank_order(a: &ScoredEvent, b: &ScoredEvent) -> Ordering {
    b.final_score
        .total_cmp(&a.final_score)
        .then_with(|| b.event.severity.cmp(&a.event.severity))
        .then_with(|| match (a.event.timestamp, b.event.timestamp) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| a.event.line_no.cmp(&b.event.line_no))
        .then_with(|| a.event.source_ip.cmp(&b.event.source_ip))
        .then_with(|| a.event.rule_id.cmp(b.event.rule_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::threat::Category;
    use chrono::{DateTime, Duration, FixedOffset, TimeZone};

    fn base_time() -> DateTime<FixedOffset> {
        FixedOffset::east_opt(0)
            .expect("utc offset is valid")
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("timestamp is unambiguous")
    }

    fn at(offset_secs: i64) -> DateTime<FixedOffset> {
        base_time() + Duration::seconds(offset_secs)
    }

    #[allow(clippy::too_many_arguments)]
    fn event(
        line_no: u64,
        offset_secs: Option<i64>,
        source_ip: &str,
        rule_id: &'static str,
        severity: u8,
        status: u16,
    ) -> ThreatEvent {
        ThreatEvent {
            line_no,
            timestamp: offset_secs.map(at),
            timestamp_raw: offset_secs
                .map(|secs| format!("2026-01-01T00:00:00+00:00+{secs}"))
                .unwrap_or_default(),
            source_ip: source_ip.parse().expect("test ip is valid"),
            category: Category::Other,
            rule_id,
            rule_name: rule_id,
            severity,
            evidence: String::new(),
            method: "GET".to_string(),
            path: "/".to_string(),
            status,
            user_agent: None,
            raw: String::new(),
        }
    }

    fn cfg(window_secs: u64, max_multiplier: f64) -> ScoringConfig {
        ScoringConfig {
            window_secs,
            max_multiplier,
        }
    }

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 1e-9,
            "expected {expected}, got {actual}"
        );
    }

    fn by_line(scored: &[ScoredEvent], line_no: u64) -> &ScoredEvent {
        scored
            .iter()
            .find(|scored| scored.event.line_no == line_no)
            .expect("scored event is present")
    }

    #[test]
    fn status_modifiers_weight_successful_attacks_higher() {
        let events = vec![
            event(1, Some(0), "10.0.0.1", "r1", 8, 200),
            event(2, Some(10), "10.0.0.2", "r1", 8, 301),
            event(3, Some(20), "10.0.0.3", "r1", 8, 404),
            event(4, Some(30), "10.0.0.4", "r1", 8, 503),
            event(5, Some(40), "10.0.0.5", "r1", 8, 0),
            event(6, Some(50), "10.0.0.6", "r1", 8, 700),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        assert_close(by_line(&scored, 1).base_score, 10.0); // 8 * 1.25
        assert_close(by_line(&scored, 2).base_score, 8.8); // 8 * 1.10
        assert_close(by_line(&scored, 3).base_score, 8.0); // 8 * 1.00
        assert_close(by_line(&scored, 4).base_score, 7.2); // 8 * 0.90
        assert_close(by_line(&scored, 5).base_score, 8.0); // unknown status
        assert_close(by_line(&scored, 6).base_score, 8.0); // unknown status

        for line_no in 1..=6 {
            assert_close(by_line(&scored, line_no).multiplier, 1.0);
            assert!(by_line(&scored, line_no).reasons.is_empty());
        }
    }

    #[test]
    fn base_score_is_capped_at_twelve_point_five() {
        let events = vec![
            event(1, Some(0), "10.0.0.1", "r1", 10, 200),
            event(2, Some(10), "10.0.0.2", "r1", 12, 200),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        assert_close(by_line(&scored, 1).base_score, 12.5); // 10 * 1.25 exactly
        assert_close(by_line(&scored, 2).base_score, 12.5); // 12 * 1.25 clamps
        assert_close(by_line(&scored, 2).final_score, 12.5);
    }

    #[test]
    fn three_distinct_rules_within_window_multiply_by_one_point_three() {
        let events = vec![
            event(1, Some(100), "45.13.2.9", "r1", 5, 404),
            event(2, Some(100), "45.13.2.9", "r2", 5, 404),
            event(3, Some(100), "45.13.2.9", "r3", 5, 404),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        for line_no in 1..=3 {
            assert_close(by_line(&scored, line_no).multiplier, 1.3);
            assert_close(by_line(&scored, line_no).final_score, 6.5); // 5 * 1.3
        }
        assert_eq!(
            by_line(&scored, 1).reasons,
            vec!["3 distinct rules within 300s from 45.13.2.9".to_string()]
        );
    }

    #[test]
    fn forward_windows_shrink_for_later_events_in_a_burst() {
        let events = vec![
            event(1, Some(0), "45.13.2.9", "r1", 5, 404),
            event(2, Some(120), "45.13.2.9", "r2", 5, 404),
            event(3, Some(299), "45.13.2.9", "r3", 5, 404),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        // The window is [t_i, t_i + 300], so only earlier events see the
        // whole burst.
        assert_close(by_line(&scored, 1).multiplier, 1.3);
        assert_close(by_line(&scored, 2).multiplier, 1.15);
        assert_close(by_line(&scored, 3).multiplier, 1.0);
    }

    #[test]
    fn five_distinct_rules_multiply_by_one_point_six() {
        let rule_ids = ["r1", "r2", "r3", "r4", "r5"];
        let events = rule_ids
            .iter()
            .enumerate()
            .map(|(index, rule)| event(index as u64 + 1, Some(100), "10.0.0.1", rule, 6, 404))
            .collect::<Vec<_>>();

        let scored = score_and_rank(events, &cfg(300, 2.5));

        for scored_event in &scored {
            assert_close(scored_event.multiplier, 1.6); // 1 + 0.15 * 4
            assert_close(scored_event.final_score, 9.6); // 6 * 1.6
        }
    }

    #[test]
    fn multiplier_is_capped_by_max_multiplier() {
        let rule_ids = [
            "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
        ];
        let events = rule_ids
            .iter()
            .enumerate()
            .map(|(index, rule)| event(index as u64 + 1, Some(100), "10.0.0.1", rule, 7, 404))
            .collect::<Vec<_>>();

        // 12 distinct rules would give 1 + 0.15 * 11 = 2.65.
        let scored = score_and_rank(events, &cfg(300, 2.5));

        for scored_event in &scored {
            assert_close(scored_event.multiplier, 2.5);
        }
    }

    #[test]
    fn max_multiplier_below_one_is_clamped_to_neutral() {
        let events = vec![
            event(1, Some(0), "10.0.0.1", "r1", 5, 404),
            event(2, Some(0), "10.0.0.1", "r2", 5, 404),
        ];

        let scored = score_and_rank(events, &cfg(300, 0.5));

        for scored_event in &scored {
            assert_close(scored_event.multiplier, 1.0);
            // Correlation is still reported even though the cap cancels the
            // numeric boost.
            assert_eq!(scored_event.reasons.len(), 1);
        }
    }

    #[test]
    fn repeated_same_rule_does_not_boost() {
        let events = vec![
            event(1, Some(0), "10.0.0.1", "r1", 5, 404),
            event(2, Some(10), "10.0.0.1", "r1", 5, 404),
            event(3, Some(20), "10.0.0.1", "r1", 5, 404),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        assert_eq!(scored.len(), 3, "events are never deduplicated");
        for scored_event in &scored {
            assert_close(scored_event.multiplier, 1.0);
            assert!(scored_event.reasons.is_empty());
        }
    }

    #[test]
    fn different_ips_are_scored_independently() {
        let events = vec![
            event(1, Some(0), "10.0.0.1", "r1", 5, 404),
            event(2, Some(10), "10.0.0.1", "r2", 5, 404),
            event(3, Some(20), "10.0.0.1", "r3", 5, 404),
            event(4, Some(0), "10.0.0.2", "r1", 5, 404),
            event(5, Some(10), "10.0.0.2", "r2", 5, 404),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        // Each IP's leading event only sees its own burst.
        assert_close(by_line(&scored, 1).multiplier, 1.3);
        assert_close(by_line(&scored, 4).multiplier, 1.15);
        assert_close(by_line(&scored, 3).multiplier, 1.0);
        assert_close(by_line(&scored, 5).multiplier, 1.0);
    }

    #[test]
    fn timestampless_events_are_never_boosted_and_do_not_join_windows() {
        let events = vec![
            event(1, None, "10.0.0.1", "r1", 5, 404),
            event(2, Some(0), "10.0.0.1", "r2", 5, 404),
            event(3, Some(30), "10.0.0.1", "r3", 5, 404),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        let timestampless = by_line(&scored, 1);
        assert_close(timestampless.multiplier, 1.0);
        assert!(timestampless.reasons.is_empty());

        // The timestampless event must not be counted for the timestamped one.
        assert_close(by_line(&scored, 2).multiplier, 1.15);
        assert_eq!(
            by_line(&scored, 2).reasons,
            vec!["2 distinct rules within 300s from 10.0.0.1".to_string()]
        );
        assert_close(by_line(&scored, 3).multiplier, 1.0);
    }

    #[test]
    fn window_boundary_is_inclusive() {
        let inside = vec![
            event(1, Some(0), "10.0.0.1", "r1", 5, 404),
            event(2, Some(300), "10.0.0.1", "r2", 5, 404),
        ];
        let outside = vec![
            event(1, Some(0), "10.0.0.1", "r1", 5, 404),
            event(2, Some(301), "10.0.0.1", "r2", 5, 404),
        ];

        let inside = score_and_rank(inside, &cfg(300, 2.5));
        let outside = score_and_rank(outside, &cfg(300, 2.5));

        assert_close(by_line(&inside, 1).multiplier, 1.15);
        assert_close(by_line(&outside, 1).multiplier, 1.0);
    }

    #[test]
    fn window_uses_only_forward_looking_matches() {
        let events = vec![
            event(1, Some(0), "10.0.0.1", "r1", 5, 404),
            event(2, Some(290), "10.0.0.1", "r2", 5, 404),
            event(3, Some(600), "10.0.0.1", "r3", 5, 404),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        assert_close(by_line(&scored, 1).multiplier, 1.15); // sees line 2
        assert_close(by_line(&scored, 2).multiplier, 1.0); // 600 is out of range
        assert_close(by_line(&scored, 3).multiplier, 1.0);
    }

    #[test]
    fn equal_timestamps_share_one_window() {
        let events = vec![
            event(1, Some(100), "10.0.0.1", "r1", 5, 404),
            event(2, Some(100), "10.0.0.1", "r2", 5, 404),
            event(3, Some(100), "10.0.0.1", "r3", 5, 404),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        for scored_event in &scored {
            assert_close(scored_event.multiplier, 1.3);
        }
    }

    #[test]
    fn sort_orders_by_score_then_severity_then_timestamp_then_line() {
        let events = vec![
            event(1, Some(300), "10.0.0.1", "r1", 8, 200), // 10.0, sev 8
            event(2, Some(300), "10.0.0.2", "r1", 10, 404), // 10.0, sev 10
            event(3, Some(100), "10.0.0.3", "r1", 10, 404), // 10.0, sev 10, earlier
            event(1, Some(100), "10.0.0.4", "r1", 10, 404), // 10.0, sev 10, line 1
            event(4, Some(0), "10.0.0.5", "r1", 5, 404),   // 5.0
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        let lines = scored
            .iter()
            .map(|scored| (scored.event.line_no, scored.event.source_ip.to_string()))
            .collect::<Vec<_>>();

        assert_eq!(
            lines,
            vec![
                (1, "10.0.0.4".to_string()),
                (3, "10.0.0.3".to_string()),
                (2, "10.0.0.2".to_string()),
                (1, "10.0.0.1".to_string()),
                (4, "10.0.0.5".to_string()),
            ]
        );
        for pair in scored.windows(2) {
            assert!(pair[0].final_score >= pair[1].final_score);
        }
    }

    #[test]
    fn timestampless_events_sort_last_among_equal_scores() {
        let events = vec![
            event(1, None, "10.0.0.1", "r1", 10, 404),
            event(2, Some(1_000), "10.0.0.2", "r1", 10, 404),
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        assert_eq!(scored[0].event.line_no, 2);
        assert_eq!(scored[1].event.line_no, 1);
        assert!(scored[1].event.timestamp.is_none());
    }

    #[test]
    fn ties_break_by_source_ip_then_rule_id() {
        // Distinct IPs, identical timestamps and line numbers: no boost, so
        // the tie falls through to source_ip.
        let ip_tie = vec![
            event(1, Some(0), "10.0.0.9", "m", 10, 404),
            event(1, Some(0), "10.0.0.2", "z", 10, 404),
        ];
        let ip_tie = score_and_rank(ip_tie, &cfg(300, 2.5));
        assert_eq!(
            ip_tie
                .iter()
                .map(|scored| scored.event.source_ip.to_string())
                .collect::<Vec<_>>(),
            vec!["10.0.0.2".to_string(), "10.0.0.9".to_string()]
        );

        // Same IP and timestamp with different rules boosts both events
        // equally, so the tie falls through to rule_id.
        let rule_tie = vec![
            event(1, Some(0), "10.0.0.9", "m", 10, 404),
            event(1, Some(0), "10.0.0.9", "a", 10, 404),
            event(1, Some(0), "10.0.0.2", "z", 10, 404),
        ];
        let rule_tie = score_and_rank(rule_tie, &cfg(300, 2.5));
        assert_eq!(
            rule_tie
                .iter()
                .map(|scored| (scored.event.source_ip.to_string(), scored.event.rule_id))
                .collect::<Vec<_>>(),
            vec![
                ("10.0.0.9".to_string(), "a"),
                ("10.0.0.9".to_string(), "m"),
                ("10.0.0.2".to_string(), "z"),
            ]
        );
    }

    #[test]
    fn ranking_is_deterministic_across_runs() {
        let events = vec![
            event(1, Some(0), "10.0.0.1", "r1", 7, 200),
            event(2, Some(5), "10.0.0.1", "r2", 7, 404),
            event(3, Some(5), "10.0.0.2", "r3", 7, 404),
            event(4, None, "10.0.0.2", "r4", 9, 500),
            event(5, Some(5), "10.0.0.3", "r5", 7, 302),
        ];

        let first = score_and_rank(events.clone(), &cfg(300, 2.5));
        let second = score_and_rank(events, &cfg(300, 2.5));

        let signature = |scored: &[ScoredEvent]| {
            scored
                .iter()
                .map(|scored| {
                    (
                        scored.event.line_no,
                        scored.event.source_ip,
                        scored.event.rule_id,
                        scored.final_score,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(signature(&first), signature(&second));
    }

    #[test]
    fn empty_input_yields_empty_ranking() {
        assert!(score_and_rank(Vec::new(), &ScoringConfig::default()).is_empty());
    }

    #[test]
    fn final_score_is_rounded_to_two_decimals() {
        let events = vec![
            event(1, Some(0), "10.0.0.1", "r1", 6, 302), // 6.6
            event(2, Some(10), "10.0.0.1", "r2", 6, 302), // 1.15 => 7.59
        ];

        let scored = score_and_rank(events, &cfg(300, 2.5));

        assert_close(by_line(&scored, 1).base_score, 6.6);
        assert_eq!(by_line(&scored, 1).final_score, 7.59);
        assert_eq!(by_line(&scored, 1).final_score * 100.0, 759.0);
    }

    #[test]
    fn huge_window_does_not_overflow() {
        let events = vec![
            event(1, Some(0), "10.0.0.1", "r1", 5, 404),
            event(2, Some(10), "10.0.0.1", "r2", 5, 404),
        ];

        let scored = score_and_rank(events, &cfg(u64::MAX, 2.5));

        // The trailing event only sees itself, but the leading one sees both
        // within the saturated window.
        assert_close(by_line(&scored, 1).multiplier, 1.15);
        assert_close(by_line(&scored, 2).multiplier, 1.0);
    }
}
