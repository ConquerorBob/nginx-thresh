//! Contextual boosting: correlate distinct rules per source IP.
//!
//! Each IP's timestamped events are sorted once by `(epoch_secs, line_no)` and
//! swept with a sliding window, so the whole pass is `O(n log n)` per IP
//! (sorting) plus `O(n)` for the sweep. Every event enters and leaves the
//! distinct-rule counter exactly once, which keeps 250k-event logs cheap.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::model::threat::ThreatEvent;

use super::ScoringConfig;

/// Contextual boost computed for one event.
pub(super) struct Boost {
    pub multiplier: f64,
    pub reason: Option<String>,
}

struct Timed {
    epoch_secs: i64,
    line_no: u64,
    index: usize,
}

/// Multiplier and optional reason for every event, in input order.
///
/// Only events carrying a timestamp take part: they are grouped per source IP,
/// sorted by `(epoch_secs, line_no)`, and for each distinct timestamp `t` the
/// forward window `[t, t + window_secs]` (inclusive) is scanned for distinct
/// `rule_id` values. Events sharing a timestamp share a window.
pub(super) fn boosts(events: &[ThreatEvent], cfg: &ScoringConfig) -> Vec<Boost> {
    let mut out: Vec<Boost> = Vec::with_capacity(events.len());
    out.resize_with(events.len(), || Boost {
        multiplier: 1.0,
        reason: None,
    });

    let mut by_ip: HashMap<IpAddr, Vec<Timed>> = HashMap::new();
    for (index, event) in events.iter().enumerate() {
        if let Some(timestamp) = event.timestamp {
            by_ip.entry(event.source_ip).or_default().push(Timed {
                epoch_secs: timestamp.timestamp(),
                line_no: event.line_no,
                index,
            });
        }
    }

    let window = cfg.window_secs.min(i64::MAX as u64) as i64;
    let cap = cfg.max_multiplier.max(1.0);
    let mut counts: HashMap<&'static str, u32> = HashMap::new();

    for (ip, mut timed) in by_ip {
        timed.sort_unstable_by_key(|item| (item.epoch_secs, item.line_no, item.index));

        counts.clear();
        let mut end = 0usize;
        let mut group_start = 0usize;

        while group_start < timed.len() {
            let window_start = timed[group_start].epoch_secs;
            let mut group_end = group_start + 1;
            while group_end < timed.len() && timed[group_end].epoch_secs == window_start {
                group_end += 1;
            }

            // Make sure the current group is inside the tracked range: the
            // sweep may have stopped short of it after the previous group.
            if end < group_end {
                for item in &timed[end..group_end] {
                    *counts.entry(events[item.index].rule_id).or_insert(0) += 1;
                }
                end = group_end;
            }

            // Extend the forward window to include every event at or before
            // window_start + window_secs.
            let limit = window_start.saturating_add(window);
            while end < timed.len() && timed[end].epoch_secs <= limit {
                *counts.entry(events[timed[end].index].rule_id).or_insert(0) += 1;
                end += 1;
            }

            let distinct = counts.len();
            if distinct >= 2 {
                let multiplier = (1.0 + 0.15 * (distinct - 1) as f64).min(cap);
                let reason = format!(
                    "{distinct} distinct rules within {}s from {ip}",
                    cfg.window_secs
                );
                for item in &timed[group_start..group_end] {
                    out[item.index] = Boost {
                        multiplier,
                        reason: Some(reason.clone()),
                    };
                }
            }

            // Drop this group before moving on: the next window starts at the
            // first event after it.
            for item in &timed[group_start..group_end] {
                retire(&mut counts, events[item.index].rule_id);
            }
            group_start = group_end;
        }
    }

    out
}

/// Decrement a rule's occurrence count, dropping the key when it hits zero so
/// `counts.len()` always equals the number of distinct rules in the window.
fn retire(counts: &mut HashMap<&'static str, u32>, rule_id: &'static str) {
    let exhausted = match counts.get_mut(rule_id) {
        Some(slot) => {
            *slot = slot.saturating_sub(1);
            *slot == 0
        }
        None => false,
    };
    if exhausted {
        counts.remove(rule_id);
    }
}
