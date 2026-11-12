//! Real-time terminal progress display for the parallel log scanner.
//!
//! [`TerminalProgress`] wraps an `indicatif` bar so parser workers can report
//! bytes without knowing anything about the terminal. `indicatif` hides the
//! bar automatically when stderr is not a TTY, which keeps redirected runs and
//! test harnesses clean.

use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

use crate::parser::reader::ProgressSink;

/// Style shared by every bar: spinner, message, 42-column gauge, byte counts,
/// throughput and ETA.
const TEMPLATE: &str =
    "{spinner:.cyan} {msg:.bold} [{bar:42.cyan/blue}] {bytes}/{total_bytes} {percent}% {bytes_per_sec} ETA {eta}";

/// Fractional block glyphs, from full to nearly empty. The final entry is the
/// empty cell.
const PROGRESS_CHARS: &str = "█▉▊▋▌▍▎▏  ";

/// Braille spinner, one frame per steady tick.
const TICK_CHARS: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";

/// Real-time terminal progress bar driven by the parser workers.
pub struct TerminalProgress {
    bar: ProgressBar,
}

impl TerminalProgress {
    pub fn new(total_bytes: u64) -> Self {
        let bar = ProgressBar::new(total_bytes);
        let style = ProgressStyle::with_template(TEMPLATE)
            .expect("progress template is a compile-time constant and always valid")
            .progress_chars(PROGRESS_CHARS)
            .tick_chars(TICK_CHARS);
        bar.set_style(style);
        bar.set_message("Parsing");
        bar.enable_steady_tick(Duration::from_millis(120));
        Self { bar }
    }
}

impl ProgressSink for TerminalProgress {
    fn set_total(&self, total_bytes: u64) {
        self.bar.set_length(total_bytes);
    }

    fn add_bytes(&self, delta: u64) {
        self.bar.inc(delta);
    }

    fn finished(&self) {
        self.bar.finish_and_clear();
    }
}

impl Drop for TerminalProgress {
    fn drop(&mut self) {
        // `main` can bail out with `?` mid-scan; clearing here keeps the
        // fatal error from being printed on top of a half-drawn bar.
        self.bar.finish_and_clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_wrapper_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TerminalProgress>();
    }

    #[test]
    fn delegates_updates_to_the_bar() {
        let progress = TerminalProgress::new(1_000);
        assert_eq!(progress.bar.length(), Some(1_000));
        assert_eq!(progress.bar.position(), 0);

        progress.add_bytes(400);
        progress.add_bytes(100);
        assert_eq!(progress.bar.position(), 500);

        progress.set_total(2_000);
        assert_eq!(progress.bar.length(), Some(2_000));

        progress.finished();
        assert!(progress.bar.is_finished());
    }
}
