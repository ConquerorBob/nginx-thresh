//! Startup splash for the `thresh` binary.
//!
//! The wordmark is drawn as a six-row block letter form so it stays legible
//! on any UTF-8 terminal. Colours come from `colored`, which automatically
//! disables itself when stdout is not a TTY (or when `--no-color` was passed
//! by `main`), so the banner remains clean in pipes and log files.

use std::io::{self, Write};

use colored::Colorize;

/// Six-row block-letter wordmark for `THRESH`.
///
/// Rows are stored with trailing padding removed; internal spacing is part of
/// the glyphs and must be preserved.
const WORDMARK: [&str; 6] = [
    "████████╗██╗  ██╗██████╗ ███████╗███████╗██╗  ██╗",
    "╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔════╝██║  ██║",
    "   ██║   ███████║██████╔╝█████╗  ███████╗███████║",
    "   ██║   ██╔══██║██╔══██╗██╔══╝  ╚════██║██╔══██║",
    "   ██║   ██║  ██║██║  ██║███████╗███████║██║  ██║",
    "   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝",
];

/// Left margin for the wordmark rows; matches the first row's shield prefix.
const INDENT: &str = "     ";

/// Separator drawn at the width of the wordmark's widest row.
const RULE_WIDTH: usize = 49;

const TAGLINE: &str = "NGINX ACCESS-LOG THREAT DETECTION";

/// Print the startup splash followed by a blank line.
pub fn print_banner() {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    // A closed pipe (`thresh | head`) is not an error worth panicking over.
    let _ = write_banner(&mut out);
}

/// Render the splash into any writer; separated from stdout for testability.
fn write_banner<W: Write>(out: &mut W) -> io::Result<()> {
    for (index, row) in WORDMARK.iter().enumerate() {
        if index == 0 {
            writeln!(out, "  {}  {}", "◆".red().bold(), row.cyan().bold())?;
        } else {
            writeln!(out, "{INDENT}{}", row.cyan().bold())?;
        }
    }

    writeln!(out)?;
    writeln!(out, "{INDENT}{}", "─".repeat(RULE_WIDTH).cyan().dimmed())?;
    writeln!(out, "{INDENT}{}", TAGLINE.bold())?;
    writeln!(out, "{INDENT}{}", version_line().dimmed())?;
    writeln!(out)?;
    Ok(())
}

/// Version and build flavour, e.g. `v0.1.0  ·  streaming parser  ·  rule engine`.
fn version_line() -> String {
    format!(
        "v{}  ·  streaming parser  ·  rule engine",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display_width(row: &str) -> usize {
        row.chars().count()
    }

    #[test]
    fn wordmark_has_six_rows() {
        assert_eq!(WORDMARK.len(), 6);
    }

    #[test]
    fn wordmark_fits_terminal_width() {
        let prefix = INDENT.chars().count();
        for row in WORDMARK {
            assert!(
                prefix + display_width(row) <= 100,
                "wordmark row exceeds 100 columns: {row:?}"
            );
        }
    }

    #[test]
    fn source_rows_have_no_trailing_whitespace() {
        for row in WORDMARK {
            assert_eq!(row, row.trim_end(), "trailing whitespace in {row:?}");
        }
    }

    #[test]
    fn tagline_and_version_fit_width() {
        let prefix = INDENT.chars().count();
        assert!(prefix + TAGLINE.chars().count() <= 100);
        assert!(prefix + version_line().chars().count() <= 100);
    }

    #[test]
    fn version_line_mentions_package_version() {
        assert!(version_line().contains(env!("CARGO_PKG_VERSION")));
        assert!(version_line().contains("streaming parser"));
    }

    #[test]
    fn renders_banner_with_blank_line_and_no_trailing_space() {
        let mut buffer = Vec::new();
        write_banner(&mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();

        assert!(text.contains(TAGLINE));
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        assert!(text.ends_with("\n\n"), "banner must end with a blank line");
        for line in text.lines() {
            assert_eq!(line, line.trim_end(), "trailing whitespace in {line:?}");
        }
    }
}
