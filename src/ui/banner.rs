//! Startup splash for the `thresh` binary.
//!
//! The wordmark is drawn as a six-row block letter form. Colour and glyphs
//! come from [`super::theme`], which also decides whether the console can be
//! trusted with box-drawing characters: when it cannot, the ASCII wordmark is
//! printed instead so the splash still lines up on a legacy codepage.
//!
//! Colours are disabled by `colored` when stdout is not a TTY (or when
//! `--no-color` was passed by `main`), so the banner remains clean in pipes
//! and log files.

use std::io::{self, Write};

use colored::Colorize;

use super::theme::{self, G};

/// Six-row block-letter wordmark for `THRESH`, in box-drawing glyphs.
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

/// Six-row ASCII fallback for `THRESH`, slanted stencil built from `/`, `\`,
/// `_` and `|`.
///
/// Every row is 7-bit ASCII so a legacy codepage cannot turn a glyph into
/// mojibake and shift the columns after it. Used whenever
/// [`theme::Theme::is_unicode`] is false.
const ASCII_WORDMARK: [&str; 6] = [
    " _______   _    _   ____    ______    _____   _    _",
    "|__   __| | |  | | |  _ \\  |  ____|  / ____| | |  | |",
    "   | |    | |__| | | |_) | | |__    | (___   | |__| |",
    "   | |    |  __  | |  _ <  |  __|    \\___ \\  |  __  |",
    "   | |    | |  | | | |_) | | |____   ____) | | |  | |",
    "   |_|    |_|  |_| |____/  |______| |_____/  |_|  |_|",
];

/// Left margin for the wordmark rows; matches the first row's shield prefix.
const INDENT: &str = "     ";

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
    let theme = theme::theme();
    let rows = if theme.is_unicode() {
        WORDMARK
    } else {
        ASCII_WORDMARK
    };
    let width = rule_width(&rows);

    for (index, row) in rows.iter().enumerate() {
        if index == 0 {
            writeln!(
                out,
                "  {}  {}",
                theme.accent(theme.glyph(G::Bullet)).bold(),
                theme.accent(row).bold()
            )?;
        } else {
            writeln!(out, "{INDENT}{}", theme.accent(row).bold())?;
        }
    }

    writeln!(out)?;
    writeln!(
        out,
        "{INDENT}{}",
        theme.accent_muted(&theme.repeated(G::Rule, width))
    )?;
    writeln!(out, "{INDENT}{}", theme.strong(TAGLINE))?;
    writeln!(out, "{INDENT}{}", theme.accent_muted(&version_line()))?;
    writeln!(out)?;
    Ok(())
}

/// Width of the rule under the wordmark: its widest row, so the two wordmarks
/// each get a rule that matches their own footprint.
fn rule_width(rows: &[&str; 6]) -> usize {
    rows.iter()
        .map(|row| row.chars().count())
        .max()
        .unwrap_or(0)
}

/// Version and build flavour: package version, parser flavour and rule
/// engine, joined with the theme's separator glyph.
fn version_line() -> String {
    let theme = theme::theme();
    let sep = theme.glyph(G::Sep);
    format!(
        "v{}  {sep}  streaming parser  {sep}  rule engine",
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
        assert_eq!(ASCII_WORDMARK.len(), 6);
    }

    #[test]
    fn wordmark_fits_terminal_width() {
        let prefix = INDENT.chars().count();
        for row in WORDMARK.iter().chain(ASCII_WORDMARK.iter()) {
            assert!(
                prefix + display_width(row) <= 100,
                "wordmark row exceeds 100 columns: {row:?}"
            );
        }
    }

    #[test]
    fn source_rows_have_no_trailing_whitespace() {
        for row in WORDMARK.iter().chain(ASCII_WORDMARK.iter()) {
            assert_eq!(*row, row.trim_end(), "trailing whitespace in {row:?}");
        }
    }

    #[test]
    fn ascii_wordmark_is_seven_bit() {
        for row in ASCII_WORDMARK {
            assert!(row.is_ascii(), "non-ASCII byte in {row:?}");
        }
    }

    #[test]
    fn rule_width_tracks_the_widest_row() {
        for rows in [&WORDMARK, &ASCII_WORDMARK] {
            let widest = rows.iter().map(|row| display_width(row)).max().unwrap_or(0);
            assert_eq!(rule_width(rows), widest);
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
