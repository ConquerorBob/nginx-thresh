//! Terminal presentation: one place that decides colour and glyphs.
//!
//! Two things differ between machines: how much colour the terminal can show,
//! and whether it can render box-drawing characters. Both are decided once,
//! here. The rest of the UI asks for a role ("accent", "danger", "rule")
//! instead of naming a colour or hard-coding a character, which is what kept
//! the Windows console from lining up: it was being handed UTF-8 box glyphs
//! under a legacy codepage, so a rule printed as mojibake and every column
//! after it shifted.
//!
//! Startup probes the console once (Windows: switch the output codepage to
//! UTF-8 and enable virtual-terminal sequences). If the probe fails, the ASCII
//! glyph set is used and the layout still lines up - the dashboard is laid out
//! in character cells either way.
//!
//! Colour depth order of precedence: `--no-color`, `NO_COLOR`, a non-TTY
//! stdout, `COLORTERM=truecolor`, `TERM=*256color*`, then 16-colour. The
//! accent can be overridden at runtime with `THRESH_ACCENT=#rrggbb`.

use std::io::IsTerminal;
use std::sync::OnceLock;

use colored::{ColoredString, Colorize};

/// Accent for headings, rules and the wordmark.
///
/// #9d7cd8: a dusty violet, less saturated than the usual terminal purples so
/// it sits under the eye for a full scan without glowing, and still holds
/// contrast on both dark and light backgrounds.
const DEFAULT_ACCENT: Rgb = Rgb(0x9D, 0x7C, 0xD8);

/// An 8-bit-per-channel colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

/// How much colour the terminal will be given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tint {
    /// No escape sequences at all.
    None,
    /// The 16 system colours.
    Basic,
    /// 24-bit colour.
    True,
}

/// Every character the UI prints that is not plain ASCII.
///
/// Call sites ask for a role, never for a codepoint, so the ASCII table is the
/// single place a fallback has to be defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum G {
    /// Horizontal rule under a heading.
    Rule,
    /// Heading marker before a section title.
    Bullet,
    /// Thin separator between two values on one line.
    Sep,
    /// Pointer from a threat row to its payload.
    Arrow,
    /// Interactive prompt marker.
    Prompt,
    /// The prompt's closing chevron.
    PromptClose,
    /// Success mark.
    Check,
    /// Failure mark.
    Cross,
    /// Truncation marker.
    Ellipsis,
    /// Box drawing: horizontal.
    BoxH,
    /// Box drawing: vertical.
    BoxV,
    /// Box drawing: top-left corner.
    BoxTL,
    /// Box drawing: top-right corner.
    BoxTR,
    /// Box drawing: bottom-left corner.
    BoxBL,
    /// Box drawing: bottom-right corner.
    BoxBR,
    /// Alert marker.
    Bang,
    /// Histogram cell.
    Bar,
}

impl G {
    /// The UTF-8 form, used whenever the console proved it can print it.
    const fn unicode(self) -> &'static str {
        match self {
            G::Rule => "─",
            G::Bullet => "◆",
            G::Sep => "·",
            G::Arrow => "↳",
            G::Prompt => "▸",
            G::PromptClose => "›",
            G::Check => "✓",
            G::Cross => "✗",
            G::Ellipsis => "…",
            G::BoxH => "─",
            G::BoxV => "│",
            G::BoxTL => "┌",
            G::BoxTR => "┐",
            G::BoxBL => "└",
            G::BoxBR => "┘",
            G::Bang => "!",
            G::Bar => "█",
        }
    }

    /// The ASCII form, for legacy consoles and `--ascii`.
    const fn ascii(self) -> &'static str {
        match self {
            G::Rule => "-",
            G::Bullet => "*",
            G::Sep => "|",
            G::Arrow => "->",
            G::Prompt => ">",
            G::PromptClose => ":",
            G::Check => "ok",
            G::Cross => "x",
            G::Ellipsis => "...",
            G::BoxH => "-",
            G::BoxV => "|",
            G::BoxTL => "+",
            G::BoxTR => "+",
            G::BoxBL => "+",
            G::BoxBR => "+",
            G::Bang => "!",
            G::Bar => "#",
        }
    }
}

/// Fractional block glyphs for the progress gauge, full to empty.
const GAUGE_UNICODE: &str = "█▉▊▋▌▍▎▏  ";
/// ASCII gauge, full to empty. `indicatif` treats the last character as the
/// empty cell and the rest as a fill gradient, so this stays two characters.
const GAUGE_ASCII: &str = "#-";
/// Braille spinner frames.
const SPINNER_UNICODE: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
/// ASCII spinner frames.
const SPINNER_ASCII: &str = "|/-\\";

static THEME: OnceLock<Theme> = OnceLock::new();

/// Resolved presentation settings.
#[derive(Debug)]
pub struct Theme {
    tint: Tint,
    unicode: bool,
    accent: Rgb,
}

/// Configure the terminal once, from `main`, before anything is printed.
///
/// `no_color` comes from `--no-color`, `ascii` from `--ascii`.
pub fn init(no_color: bool, ascii: bool) {
    let _ = THEME.set(build(no_color, ascii));
}

/// The process-wide theme. Falls back to a safe default if [`init`] was never
/// called, so library-style callers and tests do not panic.
pub fn theme() -> &'static Theme {
    THEME.get_or_init(|| build(false, false))
}

fn build(no_color: bool, ascii: bool) -> Theme {
    let (vt, utf8) = probe_console();
    let stdout_is_tty = std::io::stdout().is_terminal();
    let no_color_env = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());

    let tint = if no_color || no_color_env || !stdout_is_tty {
        Tint::None
    } else {
        detect_tint(vt)
    };
    if tint == Tint::None {
        // Keep `colored` from re-enabling itself on the same process.
        colored::control::set_override(false);
    }

    let unicode = if ascii {
        false
    } else if cfg!(windows) {
        utf8
    } else {
        true
    };

    Theme {
        tint,
        unicode,
        accent: accent_from_env(),
    }
}

fn detect_tint(vt_enabled: bool) -> Tint {
    let colorterm = std::env::var("COLORTERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if colorterm.contains("truecolor") || colorterm.contains("24bit") {
        return Tint::True;
    }
    // A Windows console with VT sequences enabled handles 24-bit colour.
    if cfg!(windows) && vt_enabled {
        return Tint::True;
    }
    if std::env::var("TERM")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("256color")
    {
        // `colored` has no 256-palette type; 24-bit sequences are the only
        // exact option, and every terminal that advertises 256 colours either
        // honours them or approximates them itself.
        return Tint::True;
    }
    Tint::Basic
}

/// `THRESH_ACCENT=#c6a0f6` or `THRESH_ACCENT=198,160,246`.
fn accent_from_env() -> Rgb {
    std::env::var("THRESH_ACCENT")
        .ok()
        .and_then(|value| parse_rgb(&value))
        .unwrap_or(DEFAULT_ACCENT)
}

/// Accept `#rrggbb`, `rrggbb`, or `r,g,b`.
fn parse_rgb(input: &str) -> Option<Rgb> {
    let trimmed = input.trim().trim_start_matches('#');
    if trimmed.contains(',') {
        let mut parts = trimmed.split(',');
        let r = parts.next()?.trim().parse().ok()?;
        let g = parts.next()?.trim().parse().ok()?;
        let b = parts.next()?.trim().parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        return Some(Rgb(r, g, b));
    }
    if trimmed.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&trimmed[0..2], 16).ok()?;
    let g = u8::from_str_radix(&trimmed[2..4], 16).ok()?;
    let b = u8::from_str_radix(&trimmed[4..6], 16).ok()?;
    Some(Rgb(r, g, b))
}

impl Theme {
    /// How much colour is in play.
    pub fn tint(&self) -> Tint {
        self.tint
    }

    /// Whether box-drawing glyphs are safe to print.
    pub fn is_unicode(&self) -> bool {
        self.unicode
    }

    /// Look up a printable glyph for the resolved console.
    pub fn glyph(&self, glyph: G) -> &'static str {
        if self.unicode {
            glyph.unicode()
        } else {
            glyph.ascii()
        }
    }

    /// A glyph repeated `count` times, already joined.
    pub fn repeated(&self, glyph: G, count: usize) -> String {
        self.glyph(glyph).repeat(count)
    }

    /// Progress-bar cells, full to empty.
    pub fn gauge_chars(&self) -> &'static str {
        if self.unicode {
            GAUGE_UNICODE
        } else {
            GAUGE_ASCII
        }
    }

    /// Spinner frames.
    pub fn spinner_chars(&self) -> &'static str {
        if self.unicode {
            SPINNER_UNICODE
        } else {
            SPINNER_ASCII
        }
    }

    /// The accent colour for headings, rules and the wordmark.
    pub fn accent(&self, text: &str) -> ColoredString {
        match self.tint {
            Tint::None => text.normal(),
            Tint::True => text.truecolor(self.accent.0, self.accent.1, self.accent.2),
            Tint::Basic => text.bright_magenta(),
        }
    }

    /// Accent, dimmed - used for the version line and de-emphasised rules.
    pub fn accent_muted(&self, text: &str) -> ColoredString {
        self.accent(text).dimmed()
    }

    /// Default foreground, bold - section labels.
    pub fn strong(&self, text: &str) -> ColoredString {
        if self.tint == Tint::None {
            text.normal()
        } else {
            text.bold()
        }
    }

    /// De-emphasised text: labels, units, counts that are not the story.
    pub fn muted(&self, text: &str) -> ColoredString {
        if self.tint == Tint::None {
            text.normal()
        } else {
            text.dimmed()
        }
    }

    /// A finding that matters.
    pub fn danger(&self, text: &str) -> ColoredString {
        if self.tint == Tint::None {
            text.normal()
        } else {
            text.bright_red()
        }
    }

    /// Something degraded but not fatal.
    pub fn warn(&self, text: &str) -> ColoredString {
        if self.tint == Tint::None {
            text.normal()
        } else {
            text.yellow()
        }
    }

    /// Healthy path: a clean scan, a verified file.
    pub fn ok(&self, text: &str) -> ColoredString {
        if self.tint == Tint::None {
            text.normal()
        } else {
            text.green()
        }
    }
}

/// Probe the console and make it capable of what the UI wants to print.
///
/// Returns `(virtual_terminal, utf8)`.
#[cfg(not(windows))]
fn probe_console() -> (bool, bool) {
    (true, true)
}

#[cfg(windows)]
fn probe_console() -> (bool, bool) {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleOutputCP, GetStdHandle, SetConsoleMode, SetConsoleOutputCP,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
    };

    // SAFETY: all four calls take plain console handles and out-parameters.
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: u32 = 0;
        let vt = if GetConsoleMode(handle, &mut mode) != 0 {
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        } else {
            false
        };

        // 65001 is CP_UTF8. Setting it makes the box glyphs one cell wide;
        // reading it back covers consoles that were already in UTF-8.
        let utf8 = SetConsoleOutputCP(65001) != 0 || GetConsoleOutputCP() == 65001;
        (vt, utf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_and_triplet_accents() {
        assert_eq!(parse_rgb("#c6a0f6"), Some(Rgb(0xC6, 0xA0, 0xF6)));
        assert_eq!(parse_rgb("c6a0f6"), Some(Rgb(0xC6, 0xA0, 0xF6)));
        assert_eq!(parse_rgb("198,160,246"), Some(Rgb(198, 160, 246)));
        assert_eq!(parse_rgb(" 198, 160, 246 "), Some(Rgb(198, 160, 246)));
        assert_eq!(parse_rgb("#fff"), None);
        assert_eq!(parse_rgb("1,2"), None);
        assert_eq!(parse_rgb("1,2,3,4"), None);
        assert_eq!(parse_rgb("zzzzzz"), None);
    }

    #[test]
    fn every_glyph_has_a_non_empty_ascii_form() {
        let all = [
            G::Rule,
            G::Bullet,
            G::Sep,
            G::Arrow,
            G::Prompt,
            G::PromptClose,
            G::Check,
            G::Cross,
            G::Ellipsis,
            G::BoxH,
            G::BoxV,
            G::BoxTL,
            G::BoxTR,
            G::BoxBL,
            G::BoxBR,
            G::Bang,
            G::Bar,
        ];
        for glyph in all {
            assert!(!glyph.ascii().is_empty(), "{glyph:?} has no ASCII form");
        }
        // The ASCII set must stay single-byte so columns keep their width.
        assert!(all.iter().all(|g| g.ascii().is_ascii()));
    }

    #[test]
    fn ascii_fallback_is_used_when_unicode_is_off() {
        let theme = Theme {
            tint: Tint::None,
            unicode: false,
            accent: DEFAULT_ACCENT,
        };
        assert_eq!(theme.glyph(G::Rule), "-");
        assert_eq!(theme.glyph(G::Arrow), "->");
        assert_eq!(theme.glyph(G::Ellipsis), "...");
        assert_eq!(theme.repeated(G::Rule, 3), "---");
        assert_eq!(theme.gauge_chars(), GAUGE_ASCII);
        assert_eq!(theme.spinner_chars(), SPINNER_ASCII);
    }

    #[test]
    fn unicode_glyphs_are_single_cells() {
        let theme = Theme {
            tint: Tint::None,
            unicode: true,
            accent: DEFAULT_ACCENT,
        };
        assert_eq!(theme.glyph(G::Rule), "─");
        assert_eq!(theme.glyph(G::Arrow), "↳");
        assert_eq!(theme.glyph(G::Ellipsis), "…");
    }
}
