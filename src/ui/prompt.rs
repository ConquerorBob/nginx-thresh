//! Interactive prompt for the nginx access-log path.
//!
//! Input is intentionally forgiving: surrounding single or double quotes are
//! stripped, whitespace is trimmed and a leading `~/` is expanded through the
//! `HOME` environment variable. Invalid paths produce a single red reason and
//! the prompt repeats until a readable regular file is supplied.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use colored::Colorize;

/// Ask the operator for the nginx access-log path, re-prompting until a
/// readable file is provided.
pub fn prompt_log_path() -> io::Result<PathBuf> {
    let interactive = io::stdin().is_terminal();
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    prompt_with(&mut reader, &mut writer, interactive)
}

/// Testable core of [`prompt_log_path`]. `interactive` controls whether a
/// newline is emitted after each read: a real terminal echoes the operator's
/// Enter, but a pipe does not, so transcripts stay readable either way.
fn prompt_with<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    interactive: bool,
) -> io::Result<PathBuf> {
    let mut buffer = String::new();

    loop {
        write!(
            writer,
            "  {} {} {} ",
            "▸".cyan().bold(),
            "nginx access log path".bold(),
            "›".cyan()
        )?;
        writer.flush()?;

        buffer.clear();
        let read = reader.read_line(&mut buffer)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "no log path provided",
            ));
        }
        if !interactive {
            writeln!(writer)?;
        }

        let Some(candidate) = normalize_input(&buffer) else {
            writeln!(
                writer,
                "    {} {}",
                "✗".red().bold(),
                "path cannot be empty".red()
            )?;
            continue;
        };

        let path = resolve_path(&candidate);
        match validate_path(&path) {
            Ok(()) => {
                // Canonicalise so the dashboard shows a stable absolute path.
                // If the platform cannot resolve it, the validated path is
                // still perfectly usable.
                return Ok(path.canonicalize().unwrap_or(path));
            }
            Err(reason) => {
                writeln!(writer, "    {} {}", "✗".red().bold(), reason.red())?;
            }
        }
    }
}

/// Trim, strip one pair of matching surrounding quotes, then require content.
fn normalize_input(raw: &str) -> Option<String> {
    let unquoted = strip_quotes(raw.trim()).trim();
    if unquoted.is_empty() {
        None
    } else {
        Some(unquoted.to_string())
    }
}

/// Remove a matching pair of single or double quotes around `input`.
fn strip_quotes(input: &str) -> &str {
    let trimmed = input.trim();
    if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0];
        let last = trimmed.as_bytes()[trimmed.len() - 1];
        let quoted = (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'');
        if quoted {
            return &trimmed[1..trimmed.len() - 1];
        }
    }
    trimmed
}

/// Resolve a user-supplied path, expanding `~` through `$HOME`.
fn resolve_path(input: &str) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    expand_tilde(input, home.as_deref())
}

/// Expand a leading `~` or `~/` to `home`; leave `~user/...` untouched.
fn expand_tilde(input: &str, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = input.strip_prefix('~') {
        if rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\') {
            if let Some(home) = home {
                let relative = rest.trim_start_matches(['/', '\\']);
                return if relative.is_empty() {
                    home.to_path_buf()
                } else {
                    home.join(relative)
                };
            }
        }
    }
    PathBuf::from(input)
}

/// Check that `path` exists, is a regular file and can be opened for reading.
fn validate_path(path: &Path) -> Result<(), String> {
    let shown = sanitize_path(path);
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            return Err(match err.kind() {
                io::ErrorKind::NotFound => format!("no such file: {shown}"),
                io::ErrorKind::PermissionDenied => {
                    format!("permission denied: {shown}")
                }
                _ => format!("cannot access {shown}: {err}"),
            });
        }
    };

    if !metadata.is_file() {
        return Err(format!("not a regular file: {shown}"));
    }

    match std::fs::File::open(path) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!("cannot read {shown}: {err}")),
    }
}

/// Terminal-safe rendering of an operator-supplied path.
fn sanitize_path(path: &Path) -> String {
    path.display()
        .to_string()
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn strips_double_quotes() {
        assert_eq!(strip_quotes("\"/var/log/nginx/access.log\""), "/var/log/nginx/access.log");
    }

    #[test]
    fn strips_single_quotes_and_surrounding_space() {
        assert_eq!(strip_quotes("  '/tmp/access.log'  "), "/tmp/access.log");
    }

    #[test]
    fn leaves_unbalanced_quotes_alone() {
        assert_eq!(strip_quotes("\"oops"), "\"oops");
        assert_eq!(strip_quotes("oops'"), "oops'");
    }

    #[test]
    fn normalizes_quoted_and_padded_input() {
        assert_eq!(
            normalize_input("  \"/var/log/nginx/access.log\" \n").as_deref(),
            Some("/var/log/nginx/access.log")
        );
        assert_eq!(normalize_input("   \n").as_deref(), None);
        assert_eq!(normalize_input("\"\"\n").as_deref(), None);
    }

    #[test]
    fn expands_tilde_to_home() {
        let home = Path::new("/home/tester");
        assert_eq!(
            expand_tilde("~/logs/access.log", Some(home)),
            PathBuf::from("/home/tester/logs/access.log")
        );
        assert_eq!(expand_tilde("~", Some(home)), PathBuf::from("/home/tester"));
        assert_eq!(
            expand_tilde("~//logs/access.log", Some(home)),
            PathBuf::from("/home/tester/logs/access.log")
        );
    }

    #[test]
    fn leaves_other_paths_untouched() {
        let home = Path::new("/home/tester");
        assert_eq!(expand_tilde("~bob/log", Some(home)), PathBuf::from("~bob/log"));
        assert_eq!(expand_tilde("~/log", None), PathBuf::from("~/log"));
        assert_eq!(
            expand_tilde("/var/log/nginx/access.log", Some(home)),
            PathBuf::from("/var/log/nginx/access.log")
        );
    }

    #[test]
    fn rejects_missing_files_and_directories() {
        assert!(validate_path(Path::new("/definitely/not/here/access.log")).is_err());
        assert!(validate_path(&std::env::temp_dir()).is_err());
    }

    #[test]
    fn eof_without_input_is_reported() {
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::new();
        let err = prompt_with(&mut reader, &mut writer, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(err.to_string(), "no log path provided");
        let rendered = String::from_utf8(writer).unwrap();
        assert!(rendered.contains("nginx access log path"));
    }

    #[test]
    fn retries_after_bad_input_and_accepts_quoted_path() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("thresh_prompt_test_{}_{stamp}.log", std::process::id()));
        std::fs::write(&path, b"127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 0\n")
            .unwrap();

        let input = format!("/definitely/not/here/access.log\n\"{}\"\n", path.display());
        let mut reader = Cursor::new(input);
        let mut writer = Vec::new();
        let resolved = prompt_with(&mut reader, &mut writer, false).unwrap();

        assert_eq!(resolved, path.canonicalize().unwrap());
        let rendered = String::from_utf8(writer).unwrap();
        assert!(rendered.contains('✗'), "expected an error marker: {rendered}");
        assert!(rendered.contains("nginx access log path"));

        let _ = std::fs::remove_file(path);
    }
}
