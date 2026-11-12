use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Options {
    pub path: Option<PathBuf>,
    pub threads: usize,
    pub top: usize,
    pub window_secs: u64,
    pub bf_threshold: u32,
    pub chunk_bytes: u64,
    pub max_events: usize,
    pub no_color: bool,
}

impl Default for Options {
    fn default() -> Self {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(1, 16);
        Self {
            path: None,
            threads,
            top: 10,
            window_secs: 300,
            bf_threshold: 20,
            chunk_bytes: 16 * 1024 * 1024,
            max_events: 250_000,
            no_color: false,
        }
    }
}

pub enum CliAction {
    Run(Options),
    Help,
    Version,
}

pub fn parse_args<I>(args: I) -> Result<CliAction, String>
where
    I: IntoIterator<Item = String>,
{
    let mut opts = Options::default();
    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(CliAction::Help),
            "-V" | "--version" => return Ok(CliAction::Version),
            "--no-color" => {
                opts.no_color = true;
                continue;
            }
            _ => {}
        }

        if let Some(rest) = arg.strip_prefix("--") {
            let (flag, inline) = match rest.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (rest, None),
            };
            let mut next_value = || {
                inline
                    .clone()
                    .or_else(|| iter.next())
                    .ok_or_else(|| format!("--{flag} expects a value"))
            };
            match flag {
                "threads" => {
                    let raw = next_value()?;
                    let parsed: usize = raw
                        .parse()
                        .map_err(|_| format!("--threads expects a whole number, got {raw:?}"))?;
                    if parsed == 0 || parsed > 64 {
                        return Err("--threads must be between 1 and 64".into());
                    }
                    opts.threads = parsed;
                }
                "top" => {
                    let raw = next_value()?;
                    let parsed: usize = raw
                        .parse()
                        .map_err(|_| format!("--top expects a whole number, got {raw:?}"))?;
                    if parsed == 0 || parsed > 100 {
                        return Err("--top must be between 1 and 100".into());
                    }
                    opts.top = parsed;
                }
                "window" => {
                    let raw = next_value()?;
                    let parsed: u64 = raw
                        .parse()
                        .map_err(|_| format!("--window expects a number of seconds, got {raw:?}"))?;
                    if parsed == 0 || parsed > 86_400 {
                        return Err("--window must be between 1 and 86400 seconds".into());
                    }
                    opts.window_secs = parsed;
                }
                "threshold" => {
                    let raw = next_value()?;
                    let parsed: u32 = raw
                        .parse()
                        .map_err(|_| format!("--threshold expects a number, got {raw:?}"))?;
                    if parsed == 0 || parsed > 1_000_000 {
                        return Err("--threshold must be between 1 and 1000000".into());
                    }
                    opts.bf_threshold = parsed;
                }
                "chunk-mb" => {
                    let raw = next_value()?;
                    let parsed: u64 = raw
                        .parse()
                        .map_err(|_| format!("--chunk-mb expects a number, got {raw:?}"))?;
                    if parsed == 0 || parsed > 1024 {
                        return Err("--chunk-mb must be between 1 and 1024".into());
                    }
                    opts.chunk_bytes = parsed * 1024 * 1024;
                }
                "max-events" => {
                    let raw = next_value()?;
                    let parsed: usize = raw
                        .parse()
                        .map_err(|_| format!("--max-events expects a whole number, got {raw:?}"))?;
                    if parsed == 0 || parsed > 5_000_000 {
                        return Err("--max-events must be between 1 and 5000000".into());
                    }
                    opts.max_events = parsed;
                }
                other => return Err(format!("unknown option --{other}")),
            }
            continue;
        }

        if arg.starts_with('-') && arg != "-" {
            return Err(format!("unknown option {arg}"));
        }

        if opts.path.is_some() {
            return Err(format!("unexpected extra argument {arg:?}"));
        }
        opts.path = Some(PathBuf::from(arg));
    }

    Ok(CliAction::Run(opts))
}

pub fn print_help() {
    println!(
        "\
sentinel {version} - rule-based threat detection for nginx access logs

USAGE:
    sentinel [LOG_PATH] [OPTIONS]

    LOG_PATH is optional. When omitted, sentinel prompts for it.

OPTIONS:
    -h, --help           Show this help
    -V, --version        Show version
        --threads N      Parser worker threads (default: auto, max 16)
        --top N          Threat entries shown on the dashboard (default: 10)
        --window SECS    Correlation window in seconds (default: 300)
        --threshold N    Failed logins per window to flag brute force (default: 20)
        --chunk-mb N     Read chunk size in MiB for parallel parsing (default: 16)
        --max-events N   Hard cap on storable threat events (default: 250000)
        --no-color       Disable ANSI colors
",
        version = env!("CARGO_PKG_VERSION")
    );
}
