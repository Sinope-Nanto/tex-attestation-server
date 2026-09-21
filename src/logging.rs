//! File based logging for the attestation service.
//!
//! Rocket installs its own [`log`] backend at launch and writes to the console,
//! so this module deliberately does **not** touch the global logger. Instead it
//! maintains a small, self-contained *audit log* on disk that records the
//! information an operator needs after the fact:
//!
//! * every HTTP request and the response it produced (status + latency),
//! * every error the service answered with,
//! * the reason a request handler panicked, and
//! * the reason the process is about to abort (panic hook).
//!
//! The log file lives in `log/` next to the project root by default and can be
//! redirected with the `TDX_LOG_DIR` / `TDX_LOG_FILE` environment variables. If
//! the file cannot be opened the logger degrades to a no-op instead of taking
//! the service down: logging must never be the reason a request fails.
//!
//! # Format
//!
//! One event per line, `key=value` pairs, so the file is both human readable
//! and easy to grep:
//!
//! ```text
//! 2024-01-01T00:00:00Z INFO  event=request method=GET uri=/ping client=127.0.0.1
//! 2024-01-01T00:00:00Z INFO  event=response method=GET uri=/ping status=200 latency_ms=0
//! 2024-01-01T00:00:00Z ERROR event=error method=POST uri=/verify-report status=400 message="..."
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::{Data, Request, Response};

/// Environment variable holding the directory the log file is written to.
pub const ENV_LOG_DIR: &str = "TDX_LOG_DIR";
/// Environment variable holding the full path of the log file.
pub const ENV_LOG_FILE: &str = "TDX_LOG_FILE";

/// Default directory (relative to the project root) the log file lives in.
pub const DEFAULT_LOG_DIR: &str = "log";
/// Default name of the log file.
pub const DEFAULT_LOG_FILE: &str = "tdx-attestation.log";

/// The process wide log sink. `None` means logging is disabled (the file could
/// not be opened); every call then becomes a cheap no-op.
static SINK: OnceLock<Option<Mutex<File>>> = OnceLock::new();

/// Resolves the log file path from the environment, falling back to
/// `<project root>/log/tdx-attestation.log`.
pub fn log_file_path() -> PathBuf {
    if let Some(path) = std::env::var_os(ENV_LOG_FILE) {
        return PathBuf::from(path);
    }

    let dir = std::env::var_os(ENV_LOG_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_LOG_DIR));
    dir.join(DEFAULT_LOG_FILE)
}

/// Opens the log file (creating its directory) and installs the panic hook.
///
/// Safe to call more than once: the sink is initialised exactly once and later
/// calls are ignored. Returns the path that was opened, or `None` when the file
/// could not be created.
pub fn init() -> Option<PathBuf> {
    let path = log_file_path();

    let sink = SINK.get_or_init(|| match open_log_file(&path) {
        Ok(file) => Some(Mutex::new(file)),
        Err(err) => {
            eprintln!(
                "warning: cannot open log file {}: {err}; file logging is disabled",
                path.display()
            );
            None
        }
    });

    install_panic_hook();

    if sink.is_some() {
        event("INFO", "event=startup", &[("log_file", path.display().to_string())]);
        Some(path)
    } else {
        None
    }
}

fn open_log_file(path: &Path) -> std::io::Result<File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    OpenOptions::new().create(true).append(true).open(path)
}

/// Writes one structured event to the log file.
///
/// `fields` are rendered as `key=value` pairs; values containing whitespace are
/// quoted. A failure to write is swallowed: logging must never break a request.
pub fn event(level: &str, message: &str, fields: &[(&str, String)]) {
    let Some(Some(sink)) = SINK.get() else {
        return;
    };

    let mut line = String::with_capacity(128);
    line.push_str(&utc_timestamp());
    line.push(' ');
    line.push_str(level);
    line.push(' ');
    line.push_str(message);
    for (key, value) in fields {
        line.push(' ');
        line.push_str(key);
        line.push('=');
        line.push_str(&quote_if_needed(value));
    }
    line.push('\n');

    if let Ok(mut file) = sink.lock() {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
}

/// Convenience wrapper for an `INFO` event.
pub fn info(message: &str, fields: &[(&str, String)]) {
    event("INFO", message, fields);
}

/// Convenience wrapper for a `WARN` event.
pub fn warn(message: &str, fields: &[(&str, String)]) {
    event("WARN", message, fields);
}

/// Convenience wrapper for an `ERROR` event.
pub fn error(message: &str, fields: &[(&str, String)]) {
    event("ERROR", message, fields);
}

/// Logs a request that is about to be routed.
pub fn log_request(method: &str, uri: &str, client: Option<std::net::IpAddr>) {
    info(
        "event=request",
        &[
            ("method", method.to_string()),
            ("uri", uri.to_string()),
            ("client", client.map(|ip| ip.to_string()).unwrap_or_else(|| "-".to_string())),
        ],
    );
}

/// Logs the response produced for a request.
pub fn log_response(method: &str, uri: &str, status: Status, latency: Duration) {
    info(
        "event=response",
        &[
            ("method", method.to_string()),
            ("uri", uri.to_string()),
            ("status", status.code.to_string()),
            ("latency_ms", latency.as_millis().to_string()),
        ],
    );
}

/// Logs an error the service answered with.
pub fn log_error(method: &str, uri: &str, status: Status, message: &str) {
    error(
        "event=error",
        &[
            ("method", method.to_string()),
            ("uri", uri.to_string()),
            ("status", status.code.to_string()),
            ("message", message.to_string()),
        ],
    );
}

/// Installs a panic hook that records the panic reason before the default hook
/// runs. This is what makes an unexpected crash diagnosable after the fact.
fn install_panic_hook() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let default_hook = std::panic::take_hook();
        let hook = move |info: &std::panic::PanicHookInfo<'_>| {
            let location = info
                .location()
                .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
                .unwrap_or_else(|| "unknown".to_string());
            let payload = panic_payload(info);
            let thread = std::thread::current()
                .name()
                .unwrap_or("<unnamed>")
                .to_string();

            error(
                "event=panic",
                &[
                    ("thread", thread),
                    ("location", location),
                    ("message", payload),
                ],
            );

            default_hook(info);
        };
        std::panic::set_hook(Box::new(hook));
    });
}

/// Extracts a human readable message from a panic payload.
fn panic_payload(info: &std::panic::PanicHookInfo<'_>) -> String {
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Quotes a value when it contains whitespace or quotes.
fn quote_if_needed(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if value.chars().any(|c| c.is_whitespace() || c == '"' || c == '=') {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

/// Current UTC time as an RFC 3339-ish `YYYY-MM-DDTHH:MM:SSZ` string.
fn utc_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs() as i64)
        .unwrap_or(0);

    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch -> Y/M/D.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

// ---------------------------------------------------------------------------
// Rocket fairing
// ---------------------------------------------------------------------------

/// Rocket fairing that logs every request and the response it produced.
///
/// The request line is written in `on_request`; the status and the latency are
/// written in `on_response`, once the final response (including error catchers)
/// is known. The start instant is stashed in the request's local cache so the
/// two callbacks can be correlated without any shared mutable state.
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestLogger;

#[rocket::async_trait]
impl Fairing for RequestLogger {
    fn info(&self) -> Info {
        Info {
            name: "request/response logger",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        req.local_cache(Instant::now);
        log_request(
            req.method().as_str(),
            req.uri().to_string().as_str(),
            req.client_ip(),
        );
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        let started = *req.local_cache(Instant::now);
        let latency = started.elapsed();
        let method = req.method().as_str();
        let uri = req.uri().to_string();
        let status = res.status();

        log_response(method, &uri, status, latency);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_if_needed_quotes_whitespace() {
        assert_eq!(quote_if_needed("plain"), "plain");
        assert_eq!(quote_if_needed("two words"), "\"two words\"");
        assert_eq!(quote_if_needed(""), "\"\"");
        assert_eq!(quote_if_needed("a=b"), "\"a=b\"");
    }

    #[test]
    fn timestamp_is_well_formed() {
        let ts = utc_timestamp();
        assert!(ts.ends_with('Z'), "got {ts}");
        assert_eq!(ts.len(), 20, "got {ts}");
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        // 1970-01-01
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2000-03-01
        assert_eq!(civil_from_days(11017), (2000, 3, 1));
    }
}
