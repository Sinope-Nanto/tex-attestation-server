//! Integration tests for the file based audit log (`src/logging.rs`).
//!
//! These tests exercise the real sink: they point `TDX_LOG_FILE` at a private
//! temporary file, initialise the logger, emit events and trigger a panic, then
//! assert on the bytes that landed on disk.
//!
//! Because the sink is process global and initialised exactly once, the whole
//! file is a single `#[test]` that drives every scenario in order.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use tdx_attestation_server::logging;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_log_file(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "tdx-logging-test-{}-{}-{}.log",
        std::process::id(),
        tag,
        n
    ))
}

#[test]
fn audit_log_records_events_and_panics() {
    let path = temp_log_file("audit");
    let _ = fs::remove_file(&path);

    // The sink is initialised once per process; point it at our file first.
    std::env::set_var(logging::ENV_LOG_FILE, &path);
    let opened = logging::init();
    assert_eq!(opened.as_deref(), Some(path.as_path()), "log file was not opened");

    // A request/response pair.
    logging::log_request("GET", "/ping", Some("127.0.0.1".parse().unwrap()));
    logging::log_response(
        "GET",
        "/ping",
        rocket::http::Status::Ok,
        std::time::Duration::from_millis(3),
    );

    // An error with a message that needs quoting.
    logging::log_error(
        "POST",
        "/verify-report",
        rocket::http::Status::BadRequest,
        "report is 1 bytes, expected 1024",
    );

    // A panic must be recorded by the installed hook.
    let panicked = std::panic::catch_unwind(|| {
        panic!("deliberate test panic");
    });
    assert!(panicked.is_err(), "the test panic did not unwind");

    let contents = fs::read_to_string(&path).expect("read log file");
    let _ = fs::remove_file(&path);

    assert!(contents.contains("event=startup"), "missing startup line:\n{contents}");
    assert!(
        contents.contains("event=request method=GET uri=/ping client=127.0.0.1"),
        "missing request line:\n{contents}"
    );
    assert!(
        contents.contains("event=response method=GET uri=/ping status=200 latency_ms=3"),
        "missing response line:\n{contents}"
    );
    assert!(
        contents.contains("event=error method=POST uri=/verify-report status=400"),
        "missing error line:\n{contents}"
    );
    assert!(
        contents.contains("message=\"report is 1 bytes, expected 1024\""),
        "the error message was not quoted:\n{contents}"
    );
    assert!(
        contents.contains("event=panic") && contents.contains("deliberate test panic"),
        "the panic was not recorded:\n{contents}"
    );
}
