//! Debug-only per-request timing instrumentation.
//!
//! # What it does
//!
//! In a **debug** build (`cargo build` / `cargo run`, i.e. `debug_assertions`
//! on) every HTTP request produces one NDJSON-style JSON file under
//! `log/json/` describing where the request spent its time:
//!
//! ```json
//! {
//!   "ts": "2026-11-06T07:04:51Z",
//!   "route": "/attestation_all",
//!   "http_status": 200,
//!   "warm": true,
//!   "concurrency": 1,
//!   "e2e_server_us": 128400,
//!   "e2e_client_us": null,
//!   "stages": { "lock_wait_us": 12, "create_quote_us": 62400, ... },
//!   "units": { "tpm2_quote_us": 25600, "files_measured": 6, ... },
//!   "unattributed_us": -1288,
//!   "checksum_ok": true
//! }
//! ```
//!
//! The schema, the meaning of every field and the way each field must be
//! measured are documented in `docs/attestation-sample-record-fields.md`.
//!
//! # Why it is invisible in release builds
//!
//! Every counter, timer, span and file write lives behind
//! `#[cfg(debug_assertions)]`, and every call site in the rest of the crate is
//! itself `#[cfg(debug_assertions)]`. In a release build the only thing that
//! remains is the zero-sized [`Timing`] request guard, whose `from_request`
//! returns immediately: no `Instant::now()`, no allocation, no file I/O.
//!
//! # Design rules (from the measurement plan)
//!
//! * **`stages` are mutually exclusive and add up**; `unattributed_us` is the
//!   residual `e2e_server_us - sum(stages)` and is never spread over a stage.
//! * **`units` are sub-parts of a stage** and are *not* added to `stages`
//!   (`measure_folder_us` belongs to `measure_and_extend_us`).
//! * **Counters are not durations**: `files_measured` / `bytes_measured` are
//!   emitted at the end of `units` but excluded from every sum.
//! * **Nothing is fabricated.** A field that was not measured is simply absent.
//!   `e2e_client_us` is `null` because a server cannot observe it.
//! * **Timing must never break a request**: every failure path (no recorder,
//!   poisoned mutex, unwritable directory) degrades to a no-op.
//!
//! # Where the samples are kept
//!
//! The recorder lives in the request's own `local_cache`, so it travels with
//! the request (`on_request` -> guard -> handler -> `on_response`) no matter
//! which worker thread runs which part. Backend functions receive it through a
//! thread-local installed by [`Timing`]; that is safe because a handler is a
//! plain synchronous `fn` - its whole call tree runs on one thread with no
//! `.await` in between.
//!
//! # Configuration
//!
//! | Variable          | Default          | Meaning                        |
//! |-------------------|------------------|--------------------------------|
//! | `TDX_TIMING_DIR`  | `<project>/log/json` | directory of the JSON files |

#![allow(dead_code)]

use std::convert::Infallible;

use rocket::request::{FromRequest, Outcome};
use rocket::Request;

/// Request guard that installs the timing recorder for one request.
///
/// A handler takes it as its first parameter; the guard is dropped when the
/// handler returns (including on `?` early return), which tears the thread-local
/// scope down again. In a release build this is a zero-sized value whose
/// `from_request` is an inlined no-op.
pub struct Timing(());

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Timing {
    type Error = Infallible;

    #[allow(unused_variables)]
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        #[cfg(debug_assertions)]
        imp::begin(req);

        Outcome::Success(Timing(()))
    }
}

impl Drop for Timing {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        imp::end();
    }
}

#[cfg(debug_assertions)]
mod imp {
    use std::cell::RefCell;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use rocket::Request;

    /// Environment variable holding the directory the JSON files are written to.
    pub const ENV_TIMING_DIR: &str = "TDX_TIMING_DIR";

    /// Default directory, relative to the project root.
    pub const DEFAULT_TIMING_DIR: &str = "log/json";

    /// Requests currently being served, observed at request arrival.
    static INFLIGHT: AtomicUsize = AtomicUsize::new(0);

    /// Monotonic sequence used to keep file names unique within a process.
    static FILE_SEQ: AtomicUsize = AtomicUsize::new(0);

    // -----------------------------------------------------------------------
    // Recorder
    // -----------------------------------------------------------------------

    /// An insertion-ordered `name -> microseconds` map that merges duplicates.
    ///
    /// Order matters: the JSON is expected to read like the execution order, not
    /// like an alphabetically sorted map. A name may be recorded several times
    /// (e.g. `tpm2_flushcontext_us` on the cold Attestation-Key path); the
    /// durations are summed, which is what "how long did all of them take"
    /// means.
    #[derive(Default)]
    struct Buckets {
        items: Vec<(String, u64)>,
    }

    impl Buckets {
        fn add(&mut self, name: &str, us: u64) {
            if let Some(slot) = self.items.iter_mut().find(|(n, _)| n == name) {
                slot.1 += us;
            } else {
                self.items.push((name.to_string(), us));
            }
        }

        fn get(&self, name: &str) -> Option<u64> {
            self.items.iter().find(|(n, _)| n == name).map(|(_, v)| *v)
        }

        fn total(&self) -> u64 {
            self.items.iter().map(|(_, v)| *v).sum()
        }

        fn is_empty(&self) -> bool {
            self.items.is_empty()
        }
    }

    /// Everything measured for one request.
    pub struct Recorder {
        /// Wall clock at request arrival, used for `ts` and for `e2e_server_us`.
        started_at: SystemTime,
        /// Monotonic start, used for every duration.
        start: Instant,
        /// Path part of the request URI (no query string).
        route: String,
        /// `false` once a cold path was taken (AK created / pubkey cache miss).
        warm: bool,
        /// In-flight requests observed when this request arrived.
        concurrency: usize,
        /// Whether this recorder contributed to [`INFLIGHT`] (only a request
        /// that went through `on_request` did).
        counted: bool,
        /// Set once the handler's first line ran (i.e. the body was read).
        handler_entered: bool,
        /// `e2e_server_us`-level, mutually exclusive phases.
        stages: Buckets,
        /// Sub-parts of a stage.
        units: Buckets,
        /// Pure counters; emitted at the end of `units`, never summed.
        counters: Buckets,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                started_at: SystemTime::now(),
                start: Instant::now(),
                route: String::new(),
                warm: true,
                concurrency: INFLIGHT.load(Ordering::Relaxed),
                counted: false,
                handler_entered: false,
                stages: Buckets::default(),
                units: Buckets::default(),
                counters: Buckets::default(),
            }
        }
    }

    /// Fetches (or creates) the recorder of `req`.
    ///
    /// First call wins: it happens in `on_request`, so `start` and `started_at`
    /// are the arrival time, not the time the handler was entered.
    fn recorder(req: &Request<'_>) -> Arc<Mutex<Recorder>> {
        let cell = req.local_cache(|| Arc::new(Mutex::new(Recorder::new())));
        Arc::clone(cell)
    }

    impl Drop for Recorder {
        /// Leaves the in-flight set when the request's last reference dies.
        ///
        /// Doing it here (instead of in `record_response`) keeps `concurrency`
        /// honest even for a request that never reaches `on_response`, e.g. one
        /// whose handler panicked.
        fn drop(&mut self) {
            if self.counted {
                INFLIGHT.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    fn lock(rec: &Arc<Mutex<Recorder>>) -> MutexGuard<'_, Recorder> {
        // A panic earlier in the same request must not lose the sample.
        rec.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // -----------------------------------------------------------------------
    // Thread-local scope (for backend functions without access to `Request`)
    // -----------------------------------------------------------------------

    thread_local! {
        static CURRENT: RefCell<Option<Arc<Mutex<Recorder>>>> = RefCell::new(None);
    }

    fn with_current<T>(f: impl FnOnce(&Arc<Mutex<Recorder>>) -> T) -> Option<T> {
        CURRENT
            .try_with(|cell| {
                let borrow = cell.borrow();
                borrow.as_ref().map(f)
            })
            .ok()
            .flatten()
    }

    /// Called by the [`crate::metrics::Timing`] guard.
    pub fn begin(req: &Request<'_>) {
        let rec = recorder(req);
        {
            let mut guard = lock(&rec);
            if guard.route.is_empty() {
                guard.route = route_of(req);
            }
        }
        CURRENT.with(|cell| *cell.borrow_mut() = Some(rec));
    }

    /// Called when the guard is dropped (handler returned).
    pub fn end() {
        CURRENT.with(|cell| {
            let _ = cell.try_borrow_mut().map(|mut slot| *slot = None);
        });
    }

    // -----------------------------------------------------------------------
    // Measurement points
    // -----------------------------------------------------------------------

    /// A running measurement. Records on [`Span::end`] or on `Drop`, whichever
    /// comes first, so a `?` early return still produces a sample.
    pub struct Span {
        name: String,
        kind: Kind,
        started: Option<Instant>,
        rec: Option<Arc<Mutex<Recorder>>>,
    }

    #[derive(Clone, Copy)]
    enum Kind {
        Stage,
        Unit,
    }

    impl Span {
        /// Stops the measurement now (instead of at end of scope).
        pub fn end(mut self) {
            self.finish();
        }

        fn finish(&mut self) {
            let (Some(started), Some(rec)) = (self.started.take(), self.rec.take()) else {
                return;
            };
            let us = started.elapsed().as_micros() as u64;
            let mut guard = lock(&rec);
            match self.kind {
                Kind::Stage => guard.stages.add(&self.name, us),
                Kind::Unit => guard.units.add(&self.name, us),
            }
        }
    }

    impl Drop for Span {
        fn drop(&mut self) {
            self.finish();
        }
    }

    fn start(name: String, kind: Kind) -> Span {
        let rec = with_current(Arc::clone);
        Span {
            name,
            kind,
            started: Some(Instant::now()),
            rec,
        }
    }

    /// Starts a **stage** measurement (`stages` bucket).
    pub fn span(name: impl Into<String>) -> Span {
        start(name.into(), Kind::Stage)
    }

    /// Starts a **unit** measurement (`units` bucket).
    pub fn unit(name: impl Into<String>) -> Span {
        start(name.into(), Kind::Unit)
    }

    /// Records a counter (`files_measured`, `bytes_measured`, ...).
    pub fn count(name: &str, value: u64) {
        with_current(|rec| lock(rec).counters.add(name, value));
    }

    /// Measures the cost of serialising `value` to JSON.
    ///
    /// The response body of a `Json<T>` responder is serialised by Rocket
    /// *after* the handler returns, so this repeats the serialisation once and
    /// measures that. It is therefore an honest upper bound of `serialize_us`,
    /// not a guess (see the field guide, section 4.3).
    pub fn measure_json<T: serde::Serialize>(value: &T) {
        let _g = span("serialize_us");
        let _ = serde_json::to_vec(value);
    }

    /// Marks the request as having taken a cold path (see `warm`).
    pub fn mark_cold() {
        with_current(|rec| lock(rec).warm = false);
    }

    /// First statement of an instrumented handler.
    ///
    /// Runs after *all* guards - including the data guard that reads the body -
    /// so the elapsed time since arrival is "routing + data guard", which is the
    /// closest honest measurement of `http_body_read_us` available from inside a
    /// handler (see the field guide, section 4.3).
    pub fn enter_handler() {
        let now = Instant::now();
        with_current(|rec| {
            let mut guard = lock(rec);
            if !guard.handler_entered {
                guard.handler_entered = true;
                let us = now.duration_since(guard.start).as_micros() as u64;
                guard.stages.add("http_body_read_us", us);
            }
        });
    }

    // -----------------------------------------------------------------------
    // Request lifecycle, driven by the `RequestLogger` fairing
    // -----------------------------------------------------------------------

    /// `on_request`: create the recorder and note the in-flight count.
    pub fn begin_request(req: &Request<'_>) {
        INFLIGHT.fetch_add(1, Ordering::Relaxed);
        let rec = recorder(req);
        let mut guard = lock(&rec);
        guard.counted = true;
        guard.concurrency = INFLIGHT.load(Ordering::Relaxed);
        if guard.route.is_empty() {
            guard.route = route_of(req);
        }
    }

    /// `on_response`: finalize, write the JSON file, leave the in-flight set.
    pub fn record_response(req: &Request<'_>, status: u16) {
        let rec = recorder(req);
        let (body, name) = {
            let guard = lock(&rec);
            let e2e = guard.start.elapsed().as_micros() as u64;
            let (ts, compact) = timestamp(guard.started_at);
            (
                render(&guard, status, e2e, &ts),
                format!("{}-{}-{:06}.json", compact, std::process::id(), next_seq()),
            )
        };

        if let Some(dir) = timing_dir() {
            if fs::create_dir_all(&dir).is_ok() {
                let _ = fs::write(dir.join(name), body);
            }
        }
    }

    fn next_seq() -> usize {
        FILE_SEQ.fetch_add(1, Ordering::Relaxed)
    }

    fn timing_dir() -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os(ENV_TIMING_DIR) {
            return Some(PathBuf::from(dir));
        }
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_TIMING_DIR))
    }

    fn route_of(req: &Request<'_>) -> String {
        // `Origin::to_string()` renders "/path?query"; only the path is wanted.
        let uri = req.uri().to_string();
        uri.split('?').next().unwrap_or("/").to_string()
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    fn render(rec: &Recorder, status: u16, e2e_us: u64, ts: &str) -> String {
        let unattributed = e2e_us as i64 - rec.stages.total() as i64;

        let mut s = String::with_capacity(1024);
        s.push_str("{\n");
        push_field_str(&mut s, "ts", ts, true);
        push_field_str(&mut s, "route", &rec.route, true);
        push_field_u64(&mut s, "http_status", status as u64, true);
        push_field_bool(&mut s, "warm", rec.warm, true);
        push_field_u64(&mut s, "concurrency", rec.concurrency as u64, true);
        push_field_u64(&mut s, "e2e_server_us", e2e_us, true);
        // A server cannot observe the client-side half of the round trip; an
        // honest `null` is better than a fabricated `0`.
        s.push_str("  \"e2e_client_us\": null,\n");
        push_map(&mut s, "stages", &rec.stages, true);
        push_units(&mut s, rec);
        s.push_str(&format!("  \"unattributed_us\": {},\n", unattributed));
        s.push_str(&format!(
            "  \"checksum_ok\": {}\n",
            checksum_ok(rec, e2e_us, unattributed)
        ));
        s.push_str("}\n");
        s
    }

    fn checksum_ok(rec: &Recorder, e2e_us: u64, unattributed: i64) -> bool {
        // (1) The residual must be small; the framework always leaves a little.
        let tolerance = std::cmp::max(1_000, e2e_us / 20);
        let mut ok = unattributed.unsigned_abs() <= tolerance;

        // (2) A stage may never be smaller than the units measured inside it.
        //     Only fixed parent/child pairs are checked: a unit such as
        //     `tpm2_flushcontext_us` is shared by several stages, so it cannot
        //     be attributed to one of them.
        if let (Some(parent), Some(a), Some(b)) = (
            rec.units.get("measure_folder_us"),
            rec.units.get("collect_regular_files_us"),
            rec.units.get("read_and_hash_loop_us"),
        ) {
            ok &= parent + tolerance.max(parent / 20) >= a + b;
        }
        if let (Some(parent), Some(child)) = (
            rec.stages.get("tdx_report_us"),
            rec.units.get("ioctl_get_report_us"),
        ) {
            ok &= parent + tolerance >= child;
        }

        // (3) Units are *not* mutually exclusive: `measure_folder_us` already
        //     contains `collect_regular_files_us` and `read_and_hash_loop_us`,
        //     so summing every unit double counts the folder walk. Only the
        //     outer, disjoint units may be compared with the whole request -
        //     otherwise a directory-measurement-dominated request (a large model,
        //     where the folder costs ~2x what the sum of its own parts plus the
        //     TPM work costs) is misreported as inconsistent.
        let tpm_us: u64 = rec
            .units
            .items
            .iter()
            .filter(|(n, _)| n.starts_with("tpm2_"))
            .map(|(_, v)| *v)
            .sum();
        let folder_us = rec.units.get("measure_folder_us").unwrap_or(0);
        ok &= tpm_us.saturating_add(folder_us) <= e2e_us.saturating_add(tolerance);

        ok
    }

    fn push_field_str(s: &mut String, key: &str, value: &str, comma: bool) {
        s.push_str("  \"");
        s.push_str(key);
        s.push_str("\": \"");
        s.push_str(&escape(value));
        s.push('"');
        s.push_str(if comma { ",\n" } else { "\n" });
    }

    fn push_field_u64(s: &mut String, key: &str, value: u64, comma: bool) {
        s.push_str(&format!(
            "  \"{}\": {}{}",
            key,
            value,
            if comma { ",\n" } else { "\n" }
        ));
    }

    fn push_field_bool(s: &mut String, key: &str, value: bool, comma: bool) {
        s.push_str(&format!(
            "  \"{}\": {}{}",
            key,
            value,
            if comma { ",\n" } else { "\n" }
        ));
    }

    fn push_map(s: &mut String, key: &str, buckets: &Buckets, trailing_comma: bool) {
        s.push_str("  \"");
        s.push_str(key);
        s.push_str("\": ");
        if buckets.is_empty() {
            s.push_str("{}");
            s.push_str(if trailing_comma { ",\n" } else { "\n" });
            return;
        }
        s.push_str("{\n");
        for (i, (name, value)) in buckets.items.iter().enumerate() {
            s.push_str("    \"");
            s.push_str(&escape(name));
            s.push_str("\": ");
            s.push_str(&value.to_string());
            s.push_str(if i + 1 == buckets.items.len() {
                "\n"
            } else {
                ",\n"
            });
        }
        s.push_str("  }");
        s.push_str(if trailing_comma { ",\n" } else { "\n" });
    }

    fn push_units(s: &mut String, rec: &Recorder) {
        if rec.units.is_empty() && rec.counters.is_empty() {
            s.push_str("  \"units\": {},\n");
            return;
        }
        s.push_str("  \"units\": {\n");
        let mut first = true;
        for (name, value) in rec.units.items.iter() {
            if !first {
                s.push_str(",\n");
            }
            first = false;
            s.push_str(&format!("    \"{}\": {}", escape(name), value));
        }
        for (name, value) in rec.counters.items.iter() {
            if !first {
                s.push_str(",\n");
            }
            first = false;
            s.push_str(&format!("    \"{}\": {}", escape(name), value));
        }
        s.push_str("\n  },\n");
    }

    fn escape(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for c in value.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Timestamps
    // -----------------------------------------------------------------------

    /// Returns `(rfc3339_seconds, compact)`:
    /// `("2026-11-06T07:04:51Z", "20261106T070451Z")`.
    fn timestamp(at: SystemTime) -> (String, String) {
        let seconds = at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let days = seconds.div_euclid(86_400);
        let sod = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let (h, m, sec) = (sod / 3600, (sod % 3600) / 60, sod % 60);

        (
            format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{sec:02}Z"),
            format!("{year:04}{month:02}{day:02}T{h:02}{m:02}{sec:02}Z"),
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn timestamp_is_shaped_like_the_contract() {
            let (rfc, compact) =
                timestamp(UNIX_EPOCH + std::time::Duration::from_secs(1_791_000_291));
            assert_eq!(rfc.len(), 20, "got {rfc}");
            assert!(rfc.ends_with('Z'));
            assert_eq!(&rfc[4..5], "-");
            assert_eq!(&rfc[10..11], "T");
            assert_eq!(compact.len(), 16, "got {compact}");
        }

        #[test]
        fn civil_from_days_matches_known_dates() {
            assert_eq!(civil_from_days(0), (1970, 1, 1));
            assert_eq!(civil_from_days(11017), (2000, 3, 1));
        }

        #[test]
        fn buckets_merge_by_name_and_keep_order() {
            let mut b = Buckets::default();
            b.add("a", 3);
            b.add("b", 5);
            b.add("a", 2);
            assert_eq!(b.items.len(), 2);
            assert_eq!(b.get("a"), Some(5));
            assert_eq!(b.get("b"), Some(5));
            assert_eq!(b.total(), 10);
            assert_eq!(b.items[0].0, "a");
        }

        #[test]
        fn escape_quotes() {
            assert_eq!(escape("a\"b"), "a\\\"b");
            assert_eq!(escape("a\nb"), "a\\nb");
            assert_eq!(escape("/plain"), "/plain");
        }

        #[test]
        fn render_produces_the_documented_shape() {
            let mut rec = Recorder::new();
            rec.route = "/attestation_all".to_string();
            rec.concurrency = 1;
            rec.stages.add("lock_wait_us", 12);
            rec.stages.add("create_quote_us", 62_400);
            rec.units.add("tpm2_quote_us", 25_600);
            rec.counters.add("files_measured", 6);
            rec.counters.add("bytes_measured", 48_213);

            let body = render(&rec, 200, 128_400, "2026-11-06T07:04:51Z");

            assert!(body.starts_with("{\n  \"ts\": \"2026-11-06T07:04:51Z\",\n"));
            assert!(body.contains("\"route\": \"/attestation_all\""));
            assert!(body.contains("\"http_status\": 200"));
            assert!(body.contains("\"warm\": true"));
            assert!(body.contains("\"concurrency\": 1"));
            assert!(body.contains("\"e2e_server_us\": 128400"));
            assert!(body.contains("\"e2e_client_us\": null"));
            // Stage order is insertion order, not alphabetical order.
            let stage_pos = body.find("\"lock_wait_us\"").unwrap();
            let quote_pos = body.find("\"create_quote_us\"").unwrap();
            assert!(stage_pos < quote_pos);
            // Counters are emitted inside `units`, after the durations.
            let unit_pos = body.find("\"tpm2_quote_us\"").unwrap();
            let files_pos = body.find("\"files_measured\": 6").unwrap();
            assert!(unit_pos < files_pos);
            // Residual is computed, never fabricated.
            assert!(body.contains("\"unattributed_us\": 65988"));
            assert!(body.contains("}\n"));
        }

        #[test]
        fn empty_stages_render_as_an_empty_object() {
            let rec = Recorder::new();
            let body = render(&rec, 404, 150, "2026-11-06T07:04:51Z");
            assert!(body.contains("\"stages\": {}"));
            assert!(body.contains("\"units\": {}"));
            // Residual is the whole request when nothing was measured.
            assert!(body.contains("\"unattributed_us\": 150"));
        }

        #[test]
        fn checksum_accepts_a_large_measured_directory() {
            // 7B 模型目录：目录度量 ~90 s 是绝对大头，TPM 部分只有 ~130 ms。
            // `measure_folder_us` 已经包含 `collect_regular_files_us` 和
            // `read_and_hash_loop_us`，三者的和接近两倍的实际耗时 —— 早期版本
            // 用"所有 units 之和 <= e2e" 判断，会把这类记录全部误判为不自洽。
            let mut rec = Recorder::new();
            rec.stages.add("http_body_read_us", 900);
            rec.stages.add("measure_and_extend_us", 90_050_000);
            rec.stages.add("ensure_ak_us", 18_200);
            rec.stages.add("create_quote_us", 62_000);
            rec.stages.add("tdx_report_us", 5_300);
            rec.units.add("measure_folder_us", 89_900_000);
            rec.units.add("collect_regular_files_us", 120_000);
            rec.units.add("read_and_hash_loop_us", 89_760_000);
            rec.units.add("tpm2_startup_us", 18_100);
            rec.units.add("tpm2_quote_us", 25_600);
            rec.units.add("ioctl_get_report_us", 5_200);
            rec.counters.add("files_measured", 20);

            let e2e = 90_150_000u64;
            let unattributed = e2e as i64 - rec.stages.total() as i64;
            assert_eq!(unattributed, 13_600);
            assert!(checksum_ok(&rec, e2e, unattributed));
        }

        #[test]
        fn checksum_rejects_units_bigger_than_the_request() {
            let mut rec = Recorder::new();
            rec.units.add("tpm2_quote_us", 900_000);
            let e2e = 1_000u64;
            let unattributed = e2e as i64;
            assert!(!checksum_ok(&rec, e2e, unattributed));
        }

        #[test]
        fn checksum_rejects_a_folder_that_beats_the_request() {
            let mut rec = Recorder::new();
            // 目录度量本身不可能比整个请求还长。
            rec.stages.add("measure_and_extend_us", 1_000);
            rec.units.add("measure_folder_us", 90_000);
            let e2e = 2_000u64;
            let unattributed = e2e as i64 - rec.stages.total() as i64;
            assert!(!checksum_ok(&rec, e2e, unattributed));
        }

        #[test]
        fn checksum_accepts_a_consistent_request() {
            let mut rec = Recorder::new();
            // A realistic `/attestation_all`: the stages add up to the whole
            // request, and every unit fits inside the stage that contains it.
            rec.stages.add("measure_and_extend_us", 41_200);
            rec.stages.add("ensure_ak_us", 18_300);
            rec.stages.add("create_quote_us", 62_400);
            rec.stages.add("tdx_report_us", 5_310);
            rec.units.add("tpm2_quote_us", 25_600);
            rec.units.add("ioctl_get_report_us", 5_230);
            rec.counters.add("files_measured", 6);

            let e2e = 128_400u64;
            let unattributed = e2e as i64 - rec.stages.total() as i64;
            assert_eq!(unattributed, 1_190);
            assert!(checksum_ok(&rec, e2e, unattributed));
        }

        #[test]
        fn checksum_rejects_a_stage_smaller_than_its_units() {
            let mut rec = Recorder::new();
            // Stages add up to the request, but `tdx_report_us` claims to be
            // shorter than the ioctl measured inside it: impossible.
            rec.stages.add("create_quote_us", 19_000);
            rec.stages.add("tdx_report_us", 1_000);
            rec.units.add("ioctl_get_report_us", 5_230);
            let e2e = 20_000u64;
            let unattributed = e2e as i64 - rec.stages.total() as i64;
            assert_eq!(unattributed, 0);
            assert!(!checksum_ok(&rec, e2e, unattributed));
        }

        #[test]
        fn counters_are_not_durations() {
            let mut rec = Recorder::new();
            rec.counters.add("bytes_measured", 48_213);
            // A counter must never leak into a sum of durations.
            assert_eq!(rec.units.total(), 0);
            assert_eq!(rec.stages.total(), 0);
        }
    }
}

#[cfg(debug_assertions)]
pub use imp::{
    begin_request, count, end, enter_handler, mark_cold, measure_json, record_response, span, unit,
    Span, DEFAULT_TIMING_DIR, ENV_TIMING_DIR,
};
