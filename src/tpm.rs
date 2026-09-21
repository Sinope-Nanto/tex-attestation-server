//! TPM 2.0 attestation backend (TPM simulator backed).
//!
//! This module adds *TPM* attestation next to the TDX attestation implemented in
//! [`crate::attestation`]. It drives a TPM 2.0 device through
//! [`tpm2-tools`](https://github.com/tpm2-software/tpm2-tools) - the very same
//! technique the reference `gpu-node` service uses - and is meant to be pointed
//! at the Microsoft / TCG reference simulator deployed in `workspace/tpm-simu`.
//!
//! # What one request does
//!
//! ```text
//!   measure_folder()          TPM
//!   ────────────────►   PCR_Reset(pcr)
//!                       PCR_Extend(pcr, folder_digest)
//!                       PCR_Read(pcr)            -> pcr_value
//!                       Quote(pcr, qualifying)   -> TPMT_SIGNATURE + TPMS_ATTEST
//! ```
//!
//! The folder digest is **not** the attestation. Only the PCR value and the
//! signed quote are, and both are produced by the TPM itself. The whole
//! sequence runs under a process wide mutex, so two concurrent HTTP requests can
//! never interleave the TPM's stateful reset/extend/read/quote sequence, and the
//! PCR is always reset before it is extended, which keeps repeated measurements
//! of the same folder deterministic.
//!
//! # Folder measurement
//!
//! The reference `gpu-node` measures a *configured file list* with SM3 and a
//! file-order that depends on `find(1)`. That scheme cannot be reproduced here
//! (the deployed `tpm-simu` simulator has no SM3 bank), so the deterministic
//! directory walk below is used instead. It is fully specified:
//!
//! * the configured directory is walked recursively;
//! * only regular files are measured (directories, FIFOs, sockets and devices
//!   are ignored);
//! * a symlink is followed only when it resolves to a regular file *inside* the
//!   measured root - anything pointing outside (or dangling) is skipped;
//! * every file is named by its path **relative to the measured root**, using
//!   `/` separators, and a relative path can never contain `..` because it is
//!   derived from the walk itself;
//! * `file_hash = SHA-256(file contents)`;
//! * files are sorted by the raw bytes of their relative path
//!   (lexicographic), and
//! * `total_hash = SHA-256( for each file in order:
//!        u64_le(len(relative_path)) || relative_path || file_hash )`.
//!
//! `total_hash` therefore binds both the *relative path* and the *contents* of
//! every file. Measuring the same directory twice yields the same digest;
//! changing a single byte of any measured file yields a different one.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use log::{debug, info, warn};
use rocket::serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Defaults and configuration names
// ---------------------------------------------------------------------------

/// Backend name reported by `/information_tpm`.
pub const BACKEND_NAME: &str = "tpm2-tools";

/// Default TPM PCR the folder digest is extended into.
///
/// PCR 16 is a debug PCR: it is resettable from locality 0, which is exactly
/// what the deterministic "reset, extend, read" cycle needs. `gpu-node` uses
/// the same index.
pub const DEFAULT_PCR_INDEX: u32 = 16;

/// Default hash bank. The deployed simulator offers `sha1`, `sha256` and
/// `sha384`; `sha256` is the natural choice and matches the TDX side of this
/// service.
pub const DEFAULT_HASH_ALGORITHM: &str = "sha256";

/// Default TCTI: the Microsoft simulator protocol on the local simulator.
pub const DEFAULT_TCTI: &str = "mssim:host=127.0.0.1,port=2321";

/// Default persistent handle of the Attestation Key.
///
/// `gpu-node` persists its AK at the same handle (`AK_HANDLE` in `tpm.h`), so an
/// existing deployment keeps working unchanged.
pub const DEFAULT_AK_HANDLE: &str = "0x81010002";

/// Default location of the simulator deployment, relative to the project root.
pub const DEFAULT_SIMULATOR_DIR: &str = "tpm-simu";

/// `TPM2B_DATA` upper bound for `Quote.qualifyingData` (the challenge/nonce).
pub const MAX_QUALIFYING_DATA_LEN: usize = 64;

/// Environment variable holding the directory to measure.
pub const ENV_MEASURE_DIR: &str = "TPM_MEASURE_DIR";
/// Environment variable holding the PCR index (decimal).
pub const ENV_PCR_INDEX: &str = "TPM_PCR_INDEX";
/// Environment variable holding the hash bank (`sha256`, `sha384`, ...).
pub const ENV_HASH_ALGORITHM: &str = "TPM_HASH_ALGORITHM";
/// Environment variable holding the tpm2-tools TCTI string.
pub const ENV_TCTI: &str = "TPM_TCTI";
/// Environment variable holding the persistent AK handle.
pub const ENV_AK_HANDLE: &str = "TPM_AK_HANDLE";
/// Environment variable holding the simulator deployment directory.
pub const ENV_SIMULATOR_DIR: &str = "TPM_SIMULATOR_DIR";

/// `gpu-node` status code: success.
pub const RC_SUCCESS: u32 = 0;
/// `gpu-node` status code: the folder could not be measured.
pub const RC_MEASURE_FAIL: u32 = 9001;
/// `gpu-node` status code: the request body was not usable.
pub const RC_REQUEST_ERROR: u32 = 9002;
/// `gpu-node` status code: the TPM quote failed.
pub const RC_QUOTE_FAIL: u32 = 9003;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Everything the TPM backend needs to know, resolved once at startup.
///
/// Values come from the environment so that the deployment (rather than the
/// source) decides which directory is measured and which TPM is talked to. The
/// names follow the existing `ROCKET_*` convention of this project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmConfig {
    /// Directory whose contents are measured.
    pub measure_dir: PathBuf,
    /// PCR the folder digest is extended into.
    pub pcr_index: u32,
    /// Hash bank used for the file digests and for the quote.
    pub hash_algorithm: String,
    /// TCTI passed to every `tpm2-*` invocation.
    pub tcti: String,
    /// Persistent handle of the Attestation Key.
    pub ak_handle: String,
    /// Simulator deployment directory (reported by `/information_tpm`).
    pub simulator_dir: PathBuf,
}

/// The directory measured when `TPM_MEASURE_DIR` is not set.
///
/// The crate's own `src/` directory: it always exists next to a build of this
/// service, it is small, and - unlike the project root - it does not contain
/// the simulator's `NVChip`, which changes every time the TPM is written to.
pub fn default_measure_dir() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("src");
    dir
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            measure_dir: default_measure_dir(),
            pcr_index: DEFAULT_PCR_INDEX,
            hash_algorithm: DEFAULT_HASH_ALGORITHM.to_string(),
            tcti: DEFAULT_TCTI.to_string(),
            ak_handle: DEFAULT_AK_HANDLE.to_string(),
            simulator_dir: PathBuf::from(DEFAULT_SIMULATOR_DIR),
        }
    }
}

impl TpmConfig {
    /// Builds the configuration from the environment, falling back to defaults.
    pub fn from_env() -> Self {
        let defaults = Self::default();

        let measure_dir = std::env::var_os(ENV_MEASURE_DIR)
            .map(PathBuf::from)
            .unwrap_or(defaults.measure_dir);

        let pcr_index = match std::env::var(ENV_PCR_INDEX) {
            Ok(raw) => match raw.trim().parse::<u32>() {
                Ok(v) => v,
                Err(_) => {
                    warn!(
                        "{ENV_PCR_INDEX}={raw:?} is not a valid PCR index; using {}",
                        defaults.pcr_index
                    );
                    defaults.pcr_index
                }
            },
            Err(_) => defaults.pcr_index,
        };

        Self {
            measure_dir,
            pcr_index,
            hash_algorithm: std::env::var(ENV_HASH_ALGORITHM)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(defaults.hash_algorithm),
            tcti: std::env::var(ENV_TCTI)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(defaults.tcti),
            ak_handle: std::env::var(ENV_AK_HANDLE)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(defaults.ak_handle),
            simulator_dir: std::env::var_os(ENV_SIMULATOR_DIR)
                .map(PathBuf::from)
                .unwrap_or(defaults.simulator_dir),
        }
    }

    /// `sha256:16` - the tpm2-tools PCR selection for this configuration.
    pub fn pcr_selection(&self) -> String {
        format!("{}:{}", self.hash_algorithm, self.pcr_index)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the TPM backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmError {
    /// The backend cannot be used at all in this environment: `tpm2-tools` is
    /// missing, or the simulator is not reachable. Surfaces as `501`.
    NotImplemented(String),
    /// The caller supplied something the backend cannot work with (a non-hex
    /// nonce, an oversized nonce, ...). Surfaces as `400`.
    InvalidInput(String),
    /// The backend failed for an internal reason: a bad configuration, an I/O
    /// error, a TPM command that was rejected. Surfaces as `500`.
    Internal(String),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::NotImplemented(msg) => write!(f, "TPM backend unavailable: {msg}"),
            TpmError::InvalidInput(msg) => write!(f, "invalid TPM input: {msg}"),
            TpmError::Internal(msg) => write!(f, "internal TPM error: {msg}"),
        }
    }
}

impl std::error::Error for TpmError {}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// One measured file, in `gpu-node` field naming.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasuredFile {
    /// Path of the file **relative to the measured directory**.
    pub name: String,
    /// `SHA-256` of the file contents, hex encoded.
    pub hash: String,
    /// Size of the file in bytes.
    pub size: u64,
}

/// Result of measuring a directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderMeasurement {
    /// Absolute path of the measured directory.
    pub directory: String,
    /// Hash algorithm used for the per-file and the total digest.
    pub hash_algorithm: String,
    /// The measured files, sorted by relative path.
    pub measurement: Vec<MeasuredFile>,
    /// The combined digest that is extended into the PCR.
    pub total_hash: String,
}

/// `gpu-node` shaped measurement block (`time-stamp` / `measurement` / `total_hash`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmMeasurement {
    /// UTC timestamp of the measurement, `YYYY.MM.DD HH:MM:SS`.
    #[serde(rename = "time-stamp")]
    pub time_stamp: String,
    /// The measured files.
    pub measurement: Vec<MeasuredFile>,
    /// The combined digest.
    pub total_hash: String,
}

impl TpmMeasurement {
    fn from_folder(folder: &FolderMeasurement) -> Self {
        Self {
            time_stamp: utc_timestamp(),
            measurement: folder.measurement.clone(),
            total_hash: folder.total_hash.clone(),
        }
    }
}

/// Successful response of `GET /information_tpm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InformationTpmResponse {
    /// Which client library is used to talk to the TPM (`tpm2-tools`).
    pub backend: String,
    /// Where the simulator deployment lives.
    pub simulator: String,
    /// The TCTI every TPM command is issued with.
    pub tcti: String,
    /// The directory that was measured (absolute).
    pub measured_directory: String,
    /// The hash algorithm used for the folder digest.
    pub hash_algorithm: String,
    /// The PCR the folder digest was extended into.
    pub pcr_index: u32,
    /// The folder measurement.
    pub measurement: TpmMeasurement,
    /// The PCR value after `PCR_Reset` + `PCR_Extend`, hex encoded.
    pub pcr_value: String,
    /// Persistent handle of the Attestation Key.
    pub ak_handle: String,
    /// Public part of the Attestation Key, PEM encoded (best effort).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ak_pubkey: Option<String>,
}

/// Request body of `POST /quote_tpm`.
///
/// The field names follow `gpu-node`'s `/quote` endpoint. `challenge` is
/// accepted as an alias of `nonce`; `nonce_size` and `mask` are accepted for
/// compatibility but are not required.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteTpmRequest {
    /// The challenge, hex encoded. Bound to the quote as `qualifyingData`.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Alias of `nonce`.
    #[serde(default)]
    pub challenge: Option<String>,
    /// Accepted for `gpu-node` compatibility; the length is derived from `nonce`.
    #[serde(default)]
    pub nonce_size: Option<usize>,
    /// Accepted for `gpu-node` compatibility; the PCR is server configured.
    #[serde(default)]
    pub mask: Option<String>,
}

impl QuoteTpmRequest {
    /// Returns the challenge to bind to the quote, validating the hex encoding.
    pub fn resolved_nonce(&self) -> Result<String, TpmError> {
        let value = match (&self.nonce, &self.challenge) {
            (Some(a), Some(b))
                if a.trim().to_ascii_lowercase() != b.trim().to_ascii_lowercase() =>
            {
                return Err(TpmError::InvalidInput(
                    "'nonce' and 'challenge' are both present but differ".to_string(),
                ));
            }
            (Some(a), _) => a,
            (None, Some(b)) => b,
            (None, None) => {
                return Err(TpmError::InvalidInput(
                    "missing required field 'nonce' (alias: 'challenge')".to_string(),
                ));
            }
        };
        let (normalized, _) = normalize_nonce(value)?;
        Ok(normalized)
    }
}

/// The TPM evidence carried by [`QuoteTpmResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmEvidence {
    /// `gpu-node` compatible blob: `signature:message:pcrs`, each part
    /// base64-encoded (see [`TpmEvidence::signature`] for the exact layering).
    pub quote: String,
    /// Length of [`TpmEvidence::quote`] in characters.
    pub quote_size: usize,
    /// `base64(hex(TPMT_SIGNATURE))`.
    pub signature: String,
    /// `base64(hex(TPMS_ATTEST))` - the structure the signature covers.
    pub message: String,
    /// `base64(hex(TPML_PCR_SELECTION))`, one digest per selected PCR.
    pub pcrs: String,
    /// Size of the raw signature in bytes.
    pub signature_size: usize,
    /// Size of the raw attestation structure in bytes.
    pub message_size: usize,
    /// The challenge that was bound to the quote, hex encoded (lowercase).
    pub nonce: String,
    /// Length of the challenge in bytes.
    pub nonce_size: usize,
    /// The PCR the quote covers.
    pub pcr_index: u32,
    /// The hash bank the quote covers.
    pub hash_algorithm: String,
    /// The Attestation Key that produced the signature.
    pub ak_handle: String,
}

/// `evidence` wrapper of [`QuoteTpmResponse`], mirroring `gpu-node`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteEvidence {
    /// The TPM evidence.
    pub tpm: TpmEvidence,
}

/// Successful response of `POST /quote_tpm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteTpmResponse {
    /// `gpu-node` status code; always [`RC_SUCCESS`] on an HTTP 200.
    pub status: u32,
    /// The folder measurement the PCR was extended with.
    pub measurement: TpmMeasurement,
    /// The PCR value after `PCR_Reset` + `PCR_Extend`, hex encoded.
    pub pcr_value: String,
    /// The PCR index the quote covers.
    pub pcr_index: u32,
    /// The hash bank the quote covers.
    pub hash_algorithm: String,
    /// The TPM evidence.
    pub evidence: QuoteEvidence,
    /// Public part of the Attestation Key, PEM encoded (best effort).
    pub ak_pubkey: String,
}

// ---------------------------------------------------------------------------
// Folder measurement
// ---------------------------------------------------------------------------

/// Measures `root` and returns its deterministic digest.
///
/// See the module documentation for the exact algorithm. The function never
/// panics: a missing directory, an unreadable file or an unreadable
/// subdirectory is reported as [`TpmError`].
///
/// # Errors
///
/// * [`TpmError::Internal`] - `root` does not exist, is not a directory, or a
///   path below it could not be read.
pub fn measure_folder(root: &Path) -> Result<FolderMeasurement, TpmError> {
    let metadata = fs::metadata(root).map_err(|err| {
        TpmError::Internal(format!(
            "measured directory {} cannot be read: {err}",
            root.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(TpmError::Internal(format!(
            "measured path {} is not a directory",
            root.display()
        )));
    }

    let root = fs::canonicalize(root).map_err(|err| {
        TpmError::Internal(format!(
            "measured directory {} cannot be resolved: {err}",
            root.display()
        ))
    })?;

    let mut files: Vec<PathBuf> = Vec::new();
    collect_regular_files(&root, &root, &mut files)?;

    let mut entries: Vec<(String, PathBuf)> = files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            (relative, path)
        })
        .collect();

    // Deterministic order: raw byte comparison of the relative path.
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    let mut total = Sha256::new();
    let mut measurement = Vec::with_capacity(entries.len());

    for (name, path) in entries {
        let contents = fs::read(&path).map_err(|err| {
            TpmError::Internal(format!(
                "measured file {} cannot be read: {err}",
                path.display()
            ))
        })?;

        let digest = Sha256::digest(&contents);
        total.update((name.len() as u64).to_le_bytes());
        total.update(name.as_bytes());
        total.update(digest);

        measurement.push(MeasuredFile {
            name,
            hash: hex::encode(digest),
            size: contents.len() as u64,
        });
    }

    Ok(FolderMeasurement {
        directory: root.to_string_lossy().into_owned(),
        hash_algorithm: DEFAULT_HASH_ALGORITHM.to_string(),
        measurement,
        total_hash: hex::encode(total.finalize()),
    })
}

/// Recursively collects the regular files below `dir` (contained by `root`).
fn collect_regular_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), TpmError> {
    let read_dir = fs::read_dir(dir).map_err(|err| {
        TpmError::Internal(format!("directory {} cannot be read: {err}", dir.display()))
    })?;

    let mut children: Vec<PathBuf> = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|err| {
            TpmError::Internal(format!(
                "directory entry below {} cannot be read: {err}",
                dir.display()
            ))
        })?;
        children.push(entry.path());
    }
    children.sort();

    for path in children {
        let metadata = fs::symlink_metadata(&path).map_err(|err| {
            TpmError::Internal(format!(
                "metadata of {} cannot be read: {err}",
                path.display()
            ))
        })?;
        let file_type = metadata.file_type();

        if file_type.is_symlink() {
            // Only follow a link that stays inside the measured root and lands
            // on a regular file; never let a link escape the root.
            match fs::canonicalize(&path) {
                Ok(target) if target.starts_with(root) => match fs::metadata(&target) {
                    Ok(target_metadata) if target_metadata.is_file() => out.push(path),
                    Ok(_) => debug!("skipping symlink to a non-file: {}", path.display()),
                    Err(err) => debug!("skipping unresolvable symlink {}: {err}", path.display()),
                },
                Ok(target) => debug!(
                    "skipping symlink leaving the measured root: {} -> {}",
                    path.display(),
                    target.display()
                ),
                Err(err) => debug!("skipping dangling symlink {}: {err}", path.display()),
            }
            continue;
        }

        if file_type.is_dir() {
            collect_regular_files(root, &path, out)?;
        } else if file_type.is_file() {
            out.push(path);
        } else {
            // FIFOs, sockets, block/char devices are not measurable content.
            debug!("skipping non-regular file: {}", path.display());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Backend state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TpmInner {
    /// Cached PEM of the Attestation Key public part.
    ak_pubkey: Option<String>,
}

/// Shared, process wide state of the TPM backend.
///
/// Holds the configuration plus a mutex that serialises every TPM interaction:
/// a TPM is a stateful device and `PCR_Reset` + `PCR_Extend` + `Quote` must be
/// one indivisible step.
pub struct TpmState {
    config: TpmConfig,
    inner: Mutex<TpmInner>,
}

impl TpmState {
    /// Builds the state and logs the resolved configuration.
    pub fn new(config: TpmConfig) -> Self {
        info!(
            "TPM backend initialised: backend={BACKEND_NAME} tcti={} simulator={} \
             measure_dir={} pcr={} hash={} ak={}",
            config.tcti,
            config.simulator_dir.display(),
            config.measure_dir.display(),
            config.pcr_index,
            config.hash_algorithm,
            config.ak_handle,
        );
        Self {
            config,
            inner: Mutex::new(TpmInner::default()),
        }
    }

    /// Builds the state from the environment.
    pub fn from_env() -> Self {
        Self::new(TpmConfig::from_env())
    }

    /// The resolved configuration.
    pub fn config(&self) -> &TpmConfig {
        &self.config
    }

    /// Takes the TPM transaction lock.
    ///
    /// A panic in an earlier request must not take the service down, so a
    /// poisoned mutex is recovered from instead of being propagated.
    fn lock(&self) -> MutexGuard<'_, TpmInner> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            warn!("TPM transaction lock was poisoned by an earlier failure; recovering");
            poisoned.into_inner()
        })
    }
}

// ---------------------------------------------------------------------------
// Nonce helpers
// ---------------------------------------------------------------------------

/// Validates a hex encoded challenge and returns it canonicalised (lowercase).
///
/// # Errors
///
/// * [`TpmError::InvalidInput`] - empty, odd length, non-hex, or longer than
///   [`MAX_QUALIFYING_DATA_LEN`] bytes.
pub fn normalize_nonce(nonce_hex: &str) -> Result<(String, usize), TpmError> {
    let trimmed = nonce_hex.trim();
    if trimmed.is_empty() {
        return Err(TpmError::InvalidInput(
            "the nonce must not be empty".to_string(),
        ));
    }
    if trimmed.len() % 2 != 0 {
        return Err(TpmError::InvalidInput(format!(
            "the nonce must have an even number of hex characters, got {}",
            trimmed.len()
        )));
    }

    let bytes = hex::decode(trimmed)
        .map_err(|err| TpmError::InvalidInput(format!("the nonce is not valid hex: {err}")))?;

    if bytes.is_empty() {
        return Err(TpmError::InvalidInput(
            "the nonce must not be empty".to_string(),
        ));
    }
    if bytes.len() > MAX_QUALIFYING_DATA_LEN {
        return Err(TpmError::InvalidInput(format!(
            "the nonce is {} bytes, but TPM qualifying data holds at most {MAX_QUALIFYING_DATA_LEN}",
            bytes.len()
        )));
    }

    Ok((hex::encode(&bytes), bytes.len()))
}

// ---------------------------------------------------------------------------
// TPM operations
// ---------------------------------------------------------------------------

/// Runs one `tpm2-*` command against the configured TPM.
fn tpm2(config: &TpmConfig, subcommand: &str, args: &[&str]) -> Result<String, TpmError> {
    let binary = format!("tpm2_{subcommand}");
    let tcti = format!("--tcti={}", config.tcti);

    let output = match Command::new(&binary).args(args).arg(&tcti).output() {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(TpmError::NotImplemented(format!(
                "`{binary}` was not found; install tpm2-tools to enable TPM attestation"
            )));
        }
        Err(err) => {
            return Err(TpmError::Internal(format!(
                "`{binary}` could not be executed: {err}"
            )));
        }
    };

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    Err(classify_failure(config, &binary, &output.stderr))
}

/// Maps a failed `tpm2-*` invocation onto the right error class.
///
/// A TPM that cannot be reached at all (missing TCTI plugin, refused socket,
/// no route) is a *deployment* problem, not a request problem, so it becomes
/// [`TpmError::NotImplemented`] and surfaces as `501`. Everything else is a
/// genuine command failure and becomes [`TpmError::Internal`] (`500`).
fn classify_failure(config: &TpmConfig, binary: &str, stderr: &[u8]) -> TpmError {
    let stderr = String::from_utf8_lossy(stderr);

    // Keep the first meaningful line: tpm2-tools is very chatty about TCTI
    // loading, and those lines may mention paths we do not want to echo back
    // in full.
    let detail = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .find(|line| line.starts_with("ERROR") || line.starts_with("WARNING"))
        .unwrap_or("no diagnostic output")
        .to_string();

    let lowered = stderr.to_ascii_lowercase();
    let unreachable = [
        "connection refused",
        "could not connect",
        "no route to host",
        "failed to connect",
        "could not load tcti",
        "failed to instantiate tcti",
        "could not initialize tcti file",
    ]
    .iter()
    .any(|marker| lowered.contains(marker));

    if unreachable {
        TpmError::NotImplemented(format!(
            "TPM is not reachable through `{binary}` (tcti={}): {detail}",
            config.tcti
        ))
    } else {
        TpmError::Internal(format!("`{binary}` failed: {detail}"))
    }
}

/// Brings the TPM out of reset. Idempotent: an already started TPM is fine.
fn ensure_ready(config: &TpmConfig) -> Result<(), TpmError> {
    match tpm2(config, "startup", &["-c"]) {
        Ok(_) => {
            info!("TPM simulator startup: OK");
            Ok(())
        }
        // The simulator (or the tools) is not there at all.
        Err(err @ TpmError::NotImplemented(_)) => Err(err),
        // `TPM2_Startup` on a started TPM fails with 0x100; that is expected.
        Err(err) => {
            debug!("tpm2_startup reported: {err} (TPM already started, continuing)");
            Ok(())
        }
    }
}

/// Best effort release of the transient object slots.
fn flush_transient(config: &TpmConfig) {
    if let Err(err) = tpm2(config, "flushcontext", &["-t"]) {
        debug!("tpm2_flushcontext -t: {err}");
    }
}

fn reset_pcr(config: &TpmConfig) -> Result<(), TpmError> {
    let index = config.pcr_index.to_string();
    tpm2(config, "pcrreset", &[&index])
        .map(|_| ())
        .map_err(|err| match err {
            TpmError::NotImplemented(msg) => TpmError::NotImplemented(msg),
            other => TpmError::Internal(format!(
                "PCR {} could not be reset, so repeated measurements would not be \
             deterministic: {other}",
                config.pcr_index
            )),
        })
}

fn extend_pcr(config: &TpmConfig, digest_hex: &str) -> Result<(), TpmError> {
    let spec = format!(
        "{}:{}={}",
        config.pcr_index, config.hash_algorithm, digest_hex
    );
    tpm2(config, "pcrextend", &[&spec]).map(|_| ())
}

fn read_pcr(config: &TpmConfig, scratch: &Scratch) -> Result<String, TpmError> {
    let output = scratch.arg("pcr.bin")?;
    tpm2(config, "pcrread", &[&config.pcr_selection(), "-o", &output])?;

    let bytes = fs::read(scratch.path("pcr.bin")).map_err(|err| {
        TpmError::Internal(format!(
            "PCR {} output cannot be read: {err}",
            config.pcr_index
        ))
    })?;
    if bytes.is_empty() {
        return Err(TpmError::Internal(format!(
            "PCR {} read returned no data",
            config.pcr_index
        )));
    }

    Ok(hex::encode(bytes))
}

/// Makes sure an Attestation Key is persisted at the configured handle.
///
/// An existing key is always reused; a new one is created (and persisted) only
/// when the handle is empty. Creating a key per request would leak persistent
/// objects, so that never happens.
fn ensure_ak(config: &TpmConfig, scratch: &Scratch) -> Result<(), TpmError> {
    let handles = tpm2(config, "getcap", &["handles-persistent"])?;
    let wanted = config.ak_handle.trim().to_ascii_lowercase();
    let present = handles
        .lines()
        .map(|line| {
            line.trim()
                .trim_start_matches('-')
                .trim()
                .to_ascii_lowercase()
        })
        .any(|line| line == wanted);

    if present {
        debug!("Attestation Key {} already persisted", config.ak_handle);
        return Ok(());
    }

    info!(
        "Attestation Key {} is missing; creating and persisting one",
        config.ak_handle
    );

    let ek_ctx = scratch.arg("ek.ctx")?;
    let ek_pub = scratch.arg("ek.pub")?;
    let ak_ctx = scratch.arg("ak.ctx")?;
    let ak_pub = scratch.arg("ak.pub")?;

    flush_transient(config);
    tpm2(
        config,
        "createek",
        &["-G", "rsa", "-c", &ek_ctx, "-u", &ek_pub],
    )?;

    flush_transient(config);
    tpm2(
        config,
        "createak",
        &[
            "-C", &ek_ctx, "-c", &ak_ctx, "-G", "rsa", "-g", "sha256", "-s", "rsassa", "-u",
            &ak_pub,
        ],
    )?;

    flush_transient(config);
    tpm2(
        config,
        "evictcontrol",
        &["-C", "o", "-c", &ak_ctx, &config.ak_handle],
    )?;

    flush_transient(config);
    Ok(())
}

/// Reads (and caches) the PEM encoded public part of the Attestation Key.
fn ak_pubkey(
    config: &TpmConfig,
    inner: &mut TpmInner,
    scratch: &Scratch,
) -> Result<String, TpmError> {
    if let Some(cached) = &inner.ak_pubkey {
        return Ok(cached.clone());
    }

    flush_transient(config);
    let path = scratch.arg("ak.pem")?;
    tpm2(
        config,
        "readpublic",
        &["-c", &config.ak_handle, "-o", &path, "-f", "pem"],
    )?;

    let pem = fs::read_to_string(scratch.path("ak.pem")).map_err(|err| {
        TpmError::Internal(format!("Attestation Key public part cannot be read: {err}"))
    })?;

    inner.ak_pubkey = Some(pem.clone());
    Ok(pem)
}

/// Produces a real TPM quote over the configured PCR, bound to `nonce_hex`.
fn create_quote(
    config: &TpmConfig,
    nonce_hex: &str,
    scratch: &Scratch,
) -> Result<(TpmEvidence, usize), TpmError> {
    flush_transient(config);

    let signature_path = scratch.arg("quote.sig")?;
    let message_path = scratch.arg("quote.msg")?;
    let pcrs_path = scratch.arg("quote.pcrs")?;

    tpm2(
        config,
        "quote",
        &[
            "-c",
            &config.ak_handle,
            "-g",
            &config.hash_algorithm,
            "-l",
            &config.pcr_selection(),
            "-q",
            nonce_hex,
            "-s",
            &signature_path,
            "-m",
            &message_path,
            "-o",
            &pcrs_path,
        ],
    )?;

    let signature = read_blob(scratch, "quote.sig")?;
    let message = read_blob(scratch, "quote.msg")?;
    let pcrs = read_blob(scratch, "quote.pcrs")?;

    // `gpu-node` joins the three blobs with ':' and reports the length of the
    // joined string as `quote_size`; the parts themselves are `base64(hex(..))`.
    let quote = format!("{}:{}:{}", signature.0, message.0, pcrs.0);

    let (_, nonce_size) = normalize_nonce(nonce_hex)?;

    let evidence = TpmEvidence {
        quote_size: quote.len(),
        quote,
        signature: signature.0,
        message: message.0,
        pcrs: pcrs.0,
        signature_size: signature.1,
        message_size: message.1,
        nonce: nonce_hex.to_ascii_lowercase(),
        nonce_size,
        pcr_index: config.pcr_index,
        hash_algorithm: config.hash_algorithm.clone(),
        ak_handle: config.ak_handle.clone(),
    };

    Ok((evidence, nonce_size))
}

/// Reads a file and returns `(base64(hex(bytes)), raw_len)`.
fn read_blob(scratch: &Scratch, name: &str) -> Result<(String, usize), TpmError> {
    let path = scratch.path(name);
    let bytes = fs::read(&path)
        .map_err(|err| TpmError::Internal(format!("{} cannot be read: {err}", path.display())))?;
    if bytes.is_empty() {
        return Err(TpmError::Internal(format!(
            "{} is empty; the TPM did not produce any data",
            path.display()
        )));
    }
    let encoded = BASE64.encode(hex::encode(&bytes).as_bytes());
    Ok((encoded, bytes.len()))
}

/// Reset, measure, extend and read - the core of both TPM endpoints.
fn measure_and_extend(
    config: &TpmConfig,
    scratch: &Scratch,
) -> Result<(FolderMeasurement, String), TpmError> {
    info!(
        "TPM measurement start: directory={} pcr={} hash={}",
        config.measure_dir.display(),
        config.pcr_index,
        config.hash_algorithm
    );
    let measurement = measure_folder(&config.measure_dir)?;
    info!(
        "TPM measurement completed: files={} total_hash={}",
        measurement.measurement.len(),
        measurement.total_hash
    );

    ensure_ready(config)?;

    info!("TPM PCR operation: reset index={}", config.pcr_index);
    reset_pcr(config)?;

    info!(
        "TPM PCR operation: extend index={} digest={}",
        config.pcr_index, measurement.total_hash
    );
    extend_pcr(config, &measurement.total_hash)?;

    let pcr_value = read_pcr(config, scratch)?;
    info!(
        "TPM PCR operation: read index={} value={}",
        config.pcr_index, pcr_value
    );

    Ok((measurement, pcr_value))
}

impl FolderMeasurement {
    /// The `gpu-node` shaped measurement block.
    pub fn as_tpm_measurement(&self) -> TpmMeasurement {
        TpmMeasurement::from_folder(self)
    }
}

/// `GET /information_tpm` backend logic.
///
/// Measures the configured directory, extends the configured PCR with the
/// folder digest, reads the PCR back and returns all of it. The Attestation Key
/// public part is attached on a best effort basis.
///
/// # Errors
///
/// * [`TpmError::NotImplemented`] - the simulator is not reachable.
/// * [`TpmError::Internal`] - the measurement or a PCR operation failed.
pub fn information_tpm(state: &TpmState) -> Result<InformationTpmResponse, TpmError> {
    let mut inner = state.lock();
    let config = state.config();
    let scratch = Scratch::new()?;

    let (measurement, pcr_value) = measure_and_extend(config, &scratch)?;

    let ak_pubkey =
        match ensure_ak(config, &scratch).and_then(|()| ak_pubkey(config, &mut inner, &scratch)) {
            Ok(pem) => Some(pem),
            Err(err) => {
                warn!("TPM Attestation Key information is unavailable: {err}");
                None
            }
        };

    Ok(InformationTpmResponse {
        backend: BACKEND_NAME.to_string(),
        simulator: config.simulator_dir.to_string_lossy().into_owned(),
        tcti: config.tcti.clone(),
        measured_directory: measurement.directory.clone(),
        hash_algorithm: config.hash_algorithm.clone(),
        pcr_index: config.pcr_index,
        measurement: measurement.as_tpm_measurement(),
        pcr_value,
        ak_handle: config.ak_handle.clone(),
        ak_pubkey,
    })
}

/// `POST /quote_tpm` backend logic.
///
/// Runs the same reset/measure/extend/read cycle as [`information_tpm`] and
/// then asks the TPM for a quote over the same PCR, with `nonce_hex` bound as
/// `qualifyingData`.
///
/// # Errors
///
/// * [`TpmError::InvalidInput`] - `nonce_hex` is not a usable challenge.
/// * [`TpmError::NotImplemented`] - the simulator is not reachable.
/// * [`TpmError::Internal`] - the measurement, a PCR operation or the quote
///   failed.
pub fn quote_tpm(state: &TpmState, nonce_hex: &str) -> Result<QuoteTpmResponse, TpmError> {
    let (nonce, nonce_size) = normalize_nonce(nonce_hex)?;

    let mut inner = state.lock();
    let config = state.config();
    let scratch = Scratch::new()?;

    let (measurement, pcr_value) = measure_and_extend(config, &scratch)?;

    info!(
        "TPM quote start: ak={} pcr={} challenge_bytes={}",
        config.ak_handle, config.pcr_index, nonce_size
    );
    ensure_ak(config, &scratch)?;
    let (evidence, _) = create_quote(config, &nonce, &scratch)?;
    info!(
        "TPM quote completed: quote_size={} signature_size={} message_size={}",
        evidence.quote_size, evidence.signature_size, evidence.message_size
    );

    let ak_pubkey = ak_pubkey(config, &mut inner, &scratch).unwrap_or_else(|err| {
        warn!("Attestation Key public part is unavailable: {err}");
        String::new()
    });

    Ok(QuoteTpmResponse {
        status: RC_SUCCESS,
        measurement: measurement.as_tpm_measurement(),
        pcr_value,
        pcr_index: config.pcr_index,
        hash_algorithm: config.hash_algorithm.clone(),
        evidence: QuoteEvidence { tpm: evidence },
        ak_pubkey,
    })
}

// ---------------------------------------------------------------------------
// Scratch directory
// ---------------------------------------------------------------------------

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A private temporary directory for the files tpm2-tools exchange with us.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new() -> Result<Self, TpmError> {
        let counter = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("tdx-tpm-{}-{}", std::process::id(), counter));
        fs::create_dir_all(&dir).map_err(|err| {
            TpmError::Internal(format!(
                "temporary directory {} cannot be created: {err}",
                dir.display()
            ))
        })?;
        Ok(Self { dir })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn arg(&self, name: &str) -> Result<String, TpmError> {
        self.path(name)
            .into_os_string()
            .into_string()
            .map_err(|path| {
                TpmError::Internal(format!("temporary path {path:?} is not valid UTF-8"))
            })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// ---------------------------------------------------------------------------
// Time helper
// ---------------------------------------------------------------------------

/// Current UTC time as `YYYY.MM.DD HH:MM:SS` (matches `gpu-node`'s format).
fn utc_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs() as i64)
        .unwrap_or(0);

    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);

    format!(
        "{year:04}.{month:02}.{day:02} {:02}:{:02}:{:02}",
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    /// A unique, self-cleaning temporary directory.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let counter = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "tdx-tpm-test-{}-{}-{}",
                std::process::id(),
                tag,
                counter
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, relative: &str, contents: &[u8]) {
            let full = self.path.join(relative);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).expect("create parent dir");
            }
            let mut file = fs::File::create(&full).expect("create test file");
            file.write_all(contents).expect("write test file");
            file.sync_all().expect("sync test file");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Two consecutive measurements of an unchanged tree are identical.
    #[test]
    fn measurement_is_deterministic() {
        let dir = TempDir::new("stable");
        dir.write("a.txt", b"alpha");
        dir.write("sub/b.txt", b"bravo");

        let first = measure_folder(dir.path()).expect("first measurement");
        let second = measure_folder(dir.path()).expect("second measurement");

        assert_eq!(first.total_hash, second.total_hash);
        assert_eq!(first.measurement, second.measurement);
        assert_eq!(first.measurement.len(), 2);
        assert_eq!(first.measurement[0].name, "a.txt");
        assert_eq!(first.measurement[1].name, "sub/b.txt");
        assert_eq!(first.total_hash.len(), 64);
    }

    /// Changing one byte of one file changes the total digest.
    #[test]
    fn measurement_changes_when_a_file_changes() {
        let dir = TempDir::new("mutate");
        dir.write("a.txt", b"alpha");
        dir.write("sub/b.txt", b"bravo");

        let before = measure_folder(dir.path()).expect("measurement before");
        dir.write("a.txt", b"alpha!");
        let after = measure_folder(dir.path()).expect("measurement after");

        assert_ne!(before.total_hash, after.total_hash);
    }

    /// Identical content, different creation order, identical digest.
    #[test]
    fn measurement_is_order_independent() {
        let first_dir = TempDir::new("order-a");
        first_dir.write("a.txt", b"alpha");
        first_dir.write("sub/b.txt", b"bravo");
        first_dir.write("zz/c.txt", b"charlie");

        let second_dir = TempDir::new("order-b");
        second_dir.write("zz/c.txt", b"charlie");
        second_dir.write("sub/b.txt", b"bravo");
        second_dir.write("a.txt", b"alpha");

        let first = measure_folder(first_dir.path()).expect("first tree");
        let second = measure_folder(second_dir.path()).expect("second tree");

        assert_eq!(first.total_hash, second.total_hash);
        assert_eq!(first.measurement, second.measurement);
    }

    /// The relative path is part of the measurement: renaming a file changes it.
    #[test]
    fn measurement_binds_the_relative_path() {
        let dir = TempDir::new("rename");
        dir.write("a.txt", b"alpha");
        let before = measure_folder(dir.path()).expect("measurement before");

        fs::rename(dir.path().join("a.txt"), dir.path().join("b.txt")).expect("rename");
        let after = measure_folder(dir.path()).expect("measurement after");

        assert_eq!(before.measurement[0].hash, after.measurement[0].hash);
        assert_ne!(before.total_hash, after.total_hash);
    }

    /// A missing directory is an error, never a panic.
    #[test]
    fn measurement_of_a_missing_directory_is_an_error() {
        let missing = std::env::temp_dir().join("tdx-tpm-does-not-exist-4d5a1c");
        let _ = fs::remove_dir_all(&missing);

        let result = measure_folder(&missing);

        assert!(result.is_err(), "a missing directory must not measure");
        assert!(matches!(result.unwrap_err(), TpmError::Internal(_)));
    }

    /// A file is not a directory.
    #[test]
    fn measurement_of_a_file_is_an_error() {
        let dir = TempDir::new("not-a-dir");
        dir.write("a.txt", b"alpha");

        let result = measure_folder(&dir.path().join("a.txt"));
        assert!(matches!(result.unwrap_err(), TpmError::Internal(_)));
    }

    /// Empty files are measured too: deleting one changes the digest.
    #[test]
    fn empty_files_are_measured() {
        let dir = TempDir::new("empty-file");
        dir.write("empty.txt", b"");

        let measurement = measure_folder(dir.path()).expect("measurement");
        assert_eq!(measurement.measurement.len(), 1);
        assert_eq!(measurement.measurement[0].size, 0);
        assert_eq!(
            measurement.measurement[0].hash,
            hex::encode(Sha256::digest(b""))
        );
    }

    #[test]
    fn nonce_is_validated() {
        assert!(normalize_nonce("00").is_ok());
        assert!(normalize_nonce("DEADBEEF").is_ok());
        assert_eq!(normalize_nonce("DEADBEEF").unwrap().0, "deadbeef");

        assert!(matches!(
            normalize_nonce(""),
            Err(TpmError::InvalidInput(_))
        ));
        assert!(matches!(
            normalize_nonce("abc"),
            Err(TpmError::InvalidInput(_))
        ));
        assert!(matches!(
            normalize_nonce("zz"),
            Err(TpmError::InvalidInput(_))
        ));
        assert!(matches!(
            normalize_nonce(&"ab".repeat(65)),
            Err(TpmError::InvalidInput(_))
        ));
    }

    #[test]
    fn request_requires_a_challenge() {
        let empty = QuoteTpmRequest::default();
        assert!(matches!(
            empty.resolved_nonce(),
            Err(TpmError::InvalidInput(_))
        ));

        let nonce = QuoteTpmRequest {
            nonce: Some("AABB".to_string()),
            ..Default::default()
        };
        assert_eq!(nonce.resolved_nonce().unwrap(), "aabb");

        let challenge = QuoteTpmRequest {
            challenge: Some("ccdd".to_string()),
            ..Default::default()
        };
        assert_eq!(challenge.resolved_nonce().unwrap(), "ccdd");

        let conflicting = QuoteTpmRequest {
            nonce: Some("aa".to_string()),
            challenge: Some("bb".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            conflicting.resolved_nonce(),
            Err(TpmError::InvalidInput(_))
        ));
    }

    #[test]
    fn an_unreachable_tpm_is_a_deployment_problem() {
        let config = TpmConfig::default();
        let stderr = b"WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, \
                       port 2321: errno 111: Connection refused\nERROR: Could not load tcti, got: \"mssim\"";

        let err = classify_failure(&config, "tpm2_startup", stderr);
        assert!(
            matches!(err, TpmError::NotImplemented(_)),
            "an unreachable TPM must map to 501, got {err:?}"
        );
        assert!(err.to_string().contains("not reachable"));
    }

    #[test]
    fn a_command_failure_is_an_internal_error() {
        let config = TpmConfig::default();
        let stderr =
            b"ERROR: Esys_PCR_Extend(0x1C3) - tpm:parameter(1):hash algorithm not supported";

        let err = classify_failure(&config, "tpm2_pcrextend", stderr);
        assert!(
            matches!(err, TpmError::Internal(_)),
            "a rejected command must map to 500, got {err:?}"
        );
    }

    #[test]
    fn the_config_pcr_selection_is_the_tpm2_tools_syntax() {
        let config = TpmConfig {
            pcr_index: 16,
            hash_algorithm: "sha256".to_string(),
            ..TpmConfig::default()
        };
        assert_eq!(config.pcr_selection(), "sha256:16");
    }

    #[test]
    fn timestamp_has_the_gpu_node_shape() {
        let stamp = utc_timestamp();
        assert_eq!(stamp.len(), 19, "unexpected timestamp {stamp:?}");
        assert_eq!(&stamp[4..5], ".");
        assert_eq!(&stamp[7..8], ".");
        assert_eq!(&stamp[10..11], " ");
    }
}
