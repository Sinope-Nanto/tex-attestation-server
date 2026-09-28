//! GPU attestation backend.
//!
//! This module adds *GPU* attestation next to the TDX attestation implemented in
//! [`crate::attestation`] and the TPM attestation implemented in [`crate::tpm`].
//!
//! The actual work is delegated to the vendor supplied script
//! `gpu-attest/gpu_local_attest.sh`, which drives the NVIDIA attestation SDK
//! (`gpu-attest/nvattest`) and prints a human readable attestation result. The
//! script is run as-is: this module never fabricates a result and never parses
//! the output into a boolean - the raw text the script produced is what the
//! caller receives.
//!
//! # Configuration
//!
//! | Variable            | Default                                    | Meaning                         |
//! |---------------------|--------------------------------------------|---------------------------------|
//! | `GPU_ATTEST_SCRIPT` | `<project>/gpu-attest/gpu_local_attest.sh` | script that produces the result |
//!
//! The script is executed with its own directory as the working directory, so a
//! relative `./nvattest` inside it resolves next to the script regardless of
//! where the service was started from.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rocket::serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Defaults and configuration names
// ---------------------------------------------------------------------------

/// Environment variable holding the path of the GPU attestation script.
pub const ENV_GPU_ATTEST_SCRIPT: &str = "GPU_ATTEST_SCRIPT";

/// Default location of the GPU attestation script, relative to the project root.
pub const DEFAULT_GPU_ATTEST_SCRIPT: &str = "gpu-attest/gpu_local_attest.sh";

/// The default GPU attestation script path.
///
/// The crate's own `gpu-attest/` directory: it always exists next to a build of
/// this service.
pub fn default_gpu_attest_script() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(DEFAULT_GPU_ATTEST_SCRIPT);
    path
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the GPU attestation backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuError {
    /// The backend cannot be used at all in this environment: the script is
    /// missing or not executable. Surfaces as `501`.
    NotImplemented(String),
    /// The script ran but failed. Surfaces as `500`.
    Internal(String),
}

impl fmt::Display for GpuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GpuError::NotImplemented(msg) => write!(f, "GPU attestation unavailable: {msg}"),
            GpuError::Internal(msg) => write!(f, "internal GPU attestation error: {msg}"),
        }
    }
}

impl std::error::Error for GpuError {}

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// Successful response of `GET /gpu-attestation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuAttestationResponse {
    /// The raw attestation result printed by the GPU attestation script.
    #[serde(rename = "gpu-attestation")]
    pub gpu_attestation: String,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Resolves the GPU attestation script path from the environment, falling back
/// to `<project root>/gpu-attest/gpu_local_attest.sh`.
pub fn gpu_attest_script_path() -> PathBuf {
    std::env::var_os(ENV_GPU_ATTEST_SCRIPT)
        .map(PathBuf::from)
        .unwrap_or_else(default_gpu_attest_script)
}

/// Runs the GPU attestation script and returns the text it produced.
///
/// Both the standard output and the standard error of the script are captured
/// and concatenated: the NVIDIA attestation SDK writes its report to stderr, so
/// dropping it would drop the attestation result itself.
///
/// * script missing / not executable -> [`GpuError::NotImplemented`] (`501`)
/// * script exits non-zero           -> [`GpuError::Internal`] (`500`)
/// * otherwise                       -> the combined output
pub fn gpu_attestation() -> Result<String, GpuError> {
    let script = gpu_attest_script_path();
    run_script(&script)
}

/// Runs `script` and returns its combined stdout + stderr.
fn run_script(script: &Path) -> Result<String, GpuError> {
    if !script.is_file() {
        return Err(GpuError::NotImplemented(format!(
            "the GPU attestation script `{}` was not found",
            script.display()
        )));
    }

    // Run the script from its own directory so a relative `./nvattest` inside it
    // resolves next to the script, no matter where the service was started.
    let working_dir = script.parent().unwrap_or_else(|| Path::new("."));

    // The script is a plain shell script (it carries no shebang), so it is run
    // through `sh` rather than executed directly.
    let output = match Command::new("sh")
        .arg(script)
        .current_dir(working_dir)
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(GpuError::NotImplemented(format!(
                "the GPU attestation script `{}` could not be executed: {err}",
                script.display()
            )));
        }
        Err(err) => {
            return Err(GpuError::Internal(format!(
                "the GPU attestation script `{}` could not be executed: {err}",
                script.display()
            )));
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The SDK writes the report to stderr; keep both streams, stdout first.
    let mut combined = String::new();
    combined.push_str(&stdout);
    combined.push_str(&stderr);

    if output.status.success() {
        return Ok(combined);
    }

    let detail = combined.trim();
    let detail = if detail.is_empty() {
        "no diagnostic output".to_string()
    } else {
        detail.to_string()
    };

    Err(GpuError::Internal(format!(
        "the GPU attestation script `{}` failed with {}: {detail}",
        script.display(),
        output.status
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_script_lives_next_to_the_project() {
        let path = default_gpu_attest_script();
        assert!(path.ends_with(DEFAULT_GPU_ATTEST_SCRIPT));
    }

    #[test]
    fn missing_script_is_not_implemented() {
        let err = run_script(Path::new("/no/such/gpu-attest.sh")).unwrap_err();
        assert!(matches!(err, GpuError::NotImplemented(_)));
    }

    #[test]
    fn response_serializes_with_the_expected_field_name() {
        let response = GpuAttestationResponse {
            gpu_attestation: "GPU attestation was successful".to_string(),
        };
        let json = serde_json::to_string(&response).expect("serializable");
        assert_eq!(
            json,
            r#"{"gpu-attestation":"GPU attestation was successful"}"#
        );
    }
}
