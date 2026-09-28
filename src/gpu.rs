//! GPU attestation backend.
//!
//! This module adds *GPU* attestation next to the TDX attestation implemented in
//! [`crate::attestation`] and the TPM attestation implemented in [`crate::tpm`].
//!
//! The actual work is delegated to the vendor supplied script
//! `gpu-attest/gpu_local_attest.sh`, which drives the NVIDIA attestation SDK
//! (`gpu-attest/nvattest`) and prints a human readable attestation result. The
//! script is run as-is: this module never fabricates a result. The text the
//! script produced is parsed into a structured JSON document (see
//! [`GpuAttestation`]) so that callers get machine readable fields instead of a
//! blob of text.
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

use std::collections::BTreeMap;
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

/// One certificate chain reported for a device.
///
/// The NVIDIA attestation SDK prints three of these per device (the attestation
/// report chain and the driver / VBIOS RIM chains). Every field is optional
/// because the SDK may omit a line for a given chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuCertChain {
    /// `Status:` of the chain, e.g. `valid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// `OCSP:` result of the chain, e.g. `good`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocsp: Option<String>,
    /// `Expires:` timestamp of the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// A single GPU reported by the attestation script.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuDevice {
    /// The device index as printed (`Device 0` -> `0`).
    pub index: u32,
    /// `Device Type:` - e.g. `gpu`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    /// `Hardware Model:` - e.g. `GH100 A01 GSP BROM`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_model: Option<String>,
    /// `UEID:` - the unique device identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ueid: Option<String>,
    /// `VBIOS Version:`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vbios_version: Option<String>,
    /// `Driver Version:`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    /// `Measurement Result:` - e.g. `success`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement_result: Option<String>,
    /// The certificate chains, keyed by their printed name (e.g.
    /// `Attestation Report Cert Chain`).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub cert_chains: BTreeMap<String, GpuCertChain>,
}

/// The parsed GPU attestation result.
///
/// This is the structured form of the text the NVIDIA attestation SDK prints.
/// Nothing is fabricated: every field is copied from the script output, and a
/// field the script did not print is simply absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuAttestation {
    /// Whether the script reported overall success (`GPU attestation was
    /// successful`).
    pub successful: bool,
    /// The trailing summary line, when the script printed one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// The devices the script reported.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<GpuDevice>,
}

/// Successful response of `GET /gpu-attestation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuAttestationResponse {
    /// The parsed attestation result.
    #[serde(rename = "gpu-attestation")]
    pub gpu_attestation: GpuAttestation,
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

/// Runs the GPU attestation script and returns the parsed result.
///
/// Both the standard output and the standard error of the script are captured
/// and concatenated: the NVIDIA attestation SDK writes its report to stderr, so
/// dropping it would drop the attestation result itself. The combined text is
/// then parsed by [`parse_gpu_attestation`].
///
/// * script missing / not executable -> [`GpuError::NotImplemented`] (`501`)
/// * script exits non-zero           -> [`GpuError::Internal`] (`500`)
/// * otherwise                       -> the parsed [`GpuAttestation`]
pub fn gpu_attestation() -> Result<GpuAttestation, GpuError> {
    let script = gpu_attest_script_path();
    let text = run_script(&script)?;
    Ok(parse_gpu_attestation(&text))
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

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parses the text printed by the NVIDIA attestation SDK into a
/// [`GpuAttestation`].
///
/// The parser is deliberately tolerant: it recognises the `key: value` lines the
/// SDK prints, groups them under the `Device <n>:` header they belong to, and
/// treats any other non-empty line as the trailing summary. A line it does not
/// understand is ignored rather than turned into an error, so a future SDK that
/// adds a field keeps working.
pub fn parse_gpu_attestation(text: &str) -> GpuAttestation {
    let mut result = GpuAttestation::default();
    let mut current: Option<GpuDevice> = None;
    // Name of the certificate chain the following `Status:`/`OCSP:`/`Expires:`
    // lines belong to, if any.
    let mut current_chain: Option<String> = None;

    for raw_line in text.lines() {
        let trimmed = raw_line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // `- Device 0:` starts a new device.
        if let Some(rest) = trimmed.strip_prefix("- Device ") {
            if let Some(device) = current.take() {
                result.devices.push(device);
            }
            let index = rest
                .trim_end_matches(':')
                .trim()
                .parse::<u32>()
                .unwrap_or(result.devices.len() as u32);
            current = Some(GpuDevice {
                index,
                ..GpuDevice::default()
            });
            current_chain = None;
            continue;
        }

        // A `key: value` line.
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            let value = value.trim().to_string();

            // A certificate chain header ends with `Cert Chain` and carries no
            // value of its own.
            if key.ends_with("Cert Chain") {
                current_chain = Some(key.to_string());
                if let Some(device) = current.as_mut() {
                    device.cert_chains.entry(key.to_string()).or_default();
                }
                continue;
            }

            // `Status:` / `OCSP:` / `Expires:` belong to the current chain.
            if let Some(chain) = current_chain.clone() {
                if let Some(device) = current.as_mut() {
                    if let Some(entry) = device.cert_chains.get_mut(&chain) {
                        match key {
                            "Status" => {
                                // `Status: valid, OCSP: good` - split the OCSP
                                // part out of the status value.
                                let (status, ocsp) = split_status_ocsp(&value);
                                entry.status = Some(status);
                                if let Some(ocsp) = ocsp {
                                    entry.ocsp = Some(ocsp);
                                }
                                continue;
                            }
                            "OCSP" => {
                                entry.ocsp = Some(value);
                                continue;
                            }
                            "Expires" => {
                                entry.expires = Some(value);
                                continue;
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Device level fields.
            if let Some(device) = current.as_mut() {
                match key {
                    "Device Type" => {
                        device.device_type = Some(value);
                        continue;
                    }
                    "Hardware Model" => {
                        device.hardware_model = Some(value);
                        continue;
                    }
                    "UEID" => {
                        device.ueid = Some(value);
                        continue;
                    }
                    "VBIOS Version" => {
                        device.vbios_version = Some(value);
                        continue;
                    }
                    "Driver Version" => {
                        device.driver_version = Some(value);
                        continue;
                    }
                    "Measurement Result" => {
                        device.measurement_result = Some(value);
                        continue;
                    }
                    _ => {}
                }
            }

            // Anything else is a summary line (e.g. `GPU attestation was
            // successful`).
            result.summary = Some(trimmed.to_string());
            continue;
        }

        // A line without a colon: the trailing summary.
        result.summary = Some(trimmed.to_string());
    }

    if let Some(device) = current.take() {
        result.devices.push(device);
    }

    result.successful = result
        .summary
        .as_deref()
        .map(|summary| summary.to_ascii_lowercase().contains("successful"))
        .unwrap_or(false);

    result
}

/// Splits a `Status: valid, OCSP: good` value into its status and (optional)
/// OCSP parts.
fn split_status_ocsp(value: &str) -> (String, Option<String>) {
    match value.split_once(',') {
        Some((status, rest)) => {
            let status = status.trim().to_string();
            let ocsp = rest
                .trim()
                .strip_prefix("OCSP:")
                .map(|ocsp| ocsp.trim().to_string());
            (status, ocsp)
        }
        None => (value.trim().to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
2026-09-28 07:19:00.105 [info] Attesting GPUs
Devices:
- Device 0:
    Device Type: gpu
    Hardware Model: GH100 A01 GSP BROM
    UEID: 430665101512341769483002607463286621189533065990
    VBIOS Version: 96.00.CF.00.05
    Driver Version: 595.71.05
    Measurement Result: success
    Attestation Report Cert Chain:
        Status: valid, OCSP: good
        Expires: 9999-12-31T23:59:59Z
    Driver RIM Cert Chain:
        Status: valid, OCSP: good
        Expires: 2028-04-23T05:42:57Z
    VBIOS RIM Cert Chain:
        Status: valid, OCSP: good
        Expires: 2027-02-03T19:23:30Z

GPU attestation was successful
";

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
    fn parses_the_sample_output() {
        let parsed = parse_gpu_attestation(SAMPLE);

        assert!(parsed.successful);
        assert_eq!(
            parsed.summary.as_deref(),
            Some("GPU attestation was successful")
        );
        assert_eq!(parsed.devices.len(), 1);

        let device = &parsed.devices[0];
        assert_eq!(device.index, 0);
        assert_eq!(device.device_type.as_deref(), Some("gpu"));
        assert_eq!(device.hardware_model.as_deref(), Some("GH100 A01 GSP BROM"));
        assert_eq!(
            device.ueid.as_deref(),
            Some("430665101512341769483002607463286621189533065990")
        );
        assert_eq!(device.vbios_version.as_deref(), Some("96.00.CF.00.05"));
        assert_eq!(device.driver_version.as_deref(), Some("595.71.05"));
        assert_eq!(device.measurement_result.as_deref(), Some("success"));

        let chain = device
            .cert_chains
            .get("Attestation Report Cert Chain")
            .expect("attestation report chain");
        assert_eq!(chain.status.as_deref(), Some("valid"));
        assert_eq!(chain.ocsp.as_deref(), Some("good"));
        assert_eq!(chain.expires.as_deref(), Some("9999-12-31T23:59:59Z"));

        assert!(device.cert_chains.contains_key("Driver RIM Cert Chain"));
        assert!(device.cert_chains.contains_key("VBIOS RIM Cert Chain"));
    }

    #[test]
    fn parses_multiple_devices() {
        let text = "\
- Device 0:
    Device Type: gpu
    Measurement Result: success
- Device 1:
    Device Type: gpu
    Measurement Result: success

GPU attestation was successful
";
        let parsed = parse_gpu_attestation(text);
        assert_eq!(parsed.devices.len(), 2);
        assert_eq!(parsed.devices[0].index, 0);
        assert_eq!(parsed.devices[1].index, 1);
        assert!(parsed.successful);
    }

    #[test]
    fn failure_output_is_not_successful() {
        let parsed = parse_gpu_attestation("GPU attestation failed\n");
        assert!(!parsed.successful);
        assert_eq!(parsed.summary.as_deref(), Some("GPU attestation failed"));
        assert!(parsed.devices.is_empty());
    }

    #[test]
    fn response_serializes_with_the_expected_field_name() {
        let response = GpuAttestationResponse {
            gpu_attestation: GpuAttestation {
                successful: true,
                summary: Some("GPU attestation was successful".to_string()),
                devices: vec![],
            },
        };
        let json = serde_json::to_string(&response).expect("serializable");
        assert_eq!(
            json,
            r#"{"gpu-attestation":{"successful":true,"summary":"GPU attestation was successful"}}"#
        );
    }
}
