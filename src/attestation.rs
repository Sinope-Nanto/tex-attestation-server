//! TDX attestation core - the two operations that need real TDX hardware.
//!
//! # Design
//!
//! Both operations sit on top of two character devices:
//!
//! | operation               | device            | kernel path                            |
//! |-------------------------|-------------------|----------------------------------------|
//! | [`generate_tdx_report`] | `/dev/tdx_guest`  | `TDX_CMD_GET_REPORT0` -> `TDG.MR.REPORT` |
//! | [`verify_tdx_report`]   | `/dev/tdx_verify` | `TDX_VERIFY_REPORT` -> `TDG.MR.VERIFYREPORT` |
//!
//! ## Generation
//!
//! `/dev/tdx_guest` is the upstream kernel driver. It accepts a 64-byte
//! `REPORTDATA` and returns a 1024-byte `TDREPORT` produced by the TDX module
//! through `TDCALL[TDG.MR.REPORT]`.
//!
//! ## Verification - and why it needs a helper module
//!
//! The upstream driver deliberately exposes *no* way to run
//! `TDCALL[TDG.MR.VERIFYREPORT]` (TDX module leaf 22), which is the only
//! *local* operation that can prove a `TDREPORT` genuinely came from the TDX
//! module: the module recomputes the MAC over `REPORTMACSTRUCT` with its own
//! key and compares.
//!
//! Two facts rule out every shortcut:
//!
//! * `TDCALL` is a CPL0 instruction - from ring 3 it raises `#GP`, so no
//!   userspace trick can reach it.
//! * Re-hashing the report (`SHA384` over `TEE_TCB_INFO` / `TDINFO`), checking
//!   `REPORTDATA`, or asserting `reserved == 0` are **structural consistency
//!   checks** only. Anyone fabricating a report can recompute those hashes, so
//!   they prove nothing about authenticity.
//!
//! The `tdx_verify` kernel module (see `kmod/`) therefore does exactly one
//! thing: it runs leaf 22 in ring 0 and hands the raw return code back. A
//! return code of `TDX_SUCCESS` (0) means "the TDX module confirms this
//! `REPORTMACSTRUCT` is authentic"; anything else means it is not. It never
//! degrades into a software hash comparison.
//!
//! If `/dev/tdx_verify` is absent the verifier reports
//! [`AttestationError::NotImplemented`] - it never guesses, and it never
//! returns `Ok(true)` for an unverified report.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;

/// Length of the `REPORTDATA` field feeding `TDG.MR.REPORT`. Fixed by the ABI.
pub const REPORTDATA_LEN: usize = 64;

/// Length of a `TDREPORT` as produced by `TDG.MR.REPORT`. Fixed by the ABI.
pub const TDREPORT_LEN: usize = 1024;

/// Offset of `REPORTMACSTRUCT.REPORTDATA` inside `TDREPORT_STRUCT`.
pub const TDREPORT_REPORTDATA_OFFSET: usize = 0x80;

/// Offset of `REPORTMACSTRUCT.MAC` inside `TDREPORT_STRUCT` (32 bytes).
pub const TDREPORT_MAC_OFFSET: usize = 0xE0;

/// Size of the MAC that protects `REPORTMACSTRUCT`.
pub const TDREPORT_MAC_LEN: usize = 32;

/// Path of the upstream TDX guest driver (report generation).
pub const TDX_GUEST_DEVICE: &str = "/dev/tdx_guest";

/// Path of the helper module exposing `TDG.MR.VERIFYREPORT`.
pub const TDX_VERIFY_DEVICE: &str = "/dev/tdx_verify";

/// TDX module call leaf for `TDG.MR.VERIFYREPORT` (TDX 1.5).
pub const TDG_MR_VERIFYREPORT_LEAF: u64 = 22;

/// `TDX_SUCCESS` - the TDX module verified the report's MAC.
pub const TDX_SUCCESS: u64 = 0;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the attestation backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The requested capability is not available in this build/environment.
    ///
    /// Used when the required device node is missing, i.e. the hardware or
    /// the helper module is not there. Surfaces on the wire as
    /// `501 Not Implemented`.
    NotImplemented,
    /// The caller supplied data that the backend cannot work with
    /// (wrong length, malformed report, ...).
    ///
    /// Surfaces on the wire as `400 Bad Request`.
    InvalidInput(String),
    /// The backend failed for an internal reason (I/O, driver error, ...).
    ///
    /// Surfaces on the wire as `500 Internal Server Error`.
    Internal(String),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttestationError::NotImplemented => {
                write!(f, "TDX attestation is not implemented in this environment")
            }
            AttestationError::InvalidInput(msg) => write!(f, "invalid attestation input: {msg}"),
            AttestationError::Internal(msg) => write!(f, "internal attestation error: {msg}"),
        }
    }
}

impl std::error::Error for AttestationError {}

// ---------------------------------------------------------------------------
// ioctl plumbing
// ---------------------------------------------------------------------------

// `_IOC` encoding from <asm-generic/ioctl.h>:
//   dir << 30 | size << 16 | type << 8 | nr
const IOC_NRBITS: u64 = 8;
const IOC_TYPEBITS: u64 = 8;
const IOC_SIZEBITS: u64 = 14;
const IOC_NRSHIFT: u64 = 0;
const IOC_TYPESHIFT: u64 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u64 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u64 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_READ: u64 = 2;
const IOC_WRITE: u64 = 1;

const fn ioc(dir: u64, ty: u64, nr: u64, size: u64) -> u64 {
    (dir << IOC_DIRSHIFT) | (size << IOC_SIZESHIFT) | (ty << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT)
}

/// `TDX_CMD_GET_REPORT0` - `_IOWR('T', 1, struct tdx_report_req)`.
const TDX_CMD_GET_REPORT0: u64 = ioc(
    IOC_READ | IOC_WRITE,
    b'T' as u64,
    1,
    (REPORTDATA_LEN + TDREPORT_LEN) as u64,
);

/// `TDX_VERIFY_REPORT` - `_IOWR('T', 2, struct tdx_verify_request)`.
const TDX_VERIFY_REPORT: u64 = ioc(
    IOC_READ | IOC_WRITE,
    b'T' as u64,
    2,
    (TDREPORT_LEN + std::mem::size_of::<u64>()) as u64,
);

/// Request of `TDX_CMD_GET_REPORT0`. Mirrors `struct tdx_report_req`.
#[repr(C)]
struct TdxReportReq {
    reportdata: [u8; REPORTDATA_LEN],
    tdreport: [u8; TDREPORT_LEN],
}

/// Request/response of `TDX_VERIFY_REPORT`. Mirrors `struct tdx_verify_request`.
#[repr(C)]
struct TdxVerifyReq {
    report: [u8; TDREPORT_LEN],
    status: u64,
}

fn ioctl(fd: i32, request: u64, arg: *mut std::ffi::c_void) -> std::io::Result<i32> {
    // SAFETY: `fd` is an open file descriptor, `request` is a request number
    // built by `ioc()` and `arg` points at a correctly laid out, live struct.
    let rc = unsafe { libc::ioctl(fd, request as libc::c_ulong, arg) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Opens a device, mapping "does not exist" onto [`AttestationError::NotImplemented`].
fn open_device(path: &str) -> Result<File, AttestationError> {
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => Ok(f),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(AttestationError::NotImplemented)
        }
        Err(err) => Err(AttestationError::Internal(format!(
            "cannot open {path}: {err}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Builds the 64-byte `REPORTDATA` from a caller supplied nonce.
///
/// Shorter nonces are zero-padded; anything longer than 64 bytes cannot be
/// bound to a report and is rejected.
fn report_data_from(nonce: &[u8]) -> Result<[u8; REPORTDATA_LEN], AttestationError> {
    if nonce.len() > REPORTDATA_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "random number is {} bytes, but REPORTDATA holds at most {REPORTDATA_LEN}",
            nonce.len()
        )));
    }

    let mut reportdata = [0u8; REPORTDATA_LEN];
    reportdata[..nonce.len()].copy_from_slice(nonce);
    Ok(reportdata)
}

/// Generates a TDX TDREPORT whose `REPORTDATA` field is seeded with
/// `random_number`.
///
/// `random_number` is the caller provided nonce; it is zero-padded to the
/// fixed 64-byte `REPORTDATA` field, so a verifier can later confirm that the
/// report was freshly produced for this challenge.
///
/// The report is produced by the TDX module through the upstream guest driver
/// (`/dev/tdx_guest`), so the returned bytes carry a genuine
/// `REPORTMACSTRUCT.MAC`.
///
/// # Errors
///
/// * [`AttestationError::InvalidInput`] - `random_number` is longer than 64 bytes.
/// * [`AttestationError::NotImplemented`] - `/dev/tdx_guest` is unavailable.
/// * [`AttestationError::Internal`] - the device exists but the TDCALL failed.
pub fn generate_tdx_report(random_number: &[u8]) -> Result<Vec<u8>, AttestationError> {
    let reportdata = report_data_from(random_number)?;
    let file = open_device(TDX_GUEST_DEVICE)?;

    let mut req = TdxReportReq {
        reportdata,
        tdreport: [0u8; TDREPORT_LEN],
    };

    ioctl(
        file.as_raw_fd(),
        TDX_CMD_GET_REPORT0,
        &mut req as *mut TdxReportReq as *mut std::ffi::c_void,
    )
    .map_err(|err| {
        AttestationError::Internal(format!(
            "TDCALL[TDG.MR.REPORT] failed via {TDX_GUEST_DEVICE}: {err}"
        ))
    })?;

    Ok(req.tdreport.to_vec())
}

/// Returns the `REPORTDATA` embedded in a `TDREPORT`.
///
/// This is a *parsing* helper. The bytes it returns are covered by the report
/// MAC, but reading them proves nothing on their own - see
/// [`verify_tdx_report_hardware`].
pub fn tdreport_reportdata(report: &[u8]) -> Result<&[u8], AttestationError> {
    if report.len() != TDREPORT_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "report is {} bytes, expected {TDREPORT_LEN}",
            report.len()
        )));
    }
    Ok(&report[TDREPORT_REPORTDATA_OFFSET..TDREPORT_REPORTDATA_OFFSET + REPORTDATA_LEN])
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verifies a TDREPORT with the TDX module itself -
/// `TDCALL[TDG.MR.VERIFYREPORT]`.
///
/// This is the only *local* check that establishes authenticity: the TDX
/// module recomputes the MAC over `REPORTMACSTRUCT` using the key it holds and
/// compares it with the one carried in the report. A fabricated report cannot
/// pass, because the attacker has no access to that key.
///
/// # Return value
///
/// * `Ok(0)` - `TDX_SUCCESS`: the TDX module confirmed the report's MAC.
/// * `Ok(status)` - non-zero: the TDX module rejected the report. `status` is
///   its raw error code (e.g. `0xc000100100000000`, "MAC verification failed").
/// * `Err(..)` - the check could not be performed at all.
///
/// # Errors
///
/// * [`AttestationError::InvalidInput`] - `report` is not exactly 1024 bytes.
/// * [`AttestationError::NotImplemented`] - `/dev/tdx_verify` is unavailable,
///   i.e. the helper module is not loaded. The caller must *not* treat this as
///   a successful verification.
/// * [`AttestationError::Internal`] - the ioctl itself failed.
pub fn verify_tdx_report_hardware(report: &[u8]) -> Result<u64, AttestationError> {
    if report.len() != TDREPORT_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "report is {} bytes, expected {TDREPORT_LEN}",
            report.len()
        )));
    }

    let file = open_device(TDX_VERIFY_DEVICE)?;

    let mut req = TdxVerifyReq {
        report: [0u8; TDREPORT_LEN],
        status: u64::MAX,
    };
    req.report.copy_from_slice(report);

    ioctl(
        file.as_raw_fd(),
        TDX_VERIFY_REPORT,
        &mut req as *mut TdxVerifyReq as *mut std::ffi::c_void,
    )
    .map_err(|err| {
        AttestationError::Internal(format!(
            "TDCALL[TDG.MR.VERIFYREPORT] (leaf {TDG_MR_VERIFYREPORT_LEAF}) failed via {TDX_VERIFY_DEVICE}: {err}"
        ))
    })?;

    Ok(req.status)
}

/// Verifies a TDX report previously produced by [`generate_tdx_report`].
///
/// Delegates to [`verify_tdx_report_hardware`] and maps its result onto a
/// boolean:
///
/// * `Ok(true)`  - the TDX module accepted the report's MAC.
/// * `Ok(false)` - the report is well-formed but the TDX module rejected it
///   (tampered, or not produced by this TDX module).
/// * `Err(..)`   - the check could not be performed; in particular
///   [`AttestationError::NotImplemented`] must never be read as "trusted".
///
/// # Errors
///
/// See [`verify_tdx_report_hardware`].
pub fn verify_tdx_report(report: &[u8]) -> Result<bool, AttestationError> {
    Ok(verify_tdx_report_hardware(report)? == TDX_SUCCESS)
}

// ---------------------------------------------------------------------------
// Nonce helper
// ---------------------------------------------------------------------------

/// Reads `n` bytes from the kernel CSPRNG (`/dev/urandom`).
pub fn random_nonce(n: usize) -> Result<Vec<u8>, AttestationError> {
    let mut buf = vec![0u8; n];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|err| AttestationError::Internal(format!("cannot read /dev/urandom: {err}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test below needs the real TDX module.
    fn require_hardware() {
        assert!(
            std::path::Path::new(TDX_GUEST_DEVICE).exists(),
            "{TDX_GUEST_DEVICE} is missing: these tests require a TDX guest"
        );
        assert!(
            std::path::Path::new(TDX_VERIFY_DEVICE).exists(),
            "{TDX_VERIFY_DEVICE} is missing: run the module load step first. \
             The tests refuse to pass without hardware verification."
        );
    }

    /// Test 1: a fresh report is 1024 bytes and echoes the 64-byte REPORTDATA.
    #[test]
    fn get_report_success() {
        require_hardware();

        let nonce = random_nonce(REPORTDATA_LEN).expect("random nonce");
        let report = generate_tdx_report(&nonce).expect("generate_tdx_report");

        assert_eq!(report.len(), TDREPORT_LEN, "TDREPORT must be 1024 bytes");

        let echoed = tdreport_reportdata(&report).expect("parse report");
        assert_eq!(
            echoed,
            &nonce[..],
            "TDREPORT.REPORTDATA must echo the input"
        );
        println!(
            "get_report_success: size={} REPORTDATA echoed",
            report.len()
        );
    }

    /// A nonce shorter than 64 bytes is zero-padded, not rejected.
    #[test]
    fn get_report_zero_pads_short_nonce() {
        require_hardware();

        let nonce = vec![0xABu8; 16];
        let report = generate_tdx_report(&nonce).expect("generate_tdx_report");
        let echoed = tdreport_reportdata(&report).expect("parse report");

        assert_eq!(&echoed[..16], &nonce[..]);
        assert!(
            echoed[16..].iter().all(|b| *b == 0),
            "the remaining bytes must be zero padding"
        );
    }

    /// A nonce that cannot fit in REPORTDATA is a client error.
    #[test]
    fn get_report_rejects_oversized_nonce() {
        let err = generate_tdx_report(&vec![0u8; REPORTDATA_LEN + 1]).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidInput(_)),
            "got {err:?}"
        );
    }

    /// Test 2: a freshly generated report must be verified by the TDX module.
    #[test]
    fn verify_fresh_report_success() {
        require_hardware();

        let nonce = random_nonce(REPORTDATA_LEN).expect("random nonce");
        let report = generate_tdx_report(&nonce).expect("generate_tdx_report");

        let status = verify_tdx_report_hardware(&report).expect("hardware verify");
        println!("backend=TDG.MR.VERIFYREPORT leaf={TDG_MR_VERIFYREPORT_LEAF}");
        println!("fresh report verification: status=0x{status:x}");

        assert_eq!(
            status, TDX_SUCCESS,
            "the TDX module rejected a fresh report"
        );
        assert!(verify_tdx_report(&report).unwrap());
        println!("fresh report verification: PASS");
    }

    /// Test 3: flipping a single bit inside REPORTMACSTRUCT must be detected.
    ///
    /// This is the test that separates real hardware verification from a
    /// software hash comparison: only the TDX-module-held MAC key can tell a
    /// pristine report from a tampered one.
    #[test]
    fn verify_tampered_report_fails() {
        require_hardware();

        let nonce = random_nonce(REPORTDATA_LEN).expect("random nonce");
        let report = generate_tdx_report(&nonce).expect("generate_tdx_report");

        // (a) tamper with REPORTDATA (covered by the MAC).
        let mut tampered = report.clone();
        tampered[TDREPORT_REPORTDATA_OFFSET] ^= 0x01;

        let status = verify_tdx_report_hardware(&tampered).expect("hardware verify");
        println!("tampered REPORTDATA: status=0x{status:x}");
        assert_ne!(status, TDX_SUCCESS, "a tampered REPORTDATA was accepted");
        assert!(!verify_tdx_report(&tampered).unwrap());

        // (b) tamper with the MAC itself.
        let mut tampered_mac = report.clone();
        tampered_mac[TDREPORT_MAC_OFFSET] ^= 0x01;

        let status = verify_tdx_report_hardware(&tampered_mac).expect("hardware verify");
        println!("tampered MAC: status=0x{status:x}");
        assert_ne!(status, TDX_SUCCESS, "a tampered MAC was accepted");

        // (c) the pristine report still verifies.
        assert_eq!(
            verify_tdx_report_hardware(&report).expect("hardware verify"),
            TDX_SUCCESS
        );
    }

    /// A report of the wrong size can never be verified.
    #[test]
    fn verify_rejects_wrong_length() {
        let err = verify_tdx_report_hardware(&[0u8; 16]).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidInput(_)),
            "got {err:?}"
        );

        let err = verify_tdx_report(&[]).unwrap_err();
        assert!(
            matches!(err, AttestationError::InvalidInput(_)),
            "got {err:?}"
        );
    }

    /// Different nonces must yield different, still verifiable reports.
    #[test]
    fn two_reports_for_different_nonces_differ() {
        require_hardware();

        let a = generate_tdx_report(&random_nonce(REPORTDATA_LEN).unwrap()).unwrap();
        let b = generate_tdx_report(&random_nonce(REPORTDATA_LEN).unwrap()).unwrap();

        assert_ne!(
            tdreport_reportdata(&a).unwrap(),
            tdreport_reportdata(&b).unwrap(),
            "different nonces must produce different REPORTDATA"
        );
        assert_eq!(verify_tdx_report_hardware(&a).unwrap(), TDX_SUCCESS);
        assert_eq!(verify_tdx_report_hardware(&b).unwrap(), TDX_SUCCESS);
    }

    #[test]
    fn error_display_is_human_readable() {
        assert!(AttestationError::NotImplemented
            .to_string()
            .contains("not implemented"));
        assert_eq!(
            AttestationError::InvalidInput("boom".into()).to_string(),
            "invalid attestation input: boom"
        );
        assert_eq!(
            AttestationError::Internal("boom".into()).to_string(),
            "internal attestation error: boom"
        );
    }
}
