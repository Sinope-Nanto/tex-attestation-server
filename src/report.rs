//! Human readable decoding of a TDX `TDREPORT`.
//!
//! A `TDREPORT` is a fixed 1024 byte binary structure produced by the TDX
//! module (`TDCALL[TDG.MR.REPORT]`). This module turns those raw bytes into a
//! JSON document that a human (or a log pipeline) can read, without ever
//! claiming anything about authenticity: decoding is a *parsing* operation
//! only. Whether a report is genuine is decided exclusively by
//! [`crate::attestation::verify_tdx_report`].
//!
//! # Layout
//!
//! The offsets below follow the Intel TDX Module ABI (`TDREPORT_STRUCT`):
//!
//! ```text
//! offset  size  field
//! 0x000   256   REPORTMACSTRUCT report_mac_struct
//! 0x100   239   TEE_TCB_INFO_STRUCT tee_tcb_info
//! 0x1EF    17   reserved
//! 0x200   512   TDINFO_STRUCT tdinfo
//! ```
//!
//! Inside `REPORTMACSTRUCT`:
//!
//! ```text
//! offset  size  field
//! 0x000   239   TEE_TCB_INFO_STRUCT tee_tcb_info
//! 0x0EF    17   reserved
//! 0x100   512   TDINFO_STRUCT tdinfo
//! 0x300   256   reserved2
//! ```
//!
//! The `REPORTDATA` (64 bytes at `0x80`) and the `MAC` (32 bytes at `0xE0`)
//! live inside `REPORTMACSTRUCT` and are covered by the MAC.

use rocket::serde::{Deserialize, Serialize};

use crate::attestation::{
    AttestationError, TDREPORT_LEN, TDREPORT_MAC_LEN, TDREPORT_MAC_OFFSET,
    TDREPORT_REPORTDATA_OFFSET, REPORTDATA_LEN,
};

// ---------------------------------------------------------------------------
// Offsets of the TDREPORT_STRUCT fields (Intel TDX Module ABI).
// ---------------------------------------------------------------------------

/// `TDREPORT_STRUCT.TEE_TCB_INFO` - 239 bytes.
const TEE_TCB_INFO_OFFSET: usize = 0x100;

/// `TDREPORT_STRUCT.TDINFO` - 512 bytes.
const TDINFO_OFFSET: usize = 0x200;

/// `TEE_TCB_INFO_STRUCT` fields (relative to `TEE_TCB_INFO_OFFSET`).
const TEE_TCB_INFO_VALID_OFFSET: usize = 0;
const TEE_TCB_INFO_TEE_TCB_SVN_OFFSET: usize = 8;
const TEE_TCB_INFO_TEE_TCB_SVN_LEN: usize = 16;
const TEE_TCB_INFO_TEE_TCB_HASH_OFFSET: usize = 24;

/// `TDINFO_STRUCT` fields (relative to `TDINFO_OFFSET`).
const TDINFO_ATTRIBUTES_OFFSET: usize = 0;
const TDINFO_XFAM_OFFSET: usize = 8;
const TDINFO_MRTD_OFFSET: usize = 16;
const TDINFO_MRTD_LEN: usize = 48;
const TDINFO_MRCONFIGID_OFFSET: usize = 64;
const TDINFO_MRCONFIGID_LEN: usize = 48;
const TDINFO_MROWNER_OFFSET: usize = 112;
const TDINFO_MROWNER_LEN: usize = 48;
const TDINFO_MROWNERCONFIG_OFFSET: usize = 160;
const TDINFO_MROWNERCONFIG_LEN: usize = 48;
const TDINFO_RTMR0_OFFSET: usize = 208;
const TDINFO_RTMR0_LEN: usize = 48;
const TDINFO_RTMR1_OFFSET: usize = 256;
const TDINFO_RTMR1_LEN: usize = 48;
const TDINFO_RTMR2_OFFSET: usize = 304;
const TDINFO_RTMR2_LEN: usize = 48;
const TDINFO_RTMR3_OFFSET: usize = 352;
const TDINFO_RTMR3_LEN: usize = 48;
const TDINFO_SERVTD_HASH_OFFSET: usize = 400;
const TDINFO_SERVTD_HASH_LEN: usize = 48;

// ---------------------------------------------------------------------------
// JSON payloads
// ---------------------------------------------------------------------------

/// Request body of `POST /parse-report`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseReportRequest {
    /// The TDX report to decode, hex encoded (2048 hex chars for 1024 bytes).
    pub report: String,
}

/// `REPORTMACSTRUCT` of a decoded `TDREPORT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportMacStruct {
    /// `REPORTDATA` - the 64 byte nonce the report is bound to, hex encoded.
    pub report_data: String,
    /// `MAC` - the 32 byte MAC over `REPORTMACSTRUCT`, hex encoded.
    pub mac: String,
}

/// `TEE_TCB_INFO_STRUCT` of a decoded `TDREPORT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeTcbInfo {
    /// `VALID` - bitmask of which fields below are valid.
    pub valid: u64,
    /// `TEE_TCB_SVN` - the TCB security version numbers, hex encoded.
    pub tee_tcb_svn: String,
    /// `MRSEAM` - the SEAM module measurement, hex encoded.
    pub mrseam: String,
    /// `MRSIGNERSEAM` - the SEAM module signer, hex encoded.
    pub mrsignerseam: String,
    /// `SEAMATTRIBUTES` - the SEAM module attributes.
    pub seamattributes: u64,
    /// `TDATTRIBUTES` - the TD attributes.
    pub tdattributes: u64,
    /// `XFD` - the extended features disabled bitmap.
    pub xfd: u64,
}

/// `TDINFO_STRUCT` of a decoded `TDREPORT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdInfo {
    /// `ATTRIBUTES` - the TD attributes.
    pub attributes: u64,
    /// `XFAM` - the extended features available bitmap.
    pub xfam: u64,
    /// `MRTD` - the initial TD measurement, hex encoded.
    pub mrtd: String,
    /// `MRCONFIGID` - the TD configuration measurement, hex encoded.
    pub mrconfigid: String,
    /// `MROWNER` - the TD owner measurement, hex encoded.
    pub mrowner: String,
    /// `MROWNERCONFIG` - the TD owner configuration measurement, hex encoded.
    pub mrownerconfig: String,
    /// `RTMR0` - runtime measurement register 0, hex encoded.
    pub rtmr0: String,
    /// `RTMR1` - runtime measurement register 1, hex encoded.
    pub rtmr1: String,
    /// `RTMR2` - runtime measurement register 2, hex encoded.
    pub rtmr2: String,
    /// `RTMR3` - runtime measurement register 3, hex encoded.
    pub rtmr3: String,
    /// `SERVTD_HASH` - the service TD hash, hex encoded.
    pub servtd_hash: String,
}

/// Successful response of `POST /parse-report`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseReportResponse {
    /// Length of the decoded report in bytes (always 1024).
    pub report_len: usize,
    /// `REPORTMACSTRUCT`.
    pub report_mac_struct: ReportMacStruct,
    /// `TEE_TCB_INFO`.
    pub tee_tcb_info: TeeTcbInfo,
    /// `TDINFO`.
    pub tdinfo: TdInfo,
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Reads a little-endian `u64` at `offset`.
fn read_u64(report: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&report[offset..offset + 8]);
    u64::from_le_bytes(buf)
}

/// Hex-encodes `len` bytes starting at `offset`.
fn read_hex(report: &[u8], offset: usize, len: usize) -> String {
    hex::encode(&report[offset..offset + len])
}

/// Decodes a raw `TDREPORT` into its human readable JSON representation.
///
/// This is a pure parsing operation: it never verifies the report and never
/// claims it is authentic. Use
/// [`crate::attestation::verify_tdx_report`] for that.
///
/// # Errors
///
/// * [`AttestationError::InvalidInput`] - `report` is not exactly 1024 bytes.
pub fn parse_tdreport(report: &[u8]) -> Result<ParseReportResponse, AttestationError> {
    if report.len() != TDREPORT_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "report is {} bytes, expected {TDREPORT_LEN}",
            report.len()
        )));
    }

    // --- REPORTMACSTRUCT ---------------------------------------------------
    let report_mac_struct = ReportMacStruct {
        report_data: read_hex(report, TDREPORT_REPORTDATA_OFFSET, REPORTDATA_LEN),
        mac: read_hex(report, TDREPORT_MAC_OFFSET, TDREPORT_MAC_LEN),
    };

    // --- TEE_TCB_INFO ------------------------------------------------------
    let tcb = TEE_TCB_INFO_OFFSET;
    let tee_tcb_info = TeeTcbInfo {
        valid: read_u64(report, tcb + TEE_TCB_INFO_VALID_OFFSET),
        tee_tcb_svn: read_hex(
            report,
            tcb + TEE_TCB_INFO_TEE_TCB_SVN_OFFSET,
            TEE_TCB_INFO_TEE_TCB_SVN_LEN,
        ),
        mrseam: read_hex(report, tcb + TEE_TCB_INFO_TEE_TCB_HASH_OFFSET, 48),
        mrsignerseam: read_hex(report, tcb + TEE_TCB_INFO_TEE_TCB_HASH_OFFSET + 48, 48),
        seamattributes: read_u64(report, tcb + TEE_TCB_INFO_TEE_TCB_HASH_OFFSET + 96),
        tdattributes: read_u64(report, tcb + TEE_TCB_INFO_TEE_TCB_HASH_OFFSET + 104),
        xfd: read_u64(report, tcb + TEE_TCB_INFO_TEE_TCB_HASH_OFFSET + 112),
    };

    // --- TDINFO ------------------------------------------------------------
    let td = TDINFO_OFFSET;
    let tdinfo = TdInfo {
        attributes: read_u64(report, td + TDINFO_ATTRIBUTES_OFFSET),
        xfam: read_u64(report, td + TDINFO_XFAM_OFFSET),
        mrtd: read_hex(report, td + TDINFO_MRTD_OFFSET, TDINFO_MRTD_LEN),
        mrconfigid: read_hex(report, td + TDINFO_MRCONFIGID_OFFSET, TDINFO_MRCONFIGID_LEN),
        mrowner: read_hex(report, td + TDINFO_MROWNER_OFFSET, TDINFO_MROWNER_LEN),
        mrownerconfig: read_hex(
            report,
            td + TDINFO_MROWNERCONFIG_OFFSET,
            TDINFO_MROWNERCONFIG_LEN,
        ),
        rtmr0: read_hex(report, td + TDINFO_RTMR0_OFFSET, TDINFO_RTMR0_LEN),
        rtmr1: read_hex(report, td + TDINFO_RTMR1_OFFSET, TDINFO_RTMR1_LEN),
        rtmr2: read_hex(report, td + TDINFO_RTMR2_OFFSET, TDINFO_RTMR2_LEN),
        rtmr3: read_hex(report, td + TDINFO_RTMR3_OFFSET, TDINFO_RTMR3_LEN),
        servtd_hash: read_hex(
            report,
            td + TDINFO_SERVTD_HASH_OFFSET,
            TDINFO_SERVTD_HASH_LEN,
        ),
    };

    Ok(ParseReportResponse {
        report_len: report.len(),
        report_mac_struct,
        tee_tcb_info,
        tdinfo,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zeroed report decodes without error and reports the right length.
    #[test]
    fn parses_zeroed_report() {
        let report = vec![0u8; TDREPORT_LEN];
        let parsed = parse_tdreport(&report).expect("parse");
        assert_eq!(parsed.report_len, TDREPORT_LEN);
        assert_eq!(parsed.report_mac_struct.report_data.len(), REPORTDATA_LEN * 2);
        assert_eq!(parsed.report_mac_struct.mac.len(), TDREPORT_MAC_LEN * 2);
        assert_eq!(parsed.tdinfo.mrtd.len(), TDINFO_MRTD_LEN * 2);
    }

    /// The REPORTDATA field is echoed at the documented offset.
    #[test]
    fn report_data_is_read_from_offset_0x80() {
        let mut report = vec![0u8; TDREPORT_LEN];
        for (i, b) in report[TDREPORT_REPORTDATA_OFFSET..TDREPORT_REPORTDATA_OFFSET + REPORTDATA_LEN]
            .iter_mut()
            .enumerate()
        {
            *b = i as u8;
        }
        let parsed = parse_tdreport(&report).expect("parse");
        let expected: String = (0..REPORTDATA_LEN).map(|i| format!("{i:02x}")).collect();
        assert_eq!(parsed.report_mac_struct.report_data, expected);
    }

    /// A report of the wrong size is rejected.
    #[test]
    fn rejects_wrong_length() {
        let err = parse_tdreport(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, AttestationError::InvalidInput(_)), "got {err:?}");
    }
}
