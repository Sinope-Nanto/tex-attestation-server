//! TDX attestation web service.
//!
//! A small [Rocket](https://rocket.rs) 0.5 service exposing three endpoints:
//!
//! * `GET  /ping`                                   - liveness probe (`pong`).
//! * `GET  /attestation-with-randomnumber?rn=<hex>` - generate a TDX report.
//! * `POST /verify-report`                          - verify a TDX report.
//!
//! The actual TDX work lives in [`attestation`]. Report generation uses the
//! upstream guest driver (`/dev/tdx_guest`); verification uses the
//! `TDG.MR.VERIFYREPORT` helper module (`/dev/tdx_verify`). When a device is
//! missing the corresponding route answers `501 Not Implemented` rather than
//! faking a result - no report is ever fabricated and no report is ever
//! reported as trusted without hardware verification.
//!
//! The Rocket instance is built by [`rocket`] so that tests can mount the very
//! same application with `rocket::local::blocking::Client`.

pub mod api;
pub mod attestation;
pub mod logging;
pub mod report;
pub mod tpm;

pub use api::{
    attestation_all, attestation_with_random_number, information_tpm, parse_report, ping,
    quote_tpm, verify_all, verify_report, ApiError, AttestationResponse, ErrorResponse,
    VerifyReportRequest, VerifyReportResponse,
};
pub use attestation::{
    generate_tdx_report, random_nonce, tdreport_reportdata, verify_tdx_report,
    verify_tdx_report_hardware, AttestationError, TDG_MR_VERIFYREPORT_LEAF, TDREPORT_LEN,
    TDREPORT_MAC_OFFSET, TDREPORT_REPORTDATA_OFFSET, TDX_GUEST_DEVICE, TDX_SUCCESS,
    TDX_VERIFY_DEVICE,
};
pub use report::{
    parse_tdreport, ParseReportRequest, ParseReportResponse, ReportMacStruct, TdInfo, TeeTcbInfo,
};
pub use tpm::{
    measure_folder, normalize_nonce, AttestationAllResponse, FolderMeasurement,
    InformationTpmResponse, MeasuredFile, QuoteTpmRequest, QuoteTpmResponse, TdxEvidence,
    TpmConfig, TpmError, TpmEvidence, TpmMeasurement, TpmState, VerifyAllResponse, BACKEND_NAME,
    DEFAULT_AK_HANDLE, DEFAULT_HASH_ALGORITHM, DEFAULT_PCR_INDEX, DEFAULT_SIMULATOR_DIR,
    DEFAULT_TCTI, ENV_AK_HANDLE, ENV_HASH_ALGORITHM, ENV_MEASURE_DIR, ENV_PCR_INDEX,
    ENV_SIMULATOR_DIR, ENV_TCTI, MAX_QUALIFYING_DATA_LEN, RC_MEASURE_FAIL, RC_QUOTE_FAIL,
    RC_REQUEST_ERROR, RC_SUCCESS,
};

use rocket::{Build, Rocket};

/// Builds the application.
///
/// Kept separate from `main` so that the integration tests can drive exactly
/// the same routes, and the same JSON catchers, through a local client.
///
/// The TPM backend is built here too (see [`tpm::TpmState`]). Its configuration
/// is read from the environment, never from the source, and the simulator is
/// only contacted when a TPM route is actually called - a host without a TPM
/// still serves the TDX routes.
///
/// # Examples
///
/// ```no_run
/// use rocket::local::blocking::Client;
///
/// let client = Client::tracked(tdx_attestation_server::rocket()).expect("valid rocket");
/// let response = client.get("/ping").dispatch();
/// assert_eq!(response.status().code, 200);
/// ```
pub fn rocket() -> Rocket<Build> {
    // File based audit log: requests, responses, errors and panics. Rocket owns
    // the console logger, so this is an independent sink (see `logging`).
    logging::init();

    let tpm_state = tpm::TpmState::from_env();

    // `/verify_all` receives a whole combined attestation structure: a 1024-byte
    // TDX report (2048 hex chars) plus the base64(hex(..)) TPM quote blobs, which
    // is well over Rocket's 8 KiB default `string` limit. Raise it so the
    // structure can be posted back verbatim; every other route is unaffected.
    let figment = rocket::Config::figment().merge(("limits.string", 2 * 1024 * 1024));

    rocket::custom(figment)
        .attach(logging::RequestLogger)
        .manage(tpm_state)
        .mount(
            "/",
            rocket::routes![
                ping,
                attestation_with_random_number,
                verify_report,
                parse_report,
                information_tpm,
                quote_tpm,
                attestation_all,
                verify_all
            ],
        )
        .register(
            "/",
            rocket::catchers![
                api::catch_bad_request,
                api::catch_not_found,
                api::catch_unprocessable_entity,
                api::catch_internal_server_error,
            ],
        )
}
