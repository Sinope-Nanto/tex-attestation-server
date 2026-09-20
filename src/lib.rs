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

pub use api::{
    attestation_with_random_number, ping, verify_report, ApiError, AttestationResponse,
    ErrorResponse, VerifyReportRequest, VerifyReportResponse,
};
pub use attestation::{
    generate_tdx_report, random_nonce, tdreport_reportdata, verify_tdx_report,
    verify_tdx_report_hardware, AttestationError, TDG_MR_VERIFYREPORT_LEAF, TDREPORT_LEN,
    TDREPORT_MAC_OFFSET, TDREPORT_REPORTDATA_OFFSET, TDX_GUEST_DEVICE, TDX_SUCCESS,
    TDX_VERIFY_DEVICE,
};

use rocket::{Build, Rocket};

/// Builds the application.
///
/// Kept separate from `main` so that the integration tests can drive exactly
/// the same routes, and the same JSON catchers, through a local client.
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
    rocket::build()
        .mount(
            "/",
            rocket::routes![ping, attestation_with_random_number, verify_report],
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
