//! HTTP layer: routes, request payloads, error responses and catchers.
//!
//! | Method | Path                                 | Success         | Failure       |
//! |--------|--------------------------------------|-----------------|---------------|
//! | `GET`  | `/ping`                              | `200 pong`      | -             |
//! | `GET`  | `/attestation-with-randomnumber?rn=` | `200 {report}`  | `400` / `501` |
//! | `POST` | `/verify-report`                     | `200 {trusted}` | `400` / `501` |
//! | `POST` | `/parse-report`                      | `200 {parsed}`  | `400`         |
//! | `GET`  | `/information_tpm`                   | `200 {info}`    | `400` / `501` |
//! | `POST` | `/quote_tpm`                         | `200 {quote}`   | `400` / `501` |
//!
//! The two `*_tpm` routes talk to a TPM 2.0 device (the simulator in
//! `tpm-simu/`) through [`crate::tpm`]; they never interfere with the TDX routes
//! above.

use std::fmt;

use rocket::catch;
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{get, post, State};

use crate::attestation::{generate_tdx_report, verify_tdx_report, AttestationError};
use crate::report::{parse_tdreport, ParseReportRequest, ParseReportResponse};
use crate::tpm::{
    self, InformationTpmResponse, QuoteTpmRequest, QuoteTpmResponse, TpmError, TpmState,
};

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

/// Successful response of `GET /attestation-with-randomnumber`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// The TDX report, hex encoded.
    pub report: String,
}

/// Request body of `POST /verify-report`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReportRequest {
    /// The TDX report to verify, hex encoded.
    pub report: String,
}

/// Successful response of `POST /verify-report`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReportResponse {
    /// Whether the report is trusted. Only ever set from the real verifier.
    pub trusted: bool,
}

/// Body returned for every error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Human readable description of the failure.
    pub error: String,
}

impl ErrorResponse {
    fn new(message: impl Into<String>) -> Self {
        Self {
            error: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// An HTTP error that can be returned from a route handler.
///
/// Handlers never panic: every failure path is expressed as an `ApiError`,
/// which renders a JSON body plus the matching status code.
#[derive(Debug, Clone)]
pub struct ApiError {
    status: Status,
    message: String,
}

impl ApiError {
    /// Creates an error with an explicit status code.
    pub fn new(status: Status, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// `400 Bad Request` - the caller sent something malformed.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(Status::BadRequest, message)
    }

    /// The HTTP status this error is rendered with.
    pub fn status(&self) -> Status {
        self.status
    }

    /// The human readable message this error is rendered with.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<AttestationError> for ApiError {
    fn from(err: AttestationError) -> Self {
        match err {
            // No TDX backend in this environment -> 501, never a fake report.
            AttestationError::NotImplemented => Self::new(
                Status::NotImplemented,
                "TDX attestation is not implemented on this host",
            ),
            AttestationError::InvalidInput(msg) => Self::new(Status::BadRequest, msg),
            AttestationError::Internal(msg) => Self::new(Status::InternalServerError, msg),
        }
    }
}

impl From<TpmError> for ApiError {
    fn from(err: TpmError) -> Self {
        match err {
            // No TPM backend reachable -> 501, never a fabricated measurement.
            TpmError::NotImplemented(msg) => Self::new(Status::NotImplemented, msg),
            TpmError::InvalidInput(msg) => Self::new(Status::BadRequest, msg),
            TpmError::Internal(msg) => Self::new(Status::InternalServerError, msg),
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}

impl std::error::Error for ApiError {}

impl<'r> Responder<'r, 'static> for ApiError {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        let body = Json(ErrorResponse::new(self.message));
        (self.status, body).respond_to(req)
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `GET /ping` - liveness probe.
///
/// Always answers `200 OK` with the plain-text body `pong`.
#[get("/ping")]
pub fn ping() -> &'static str {
    "pong"
}

/// `GET /attestation-with-randomnumber?rn=<hex>`
///
/// `rn` is the hex encoded random number (nonce) that the report must be bound
/// to. It is decoded and handed to [`generate_tdx_report`].
///
/// * missing `rn`         -> `400 Bad Request`
/// * non-hexadecimal `rn` -> `400 Bad Request`
/// * well-formed `rn`     -> `200 { "report": "<hex>" }` once the TDX backend
///   exists, `501 Not Implemented` until then.
#[get("/attestation-with-randomnumber?<rn>")]
pub fn attestation_with_random_number(
    rn: Option<String>,
) -> Result<Json<AttestationResponse>, ApiError> {
    let rn = rn.ok_or_else(|| ApiError::bad_request("missing query parameter 'rn'"))?;

    // `rn` is only required to be a valid hex string. No fixed byte length is
    // enforced here: the byte-length/zero-padding rules belong to the future
    // REPORTDATA binding inside `generate_tdx_report`.
    let random_number = hex::decode(&rn)
        .map_err(|err| ApiError::bad_request(format!("'rn' is not a valid hex string: {err}")))?;

    let report = generate_tdx_report(&random_number)?;
    Ok(Json(AttestationResponse {
        report: hex::encode(report),
    }))
}

/// `POST /verify-report`
///
/// Request body: `{ "report": "<hex>" }`.
///
/// The body is read as text so that a missing or mismatched `Content-Type`
/// header yields a friendly `400` instead of a routing `404`.
///
/// * unreadable / non-JSON body -> `400 Bad Request`
/// * `report` not hex           -> `400 Bad Request`
/// * well-formed request        -> `200 { "trusted": bool }` once the TDX
///   verifier exists, `501 Not Implemented` until then.
#[post("/verify-report", data = "<body>")]
pub fn verify_report(
    body: Result<String, std::io::Error>,
) -> Result<Json<VerifyReportResponse>, ApiError> {
    let body = body.map_err(|err| ApiError::bad_request(format!("could not read body: {err}")))?;

    let request: VerifyReportRequest = serde_json::from_str(&body)
        .map_err(|err| ApiError::bad_request(format!("invalid JSON body: {err}")))?;

    let report = hex::decode(&request.report).map_err(|err| {
        ApiError::bad_request(format!("'report' is not a valid hex string: {err}"))
    })?;

    let trusted = verify_tdx_report(&report)?;
    Ok(Json(VerifyReportResponse { trusted }))
}

/// `POST /parse-report`
///
/// Request body: `{ "report": "<hex>" }`.
///
/// Decodes a hex encoded `TDREPORT` into a human readable JSON document. This
/// is a *parsing* endpoint: it never verifies the report and never claims it
/// is authentic. Use `POST /verify-report` for that.
///
/// * unreadable / non-JSON body -> `400 Bad Request`
/// * `report` not hex           -> `400 Bad Request`
/// * `report` not 1024 bytes    -> `400 Bad Request`
/// * well-formed request        -> `200 { ...decoded fields... }`
#[post("/parse-report", data = "<body>")]
pub fn parse_report(
    body: Result<String, std::io::Error>,
) -> Result<Json<ParseReportResponse>, ApiError> {
    let body = body.map_err(|err| ApiError::bad_request(format!("could not read body: {err}")))?;

    let request: ParseReportRequest = serde_json::from_str(&body)
        .map_err(|err| ApiError::bad_request(format!("invalid JSON body: {err}")))?;

    let report = hex::decode(&request.report).map_err(|err| {
        ApiError::bad_request(format!("'report' is not a valid hex string: {err}"))
    })?;

    let parsed = parse_tdreport(&report)?;
    Ok(Json(parsed))
}

// ---------------------------------------------------------------------------
// TPM routes
// ---------------------------------------------------------------------------

/// `GET /information_tpm`
///
/// Measures the configured directory (`TPM_MEASURE_DIR`, default: `src/`),
/// extends the configured PCR (`TPM_PCR_INDEX`, default: `16`) with the folder
/// digest, reads the PCR back and returns the measurement, the PCR value and
/// the TPM information.
///
/// * missing / unreadable directory   -> `500 Internal Server Error`
/// * simulator not reachable          -> `501 Not Implemented`
/// * otherwise                        -> `200 { ... }`
///
/// Nothing is fabricated: both the PCR value and every digest come from the TPM
/// and from the filesystem respectively.
#[get("/information_tpm")]
pub fn information_tpm(state: &State<TpmState>) -> Result<Json<InformationTpmResponse>, ApiError> {
    let response = tpm::information_tpm(state.inner())?;
    Ok(Json(response))
}

/// `POST /quote_tpm`
///
/// Request body (`gpu-node` compatible):
///
/// ```json
/// { "nonce": "<hex>", "nonce_size": 32, "mask": "..." }
/// ```
///
/// `challenge` is accepted as an alias of `nonce`; `nonce_size` and `mask` are
/// accepted and ignored (the PCR is configured server side).
///
/// Runs the same measurement and PCR cycle as `/information_tpm` and then asks
/// the TPM for a quote over the same PCR, with the challenge bound as
/// `qualifyingData`. The response carries the real `TPMT_SIGNATURE` and
/// `TPMS_ATTEST` produced by the TPM.
///
/// * unreadable / non-JSON body        -> `400 Bad Request`
/// * missing / non-hex / oversized     -> `400 Bad Request`
/// * simulator not reachable           -> `501 Not Implemented`
/// * otherwise                         -> `200 { ... }`
#[post("/quote_tpm", data = "<body>")]
pub fn quote_tpm(
    state: &State<TpmState>,
    body: Result<String, std::io::Error>,
) -> Result<Json<QuoteTpmResponse>, ApiError> {
    let body = body.map_err(|err| ApiError::bad_request(format!("could not read body: {err}")))?;

    let request: QuoteTpmRequest = serde_json::from_str(&body)
        .map_err(|err| ApiError::bad_request(format!("invalid JSON body: {err}")))?;

    let nonce = request.resolved_nonce()?;
    let response = tpm::quote_tpm(state.inner(), &nonce)?;
    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Catchers
// ---------------------------------------------------------------------------
//
// Requests that never reach a route (malformed URI, unknown path, unparsable
// query string, panic) are answered with the same JSON envelope as the
// handlers instead of Rocket's default HTML page.

/// `400` - the request could not be parsed at the HTTP level.
#[catch(400)]
pub fn catch_bad_request() -> (Status, Json<ErrorResponse>) {
    (
        Status::BadRequest,
        Json(ErrorResponse::new(
            "the request could not be understood (malformed syntax)",
        )),
    )
}

/// `404` - no route matched the request.
#[catch(404)]
pub fn catch_not_found() -> (Status, Json<ErrorResponse>) {
    (
        Status::NotFound,
        Json(ErrorResponse::new("resource not found")),
    )
}

/// `422` - a route matched but its parameters could not be parsed.
#[catch(422)]
pub fn catch_unprocessable_entity() -> (Status, Json<ErrorResponse>) {
    (
        Status::UnprocessableEntity,
        Json(ErrorResponse::new(
            "the request parameters could not be processed",
        )),
    )
}

/// `500` - an unexpected internal failure.
#[catch(500)]
pub fn catch_internal_server_error() -> (Status, Json<ErrorResponse>) {
    (
        Status::InternalServerError,
        Json(ErrorResponse::new("internal server error")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_implemented_maps_to_501() {
        let err: ApiError = AttestationError::NotImplemented.into();
        assert_eq!(err.status(), Status::NotImplemented);
    }

    #[test]
    fn invalid_input_maps_to_400() {
        let err: ApiError = AttestationError::InvalidInput("nope".into()).into();
        assert_eq!(err.status(), Status::BadRequest);
        assert_eq!(err.message(), "nope");
    }

    #[test]
    fn internal_maps_to_500() {
        let err: ApiError = AttestationError::Internal("boom".into()).into();
        assert_eq!(err.status(), Status::InternalServerError);
    }

    #[test]
    fn tpm_not_implemented_maps_to_501() {
        let err: ApiError = TpmError::NotImplemented("no simulator".into()).into();
        assert_eq!(err.status(), Status::NotImplemented);
        assert_eq!(err.message(), "no simulator");
    }

    #[test]
    fn tpm_invalid_input_maps_to_400() {
        let err: ApiError = TpmError::InvalidInput("bad nonce".into()).into();
        assert_eq!(err.status(), Status::BadRequest);
        assert_eq!(err.message(), "bad nonce");
    }

    #[test]
    fn tpm_internal_maps_to_500() {
        let err: ApiError = TpmError::Internal("boom".into()).into();
        assert_eq!(err.status(), Status::InternalServerError);
    }
}
