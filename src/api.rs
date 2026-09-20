//! HTTP layer: routes, request payloads, error responses and catchers.
//!
//! | Method | Path                                 | Success         | Failure       |
//! |--------|--------------------------------------|-----------------|---------------|
//! | `GET`  | `/ping`                              | `200 pong`      | -             |
//! | `GET`  | `/attestation-with-randomnumber?rn=` | `200 {report}`  | `400` / `501` |
//! | `POST` | `/verify-report`                     | `200 {trusted}` | `400` / `501` |
//! | `POST` | `/parse-report`                      | `200 {parsed}`  | `400`         |

use std::fmt;

use rocket::catch;
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::{self, Responder};
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{get, post};

use crate::attestation::{generate_tdx_report, verify_tdx_report, AttestationError};
use crate::report::{parse_tdreport, ParseReportRequest, ParseReportResponse};

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
}
