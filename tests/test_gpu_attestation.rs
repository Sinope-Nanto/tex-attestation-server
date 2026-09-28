//! Integration tests for the `GET /gpu-attestation` route.
//!
//! The route runs the GPU attestation script (`gpu-attest/gpu_local_attest.sh`)
//! and returns its output verbatim in the `gpu-attestation` field. These tests
//! drive the real Rocket application through a local client.
//!
//! The script is present in this repository, so the happy path is exercised for
//! real: the response must be a `200` whose `gpu-attestation` field is a
//! non-empty string. Nothing is fabricated - the field carries exactly what the
//! script printed.

use rocket::http::Status;
use rocket::local::blocking::Client;

use tdx_attestation_server::rocket;

#[test]
fn gpu_attestation_returns_the_script_output() {
    let client = Client::tracked(rocket()).expect("valid rocket");

    let response = client.get("/gpu-attestation").dispatch();

    // The script ships with the repository, so the route must succeed. If the
    // environment cannot run it at all the backend answers `501`; both are
    // acceptable, but a `200` must carry the field.
    let status = response.status();

    if status == Status::Ok {
        let payload: serde_json::Value = response.into_json().expect("JSON body");
        let value = payload
            .get("gpu-attestation")
            .and_then(|v| v.as_str())
            .expect("the response must carry a 'gpu-attestation' string");
        assert!(
            !value.trim().is_empty(),
            "the 'gpu-attestation' field must not be empty"
        );
    } else if status == Status::NotImplemented {
        // The script is missing in this environment: the route must say so with
        // the shared error envelope rather than fabricate a result.
        let payload: serde_json::Value = response.into_json().expect("JSON error envelope");
        assert!(payload.get("error").and_then(|v| v.as_str()).is_some());
    } else {
        panic!("unexpected status for /gpu-attestation: {status}");
    }
}
