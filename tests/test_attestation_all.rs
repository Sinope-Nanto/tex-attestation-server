//! Integration tests for the combined `/attestation_all` and `/verify_all`
//! routes.
//!
//! These tests drive the real Rocket application through a local client. They
//! deliberately cover only the paths that do **not** need a TPM or TDX hardware:
//! request validation and the shape of the error envelope. The happy path (a
//! real TPM quote plus a real TDX report, and their verification) is exercised
//! end-to-end by `tests/test_tpm_web.sh` against a running service.
//!
//! Nothing here fabricates a quote or a report: a request that would need
//! hardware is expected to answer `501` when the backend is absent, never a
//! made-up `200`.

use rocket::http::{ContentType, Status};
use rocket::local::blocking::Client;

use tdx_attestation_server::rocket;

/// A malformed body must be a `400` with the shared JSON error envelope.
fn assert_bad_request(client: &Client, uri: &str, body: &str) {
    let response = client
        .post(uri)
        .header(ContentType::JSON)
        .body(body)
        .dispatch();

    assert_eq!(
        response.status(),
        Status::BadRequest,
        "POST {uri} with {body:?} should be a 400"
    );

    let payload: serde_json::Value = response.into_json().expect("JSON error envelope");
    assert!(
        payload.get("error").and_then(|v| v.as_str()).is_some(),
        "the error envelope must carry an 'error' string: {payload}"
    );
}

#[test]
fn attestation_all_rejects_a_missing_nonce() {
    let client = Client::tracked(rocket()).expect("valid rocket");
    assert_bad_request(&client, "/attestation_all", "{}");
}

#[test]
fn attestation_all_rejects_a_non_hex_nonce() {
    let client = Client::tracked(rocket()).expect("valid rocket");
    assert_bad_request(&client, "/attestation_all", r#"{"nonce":"nothex"}"#);
}

#[test]
fn attestation_all_rejects_a_malformed_body() {
    let client = Client::tracked(rocket()).expect("valid rocket");
    assert_bad_request(&client, "/attestation_all", "this-is-not-json");
}

#[test]
fn verify_all_rejects_a_malformed_body() {
    let client = Client::tracked(rocket()).expect("valid rocket");
    assert_bad_request(&client, "/verify_all", "this-is-not-json");
}

/// A structure without the `tdx` field cannot be verified: it is a client
/// error, not a silent `trusted=false`.
#[test]
fn verify_all_rejects_a_structure_without_tdx() {
    let client = Client::tracked(rocket()).expect("valid rocket");

    let body = r#"{
        "status": 0,
        "measurement": {"time-stamp": "2024.01.01 00:00:00", "measurement": [], "total_hash": "00"},
        "pcr_value": "00",
        "pcr_index": 16,
        "hash_algorithm": "sha256",
        "evidence": {"tpm": {
            "quote": "a:b:c", "quote_size": 5,
            "signature": "", "message": "", "pcrs": "",
            "signature_size": 0, "message_size": 0,
            "nonce": "aabb", "nonce_size": 2,
            "pcr_index": 16, "hash_algorithm": "sha256",
            "ak_handle": "0x81010002"
        }},
        "ak_pubkey": ""
    }"#;

    assert_bad_request(&client, "/verify_all", body);
}

/// A non-hex TDX report is a client error too.
#[test]
fn verify_all_rejects_a_non_hex_tdx_report() {
    let client = Client::tracked(rocket()).expect("valid rocket");

    let body = r#"{
        "status": 0,
        "measurement": {"time-stamp": "2024.01.01 00:00:00", "measurement": [], "total_hash": "00"},
        "pcr_value": "00",
        "pcr_index": 16,
        "hash_algorithm": "sha256",
        "evidence": {
            "tpm": {
                "quote": "a:b:c", "quote_size": 5,
                "signature": "", "message": "", "pcrs": "",
                "signature_size": 0, "message_size": 0,
                "nonce": "aabb", "nonce_size": 2,
                "pcr_index": 16, "hash_algorithm": "sha256",
                "ak_handle": "0x81010002"
            },
            "tdx": {"report": "nothex", "nonce": "aabb", "nonce_size": 2}
        },
        "ak_pubkey": ""
    }"#;

    assert_bad_request(&client, "/verify_all", body);
}
