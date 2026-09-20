//! Binary entry point.
//!
//! The application itself is assembled in the library crate (`rocket()`), so
//! the tests exercise the exact same route table.

#[rocket::launch]
fn rocket() -> _ {
    tdx_attestation_server::rocket()
}
