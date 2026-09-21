//! Prints the [`tdx_attestation_server::tpm::measure_folder`] digest of a
//! directory.
//!
//! ```console
//! $ cargo run --example measure_folder -- ./src
//! <64 hex chars>
//! ```
//!
//! It exists so that the shell level tests can obtain the *exact* digest the
//! server computes, without reimplementing the algorithm in a second language.

use std::path::PathBuf;
use std::process::ExitCode;

use tdx_attestation_server::tpm::measure_folder;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: measure_folder <directory>");
        return ExitCode::from(2);
    };
    let dir = PathBuf::from(dir);

    match measure_folder(&dir) {
        Ok(measurement) => {
            println!("{}", measurement.total_hash);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("measurement of {} failed: {err}", dir.display());
            ExitCode::FAILURE
        }
    }
}
