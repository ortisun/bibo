//! The per-job egress relay, shipped as a container image next to the sandbox image. It holds no
//! real credential.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("factory-egress-sidecar is not implemented yet.");
    ExitCode::FAILURE
}
