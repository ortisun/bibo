//! The worker: runs the engine loop in one process, claiming work, running stage handlers, sweeping
//! leases and deadlines, and supervising sandboxes.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("factory-worker is not implemented yet.");
    ExitCode::FAILURE
}
