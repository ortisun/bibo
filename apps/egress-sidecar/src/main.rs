//! The per-job egress relay, shipped as a container image next to the sandbox image. It holds no
//! real credential.
//!
//! The logic is in `factory_egress::relay` (so its tests run with the broker's); this file only
//! reads the command line, starts the relay and stays alive. It fails closed: a command line it
//! does not understand, or a listener that does not bind, ends the program with a non-zero code
//! before it has accepted a connection.
//!
//! Exit codes: 2 for a command line that is not accepted, 1 when the listener cannot bind.
//! Decisions and the `ready` line go to standard output, one JSON object per line. A refusal to
//! start is written to standard error without any value from the command line.
//!
//! Signals: the supervisor starts the container with `--init`, so SIGTERM reaches this program as
//! a process that is not PID 1 and ends it at once, well inside the 10 seconds of `--stop-timeout`.

use std::process::ExitCode;
use std::sync::Arc;

use factory_egress::relay::{Relay, RelayConfig, StdoutLog, SystemResolver, TcpConnector};

fn main() -> ExitCode {
    let mut args = Vec::new();
    for arg in std::env::args_os().skip(1) {
        match arg.into_string() {
            Ok(text) => args.push(text),
            Err(_) => {
                eprintln!("factory-egress-sidecar: an argument is not text");
                return ExitCode::from(2);
            }
        }
    }
    let config = match RelayConfig::from_args(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("factory-egress-sidecar: {error}");
            return ExitCode::from(2);
        }
    };
    let relay = Relay::new(
        config,
        Arc::new(SystemResolver),
        Arc::new(TcpConnector),
        Arc::new(StdoutLog),
    );
    match relay.start() {
        Ok(handle) => {
            handle.wait();
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("factory-egress-sidecar: the listener could not be started");
            ExitCode::from(1)
        }
    }
}
