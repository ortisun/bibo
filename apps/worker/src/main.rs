//! The worker: runs the engine loop in one process, claiming work, running stage handlers, sweeping
//! leases and deadlines, and hosting the model broker listener.
//!
//! ```text
//! FACTORY_CONFIG=/etc/factory/worker.yaml factory-worker
//! ```
//!
//! Exit codes: 0 a clean stop, 1 an engine error or a start-up check that failed, 2 bad
//! configuration, 3 BLOCKED (an adapter this build cannot assemble; one `BLOCKED:` line for each,
//! on standard error), 4 an attempt was abandoned at the end of the drain budget.

use std::process::ExitCode;

use factory_worker::assemble::{blocked_adapters, prepare};
use factory_worker::config::FactoryConfig;

fn main() -> ExitCode {
    let config = match FactoryConfig::from_environment(|name| std::env::var(name).ok()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("factory-worker: {error}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("factory-worker: the runtime cannot start: {error}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(async move {
        let prepared = match prepare(&config).await {
            Ok(prepared) => prepared,
            Err(error) => {
                eprintln!("factory-worker: start-up check failed: {error}");
                return ExitCode::from(1);
            }
        };
        // Every check that needs no credential passed. The adapters that do are not assembled in
        // this part of the work package, so the process stops here and says which.
        let blocked = blocked_adapters(config.profile);
        if !blocked.is_empty() {
            for item in &blocked {
                eprintln!("BLOCKED: {}: {}", item.port.label(), item.reason);
            }
            eprintln!("BLOCKED is not a pass: the start-up checks passed, and no job was claimed.");
            prepared.broker.shutdown();
            return ExitCode::from(3);
        }
        prepared.broker.shutdown();
        ExitCode::SUCCESS
    })
}
