//! The worker: runs the engine loop in one process, claiming work, running stage handlers, sweeping
//! leases and deadlines, and hosting the model broker listener.
//!
//! ```text
//! FACTORY_CONFIG=/etc/factory/worker.yaml factory-worker
//! ```
//!
//! Exit codes: 0 a clean stop, 1 an engine error or a start-up check that failed, 2 bad
//! configuration, 3 BLOCKED (something the configuration does not supply; one `BLOCKED:` line for
//! each, on standard error, starting with the configuration key), 4 an attempt was abandoned at the
//! end of the drain budget.

use std::process::ExitCode;
use std::sync::Arc;

use factory_composition::config::FactoryConfig;
use factory_composition::system::{Shutdown, raise_on_termination};
use factory_worker::boot::boot;
use factory_worker::pipeline::{assemble_loop, external_ports, token_sweep};
use factory_worker::run::exit_code;

fn main() -> ExitCode {
    let config = match FactoryConfig::from_environment(|name| std::env::var(name).ok()) {
        Ok(config) => Arc::new(config),
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
        let booted = match boot(&config).await {
            Ok(booted) => booted,
            Err(error) => {
                eprintln!("factory-worker: start-up check failed: {error}");
                return ExitCode::from(1);
            }
        };
        // Every check that needs no outside service passed. The ports that reach the outside
        // world are built from the configuration; what it does not supply is listed, one line for
        // each, starting with the key to write, and the process stops here.
        let world = match external_ports(&booted, &config).await {
            Ok(world) => world,
            Err(missing) => {
                for item in &missing {
                    eprintln!("BLOCKED: {item}");
                }
                eprintln!(
                    "BLOCKED is not a pass: the start-up checks passed, and no job was claimed."
                );
                booted.broker.shutdown();
                return ExitCode::from(3);
            }
        };
        let shutdown = Shutdown::new();
        tokio::spawn(raise_on_termination(shutdown.clone()));
        let sweep = token_sweep(&booted, &config, &world).into_iter().collect();
        let (worker_loop, _pipeline) =
            match assemble_loop(&booted, &config, world.ports, sweep, shutdown) {
                Ok(assembled) => assembled,
                Err(error) => {
                    eprintln!("factory-worker: the pipeline cannot be assembled: {error}");
                    booted.broker.shutdown();
                    return ExitCode::from(1);
                }
            };
        let summary = worker_loop.run().await;
        booted.broker.shutdown();
        ExitCode::from(exit_code(&summary))
    })
}
