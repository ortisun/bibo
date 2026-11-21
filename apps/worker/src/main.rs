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
use factory_composition::design_gate::FileDesignGatePolicy;
use factory_composition::health::CheckStatus;
use factory_composition::issue_status::StatusStep;
use factory_composition::system::{Shutdown, raise_on_termination};
use factory_worker::boot::boot;
use factory_worker::pipeline::{
    assemble_loop, external_ports, issue_status, knowledge_measurements, project_rules,
    pull_request_fates, token_sweep,
};
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
        // The design gate is a control, not a label: when its rule cannot be read, intake refuses
        // every issue (it never guesses), so the worker says so now, and the stage says it again
        // each time it refuses one. The worker still starts: jobs that are past intake go on.
        let gate = FileDesignGatePolicy::new(config.protected_checkout.clone()).health_check();
        if gate.status != CheckStatus::Pass {
            eprintln!(
                "factory-worker: NOT READY: {}: {}",
                gate.name, gate.detail
            );
        }
        let shutdown = Shutdown::new();
        tokio::spawn(raise_on_termination(shutdown.clone()));
        let mut sweep: Vec<_> = token_sweep(&booted, &config, &world).into_iter().collect();
        // After the sweep, so that the sweep runs first; the step writes on issues from a task of
        // its own and never holds up a claim.
        match issue_status(&booted, &config, &world) {
            Ok(step) => {
                // A step whose policy cannot be used writes nothing and says so; the worker goes on.
                if step.as_ref().is_some_and(StatusStep::is_off) {
                    eprintln!(
                        "factory-worker: DEGRADED: the issue status step is off and writes nothing on any issue; jobs are not affected"
                    );
                }
                sweep.extend(step.map(|step| step.hook()));
            }
            Err(error) => {
                eprintln!("factory-worker: the issue status step cannot be built: {error}");
                booted.broker.shutdown();
                return ExitCode::from(1);
            }
        }
        // The rules check (ADR 0026): before each claim, and told about every register and enable.
        let rules = match project_rules(&booted, &config, &world) {
            Ok(rules) => rules,
            Err(error) => {
                eprintln!("factory-worker: the project rules check cannot be built: {error}");
                booted.broker.shutdown();
                return ExitCode::from(1);
            }
        };
        if let Some(rules) = &rules {
            sweep.push(rules.clone());
        }
        // The fate of the pull requests the factory opened (ADR 0029): before each claim.
        match pull_request_fates(&booted, &config, &world) {
            Ok(Some(fates)) => sweep.push(fates),
            Ok(None) => {}
            Err(error) => {
                eprintln!("factory-worker: the pull request step cannot be built: {error}");
                booted.broker.shutdown();
                return ExitCode::from(1);
            }
        }
        // The weekly measurement (ADR 0029, ADR 0031): before each claim, once an hour a tenant.
        match knowledge_measurements(&booted, &config, &world) {
            Ok(Some(weekly)) => sweep.push(weekly),
            Ok(None) => {}
            Err(error) => {
                eprintln!("factory-worker: the weekly measurement step cannot be built: {error}");
                booted.broker.shutdown();
                return ExitCode::from(1);
            }
        }
        let (worker_loop, pipeline) =
            match assemble_loop(&booted, &config, world.ports, sweep, shutdown) {
                Ok(assembled) => assembled,
                Err(error) => {
                    eprintln!("factory-worker: the pipeline cannot be assembled: {error}");
                    booted.broker.shutdown();
                    return ExitCode::from(1);
                }
            };
        if let Some(rules) = rules {
            pipeline.repository_changes.tell_when_onboarded(rules);
        }
        let summary = worker_loop.run().await;
        booted.broker.shutdown();
        ExitCode::from(exit_code(&summary))
    })
}
