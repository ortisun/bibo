//! The troubleshooter: watches the factory itself and files issues for a person (ADR 0021).
//!
//! ```text
//! factory-troubleshooter --config /etc/factory/troubleshooter.yaml [--once] [--sweep-now] [--dry-run]
//! ```
//!
//! * `--config PATH` the configuration file (required).
//! * `--once` one pass (probes, and an agent run when one is due), then exit.
//! * `--sweep-now` start the slow sweep in the first pass, whatever the schedule says.
//! * `--dry-run` everything but writing to GitHub: the decisions are printed instead.
//!
//! Exit codes: 0 a clean stop, 1 a pass or a start-up check failed, 2 bad usage or configuration,
//! 4 `--once` and another troubleshooter is active (this one did nothing).

use std::path::PathBuf;
use std::process::ExitCode;

use factory_composition::system::{Shutdown, raise_on_termination};
use factory_troubleshooter::boot::boot;
use factory_troubleshooter::config::TroubleshooterConfig;
use factory_troubleshooter::scheduler::{Activation, activate, run_loop};
use factory_troubleshooter::troubleshooter::{IssueAction, PassOptions, PassReport};

const USAGE: &str =
    "usage: factory-troubleshooter --config PATH [--once] [--sweep-now] [--dry-run]";

struct Options {
    config: PathBuf,
    once: bool,
    sweep_now: bool,
    dry_run: bool,
}

fn options() -> Result<Options, String> {
    let mut config = None;
    let (mut once, mut sweep_now, mut dry_run) = (false, false, false);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config = Some(PathBuf::from(args.next().ok_or(USAGE)?)),
            "--once" => once = true,
            "--sweep-now" => sweep_now = true,
            "--dry-run" => dry_run = true,
            "--help" | "-h" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    Ok(Options {
        config: config.ok_or_else(|| format!("--config is required\n{USAGE}"))?,
        once,
        sweep_now,
        dry_run,
    })
}

fn print_report(report: &Result<PassReport, String>, dry_run: bool) {
    match report {
        Err(error) => eprintln!("factory-troubleshooter: the pass failed: {error}"),
        Ok(report) => {
            let probes: Vec<String> = report
                .probes
                .iter()
                .map(|(id, outcome)| format!("{id}={}", outcome.as_str()))
                .collect();
            eprintln!("factory-troubleshooter: probes {}", probes.join(" "));
            if let (Some(run), Some(outcome)) = (&report.run, &report.outcome) {
                eprintln!(
                    "factory-troubleshooter: run {} ended {} (agent ran: {})",
                    run.as_str(),
                    outcome.as_str(),
                    report.agent_ran
                );
            }
            for action in &report.issues {
                match action {
                    IssueAction::DryRun(what) if dry_run => println!("DRY RUN: {what}"),
                    other => eprintln!("factory-troubleshooter: issue {other:?}"),
                }
            }
        }
    }
}

fn main() -> ExitCode {
    let options = match options() {
        Ok(options) => options,
        Err(why) => {
            eprintln!("{why}");
            return ExitCode::from(2);
        }
    };
    let config = match TroubleshooterConfig::from_file(&options.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("factory-troubleshooter: {error}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("factory-troubleshooter: the runtime cannot start: {error}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(async move {
        let booted = match boot(&config, options.dry_run).await {
            Ok(booted) => booted,
            Err(error) => {
                eprintln!("factory-troubleshooter: start-up check failed: {error}");
                return ExitCode::from(1);
            }
        };
        for missing in &booted.catalog.missing {
            eprintln!(
                "factory-troubleshooter: the gateway does not offer {}: {:?}",
                missing.tool.gateway_name, missing.reason
            );
        }
        if config.gateway.datadog.is_none() {
            eprintln!("factory-troubleshooter: Datadog is not configured; its probes and tools are off");
        }
        let pass_options = PassOptions {
            sweep_now: options.sweep_now,
        };
        let code = if options.once {
            match activate(&booted.lock_url).await {
                Ok(Activation::Active(lock)) => {
                    let report = booted
                        .troubleshooter
                        .pass(pass_options)
                        .await
                        .map_err(|e| e.to_string());
                    print_report(&report, options.dry_run);
                    lock.release().await;
                    if report.is_ok() { ExitCode::SUCCESS } else { ExitCode::from(1) }
                }
                Ok(Activation::Idle) => {
                    eprintln!(
                        "factory-troubleshooter: another troubleshooter is active; this one did nothing"
                    );
                    ExitCode::from(4)
                }
                Err(error) => {
                    eprintln!("factory-troubleshooter: {error}");
                    ExitCode::from(1)
                }
            }
        } else {
            let shutdown = Shutdown::new();
            tokio::spawn(raise_on_termination(shutdown.clone()));
            let dry_run = options.dry_run;
            run_loop(
                &booted.troubleshooter,
                &booted.lock_url,
                booted.probe_period,
                pass_options,
                &shutdown,
                &move |report| print_report(report, dry_run),
            )
            .await;
            ExitCode::SUCCESS
        };
        booted.broker.shutdown();
        booted.server.shutdown().await;
        drop(booted.telemetry);
        code
    })
}
