//! The HTTP API.
//!
//! ```text
//! FACTORY_CONFIG=/etc/factory/api.yaml factory-api
//! ```
//!
//! Exit codes: 0 a clean stop (SIGTERM or SIGINT), 1 a start-up check failed or the listener could
//! not bind, 2 the configuration was refused.

use std::process::ExitCode;
use std::sync::Arc;

use factory_api::boot::boot;
use factory_api::config::ApiConfig;
use factory_api::routes::router;
use factory_api::server::serve;
use factory_composition::system::{Shutdown, raise_on_termination};
use tokio::net::TcpListener;

fn main() -> ExitCode {
    let config = match ApiConfig::from_environment(|name| std::env::var(name).ok()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("factory-api: {error}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("factory-api: the runtime cannot start: {error}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(async move {
        let booted = match boot(&config).await {
            Ok(booted) => booted,
            Err(error) => {
                eprintln!("factory-api: start-up check failed: {error}");
                return ExitCode::from(1);
            }
        };
        let listener = match TcpListener::bind(config.listen).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("factory-api: cannot listen on {}: {error}", config.listen);
                return ExitCode::from(1);
            }
        };
        let shutdown = Shutdown::new();
        tokio::spawn(raise_on_termination(shutdown.clone()));
        if shutdown.is_raised() {
            eprintln!("factory-api: the stop signal handlers could not be installed");
            return ExitCode::from(1);
        }
        tracing::info!(listen = %config.listen, profile = config.profile.name(), "the API is serving");
        let app = router(Arc::clone(&booted.state));
        match serve(listener, app, config.limits.clone(), shutdown).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("factory-api: the server stopped: {error}");
                ExitCode::from(1)
            }
        }
    })
}
