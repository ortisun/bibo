//! `factory-mcp-postgres`: serves the read-only PostgreSQL MCP server over stdio or Streamable
//! HTTP. Diagnostics go to stderr; in stdio mode stdout carries the protocol and nothing else.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use factory_composition::redaction::redactor_from_policy;
use factory_composition::startup::load_policy;
use factory_domain::redaction::Redactor;
use factory_mcp_postgres::{
    BudgetScope, ConnectSettings, DEFAULT_BUDGET_WINDOW, Inspector, Limits, Password, PostgresMcp,
    Redact,
};
use factory_mcp_postgres_app::{
    Options, Settings, USAGE, bearer_matches, check_registered, check_token, parse_args,
    read_secret_file,
};
use rmcp::ServiceExt;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const USAGE_ERROR: u8 = 2;
const FAILURE: u8 = 1;

fn main() -> ExitCode {
    let options = match parse_args(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(why) => {
            eprintln!("factory-mcp-postgres: {why}\n\n{USAGE}");
            return ExitCode::from(USAGE_ERROR);
        }
    };
    if options.help {
        eprintln!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("factory-mcp-postgres: cannot start the async runtime");
            return ExitCode::from(FAILURE);
        }
    };
    match runtime.block_on(run(options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, why)) => {
            eprintln!("factory-mcp-postgres: {why}");
            ExitCode::from(code)
        }
    }
}

fn settings(options: &Options) -> Result<Settings, String> {
    let file = options
        .config
        .clone()
        .or_else(|| std::env::var_os("FACTORY_MCP_PG_CONFIG").map(Into::into));
    match file {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|_| format!("the settings file {} cannot be read", path.display()))?;
            Settings::from_json(&text)
        }
        None => Settings::from_env(|key| std::env::var(key).ok()),
    }
}

fn redactor(settings: &Settings) -> Result<Redactor, String> {
    match &settings.policy_checkout {
        Some(checkout) => {
            let policies = load_policy(checkout, &[])
                .map_err(|error| format!("the policy cannot be loaded: {error}"))?;
            redactor_from_policy(&policies.security)
                .map_err(|error| format!("the redactor cannot be built: {error}"))
        }
        None => {
            eprintln!(
                "factory-mcp-postgres: no policy_checkout is set, so only the password and the token are redacted, \
                 not the secret patterns of policies/security.yaml"
            );
            Redactor::builder()
                .build()
                .map_err(|error| format!("the redactor cannot be built: {error}"))
        }
    }
}

async fn run(options: Options) -> Result<(), (u8, String)> {
    let usage = |why: String| (USAGE_ERROR, why);
    let settings = settings(&options).map_err(usage)?;
    let password = match &settings.password_file {
        Some(path) => Some(read_secret_file(path, "password").map_err(usage)?),
        None => None,
    };
    let token = match &options.token_file {
        Some(path) => {
            let token = read_secret_file(path, "token").map_err(usage)?;
            check_token(&token).map_err(usage)?;
            Some(token)
        }
        None => None,
    };
    let redactor = redactor(&settings).map_err(usage)?;
    for (label, secret) in [
        ("database_password", &password),
        ("mcp_bearer_token", &token),
    ] {
        if let Some(secret) = secret {
            check_registered(label, redactor.register(label, secret)).map_err(usage)?;
        }
    }
    let redactor: Arc<dyn Redact> = Arc::new(redactor);

    let mut connect = ConnectSettings::new(
        settings.host.clone(),
        settings.port,
        settings.user.clone(),
        settings.database.clone(),
    );
    if let Some(password) = password {
        connect = connect.with_password(Password::new(password));
    }
    let mut limits = Limits::default();
    if let Some(max_calls) = settings.max_calls {
        limits.max_calls = max_calls;
    }
    let inspector = Arc::new(Inspector::new(connect, limits, redactor));
    let login = inspector
        .check_login()
        .await
        .map_err(|failure| (FAILURE, format!("will not serve: {failure}")))?;
    // One budget for the process, renewed every window: the clones served to HTTP sessions share
    // it, so a new session does not start a new budget.
    let window = settings
        .budget_window_s
        .map_or(DEFAULT_BUDGET_WINDOW, Duration::from_secs);
    if window.is_zero() {
        return Err((USAGE_ERROR, "budget_window_s must be at least 1".to_owned()));
    }
    let server = PostgresMcp::with_budget(inspector, BudgetScope::Window(window));

    match (options.http, token) {
        (None, _) => {
            eprintln!(
                "factory-mcp-postgres: serving MCP over stdio as {login} on {}:{}/{}",
                settings.host, settings.port, settings.database
            );
            let running = server
                .serve(stdio_pipe())
                .await
                .map_err(|_| (FAILURE, "the MCP session could not start".to_owned()))?;
            running
                .waiting()
                .await
                .map_err(|_| (FAILURE, "the MCP session ended with an error".to_owned()))?;
            Ok(())
        }
        (Some(address), Some(token)) => {
            let mut config = StreamableHttpServerConfig::default();
            if !address.ip().is_loopback() {
                config = config.with_allowed_hosts([address.ip().to_string(), address.to_string()]);
            }
            config.sse_keep_alive = Some(Duration::from_secs(15));
            let service = StreamableHttpService::new(
                move || Ok(server.clone()),
                Arc::new(LocalSessionManager::default()),
                config,
            );
            let router = axum::Router::new().nest_service("/mcp", service).layer(
                middleware::from_fn_with_state(Arc::new(token), require_bearer),
            );
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|_| (FAILURE, format!("cannot listen on {address}")))?;
            eprintln!(
                "factory-mcp-postgres: serving Streamable HTTP at http://{address}/mcp as {login} on {}:{}/{}",
                settings.host, settings.port, settings.database
            );
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
                .map_err(|_| (FAILURE, "the HTTP server stopped with an error".to_owned()))
        }
        (Some(_), None) => Err((USAGE_ERROR, "--http needs --token-file".to_owned())),
    }
}

/// The server's end of a pipe whose other end two threads join to this process's stdin and
/// stdout. Blocking reads of stdin stay on their own thread, off the runtime.
fn stdio_pipe() -> tokio::io::DuplexStream {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (mut from_server, mut to_server) = tokio::io::split(theirs);
    let inbound = tokio::runtime::Handle::current();
    let outbound = inbound.clone();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buffer = [0_u8; 8192];
        loop {
            match stdin.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if inbound
                        .block_on(to_server.write_all(&buffer[..read]))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        // End of input ends the session.
        let _ = inbound.block_on(to_server.shutdown());
    });
    std::thread::spawn(move || {
        let mut stdout = std::io::stdout().lock();
        let mut buffer = [0_u8; 8192];
        loop {
            match outbound.block_on(from_server.read(&mut buffer)) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if stdout
                        .write_all(&buffer[..read])
                        .and_then(|()| stdout.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    ours
}

async fn require_bearer(
    State(token): State<Arc<String>>,
    request: Request,
    next: Next,
) -> Response {
    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if bearer_matches(header, &token) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "a valid bearer token is required\n",
        )
            .into_response()
    }
}
