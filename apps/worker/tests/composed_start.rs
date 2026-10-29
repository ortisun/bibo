//! The worker binary with a complete loopback configuration: it builds every adapter for the outside
//! world, serves the broker, runs the loop, and stops with code 0 when it is asked to.
//!
//! Real: the binary, PostgreSQL, the policies, the GitHub App adapter (a throwaway RSA key, the HTTP
//! client), the broker listener, the routing policy, the engine and the loop. Fake, and labelled: the
//! GitHub server (FX-GH of the test kit), the registry server, and the capability list, which is
//! declared because the Docker daemon is not part of this test. Nothing leaves the machine.
#![allow(dead_code)]

mod support;

#[path = "../../../crates/github/tests/common/mod.rs"]
mod gh;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use factory_domain::ids::TenantId;
use factory_testkit::fx::http::{HttpResponse, HttpServer};
use gh::harness::{FIXTURE, World};
use gh::keys::{Form, Throwaway};
use serde_json::json;
use support::deployment::{Deployment, deployment, write_private};

/// `bytes` random bytes as hex, from the operating system, so no key-shaped literal sits in the source.
fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buffer))
        .expect("random bytes");
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    listener.local_addr().expect("an address").port()
}

/// A running worker and everything that keeps it alive.
struct Running {
    child: Child,
    port: u16,
    made: Deployment,
    _world: World,
    _registry: HttpServer,
}

impl Running {
    fn stderr_so_far(&mut self) -> String {
        let mut text = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            let _ = pipe.read_to_string(&mut text);
        }
        text
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.made.dir);
    }
}

/// Starts the binary on a configuration that supplies everything, built around the fake servers.
/// `change` edits the configuration text after the deployment wrote it.
async fn start(change: impl FnOnce(String) -> String) -> Running {
    let world = World::new();
    let registry = HttpServer::start("fx-crates-io", |_| {
        HttpResponse::json(404, &json!({"errors": [{"detail": "Not Found"}]}))
    })
    .expect("the fake registry starts");
    let port = free_port();
    let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(
        0x7000_0000_0000_4000_8000_0000_0000_0001,
    ));
    let tenant_text = tenant.as_uuid().to_string();
    let github_base = world.server.base_url();
    let registry_base = registry.base_url();
    let app_id = world.fake.app().id;
    let made = deployment(
        "local",
        false,
        "http://127.0.0.1:9",
        &format!("127.0.0.1:{port}"),
        |dir| {
            write_private(
                &dir.join("app.pem"),
                &Throwaway::new(Form::Pkcs8).private_pem,
            );
            write_private(&dir.join("advisory.date"), "2026-10-27\n");
            write_private(&dir.join("decision.key"), &random_hex(32));
            format!(
                "github:\n  app_id: {app_id}\n  key_file: {dir}/app.pem\n  api_base_url: '{github_base}'\n  installations:\n    - {{ tenant: {tenant_text}, repository: {FIXTURE}, installation_id: 1 }}\n\
                 registry: {{ base_url: '{registry_base}', user_agent: factory-test }}\n\
                 advisory_database: {{ date_file: {dir}/advisory.date }}\n\
                 runtimes: {{ declare_capabilities: true }}\n\
                 decisions: {{ key_file: {dir}/decision.key }}\n\
                 worker: {{ name_prefix: composed, poll_interval_ms: 100, sweep_interval_s: 1, drain_s: 5, tenants: ['{tenant_text}'] }}\n",
                dir = dir.display(),
            )
        },
    )
    .await;
    // The tenant has to exist for the loop to read its requests.
    support::seed_tenant(&made.db, tenant, 0, FIXTURE).await;
    let text = std::fs::read_to_string(&made.config_path).expect("the configuration");
    std::fs::write(&made.config_path, change(text)).expect("the changed configuration");
    let child = Command::new(env!("CARGO_BIN_EXE_factory-worker"))
        .env("FACTORY_CONFIG", &made.config_path)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("the binary starts");
    Running {
        child,
        port,
        made,
        _world: world,
        _registry: registry,
    }
}

/// Waits until the broker answers, or the process ends first.
fn wait_for_the_listener(running: &mut Running) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = running.child.try_wait() {
            return Err(format!(
                "the worker ended with {status}: {}",
                running.stderr_so_far()
            ));
        }
        if TcpStream::connect(("127.0.0.1", running.port)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("the broker never listened".to_owned())
}

fn ask_the_broker_without_a_token(port: u16) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the listener accepts");
    stream
        .write_all(
            b"POST /v1/messages HTTP/1.1\r\nHost: broker\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
        )
        .expect("write");
    let mut answer = String::new();
    stream.read_to_string(&mut answer).expect("read");
    answer
}

#[tokio::test(flavor = "multi_thread")]
async fn a_complete_loopback_configuration_serves_the_broker_runs_the_loop_and_stops_on_sigterm_with_code_zero()
 {
    let mut running = start(|text| text).await;
    tokio::task::block_in_place(|| {
        wait_for_the_listener(&mut running).unwrap_or_else(|reason| panic!("{reason}"));
        // The broker is the one the worker hosts: it refuses a request with no token.
        let answer = ask_the_broker_without_a_token(running.port);
        assert!(answer.starts_with("HTTP/1.1 401"), "{answer}");
        // Let the loop run a few passes: the preflight and the claim hooks run against the store.
        std::thread::sleep(Duration::from_millis(1500));
        assert!(
            running.child.try_wait().expect("status").is_none(),
            "the worker stopped by itself:\n{}",
            running.stderr_so_far()
        );
        // SIGTERM, as the container runtime sends it.
        let kill = Command::new("kill")
            .args(["-TERM", &running.child.id().to_string()])
            .status()
            .expect("kill runs");
        assert!(kill.success());
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = running.child.try_wait().expect("status") {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "the worker did not stop on SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        let stderr = running.stderr_so_far();
        assert_eq!(status.code(), Some(0), "{stderr}");
        assert!(!stderr.contains("BLOCKED"), "{stderr}");
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_one_key_makes_the_worker_stop_with_code_three_and_name_that_key() {
    // Break: a configuration with one missing key. The line names it, and the worker never claims.
    let mut running = start(|text| {
        let start = text.find("registry:").expect("registry");
        let end = text.find("advisory_database:").expect("advisory");
        format!("{}{}", &text[..start], &text[end..])
    })
    .await;
    tokio::task::block_in_place(|| {
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = running.child.try_wait().expect("status") {
                break status;
            }
            assert!(Instant::now() < deadline, "the worker did not stop");
            std::thread::sleep(Duration::from_millis(100));
        };
        let stderr = running.stderr_so_far();
        assert_eq!(status.code(), Some(3), "{stderr}");
        assert!(
            stderr.contains("BLOCKED: RegistryMetadata: registry.base_url:"),
            "{stderr}"
        );
        // Only that key is missing.
        assert_eq!(stderr.matches("BLOCKED: ").count(), 1, "{stderr}");
    });
}
