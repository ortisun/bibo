//! The start-up path of the binary, from a configuration file and secret files to a connected
//! store, a hosted broker and the list of adapters it cannot assemble.

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use factory_worker::assemble::{blocked_adapters, prepare};
use factory_worker::config::FactoryConfig;
use factory_worker::profile::{PortName, Profile};
use support::server;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn write_private(path: &Path, text: &str) {
    std::fs::write(path, text).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("mode");
}

/// A deployment on disk: a database with two logins of the right groups, URL files, a provider
/// key file and a configuration file. Returns the configuration path and the scratch directory.
async fn deployment(profile: &str, same_login: bool) -> (PathBuf, PathBuf, support::TestDb) {
    let db = server().clone_database().await;
    let run = std::process::id();
    let worker = format!("dbtest_prep_w_{run}");
    let engine = if same_login {
        worker.clone()
    } else {
        format!("dbtest_prep_e_{run}")
    };
    // Passwords are made here and never written in source.
    let password = ["pw", "-", &run.to_string(), "-abcdef"].concat();
    db.run(&format!(
        "CREATE ROLE {worker} LOGIN PASSWORD '{password}' IN ROLE factory_app;"
    ))
    .await;
    if !same_login {
        db.run(&format!(
            "CREATE ROLE {engine} LOGIN PASSWORD '{password}' IN ROLE factory_system;"
        ))
        .await;
    }
    let port = db
        .text("SELECT current_setting('port')")
        .await
        .expect("a port");
    let sockets = db
        .text("SELECT current_setting('unix_socket_directories')")
        .await
        .expect("a socket directory");
    let host = sockets.split(',').next().expect("a host").trim().to_owned();
    let url = |login: &str| {
        format!(
            "host={host} port={port} user={login} password={password} dbname={}",
            db.name
        )
    };
    let dir = repository_root()
        .join("target/prepare-test")
        .join(format!("{profile}-{run}"));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    write_private(&dir.join("tenant.url"), &url(&worker));
    write_private(&dir.join("system.url"), &url(&engine));
    write_private(
        &dir.join("provider.key"),
        &["provider", "-key-", &"ab".repeat(13)].concat(),
    );
    let root = repository_root();
    let text = format!(
        "profile: {profile}\n\
         protected_checkout: {root}\n\
         definitions_root: {root}\n\
         database:\n  tenant: {{ url_file: {dir}/tenant.url, login: {worker} }}\n  system: {{ url_file: {dir}/system.url, login: {engine} }}\n\
         artifacts: {{ root: {dir}/artifacts }}\n\
         sandbox: {{ images_catalog: {root}/infra/sandbox-images/images.json, token_root: {dir}/tokens, workspace_root: {dir}/workspaces, platform: linux/arm64 }}\n\
         broker:\n  listen: '127.0.0.1:0'\n  upstreams:\n    - {{ provider: anthropic, base_url: 'http://127.0.0.1:9', key_file: {dir}/provider.key }}\n",
        root = root.display(),
        dir = dir.display(),
    );
    let config_path = dir.join("worker.yaml");
    std::fs::write(&config_path, text).expect("the configuration");
    (config_path, dir, db)
}

#[tokio::test(flavor = "multi_thread")]
async fn prepare_connects_both_pools_hosts_the_broker_and_lists_what_is_blocked() {
    let (config_path, dir, _db) = deployment("local", false).await;
    let config = FactoryConfig::from_file(&config_path).expect("the configuration loads");
    let prepared = prepare(&config).await.expect("every start-up check passes");
    assert!(
        prepared
            .secrets
            .count(factory_worker::redaction::SecretKind::DatabaseCredentials)
            >= 4
    );
    assert!(
        prepared
            .secrets
            .count(factory_worker::redaction::SecretKind::BrokerKeys)
            >= 1
    );
    prepared.broker.shutdown();
    let blocked = blocked_adapters(Profile::Local);
    assert!(blocked.iter().any(|b| b.port == PortName::Runtime));
    assert!(blocked.iter().all(|b| !b.reason.is_empty()));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_binary_stops_with_blocked_lines_and_code_three_after_its_checks_pass() {
    let (config_path, dir, _db) = deployment("local", false).await;
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_factory-worker"))
            .env("FACTORY_CONFIG", &config_path)
            .output()
            .expect("the binary runs")
    })
    .await
    .expect("joins");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("BLOCKED: agent runtime"), "{stderr}");
    assert!(stderr.contains("BLOCKED is not a pass"), "{stderr}");
    // No secret reached the output.
    assert!(!stderr.contains(&"ab".repeat(13)));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_binary_refuses_a_configuration_that_names_one_login_for_both_pools() {
    let (config_path, dir, _db) = deployment("local", true).await;
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_factory-worker"))
            .env("FACTORY_CONFIG", &config_path)
            .output()
            .expect("the binary runs")
    })
    .await
    .expect("joins");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("must differ"), "{stderr}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_binary_refuses_to_start_without_a_configuration_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_factory-worker"))
        .env_remove("FACTORY_CONFIG")
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code(), Some(2));
}
