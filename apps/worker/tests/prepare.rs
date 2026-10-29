//! The start-up path of the binary, from a configuration file and secret files to a connected
//! store, a hosted broker and the list of what the configuration does not yet supply.

mod support;

use std::path::PathBuf;
use std::process::Command;

use factory_composition::assemble::blocked_adapters;
use factory_composition::config::FactoryConfig;
use factory_composition::profile::{PortName, Profile};
use factory_worker::boot::boot;

/// A deployment with a provider and nothing else: the minimum the start-up checks need.
async fn deployment(profile: &str, same_login: bool) -> (PathBuf, PathBuf, support::TestDb) {
    let made = support::deployment::deployment(
        profile,
        same_login,
        "http://127.0.0.1:9",
        "127.0.0.1:0",
        |_| String::new(),
    )
    .await;
    (made.config_path, made.dir, made.db)
}

#[tokio::test(flavor = "multi_thread")]
async fn prepare_connects_both_pools_hosts_the_broker_and_lists_what_is_blocked() {
    let (config_path, dir, _db) = deployment("local", false).await;
    let config = FactoryConfig::from_file(&config_path).expect("the configuration loads");
    let booted = boot(&config).await.expect("every start-up check passes");
    let prepared = &booted.prepared;
    assert!(
        prepared
            .secrets
            .count(factory_composition::redaction::SecretKind::DatabaseCredentials)
            >= 4
    );
    assert!(
        prepared
            .secrets
            .count(factory_composition::redaction::SecretKind::BrokerKeys)
            >= 1
    );
    booted.broker.shutdown();
    let blocked = blocked_adapters(Profile::Local);
    assert!(blocked.iter().any(|b| b.port == PortName::Runtime));
    assert!(blocked.iter().all(|b| !b.reason.is_empty()));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_binary_stops_with_blocked_lines_that_name_the_missing_keys_and_code_three() {
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
    // The provider is configured, so the runtime and the router are not on the list; what the
    // configuration lacks is, and each line starts with the key to write.
    for line in [
        "BLOCKED: issue source: github:",
        "BLOCKED: change host: github:",
        "BLOCKED: CapabilityProbes: worker.tenants:",
        "BLOCKED: RegistryMetadata: registry.base_url:",
        "BLOCKED: AdvisoryDatabase: advisory_database.date_file:",
    ] {
        assert!(stderr.contains(line), "{line} is missing from:\n{stderr}");
    }
    assert!(!stderr.contains("BLOCKED: agent runtime"), "{stderr}");
    assert!(!stderr.contains("BLOCKED: model router"), "{stderr}");
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
