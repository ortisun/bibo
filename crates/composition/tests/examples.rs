//! The example configurations of the local deployment (`infra/compose/config/*.example.yaml`),
//! run through the real parser. The tests read the files the Compose stack mounts, not a copy of
//! their text, so an example that the parser refuses fails here and cannot drift again.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use factory_composition::config::{ConfigError, FactoryConfig, SecretFile};
use factory_composition::profile::Profile;

fn example(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../infra/compose/config")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn the_worker_example_of_the_local_stack_parses() {
    let config = FactoryConfig::from_yaml(&example("worker.local.example.yaml"))
        .expect("the worker example must parse");
    assert_eq!(config.profile, Profile::Local);
    // The values the stack decides are the ones the parser reads.
    assert_eq!(config.database.tenant.login, "factory_worker");
    assert_eq!(config.database.system.login, "factory_engine");
    assert_eq!(config.broker.listen.port(), 8731);
    assert!(
        config.broker.upstreams.is_empty() && config.broker.prices.is_empty(),
        "the example has no credential, so the worker is BLOCKED until the deployment adds one"
    );
    assert!(config.github.is_none());
    assert!(config.worker.tenants.is_empty());
}

/// A deliberate break: the API's file given to the worker. The two programs have their own
/// configuration types, and the API example names `database.api` and `listen`, which the worker's
/// configuration does not have. Handing it to the worker is refused, not half read.
#[test]
fn the_api_example_is_refused_by_the_worker_parser() {
    let refused = FactoryConfig::from_yaml(&example("api.local.example.yaml"))
        .expect_err("the API file is not a worker configuration");
    assert!(matches!(refused, ConfigError::Invalid(_)), "{refused:?}");
}

#[test]
fn a_misspelled_setting_in_the_worker_example_is_an_error_and_not_a_weaker_run() {
    let broken = example("worker.local.example.yaml").replace("max_connections", "max_connection");
    assert!(FactoryConfig::from_yaml(&broken).is_err());
}

/// What the deployment must do about the secret files. Compose mounts a file with the mode the host
/// file has. The worker refuses a secret file that group or others can read, that is a link, or
/// that is not a regular file, and it must be readable by the uid the container runs as.
#[test]
fn a_secret_file_is_refused_when_group_or_others_can_read_it_and_accepted_at_0600() {
    let dir = std::env::temp_dir().join(format!("composition-secret-modes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    let file = dir.join("db_worker");
    let value = ["not", "-a-real-", "secret-value"].concat();
    std::fs::write(&file, &value).expect("write");
    let secret = SecretFile::at(file.clone());
    for (mode, accepted) in [
        (0o600, true),
        (0o400, true),
        (0o640, false),
        (0o644, false),
        (0o604, false),
    ] {
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).expect("mode");
        let read = secret.read();
        assert_eq!(read.is_ok(), accepted, "mode {mode:o}: {read:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The key that verifies decision requests is the one the API signs with. The worker example names
/// a key file, the sandbox settings a deployment that runs agents sets, and still holds no
/// credential: the worker stays BLOCKED until a person supplies them, which is the right answer.
#[test]
fn the_corrected_worker_example_for_the_local_stack_parses_and_names_the_shared_key() {
    let config = FactoryConfig::from_yaml(&example("worker.local.example.yaml"))
        .expect("the example in infra/compose/config parses");
    assert_eq!(config.profile, Profile::Local);
    assert_eq!(config.broker.listen.port(), 8731);
    let decisions = config
        .decisions
        .as_ref()
        .expect("the key that verifies decision requests is named");
    assert_eq!(
        decisions.key_file.path(),
        std::path::Path::new("/run/secrets/decision_signing_key"),
        "the path the Compose file mounts the shared secret at"
    );
    assert!(config.broker.upstreams.is_empty() && config.github.is_none());
}

/// A deliberate break: the example without the decision key still parses in the local profile (the
/// production profile is the one that requires it), so this test pins the key down by name.
#[test]
fn an_example_that_drops_the_decision_key_no_longer_names_the_shared_key() {
    let without: String = example("worker.local.example.yaml")
        .lines()
        .filter(|line| {
            !line.starts_with("decisions:")
                && !line.contains("key_file: /run/secrets/decision_signing_key")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config = FactoryConfig::from_yaml(&without).expect("the rest still parses");
    assert!(config.decisions.is_none());
}

/// The two Docker keys are written in the example as comments. Taking the comment marks off must
/// give a file the parser accepts and that carries the values, so the example cannot drift from the
/// keys of the parser (a misspelled key is an error in the worker).
#[test]
fn the_docker_keys_in_the_worker_example_parse_once_uncommented() {
    let text = example("worker.local.example.yaml");
    let uncommented = text
        .replace("  # docker_host: ", "  docker_host: ")
        .replace("  # docker_config: ", "  docker_config: ");
    assert_ne!(uncommented, text, "the example holds both keys");
    let config = FactoryConfig::from_yaml(&uncommented).expect("the uncommented keys parse");
    assert_eq!(
        config.sandbox.docker_host.as_deref(),
        Some("unix:///var/run/docker.sock")
    );
    assert_eq!(
        config.sandbox.docker_config,
        Some(PathBuf::from("/home/factory/.docker"))
    );
    // The file as shipped sets neither.
    let shipped = FactoryConfig::from_yaml(&text).expect("parses");
    assert!(shipped.sandbox.docker_host.is_none() && shipped.sandbox.docker_config.is_none());
}
