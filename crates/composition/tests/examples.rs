//! The example configurations of the local deployment (`infra/compose/config/*.example.yaml`),
//! run through the real parser. They were written before the parser was used on them; this test is
//! the first time. Where the parser refuses an example, the test says so and the README tells the
//! owner of `infra/**` what to change, because this crate does not edit that directory.

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

/// A deliberate break: an example that the parser refuses. The API example of the same directory
/// is one, and this test keeps the refusal visible until the API has its own configuration type:
/// the API example names `database.api` and `listen`, which the worker's configuration does not
/// have, and lacks the protected checkout and the definitions root, which it requires.
#[test]
fn the_api_example_is_refused_by_the_parser_it_was_never_run_through() {
    let refused = FactoryConfig::from_yaml(&example("api.local.example.yaml"))
        .expect_err("the placeholder is not a worker configuration");
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

/// The text the owner of `infra/compose` puts in `config/worker.local.example.yaml`: the existing
/// file with the key that verifies the decision requests (the same file the API signs with), the
/// two settings of the sandbox that a deployment that runs agents sets, and the gate definitions
/// commit that production requires. The credentials stay out: the worker is still BLOCKED until
/// they are supplied, which is the right answer.
const CORRECTED_WORKER_EXAMPLE: &str = "\
profile: local
protected_checkout: /srv/factory/protected
definitions_root: /srv/factory/protected

database:
  tenant: { url_file: /run/secrets/db_worker, login: factory_worker, max_connections: 8 }
  system: { url_file: /run/secrets/db_engine, login: factory_engine, max_connections: 4 }

artifacts: { root: /var/lib/factory/artifacts }

sandbox:
  images_catalog: /srv/factory/protected/infra/sandbox-images/images.json
  token_root: /var/lib/factory/tokens
  workspace_root: /var/lib/factory/workspaces
  # remote: { https_host: github.com }   # or { directory: /abs/path } outside production
  # sidecar_command: []                  # the egress sidecar's arguments; with none the real sidecar refuses to start

broker:
  listen: 0.0.0.0:8731
  upstreams: []
  prices: []

decisions:
  key_file: /run/secrets/decision_signing_key   # the SAME file the API signs with; mode 0600; 32 bytes or more

# stages:
#   definition_commit: 1405df66cbe219b0bf6355bc3d60361a8376b6b4   # required in production
# github: { app_id: 0, key_file: /run/secrets/github_app_key }     # needs a registered GitHub App
# worker: { name_prefix: worker, poll_interval_ms: 1000, sweep_interval_s: 10, drain_s: 120, tenants: [] }
";

#[test]
fn the_corrected_worker_example_for_the_local_stack_parses_and_names_the_shared_key() {
    let config = FactoryConfig::from_yaml(CORRECTED_WORKER_EXAMPLE).expect("the text parses");
    assert_eq!(config.profile, Profile::Local);
    assert_eq!(config.broker.listen.port(), 8731);
    assert!(
        config.decisions.is_some(),
        "the key that verifies decision requests is named"
    );
    assert!(config.broker.upstreams.is_empty() && config.github.is_none());
}
