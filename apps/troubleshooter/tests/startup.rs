//! The start-up refusals of the troubleshooter: an unknown setting, a gateway that does not listen
//! on loopback, a secret file that others can read, an observer login that can write. Also: the
//! repository's own troubleshooting policy loads, and the README's example configuration parses.

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use factory_composition::startup::load_policy;
use factory_domain::redaction::Redactor;
use factory_troubleshooter::boot::{load_troubleshooting, observer_inspector};
use factory_troubleshooter::config::TroubleshooterConfig;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "factory-troubleshooter-startup-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn secret(dir: &Path, name: &str, mode: u32, content: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

/// The README's example, with its placeholder paths moved under `dir`.
fn example(dir: &Path) -> String {
    let readme = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"))
        .expect("the README");
    let start = readme.find("```yaml\n").expect("a yaml block") + "```yaml\n".len();
    let end = readme[start..].find("```").expect("its end") + start;
    readme[start..end].replace("/etc/factory/troubleshooter", &dir.display().to_string())
}

fn parse(text: &str) -> TroubleshooterConfig {
    factory_composition::config::read_document(text).expect("the configuration parses")
}

#[test]
fn the_readme_example_parses_and_passes_the_checks() {
    let dir = scratch("example");
    let config = parse(&example(&dir));
    assert_eq!(config.check(), Ok(()));
    assert!(config.gateway.datadog.is_none(), "Datadog is optional");
}

#[test]
fn an_unknown_setting_is_refused() {
    let dir = scratch("unknown");
    let text = format!("{}\nnot_a_setting: true\n", example(&dir));
    assert!(factory_composition::config::read_document::<TroubleshooterConfig>(&text).is_err());
}

#[test]
fn a_gateway_that_does_not_listen_on_loopback_is_refused() {
    let dir = scratch("listen");
    let text = example(&dir).replace("listen: 127.0.0.1:8445", "listen: 0.0.0.0:8445");
    let problems = parse(&text).check().expect_err("refused");
    assert!(
        problems.iter().any(|p| p.starts_with("gateway:")),
        "{problems:?}"
    );
}

#[test]
fn the_repository_troubleshooting_policy_loads() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let policies = load_policy(&root, &[]).expect("the security policy");
    let (policy, hash) =
        load_troubleshooting(&root, &[], &policies.security).expect("the troubleshooting policy");
    assert!(!policy.probes.is_empty());
    assert!(hash.as_str().starts_with("sha256:"));
}

#[tokio::test]
async fn an_observer_password_file_others_can_read_is_refused() {
    let dir = scratch("password");
    let mut config = parse(&example(&dir));
    config.observer.password_file = secret(&dir, "observer-password", 0o644, "not-a-real-password");
    let refused = observer_inspector(&config, &Redactor::builder().build().expect("redactor"))
        .await
        .err()
        .unwrap_or_else(|| panic!("refused"));
    assert!(
        refused.to_string().contains("observer.password_file"),
        "{refused}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_observer_login_that_can_write_is_refused() {
    let db = support::server::server().clone_database().await;
    let writer = db
        .server
        .create_login("writer", &["factory_observer", "factory_app"])
        .await;
    let password = format!("pw-{}", std::process::id());
    db.run(&format!(
        "ALTER ROLE \"{}\" PASSWORD '{password}'",
        writer.name
    ))
    .await;
    let dir = scratch("writer");
    let mut config = parse(&example(&dir));
    let url = std::env::var("FACTORY_DB_ADMIN_URL").expect("BLOCKED: FACTORY_DB_ADMIN_URL");
    let authority = url
        .split("://")
        .nth(1)
        .and_then(|r| r.split('/').next())
        .expect("url");
    let host_port = authority.rsplit('@').next().expect("host");
    let (host, port) = host_port.rsplit_once(':').unwrap_or((host_port, "5432"));
    config.observer.host = host.to_owned();
    config.observer.port = port.parse().expect("port");
    config.observer.database = db.name.clone();
    config.observer.user = writer.name.clone();
    config.observer.password_file = secret(&dir, "observer-password", 0o600, &password);
    let refused = observer_inspector(&config, &Redactor::builder().build().expect("redactor"))
        .await
        .err()
        .unwrap_or_else(|| panic!("a login that can write is refused"));
    assert!(
        refused.to_string().contains("will not use this login"),
        "{refused}"
    );
}
