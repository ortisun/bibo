//! The worker hosts the model broker listener, and the key never leaves the broker.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use factory_composition::config::{BrokerConfig, SecretFile, UpstreamConfig};
use factory_composition::redaction::{FactorySecrets, redactor_from_policy};
use factory_composition::startup::load_policy;
use factory_composition::system::{RandomIds, SystemClock};
use factory_worker::broker_host::start;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scratch(name: &str) -> PathBuf {
    let dir = repository_root()
        .join("target/broker-test")
        .join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn key_file(dir: &std::path::Path, mode: u32) -> SecretFile {
    // Built at run time so that no secret-shaped literal sits in the source.
    let key = ["provider", "-key-", &"ab".repeat(13)].concat();
    let path = dir.join("provider.key");
    std::fs::write(&path, key).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
    SecretFile::at(path)
}

fn config(key: SecretFile) -> BrokerConfig {
    BrokerConfig {
        listen: "127.0.0.1:0".parse().expect("an address"),
        upstreams: vec![UpstreamConfig {
            provider: "anthropic".to_owned(),
            base_url: "http://127.0.0.1:9".to_owned(),
            key_file: key,
        }],
        prices: Vec::new(),
    }
}

#[test]
fn the_worker_hosts_the_broker_listener_and_it_refuses_a_request_with_no_token() {
    let policies = load_policy(&repository_root(), &[]).expect("policies");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("redactor"));
    let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
    let dir = scratch("host");
    let hosted = start(
        &config(key_file(&dir, 0o600)),
        Arc::clone(&redactor),
        Arc::new(SystemClock),
        Arc::new(RandomIds::new().expect("random")),
        &mut secrets,
    )
    .expect("the broker starts");

    // The provider key is now known to the redactor, in every encoding.
    let line = format!("a log line with provider-key-{} in it", "ab".repeat(13));
    let leaked = redactor.redact_str(&line).expect("redacts");
    assert!(!leaked.output.contains(&"ab".repeat(13)));

    let mut stream = TcpStream::connect(hosted.local_addr()).expect("the listener accepts");
    stream
        .write_all(
            b"POST /v1/messages HTTP/1.1\r\nHost: broker\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}",
        )
        .expect("write");
    let mut answer = String::new();
    stream.read_to_string(&mut answer).expect("read");
    assert!(answer.starts_with("HTTP/1.1 401"), "{answer}");
    assert!(
        !answer.contains(&"ab".repeat(13)),
        "the key reached a response"
    );

    hosted.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_provider_key_file_that_others_can_read_is_refused_before_the_listener_starts() {
    let policies = load_policy(&repository_root(), &[]).expect("policies");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("redactor"));
    let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
    let dir = scratch("unsafe");
    let refusal = start(
        &config(key_file(&dir, 0o644)),
        redactor,
        Arc::new(SystemClock),
        Arc::new(RandomIds::new().expect("random")),
        &mut secrets,
    );
    assert!(refusal.is_err());
    let _ = std::fs::remove_dir_all(dir);
}
