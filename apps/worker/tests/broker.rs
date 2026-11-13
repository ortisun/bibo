//! The worker hosts the model broker listener, and the key never leaves the broker.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use factory_composition::config::{BrokerConfig, SecretFile, UpstreamConfig};
use factory_composition::profile::Profile;
use factory_composition::redaction::{FactorySecrets, redactor_from_policy};
use factory_composition::startup::StartupFailure;
use factory_composition::startup::{load_policy, load_routing};
use factory_composition::system::{RandomIds, SystemClock};
use factory_domain::policy::security::ProviderCredentialMode;
use factory_egress::http::SUBSCRIPTION_TOKEN_PREFIX;
use factory_worker::broker_host::{CredentialSetting, start};

const API_KEY_MODE: CredentialSetting = CredentialSetting {
    mode: ProviderCredentialMode::ApiKey,
    profile: Profile::Local,
};

const SUBSCRIPTION: CredentialSetting = CredentialSetting {
    mode: ProviderCredentialMode::Subscription,
    profile: Profile::Local,
};

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
            models: Vec::new(),
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
    let routing = load_routing(&repository_root(), &[], &policies.security).expect("routing");
    let hosted = start(
        &config(key_file(&dir, 0o600)),
        API_KEY_MODE,
        &routing.policy,
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
    let routing = load_routing(&repository_root(), &[], &policies.security).expect("routing");
    let refusal = start(
        &config(key_file(&dir, 0o644)),
        API_KEY_MODE,
        &routing.policy,
        redactor,
        Arc::new(SystemClock),
        Arc::new(RandomIds::new().expect("random")),
        &mut secrets,
    );
    assert!(refusal.is_err());
    let _ = std::fs::remove_dir_all(dir);
}

/// A made-up subscription token, built at run time so that no secret-shaped literal sits in the
/// source.
fn made_up_token() -> String {
    [SUBSCRIPTION_TOKEN_PREFIX, &"Zq9-".repeat(20), "AA"].concat()
}

fn token_file(dir: &std::path::Path, text: &str, mode: u32) -> SecretFile {
    let path = dir.join("claud-oauth-token.txt");
    std::fs::write(&path, text).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
    SecretFile::at(path)
}

fn start_with(
    broker: &BrokerConfig,
    setting: CredentialSetting,
) -> (
    Result<factory_worker::broker_host::HostedBroker, StartupFailure>,
    Arc<factory_domain::redaction::Redactor>,
    FactorySecrets,
) {
    let policies = load_policy(&repository_root(), &[]).expect("policies");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("redactor"));
    let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
    let routing = load_routing(&repository_root(), &[], &policies.security).expect("routing");
    let started = start(
        broker,
        setting,
        &routing.policy,
        Arc::clone(&redactor),
        Arc::new(SystemClock),
        Arc::new(RandomIds::new().expect("random")),
        &mut secrets,
    );
    (started, redactor, secrets)
}

fn refusal_text(
    started: Result<factory_worker::broker_host::HostedBroker, StartupFailure>,
) -> String {
    match started {
        Err(error @ StartupFailure::SubscriptionTokenMissing(_)) => error.to_string(),
        Err(other) => panic!("not the named refusal: {other}"),
        Ok(_) => panic!("the broker started"),
    }
}

#[test]
fn in_subscription_mode_the_broker_starts_on_the_owners_token_and_the_redactor_knows_it() {
    let dir = scratch("subscription");
    let token = made_up_token();
    // Whitespace around the token, as an editor or `echo` leaves it, is not an error.
    let (started, redactor, secrets) = start_with(
        &config(token_file(&dir, &format!("  {token}\n\n"), 0o600)),
        SUBSCRIPTION,
    );
    let hosted = started.expect("the broker starts");
    let line = format!("a log line with {token} in it");
    let cleaned = redactor.redact_str(&line).expect("redacts");
    assert!(!cleaned.output.contains(&token), "{}", cleaned.output);
    assert!(
        cleaned.output.contains("subscription_token"),
        "{}",
        cleaned.output
    );
    use factory_composition::redaction::SecretKind;
    assert_eq!(secrets.count(SecretKind::SubscriptionToken), 1);
    assert!(
        !secrets
            .unregistered_kinds()
            .contains(&SecretKind::BrokerKeys),
        "no API key is required in subscription mode"
    );
    hosted.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn in_subscription_mode_a_token_that_cannot_be_used_stops_start_up_by_name() {
    let dir = scratch("subscription-refused");
    let token = made_up_token();
    let (head, tail) = token.split_at(30);
    let cases = [
        (format!("{head}\n{tail}\n"), 0o600, "wrapped when copied"),
        (format!("{head} {tail}"), 0o600, "wrapped when copied"),
        (format!("{token}\n"), 0o640, "0600"),
        (format!("{token}\n"), 0o700, "0600"),
        (
            ["sk-ant-api03-", &"x".repeat(40)].concat(),
            0o600,
            "sk-ant-oat01-",
        ),
        ("\n".to_owned(), 0o600, "empty"),
    ];
    for (text, mode, expected) in cases {
        let (started, _, _) = start_with(&config(token_file(&dir, &text, mode)), SUBSCRIPTION);
        let message = refusal_text(started);
        assert!(message.contains(expected), "{expected}: {message}");
        assert!(message.contains("claude setup-token"), "{message}");
        assert!(
            !message.contains(tail),
            "the message holds part of the token: {message}"
        );
    }
    let missing = config(SecretFile::at(dir.join("no-such-file")));
    let message = refusal_text(start_with(&missing, SUBSCRIPTION).0);
    assert!(message.contains("does not exist"), "{message}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn in_subscription_mode_production_needs_an_anthropic_entry_and_openai_is_not_started() {
    let dir = scratch("subscription-production");
    let empty = BrokerConfig {
        listen: "127.0.0.1:0".parse().expect("an address"),
        upstreams: Vec::new(),
        prices: Vec::new(),
    };
    let production = CredentialSetting {
        profile: Profile::Production,
        ..SUBSCRIPTION
    };
    let message = refusal_text(start_with(&empty, production).0);
    assert!(message.contains("no anthropic entry"), "{message}");
    // Only an openai entry: Codex is unavailable in this mode, so nothing could serve.
    let mut only_openai = config(key_file(&dir, 0o600));
    only_openai.upstreams[0].provider = "openai".to_owned();
    let message = refusal_text(start_with(&only_openai, SUBSCRIPTION).0);
    assert!(message.contains("no anthropic entry"), "{message}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn in_api_key_mode_a_subscription_token_in_a_key_file_is_refused() {
    let dir = scratch("api-key-with-token");
    let (started, _, _) = start_with(
        &config(token_file(&dir, &made_up_token(), 0o600)),
        API_KEY_MODE,
    );
    let message = match started {
        Err(error) => error.to_string(),
        Ok(_) => panic!("the broker started"),
    };
    assert!(message.contains("mode is api_key"), "{message}");
    let _ = std::fs::remove_dir_all(dir);
}
