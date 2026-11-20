//! The real end-to-end run, for the composed wiring program `scripts/e2e-composed.sh`.
//!
//! These two tests are the program's two commands (`tests/end_to_end/README.md`, "Wirings"). They
//! are ignored in every suite: they call GitHub with the owner's App and their `gh` login, and the
//! model provider with the owner's Claude subscription. Nobody runs them by hand; the program sets
//! their variables and reads what they write in `FACTORY_E2E_OUT`. What the run is, and what in it
//! is real, is in `real/mod.rs`.

#[allow(dead_code, unused_imports)]
#[path = "../../../crates/workflow/tests/validation/cargo.rs"]
mod cargo;
mod e2e;
mod full;
mod live;
#[allow(dead_code)]
mod playbook;
mod real;
mod support;

/// The worker's configuration of a real run parses in the production profile, with GitHub, the
/// broker in front of the real provider and the owner's statement about the bypass list. Nothing
/// here calls anything.
#[test]
fn the_configuration_of_a_real_run_is_a_production_configuration() {
    let root = real::root();
    let scratch = root.join("target/e2e-real/config-check");
    let tenant: uuid::Uuid = "2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60"
        .parse()
        .expect("uuid");
    let owner: uuid::Uuid = "0190a3b2-7c4d-4e5f-8a6b-0000000000aa"
        .parse()
        .expect("uuid");
    let text = real::worker_config(&real::ConfigInputs {
        root: &root,
        scratch: &scratch,
        run: "real-1",
        host: "192.168.65.254",
        port: 8731,
        token_file: std::path::Path::new("/Users/someone/claud-oauth-token.txt"),
        app_id: 123_456,
        key_file: std::path::Path::new("/Users/someone/app.pem"),
        repo: "someone/word-count-fixture",
        tenant,
        installation: 777,
        owner,
        now: "2026-11-13T10:00:00Z".to_owned(),
        commit: "0123456789abcdef0123456789abcdef01234567",
        docker_host: Some("unix:///Users/someone/.colima/software-factory/docker.sock".to_owned()),
    });
    let config = factory_composition::config::FactoryConfig::from_yaml(&text)
        .unwrap_or_else(|error| panic!("{error}\n{text}"));
    assert_eq!(
        config.profile,
        factory_composition::profile::Profile::Production
    );
    let github = config.github.as_ref().expect("github");
    assert_eq!(github.app_id, 123_456);
    assert_eq!(github.api_base_url, "https://api.github.com");
    assert_eq!(github.installations.len(), 1);
    assert_eq!(github.bypass_attestations.len(), 1);
    assert_eq!(config.broker.upstreams.len(), 1, "anthropic only");
    assert_eq!(config.broker.upstreams[0].provider, "anthropic");
    assert_eq!(
        config.sandbox.docker_host.as_deref(),
        Some("unix:///Users/someone/.colima/software-factory/docker.sock"),
        "the worker's docker client talks to the run's own daemon"
    );
}

/// While the specification waits with questions, the owner is told the exact command that answers
/// them, command first and then the options, with one `Q-00N: <answer>` per question, and the
/// questions themselves. With no question there is no such line.
#[test]
fn the_owner_is_told_how_to_answer_the_questions_of_a_waiting_specification() {
    let questions = vec![
        (
            "Q-001".to_owned(),
            "Should the --help text add a line for --json?".to_owned(),
        ),
        ("Q-002".to_owned(), "Which exit code on error?".to_owned()),
    ];
    let text = real::answer_lines(
        "factory-cli",
        "--api http://127.0.0.1:8080 --token-file /tmp/t",
        "J",
        "R",
        &questions,
    );
    assert!(
        text.contains(
            "Answer it:   factory-cli answer --api http://127.0.0.1:8080 --token-file /tmp/t J R -- Q-001: <answer> Q-002: <answer>"
        ),
        "{text}"
    );
    assert!(text.contains("Q-001: Should the --help text add a line for --json?"));
    assert!(text.contains("Q-002: Which exit code on error?"));
    assert_eq!(
        real::answer_lines("factory-cli", "--api x", "J", "R", &[]),
        ""
    );
}

/// The configuration the `protection` command reads the default branch's protection with parses.
/// It holds only GitHub for real: the sandbox and the broker are there because the configuration
/// requires them, and that command starts neither. The first real run on 2026-11-15 stopped here
/// with "missing field `sandbox`".
#[test]
fn the_configuration_that_reads_the_protection_parses() {
    let root = real::root();
    let text = real::protection_config(
        &root,
        123_456,
        std::path::Path::new("/Users/someone/app.pem"),
        "2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60"
            .parse()
            .expect("uuid"),
        "someone/word-count-fixture",
        777,
    );
    let config = factory_composition::config::FactoryConfig::from_yaml(&text)
        .unwrap_or_else(|error| panic!("{error}\n{text}"));
    let github = config.github.as_ref().expect("github");
    assert_eq!(github.app_id, 123_456);
    assert_eq!(github.installations.len(), 1);
    assert_eq!(github.installations[0].installation_id, 777);
}

/// The record of the App's requests keeps the method and path of each, and the permissions and
/// repositories of each installation token asked for, and never a header.
#[tokio::test]
async fn the_record_of_the_apps_requests_keeps_paths_and_permissions_and_no_header() {
    use factory_github::{Method, Transport, TransportError, WireRequest, WireResponse};
    struct Answers;
    #[async_trait::async_trait]
    impl Transport for Answers {
        async fn execute(&self, _: WireRequest) -> Result<WireResponse, TransportError> {
            Ok(WireResponse {
                status: 201,
                headers: Vec::new(),
                body: b"{}".to_vec(),
            })
        }
    }
    let recorder = std::sync::Arc::new(real::Recorder::default());
    let transport = (recorder.wrapper())(std::sync::Arc::new(Answers));
    transport
        .execute(WireRequest {
            method: Method::Post,
            target: "/app/installations/777/access_tokens".to_owned(),
            headers: vec![(
                "authorization".to_owned(),
                "Bearer secret-jwt-value".to_owned(),
            )],
            body: br#"{"repositories":["word-count-fixture"],"permissions":{"contents":"write","metadata":"read"}}"#.to_vec(),
        })
        .await
        .expect("an answer");
    transport
        .execute(WireRequest {
            method: Method::Get,
            target: "/repos/someone/word-count-fixture/issues/3?per_page=100".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .await
        .expect("an answer");
    assert_eq!(
        recorder.requests(),
        vec![
            (
                "POST".to_owned(),
                "/app/installations/777/access_tokens".to_owned()
            ),
            (
                "GET".to_owned(),
                "/repos/someone/word-count-fixture/issues/3".to_owned()
            ),
        ]
    );
    let mints = recorder.mints();
    assert_eq!(mints.len(), 1);
    assert_eq!(mints[0].0["contents"], "write");
    assert_eq!(mints[0].1, vec!["word-count-fixture".to_owned()]);
    let everything = format!("{:?}{:?}", recorder.requests(), recorder.mints());
    assert!(!everything.contains("secret-jwt-value"));
}

/// `PROGRAM protection`: the protection of the fixture's default branch, read through the App.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "calls GitHub with the owner's App; only scripts/e2e-composed.sh runs it"]
async fn the_protection_of_the_fixture_repository() {
    real::protection().await;
}

/// `PROGRAM run SCENARIO`: the scenario against GitHub and the owner's subscription.
#[test]
#[ignore = "calls GitHub and the model provider with the owner's credentials; only scripts/e2e-composed.sh runs it"]
fn the_real_scenario() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(real::scenario());
}
