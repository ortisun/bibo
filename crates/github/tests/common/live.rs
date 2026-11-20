//! Helpers for the live tests, which talk to the real GitHub with a registered App.
//!
//! NOTHING IN THIS FILE HAS EVER RUN. No App is registered yet. The code compiles and is written
//! from the documentation; every call it makes is UNVERIFIED until a person has run it with the
//! credentials below. Without them the live tests stop with a message that starts `BLOCKED:`.
//! Without `FACTORY_LIVE=1` they do nothing and say so.

use std::sync::Arc;

use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_github::{
    ApiBase, AppJwt, GithubAdapter, GithubConfig, GithubParts, Method, RingRs256Signer,
    StaticInstallations, TokioSleeper, Transport, UreqTransport, WireRequest,
};
use factory_ports::clock::Clock;
use factory_ports::githost::{AppId, GitScope};
use factory_ports::paths::RepoRef;
use factory_ports::store::InstallationId;
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::timeutil::format_rfc3339;
use serde_json::{Value, json};

use super::policy;

/// The system time, for the live runs only.
pub struct SystemClock;

impl Clock for SystemClock {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }
    fn now(&self) -> Timestamp {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
        Timestamp::parse(&format_rfc3339(seconds)).expect("a valid time")
    }
}

/// True when the person asked for live runs.
pub fn live_requested() -> bool {
    std::env::var("FACTORY_LIVE").is_ok_and(|v| v == "1")
}

/// Reads the named variables, or stops the test with `BLOCKED:` and the list of what is missing.
pub fn require(what: &str, names: &[&str]) -> Vec<String> {
    let values: Vec<Option<String>> = names
        .iter()
        .map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()))
        .collect();
    let missing: Vec<&str> = names
        .iter()
        .zip(&values)
        .filter(|(_, v)| v.is_none())
        .map(|(n, _)| *n)
        .collect();
    assert!(
        missing.is_empty(),
        "BLOCKED: {what} needs a registered GitHub App and a protected fixture repository, and these \
         are not set: {}. A person must provide: the App id, the App's private key as a file \
         (its path), the installation id of the fixture repository, and the fixture repository as \
         owner/name with a pushed branch under factory/ that differs from the default branch.",
        missing.join(", ")
    );
    values.into_iter().flatten().collect()
}

/// One registered App and the installation that covers the fixture repository.
pub struct LiveApp {
    pub app_id: u64,
    pub installation: u64,
    pub key_pem: String,
    pub repo: RepoRef,
}

impl LiveApp {
    /// Reads the App from `<prefix>_APP_ID`, `<prefix>_PRIVATE_KEY_PATH` and
    /// `<prefix>_INSTALLATION_ID`, and the repository from `FACTORY_GITHUB_FIXTURE_REPO`.
    pub fn from_env(what: &str, prefix: &str) -> Self {
        let id = format!("{prefix}_APP_ID");
        let key = format!("{prefix}_PRIVATE_KEY_PATH");
        let installation = format!("{prefix}_INSTALLATION_ID");
        let v = require(
            what,
            &[&id, &key, &installation, "FACTORY_GITHUB_FIXTURE_REPO"],
        );
        Self {
            app_id: v[0].parse().expect("the App id is a number"),
            key_pem: std::fs::read_to_string(&v[1]).expect("the private key file can be read"),
            installation: v[2].parse().expect("the installation id is a number"),
            repo: RepoRef::parse(&v[3]).expect("the fixture repository is owner/name"),
        }
    }

    /// An adapter for this App against the real API.
    pub fn adapter(&self) -> GithubAdapter {
        let tenant = scope(1, 1).tenant;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        GithubAdapter::new(
            GithubConfig::new(
                AppId(self.app_id),
                ApiBase::github_com(),
                policy::app_policy(),
            ),
            GithubParts {
                transport: Arc::new(UreqTransport::new(ApiBase::github_com())),
                signer: Arc::new(
                    RingRs256Signer::from_pem(&self.key_pem).expect("a usable private key"),
                ),
                clock,
                redactor: Arc::new(policy::redactor()),
                directory: Arc::new(StaticInstallations::new().bind(
                    tenant,
                    self.repo.clone(),
                    InstallationId(self.installation),
                )),
                sleeper: Arc::new(TokioSleeper),
            },
        )
    }

    pub fn scope(&self, stage: StageKind, job: u128) -> GitScope {
        GitScope {
            stage,
            repo: self.repo.clone(),
            ..scope(1, job)
        }
    }

    /// A token with the permissions named, made the way the adapter makes one, for the calls the
    /// adapter does not have (closing a pull request, reading the merge state). Test use only.
    pub async fn token_for_test(&self, permissions: &Value) -> String {
        let transport = UreqTransport::new(ApiBase::github_com());
        let signer = RingRs256Signer::from_pem(&self.key_pem).expect("a usable private key");
        let jwt = AppJwt::make(self.app_id, &SystemClock.now(), &signer).expect("a JWT");
        let body = json!({"repositories": [self.repo.name()], "permissions": permissions});
        let response = transport
            .execute(WireRequest {
                method: Method::Post,
                target: format!("/app/installations/{}/access_tokens", self.installation),
                headers: vec![
                    (
                        "Authorization".to_owned(),
                        format!("Bearer {}", jwt.expose()),
                    ),
                    (
                        "Accept".to_owned(),
                        "application/vnd.github+json".to_owned(),
                    ),
                    ("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned()),
                    ("Content-Type".to_owned(), "application/json".to_owned()),
                ],
                body: body.to_string().into_bytes(),
            })
            .await
            .expect("a response");
        assert_eq!(response.status, 201, "the token request was refused");
        let value: Value = serde_json::from_slice(&response.body).expect("JSON");
        value["token"].as_str().expect("a token").to_owned()
    }

    /// Sends one request with an installation token and returns the status and the JSON body.
    pub async fn call(
        &self,
        token: &str,
        method: Method,
        target: &str,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let transport = UreqTransport::new(ApiBase::github_com());
        let response = transport
            .execute(WireRequest {
                method,
                target: target.to_owned(),
                headers: vec![
                    ("Authorization".to_owned(), format!("Bearer {token}")),
                    (
                        "Accept".to_owned(),
                        "application/vnd.github+json".to_owned(),
                    ),
                    ("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned()),
                    ("Content-Type".to_owned(), "application/json".to_owned()),
                ],
                body: body.map(|b| b.to_string().into_bytes()).unwrap_or_default(),
            })
            .await
            .expect("a response");
        (
            response.status,
            serde_json::from_slice(&response.body).unwrap_or(Value::Null),
        )
    }
}
