//! The world the adapter is tested in: the fake GitHub server of the test kit (FX-GH) on the
//! loopback interface, behind a small front that answers the few routes FX-GH does not have.
//!
//! The front exists because FX-GH is a fake of the routes the factory used before ports-v1.1. It
//! has no rules route (the preflight), no comment-by-id route (`fetch_comment`), no check-run
//! update or listing route (`publish_check`) and no way to rename an issue. The front adds those
//! as plain, labelled stand-ins: the rules and comments it serves are what a test seeded, not
//! recorded GitHub answers. Every request still goes through FX-GH's token check first (a probe
//! with the same `Authorization` header), so an expired, revoked or wrong-repository token is
//! refused by the same code that refuses it on every other route.
//!
//! Everything here is labelled fake; nothing leaves the machine.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::redaction::Redactor;
use factory_github::{
    ApiBase, GithubAdapter, GithubConfig, GithubParts, InstallationDirectory, RingRs256Signer,
    Sleeper, StaticInstallations, Transport, UreqTransport,
};
use factory_ports::githost::AppId;
use factory_ports::store::InstallationId;
use factory_testkit::clock::FakeClock;
use factory_testkit::contracts::githost::scope;
use factory_testkit::fx::digest::sha256;
use factory_testkit::fx::encoding::hex_encode;
use factory_testkit::fx::github::{AppConfig, FakeGithub, User};
use factory_testkit::fx::http::{HttpRequest, HttpResponse, HttpServer};
use serde_json::{Value, json};

use super::keys::{Form, Throwaway};
use super::policy;

pub const FIXTURE: &str = "example-org/fixture";
pub const OTHER: &str = "example-org/other";
pub const INSTALLATION: u64 = 1;

/// The key all tests of one process sign with. Made once; the files are removed at once.
fn private_pem() -> &'static str {
    static PEM: OnceLock<String> = OnceLock::new();
    PEM.get_or_init(|| Throwaway::new(Form::Pkcs8).private_pem.clone())
}

/// A sleeper that records the waits and does not sleep.
#[derive(Debug, Default)]
pub struct RecordingSleeper {
    waits: Mutex<Vec<Duration>>,
}

impl RecordingSleeper {
    pub fn waits(&self) -> Vec<Duration> {
        self.waits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl Sleeper for RecordingSleeper {
    async fn sleep(&self, duration: Duration) {
        self.waits
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(duration);
    }
}

/// A check run as the front records it.
#[derive(Debug, Clone)]
pub struct CheckRecord {
    pub id: u64,
    pub repo: String,
    pub name: String,
    pub head_sha: String,
    pub external_id: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub app_id: u64,
    pub title: String,
    pub summary: String,
}

/// What the front serves on its own routes.
#[derive(Default)]
pub struct Extras {
    pub comments: Mutex<HashMap<(String, u64), Value>>,
    pub rules: Mutex<BTreeMap<String, Value>>,
    pub checks: Mutex<Vec<CheckRecord>>,
    pub titles: Mutex<HashMap<(String, u64), String>>,
    pub issue_counters: Mutex<HashMap<String, u64>>,
    pub foreign_comments: Mutex<HashMap<(String, u64), Vec<Value>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn iso(seconds: i64) -> String {
    factory_testkit::fx::timeutil::format_rfc3339(seconds)
}

fn probe(
    fake: &FakeGithub,
    request: &HttpRequest,
    owner: &str,
    repo: &str,
) -> Option<HttpResponse> {
    let probe = HttpRequest {
        method: "GET".to_owned(),
        target: format!("/repos/{owner}/{repo}"),
        version: "HTTP/1.1".to_owned(),
        headers: request
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .cloned()
            .collect(),
        body: Vec::new(),
        peer: request.peer,
    };
    let response = fake.handle(&probe);
    (response.status != 200).then_some(response)
}

fn front(fake: &FakeGithub, extras: &Extras, request: &HttpRequest) -> HttpResponse {
    let segments: Vec<String> = request
        .path()
        .trim_matches('/')
        .split('/')
        .map(factory_testkit::fx::http::percent_decode)
        .collect();
    let s: Vec<&str> = segments.iter().map(String::as_str).collect();
    let method = request.method.as_str();
    match (method, s.as_slice()) {
        ("GET", ["repos", owner, repo, "issues", "comments", id]) => {
            if let Some(refused) = probe(fake, request, owner, repo) {
                return refused;
            }
            let found = lock(&extras.comments)
                .get(&(format!("{owner}/{repo}"), id.parse().unwrap_or(0)))
                .cloned();
            found.map_or_else(
                || HttpResponse::json(404, &json!({"message": "Not Found"})),
                |comment| HttpResponse::json(200, &comment),
            )
        }
        ("GET", ["repos", owner, repo, "issues", number, "comments"])
            if lock(&extras.foreign_comments)
                .contains_key(&(format!("{owner}/{repo}"), number.parse().unwrap_or(0))) =>
        {
            // The comments of the fake, then the ones other people wrote, which the fake cannot.
            let response = fake.handle(request);
            if response.status != 200 {
                return response;
            }
            let mut list: Vec<Value> = serde_json::from_slice(&response.body).unwrap_or_default();
            if let Some(more) = lock(&extras.foreign_comments)
                .get(&(format!("{owner}/{repo}"), number.parse().unwrap_or(0)))
            {
                list.extend(more.iter().cloned());
            }
            HttpResponse::json(200, &Value::Array(list))
        }
        ("GET", ["repos", owner, repo, "rules", "branches", _branch]) => {
            if let Some(refused) = probe(fake, request, owner, repo) {
                return refused;
            }
            let rules = lock(&extras.rules)
                .get(&format!("{owner}/{repo}"))
                .cloned()
                .unwrap_or_else(|| json!([]));
            HttpResponse::json(200, &rules)
        }
        ("GET", ["repos", owner, repo, "issues", number])
            if lock(&extras.titles)
                .contains_key(&(format!("{owner}/{repo}"), number.parse().unwrap_or(0))) =>
        {
            // A renamed issue: forward without the validator, then put the new title in.
            let mut forwarded = request.clone_without_header("if-none-match");
            forwarded.method = "GET".to_owned();
            let response = fake.handle(&forwarded);
            if response.status != 200 {
                return response;
            }
            let mut value: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
            let title = lock(&extras.titles)
                .get(&(format!("{owner}/{repo}"), number.parse().unwrap_or(0)))
                .cloned();
            if let Some(title) = title {
                value["title"] = json!(title);
            }
            let etag = format!(
                "W/\"{}\"",
                hex_encode(&sha256(value.to_string().as_bytes())[..8], false)
            );
            if request.header("if-none-match") == Some(etag.as_str()) {
                return HttpResponse::empty(304).with_header("ETag", &etag);
            }
            HttpResponse::json(200, &value).with_header("ETag", &etag)
        }
        ("POST", ["repos", owner, repo, "check-runs"]) => {
            let response = fake.handle(request);
            if response.status == 201 {
                let sent: Value = request.json().unwrap_or(Value::Null);
                let made: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
                lock(&extras.checks).push(CheckRecord {
                    id: made["id"].as_u64().unwrap_or(0),
                    repo: format!("{owner}/{repo}"),
                    name: sent["name"].as_str().unwrap_or_default().to_owned(),
                    head_sha: sent["head_sha"].as_str().unwrap_or_default().to_owned(),
                    external_id: sent["external_id"].as_str().unwrap_or_default().to_owned(),
                    status: sent["status"].as_str().unwrap_or("queued").to_owned(),
                    conclusion: sent["conclusion"].as_str().map(str::to_owned),
                    app_id: made["app"]["id"].as_u64().unwrap_or(0),
                    title: sent["output"]["title"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    summary: sent["output"]["summary"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                });
            }
            response
        }
        ("PATCH", ["repos", owner, repo, "check-runs", id]) => {
            if let Some(refused) = probe(fake, request, owner, repo) {
                return refused;
            }
            let sent: Value = request.json().unwrap_or(Value::Null);
            let mut checks = lock(&extras.checks);
            let Some(record) = checks
                .iter_mut()
                .find(|c| c.id.to_string() == *id && c.repo == format!("{owner}/{repo}"))
            else {
                return HttpResponse::json(404, &json!({"message": "Not Found"}));
            };
            if let Some(status) = sent["status"].as_str() {
                record.status = status.to_owned();
            }
            record.conclusion = sent["conclusion"].as_str().map(str::to_owned);
            if let Some(title) = sent["output"]["title"].as_str() {
                title.clone_into(&mut record.title);
            }
            if let Some(summary) = sent["output"]["summary"].as_str() {
                summary.clone_into(&mut record.summary);
            }
            HttpResponse::json(200, &check_json(record))
        }
        ("GET", ["repos", owner, repo, "commits", sha, "check-runs"]) => {
            if let Some(refused) = probe(fake, request, owner, repo) {
                return refused;
            }
            let name = request.query_param("check_name");
            let app = request.query_param("app_id");
            let runs: Vec<Value> = lock(&extras.checks)
                .iter()
                .filter(|c| c.repo == format!("{owner}/{repo}") && c.head_sha == *sha)
                .filter(|c| name.as_ref().is_none_or(|n| &c.name == n))
                .filter(|c| app.as_ref().is_none_or(|a| c.app_id.to_string() == *a))
                .map(check_json)
                .collect();
            HttpResponse::json(200, &json!({"total_count": runs.len(), "check_runs": runs}))
        }
        _ => fake.handle(request),
    }
}

fn check_json(c: &CheckRecord) -> Value {
    json!({"id": c.id, "name": c.name, "head_sha": c.head_sha, "external_id": c.external_id,
           "status": c.status, "conclusion": c.conclusion, "app": {"id": c.app_id}})
}

trait CloneWithout {
    fn clone_without_header(&self, name: &str) -> HttpRequest;
}

impl CloneWithout for HttpRequest {
    fn clone_without_header(&self, name: &str) -> HttpRequest {
        HttpRequest {
            method: self.method.clone(),
            target: self.target.clone(),
            version: self.version.clone(),
            headers: self
                .headers
                .iter()
                .filter(|(n, _)| !n.eq_ignore_ascii_case(name))
                .cloned()
                .collect(),
            body: self.body.clone(),
            peer: self.peer,
        }
    }
}

/// Puts a decorator around the real transport.
pub type WrapTransport = Box<dyn FnOnce(Arc<dyn Transport>) -> Arc<dyn Transport>>;

/// Changes the adapter settings before the adapter is built.
pub type ConfigureAdapter = Box<dyn FnOnce(&mut GithubConfig)>;

/// How a test changes the world before it starts.
#[derive(Default)]
pub struct Options {
    pub app: Option<AppConfig>,
    pub wrap: Option<WrapTransport>,
    pub configure: Option<ConfigureAdapter>,
}

pub struct World {
    pub fake: FakeGithub,
    pub clock: Arc<FakeClock>,
    pub server: HttpServer,
    pub extras: Arc<Extras>,
    pub adapter: GithubAdapter,
    pub sleeper: Arc<RecordingSleeper>,
    pub redactor: Arc<Redactor>,
}

impl World {
    pub fn new() -> Self {
        Self::with(Options::default())
    }

    pub fn with(options: Options) -> Self {
        let clock = Arc::new(FakeClock::starting_at("2026-10-28T10:00:00Z"));
        let fake = FakeGithub::with_clock(clock.clone());
        if let Some(app) = options.app {
            fake.set_app(app);
        }
        fake.add_repo(FIXTURE, "main");
        fake.add_repo(OTHER, "main");
        fake.add_installation(INSTALLATION, "example-org", &[FIXTURE, OTHER]);
        for (login, id) in [("octocat", 1), ("maintainer", 77), ("outsider", 90)] {
            fake.add_user(User::person(login, id, "write", "MEMBER"));
        }
        for branch in ["factory/job-1", "factory/job-2", "factory/job-3"] {
            fake.push_commit(FIXTURE, branch);
        }
        let extras = Arc::new(Extras::default());
        let server = {
            let fake = fake.clone();
            let extras = Arc::clone(&extras);
            HttpServer::start("fx-github-front", move |request| {
                front(&fake, &extras, request)
            })
            .expect("the front server starts")
        };
        let base = ApiBase::loopback_for_tests(&server.base_url()).expect("a loopback base");
        let mut transport: Arc<dyn Transport> = Arc::new(UreqTransport::new(base.clone()));
        if let Some(wrap) = options.wrap {
            transport = wrap(transport);
        }
        let redactor = Arc::new(policy::redactor());
        let sleeper = Arc::new(RecordingSleeper::default());
        let tenant = scope(1, 1).tenant;
        let directory: Arc<dyn InstallationDirectory> = Arc::new(
            StaticInstallations::new()
                .bind(
                    tenant,
                    factory_ports::paths::RepoRef::parse(FIXTURE).unwrap(),
                    InstallationId(INSTALLATION),
                )
                .bind(
                    tenant,
                    factory_ports::paths::RepoRef::parse(OTHER).unwrap(),
                    InstallationId(INSTALLATION),
                ),
        );
        let mut config = GithubConfig::new(AppId(fake.app().id), base, policy::app_policy());
        if let Some(configure) = options.configure {
            configure(&mut config);
        }
        let adapter = GithubAdapter::new(
            config,
            GithubParts {
                transport,
                signer: Arc::new(RingRs256Signer::from_pem(private_pem()).expect("the test key")),
                clock: clock.clone(),
                redactor: Arc::clone(&redactor),
                directory,
                sleeper: sleeper.clone(),
            },
        );
        Self {
            fake,
            clock,
            server,
            extras,
            adapter,
            sleeper,
            redactor,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.server.addr()
    }
}
