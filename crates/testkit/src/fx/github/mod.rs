//! FX-GH: a fake GitHub server.
//!
//! It stands in for `api.github.com` in the tests of the GitHub adapter, the API's webhook
//! endpoint, the workflow engine and the end-to-end scenarios. It does three jobs:
//!
//! 1. **Serve a REST subset** that the factory uses, with GitHub's own response shapes, status
//!    codes and error messages: the App and its installations, installation tokens narrowed to
//!    repositories and permissions, issues, their comments and their event list (the only place
//!    that says who applied a label), entity tags with `If-None-Match`, collaborator permission, branches and
//!    protection, refs, pull requests (draft, idempotent by head branch, merge with a `sha` check),
//!    reviews, check runs and commit statuses. Run it over HTTP with [`FakeGithub::serve`], or
//!    call [`FakeGithub::handle`] directly.
//! 2. **Send webhooks**: [`FakeGithub::deliver`] and the typed builders make a signed delivery
//!    with GitHub's headers, and [`webhook`] makes the forged variants that the catalog attacks
//!    with (NT-WH-01 to NT-WH-03), each with the verdict of a reference verifier.
//! 3. **Record everything**: every request, with the `Authorization` value masked (kept as a
//!    length and a fingerprint), every token minted with the exact request body, every revoke,
//!    push, merge attempt and collaborator-permission lookup. A test asserts on these durable
//!    facts and never on log text.
//!
//! # It is labelled fake
//!
//! Each response carries `X-Factory-Fidelity: fake` and `Server: factory-testkit-fake`. Each
//! record, and the JSON export, has `"fidelity": "fake"`. The tokens it mints look like real ones
//! (`ghs_` and 36 characters) and carry the canary marker, so [`FakeGithub::minted_secrets`] can
//! hand them to the sweeper.
//!
//! # What it does not do
//!
//! * It does not verify the RSA signature of the App JWT. It checks the algorithm, the issuer and
//!   the lifetime claims, and that a signature is present. No RSA verification is on the testkit's
//!   allow list. The JWT code in the adapter is checked against a known-answer signature by the
//!   adapter's own tests.
//! * It does not speak the git smart-HTTP protocol. A "push" appears when the adapter uses the
//!   refs API, or when a test calls [`FakeGithub::push_commit`].
//! * It serves REST only. There is no GraphQL endpoint; use [`FakeGithub::mark_ready`] to flip a
//!   draft in a test.
//! * Branch protection is read two ways, as in GitHub. The branch endpoint shows the summary a
//!   token with push access sees. The protection endpoint needs the `administration` permission,
//!   which the factory's App must not hold (`policies/security.yaml`, `credentials.github_app`),
//!   so an adapter that calls it with a stage token gets a 403 here, as it would there.

mod routes;
pub mod webhook;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use factory_ports::clock::Clock;
use serde_json::{Value, json};

use super::canary::{Canary, CanaryKind};
use super::digest::sha256;
use super::encoding::hex_encode;
use super::http::{HttpRequest, HttpResponse, HttpServer};
use super::rng::{ALPHANUMERIC, FxRng, HEX_LOWER};
use super::timeutil::format_rfc3339;

pub use webhook::{
    Attack, Delivery, Expect, Reason, ReceiveOutcome, ReferenceReceiver, ReferenceVerifier,
    Rejection, Verdict, sign_sha1, sign_sha256, verdict_matches,
};

/// The documentation link GitHub puts in an error body.
pub(crate) const DOCS: &str = "https://docs.github.com/rest";

/// An installation token lives one hour, as on GitHub.
pub const TOKEN_LIFETIME_SECONDS: i64 = 3600;

/// The permission names and levels the fake knows about, lowest level first.
pub(crate) fn level_rank(level: &str) -> u8 {
    match level {
        "read" => 1,
        "write" => 2,
        "admin" => 3,
        _ => 0,
    }
}

/// The App the fake stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    /// The numeric App id (the `iss` claim of its JWT).
    pub id: u64,
    /// The App slug. Its bot account is `<slug>[bot]`.
    pub slug: String,
    /// The permissions the App holds, as a map from name to `read`, `write` or `admin`.
    pub permissions: BTreeMap<String, String>,
}

impl AppConfig {
    /// The App as `policies/security.yaml` says it must be: the required permissions and none of
    /// the forbidden ones.
    #[must_use]
    pub fn factory_default() -> Self {
        let permissions = [
            ("metadata", "read"),
            ("contents", "write"),
            ("pull_requests", "write"),
            ("issues", "write"),
            ("checks", "write"),
            ("statuses", "write"),
            ("actions", "read"),
        ]
        .into_iter()
        .map(|(name, level)| (name.to_owned(), level.to_owned()))
        .collect();
        Self {
            id: 424_242,
            slug: "factory-test-app".to_owned(),
            permissions,
        }
    }

    /// Adds or changes one permission. Use it to make an App that holds a forbidden one
    /// (NT-AUTHZ-09) or lacks a required one.
    #[must_use]
    pub fn with_permission(mut self, name: &str, level: &str) -> Self {
        self.permissions.insert(name.to_owned(), level.to_owned());
        self
    }

    /// Removes a permission.
    #[must_use]
    pub fn without_permission(mut self, name: &str) -> Self {
        self.permissions.remove(name);
        self
    }

    /// The login of the App's bot account.
    #[must_use]
    pub fn bot_login(&self) -> String {
        format!("{}[bot]", self.slug)
    }

    /// The numeric id of the App's bot account.
    #[must_use]
    pub fn bot_id(&self) -> u64 {
        self.id + 1_000_000
    }
}

/// A GitHub account the fake knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// The login.
    pub login: String,
    /// The numeric id. Authority in the factory is keyed by this, never by the login.
    pub id: u64,
    /// The repository role the fake reports for the collaborator-permission endpoint:
    /// `admin`, `maintain`, `write`, `triage`, `read` or `none`.
    pub role: String,
    /// The `author_association` the fake puts in payloads: `OWNER`, `MEMBER`, `COLLABORATOR`,
    /// `CONTRIBUTOR`, `NONE`. Tests set it high for someone who is not on the allowlist, to show
    /// that a role grants nothing.
    pub association: String,
    /// True for a bot account.
    pub is_bot: bool,
}

impl User {
    /// A person with the given role and association.
    #[must_use]
    pub fn person(login: &str, id: u64, role: &str, association: &str) -> Self {
        Self {
            login: login.to_owned(),
            id,
            role: role.to_owned(),
            association: association.to_owned(),
            is_bot: false,
        }
    }

    pub(crate) fn json(&self) -> Value {
        json!({
            "login": self.login,
            "id": self.id,
            "node_id": format!("U_fake_{}", self.id),
            "type": if self.is_bot { "Bot" } else { "User" },
        })
    }
}

/// One required status check of a branch protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredCheck {
    /// The check name.
    pub context: String,
    /// The App the check must come from. `None` accepts any source, which is the weak setting
    /// the preflight rejects.
    pub app_id: Option<u64>,
}

/// A branch protection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Protection {
    /// Checks that must pass before a merge.
    pub required_checks: Vec<RequiredCheck>,
    /// Approving reviews needed. Zero means none are required.
    pub required_approvals: u32,
    /// Whether a pull request is required at all.
    pub require_pull_request: bool,
    /// Whether the rules apply to administrators.
    pub enforce_admins: bool,
    /// Whether a new commit dismisses earlier approvals.
    pub dismiss_stale_reviews: bool,
    /// Whether force pushes are allowed.
    pub allow_force_pushes: bool,
    /// Whether the branch can be deleted.
    pub allow_deletions: bool,
    /// Apps that may bypass the pull request requirement. The factory's App must not be here.
    pub bypass_apps: Vec<String>,
}

impl Protection {
    /// A protection that satisfies every item of `credentials.repository_requirements`: a pull
    /// request is required, the checks are pinned to the App, stale approvals are dismissed,
    /// force pushes and deletion are off, the App is not on a bypass list.
    #[must_use]
    pub fn satisfying_the_policy(app_id: u64) -> Self {
        Self {
            required_checks: vec![RequiredCheck {
                context: "ci".to_owned(),
                app_id: Some(app_id),
            }],
            required_approvals: 1,
            require_pull_request: true,
            enforce_admins: true,
            dismiss_stale_reviews: true,
            allow_force_pushes: false,
            allow_deletions: false,
            bypass_apps: Vec::new(),
        }
    }
}

/// What a request carried as proof of who sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthSummary {
    /// No `Authorization` header.
    None,
    /// An App JWT.
    AppJwt {
        /// The `iss` claim.
        issuer: String,
    },
    /// An installation token the fake issued.
    InstallationToken {
        /// The fake's own id for the token (1 for the first minted).
        token_id: u64,
    },
    /// Something the fake does not recognise: an unknown token, a malformed JWT, a revoked or
    /// expired token (see `reason`).
    Rejected {
        /// Why it was refused.
        reason: String,
    },
}

/// One request the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRecord {
    /// 1 for the first request.
    pub seq: u64,
    /// Seconds since the epoch, from the fake's clock.
    pub at: i64,
    /// The method.
    pub method: String,
    /// The path.
    pub path: String,
    /// The query string, if any.
    pub query: Option<String>,
    /// The route template, such as `POST /repos/{owner}/{repo}/pulls`, or `UNROUTED`.
    pub route: String,
    /// The headers as received, except that the value of `Authorization` is masked.
    pub headers: Vec<(String, String)>,
    /// The body as received.
    pub body: Vec<u8>,
    /// Who the request said it was.
    pub auth: AuthSummary,
    /// The status the fake answered with.
    pub status: u16,
}

impl RequestRecord {
    /// The body as text.
    #[must_use]
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON, if it is.
    #[must_use]
    pub fn body_json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// The request as one block of text: request line, headers (with the masked
    /// `Authorization`), a blank line and the body. The sink collector sweeps this.
    #[must_use]
    pub fn as_text(&self) -> String {
        let mut text = format!(
            "{} {}{}\n",
            self.method,
            self.path,
            self.query
                .as_ref()
                .map_or(String::new(), |q| format!("?{q}"))
        );
        for (name, value) in &self.headers {
            text.push_str(&format!("{name}: {value}\n"));
        }
        text.push('\n');
        text.push_str(&self.body_text());
        text
    }

    /// The record as JSON, with the fidelity label.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "fidelity": "fake",
            "seq": self.seq,
            "at": self.at,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "route": self.route,
            "headers": self.headers,
            "body": self.body_text(),
            "auth": format!("{:?}", self.auth),
            "status": self.status,
        })
    }
}

/// One installation token that was minted, with the request that asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRecord {
    /// The sequence number of the request in the log.
    pub request_seq: u64,
    /// The fake's id for the token.
    pub token_id: u64,
    /// The installation.
    pub installation_id: u64,
    /// The request body exactly as sent, if there was one.
    pub request_body: Option<Value>,
    /// The `repositories` the caller asked for, or `None` when it did not narrow the token.
    pub requested_repositories: Option<Vec<String>>,
    /// The `permissions` the caller asked for, or `None` when it asked for all of the App's.
    pub requested_permissions: Option<BTreeMap<String, String>>,
    /// The repositories the token covers.
    pub granted_repositories: Vec<String>,
    /// The permissions the token carries.
    pub granted_permissions: BTreeMap<String, String>,
}

/// What the fake knows about one token, without its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenView {
    /// The fake's id for the token.
    pub id: u64,
    /// The installation.
    pub installation_id: u64,
    /// The repositories it covers, as `owner/name`.
    pub repositories: Vec<String>,
    /// The permissions it carries.
    pub permissions: BTreeMap<String, String>,
    /// Seconds since the epoch when it stops working.
    pub expires_at: i64,
    /// Seconds since the epoch when it was revoked.
    pub revoked_at: Option<i64>,
    /// How many requests used it while it was valid.
    pub uses: u32,
    /// How many requests tried it after it was revoked. Each was refused.
    pub uses_after_revoke: u32,
}

/// A change of a branch that a test can look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushRecord {
    /// `owner/name`.
    pub repo: String,
    /// The branch.
    pub branch: String,
    /// `create`, `update` or `delete`.
    pub kind: String,
    /// The commit the branch points at afterwards (empty for a delete).
    pub sha: String,
    /// The fake's id of the token that did it, or `None` for a change made by a test.
    pub token_id: Option<u64>,
}

/// A failure to return in place of the normal answer.
#[derive(Debug, Clone)]
pub(crate) struct Fault {
    pub route: String,
    pub status: u16,
    pub message: String,
    pub headers: Vec<(String, String)>,
    pub remaining: Option<u32>,
}

#[derive(Debug, Clone)]
pub(crate) struct TokenRecord {
    pub id: u64,
    pub value: String,
    pub installation_id: u64,
    pub repositories: Vec<String>,
    pub permissions: BTreeMap<String, String>,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub uses: u32,
    pub uses_after_revoke: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct Installation {
    pub id: u64,
    pub account_login: String,
    pub account_id: u64,
    pub repositories: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Issue {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub state: String,
    /// True for the issue record that GitHub keeps for every pull request.
    pub is_pull: bool,
    pub author: String,
    pub labels: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub comments: Vec<Comment>,
    /// The timeline GitHub serves at `/issues/{n}/events`: who labelled, unlabelled or closed.
    pub events: Vec<IssueEvent>,
}

/// One entry of an issue's event list. The `labeled` event is the only place the API says who
/// applied a label.
#[derive(Debug, Clone)]
pub(crate) struct IssueEvent {
    pub id: u64,
    pub event: String,
    pub actor: String,
    pub label: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct Comment {
    pub id: u64,
    pub author: String,
    pub body: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct Review {
    pub id: u64,
    pub author: String,
    pub state: String,
    pub commit_id: String,
    pub body: String,
}

#[derive(Debug, Clone)]
pub(crate) struct Pull {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub state: String,
    pub draft: bool,
    pub merged: bool,
    pub merge_commit_sha: Option<String>,
    pub head_ref: String,
    pub head_sha: String,
    pub base_ref: String,
    pub author: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub reviews: Vec<Review>,
}

#[derive(Debug, Clone)]
pub(crate) struct CheckRun {
    pub name: String,
    pub head_sha: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub app_id: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Repo {
    pub id: u64,
    pub full_name: String,
    pub default_branch: String,
    pub branches: BTreeMap<String, String>,
    pub protection: BTreeMap<String, Protection>,
    pub next_number: u64,
    pub issues: BTreeMap<u64, Issue>,
    pub pulls: BTreeMap<u64, Pull>,
    pub checks: Vec<CheckRun>,
    pub statuses: Vec<Value>,
}

/// Everything the fake holds. Locked as a whole for each request, so a request is atomic.
#[derive(Debug)]
pub(crate) struct State {
    pub app: AppConfig,
    pub webhook_secrets: Vec<String>,
    pub installations: BTreeMap<u64, Installation>,
    pub repos: BTreeMap<String, Repo>,
    pub users: BTreeMap<String, User>,
    pub tokens: Vec<TokenRecord>,
    pub mints: Vec<MintRecord>,
    pub pushes: Vec<PushRecord>,
    pub log: Vec<RequestRecord>,
    pub faults: Vec<Fault>,
    pub rng: FxRng,
    pub next_id: u64,
}

impl State {
    /// A fresh 40-character commit id.
    pub fn new_sha(&mut self) -> String {
        self.rng.string_from(HEX_LOWER, 40)
    }

    /// A fresh numeric id for a comment or a review.
    pub fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

/// A fake GitHub. Cloning gives another handle to the same fake.
#[derive(Clone)]
pub struct FakeGithub {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for FakeGithub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeGithub")
            .field("requests", &self.lock().log.len())
            .finish_non_exhaustive()
    }
}

impl Default for FakeGithub {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeGithub {
    /// A fake with the factory's App, a generated webhook secret, no repositories and a clock
    /// that only moves when the test moves it.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Arc::new(crate::clock::FakeClock::new()))
    }

    /// A fake that reads time from this clock. Share a `FakeClock` with the code under test so
    /// token expiry and JWT lifetimes agree.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        let mut rng = FxRng::from_entropy();
        let secret = Canary::generate(CanaryKind::WebhookSecret, &mut rng)
            .value()
            .to_owned();
        let app = AppConfig::factory_default();
        let mut users = BTreeMap::new();
        users.insert(
            app.bot_login(),
            User {
                login: app.bot_login(),
                id: app.bot_id(),
                role: "write".to_owned(),
                association: "NONE".to_owned(),
                is_bot: true,
            },
        );
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    app,
                    webhook_secrets: vec![secret],
                    installations: BTreeMap::new(),
                    repos: BTreeMap::new(),
                    users,
                    tokens: Vec::new(),
                    mints: Vec::new(),
                    pushes: Vec::new(),
                    log: Vec::new(),
                    faults: Vec::new(),
                    rng,
                    next_id: 1_000,
                }),
                clock,
            }),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .expect("the fake GitHub lock is never poisoned")
    }

    /// The fake's current time in seconds since the epoch.
    #[must_use]
    pub fn now(&self) -> i64 {
        self.inner.clock.now().to_utc().unix_timestamp()
    }

    // ---- setting the world up --------------------------------------------------------------

    /// Replaces the App. Use it to model an App that holds a forbidden permission.
    pub fn set_app(&self, app: AppConfig) -> &Self {
        {
            let mut state = self.lock();
            let old_bot = state.app.bot_login();
            state.users.remove(&old_bot);
            state.users.insert(
                app.bot_login(),
                User {
                    login: app.bot_login(),
                    id: app.bot_id(),
                    role: "write".to_owned(),
                    association: "NONE".to_owned(),
                    is_bot: true,
                },
            );
            state.app = app;
        }
        self
    }

    /// The App.
    #[must_use]
    pub fn app(&self) -> AppConfig {
        self.lock().app.clone()
    }

    /// Adds a repository (`owner/name`) with a default branch that has a first commit.
    pub fn add_repo(&self, full_name: &str, default_branch: &str) -> &Self {
        let mut state = self.lock();
        let id = state.new_id();
        let sha = state.new_sha();
        state.repos.insert(
            full_name.to_owned(),
            Repo {
                id,
                full_name: full_name.to_owned(),
                default_branch: default_branch.to_owned(),
                branches: BTreeMap::from([(default_branch.to_owned(), sha)]),
                protection: BTreeMap::new(),
                next_number: 1,
                issues: BTreeMap::new(),
                pulls: BTreeMap::new(),
                checks: Vec::new(),
                statuses: Vec::new(),
            },
        );
        drop(state);
        self
    }

    /// Adds an installation of the App on an account, covering these repositories
    /// (`owner/name`, each added with [`add_repo`](Self::add_repo) first).
    pub fn add_installation(&self, id: u64, account_login: &str, repos: &[&str]) -> &Self {
        let mut state = self.lock();
        let account_id = state.new_id();
        state.installations.insert(
            id,
            Installation {
                id,
                account_login: account_login.to_owned(),
                account_id,
                repositories: repos.iter().map(|r| (*r).to_owned()).collect(),
            },
        );
        drop(state);
        self
    }

    /// Adds or replaces an account.
    pub fn add_user(&self, user: User) -> &Self {
        self.lock().users.insert(user.login.clone(), user);
        self
    }

    /// Adds an open issue and returns its number.
    ///
    /// # Panics
    /// Panics when the repository or the author is not known.
    pub fn add_issue(
        &self,
        repo: &str,
        title: &str,
        body: &str,
        author: &str,
        labels: &[&str],
    ) -> u64 {
        let now = self.now();
        let mut state = self.lock();
        assert!(state.users.contains_key(author), "unknown user {author}");
        // Labels given at creation are applied by the author, and GitHub records that.
        let events: Vec<IssueEvent> = labels
            .iter()
            .map(|label| IssueEvent {
                id: state.new_id(),
                event: "labeled".to_owned(),
                actor: author.to_owned(),
                label: Some((*label).to_owned()),
                created_at: now,
            })
            .collect();
        let repo = state.repos.get_mut(repo).expect("a known repository");
        let number = repo.next_number;
        repo.next_number += 1;
        repo.issues.insert(
            number,
            Issue {
                number,
                title: title.to_owned(),
                body: body.to_owned(),
                state: "open".to_owned(),
                is_pull: false,
                author: author.to_owned(),
                labels: labels.iter().map(|l| (*l).to_owned()).collect(),
                created_at: now,
                updated_at: now,
                comments: Vec::new(),
                events,
            },
        );
        number
    }

    /// Changes the body of an issue, as an author editing it after the label was applied
    /// (NT-AUTHZ-05).
    ///
    /// # Panics
    /// Panics when the issue is not known.
    pub fn edit_issue_body(&self, repo: &str, number: u64, body: &str) {
        let now = self.now();
        let mut state = self.lock();
        let issue = state
            .repos
            .get_mut(repo)
            .and_then(|r| r.issues.get_mut(&number))
            .expect("a known issue");
        issue.body = body.to_owned();
        issue.updated_at = now;
    }

    /// Adds a label to an issue, applied by `actor`. The issue's event list records who did it,
    /// which is the only way the API says (`GET /issues/{n}/events`, event `labeled`). The
    /// webhook's `sender` can say something else, and the factory must trust the events.
    ///
    /// # Panics
    /// Panics when the issue or the actor is not known.
    pub fn label_issue(&self, repo: &str, number: u64, label: &str, actor: &str) {
        self.change_issue(repo, number, actor, |issue| {
            if !issue.labels.iter().any(|l| l == label) {
                issue.labels.push(label.to_owned());
            }
            ("labeled", Some(label.to_owned()))
        });
    }

    /// Adds a label to an issue, applied by the issue's author.
    ///
    /// # Panics
    /// Panics when the issue is not known.
    pub fn add_label(&self, repo: &str, number: u64, label: &str) {
        let author = self.issue_author(repo, number);
        self.label_issue(repo, number, label, &author);
    }

    /// Removes a label from an issue, taken off by `actor`.
    ///
    /// # Panics
    /// Panics when the issue or the actor is not known.
    pub fn unlabel_issue(&self, repo: &str, number: u64, label: &str, actor: &str) {
        self.change_issue(repo, number, actor, |issue| {
            issue.labels.retain(|l| l != label);
            ("unlabeled", Some(label.to_owned()))
        });
    }

    /// Removes a label from an issue, so that the live state disagrees with a webhook payload
    /// that still says the label is there (NT-WH-06). The issue's author takes it off.
    ///
    /// # Panics
    /// Panics when the issue is not known.
    pub fn remove_label(&self, repo: &str, number: u64, label: &str) {
        let author = self.issue_author(repo, number);
        self.unlabel_issue(repo, number, label, &author);
    }

    /// Closes an issue, closed by its author.
    ///
    /// # Panics
    /// Panics when the issue is not known.
    pub fn close_issue(&self, repo: &str, number: u64) {
        let author = self.issue_author(repo, number);
        self.change_issue(repo, number, &author, |issue| {
            "closed".clone_into(&mut issue.state);
            ("closed", None)
        });
    }

    fn issue_author(&self, repo: &str, number: u64) -> String {
        self.lock()
            .repos
            .get(repo)
            .and_then(|r| r.issues.get(&number))
            .expect("a known issue")
            .author
            .clone()
    }

    /// Applies a change to an issue and records it in the issue's event list.
    fn change_issue(
        &self,
        repo: &str,
        number: u64,
        actor: &str,
        change: impl FnOnce(&mut Issue) -> (&'static str, Option<String>),
    ) {
        let now = self.now();
        let mut state = self.lock();
        assert!(state.users.contains_key(actor), "unknown user {actor}");
        let id = state.new_id();
        let issue = state
            .repos
            .get_mut(repo)
            .and_then(|r| r.issues.get_mut(&number))
            .expect("a known issue");
        let (event, label) = change(issue);
        issue.updated_at = now;
        issue.events.push(IssueEvent {
            id,
            event: event.to_owned(),
            actor: actor.to_owned(),
            label,
            created_at: now,
        });
    }

    /// Protects a branch.
    ///
    /// # Panics
    /// Panics when the repository is not known.
    pub fn protect_branch(&self, repo: &str, branch: &str, protection: Protection) {
        self.lock()
            .repos
            .get_mut(repo)
            .expect("a known repository")
            .protection
            .insert(branch.to_owned(), protection);
    }

    /// Removes the protection of a branch.
    ///
    /// # Panics
    /// Panics when the repository is not known.
    pub fn unprotect_branch(&self, repo: &str, branch: &str) {
        self.lock()
            .repos
            .get_mut(repo)
            .expect("a known repository")
            .protection
            .remove(branch);
    }

    /// Makes a new commit on a branch, as a person pushing would. The branch is created when it
    /// does not exist. Every open pull request from that branch moves to the new head, and the
    /// approvals on it go stale when the base branch's protection dismisses stale reviews.
    ///
    /// # Panics
    /// Panics when the repository is not known.
    pub fn push_commit(&self, repo: &str, branch: &str) -> String {
        let mut state = self.lock();
        let sha = state.new_sha();
        let repo_state = state.repos.get_mut(repo).expect("a known repository");
        let existed = repo_state
            .branches
            .insert(branch.to_owned(), sha.clone())
            .is_some();
        routes::move_pull_heads(repo_state, branch, &sha);
        state.pushes.push(PushRecord {
            repo: repo.to_owned(),
            branch: branch.to_owned(),
            kind: if existed { "update" } else { "create" }.to_owned(),
            sha: sha.clone(),
            token_id: None,
        });
        sha
    }

    /// The commit a branch points at.
    #[must_use]
    pub fn branch_sha(&self, repo: &str, branch: &str) -> Option<String> {
        self.lock()
            .repos
            .get(repo)
            .and_then(|r| r.branches.get(branch))
            .cloned()
    }

    /// Records a check run on a commit, as a CI system would.
    ///
    /// # Panics
    /// Panics when the repository is not known.
    pub fn add_check_run(&self, repo: &str, sha: &str, name: &str, conclusion: &str, app_id: u64) {
        self.lock()
            .repos
            .get_mut(repo)
            .expect("a known repository")
            .checks
            .push(CheckRun {
                name: name.to_owned(),
                head_sha: sha.to_owned(),
                status: "completed".to_owned(),
                conclusion: Some(conclusion.to_owned()),
                app_id,
            });
    }

    /// Records a review by a person on a pull request.
    ///
    /// # Panics
    /// Panics when the pull request is not known.
    pub fn add_review(&self, repo: &str, number: u64, author: &str, state: &str, commit_id: &str) {
        let mut state_guard = self.lock();
        let id = state_guard.new_id();
        let pull = state_guard
            .repos
            .get_mut(repo)
            .and_then(|r| r.pulls.get_mut(&number))
            .expect("a known pull request");
        pull.reviews.push(Review {
            id,
            author: author.to_owned(),
            state: state.to_owned(),
            commit_id: commit_id.to_owned(),
            body: String::new(),
        });
    }

    /// Marks a draft pull request ready for review, as a person does in the web page.
    ///
    /// # Panics
    /// Panics when the pull request is not known.
    pub fn mark_ready(&self, repo: &str, number: u64) {
        self.lock()
            .repos
            .get_mut(repo)
            .and_then(|r| r.pulls.get_mut(&number))
            .expect("a known pull request")
            .draft = false;
    }

    /// The next request that matches `route` (a template such as
    /// `POST /repos/{owner}/{repo}/pulls`, or `*` for any) is answered with this status and
    /// message instead. Use 403, 404, 409, 422 or 500.
    pub fn fail_next(&self, route: &str, status: u16, message: &str) {
        self.add_fault(route, status, message, Vec::new(), Some(1));
    }

    /// Every request that matches `route` fails, until [`clear_faults`](Self::clear_faults).
    pub fn fail_always(&self, route: &str, status: u16, message: &str) {
        self.add_fault(route, status, message, Vec::new(), None);
    }

    /// The next request that matches `route` is answered the way GitHub answers a request over
    /// the rate limit: 429 with `Retry-After`, `x-ratelimit-remaining: 0` and a reset time.
    pub fn rate_limit_next(&self, route: &str, retry_after_seconds: u32) {
        let reset = self.now() + i64::from(retry_after_seconds);
        self.add_fault(
            route,
            429,
            "API rate limit exceeded",
            vec![
                ("Retry-After".to_owned(), retry_after_seconds.to_string()),
                ("x-ratelimit-remaining".to_owned(), "0".to_owned()),
                ("x-ratelimit-reset".to_owned(), reset.to_string()),
            ],
            Some(1),
        );
    }

    /// Removes every scripted failure.
    pub fn clear_faults(&self) {
        self.lock().faults.clear();
    }

    fn add_fault(
        &self,
        route: &str,
        status: u16,
        message: &str,
        headers: Vec<(String, String)>,
        remaining: Option<u32>,
    ) {
        self.lock().faults.push(Fault {
            route: route.to_owned(),
            status,
            message: message.to_owned(),
            headers,
            remaining,
        });
    }

    // ---- what happened -----------------------------------------------------------------------

    /// Every request, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<RequestRecord> {
        self.lock().log.clone()
    }

    /// The requests that matched a route template.
    #[must_use]
    pub fn requests_to(&self, route: &str) -> Vec<RequestRecord> {
        self.lock()
            .log
            .iter()
            .filter(|r| r.route == route)
            .cloned()
            .collect()
    }

    /// How many requests matched a route template.
    #[must_use]
    pub fn count(&self, route: &str) -> usize {
        self.lock().log.iter().filter(|r| r.route == route).count()
    }

    /// Every token minted, with the request that asked for it.
    #[must_use]
    pub fn mints(&self) -> Vec<MintRecord> {
        self.lock().mints.clone()
    }

    /// What the fake knows about each token, without its value.
    #[must_use]
    pub fn tokens(&self) -> Vec<TokenView> {
        self.lock()
            .tokens
            .iter()
            .map(|t| TokenView {
                id: t.id,
                installation_id: t.installation_id,
                repositories: t.repositories.clone(),
                permissions: t.permissions.clone(),
                expires_at: t.expires_at,
                revoked_at: t.revoked_at,
                uses: t.uses,
                uses_after_revoke: t.uses_after_revoke,
            })
            .collect()
    }

    /// The `DELETE /installation/token` requests that succeeded: one per revoked token.
    #[must_use]
    pub fn revocations(&self) -> Vec<RequestRecord> {
        self.lock()
            .log
            .iter()
            .filter(|r| r.route == "DELETE /installation/token" && r.status == 204)
            .cloned()
            .collect()
    }

    /// Branch changes, from the refs API and from [`push_commit`](Self::push_commit).
    #[must_use]
    pub fn pushes(&self) -> Vec<PushRecord> {
        self.lock().pushes.clone()
    }

    /// Calls of the merge endpoint, whatever they got back.
    #[must_use]
    pub fn merge_attempts(&self) -> Vec<RequestRecord> {
        self.requests_to("PUT /repos/{owner}/{repo}/pulls/{number}/merge")
    }

    /// Merges that succeeded.
    #[must_use]
    pub fn merges(&self) -> Vec<RequestRecord> {
        self.merge_attempts()
            .into_iter()
            .filter(|r| r.status == 200)
            .collect()
    }

    /// Lookups of the collaborator-permission endpoint. The factory authorises by its own
    /// allowlist and must never call it to decide anything, so a test asserts this is empty.
    #[must_use]
    pub fn permission_lookups(&self) -> Vec<RequestRecord> {
        self.requests_to("GET /repos/{owner}/{repo}/collaborators/{username}/permission")
    }

    /// The bodies of the comments on an issue or pull request, in order.
    #[must_use]
    pub fn comments(&self, repo: &str, number: u64) -> Vec<String> {
        self.lock()
            .repos
            .get(repo)
            .and_then(|r| r.issues.get(&number))
            .map(|i| i.comments.iter().map(|c| c.body.clone()).collect())
            .unwrap_or_default()
    }

    /// A pull request as the API shows it.
    #[must_use]
    pub fn pull_json(&self, repo: &str, number: u64) -> Option<Value> {
        let state = self.lock();
        let repo_state = state.repos.get(repo)?;
        routes::pull_json(&state, repo_state, repo_state.pulls.get(&number)?)
    }

    /// The numbers of the pull requests of a repository, in order.
    #[must_use]
    pub fn pull_numbers(&self, repo: &str) -> Vec<u64> {
        self.lock()
            .repos
            .get(repo)
            .map(|r| r.pulls.keys().copied().collect())
            .unwrap_or_default()
    }

    /// The tokens that were minted, as canaries, so the sweeper looks for them in every sink.
    /// The only place a token may appear is the `Authorization` header sent to this server,
    /// which the fake masks in its own log.
    #[must_use]
    pub fn minted_secrets(&self) -> Vec<Canary> {
        self.lock()
            .tokens
            .iter()
            .map(|t| Canary::custom(&format!("fx-gh-token-{}", t.id), &t.value))
            .collect()
    }

    /// The webhook secret, as a canary, so the sweeper looks for it too.
    #[must_use]
    pub fn webhook_secret_canary(&self) -> Canary {
        Canary::custom("fx-gh-webhook-secret", &self.lock().webhook_secrets[0])
    }

    /// The secret webhooks are signed with. The adapter under test is configured with it, as it
    /// would be with the real one.
    #[must_use]
    pub fn webhook_secret(&self) -> String {
        self.lock().webhook_secrets[0].clone()
    }

    /// Every secret the fake still accepts when it checks a delivery, newest first.
    #[must_use]
    pub fn accepted_webhook_secrets(&self) -> Vec<String> {
        self.lock().webhook_secrets.clone()
    }

    /// Starts signing with a new secret and keeps the old one accepted, as in the overlap window
    /// of a rotation (NT-WH-08).
    pub fn rotate_webhook_secret(&self) -> String {
        let mut state = self.lock();
        let fresh = Canary::generate(CanaryKind::WebhookSecret, &mut state.rng)
            .value()
            .to_owned();
        state.webhook_secrets.insert(0, fresh.clone());
        fresh
    }

    /// Stops accepting every secret except the newest.
    pub fn retire_old_webhook_secrets(&self) {
        self.lock().webhook_secrets.truncate(1);
    }

    /// The fake as JSON, with the fidelity label: every request record and the mints. The
    /// `Authorization` values are masked.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let state = self.lock();
        json!({
            "fidelity": "fake",
            "server": "factory-testkit-fake (github)",
            "requests": state.log.iter().map(RequestRecord::to_json).collect::<Vec<_>>(),
            "mints": state.mints.len(),
            "revocations": state.log.iter().filter(|r| r.route == "DELETE /installation/token" && r.status == 204).count(),
        })
    }

    // ---- the server --------------------------------------------------------------------------

    /// Starts an HTTP server on `127.0.0.1` that answers with this fake.
    ///
    /// # Errors
    /// Returns the I/O error when the socket cannot be bound.
    pub fn serve(&self) -> io::Result<GithubServer> {
        let fake = self.clone();
        let server = HttpServer::start("github", move |request| fake.handle(request))?;
        Ok(GithubServer {
            server,
            fake: self.clone(),
        })
    }

    /// Answers one request. The HTTP server calls this, and a test may too.
    #[must_use]
    pub fn handle(&self, request: &HttpRequest) -> HttpResponse {
        let now = self.now();
        let mut state = self.lock();
        routes::handle(&mut state, now, request)
    }

    /// A structurally valid App JWT: RS256 header, `iss` of the App, `iat` a minute ago and
    /// `exp` nine minutes ahead, with a placeholder signature. For tests of the fake itself and
    /// for adapters that are handed a ready-made JWT. The fake does not check the signature.
    #[must_use]
    pub fn sample_app_jwt(&self) -> String {
        let app_id = self.lock().app.id;
        let now = self.now();
        routes::build_jwt(app_id, now - 60, now + 540)
    }
}

/// A running fake GitHub server.
#[derive(Debug)]
pub struct GithubServer {
    server: HttpServer,
    fake: FakeGithub,
}

impl GithubServer {
    /// `http://127.0.0.1:<port>`: the base URL to give the adapter in place of
    /// `https://api.github.com`.
    #[must_use]
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// The address.
    #[must_use]
    pub fn addr(&self) -> std::net::SocketAddr {
        self.server.addr()
    }

    /// The fake behind the server.
    #[must_use]
    pub fn fake(&self) -> &FakeGithub {
        &self.fake
    }
}

/// How a credential is shown in the log: its scheme, its length and a fingerprint, never the
/// value. Two requests with the same token show the same fingerprint.
pub(crate) fn mask_authorization(value: &str) -> String {
    let (scheme, credential) = value.split_once(' ').unwrap_or(("", value));
    let digest = sha256(credential.as_bytes());
    let fingerprint = hex_encode(&digest[..4], false);
    let prefix = if scheme.is_empty() {
        String::new()
    } else {
        format!("{scheme} ")
    };
    format!("{prefix}[MASKED len={} fp={fingerprint}]", credential.len())
}

/// A token in the shape of a real installation token.
pub(crate) fn new_token_value(rng: &mut FxRng) -> String {
    format!("ghs_CANARY{}", rng.string_from(ALPHANUMERIC, 30))
}

/// Formats seconds since the epoch the way GitHub does.
pub(crate) fn iso(seconds: i64) -> String {
    format_rfc3339(seconds)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod webhook_tests;
