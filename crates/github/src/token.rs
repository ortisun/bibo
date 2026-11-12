//! Installation tokens: minted per job, narrowed to one repository and to the permissions of the
//! stage, refreshed before they expire, and revoked when the job ends.
//!
//! * **One repository.** The mint request names exactly one repository. The answer is checked: a
//!   token that covers anything else, or carries a permission or a level that was not asked for,
//!   is revoked at once and refused. The code never trusts that the server narrowed it.
//! * **Per stage.** The permissions come from [`PermissionSet`]. A push credential is minted only
//!   for a stage that may write.
//! * **The App is audited** on the first token of every job: an App that holds a forbidden
//!   permission gets no token.
//! * **Memory only.** A token is held in this process, never written anywhere, never printed (its
//!   `Debug` shows nothing), and registered with the redactor so that no sink can carry it.
//! * **Refresh.** A token is replaced when less than the refresh margin of its hour is left, and
//!   once more if the server answers 401 to a token we still think is valid.
//! * **Revocation.** `DELETE /installation/token` with the token itself, for every live token of
//!   the job, at job end. A job that has ended can never mint again. A revocation that failed is
//!   kept and retried by the next call or by the sweep.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use factory_domain::ids::{JobId, TenantId};
use factory_domain::redaction::{Redactor, Registered, SecretHandle};
use factory_domain::values::Timestamp;
use factory_ports::clock::Clock;
use factory_ports::githost::{AppId, GitHostError, GitScope};
use factory_ports::paths::RepoRef;
use factory_ports::store::InstallationId;
use serde_json::{Value, json};

use crate::core::{HttpCore, error_for};
use crate::jwt::{AppJwt, JwtSigner};
use crate::permissions::{AppAudit, AppPolicy, Level, PermissionSet, audit_app, may_write};
use crate::wire::{Method, WireRequest};

/// How many ended jobs are remembered. A job id is never reused, so an older one that falls out
/// of the memory also holds no live token; the bound only keeps the memory finite.
const ENDED_JOBS_REMEMBERED: usize = 100_000;

/// Which credential a call needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TokenClass {
    /// The permissions of the stage in the scope.
    Stage,
    /// The right to write issues and the metadata, for a comment (SF-14), for a stage that holds
    /// `issues: write`. Any other stage keeps its own permissions for the call.
    Comment,
    /// A read-only credential for a fetch.
    Fetch,
    /// A write credential for a push.
    Push,
    /// `issues: write` and nothing else, for the status label and the status comment (ports v1.2).
    /// It does not depend on the stage in the scope.
    IssueStatus,
    /// `administration: read` and `metadata: read`, for the one read of classic branch protection
    /// that the protection preflight makes ([`PermissionSet::protection_reader`]). It does not
    /// depend on the stage in the scope, and no other call uses it.
    ProtectionRead,
}

/// Where the factory's tenants' installations are. The adapter does not discover them: a tenant
/// is bound to an installation when its repository is registered, and an unbound tenant reaches
/// nothing (the answer is `NotFound`, as for another tenant's pull request).
pub trait InstallationDirectory: Send + Sync {
    /// The installation that covers `repo` for `tenant`, or `None`.
    fn installation_for(&self, tenant: TenantId, repo: &RepoRef) -> Option<InstallationId>;
}

/// A fixed table of bindings, for tests and for a single-tenant deployment.
#[derive(Debug, Clone, Default)]
pub struct StaticInstallations {
    bindings: HashMap<(TenantId, RepoRef), InstallationId>,
}

impl StaticInstallations {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds a tenant's repository to an installation.
    #[must_use]
    pub fn bind(mut self, tenant: TenantId, repo: RepoRef, installation: InstallationId) -> Self {
        self.bindings.insert((tenant, repo), installation);
        self
    }
}

impl InstallationDirectory for StaticInstallations {
    fn installation_for(&self, tenant: TenantId, repo: &RepoRef) -> Option<InstallationId> {
        self.bindings.get(&(tenant, repo.clone())).copied()
    }
}

/// The text of a token. It never appears in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Bearer(String);

impl Bearer {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bearer(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TokenKey {
    class: TokenClass,
    repo: RepoRef,
    permissions: Vec<(&'static str, crate::permissions::Level)>,
}

struct Live {
    key: TokenKey,
    bearer: Bearer,
    expires_at: Timestamp,
    handle: Option<SecretHandle>,
}

impl fmt::Debug for Live {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Live")
            .field("key", &self.key)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct State {
    live: HashMap<JobId, Vec<Live>>,
    ended: HashSet<JobId>,
    ended_order: VecDeque<JobId>,
    /// Tokens whose revocation failed. They are retried.
    leftovers: Vec<(JobId, Live)>,
}

/// What the App says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppIdentity {
    /// The login of the App's bot account, such as `factory[bot]`.
    pub bot_login: String,
    /// The permissions the App holds.
    pub permissions: BTreeMap<String, String>,
}

/// What the minter is told about the App and about refreshing.
pub(crate) struct MinterSettings {
    /// The App's id (the `iss` of its JWT).
    pub app: AppId,
    /// The permissions the App must and must not hold.
    pub policy: AppPolicy,
    /// A token with less than this left of its hour is replaced.
    pub refresh_margin: Duration,
}

/// Mints, tracks and revokes installation tokens.
pub(crate) struct TokenMinter {
    core: Arc<HttpCore>,
    signer: Arc<dyn JwtSigner>,
    clock: Arc<dyn Clock>,
    directory: Arc<dyn InstallationDirectory>,
    redactor: Arc<Redactor>,
    app: AppId,
    policy: AppPolicy,
    refresh_margin: Duration,
    state: Mutex<State>,
    /// Serialises minting, so two calls for the same job do not mint two tokens.
    gate: tokio::sync::Mutex<()>,
    identity: Mutex<Option<AppIdentity>>,
}

impl TokenMinter {
    pub(crate) fn new(
        core: Arc<HttpCore>,
        signer: Arc<dyn JwtSigner>,
        clock: Arc<dyn Clock>,
        directory: Arc<dyn InstallationDirectory>,
        redactor: Arc<Redactor>,
        settings: MinterSettings,
    ) -> Self {
        Self {
            core,
            signer,
            clock,
            directory,
            redactor,
            app: settings.app,
            policy: settings.policy,
            refresh_margin: settings.refresh_margin,
            state: Mutex::new(State::default()),
            gate: tokio::sync::Mutex::new(()),
            identity: Mutex::new(None),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// True when the job's tokens were revoked. Such a job gets no credential and no call.
    pub(crate) fn job_has_ended(&self, job: JobId) -> bool {
        self.state().ended.contains(&job)
    }

    fn permissions_for(scope: &GitScope, class: TokenClass) -> Result<PermissionSet, GitHostError> {
        match class {
            TokenClass::Stage => Ok(PermissionSet::for_stage(scope.stage)),
            // A stage that holds the right to write issues comments with that right and the
            // metadata only. A stage that does not hold it keeps its own token for the call, so
            // that the code host refuses the comment as before.
            TokenClass::Comment => {
                let own = PermissionSet::for_stage(scope.stage);
                Ok(if own.holds("issues", Level::Write) {
                    PermissionSet::comment()
                } else {
                    own
                })
            }
            TokenClass::IssueStatus => Ok(PermissionSet::issue_status()),
            TokenClass::Fetch => Ok(PermissionSet::fetch()),
            TokenClass::ProtectionRead => Ok(PermissionSet::protection_reader()),
            TokenClass::Push if may_write(scope.stage) => Ok(PermissionSet::push()),
            // The write credential is never minted for a stage that may not write.
            TokenClass::Push => Err(GitHostError::Forbidden),
        }
    }

    /// A token for the scope, minted if there is none that is still good.
    pub(crate) async fn token_for(
        &self,
        scope: &GitScope,
        class: TokenClass,
    ) -> Result<Bearer, GitHostError> {
        if self.job_has_ended(scope.job) {
            return Err(GitHostError::Unauthorized);
        }
        let permissions = Self::permissions_for(scope, class)?;
        let key = TokenKey {
            class,
            repo: scope.repo.clone(),
            permissions: permissions.entries(),
        };
        if let Some(found) = self.usable(scope.job, &key) {
            return Ok(found);
        }
        let _gate = self.gate.lock().await;
        // Another call may have minted while this one waited, or the job may have ended.
        if self.job_has_ended(scope.job) {
            return Err(GitHostError::Unauthorized);
        }
        if let Some(found) = self.usable(scope.job, &key) {
            return Ok(found);
        }
        let installation = self
            .directory
            .installation_for(scope.tenant, &scope.repo)
            .ok_or(GitHostError::NotFound)?;
        let first_for_job = !self.state().live.contains_key(&scope.job);
        if first_for_job {
            self.check_the_app().await?;
        }
        let (bearer, expires_at) = self.mint(installation, &scope.repo, &permissions).await?;
        // A token the redactor does not know is a token a sink could carry. Fail closed: end it.
        let Ok(Registered::Added(handle)) = self
            .redactor
            .register("github_installation_token", bearer.expose())
        else {
            let _ = self.revoke_value(&bearer).await;
            return Err(GitHostError::Unavailable);
        };
        let handle = Some(handle);
        let live = Live {
            key,
            bearer: bearer.clone(),
            expires_at,
            handle,
        };
        match self.store(scope.job, live) {
            // The replaced token is still valid on GitHub's side until it expires: end it now.
            Ok(Some(old)) => {
                let _ = self.revoke_one(old).await;
            }
            Ok(None) => {}
            // The job ended while the token was being minted. End the token too.
            Err(rejected) => {
                let _ = self.revoke_one(*rejected).await;
                return Err(GitHostError::Unauthorized);
            }
        }
        Ok(bearer)
    }

    /// Keeps a fresh token for the job, in one step with the check that the job has not ended.
    /// Returns the token it replaced, or the token itself when the job is over.
    fn store(&self, job: JobId, live: Live) -> Result<Option<Live>, Box<Live>> {
        let mut state = self.state();
        if state.ended.contains(&job) {
            return Err(Box::new(live));
        }
        let tokens = state.live.entry(job).or_default();
        let old = tokens
            .iter()
            .position(|t| t.key == live.key)
            .map(|p| tokens.remove(p));
        tokens.push(live);
        Ok(old)
    }

    fn usable(&self, job: JobId, key: &TokenKey) -> Option<Bearer> {
        let horizon = self.clock.now().checked_add(self.refresh_margin)?;
        let state = self.state();
        state
            .live
            .get(&job)?
            .iter()
            .find(|t| &t.key == key && t.expires_at > horizon)
            .map(|t| t.bearer.clone())
    }

    /// Drops a token the server refused (a 401), so the next call mints a new one.
    pub(crate) async fn discard(&self, job: JobId, bearer: &Bearer) {
        let dropped = {
            let mut state = self.state();
            state.live.get_mut(&job).and_then(|tokens| {
                tokens
                    .iter()
                    .position(|t| &t.bearer == bearer)
                    .map(|p| tokens.remove(p))
            })
        };
        if let Some(live) = dropped
            && let Some(handle) = live.handle
        {
            self.redactor.forget(handle);
        }
    }

    async fn check_the_app(&self) -> Result<(), GitHostError> {
        let identity = self.app_identity().await?;
        match audit_app(&self.policy, &identity.permissions) {
            AppAudit::Refuse { .. } => Err(GitHostError::Forbidden),
            AppAudit::Pass | AppAudit::CapAtL0 { .. } => Ok(()),
        }
    }

    fn jwt_request(
        &self,
        method: Method,
        target: String,
        body: Vec<u8>,
    ) -> Result<WireRequest, GitHostError> {
        let jwt = AppJwt::make(self.app.0, &self.clock.now(), &*self.signer)
            .map_err(|_| GitHostError::Unauthorized)?;
        Ok(WireRequest {
            method,
            target,
            headers: api_headers(jwt.expose(), !body.is_empty()),
            body,
        })
    }

    /// `GET /app`, authenticated with a JWT. Cached after the first answer.
    pub(crate) async fn app_identity(&self) -> Result<AppIdentity, GitHostError> {
        if let Some(found) = self
            .identity
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Ok(found);
        }
        let request = self.jwt_request(Method::Get, "/app".to_owned(), Vec::new())?;
        let response = self.core.send(request).await?;
        if response.status != 200 {
            return Err(error_for(&response));
        }
        let value: Value =
            serde_json::from_slice(&response.body).map_err(|_| GitHostError::Unavailable)?;
        let slug = value["slug"].as_str().ok_or(GitHostError::Unavailable)?;
        let identity = AppIdentity {
            bot_login: format!("{slug}[bot]"),
            permissions: string_map(&value["permissions"]),
        };
        *self.identity.lock().unwrap_or_else(PoisonError::into_inner) = Some(identity.clone());
        Ok(identity)
    }

    /// The App's permissions, read fresh (not from the cache), judged against the policy. For the
    /// onboarding check.
    pub(crate) async fn audit_now(&self) -> Result<AppAudit, GitHostError> {
        *self.identity.lock().unwrap_or_else(PoisonError::into_inner) = None;
        let identity = self.app_identity().await?;
        Ok(audit_app(&self.policy, &identity.permissions))
    }

    async fn mint(
        &self,
        installation: InstallationId,
        repo: &RepoRef,
        permissions: &PermissionSet,
    ) -> Result<(Bearer, Timestamp), GitHostError> {
        let body = json!({
            "repositories": [repo.name()],
            "permissions": permissions.to_json(),
        })
        .to_string()
        .into_bytes();
        let request = self.jwt_request(
            Method::Post,
            format!("/app/installations/{}/access_tokens", installation.0),
            body,
        )?;
        let response = self.core.send(request).await?;
        if response.status != 201 {
            let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
            return Err(match response.status {
                // The repository is not one of the installation's, or the installation is gone.
                422 if text.contains("repositor") => GitHostError::NotFound,
                422 => GitHostError::Forbidden,
                _ => error_for(&response),
            });
        }
        let value: Value =
            serde_json::from_slice(&response.body).map_err(|_| GitHostError::Unavailable)?;
        let token = value["token"]
            .as_str()
            .ok_or(GitHostError::Unavailable)?
            .to_owned();
        let bearer = Bearer(token);
        let expires_at = value["expires_at"]
            .as_str()
            .and_then(|t| Timestamp::parse(t).ok())
            .ok_or(GitHostError::Unavailable)?;
        // Do not trust the server to have narrowed the token: look at what it says it granted.
        let covers_only_this_repository = value["repositories"].as_array().is_some_and(|list| {
            list.len() == 1
                && list
                    .first()
                    .and_then(|r| r["full_name"].as_str())
                    .is_some_and(|name| {
                        name.eq_ignore_ascii_case(&format!("{}/{}", repo.owner(), repo.name()))
                    })
        });
        let only_what_was_asked = permissions.contains_all_of(&string_map(&value["permissions"]));
        if !(covers_only_this_repository && only_what_was_asked) {
            // Wider than the request. End it before anyone can use it.
            let _ = self.revoke_value(&bearer).await;
            return Err(GitHostError::Forbidden);
        }
        Ok((bearer, expires_at))
    }

    /// `DELETE /installation/token` with the token itself. A 401 means it was already dead.
    async fn revoke_value(&self, bearer: &Bearer) -> Result<(), GitHostError> {
        let request = WireRequest {
            method: Method::Delete,
            target: "/installation/token".to_owned(),
            headers: api_headers(bearer.expose(), false),
            body: Vec::new(),
        };
        let response = self.core.send(request).await?;
        match response.status {
            204 | 401 | 404 => Ok(()),
            _ => Err(error_for(&response)),
        }
    }

    async fn revoke_one(&self, live: Live) -> Result<(), Box<Live>> {
        match self.revoke_value(&live.bearer).await {
            Ok(()) => {
                if let Some(handle) = live.handle {
                    self.redactor.forget(handle);
                }
                Ok(())
            }
            Err(_) => Err(Box::new(live)),
        }
    }

    /// Ends a job: no further token for it, and every token it holds is revoked. Idempotent. A
    /// revocation that fails is kept for the next call and the call reports `Unavailable`.
    pub(crate) async fn revoke_job(&self, job: JobId) -> Result<(), GitHostError> {
        let (tokens, mut retries) = {
            let mut state = self.state();
            if state.ended.insert(job) {
                state.ended_order.push_back(job);
                while state.ended_order.len() > ENDED_JOBS_REMEMBERED {
                    if let Some(oldest) = state.ended_order.pop_front() {
                        state.ended.remove(&oldest);
                    }
                }
            }
            let tokens = state.live.remove(&job).unwrap_or_default();
            let (mine, others): (Vec<_>, Vec<_>) = std::mem::take(&mut state.leftovers)
                .into_iter()
                .partition(|(j, _)| *j == job);
            state.leftovers = others;
            (
                tokens,
                mine.into_iter().map(|(_, live)| live).collect::<Vec<_>>(),
            )
        };
        retries.extend(tokens);
        let mut failed = Vec::new();
        for live in retries {
            if let Err(live) = self.revoke_one(live).await {
                failed.push((job, *live));
            }
        }
        if failed.is_empty() {
            return Ok(());
        }
        self.state().leftovers.extend(failed);
        Err(GitHostError::Unavailable)
    }

    /// Revokes every token that `job` holds and does **not** end the job (LB-04): a later call
    /// mints a new token. This is for a job that waits for a person for a long time; `revoke_job`
    /// is for a job that is over, and refuses every later call. A revocation that fails is kept
    /// for the next pass. Returns how many tokens were revoked.
    async fn release_job(&self, job: JobId) -> usize {
        let (tokens, retries) = {
            let mut state = self.state();
            let tokens = state.live.remove(&job).unwrap_or_default();
            let (mine, others): (Vec<_>, Vec<_>) = std::mem::take(&mut state.leftovers)
                .into_iter()
                .partition(|(j, _)| *j == job);
            state.leftovers = others;
            (tokens, mine.into_iter().map(|(_, live)| live))
        };
        let all: Vec<Live> = retries.chain(tokens).collect();
        let total = all.len();
        let mut failed = Vec::new();
        for live in all {
            if let Err(live) = self.revoke_one(live).await {
                failed.push((job, *live));
            }
        }
        let released = total - failed.len();
        if !failed.is_empty() {
            self.state().leftovers.extend(failed);
        }
        released
    }

    /// Releases the tokens of the jobs in `idle` that are not running now, without ending them
    /// (LB-04). As for the cleanup sweep, `running_now` is asked **after** the tokens that exist
    /// have been listed, so a round that began meanwhile keeps its token (finding STS-4). A job
    /// that is not in `idle` is never touched. Returns how many tokens were revoked.
    pub(crate) async fn release_idle_after(
        &self,
        idle: &HashSet<JobId>,
        running_now: &dyn Fn() -> HashSet<JobId>,
    ) -> usize {
        let listed: Vec<JobId> = {
            let state = self.state();
            state
                .live
                .keys()
                .chain(state.leftovers.iter().map(|(job, _)| job))
                .filter(|job| idle.contains(job))
                .copied()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect()
        };
        let running = running_now();
        let mut released = 0;
        for job in listed.into_iter().filter(|job| !running.contains(job)) {
            released += self.release_job(job).await;
        }
        released
    }

    /// The cleanup sweep: revokes the tokens of every job that is not in `running`, including
    /// tokens whose earlier revocation failed. Returns how many tokens were revoked.
    pub(crate) async fn sweep(&self, running: &HashSet<JobId>) -> usize {
        self.sweep_after(running, &HashSet::new).await
    }

    /// The cleanup sweep for a caller whose set of running work changes while it looks. `open` is
    /// the set it has already read, and `running_now` is asked **after** the tokens that exist
    /// have been listed. A token is minted after its job is noted as running, so a job that has a
    /// token in the list is already in the answer, and the sweep cannot revoke the token of a
    /// round that began after the caller read `open` (finding STS-4).
    pub(crate) async fn sweep_after(
        &self,
        open: &HashSet<JobId>,
        running_now: &dyn Fn() -> HashSet<JobId>,
    ) -> usize {
        let listed: Vec<JobId> = {
            let state = self.state();
            state
                .live
                .keys()
                .chain(state.leftovers.iter().map(|(job, _)| job))
                .filter(|job| !open.contains(job))
                .copied()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect()
        };
        let running = running_now();
        let orphans: Vec<JobId> = listed
            .into_iter()
            .filter(|job| !running.contains(job))
            .collect();
        let mut revoked = 0;
        for job in orphans {
            let before = self.live_count(job);
            if self.revoke_job(job).await.is_ok() {
                revoked += before;
            }
        }
        revoked
    }

    fn live_count(&self, job: JobId) -> usize {
        let state = self.state();
        state.live.get(&job).map_or(0, Vec::len)
            + state.leftovers.iter().filter(|(j, _)| *j == job).count()
    }
}

/// The headers of an API request. `credential` is a JWT or an installation token, and is a secret.
pub(crate) fn api_headers(credential: &str, has_body: bool) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Authorization".to_owned(), format!("Bearer {credential}")),
        (
            "Accept".to_owned(),
            "application/vnd.github+json".to_owned(),
        ),
        ("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned()),
    ];
    if has_body {
        headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
    }
    headers
}

fn string_map(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bearer_and_a_live_token_print_nothing_of_the_token() {
        let live = Live {
            key: TokenKey {
                class: TokenClass::Stage,
                repo: RepoRef::parse("example-org/fixture").unwrap(),
                permissions: Vec::new(),
            },
            bearer: Bearer("TOKENVALUE0123456789".to_owned()),
            expires_at: Timestamp::parse("2026-10-28T11:00:00Z").unwrap(),
            handle: None,
        };
        let shown = format!("{:?} {live:?}", live.bearer);
        assert!(!shown.contains("TOKENVALUE"), "{shown}");
    }
}
