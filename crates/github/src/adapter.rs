//! The adapter as a whole: one value that holds the transport, the signer, the clock, the redactor
//! and the tenant bindings, and hands out the two ports.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use factory_domain::ids::JobId;
use factory_domain::redaction::Redactor;
use factory_domain::values::Slug;
use factory_ports::clock::Clock;
use factory_ports::githost::{
    AppId, BypassAttestation, GitHostError, GitScope, IssueSource, PreflightVerdict, WorkflowRule,
};
use factory_ports::paths::RepoRef;

use crate::changes::GithubChangeHost;
use crate::client::{Client, PageLimits};
use crate::core::{BackoffPolicy, HttpCore, Sleeper};
use crate::issues::GithubIssueSource;
use crate::jwt::JwtSigner;
use crate::permissions::{AppAudit, AppPolicy};
use crate::project_rules::GithubProjectRules;
use crate::status::GithubIssueStatus;
use crate::text::{Outbound, OutboundPolicy};
use crate::token::{InstallationDirectory, MinterSettings, TokenMinter};
use crate::triage::GithubTriageIssues;
use crate::wire::{ApiBase, Transport};

/// A token with less than this left of its hour is replaced before use.
pub const DEFAULT_REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

/// Settings of the adapter.
#[derive(Debug, Clone)]
pub struct GithubConfig {
    /// The App's id.
    pub app_id: AppId,
    /// Where the API is. Used to decide which pagination links may be followed.
    pub base: ApiBase,
    /// What the App must and must not hold.
    pub app_policy: AppPolicy,
    /// When a token is replaced before it expires.
    pub refresh_margin: Duration,
    /// How rate limits and server errors are retried.
    pub backoff: BackoffPolicy,
    /// How listings are read.
    pub pages: PageLimits,
    /// What may be sent as text.
    pub outbound: OutboundPolicy,
}

impl GithubConfig {
    /// The defaults for everything but the App, the base URL and the permission policy.
    #[must_use]
    pub fn new(app_id: AppId, base: ApiBase, app_policy: AppPolicy) -> Self {
        Self {
            app_id,
            base,
            app_policy,
            refresh_margin: DEFAULT_REFRESH_MARGIN,
            backoff: BackoffPolicy::default(),
            pages: PageLimits::default(),
            outbound: OutboundPolicy::default(),
        }
    }
}

/// The collaborators of the adapter. Each is a port or a seam, so a test replaces any of them.
pub struct GithubParts {
    /// Sends requests.
    pub transport: Arc<dyn Transport>,
    /// Signs the App JWT.
    pub signer: Arc<dyn JwtSigner>,
    /// The time, for the JWT and for token expiry.
    pub clock: Arc<dyn Clock>,
    /// The redactor. Every installation token is registered with it, and every text bound for
    /// GitHub is checked with it.
    pub redactor: Arc<Redactor>,
    /// Which installation covers which tenant's repository.
    pub directory: Arc<dyn InstallationDirectory>,
    /// Waits for a back-off.
    pub sleeper: Arc<dyn Sleeper>,
}

/// The GitHub App adapter.
#[derive(Clone)]
pub struct GithubAdapter {
    client: Arc<Client>,
    outbound: Arc<Outbound>,
    clock: Arc<dyn Clock>,
    sleeper: Arc<dyn Sleeper>,
    app_id: AppId,
}

impl std::fmt::Debug for GithubAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubAdapter")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

impl GithubAdapter {
    /// Builds the adapter. Nothing is sent until a port method is called.
    #[must_use]
    pub fn new(config: GithubConfig, parts: GithubParts) -> Self {
        let core = Arc::new(HttpCore::new(
            parts.transport,
            Arc::clone(&parts.sleeper),
            Arc::clone(&parts.clock),
            config.backoff,
        ));
        let minter = Arc::new(TokenMinter::new(
            Arc::clone(&core),
            parts.signer,
            Arc::clone(&parts.clock),
            parts.directory,
            Arc::clone(&parts.redactor),
            MinterSettings {
                app: config.app_id,
                policy: config.app_policy,
                refresh_margin: config.refresh_margin,
            },
        ));
        let client = Arc::new(Client::new(core, minter, config.base, config.pages));
        Self {
            client,
            outbound: Arc::new(Outbound::new(parts.redactor, config.outbound)),
            clock: parts.clock,
            sleeper: parts.sleeper,
            app_id: config.app_id,
        }
    }

    /// The issue source.
    #[must_use]
    pub fn issue_source(&self) -> GithubIssueSource {
        GithubIssueSource::new(Arc::clone(&self.client), Arc::clone(&self.clock))
    }

    /// The change host.
    #[must_use]
    pub fn change_host(&self) -> GithubChangeHost {
        GithubChangeHost::new(
            Arc::clone(&self.client),
            Arc::clone(&self.outbound),
            self.app_id,
            Arc::clone(&self.clock),
        )
    }

    /// The status writer: one `factory: <state>` label and one status comment on an issue, with a
    /// token of its own that holds `issues: write` for one repository and nothing else.
    #[must_use]
    pub fn issue_status_writer(&self) -> GithubIssueStatus {
        GithubIssueStatus::new(
            Arc::clone(&self.client),
            Arc::clone(&self.outbound),
            Arc::clone(&self.sleeper),
            Arc::clone(&self.clock),
        )
    }

    /// The troubleshooter's triage issue writer (ports v1.3), bound to `issue_repository`, the
    /// `troubleshooting.issue_repository` of the configuration. It works under a run's scope with a
    /// token of its own (`issues: write`, `metadata: read`) and refuses any other repository.
    #[must_use]
    pub fn triage_issue_writer(&self, issue_repository: RepoRef) -> GithubTriageIssues {
        GithubTriageIssues::new(
            Arc::clone(&self.client),
            Arc::clone(&self.outbound),
            Arc::clone(&self.sleeper),
            Arc::clone(&self.clock),
            issue_repository,
        )
    }

    /// The project rules host: the draft pull request that installs or updates the project's
    /// rules for agents, with a token of its own that holds `contents: write` and
    /// `pull_requests: write` for one repository (ports v1.4, ADR 0026).
    #[must_use]
    pub fn project_rules_host(&self) -> GithubProjectRules {
        GithubProjectRules::new(
            Arc::clone(&self.client),
            Arc::clone(&self.outbound),
            Arc::clone(&self.sleeper),
            Arc::clone(&self.clock),
        )
    }

    /// Reads the App's own permissions (`GET /app`, signed with the App JWT) and judges them
    /// against the policy: a forbidden permission refuses onboarding, a missing required one caps
    /// the repository at level L0. Run at onboarding. The same check runs, without the cap, on the
    /// first token of every job.
    ///
    /// # Errors
    /// [`GitHostError`] when the App cannot be read.
    pub async fn audit_app(&self) -> Result<AppAudit, GitHostError> {
        self.client.minter().audit_now().await
    }

    /// The repository protection preflight: reads the rulesets with the Metadata permission and
    /// classic branch protection with the protection read token (`administration: read`), and
    /// judges the stricter of the two, together with the admin's bypass attestation, against the
    /// policy.
    /// `required_approvals` is the number of approving reviews the policy says a pull request
    /// needs (SF-07). A failure to read is an error, which the engine treats as level L0.
    ///
    /// It does not judge the workflows of the repository (threat T-48): this crate has no YAML
    /// reader. The worker's preflight (`factory_composition::preflight`) reads them through
    /// `IssueSource::workflow_files` and judges them; this method is the rules and the statement
    /// only, and no production code calls it.
    ///
    /// # Errors
    /// [`GitHostError`] when the rules cannot be read.
    pub async fn preflight(
        &self,
        scope: &GitScope,
        factory_checks: &[Slug],
        attestation: Option<&BypassAttestation>,
        required_approvals: u32,
    ) -> Result<PreflightVerdict, GitHostError> {
        let report = self.issue_source().repository_protection(scope).await?;
        Ok(report.evaluate(
            self.app_id,
            factory_checks,
            attestation,
            required_approvals,
            WorkflowRule::RECORD_ONLY,
        ))
    }

    /// The cleanup sweep: revokes the tokens of every job that is not in `running`, whether the
    /// job's end was missed or an earlier revocation failed. Returns how many were revoked.
    pub async fn sweep_orphans(&self, running: &HashSet<JobId>) -> usize {
        self.client.minter().sweep(running).await
    }

    /// Revokes the tokens of the jobs in `idle` that are not running, without ending the jobs
    /// (LB-04). A job that has waited blocked for a long time should not hold a token until
    /// GitHub expires it, and it is not over: when it goes on, its next call mints a new token,
    /// which an ended job cannot do. `running_now` is asked after the tokens are listed, as for
    /// [`sweep_orphans_after`](Self::sweep_orphans_after). Returns how many tokens were revoked.
    pub async fn release_idle_after(
        &self,
        idle: &HashSet<JobId>,
        running_now: &dyn Fn() -> HashSet<JobId>,
    ) -> usize {
        self.client
            .minter()
            .release_idle_after(idle, running_now)
            .await
    }

    /// The cleanup sweep for a caller whose set of running work changes while it looks: `open` is
    /// what it has read, and `running_now` is asked after the live tokens are listed, so that a
    /// job that began meanwhile is spared (finding STS-4). Returns how many tokens were revoked.
    pub async fn sweep_orphans_after(
        &self,
        open: &HashSet<JobId>,
        running_now: &dyn Fn() -> HashSet<JobId>,
    ) -> usize {
        self.client.minter().sweep_after(open, running_now).await
    }
}
