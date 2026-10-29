//! The ports the handlers use, and what the API shares between requests.
//!
//! [`ApiPorts`] is the API's own registry: the store, the clock, the identifier source, the webhook
//! verifier, the authority and the allowlist. [`ApiPorts::check`] runs the profile's rule over each
//! of them, the same rule the worker's registry runs over its 25 ports
//! (`factory_composition::registry::check_fidelities`), so the production profile refuses a fake
//! here as it does there. [`ApiState`] is what a handler gets.

use std::sync::Arc;

use factory_composition::config::SecretFile;
use factory_composition::health::{
    CheckResult, EXPECTED_SCHEMA_VERSION, HealthReport, check_schema,
};
use factory_composition::profile::{PortName, Profile};
use factory_composition::registry::{RegistryRefused, check_fidelities};
use factory_composition::seams::FileAllowlist;
use factory_domain::redaction::Redactor;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::WebhookVerifier;
use factory_ports::store::Store;
use factory_workflow::commands::Authority;
use factory_workflow::stages::intake::seams::AllowlistSource;

use crate::config::{GithubSettings, Limits};
use crate::limits::{PlatformAudit, RateLimiter, RefusalBudget};

/// Every port of the API, chosen by the composition root.
#[derive(Clone)]
pub struct ApiPorts {
    /// The store, connected as the API login.
    pub store: Arc<dyn Store>,
    /// The time.
    pub clock: Arc<dyn Clock>,
    /// New identifiers.
    pub ids: Arc<dyn IdGenerator>,
    /// Checks a webhook delivery. `None` when the profile allows the API to run without one: the
    /// webhook route then answers as an unknown route does.
    pub webhooks: Option<Arc<dyn WebhookVerifier>>,
    /// The roles of a principal, from the protected allowlist.
    pub authority: Arc<dyn Authority>,
    /// The allowlist as a source (the same file the authority reads).
    pub allowlist: Arc<dyn AllowlistSource>,
}

impl ApiPorts {
    /// The fidelity each port reports.
    #[must_use]
    pub fn fidelities(&self) -> Vec<(PortName, Fidelity)> {
        let mut found = vec![
            (PortName::Store, self.store.fidelity()),
            (PortName::Clock, self.clock.fidelity()),
            (PortName::Ids, self.ids.fidelity()),
            (PortName::Authority, self.authority.fidelity()),
            (PortName::Allowlist, self.allowlist.fidelity()),
        ];
        if let Some(verifier) = &self.webhooks {
            found.push((PortName::Webhooks, verifier.fidelity()));
        }
        found
    }

    /// Runs the profile's rule for every port, and lists every refusal.
    ///
    /// # Errors
    /// [`RegistryRefused`] with each port the profile does not accept.
    pub fn check(&self, profile: Profile) -> Result<(), RegistryRefused> {
        check_fidelities(profile, &self.fidelities())
    }
}

/// What a handler reads. Built once at start-up and shared.
pub struct ApiState {
    /// The profile.
    pub profile: Profile,
    /// The ports.
    pub ports: ApiPorts,
    /// The allowlist file, for the decision check.
    pub allowlist_file: Arc<FileAllowlist>,
    /// The policy and its hash.
    pub policies: factory_composition::startup::LoadedPolicies,
    /// The one redactor of the process.
    pub redactor: Arc<Redactor>,
    /// The audience of the tokens this API serves.
    pub audience: factory_ports::store::Audience,
    /// GitHub-facing settings.
    pub github: GithubSettings,
    /// The limits.
    pub limits: Limits,
    /// The rate limits.
    pub limiter: RateLimiter,
    /// How many refused decisions of one person are written as audit rows (API-8).
    pub refusals: RefusalBudget,
    /// The queue of audit events for deliveries that belong to no tenant.
    pub platform_audit: PlatformAudit,
    /// Lets a test change what readiness reports as the expected schema.
    pub expected_schema: factory_ports::store::SchemaVersion,
}

impl ApiState {
    /// The hash of the policy bundle in force, for audit records.
    #[must_use]
    pub fn policy_hash(&self) -> Sha256Digest {
        self.policies.hash.clone()
    }

    /// Readiness: the report the `/readyz` route serves.
    pub async fn readiness(&self) -> HealthReport {
        let checks: Vec<CheckResult> = vec![
            check_schema(self.ports.store.as_ref(), self.expected_schema).await,
            CheckResult::pass("policy", "loaded and hashed"),
            match self.ports.check(self.profile) {
                Ok(()) => CheckResult::pass("ports", "every port is acceptable to the profile"),
                Err(refused) => CheckResult::fail("ports", &refused.to_string()),
            },
        ];
        HealthReport::from_checks(self.profile, true, checks, &self.ports.fidelities())
    }
}

/// The expected schema version of this build.
#[must_use]
pub const fn expected_schema() -> factory_ports::store::SchemaVersion {
    EXPECTED_SCHEMA_VERSION
}

/// Reads the webhook secret files of the configuration, for a caller that wants to build the
/// verifier itself.
#[must_use]
pub fn webhook_files(github: &GithubSettings) -> &[SecretFile] {
    &github.webhook_secret_files
}
