//! The redactor, built from the loaded policy, and the registry of the factory's own secret values.
//!
//! Every binary builds **one** redactor at start-up and passes the same `Arc` to every adapter and
//! stage handler that takes one, and to the telemetry setup (ADR 0013). The patterns, the entropy
//! heuristic, the shortest registered value and the encodings come from `policies/security.yaml`
//! section 9 as loaded, hashed and checked by `factory-contracts`; none is written here.
//!
//! # The registry of secret values
//!
//! The policy lists the kinds of value the factory registers for exact matching
//! (`secrets.exact_values.register_from`). [`FactorySecrets`] registers, in every encoding the
//! policy names, each value this process holds:
//!
//! | Policy kind | Where this process gets it |
//! |---|---|
//! | `database_credentials` | the two connection URLs (the whole URL and its password) |
//! | `broker_keys` | the provider key files of the broker |
//! | `app_private_key`, `webhook_secret` | the GitHub files, when configured |
//! | `job_tokens` | each token as the broker issues it: [`RegisteringBroker`] registers on `issue` and forgets on revoke |
//! | `object_store_keys` | none: Slice 1 stores artifacts on the local disk |
//!
//! [`FactorySecrets::unregistered_kinds`] says which policy kinds have no value registered, so a
//! start-up check can refuse to run when a kind the deployment needs is missing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use factory_domain::ids::JobId;
use factory_domain::policy::security::{SecretAction, SecurityPolicy};
use factory_domain::redaction::{
    Encoding, EntropySpec, FlagHandling, PatternAction, PatternSpec, Redactor, SecretHandle,
};
use factory_domain::vocabulary::Fidelity;
use factory_observability::redact::{Scrub, ScrubError};
use factory_ports::agent::{BrokerError, IssuedJobToken, JobTokenRequest, ModelBroker, TokenUsage};
use factory_ports::agent::{JobTokenId, JobTokenSecret};

use crate::config::{ConfigError, SecretFile, SecretText, login_of_url};

/// Why the redactor or the registry could not be set up.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedactionSetupError {
    /// A policy pattern or the entropy settings did not compile.
    #[error("the redactor cannot be built from the policy: {0}")]
    Build(String),
    /// The policy names an encoding this build does not know.
    #[error("the policy names the unknown encoding {0}")]
    UnknownEncoding(String),
    /// A secret file could not be read.
    #[error(transparent)]
    Secret(#[from] ConfigError),
    /// A value cannot be registered (label unusable or value too long).
    #[error("a secret value of kind {0} cannot be registered")]
    Register(&'static str),
}

/// The kinds the policy names, in the words of `exact_values.register_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretKind {
    /// Tokens the broker mints for one job.
    JobTokens,
    /// The GitHub webhook secret.
    WebhookSecret,
    /// The GitHub App private key.
    AppPrivateKey,
    /// Database logins and passwords.
    DatabaseCredentials,
    /// Provider keys held by the broker.
    BrokerKeys,
    /// Object store keys.
    ObjectStoreKeys,
}

impl SecretKind {
    /// The policy's word for the kind, also the label of its redaction marker.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::JobTokens => "job_tokens",
            Self::WebhookSecret => "webhook_secret",
            Self::AppPrivateKey => "app_private_key",
            Self::DatabaseCredentials => "database_credentials",
            Self::BrokerKeys => "broker_keys",
            Self::ObjectStoreKeys => "object_store_keys",
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        [
            Self::JobTokens,
            Self::WebhookSecret,
            Self::AppPrivateKey,
            Self::DatabaseCredentials,
            Self::BrokerKeys,
            Self::ObjectStoreKeys,
        ]
        .into_iter()
        .find(|kind| kind.label() == label)
    }
}

fn action(action: SecretAction) -> PatternAction {
    match action {
        SecretAction::Block => PatternAction::Block,
        SecretAction::Flag => PatternAction::Flag,
    }
}

/// Builds the redactor from section 9 of the security policy.
///
/// # Errors
/// [`RedactionSetupError::Build`] when a pattern does not compile, and
/// [`RedactionSetupError::UnknownEncoding`] for an encoding name this build lacks.
pub fn redactor_from_policy(policy: &SecurityPolicy) -> Result<Redactor, RedactionSetupError> {
    let secrets = &policy.secrets;
    let patterns = secrets
        .patterns
        .iter()
        .map(|p| PatternSpec::new(p.id.clone(), p.regex.0.clone(), action(p.action)));
    let mut encodings = Vec::new();
    for name in &secrets.exact_values.encodings {
        encodings.push(
            Encoding::from_policy_name(name)
                .ok_or_else(|| RedactionSetupError::UnknownEncoding(name.clone()))?,
        );
    }
    let mut builder = Redactor::builder()
        .patterns(patterns)
        .exact_value_min_len(usize::try_from(secrets.exact_values.min_length).unwrap_or(8))
        .encodings(&encodings)
        .flagged(FlagHandling::ReportOnly);
    let entropy = &secrets.entropy_heuristic;
    if entropy.enabled {
        builder = builder.entropy(EntropySpec {
            min_length: usize::try_from(entropy.min_length).unwrap_or(32),
            min_bits_per_char: entropy.min_shannon_bits_per_char,
            action: action(entropy.action),
        });
    }
    builder
        .build()
        .map_err(|error| RedactionSetupError::Build(error.to_string()))
}

/// The secret values this process holds, registered with the redactor.
#[derive(Debug)]
pub struct FactorySecrets {
    redactor: Arc<Redactor>,
    registered: BTreeMap<SecretKind, usize>,
    required: BTreeSet<SecretKind>,
}

impl FactorySecrets {
    /// An empty registry over `redactor`. `policy` says which kinds the deployment must cover.
    #[must_use]
    pub fn new(redactor: Arc<Redactor>, policy: &SecurityPolicy) -> Self {
        let required = policy
            .secrets
            .exact_values
            .register_from
            .iter()
            .filter_map(|name| SecretKind::from_label(name))
            .collect();
        Self {
            redactor,
            registered: BTreeMap::new(),
            required,
        }
    }

    /// The redactor.
    #[must_use]
    pub fn redactor(&self) -> &Arc<Redactor> {
        &self.redactor
    }

    /// Registers one value under a kind.
    ///
    /// # Errors
    /// [`RedactionSetupError::Register`].
    pub fn register(&mut self, kind: SecretKind, value: &str) -> Result<(), RedactionSetupError> {
        self.redactor
            .register(kind.label(), value)
            .map_err(|_| RedactionSetupError::Register(kind.label()))?;
        *self.registered.entry(kind).or_insert(0) += 1;
        Ok(())
    }

    /// Reads a secret file and registers its content.
    ///
    /// # Errors
    /// [`RedactionSetupError::Secret`] or [`RedactionSetupError::Register`].
    pub fn register_file(
        &mut self,
        kind: SecretKind,
        file: &SecretFile,
    ) -> Result<SecretText, RedactionSetupError> {
        let text = file.read()?;
        self.register(kind, text.expose())?;
        Ok(text)
    }

    /// Registers a connection URL and, separately, its password, so that a log line that prints
    /// only the password is found too.
    ///
    /// # Errors
    /// [`RedactionSetupError::Register`].
    pub fn register_database_url(&mut self, url: &str) -> Result<(), RedactionSetupError> {
        self.register(SecretKind::DatabaseCredentials, url)?;
        if let Some(password) = password_of_url(url) {
            self.register(SecretKind::DatabaseCredentials, &password)?;
        }
        Ok(())
    }

    /// Marks a kind as not applicable to this deployment, with the reason kept by the caller.
    pub fn mark_not_applicable(&mut self, kind: SecretKind) {
        self.required.remove(&kind);
    }

    /// The kinds the policy requires and that have no value registered. `JobTokens` are
    /// registered when issued, so they never count as missing at start-up.
    #[must_use]
    pub fn unregistered_kinds(&self) -> Vec<SecretKind> {
        self.required
            .iter()
            .copied()
            .filter(|kind| *kind != SecretKind::JobTokens && !self.registered.contains_key(kind))
            .collect()
    }

    /// How many values are registered for a kind.
    #[must_use]
    pub fn count(&self, kind: SecretKind) -> usize {
        self.registered.get(&kind).copied().unwrap_or(0)
    }
}

/// The password part of a connection URL, if it has one.
fn password_of_url(url: &str) -> Option<String> {
    if !url.contains("://") {
        return crate::config::password_of_key_value(url);
    }
    let login = login_of_url(url)?;
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (userinfo, _) = authority.rsplit_once('@')?;
    let password = userinfo.strip_prefix(&login)?.strip_prefix(':')?;
    if password.is_empty() {
        None
    } else {
        Some(password.to_owned())
    }
}

/// The `Scrub` seam of the telemetry setup, over the real redactor.
///
/// ADR 0013 plans `s1-telemetry-wiring` to implement `Scrub` for the redactor inside the
/// observability crate and to make the scrubber a required argument. That package has not landed,
/// so this newtype is the adapter, and [`crate::telemetry`] passes it with `with_scrubber`.
#[derive(Clone)]
pub struct RedactorScrubber(Arc<Redactor>);

impl RedactorScrubber {
    /// Wraps the redactor.
    #[must_use]
    pub fn new(redactor: Arc<Redactor>) -> Self {
        Self(redactor)
    }

    /// The redactor behind the scrubber.
    #[must_use]
    pub fn redactor(&self) -> &Arc<Redactor> {
        &self.0
    }
}

impl std::fmt::Debug for RedactorScrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactorScrubber")
    }
}

impl Scrub for RedactorScrubber {
    fn scrub<'a>(&self, text: &'a str) -> Result<std::borrow::Cow<'a, str>, ScrubError> {
        let redacted = self
            .0
            .redact_str(text)
            .map_err(|_| ScrubError::Unavailable)?;
        Ok(redacted.output)
    }
}

/// A broker that registers each job token with the redactor when it is issued and forgets it when
/// it is revoked, so a token that reaches a log line or a transcript is found by exact value as
/// well as by the `sfjt_` pattern.
pub struct RegisteringBroker {
    inner: Arc<dyn ModelBroker>,
    redactor: Arc<Redactor>,
    held: Mutex<BTreeMap<String, (JobId, SecretHandle, JobTokenSecret)>>,
}

impl RegisteringBroker {
    /// Wraps `inner`.
    #[must_use]
    pub fn new(inner: Arc<dyn ModelBroker>, redactor: Arc<Redactor>) -> Self {
        Self {
            inner,
            redactor,
            held: Mutex::new(BTreeMap::new()),
        }
    }

    /// The secret of a token that is still held, by its id.
    ///
    /// `AgentSandboxSpecs::agent_spec` receives only a `JobTokenRef` (the id), and the sandbox
    /// spec needs the secret to write the token file. The engine never passes the secret to a
    /// handler, so the composition root keeps it here from `issue` until `revoke`, and the spec
    /// builder looks it up by id.
    #[must_use]
    pub fn secret_of(&self, token: &JobTokenId) -> Option<JobTokenSecret> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&token.to_string())
            .map(|(_, _, secret)| secret.clone())
    }

    /// How many tokens are registered right now.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[async_trait]
impl ModelBroker for RegisteringBroker {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn issue(&self, req: JobTokenRequest) -> Result<IssuedJobToken, BrokerError> {
        let job = req.job;
        let issued = self.inner.issue(req).await?;
        match self
            .redactor
            .register(SecretKind::JobTokens.label(), issued.secret.expose())
        {
            Ok(factory_domain::redaction::Registered::Added(handle)) => {
                self.held
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(issued.id.to_string(), (job, handle, issued.secret.clone()));
            }
            Ok(factory_domain::redaction::Registered::TooShort) | Err(_) => {
                // A token the redactor cannot hold is a token nobody may use: fail closed.
                let _ = self.inner.revoke(&issued.id).await;
                return Err(BrokerError::Unavailable);
            }
        }
        Ok(issued)
    }

    async fn revoke(&self, token: &JobTokenId) -> Result<(), BrokerError> {
        let result = self.inner.revoke(token).await;
        if result.is_ok()
            && let Some((_, handle, _)) = self
                .held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&token.to_string())
        {
            self.redactor.forget(handle);
        }
        result
    }

    async fn revoke_for_job(&self, job: JobId) -> Result<(), BrokerError> {
        let result = self.inner.revoke_for_job(job).await;
        if result.is_ok() {
            let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
            let ids: Vec<String> = held
                .iter()
                .filter(|(_, (owner, _, _))| *owner == job)
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                if let Some((_, handle, _)) = held.remove(&id) {
                    self.redactor.forget(handle);
                }
            }
        }
        result
    }

    async fn usage(&self, token: &JobTokenId) -> Result<TokenUsage, BrokerError> {
        self.inner.usage(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Section 9 of the real policy file, loaded the way a binary loads it.
    fn policy() -> SecurityPolicy {
        crate::startup::tests_support::repository_security_policy()
    }

    #[test]
    fn the_redactor_carries_the_policy_patterns_and_removes_a_token_shaped_value() {
        let policy = policy();
        let redactor = redactor_from_policy(&policy).expect("builds");
        assert_eq!(redactor.pattern_ids().len(), policy.secrets.patterns.len());
        // Built at run time so the source holds no secret-shaped literal.
        let token = ["sfjt", "_", &"a1B2c3D4".repeat(5)].concat();
        let line = format!("token is {token} done");
        let cleaned = redactor.redact_str(&line).expect("redacts");
        assert!(!cleaned.output.contains(&token));
        assert!(cleaned.output.contains("[REDACTED:"));
    }

    #[test]
    fn a_registered_value_is_found_in_its_encodings() {
        let policy = policy();
        let redactor = Arc::new(redactor_from_policy(&policy).expect("builds"));
        let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policy);
        secrets
            .register(SecretKind::BrokerKeys, "plain-key-value-123")
            .expect("registers");
        let hex: String = "plain-key-value-123"
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        let line = format!("raw plain-key-value-123 and hex {hex}");
        let cleaned = redactor.redact_str(&line).expect("redacts");
        assert!(!cleaned.output.contains("plain-key-value-123"));
        assert!(!cleaned.output.contains(&hex));
    }

    #[test]
    fn the_password_of_a_database_url_is_registered_apart_from_the_url() {
        let policy = policy();
        let redactor = Arc::new(redactor_from_policy(&policy).expect("builds"));
        let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policy);
        let url = [
            "postgres",
            "://",
            "factory_worker",
            ":",
            "s3cretPassw0rd",
            "@",
            "db/f",
        ]
        .concat();
        secrets.register_database_url(&url).expect("registers");
        assert_eq!(secrets.count(SecretKind::DatabaseCredentials), 2);
        let cleaned = redactor
            .redact_str("connection failed for s3cretPassw0rd")
            .expect("redacts");
        assert!(!cleaned.output.contains("s3cretPassw0rd"));
    }

    #[test]
    fn a_kind_the_policy_requires_and_nothing_registered_is_reported() {
        let policy = policy();
        let redactor = Arc::new(redactor_from_policy(&policy).expect("builds"));
        let mut secrets = FactorySecrets::new(redactor, &policy);
        let missing = secrets.unregistered_kinds();
        assert!(missing.contains(&SecretKind::DatabaseCredentials));
        assert!(!missing.contains(&SecretKind::JobTokens));
        secrets.mark_not_applicable(SecretKind::ObjectStoreKeys);
        assert!(
            !secrets
                .unregistered_kinds()
                .contains(&SecretKind::ObjectStoreKeys)
        );
    }

    #[test]
    fn the_scrubber_removes_secrets_through_the_telemetry_seam() {
        let policy = policy();
        let redactor = Arc::new(redactor_from_policy(&policy).expect("builds"));
        let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policy);
        secrets
            .register(SecretKind::AppPrivateKey, "app-private-material-xyz")
            .expect("registers");
        let scrubber = RedactorScrubber::new(redactor);
        let cleaned = scrubber
            .scrub("log app-private-material-xyz end")
            .expect("scrubs");
        assert!(!cleaned.contains("app-private-material-xyz"));
    }
}
