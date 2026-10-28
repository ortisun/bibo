//! The webhook verifier of the API, built from secret files.
//!
//! The API depends on the `WebhookVerifier` port and not on the `github` crate (ADR 0014), so the
//! composition library, which may depend on several adapters, builds the real verifier. Each file
//! holds one webhook secret; more than one file is a rotation window, and a delivery signed with
//! any of them is accepted (NT-WH-08). Every secret is registered with the redactor under the kind
//! `webhook_secret`, so a log line that prints one is redacted.

use std::sync::Arc;

use factory_github::{GithubWebhookVerifier, WebhookSecret};
use factory_ports::githost::WebhookVerifier;

use crate::config::SecretFile;
use crate::redaction::{FactorySecrets, SecretKind};
use crate::startup::StartupFailure;

/// Builds the GitHub webhook verifier from the files named in the configuration.
///
/// # Errors
/// [`StartupFailure::Other`] when no file is named, a file is unsafe or unreadable, or a secret is
/// shorter than the adapter allows.
pub fn verifier_from_files(
    files: &[SecretFile],
    secrets: &mut FactorySecrets,
) -> Result<Arc<dyn WebhookVerifier>, StartupFailure> {
    let mut parsed = Vec::with_capacity(files.len());
    for file in files {
        let text = secrets
            .register_file(SecretKind::WebhookSecret, file)
            .map_err(|error| StartupFailure::Other(error.to_string()))?;
        parsed.push(
            WebhookSecret::new(text.expose().as_bytes()).map_err(|error| {
                StartupFailure::Other(format!(
                    "the webhook secret in {} is refused: {error}",
                    file.path().display()
                ))
            })?,
        );
    }
    let verifier = GithubWebhookVerifier::new(parsed)
        .map_err(|error| StartupFailure::Other(error.to_string()))?;
    Ok(Arc::new(verifier))
}
