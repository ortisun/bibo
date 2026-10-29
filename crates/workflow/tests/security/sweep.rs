//! The canaries and the sweep of the sinks of a job.
//!
//! Every secret value is built at run time from parts, so that no secret-shaped literal sits in
//! the source. The classes are the ones of `secrets.patterns` in `policies/security.yaml`, plus the
//! values the factory registers itself (job tokens, the webhook secret, the key that signs
//! decisions, database passwords). A canary of a class that has a pattern has the shape of the
//! pattern, so the pattern can find it even when nothing registered its value.

use factory_domain::contracts::ArtifactRef;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_ports::artifact::ArtifactStore;
use factory_testkit::fx::canary::{Canary, CanarySet};
use factory_testkit::fx::sinks::{SinkCollector, SinkKind};
use serde_json::Value;

use crate::rig::Rig;

const ALNUM: &[u8] = b"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

/// `n` letters and digits that look random and are the same on every run.
fn filler(n: usize, offset: usize) -> String {
    (0..n)
        .map(|i| ALNUM[(i * 7 + offset * 13 + i / 5) % ALNUM.len()] as char)
        .collect()
}

fn upper_digits(n: usize, offset: usize) -> String {
    filler(n, offset)
        .chars()
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// A canary for every class of secret that the policy names, with the label of its class.
pub fn every_class() -> CanarySet {
    let join = |prefix: &str, rest: String| format!("{prefix}{rest}");
    let make = |label: &str, value: String| Canary::custom(label, &value);
    CanarySet::generate()
        .with(make(
            "api_token",
            join(&format!("{}{}", "sf", "at_"), filler(43, 1)),
        ))
        .with(make(
            "github_token_classic",
            join(&format!("{}{}", "gh", "p_"), filler(36, 2)),
        ))
        .with(make(
            "github_fine_grained",
            join(&format!("{}{}", "github", "_pat_"), filler(40, 3)),
        ))
        .with(make(
            "openai_api_key",
            join(&format!("{}{}", "sk", "-proj-"), filler(40, 4)),
        ))
        .with(make(
            "aws_access_key_id",
            join(&format!("{}{}", "AK", "IA"), upper_digits(16, 5)),
        ))
        .with(make(
            "gcp_api_key",
            join(&format!("{}{}", "AI", "za"), filler(35, 6)),
        ))
        .with(make(
            "slack_token",
            join(&format!("{}{}", "xo", "xb-"), filler(24, 7)),
        ))
        .with(make(
            "npm_token",
            join(&format!("{}{}", "np", "m_"), filler(36, 8)),
        ))
        .with(make(
            "jwt",
            format!(
                "{}.{}.{}",
                join(&format!("{}{}", "ey", "J"), filler(20, 9)),
                join(&format!("{}{}", "ey", "J"), filler(24, 10)),
                filler(30, 11)
            ),
        ))
        .with(make(
            "url_with_credentials",
            format!(
                "https://deploy:{}@registry.internal.test/path",
                filler(18, 12)
            ),
        ))
        .with(make(
            "database_url",
            format!(
                "postgres://factory:{}@db.internal.test:5432/factory",
                filler(20, 13)
            ),
        ))
        .with(make(
            "decision_signing_key",
            filler(64, 14).to_ascii_lowercase(),
        ))
        .with(make(
            "authorization_header",
            format!("Authorization: Bearer {}", filler(32, 15)),
        ))
}

/// Records everything the job wrote down. The ledger and the audit log are read through the
/// store, the artifacts through the artifact store by every hash the job's records name, and the
/// prompts and the log lines from the rig.
pub async fn collect(rig: &Rig) -> SinkCollector {
    let sinks = SinkCollector::new();
    let job = rig.job;
    for record in rig.world.audit(job).await {
        sinks.record(
            SinkKind::AuditRow,
            &format!("audit#{}", record.sequence),
            format!("{record:?}"),
        );
    }
    for event in rig.world.events(job).await {
        sinks.record(SinkKind::OutboxRow, "outbox", format!("{event:?}"));
    }
    let mut hashes = Vec::new();
    for entry in rig.world.ledger(job).await {
        let document = serde_json::to_value(&entry).expect("an entry serializes");
        sinks.record_json(SinkKind::DatabaseDump, "ledger", &document);
        hashes_in(&document, &mut hashes);
    }
    let view = rig.world.view(job).await;
    for run in &view.stage_runs {
        for link in rig.world.links(run.id).await {
            hashes.push(link.sha256.to_string());
        }
    }
    hashes.sort();
    hashes.dedup();
    let tenant = TenantScope::new(rig.world.tenant);
    for text in hashes {
        let Ok(sha256) = Sha256Digest::parse(&text) else {
            continue;
        };
        let reference = ArtifactRef {
            sha256,
            media_type: MediaType::parse("application/json").expect("a media type"),
            size_bytes: None,
        };
        if let Ok(bytes) = ArtifactStore::get(&*rig.artifacts, &tenant, &reference).await {
            sinks.record(SinkKind::Artifact, &text, bytes);
        }
    }
    for agent in ["builder", "code-reviewer"] {
        for prompt in rig.runtime.prompts(agent) {
            sinks.record(
                SinkKind::CapturedPrompt,
                &format!("{agent} instructions"),
                &prompt.instructions,
            );
            for part in &prompt.data {
                sinks.record(
                    SinkKind::CapturedPrompt,
                    &format!("{agent} data {}", part.source),
                    &part.text,
                );
            }
        }
    }
    for line in rig.events() {
        sinks.record(SinkKind::LogLine, "rig log", line);
    }
    sinks.record(
        SinkKind::LogLine,
        "what the scripted model did",
        format!("{:?}", rig.runtime.inner.performed()),
    );
    sinks
}

fn hashes_in(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) if text.starts_with("sha256:") => found.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| hashes_in(item, found)),
        Value::Object(map) => map.values().for_each(|item| hashes_in(item, found)),
        _ => {}
    }
}

/// How many entries of each kind of sink were swept, so that a sweep of nothing cannot pass.
pub fn count(sinks: &SinkCollector, kind: SinkKind) -> usize {
    sinks.entries().iter().filter(|e| e.kind == kind).count()
}
