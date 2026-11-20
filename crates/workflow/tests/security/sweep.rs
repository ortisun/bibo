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
use factory_testkit::fx::sinks::{SinkCollector, SinkKind};
use serde_json::Value;

use crate::rig::Rig;

pub use crate::classes::every_class;

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
