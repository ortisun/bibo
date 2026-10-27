//! Small builders for the values the contract suites and the fakes' tests need: typed identifiers
//! from a deterministic generator, a valid ledger entry, a valid domain event, and a sandbox
//! policy and spec that satisfy it.

use std::path::PathBuf;
use std::time::Duration;

use factory_domain::contracts::{Contract, DomainEvent, EvidenceLedgerEntry};
use factory_domain::ids::{
    AttemptId, CorrelationId, EventId, JobId, LedgerEntryId, PrincipalId, StageRunId, TaskNodeId,
    TenantId,
};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_ports::clock::IdGenerator;
use factory_ports::sandbox::{
    ExecArgv, FixedEnv, Hardening, ImageDigest, JobTokenFile, NetworkAttachment, SandboxLimits,
    SandboxPolicy, SandboxProfile, SandboxSpec,
};
use factory_ports::workspace::WorkspaceMounts;
use serde_json::json;

use crate::clock::SequentialIdGenerator;

/// Typed identifiers from a deterministic generator.
#[derive(Debug, Default)]
pub struct Ids {
    generator: SequentialIdGenerator,
}

impl Ids {
    /// A fresh set of identifiers, starting at counter 1.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A new tenant id.
    pub fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.generator.new_uuid())
    }

    /// A new job id.
    pub fn job(&self) -> JobId {
        JobId::from_uuid(self.generator.new_uuid())
    }

    /// A new stage run id.
    pub fn stage_run(&self) -> StageRunId {
        StageRunId::from_uuid(self.generator.new_uuid())
    }

    /// A new attempt id.
    pub fn attempt(&self) -> AttemptId {
        AttemptId::from_uuid(self.generator.new_uuid())
    }

    /// A new task node id.
    pub fn task_node(&self) -> TaskNodeId {
        TaskNodeId::from_uuid(self.generator.new_uuid())
    }

    /// A new principal id.
    pub fn principal(&self) -> PrincipalId {
        PrincipalId::from_uuid(self.generator.new_uuid())
    }

    /// A new correlation id.
    pub fn correlation(&self) -> CorrelationId {
        CorrelationId::from_uuid(self.generator.new_uuid())
    }

    /// A new event id.
    pub fn event(&self) -> EventId {
        EventId::from_uuid(self.generator.new_uuid())
    }

    /// A new ledger entry id.
    pub fn ledger_entry(&self) -> LedgerEntryId {
        LedgerEntryId::from_uuid(self.generator.new_uuid())
    }
}

/// A valid, sealed ledger entry for `job`.
///
/// `sequence` is the position in the chain, from 1. `previous` is the `entry_hash` of the entry
/// before it, and must be `None` exactly when `sequence` is 1. The entry is an assumption by a
/// fake component in test mode, so it needs no evidence. Its hash is computed by the domain's
/// chain code.
///
/// # Panics
/// Panics when the arguments describe an entry the domain refuses (for example a missing
/// `previous` after the first entry). That is a bug in the test.
#[must_use]
pub fn ledger_entry(
    ids: &Ids,
    job: JobId,
    stage_run: StageRunId,
    sequence: u64,
    previous: Option<&Sha256Digest>,
    recorded_at: &Timestamp,
    statement: &str,
) -> EvidenceLedgerEntry {
    let zero_hash = format!("sha256:{}", "0".repeat(64));
    let document = json!({
        "schema_version": 1,
        "metadata": {
            "entry_id": ids.ledger_entry().to_string(),
            "job_id": job.to_string(),
            "stage_run_id": stage_run.to_string(),
            "sequence": sequence,
            "recorded_at": recorded_at.to_string(),
            "execution_mode": "test",
            "recorded_by": { "component": "testkit.fake", "fidelity": "fake" }
        },
        "claim": { "statement": format!("{statement} Recorded by a test fixture."), "kind": "assumption" },
        "evidence": [],
        "confidence": { "level": "low", "rationale": "A test fixture makes no measurement." },
        "prev_entry_hash": previous.map(ToString::to_string),
        "entry_hash": zero_hash
    });
    EvidenceLedgerEntry::from_json_value(document)
        .expect("the fixture ledger entry follows the schema")
        .sealed()
        .expect("the fixture ledger entry can be hashed")
}

/// A valid domain event for `job` in `tenant`.
///
/// # Panics
/// Panics when the arguments describe an event the domain refuses. That is a bug in the test.
#[must_use]
pub fn domain_event(
    ids: &Ids,
    tenant: TenantId,
    job: JobId,
    aggregate_version: i64,
    occurred_at: &Timestamp,
) -> DomainEvent {
    let document = json!({
        "schema_version": 1,
        "event_id": ids.event().to_string(),
        "event_type": "job.admitted",
        "event_version": 1,
        "tenant_id": tenant.to_string(),
        "job_id": job.to_string(),
        "aggregate": { "type": "job", "id": job.to_string(), "version": aggregate_version },
        "transition_id": "J01",
        "correlation_id": job.to_string(),
        "causation_id": null,
        "occurred_at": occurred_at.to_string(),
        "producer": "testkit.fake",
        "payload": {}
    });
    DomainEvent::from_json_value(document).expect("the fixture domain event follows the schema")
}

/// The digest of the image the fixtures run, pinned the way the policy requires.
///
/// # Panics
/// Never in practice: the literal is a valid digest reference.
#[must_use]
pub fn image() -> ImageDigest {
    ImageDigest::parse(&format!(
        "registry.local/factory/sandbox@sha256:{}",
        "a".repeat(64)
    ))
    .expect("a valid digest reference")
}

fn limits(scale: u32) -> SandboxLimits {
    SandboxLimits {
        cpu_millis: 1000 * scale,
        memory_mb: 1024 * scale,
        memory_swap_mb: 1024 * scale,
        pids: 128 * scale,
        nofile: 2048,
        max_file_mb: 512,
        tmpfs_mb: 256,
        workspace_disk_mb: 2048,
        wall_clock: Duration::from_secs(600 * u64::from(scale)),
    }
}

/// A sandbox policy for tests, shaped like the `sandbox` section of `policies/security.yaml`.
/// The real values are loaded from that file by the sandbox adapter; this one only has to be
/// strict enough to exercise every rule.
#[must_use]
pub fn sandbox_policy() -> SandboxPolicy {
    SandboxPolicy {
        min_uid: 10_000,
        forbidden_mount_sources: [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/",
            "/etc",
            "/root",
            "/home",
            "/var",
            "/usr",
            "/proc",
            "/sys",
            "/dev",
        ]
        .map(String::from)
        .to_vec(),
        forbidden_env_names: ["LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS", "BASH_ENV"]
            .map(String::from)
            .to_vec(),
        allowed_env_names: ["HOME", "PATH", "TERM", "LANG"].map(String::from).to_vec(),
        fetch_deps_max: limits(1),
        agent_max: limits(2),
        verify_max: limits(4),
    }
}

/// A sandbox spec that satisfies [`sandbox_policy`] for the given profile.
///
/// # Panics
/// Never in practice: every literal is valid.
#[must_use]
pub fn sandbox_spec(ids: &Ids, profile: SandboxProfile) -> SandboxSpec {
    let (network, job_token) = match profile {
        SandboxProfile::Verify => (NetworkAttachment::None, None),
        SandboxProfile::FetchDeps => (
            NetworkAttachment::JobInternal {
                sidecar: "sidecar-fixture".to_owned(),
            },
            None,
        ),
        SandboxProfile::Agent => (
            NetworkAttachment::JobInternal {
                sidecar: "sidecar-fixture".to_owned(),
            },
            Some(JobTokenFile {
                host_path: PathBuf::from("/run/factory/fixture-token"),
            }),
        ),
    };
    SandboxSpec {
        job: ids.job(),
        attempt: ids.attempt(),
        profile,
        image: image(),
        limits: limits(1),
        network,
        mounts: WorkspaceMounts {
            workspace: PathBuf::from("/fake/job/worktree"),
            out: PathBuf::from("/fake/job/out"),
            protected_overlays: Vec::new(),
            git_masked: true,
        },
        job_token,
        env: FixedEnv::new(vec![("HOME".to_owned(), "/home/agent".to_owned())])
            .expect("a valid environment"),
        hardening: Hardening::strict(10_001, 10_001),
        extra_mounts: Vec::new(),
    }
}

/// A command from words, for example `argv(&["echo", "hello"])`.
///
/// # Panics
/// Panics when the words are not a usable command (empty, or holding a NUL byte).
#[must_use]
pub fn argv(words: &[&str]) -> ExecArgv {
    ExecArgv::new(words.iter().map(|word| (*word).to_owned()).collect()).expect("a usable command")
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::ledger::verify_chain;

    #[test]
    fn fixture_ledger_entries_form_a_valid_chain() {
        let ids = Ids::new();
        let job = ids.job();
        let stage = ids.stage_run();
        let at = Timestamp::parse("2026-10-27T08:30:00Z").unwrap();
        let first = ledger_entry(&ids, job, stage, 1, None, &at, "First.");
        let second = ledger_entry(&ids, job, stage, 2, Some(&first.entry_hash), &at, "Second.");
        assert_eq!(verify_chain(&[first, second]), Ok(()));
    }

    #[test]
    fn the_fixture_event_is_valid() {
        let ids = Ids::new();
        let at = Timestamp::parse("2026-10-27T08:30:00Z").unwrap();
        let event = domain_event(&ids, ids.tenant(), ids.job(), 2, &at);
        assert_eq!(event.event_type.as_str(), "job.admitted");
    }

    #[test]
    fn the_fixture_specs_satisfy_the_fixture_policy() {
        let ids = Ids::new();
        for profile in [
            SandboxProfile::FetchDeps,
            SandboxProfile::Agent,
            SandboxProfile::Verify,
        ] {
            assert_eq!(
                sandbox_spec(&ids, profile).validate(&sandbox_policy()),
                Ok(()),
                "{profile:?}"
            );
        }
    }
}
