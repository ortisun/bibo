//! Small builders for the values the contract suites and the fakes' tests need: typed identifiers
//! from a deterministic generator, a valid ledger entry, a valid domain event, and a sandbox
//! policy and spec that satisfy it.

use std::path::PathBuf;
use std::time::Duration;

use factory_domain::contracts::stage_contract::RetryClass;
use factory_domain::contracts::{
    AgentManifest, Contract, DomainEvent, EvidenceLedgerEntry, VersionedRef,
};
use factory_domain::ids::{
    AttemptId, CorrelationId, EventId, JobId, LedgerEntryId, PrincipalId, StageRunId, TaskNodeId,
    TenantId,
};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::{
    AdmissionFacts, ApprovalFacts, AttemptsFacts, BlockingFacts, CancelFacts, DeadlineFacts,
    EnvironmentCause, EnvironmentFacts, EpochFacts, EscalationFacts, GatePassFacts, GuardCleared,
    GuardFacts, LeaseExpiryFacts, LeaseGrantFacts, NeedsHumanFacts, NotApplicableBasis,
    NotApplicableFacts, OutputFacts, RetryFacts, ReworkFacts, SandboxGoneFacts,
    SandboxProvisionFacts, TaskDepsFacts, TaskEvidenceFacts, TaskStartFacts, TeardownFacts,
    UnrecoverableFacts, UpstreamFacts, evaluate,
};
use factory_domain::machines::limits::{RepairCap, ReworkCap};
use factory_domain::state::{Guard, JobStatus};
use factory_domain::values::{NonEmptyString, Sha256Digest, Timestamp, Uri};
use factory_domain::vocabulary::StageKind;
use factory_ports::agent::JobTokenSecret;
use factory_ports::agent::{
    AgentRunRequest, AssembledPrompt, BrokerEndpoint, DataClass, DataPart, FlagSet, JobTokenId,
    JobTokenRef, ModelSelection, RuntimeId,
};
use factory_ports::clock::IdGenerator;
use factory_ports::sandbox::{
    ExecArgv, FixedEnv, Hardening, ImageDigest, JobTokenMount, NetworkAttachment, SandboxLimits,
    SandboxMounts, SandboxPolicy, SandboxProfile, SandboxSpec,
};
use factory_ports::workspace::WorkspaceMounts;
use serde_json::json;
use std::num::NonZeroU32;

use crate::clock::SequentialIdGenerator;

/// A repository for a test that runs against a real database, written as SQL for the table owner.
///
/// The table refuses a repository that is enabled without a project map, for every role. So a
/// fixture that wants a repository which takes work has to do what a person does: have somebody
/// attest the map. [`SeededRepository::sql`] writes that person (a human principal, one for each
/// tenant, with a GitHub user id no test uses) and the repository, enabled, with a map commit
/// that names the person. It is the one place the fixtures of the other crates get this from, so
/// they cannot drift apart. A test of the registration path itself does not use it: it registers
/// through the API or the store and attests the map there.
#[derive(Debug, Clone, Copy)]
pub struct SeededRepository<'a> {
    /// The tenant, as a hyphenated UUID.
    pub tenant: &'a str,
    /// The repository, as a hyphenated UUID.
    pub id: &'a str,
    /// The GitHub App installation.
    pub installation: u64,
    /// GitHub's numeric repository id.
    pub github_repository: u64,
    /// `owner/name`.
    pub full_name: &'a str,
    /// The default branch.
    pub default_branch: &'a str,
    /// The autonomy ceiling an administrator set: `L0` to `L3`.
    pub autonomy_ceiling: &'a str,
}

impl SeededRepository<'_> {
    /// The GitHub user id of the person who attests the map in a fixture.
    pub const ATTESTOR_GITHUB_USER: u64 = 4_000_000_001;

    /// The commit a fixture attests.
    pub const MAP_COMMIT: &'static str = "0123456789abcdef0123456789abcdef01234567";

    /// Two statements: the attesting person (once for each tenant) and the enabled repository.
    #[must_use]
    pub fn sql(&self) -> String {
        let tenant = self.tenant;
        let attestor = format!("md5('map-attestor-{tenant}')::uuid");
        format!(
            "INSERT INTO principals (tenant_id, id, kind, github_user_id, login) \
               VALUES ('{tenant}', {attestor}, 'human', {user}, 'map-attestor') \
               ON CONFLICT (tenant_id, id) DO NOTHING; \
             INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, \
                    full_name, default_branch, autonomy_ceiling, enabled, project_map_commit, \
                    project_map_attested_by_principal_id, enabled_by_principal_id) \
               VALUES ('{tenant}', '{id}', {installation}, {github}, '{full_name}', '{branch}', \
                    '{ceiling}', true, '{commit}', {attestor}, {attestor});",
            user = Self::ATTESTOR_GITHUB_USER,
            id = self.id,
            installation = self.installation,
            github = self.github_repository,
            full_name = self.full_name,
            branch = self.default_branch,
            ceiling = self.autonomy_ceiling,
            commit = Self::MAP_COMMIT,
        )
    }
}

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

    /// A new identifier for a row that has no typed id of its own.
    pub fn uuid7(&self) -> factory_ports::store::Uuid7 {
        self.generator.new_uuid()
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

fn nz(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("a non-zero fixture value")
}

fn limits(scale: u32) -> SandboxLimits {
    SandboxLimits {
        cpu_millis: nz(1000 * scale),
        memory_mb: nz(1024 * scale),
        memory_swap_mb: nz(1024 * scale),
        pids: nz(128 * scale),
        nofile: nz(2048),
        max_file_mb: nz(512),
        tmpfs_mb: nz(256),
        workspace_disk_mb: nz(2048),
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
        apparmor_may_be_unavailable: false,
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
            Some(JobTokenMount {
                // Built at run time so that no secret-shaped literal sits in the source.
                secret: JobTokenSecret::new(format!("{}-{}", "fixture", "job-token")),
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
        mounts: SandboxMounts {
            workspace: WorkspaceMounts {
                workspace: PathBuf::from("/fake/job/worktree"),
                workspace_read_only: profile == SandboxProfile::Verify,
                out: PathBuf::from("/fake/job/out"),
                protected_overlays: Vec::new(),
                git_masked: true,
            },
            caches: Vec::new(),
        },
        job_token,
        env: FixedEnv::new(vec![("HOME".to_owned(), "/home/agent".to_owned())])
            .expect("a valid environment"),
        hardening: Hardening::strict(10_001, 10_001),
    }
}

/// The builder agent's manifest, from the schema examples.
///
/// # Panics
/// Never in practice: the example is checked by the domain crate's own tests.
#[must_use]
pub fn builder_manifest() -> AgentManifest {
    AgentManifest::from_json_str(include_str!(
        "../../../schemas/examples/agent-manifest/valid/builder.json"
    ))
    .expect("the builder example is a valid agent manifest")
}

/// A well-formed agent run request for the builder agent: a prompt with its instructions and one
/// issue text apart, the builder's tools and limits, and a job token reference.
///
/// # Panics
/// Never in practice: every literal is valid.
#[must_use]
pub fn agent_run_request(ids: &Ids) -> AgentRunRequest {
    let manifest = builder_manifest();
    let issue = "Please add a word count command to the tool.";
    AgentRunRequest {
        attempt: ids.attempt(),
        agent: VersionedRef {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
        },
        prompt: AssembledPrompt {
            instructions: "You are the builder. Do the planned task and nothing else.".to_owned(),
            data: vec![DataPart {
                source: "issue#12".to_owned(),
                class: DataClass::IssueText,
                sha256: Sha256Digest::of(issue.as_bytes()),
                text: issue.to_owned(),
            }],
        },
        output_schema: manifest.outputs_schema.clone(),
        broker: BrokerEndpoint {
            base_url: Uri::parse("https://model-broker.sandbox.internal:8443")
                .expect("a valid URI"),
        },
        job_token: JobTokenRef {
            id: JobTokenId::from_uuid(ids.generator.new_uuid()),
        },
        tools: manifest.allowed_tools.as_slice().to_vec(),
        limits: manifest.resource_limits.clone(),
        model: ModelSelection {
            runtime: RuntimeId::new("fake").expect("a valid runtime id"),
            model: NonEmptyString::parse("fake-model").expect("a valid model name"),
        },
        flag_set: FlagSet::Standard,
        max_output_bytes: 1_048_576,
    }
}

/// A clearance for `guard`, from facts on which it holds. For tests that plan a transition and do
/// not care what the guard looked at. The facts are plain, so a test that cares builds its own.
///
/// # Panics
/// Panics for a guard this helper has no facts for. Add them here.
pub fn cleared(guard: Guard) -> GuardCleared {
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("a valid time");
    let epoch = EpochFacts {
        sent_epoch: 1,
        stored_epoch: 1,
    };
    let request = Sha256Digest::of(b"request");
    let none_authorized = None;
    let facts = match guard {
        Guard::AdmissionOk => GuardFacts::Admission(AdmissionFacts {
            requester_on_allowlist: true,
            tenant_within_job_quota: true,
            repository_registered_and_enabled: true,
            policy_allows_request_class: true,
            protection_preflight_passed: true,
        }),
        Guard::UpstreamPassed => GuardFacts::Upstream(UpstreamFacts {
            stage: StageKind::Intake,
            stage_runs: &[],
            consumed_artifact_hashes_current: true,
            stage_contract_resolved_and_valid: true,
        }),
        Guard::NotApplicableDecided => GuardFacts::NotApplicable(NotApplicableFacts {
            basis: Some(NotApplicableBasis::Policy),
            rule_and_inputs_recorded: true,
        }),
        Guard::LeaseAcquired => GuardFacts::LeaseGrant(LeaseGrantFacts {
            claim_candidate_current: true,
            job_status: JobStatus::Active,
            now: at,
            not_before: None,
            concurrency_quota_allows: true,
            runtime_capability_check_passed: true,
        }),
        Guard::OutputSchemaValid => GuardFacts::Output(OutputFacts {
            attempt_succeeded: true,
            output_validates_against_outputs_schema: true,
            output_artifact_hash_stored: true,
        }),
        Guard::RetryAllowed => GuardFacts::Retry(RetryFacts {
            class: FailureClass::ToolError,
            retry_on: &[RetryClass::ToolError],
            attempts_used: 1,
            max_attempts: 3,
            budget_has_room: true,
            invalid_output_failures: 0,
            repair_cap: RepairCap::DEFAULT,
            environment: None,
        }),
        Guard::FailureNonretryable => GuardFacts::Retry(RetryFacts {
            class: FailureClass::PolicyDenied,
            retry_on: &[],
            attempts_used: 1,
            max_attempts: 3,
            budget_has_room: true,
            invalid_output_failures: 0,
            repair_cap: RepairCap::DEFAULT,
            environment: None,
        }),
        Guard::EscalationRequired => GuardFacts::Escalation(EscalationFacts {
            budget_limit_hit: true,
            attempt_limit_reached: false,
            agent_requested_a_human: false,
            stagnation_detected: false,
            policy_requires_human_decision: false,
        }),
        Guard::GatePassEvidenced => GuardFacts::GatePass(GatePassFacts {
            decision_is_pass_and_persisted: true,
            criteria_without_ledger_entry: 0,
            mandatory_gate_reports: &[],
        }),
        Guard::BlockingCondition => GuardFacts::Blocking(BlockingFacts {
            verdict_is_block: false,
            mandatory_gate_could_not_run: true,
            policy_violation_detected: false,
        }),
        Guard::ReworkAllowed => GuardFacts::Rework(ReworkFacts {
            verdict_is_changes_required: false,
            deterministic_gate_failed: true,
            rounds_used: 0,
            cap: ReworkCap::DEFAULT,
            failing_set_differs_from_previous_round: true,
            budget_remains: true,
        }),
        Guard::NeedsHumanVerdict => GuardFacts::NeedsHuman(NeedsHumanFacts {
            verdict_is_needs_human: false,
            rework_limit_reached: false,
            stagnation_detected: false,
            budget_limit_reached: false,
            gate_is_a_human_gate: true,
            defect_needs_a_person: false,
        }),
        Guard::ApproverAuthorized => GuardFacts::Approval(ApprovalFacts {
            decision_is_approve: true,
            principal_holds_required_role: true,
            evidence_digest_seen_equals_current: true,
            translation_warnings_decided: true,
        }),
        Guard::Unrecoverable => GuardFacts::Unrecoverable(UnrecoverableFacts {
            stage_run_failed: true,
            newer_run_of_kind_exists: false,
            rework_route_remains: false,
            retry_budget_remains: false,
            hard_limit_reached: false,
            policy_says_fail: false,
        }),
        Guard::EnvironmentBlocked => GuardFacts::Environment(EnvironmentFacts {
            cause: EnvironmentCause::DaemonUnavailable,
            attempt_ended_failed: true,
        }),
        Guard::ReauthorizationRequired => {
            GuardFacts::Reauthorization(factory_domain::machines::guards::ReauthorizationFacts {
                authorized_request: none_authorized,
                current_request: &request,
                policy_asks_confirmation: false,
            })
        }
        Guard::SandboxProvisioned => GuardFacts::SandboxProvision(SandboxProvisionFacts {
            posture_verified: true,
            tool_grants_recorded: true,
            probe_satisfies_stage: true,
            epoch,
        }),
        Guard::EpochCurrent => GuardFacts::Epoch(epoch),
        Guard::DeadlinePassed => GuardFacts::Deadline(DeadlineFacts {
            now: at
                .checked_add(Duration::from_secs(1))
                .expect("a later time"),
            attempt_deadline: at,
        }),
        Guard::LeaseExpired => GuardFacts::LeaseExpiry(LeaseExpiryFacts {
            now: at
                .checked_add(Duration::from_secs(1))
                .expect("a later time"),
            lease_expires_at: at,
            heartbeat_arrived: false,
        }),
        Guard::CancelAllowed => GuardFacts::Cancel(CancelFacts {
            attempt: factory_domain::state::AttemptStatus::Running,
            job: JobStatus::Cancelling,
            stage_run_is_being_superseded: false,
        }),
        Guard::SandboxGone => GuardFacts::SandboxGone(SandboxGoneFacts {
            provider_confirms_sandbox_gone: true,
        }),
        Guard::TeardownDeadlinePassed => GuardFacts::Teardown(TeardownFacts {
            now: at
                .checked_add(Duration::from_secs(60))
                .expect("a later time"),
            cancel_requested_at: at,
            grace_seconds: 30,
        }),
        Guard::NoActiveAttempt => GuardFacts::Attempts(AttemptsFacts { attempts: &[] }),
        Guard::TaskDepsSucceeded => GuardFacts::TaskDeps(TaskDepsFacts { dependencies: &[] }),
        Guard::TaskStartedByAttempt => {
            let node =
                TaskNodeId::parse("00000000-0000-7000-8000-000000000001").expect("a valid id");
            GuardFacts::TaskStart(TaskStartFacts {
                this_task: node,
                next_in_topological_order: Some(node),
            })
        }
        Guard::TaskEvidenceRecorded => GuardFacts::TaskEvidence(TaskEvidenceFacts {
            commit_exists_for_task: true,
            changed_paths_inside_owned_files: true,
            protected_path_changed: false,
            per_task_checks_passed: true,
        }),
        Guard::ActorMayPause | Guard::ActorMayCancel => {
            GuardFacts::Principal(factory_domain::machines::guards::PrincipalFacts {
                roles: &[factory_domain::vocabulary::HumanRole::Operator],
                is_job_requester: true,
            })
        }
        // The requester is not on the allowlist, so the job is refused at admission.
        Guard::AdmissionDenied => GuardFacts::Admission(AdmissionFacts {
            requester_on_allowlist: false,
            tenant_within_job_quota: true,
            repository_registered_and_enabled: true,
            policy_allows_request_class: true,
            protection_preflight_passed: true,
        }),
        other => panic!("fixtures::cleared has no facts for {other}; add them"),
    };
    evaluate(guard, &facts)
        .unwrap_or_else(|error| panic!("the fixture facts for {guard} do not hold: {error}"))
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
