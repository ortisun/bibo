//! The real policy engine, an allowlist of a few people, and the authorization of a decision.

use std::sync::LazyLock;

use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::authority::{
    ActionVerdict, Actor, ActorKind, Allowlist, AllowlistEntry, AutonomyLevel,
};
use factory_domain::policy::decision::{AuthorizedApproval, Designation, GithubUserId};
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::RiskTier;
use factory_workflow::gates::supply_chain::approval::{
    ApprovalError, DecisionScope, DependencyApproval, Request, Subject, authorize,
};

const SECURITY_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");

/// Alice asks for work and may approve.
pub const REQUESTER: u64 = 1001;
/// Bob is an approver.
pub const APPROVER: u64 = 1004;
/// Sam is a security approver.
pub const SECURITY: u64 = 1005;
/// Olga can operate jobs and approves nothing.
pub const OPERATOR: u64 = 1002;

const REPOSITORY: &str = "example-org/app";

pub fn engine() -> &'static PolicyEngine {
    static ENGINE: LazyLock<PolicyEngine> = LazyLock::new(|| build_engine(&[]));
    &ENGINE
}

/// A policy engine from the fixtures, with these extra subcommands allowed for `cargo`. The real
/// command sets list no SBOM tool, so a test of the path where an SBOM is made adds one here and
/// changes nothing else.
pub fn build_engine(extra_cargo_subcommands: &[&str]) -> PolicyEngine {
    let mut security: serde_json::Value =
        serde_json::from_str(SECURITY_POLICY).expect("the security policy fixture");
    if !extra_cargo_subcommands.is_empty() {
        let sets = security["command_sets"]["sets"]
            .as_array_mut()
            .expect("command sets");
        let rust = sets
            .iter_mut()
            .find(|set| set["id"] == "rust")
            .expect("the rust set");
        let allowed = rust["executables"]["cargo"]["allowed_subcommands"]
            .as_array_mut()
            .expect("subcommands");
        allowed.extend(
            extra_cargo_subcommands
                .iter()
                .map(|name| serde_json::json!(name)),
        );
    }
    let security: SecurityPolicy = serde_json::from_value(security).expect("a security policy");
    let approval: ApprovalPolicy =
        serde_json::from_str(APPROVAL_POLICY).expect("the approval policy fixture");
    PolicyEngine::new(&security, &approval).expect("a policy engine")
}

/// The job every decision of the tests is for.
pub fn job() -> JobId {
    JobId::parse("018f3a00-0000-7000-8000-00000000d001").expect("a job")
}

/// The tenant and the job a decision of the tests is for.
pub fn scope() -> DecisionScope {
    DecisionScope {
        tenant: tenant(),
        job: job(),
    }
}

pub fn tenant() -> TenantId {
    TenantId::parse("018f3a00-0000-7000-8000-00000000c001").expect("a tenant")
}

pub fn now() -> Timestamp {
    Timestamp::parse("2026-10-28T12:00:00Z").expect("a time")
}

pub fn policy_hash() -> Sha256Digest {
    Sha256Digest::of(b"policy bundle one")
}

fn id(number: u64) -> GithubUserId {
    GithubUserId::new(number).expect("a GitHub id")
}

fn entry(number: u64, login: &str, designations: &[Designation]) -> AllowlistEntry {
    AllowlistEntry {
        tenant: tenant(),
        github_user_id: id(number),
        login: login.to_owned(),
        designations: designations.iter().copied().collect(),
        repositories: None,
        expires_at: None,
    }
}

pub fn allowlist() -> Allowlist {
    use Designation::{Approver, Operator, Requester, SecurityApprover};
    Allowlist::new(
        "sha256:allowlist-v1",
        vec![
            entry(REQUESTER, "alice", &[Requester, Approver]),
            entry(OPERATOR, "olga", &[Operator]),
            entry(APPROVER, "bob", &[Approver]),
            entry(SECURITY, "sam", &[SecurityApprover]),
        ],
    )
    .expect("no duplicates")
}

pub fn human(number: u64, login: &str) -> Actor<'_> {
    Actor {
        github_user_id: id(number),
        login,
        kind: ActorKind::User,
        github_permission: None,
        author_association: None,
    }
}

/// Asks the policy engine whether `actor` may approve a dependency that needs `needed`, for a job
/// that `requester` asked for.
pub fn decide(actor: &Actor<'_>, needed: Designation, requester: Option<u64>) -> ActionVerdict {
    let (tenant, now, allowlist) = (tenant(), now(), allowlist());
    authorize(
        &Request {
            policy: &engine().authority,
            level: AutonomyLevel::L1,
            tenant: &tenant,
            repository: REPOSITORY,
            actor,
            allowlist: &allowlist,
            now: &now,
            requester: requester.map(id),
            risk_tier: RiskTier::Low,
            protected_path_change: false,
            sensitive_file_change: false,
        },
        needed,
    )
}

pub fn authorized(verdict: ActionVerdict) -> AuthorizedApproval {
    match verdict {
        ActionVerdict::Authorized(proof) => proof,
        other => panic!("expected an authorization, got {other:?}"),
    }
}

/// A recorded decision by `number`, who must hold `needed`, on `subject`.
pub fn approve(
    number: u64,
    login: &str,
    needed: Designation,
    subject: &Subject,
) -> Result<DependencyApproval, ApprovalError> {
    let proof = authorized(decide(&human(number, login), needed, Some(REQUESTER)));
    DependencyApproval::record(
        &proof,
        subject.clone(),
        policy_hash(),
        scope(),
        "Reviewed the package, its maintainers and its license.",
    )
}
