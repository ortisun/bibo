//! Requirements on the composition root.
//!
//! The gates are a library; the code that calls `gate::run` is being written elsewhere. These
//! tests do not find a defect in the library. Each one shows, with a passing test, a fact about
//! the current behaviour that the caller must account for, so that the requirement in the review
//! document (section "Requirements on the composition root") is not read as an opinion.

use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::decision::Designation;
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::supply_chain::approval::{DecisionScope, DependencyApproval, Subject};
use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::facts::{RegistryRecord, StaticRegistry};
use factory_workflow::gates::supply_chain::integrity::{Context, inspect};
use factory_workflow::gates::supply_chain::licenses::LicensePolicy;
use factory_workflow::gates::supply_chain::model::DependencyFormat;
use factory_workflow::gates::supply_chain::model::normalize;
use factory_workflow::gates::supply_chain::names::PopularNames;
use factory_workflow::gates::supply_chain::report::gate;
use factory_workflow::gates::supply_chain::review::{Plan, RegistryTable, Settings};

use crate::files::{Files, base, head_adding, side, sum};
use crate::people::{
    APPROVER, REQUESTER, authorized, decide, engine, human, now, policy_hash, scope,
};
use crate::world::World;

fn subject() -> Subject {
    Subject {
        name: "some-crate".to_owned(),
        version: "0.1.0".to_owned(),
        checksum: sum('c'),
    }
}

fn approval_for(policy: Sha256Digest, scope: DecisionScope) -> DependencyApproval {
    let proof = authorized(decide(
        &human(APPROVER, "bob"),
        Designation::Approver,
        Some(REQUESTER),
    ));
    DependencyApproval::record(
        &proof,
        subject(),
        policy,
        scope,
        "Read the crate and its owners.",
    )
    .expect("recorded")
}

fn approval_under(policy: Sha256Digest) -> DependencyApproval {
    approval_for(policy, scope())
}

/// A plan for the change that adds `some-crate`, with the settings of the test tenant and job and
/// the current policy hash of the tests.
fn plan_with_approval(approval: DependencyApproval) -> Plan {
    let popular = PopularNames::bundled().expect("the bundled list");
    let cx = Context {
        internal_names: &[],
        popular: &popular,
    };
    let head = head_adding("some-crate", "0.1.0", 'c');
    let integrity = inspect(&CargoFormat, &side(&base()), &side(&head), &cx).expect("readable");
    let licenses = LicensePolicy::owner_approved();
    let mut registry = RegistryTable::new();
    registry.insert(
        normalize("some-crate"),
        RegistryRecord {
            exists: Some(true),
            first_published: Some(Timestamp::parse("2020-01-01T00:00:00Z").expect("a time")),
            license: Some("MIT".to_owned()),
            repository: None,
            downloads: None,
        },
    );
    Plan::new(
        integrity,
        &registry,
        &[approval],
        &Settings {
            dependency: &engine().dependency,
            authority: &engine().authority,
            licenses: &licenses,
            internal_names: &[],
            popular: &popular,
            now: now(),
            scope: scope(),
            policy_hash: &policy_hash(),
        },
    )
}

/// R-4. A `Side` is a path and a text. It has no file mode. In git, a symbolic link is a blob
/// whose text is the path it points to, and `cargo` follows the link when it reads the file. A
/// `Cargo.lock` that is a link to a file called `version=4` (a legal file name) reads, as a blob,
/// as the TOML document `version=4`: a valid lockfile with no package. Cargo reads the real file.
/// The caller must read the mode of every dependency file in both commits and refuse a symbolic
/// link or a submodule (modes 120000 and 160000) before it builds a `Side`, because the gate
/// cannot see the difference.
#[test]
fn requirement_a_symbolic_link_blob_reads_as_a_valid_empty_lockfile_and_manifest() {
    let lock = CargoFormat.parse_lockfile("version=4").expect("a lockfile");
    assert!(lock.packages.is_empty());
    let manifest = CargoFormat.parse_manifest("a=1").expect("a manifest");
    assert!(manifest.declared.is_empty());
    let config = CargoFormat.parse_build_config("a=1").expect("a config");
    assert_eq!(config.entries.len(), 1);
}

/// R-1. A `Side` holds only the files that `kind_of` recognises, and a `Side` with no file is a
/// project with no dependency. If the caller builds both sides from an empty or truncated listing
/// of the object store, the integrity gate says NOT_APPLICABLE ("no dependency file") and the
/// other three gates have nothing to scan. The gate cannot tell a project with no lockfile from a
/// listing that failed. The caller must refuse to build a `Side` from a partial read.
#[tokio::test]
async fn requirement_an_empty_side_is_not_applicable_so_the_caller_must_never_pass_one_by_mistake()
{
    let world = World::new();
    let nothing: Files = Vec::new();
    let ran = world
        .gate(&nothing, &nothing, &StaticRegistry::new(), &[], false)
        .await
        .expect("the gate runs");
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::NotApplicable);
}

/// R-2, closed. A recorded approval names the tenant and the job it was decided for. The review
/// drops a decision that is for another tenant or another job, so a decision cannot be carried
/// from one job to another, whatever the caller loaded. (The caller still loads by tenant and
/// job, and only rows written by the approval command; this is the second check.)
#[test]
fn requirement_an_approval_names_its_tenant_and_its_job_and_no_other_covers() {
    let json = approval_under(policy_hash()).to_json();
    assert_eq!(json["tenant_id"], scope().tenant.as_text());
    assert_eq!(json["job_id"], scope().job.as_text());

    let other_job = JobId::parse("018f3a00-0000-7000-8000-00000000d002").expect("a job");
    let other_tenant = TenantId::parse("018f3a00-0000-7000-8000-00000000c002").expect("a tenant");
    for foreign in [
        DecisionScope {
            job: other_job,
            ..scope()
        },
        DecisionScope {
            tenant: other_tenant,
            ..scope()
        },
    ] {
        let plan = plan_with_approval(approval_for(policy_hash(), foreign));
        assert_eq!(plan.needs.len(), 1);
        assert!(plan.needs[0].approval.is_none(), "{foreign:?}");
        assert!(!plan.may_fetch());
    }
    let own = plan_with_approval(approval_under(policy_hash()));
    assert!(own.needs[0].approval.is_some());
    assert!(own.may_fetch());
}

/// A record that carries no tenant or no job is not an approval.
#[test]
fn requirement_a_stored_approval_without_a_tenant_or_job_is_not_read() {
    let json = approval_under(policy_hash()).to_json();
    for missing in ["tenant_id", "job_id"] {
        let mut broken = json.clone();
        broken.as_object_mut().expect("an object").remove(missing);
        assert!(
            DependencyApproval::from_json(&broken).is_none(),
            "{missing}"
        );
    }
    assert!(DependencyApproval::from_json(&json).is_some());
}

/// R-3, closed (B-7). `Plan::new` knows the policy hash in force, and an approval decided under
/// another policy bundle does not cover the dependency: a decision taken under a weaker bundle is
/// not valid after the bundle tightens. The caller must still drop the approvals of an approver
/// who has left the allowlist, because the allowlist is not an input of the plan.
#[test]
fn requirement_an_approval_decided_under_an_old_policy_hash_no_longer_covers_the_dependency() {
    let old_hash = Sha256Digest::of(b"a policy bundle from last year");
    assert_ne!(old_hash, policy_hash());
    let plan = plan_with_approval(approval_under(old_hash));
    assert_eq!(plan.needs.len(), 1);
    assert!(
        plan.needs[0].approval.is_none(),
        "the old approval is dropped"
    );
    assert!(!plan.may_fetch(), "so a person must decide again");
}
