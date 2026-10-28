//! Requirements on the composition root.
//!
//! The gates are a library; the code that calls `gate::run` is being written elsewhere. These
//! tests do not find a defect in the library. Each one shows, with a passing test, a fact about
//! the current behaviour that the caller must account for, so that the requirement in the review
//! document (section "Requirements on the composition root") is not read as an opinion.

use factory_domain::policy::decision::Designation;
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::supply_chain::approval::{DependencyApproval, Subject};
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
use crate::people::{APPROVER, REQUESTER, authorized, decide, engine, human, now, policy_hash};
use crate::world::World;

fn subject() -> Subject {
    Subject {
        name: "some-crate".to_owned(),
        version: "0.1.0".to_owned(),
        checksum: sum('c'),
    }
}

fn approval_under(policy: Sha256Digest) -> DependencyApproval {
    let proof = authorized(decide(
        &human(APPROVER, "bob"),
        Designation::Approver,
        Some(REQUESTER),
    ));
    DependencyApproval::record(&proof, subject(), policy, "Read the crate and its owners.")
        .expect("recorded")
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

/// R-2. A recorded approval is bound to the package (name, version, checksum), the designation,
/// the allowlist version and the policy hash, and to no job, tenant or repository. The caller
/// must load approvals by (tenant, job) and only from the ledger rows written by the approval
/// command.
#[test]
fn requirement_an_approval_names_no_job_no_tenant_and_no_repository() {
    let json = approval_under(policy_hash()).to_json();
    let keys: Vec<&str> = json
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    for absent in [
        "job",
        "job_id",
        "tenant",
        "tenant_id",
        "repository",
        "commit",
    ] {
        assert!(!keys.contains(&absent), "{absent} is now in the record");
    }
}

/// R-3. `Plan::new` does not know the policy hash in force, the allowlist, or the time: an
/// approval decided under another policy bundle still covers the dependency. Whoever loads
/// approvals must drop the ones whose policy hash is not the current one, or whose approver has
/// left the allowlist, because nothing in the library does.
#[test]
fn requirement_an_approval_decided_under_an_old_policy_hash_still_covers_the_dependency() {
    let old_hash = Sha256Digest::of(b"a policy bundle from last year");
    assert_ne!(old_hash, policy_hash());
    let approval = approval_under(old_hash);

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
    let plan = Plan::new(
        integrity,
        &registry,
        &[approval],
        &Settings {
            dependency: &engine().dependency,
            licenses: &licenses,
            internal_names: &[],
            popular: &popular,
            now: now(),
        },
    );
    assert_eq!(plan.needs.len(), 1);
    assert!(plan.needs[0].approval.is_some(), "the old approval counts");
    assert!(plan.may_fetch());
}
