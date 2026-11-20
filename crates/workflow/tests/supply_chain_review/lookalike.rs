//! Hypothesis H-4: a squatter adds a word to a popular name, and the policy engine measures one
//! edit only. The gate adds the decorated names to the scrutiny of a new direct dependency: the
//! name is flagged as near a popular name and a security approver decides. It never lowers the
//! level and never approves.

use factory_domain::policy::decision::Designation;
use factory_domain::policy::dependency::DependencyFlag;
use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::facts::RegistryRecord;
use factory_workflow::gates::supply_chain::integrity::{Context, inspect};
use factory_workflow::gates::supply_chain::licenses::LicensePolicy;
use factory_workflow::gates::supply_chain::model::normalize;
use factory_workflow::gates::supply_chain::names::PopularNames;
use factory_workflow::gates::supply_chain::review::{Plan, RegistryTable, Settings};

use crate::files::{base, head_adding, side};
use crate::people::{engine, now, policy_hash, scope};

/// A package that is old, exists and is licensed, so that the name is the only reason for scrutiny.
fn established() -> RegistryRecord {
    RegistryRecord {
        exists: Some(true),
        first_published: Some(
            factory_domain::values::Timestamp::parse("2020-01-01T00:00:00Z").expect("a time"),
        ),
        license: Some("MIT".to_owned()),
        repository: None,
        downloads: Some(1_000),
    }
}

fn plan_adding(name: &'static str) -> Plan {
    let popular = PopularNames::bundled().expect("the bundled list");
    let cx = Context {
        internal_names: &[],
        popular: &popular,
    };
    let integrity = inspect(
        &CargoFormat,
        &side(&base()),
        &side(&head_adding(name, "0.1.0", 'c')),
        &cx,
    )
    .expect("readable");
    let mut registry = RegistryTable::new();
    registry.insert(normalize(name), established());
    Plan::new(
        integrity,
        &registry,
        &[],
        &Settings {
            dependency: &engine().dependency,
            authority: &engine().authority,
            licenses: &LicensePolicy::owner_approved(),
            internal_names: &[],
            popular: &popular,
            now: now(),
            scope: scope(),
            policy_hash: &policy_hash(),
        },
    )
}

#[test]
fn a_popular_name_with_a_decoration_goes_to_a_security_approver() {
    for name in [
        "reqwest-rs",
        "clap-derive-macros",
        "anyhow-ext",
        "rust-serde",
    ] {
        let plan = plan_adding(name);
        assert_eq!(plan.needs.len(), 1, "{name}");
        assert_eq!(
            plan.needs[0].designation,
            Designation::SecurityApprover,
            "{name}"
        );
        assert!(
            plan.needs[0]
                .flags
                .iter()
                .any(|flag| matches!(flag, DependencyFlag::NearPopularName(_))),
            "{name}: {:?}",
            plan.needs[0].flags
        );
        assert!(plan.awaiting().len() == 1, "{name}: nothing approves it");
    }
}

#[test]
fn an_established_unrelated_name_stays_with_an_ordinary_approver() {
    let plan = plan_adding("some-crate");
    assert_eq!(plan.needs[0].designation, Designation::Approver);
    assert!(plan.needs[0].flags.is_empty());
}
