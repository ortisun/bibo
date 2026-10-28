//! Attack: text that a package author controls travels into the ledger evidence unchanged.
//!
//! `Plan::evidence` writes `registry.repository` and `registry.license` into the evidence
//! document as they came from the registry source. A package author chooses both. The text goes
//! on to the ledger and to the page where a person decides. Everything else the gate writes from
//! candidate text passes through `model::plain` (a fixed alphabet and a length bound); these two
//! fields do not.

use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::facts::RegistryRecord;
use factory_workflow::gates::supply_chain::integrity::{Context, inspect};
use factory_workflow::gates::supply_chain::licenses::LicensePolicy;
use factory_workflow::gates::supply_chain::model::normalize;
use factory_workflow::gates::supply_chain::names::PopularNames;
use factory_workflow::gates::supply_chain::review::{Plan, RegistryTable, Settings};

use crate::files::{base, head_adding, side};
use crate::people::{engine, now, policy_hash, scope};

fn plan_for(record: RegistryRecord) -> Plan {
    let popular = PopularNames::bundled().expect("the bundled list");
    let cx = Context {
        internal_names: &[],
        popular: &popular,
    };
    let head = head_adding("some-crate", "0.1.0", 'c');
    let integrity = inspect(&CargoFormat, &side(&base()), &side(&head), &cx).expect("readable");
    let licenses = LicensePolicy::owner_approved();
    let mut registry = RegistryTable::new();
    registry.insert(normalize("some-crate"), record);
    Plan::new(
        integrity,
        &registry,
        &[],
        &Settings {
            dependency: &engine().dependency,
            licenses: &licenses,
            internal_names: &[],
            popular: &popular,
            now: now(),
            scope: scope(),
            policy_hash: &policy_hash(),
        },
    )
}

#[test]
fn sc8_registry_text_is_cleaned_and_bounded_before_it_is_stored() {
    let hostile = format!("<script>alert(1)</script>{}", "x".repeat(20_000));
    let plan = plan_for(RegistryRecord {
        exists: Some(true),
        first_published: None,
        license: Some(hostile.clone()),
        repository: Some(hostile),
        downloads: Some(1),
    });
    let evidence = plan.evidence();
    let registry = &evidence["new_direct_dependencies"][0]["registry"];
    for field in ["repository", "license"] {
        let text = registry[field].as_str().unwrap_or_default();
        assert!(
            text.len() <= 300 && !text.contains('<'),
            "{field} was stored as {} bytes starting {:?}",
            text.len(),
            text.chars().take(30).collect::<String>()
        );
    }
}
