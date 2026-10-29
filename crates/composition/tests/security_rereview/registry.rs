//! The claim "the production profile refuses every stand-in" (AUT-13), read against the registry
//! itself. A port that reports no fidelity cannot be refused, so the check is only as complete as the
//! list of ports that report one.

use std::fs;

use crate::repository_root;

fn source(relative: &str) -> String {
    fs::read_to_string(repository_root().join(relative))
        .unwrap_or_else(|error| panic!("{relative}: {error}"))
}

/// The text of `pub trait <name>` up to its closing brace at the left margin.
fn trait_text(text: &str, name: &str) -> String {
    let marker = format!("pub trait {name}");
    let start = text
        .find(&marker)
        .unwrap_or_else(|| panic!("the trait {name} is not where it was"));
    let rest = &text[start..];
    let end = rest.find("\n}\n").unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// RR-6. The registry has sixteen seams and the fidelity of eight. The other eight (the capability
/// probes, the job repository, the project manifest parser, the rework, round, risk and history
/// sources, the evidence drift channel) are read by the stages and cannot be refused, in any profile,
/// whatever they are.
#[test]
#[ignore = "confirmed defect RR-6: eight of the sixteen seams of the registry report no fidelity, so the production profile cannot refuse them; cargo test -p factory-composition --test security_rereview --locked -- --ignored rr_6 --exact"]
fn rr_6_every_seam_of_the_registry_is_checked_by_the_profile() {
    let text = source("crates/composition/src/registry.rs");
    let declared = text
        .split("seams! {")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("the seams macro call");
    let seams = declared
        .lines()
        .filter(|line| line.contains(": dyn "))
        .count();
    let checked = text
        .split("pub fn fidelities(&self) -> Vec<(PortName, Fidelity)> {\n        vec![")
        .nth(1)
        .and_then(|rest| rest.split("]\n").next())
        .expect("the seam fidelities")
        .matches("(PortName::")
        .count();
    assert_eq!(
        checked, seams,
        "{seams} seams are declared and {checked} are checked against the profile"
    );
}

/// RR-7. The four inputs that carry facts into a security decision have no fidelity method at all:
/// the registry facts about a package (its age, its owners), the date of the advisory database, the
/// recorded dependency decisions, and the administrator's statement about the bypass list. A stand-in
/// that always answers "old and clean", "updated yesterday", "approved" or "nobody can bypass" would
/// be accepted by the production profile, and by the engine's own check, which reads only what has a
/// fidelity. Nothing builds such a stand-in today; the worker stops with `BLOCKED:` for want of an
/// adapter. The day an adapter is written, nothing will tell a real one from a convenient one.
#[test]
#[ignore = "confirmed defect RR-7: the supply chain seams and the bypass attestation report no fidelity; cargo test -p factory-composition --test security_rereview --locked -- --ignored rr_7 --exact"]
fn rr_7_the_inputs_of_security_decisions_report_a_fidelity() {
    let facts = source("crates/workflow/src/gates/supply_chain/facts.rs");
    let approval = source("crates/workflow/src/gates/supply_chain/approval.rs");
    let preflight = source("crates/composition/src/preflight.rs");
    let mut silent = Vec::new();
    for (name, text) in [
        ("RegistryMetadata", &facts),
        ("AdvisoryDatabase", &facts),
        ("RecordedApprovals", &approval),
        ("BypassAttestations", &preflight),
    ] {
        if !trait_text(text, name).contains("fn fidelity") {
            silent.push(name);
        }
    }
    assert!(
        silent.is_empty(),
        "these seams cannot be refused by a profile: {silent:?}"
    );
}

/// What does hold: the ports and eight of the seams are in the list, and the list is checked for
/// every profile. A port added to the registry without a name fails to compile.
#[test]
fn held_the_ports_and_the_listed_seams_are_refused_one_by_one() {
    use factory_composition::profile::{PortName, Profile};
    use factory_composition::registry::check_fidelities;
    use factory_domain::vocabulary::Fidelity;
    for odd in PortName::ALL {
        let reported: Vec<_> = PortName::ALL
            .iter()
            .map(|port| {
                (
                    *port,
                    if *port == odd {
                        Fidelity::Fake
                    } else {
                        Fidelity::Real
                    },
                )
            })
            .collect();
        let refusal = check_fidelities(Profile::Production, &reported).expect_err("refused");
        assert_eq!(refusal.refused, vec![odd]);
    }
}
