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

/// RR-6 (fixed). The registry had sixteen seams and the fidelity of eight. The other eight (the
/// capability probes, the job repository, the project manifest parser, the rework, round, risk and
/// history sources, the evidence drift channel) were read by the stages and could not be refused, in
/// any profile, whatever they were. Now one macro call declares every seam with the name under which
/// the profile checks it, and writes the report by calling `fidelity()` on each: a seam whose trait
/// has no such method does not compile, and none can be left out. This test reads the call and
/// compares it with the report and with the list of names.
#[test]
fn rr_6_every_seam_of_the_registry_is_checked_by_the_profile() {
    use factory_composition::profile::PortName;
    use factory_composition::registry::Seams;
    let text = source("crates/composition/src/registry.rs");
    let declared = text
        .split("\nseams! {\n")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("the seams macro call");
    let seams: Vec<&str> = declared
        .lines()
        .filter(|line| line.contains(": dyn "))
        .collect();
    // Every declared seam names the port under which the profile checks it ...
    for line in &seams {
        assert!(line.contains("=> "), "no port name on: {line}");
    }
    // ... the report is written from that same list, by asking each seam ...
    assert!(
        text.contains("vec![ $( (PortName::$port, self.$field.fidelity()), )* ]"),
        "the report is not written from the declaration"
    );
    // ... and the names are the ones of the list, once each.
    let mut named: Vec<PortName> = Seams::port_names().to_vec();
    assert_eq!(named.len(), seams.len());
    named.sort();
    named.dedup();
    assert_eq!(named.len(), seams.len(), "two seams share a port name");
    for port in named {
        assert!(PortName::ALL.contains(&port), "{port:?} is not in the list");
    }
}

/// RR-7 (fixed). The four inputs that carry facts into a security decision had no fidelity method at
/// all: the registry facts about a package (its age, its owners), the date of the advisory database,
/// the recorded dependency decisions, and the administrator's statement about the bypass list. A
/// stand-in that always answers "old and clean", "updated yesterday", "approved" or "nobody can
/// bypass" would have been accepted by the production profile, and by the engine's own check, which
/// reads only what has a fidelity. Now each trait has the method and each is a seam of the registry.
#[test]
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
    // And each is in the registry under a name of its own.
    use factory_composition::profile::PortName;
    for port in [
        PortName::PackageMetadata,
        PortName::AdvisoryDatabase,
        PortName::RecordedApprovals,
        PortName::Attestations,
    ] {
        assert!(
            factory_composition::registry::Seams::port_names().contains(&port),
            "{port:?} is not a seam of the registry"
        );
    }
}

/// What holds: the ports and every seam are in the list, and the list is checked for every profile.
/// A port added to the registry without a name fails to compile.
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
