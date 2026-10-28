//! The register rule (ports-v1.1 decision 10): every check of every contract suite is named by at
//! least one seeded defect of its fake, or carries a waiver with a reason and a trigger. A check
//! that no wrong fake can fail may pass for the wrong reason.

use std::collections::BTreeSet;

use factory_testkit::contracts::register;

#[test]
fn every_check_is_named_by_a_defect_or_waived() {
    let mut problems = Vec::new();
    for entry in register::all() {
        let named: BTreeSet<&str> = entry
            .defects
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        let waived: BTreeSet<&str> = entry.waivers.iter().map(|w| w.check).collect();
        for check in &entry.checks {
            if !named.contains(check) && !waived.contains(check) {
                problems.push(format!(
                    "{}: the check {check} is named by no defect and has no waiver",
                    entry.suite
                ));
            }
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn a_table_never_names_a_check_that_does_not_exist() {
    let mut problems = Vec::new();
    for entry in register::all() {
        let known: BTreeSet<&str> = entry.checks.iter().copied().collect();
        for (defect, names) in &entry.defects {
            for name in *names {
                if !known.contains(name) {
                    problems.push(format!(
                        "{}: the defect {defect} names {name}, which is not a check",
                        entry.suite
                    ));
                }
            }
        }
        for waiver in entry.waivers {
            if !known.contains(waiver.check) {
                problems.push(format!(
                    "{}: the waiver names {}, which is not a check",
                    entry.suite, waiver.check
                ));
            }
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn a_waiver_has_a_reason_and_a_trigger() {
    for entry in register::all() {
        for waiver in entry.waivers {
            assert!(
                waiver.reason.trim().len() > 20,
                "{}: the waiver for {} needs a reason",
                entry.suite,
                waiver.check
            );
            assert!(
                waiver.trigger.trim().len() > 10,
                "{}: the waiver for {} needs a trigger",
                entry.suite,
                waiver.check
            );
        }
    }
}

#[test]
fn a_check_is_not_waived_and_named_at_once() {
    for entry in register::all() {
        let named: BTreeSet<&str> = entry
            .defects
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        for waiver in entry.waivers {
            assert!(
                !named.contains(waiver.check),
                "{}: {} has a defect, so its waiver should go",
                entry.suite,
                waiver.check
            );
        }
    }
}

#[test]
fn every_check_name_is_unique_within_its_suite() {
    for entry in register::all() {
        let unique: BTreeSet<&str> = entry.checks.iter().copied().collect();
        assert_eq!(
            unique.len(),
            entry.checks.len(),
            "{}: two checks share a name",
            entry.suite
        );
    }
}

#[test]
fn the_register_counts_what_the_report_quotes() {
    let suites = register::all();
    let checks: usize = suites.iter().map(|s| s.checks.len()).sum();
    let defects: usize = suites.iter().map(|s| s.defects.len()).sum();
    let waivers: usize = suites.iter().map(|s| s.waivers.len()).sum();
    println!(
        "REGISTER: {} suites, {checks} checks, {defects} seeded defects, {waivers} waivers",
        suites.len()
    );
    assert!(checks > 0 && defects > 0);
}
