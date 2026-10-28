//! Two real-Docker tests must never make an object with the same name. The names of a sandbox
//! are `sf-<job>-<attempt>-<random>`, and the tests give every sandbox the same job and often the
//! same attempt, so the random part is all that tells two labs apart. It came from a counter that
//! each test's generator started at zero, so two labs of one process made the same names and the
//! second `docker create` failed with `ProvisionFailed(Create)`.

use std::collections::BTreeSet;

use factory_ports::clock::IdGenerator;
use factory_sandbox::container::names::SandboxNames;

use crate::support::{self, UniqueIds};

#[test]
fn generators_of_different_labs_in_one_process_never_repeat_a_name() {
    let labs: Vec<UniqueIds> = (0..8).map(|_| UniqueIds::new()).collect();
    let mut suffixes = BTreeSet::new();
    let mut total = 0;
    for lab in &labs {
        for _ in 0..8 {
            let names = SandboxNames::new(
                &support::job(1),
                &support::attempt(1),
                &lab.new_uuid().to_string(),
            );
            total += 1;
            suffixes.insert(names.suffix);
        }
    }
    assert_eq!(
        suffixes.len(),
        total,
        "two sandboxes of the same job and attempt got the same name"
    );
}
