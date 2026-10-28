//! Networks a test makes by hand, the way a crash or a neighbour would leave them.
//!
//! The provider makes its own networks through the retrying runner of the harness, and each one
//! takes an address block from Docker's default pool. That pool is small and shared with every
//! other stack on the machine, and on a busy one only two or three blocks are free. A test that
//! needs a stray network and a foreign one next to its two sandboxes needs four blocks at once.
//! `docker network create` then answers "all predefined address pools have been fully subnetted",
//! and a test that only checks that the command could be started goes on without the network.
//!
//! Two rules follow, and this module is where both are kept:
//!
//! * A network made by hand takes its subnet from 198.18.0.0/15, the range set aside for
//!   benchmarking (RFC 2544). Docker's default pool never hands it out, so the network does not
//!   compete with the machine's stacks for a block.
//! * A `docker network create` that does not succeed ends the test with what the daemon said.

use std::panic::{AssertUnwindSafe, catch_unwind};

use factory_testkit::fx::docker::DockerCli;
use factory_testkit::fx::spawn::{Behavior, Reply, SpawnPolicy, SpawnRecorder};

/// How many subnets one network tries when Docker says the one it asked for is taken.
const TRIES: u32 = 16;

/// A number made from `text`, so that two runs with different labels start at different subnets.
pub fn seed_of(text: &str) -> u32 {
    text.bytes()
        .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)))
}

/// The `step`-th subnet to try for a network with this `seed`: a /28 inside 198.18.0.0/15.
pub fn outside_pool_subnet(seed: u32, step: u32) -> String {
    // A /15 holds 8192 blocks of 16 addresses. 7919 is odd, so no two of the first 8192 steps of
    // one seed give the same block.
    let block = seed.wrapping_add(step.wrapping_mul(7919)) % 8192;
    format!(
        "198.{}.{}.{}/28",
        18 + (block >> 12),
        (block >> 4) & 0xff,
        (block & 0xf) * 16
    )
}

/// Makes an internal network called `name` with these `key=value` labels, outside Docker's
/// address pool.
///
/// # Panics
/// With the words of the daemon when the command fails, except when the subnet is taken, which
/// is tried again with the next one (at most [`TRIES`] times).
pub fn create_network_outside_pool(cli: &DockerCli, name: &str, labels: &[String]) {
    let seed = seed_of(name);
    let mut last = String::new();
    for step in 0..TRIES {
        let subnet = outside_pool_subnet(seed, step);
        let mut args = vec![
            "network",
            "create",
            "--internal",
            "--subnet",
            subnet.as_str(),
        ];
        for label in labels {
            args.extend(["--label", label.as_str()]);
        }
        args.push(name);
        let out = cli
            .run(&args)
            .unwrap_or_else(|error| panic!("docker network create {name}: {error}"));
        if out.success() {
            return;
        }
        last = out.stderr.trim().to_owned();
        if !last.to_ascii_lowercase().contains("pool overlaps") {
            panic!(
                "docker network create {name} failed with exit code {:?}: {last}",
                out.code
            );
        }
    }
    panic!(
        "docker network create {name}: all {TRIES} subnets were taken; the last answer was: {last}"
    );
}

const TAKEN: &str = "Error response from daemon: invalid pool request: Pool overlaps with other one on this address space";
const POOL_FULL: &str =
    "Error response from daemon: all predefined address pools have been fully subnetted";

fn scripted(rules: Vec<(String, Reply)>, default: Reply) -> (SpawnRecorder, DockerCli) {
    let mut recorder = SpawnRecorder::new(SpawnPolicy::allowing(&["docker"])).expect("recorder");
    recorder
        .install("docker", &Behavior::ByArguments { rules, default })
        .expect("a docker shim");
    let cli = DockerCli::with_program(recorder.bin_dir().join("docker"));
    (recorder, cli)
}

fn commands(recorder: &SpawnRecorder) -> Vec<Vec<String>> {
    recorder
        .records()
        .expect("records")
        .into_iter()
        .map(|r| r.argv)
        .collect()
}

fn panic_message(result: std::thread::Result<()>) -> String {
    let payload = result.expect_err("expected a panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default()
}

#[test]
fn every_subnet_is_a_28_inside_the_benchmarking_range_and_a_run_tries_sixteen_different_ones() {
    for seed in [0, 1, 7, 0x00ab_cdef, u32::MAX, seed_of("12345-deadbeef")] {
        let mut seen = std::collections::BTreeSet::new();
        for step in 0..TRIES {
            let subnet = outside_pool_subnet(seed, step);
            let (address, length) = subnet.split_once('/').expect("an address and a length");
            assert_eq!(length, "28", "{subnet}");
            let octets: Vec<u32> = address
                .split('.')
                .map(|part| part.parse().expect("a number"))
                .collect();
            assert_eq!(octets.len(), 4, "{subnet}");
            assert_eq!(octets[0], 198, "{subnet}");
            assert!(matches!(octets[1], 18 | 19), "{subnet}");
            assert!(octets[2] <= 255 && octets[3].is_multiple_of(16), "{subnet}");
            seen.insert(subnet);
        }
        assert_eq!(seen.len(), TRIES as usize, "seed {seed}: {seen:?}");
    }
}

#[test]
fn the_network_is_internal_carries_its_labels_and_names_its_subnet() {
    let (recorder, cli) = scripted(Vec::new(), Reply::ok("net-id\n"));
    create_network_outside_pool(
        &cli,
        "sf-net-ffffffff-ffffffff-00000001",
        &["sf.sandbox=network".to_owned(), "a=b".to_owned()],
    );
    let made = commands(&recorder);
    assert_eq!(made.len(), 1, "{made:?}");
    let line = made[0].join(" ");
    let subnet = outside_pool_subnet(seed_of("sf-net-ffffffff-ffffffff-00000001"), 0);
    assert_eq!(
        line,
        format!(
            "network create --internal --subnet {subnet} --label sf.sandbox=network --label a=b sf-net-ffffffff-ffffffff-00000001"
        )
    );
}

#[test]
fn a_subnet_that_is_taken_is_replaced_by_the_next_one() {
    let name = "sf-net-ffffffff-ffffffff-00000002";
    let first = outside_pool_subnet(seed_of(name), 0);
    let (recorder, cli) = scripted(
        vec![(
            format!("network create --internal --subnet {first}"),
            Reply::fail(1, TAKEN),
        )],
        Reply::ok("net-id\n"),
    );
    create_network_outside_pool(&cli, name, &[]);
    let made = commands(&recorder);
    assert_eq!(made.len(), 2, "{made:?}");
    assert!(made[0].contains(&first), "{made:?}");
    assert!(
        made[1].contains(&outside_pool_subnet(seed_of(name), 1)),
        "{made:?}"
    );
}

#[test]
fn a_create_that_fails_ends_the_test_with_the_words_of_the_daemon_and_is_not_retried() {
    for said in [
        POOL_FULL,
        "Error response from daemon: network with name sf-net-x already exists",
        "Cannot connect to the Docker daemon",
    ] {
        let (recorder, cli) = scripted(Vec::new(), Reply::fail(1, said));
        let message = panic_message(catch_unwind(AssertUnwindSafe(|| {
            create_network_outside_pool(&cli, "sf-net-x", &[]);
        })));
        assert!(message.contains(said), "{message}");
        assert!(message.contains("sf-net-x"), "{message}");
        assert_eq!(commands(&recorder).len(), 1, "{said}");
    }
}

#[test]
fn subnets_that_are_all_taken_end_the_test_after_sixteen_tries() {
    let (recorder, cli) = scripted(Vec::new(), Reply::fail(1, TAKEN));
    let message = panic_message(catch_unwind(AssertUnwindSafe(|| {
        create_network_outside_pool(&cli, "sf-net-y", &[]);
    })));
    assert!(message.contains(TAKEN), "{message}");
    assert_eq!(commands(&recorder).len(), TRIES as usize);
}

#[test]
fn a_docker_that_cannot_be_started_ends_the_test_too() {
    let cli = DockerCli::with_program("/nonexistent/place/docker");
    let message = panic_message(catch_unwind(AssertUnwindSafe(|| {
        create_network_outside_pool(&cli, "sf-net-z", &[]);
    })));
    assert!(message.contains("sf-net-z"), "{message}");
}
