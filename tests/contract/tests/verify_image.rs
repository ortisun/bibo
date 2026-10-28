//! The fixture's commands in the pinned verify image, with no network.
//!
//! These tests need Docker and the image `factory-sandbox/verify`. When either is missing they
//! panic with a message that starts `BLOCKED:`, as the testkit's guards do. They are never
//! skipped, and a missing Docker is never a pass. The image comes from
//! `infra/sandbox-images/images.json`, by digest.

use fixture_contract::exec;
use fixture_contract::workdir::copy_fixture;
use fixture_contract::{Outcome, fixture_dir, repository_root};

fn reference_or_blocked() -> String {
    let images = repository_root().join("infra/sandbox-images/images.json");
    let reference =
        exec::verify_image_reference(&images).unwrap_or_else(|reason| panic!("BLOCKED: {reason}"));
    if let Some(reason) = exec::image_blocker(&reference) {
        panic!("BLOCKED: {reason}");
    }
    reference
}

#[test]
fn the_fixture_builds_and_passes_its_tests_in_the_pinned_verify_image() {
    let reference = reference_or_blocked();
    assert!(
        reference.contains("@sha256:"),
        "the image must be pinned by digest: {reference}"
    );
    let copy = copy_fixture(&fixture_dir(), "image").expect("the fixture copies");
    let results = exec::run_in_image(copy.path(), &reference);
    let leftovers = exec::remove_leftover_containers();
    assert_eq!(leftovers, 0, "a container was left behind");
    for result in &results {
        assert!(
            result.succeeded(),
            "{} failed in the image: {}\n{}",
            result.label,
            result.argv.join(" "),
            result.stderr
        );
    }
    assert_eq!(exec::outcome_of(&results), Outcome::Passed);
}

#[test]
fn the_verify_image_reference_is_read_from_the_registry_file() {
    let images = repository_root().join("infra/sandbox-images/images.json");
    let reference = exec::verify_image_reference(&images).expect("a ready verify image");
    assert!(
        reference.starts_with("factory-sandbox/verify@sha256:"),
        "{reference}"
    );
}

#[test]
fn a_registry_file_without_a_ready_verify_image_is_refused() {
    let dir = fixture_contract::workdir::TempDir::new("images").expect("a directory");
    let path = dir.path().join("images.json");
    std::fs::write(&path, r#"{"platforms": {}}"#).expect("written");
    assert!(exec::verify_image_reference(&path).is_err());
}
