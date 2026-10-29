//! The two values the validation evidence is bound to, asked for by someone else.
//!
//! The delivery and approval stages compare them with the evidence, so they must come from the
//! computation the validation stage uses for its own binding. Before `current_values` was public
//! the composition crate had no way to answer, and the delivery stage failed closed at that point.

use factory_ports::workspace::WorkspaceProvider as _;
use factory_workflow::stages::validation::current_values;

use crate::world::World;

#[tokio::test]
async fn current_values_are_the_values_the_stage_bound_its_evidence_to() {
    let world = World::new();
    let (base, head) = world.project(&[("src/lib.rs", Some("// changed\n"))]).await;
    let ran = world.run(&base, &head).await;

    let repo = world
        .workspaces
        .repo(world.job)
        .await
        .expect("the job's repository");
    let (definition_hash, image_digest) = current_values(&*repo, &world.config(), &base)
        .await
        .expect("the values");

    let binding = &ran.evidence["binding"];
    assert_eq!(
        binding["definition_hash"].as_str(),
        Some(definition_hash.as_str()),
        "the hash of the gate definitions"
    );
    assert_eq!(
        binding["image_digest"].as_str(),
        Some(image_digest.as_str()),
        "the digest of the verify image"
    );
}

#[tokio::test]
async fn definitions_that_cannot_be_read_give_a_hash_of_their_own() {
    // A base commit without a manifest has no definitions. The hash says so, and it is not the
    // hash of a base that has them, so evidence made with a manifest no longer matches.
    let world = World::new();
    let with_manifest = world.project(&[]).await.0;
    let without = world
        .push(&[("src/lib.rs".to_owned(), "// no manifest\n".to_owned())])
        .await;
    let repo = world
        .workspaces
        .repo(world.job)
        .await
        .expect("the job's repository");
    let config = world.config();
    let (held, _) = current_values(&*repo, &config, &with_manifest)
        .await
        .expect("values");
    let (missing, _) = current_values(&*repo, &config, &without)
        .await
        .expect("values");
    assert_ne!(held, missing);
}
