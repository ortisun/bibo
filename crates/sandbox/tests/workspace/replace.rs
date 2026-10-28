//! A sandbox that replaces a path it was never shown, by making a directory of the same name.

use std::fs;

use factory_ports::workspace::{Workspace, WorkspaceError};
use factory_testkit::clock::FakeCancel;

use crate::world::World;

#[tokio::test(flavor = "multi_thread")]
async fn a_directory_made_where_a_hidden_file_is_cannot_remove_that_file_from_the_tree() {
    // `.env` is hidden, so it is not in the checkout. A directory with that name, holding a file,
    // would replace the hidden file in the new tree without any file written at a hidden path.
    let world = World::new().await;
    let (ws, _) = world.open(1).await;
    let dir = ws.mounts().workspace;
    assert!(!dir.join(".env").exists());
    fs::create_dir_all(dir.join(".env")).expect("a directory");
    fs::write(dir.join(".env/inner.txt"), "x\n").expect("a file");
    match ws.ingest(&FakeCancel::new()).await {
        Err(WorkspaceError::HiddenPathPresent(found)) => assert_eq!(found.as_str(), ".env"),
        other => panic!("expected HiddenPathPresent, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_directory_made_where_a_protected_file_is_counts_as_deleting_it() {
    let world = World::new().await;
    let (ws, _) = world.open(1).await;
    let dir = ws.mounts().workspace;
    fs::remove_file(dir.join("CHANGELOG.md")).expect("remove");
    fs::create_dir_all(dir.join("CHANGELOG.md")).expect("a directory");
    fs::write(dir.join("CHANGELOG.md/inner.txt"), "x\n").expect("a file");
    match ws.ingest(&FakeCancel::new()).await {
        Err(WorkspaceError::ProtectedPathChanged(list)) => {
            assert!(list.iter().any(|v| v.path.as_str() == "CHANGELOG.md"));
        }
        other => panic!("expected ProtectedPathChanged, got {other:?}"),
    }
}
