//! The engine side of RR-28: the hook that applies a person's decision and the admission of a job ask
//! about a registered repository with GitHub's numeric id, so an allowlist entry that lists the id follows
//! the repository through a rename or a transfer, and a new repository created under the old name is
//! another repository. The API side is in `apps/api/tests/repositories.rs`.

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use factory_composition::authority::StoreAuthority;
use factory_composition::decisions::{AllowlistAuthority, DecisionAuthority};
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::load_policy;
use factory_composition::system::SystemClock;
use factory_domain::ids::RepositoryId;
use factory_domain::policy::authority::RepositoryIdentity;
use factory_ports::clock::IdGenerator;
use factory_testkit::fixtures::SeededRepository;
use factory_workflow::commands::Authority;
use factory_workflow::stages::approval::Verb;
use support::pg_world;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// Admission of a requester whose entry lists repository one by id: it follows the repository through a
/// rename and a transfer, it does not reach a new repository registered under the same name, and the
/// entry that lists the name alone does (the weaker form).
#[tokio::test(flavor = "multi_thread")]
async fn rr_28_admission_follows_the_id_through_a_rename_and_not_to_a_new_repository_under_the_old_name()
 {
    let (db, world, tenant) = pg_world().await;
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let checkout = root()
        .join("target/repository-identity")
        .join(world.ids.new_uuid().simple().to_string());
    std::fs::create_dir_all(checkout.join("allowlist")).expect("a directory");
    let write_allowlist = |repositories: &str| {
        std::fs::write(
            checkout.join("allowlist/allowlist.yaml"),
            format!(
                "version: 1\nentries:\n  - tenant: {}\n    github_user_id: 1001\n    login: requester-one\n    designations: [requester]\n{repositories}",
                tenant.as_uuid()
            ),
        )
        .expect("the allowlist file");
    };
    let authority = StoreAuthority::new(
        world.store.clone(),
        Arc::new(FileAllowlist::in_checkout(&checkout)),
        Arc::clone(&policies.engine),
        world.deps.clock.clone(),
    );
    let tenant_text = tenant.as_uuid().to_string();
    let seed = |id: RepositoryId, github: u64, name: &'static str| {
        let sql = SeededRepository {
            tenant: &tenant_text,
            id: &id.as_uuid().to_string(),
            installation: 1000,
            github_repository: github,
            full_name: name,
            default_branch: "main",
            autonomy_ceiling: "L0",
        }
        .sql();
        let db = &db;
        async move { db.run(&sql).await }
    };
    let old = RepositoryId::from_uuid(world.ids.new_uuid());
    let reused = RepositoryId::from_uuid(world.ids.new_uuid());
    seed(old, 5_001, "org/old-name").await;
    seed(reused, 5_002, "org/old-name").await;
    let requester_reaches = |id: RepositoryId| {
        let authority = &authority;
        async move {
            authority
                .admission(tenant, world.requester, id)
                .await
                .expect("facts")
                .requester_on_allowlist
        }
    };

    // The entry lists the id of the old repository.
    write_allowlist(
        "    repositories:\n      - name: org/old-name\n        github_repository_id: 5001\n",
    );
    assert!(
        requester_reaches(old).await,
        "the repository the entry lists"
    );
    assert!(
        !requester_reaches(reused).await,
        "a new repository under the old name inherits nothing"
    );
    // Renamed, and transferred: the registered name changes and the id does not.
    for name in ["org/renamed", "elsewhere/renamed"] {
        db.run(&format!(
            "UPDATE repositories SET full_name = '{name}', version = version + 1 WHERE id = '{}'",
            old.as_uuid()
        ))
        .await;
        assert!(
            requester_reaches(old).await,
            "{name}: the id is the same repository"
        );
    }
    // The weaker form: an entry that lists the name alone is inherited by the new repository.
    write_allowlist("    repositories: [org/old-name]\n");
    assert!(
        requester_reaches(reused).await,
        "the name alone follows the name"
    );
    assert!(
        !requester_reaches(old).await,
        "and loses the renamed repository"
    );
}

/// The hook that applies a decision asks `AllowlistAuthority::permits` with the repository's identity.
#[tokio::test(flavor = "multi_thread")]
async fn rr_28_the_hook_asks_with_the_id_so_a_new_repository_under_the_old_name_is_not_reached() {
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let tenant = factory_domain::ids::TenantId::from_uuid(uuid::Uuid::from_u128(0x28));
    let ids = factory_composition::system::RandomIds::new().expect("the random source opens");
    let checkout = root()
        .join("target/repository-identity")
        .join(ids.new_uuid().simple().to_string());
    std::fs::create_dir_all(checkout.join("allowlist")).expect("a directory");
    std::fs::write(
        checkout.join("allowlist/allowlist.yaml"),
        format!(
            "version: 1\nentries:\n  - tenant: {}\n    github_user_id: 2001\n    login: approver-one\n    designations: [approver]\n    repositories:\n      - name: acme/widgets\n        github_repository_id: 7001\n",
            tenant.as_uuid()
        ),
    )
    .expect("the allowlist file");
    let authority = AllowlistAuthority::new(
        Arc::new(FileAllowlist::in_checkout(&checkout)),
        Arc::clone(&policies.approval),
        Arc::new(SystemClock),
    );
    let asks = |identity: RepositoryIdentity<'static>| {
        let authority = &authority;
        async move {
            authority
                .permits(tenant, 2001, Verb::Approve, &identity)
                .await
                .expect("the allowlist reads")
        }
    };
    assert!(asks(RepositoryIdentity::registered("acme/widgets", 7001)).await);
    assert!(
        asks(RepositoryIdentity::registered("acme/renamed", 7001)).await,
        "renamed"
    );
    assert!(
        !asks(RepositoryIdentity::registered("acme/widgets", 7002)).await,
        "a new repository under the old name"
    );
    let _ = std::fs::remove_dir_all(&checkout);
}
