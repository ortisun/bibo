//! The evidence ledger on a real database: a chain that stays continuous under concurrent
//! appends, a verifier that fails when a stored byte changes, and the two published hash vectors.
//!
//! An append moves the head of the job without raising the job's version (migration 17). A second
//! writer waits for the first writer's lock on the job and then finds the position taken, so the
//! retry loop below never meets a fork: the chain is continuous.

mod support;

use std::sync::Arc;
use std::time::Duration;

use diesel_async::SimpleAsyncConnection;
use factory_domain::ids::{JobId, StageRunId};
use factory_domain::ledger::{ChainError, canonical_form, chain_hash, head_of, verify_chain};
use factory_domain::values::Sha256Digest;
use factory_ports::store::StoreError;
use factory_testkit::fixtures::ledger_entry;
use support::{Scene, at};

/// Appends one entry at the head of the job's chain, retrying while another writer is in the way.
async fn append_next(scene: &Scene, job: JobId, run: StageRunId, text: &str) -> u64 {
    loop {
        let mut tx = scene.tx(scene.a).await;
        let head = tx.ledger_head(job).await.expect("head");
        let (sequence, previous) = match &head {
            Some(head) => (head.sequence + 1, Some(head.hash.clone())),
            None => (1, None),
        };
        let entry = ledger_entry(
            &scene.ids,
            job,
            run,
            sequence,
            previous.as_ref(),
            &at(),
            text,
        );
        match tx.append_ledger_entry(entry).await {
            Ok(new_head) => match tx.commit().await {
                Ok(()) => return new_head.sequence,
                Err(StoreError::Conflict) => {}
                Err(other) => panic!("commit: {other:?}"),
            },
            Err(StoreError::Conflict) => {}
            Err(other) => panic!("append: {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_appends_to_one_job_give_a_continuous_verifiable_chain() {
    let scene = Arc::new(Scene::new().await);
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    // Eight writers, five entries each, all on one job.
    let mut writers = Vec::new();
    for writer in 0..8 {
        let scene = scene.clone();
        writers.push(tokio::spawn(async move {
            let mut taken = Vec::new();
            for round in 0..5 {
                taken.push(
                    append_next(&scene, job, run, &format!("Writer {writer} entry {round}.")).await,
                );
            }
            taken
        }));
    }
    let mut positions = Vec::new();
    for writer in writers {
        positions.extend(writer.await.expect("a writer does not panic"));
    }
    positions.sort_unstable();
    assert_eq!(
        positions,
        (1..=40).collect::<Vec<u64>>(),
        "every position was taken exactly once"
    );

    // The domain verifies the chain that was read back.
    let mut tx = scene.tx(scene.a).await;
    let entries = tx.read_ledger(job, 1, 1000).await.expect("read");
    assert_eq!(entries.len(), 40);
    assert_eq!(verify_chain(&entries), Ok(()));
    let head = head_of(&entries).expect("a head");
    assert_eq!(tx.ledger_head(job).await.expect("head"), Some(head.clone()));
    assert_eq!(head.sequence, 40);

    // And the database verifier agrees: NULL means sound. It runs as the superuser here, which
    // sees every tenant. A verifier run by a session for another tenant would read nothing.
    let verdict = scene
        .db
        .text(&format!(
            "SELECT coalesce(ledger_verify_chain('{}', '{}')::text, 'sound')",
            scene.a.as_uuid(),
            job.as_uuid()
        ))
        .await;
    assert_eq!(verdict.as_deref(), Some("sound"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn flipping_one_byte_of_a_stored_entry_fails_verification() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    for position in 1..=5 {
        let sequence =
            append_next(&scene, job, run, &format!("Chain entry number {position}.")).await;
        assert_eq!(sequence, position);
    }

    // Before the change the chain is sound, by both verifiers.
    let verdict_query = format!(
        "SELECT coalesce(ledger_verify_chain('{}', '{}')::text, 'sound')",
        scene.a.as_uuid(),
        job.as_uuid()
    );
    assert_eq!(
        scene.db.text(&verdict_query).await.as_deref(),
        Some("sound")
    );
    let mut tx = scene.tx(scene.a).await;
    assert_eq!(
        verify_chain(&tx.read_ledger(job, 1, 100).await.expect("read")),
        Ok(())
    );
    drop(tx);

    // The application role cannot change a row, and neither can the owner while the trigger is on.
    let blocked = scene
        .db
        .admin()
        .await
        .batch_execute("UPDATE ledger_entries SET entry_id = entry_id")
        .await;
    assert!(
        blocked.is_err_and(|error| error.to_string().contains("append-only")),
        "the trigger refuses the owner"
    );

    // The table owner disables the trigger and flips one byte of entry 3: 'e' becomes 'E'.
    scene
        .db
        .run(&format!(
            "ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_change; \
             UPDATE ledger_entries SET canonical_json = replace(canonical_json, 'entry number 3', 'entry numbEr 3') \
              WHERE job_id = '{}' AND sequence = 3; \
             ALTER TABLE ledger_entries ENABLE TRIGGER ledger_entries_no_change;",
            job.as_uuid()
        ))
        .await;

    // The database verifier names entry 3.
    assert_eq!(scene.db.text(&verdict_query).await.as_deref(), Some("3"));
    // The Rust verifier fails at entry 3 as well: the stored hash no longer matches the content.
    let mut tx = scene.tx(scene.a).await;
    let entries = tx
        .read_ledger(job, 1, 100)
        .await
        .expect("the changed entry still parses");
    match verify_chain(&entries) {
        Err(ChainError::HashMismatch { sequence, .. }) => assert_eq!(sequence, 3),
        other => panic!("the verifier must fail at entry 3: {other:?}"),
    }
}

/// The two vectors of `docs/database/ledger-and-audit.md`, computed outside PostgreSQL with
/// Python's `hashlib`: the domain function and the database function must give the same hashes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ledger_vectors_from_the_database_docs() {
    let canonical =
        r#"{"claim":{"kind":"assumption","statement":"Café ü ß gate"},"schema_version":1}"#;
    let previous = Sha256Digest::parse(&format!("sha256:{}", "a".repeat(64))).expect("digest");
    let vectors = [
        (
            Some(previous),
            "sha256:0f5f57aa591430b785ee073cdf1ac6e09932ee15965755ae728714f00e2bc7c3",
        ),
        (
            None,
            "sha256:9f563e281c5bf7065d0ead6194d1e3140cee4610b140dc82263618a4d2302520",
        ),
    ];
    let scene = Scene::new().await;
    for (previous, expected) in &vectors {
        // The domain function.
        let from_domain = chain_hash(previous.as_ref(), canonical.as_bytes());
        assert_eq!(from_domain.as_str(), *expected, "the domain hash");
        // The database function, which the insert trigger uses.
        let previous_sql = previous
            .as_ref()
            .map_or_else(|| "NULL".to_owned(), |p| format!("'{}'", p.as_str()));
        let from_database = scene
            .db
            .text(&format!(
                "SELECT ledger_entry_hash({previous_sql}, '{}')",
                canonical.replace('\'', "''")
            ))
            .await;
        assert_eq!(
            from_database.as_deref(),
            Some(*expected),
            "the database hash"
        );
    }

    // The first append: the hash the domain computed for a real entry is the one the database
    // trigger recomputes and accepts, and it is the one stored.
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let entry = ledger_entry(&scene.ids, job, run, 1, None, &at(), "The first claim.");
    let text = String::from_utf8(canonical_form(&entry).expect("canonical")).expect("utf-8");
    let mut tx = scene.tx(scene.a).await;
    let head = tx.append_ledger_entry(entry.clone()).await.expect("append");
    tx.commit().await.expect("commit");
    assert_eq!(head.hash, entry.entry_hash);
    let stored = scene
        .db
        .text(&format!(
            "SELECT entry_hash || '|' || canonical_json FROM ledger_entries WHERE job_id = '{}'",
            job.as_uuid()
        ))
        .await
        .expect("row");
    assert_eq!(stored, format!("{}|{text}", entry.entry_hash.as_str()));
    let recomputed = scene
        .db
        .text(&format!(
            "SELECT ledger_entry_hash(prev_entry_hash, canonical_json) FROM ledger_entries WHERE job_id = '{}'",
            job.as_uuid()
        ))
        .await;
    assert_eq!(recomputed.as_deref(), Some(entry.entry_hash.as_str()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ledger_entry_for_a_stage_run_that_does_not_exist_is_refused() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let phantom = scene.ids.stage_run();
    let mut tx = scene.tx(scene.a).await;
    let refused = tx
        .append_ledger_entry(ledger_entry(
            &scene.ids,
            job,
            phantom,
            1,
            None,
            &at(),
            "No such run.",
        ))
        .await;
    // The composite key to `stage_runs` refuses it. The database aborts the transaction, so what
    // follows in it is refused too and the caller rolls back.
    assert_eq!(refused, Err(StoreError::NotFound), "no such stage run");
    assert_eq!(tx.ledger_head(job).await, Err(StoreError::Unavailable));
    drop(tx);
    let mut check = scene.tx(scene.a).await;
    assert_eq!(
        check.ledger_head(job).await,
        Ok(None),
        "the chain is still empty"
    );
}
