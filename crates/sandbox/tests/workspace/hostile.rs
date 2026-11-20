//! The hostile fixtures of the security harness against the audit and ingestion (NT-SBX-09,
//! NT-SBX-10), host side. Nothing hostile runs: the fixtures are written to disk as data, the
//! adapter audits them, and the spawn recorder shows what host git was asked to do.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use factory_ports::workspace::{Workspace, WorkspaceError, WorkspaceProvider};
use factory_sandbox::SystemProcessRunner;
use factory_sandbox::workspace::{
    AuditKind, AuditLimits, GitWorkspace, audit_output, read_output_file,
};
use factory_testkit::clock::FakeCancel;
use factory_testkit::fx::archive::{self, Entry};
use factory_testkit::fx::canary::{CanaryKind, CanarySet, Sweeper};
use factory_testkit::fx::repos::{
    AttackKind, AttackOptions, Fixture, MaterializeOptions, materialize, plant_ingestion_attacks,
};
use factory_testkit::fx::spawn::{Behavior, SpawnPolicy, SpawnRecord, SpawnRecorder};

use crate::harness::TestGit;
use crate::world::{Options, World, commit_request, real_git};

/// A world whose host git calls all go through the spawn recorder.
pub struct Recording {
    pub recorder: SpawnRecorder,
    pub runner: Arc<SystemProcessRunner>,
}

impl Recording {
    pub fn new() -> Self {
        let mut recorder = SpawnRecorder::new(SpawnPolicy::docker_and_git()).expect("a recorder");
        recorder
            .install("git", &Behavior::Passthrough(real_git()))
            .expect("a git shim");
        let runner = Arc::new(
            SystemProcessRunner::new()
                .with_programs(PathBuf::from("docker"), recorder.bin_dir().join("git")),
        );
        Self { recorder, runner }
    }

    pub fn records(&self) -> Vec<SpawnRecord> {
        self.recorder.records().expect("the records")
    }
}

/// Everything wrong with how host git was started: missing hardening, a working directory or an
/// argument or an environment value inside a tree the sandbox could write, a URL with a password,
/// a signing flag, an ownership override.
pub fn problems(records: &[SpawnRecord], writable: &[&Path]) -> Vec<String> {
    let writable: Vec<String> = writable
        .iter()
        .map(|p| {
            fs::canonicalize(p)
                .unwrap_or_else(|_| p.to_path_buf())
                .display()
                .to_string()
        })
        .collect();
    let mut found = Vec::new();
    for record in records.iter().filter(|r| r.program == "git") {
        for missing in record.missing_git_hardening() {
            found.push(format!("#{} lacks {missing}", record.seq));
        }
        for tree in &writable {
            let canonical = |text: &str| text.replace("/private", "");
            let tree = canonical(tree);
            if canonical(&record.cwd).starts_with(&tree) {
                found.push(format!(
                    "#{} ran in the writable tree {}",
                    record.seq, record.cwd
                ));
            }
            if record.argv.iter().any(|a| canonical(a).contains(&tree)) {
                found.push(format!(
                    "#{} names the writable tree: {:?}",
                    record.seq, record.argv
                ));
            }
            if record.env.values().any(|v| canonical(v).contains(&tree)) {
                found.push(format!(
                    "#{} has the writable tree in its environment",
                    record.seq
                ));
            }
        }
        if !record.arguments_with_url_credentials().is_empty() {
            found.push(format!("#{} has a URL with a password", record.seq));
        }
        if record
            .argv
            .iter()
            .any(|a| a == "-S" || a.starts_with("--gpg-sign") || a.contains("safe."))
        {
            found.push(format!(
                "#{} signs or overrides the ownership check",
                record.seq
            ));
        }
    }
    found
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("a directory");
    for entry in fs::read_dir(from).expect("read_dir").flatten() {
        let target = to.join(entry.file_name());
        let kind = entry.file_type().expect("type");
        if kind.is_symlink() {
            let link = fs::read_link(entry.path()).expect("a link");
            let _ = fs::remove_file(&target);
            symlink(link, &target).expect("a link");
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("a file");
        }
    }
}

async fn ingest_error(ws: &GitWorkspace) -> WorkspaceError {
    match ws.ingest(&FakeCancel::new()).await {
        Err(error) => error,
        Ok(change) => panic!("the tree was accepted: {change:?}"),
    }
}

fn kinds(ws: &GitWorkspace) -> Vec<(AuditKind, String)> {
    ws.last_audit_report()
        .expect("an audit report")
        .reasons
        .into_iter()
        .map(|r| (r.kind, r.path.as_str().to_owned()))
        .collect()
}

// ---- NT-SBX-10: hostile git configuration runs nothing on the host --------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_10_hostile_git_configuration_runs_nothing_on_the_host() {
    let recording = Recording::new();
    let world = World::with(Options {
        runner: Some(Arc::clone(&recording.runner) as _),
        ..Options::default()
    })
    .await;
    let canaries = CanarySet::generate();

    // The sandbox's worst case: the mask is gone and a hostile repository, with a configuration
    // that names a file system monitor, a hooks directory and an alias, sits in its place.
    let hostile = materialize(
        Fixture::Hostile,
        &canaries,
        &MaterializeOptions {
            replaced_root_git: true,
            marker_path_text: None,
        },
    )
    .expect("the hostile fixture");
    let (ws, _) = world.open(1).await;
    let checkout = ws.mounts().workspace;
    fs::remove_file(checkout.join(".git")).expect("take the mask away");
    copy_tree(&hostile.root(), &checkout);
    assert!(
        checkout.join(".git/config").exists(),
        "the hostile config is on disk"
    );
    assert!(checkout.join("vendor/dep/.git/config").exists());

    let error = ingest_error(&ws).await;
    assert!(
        matches!(error, WorkspaceError::NestedGit(_)),
        "a replaced .git is the first thing refused: {error:?}"
    );
    let found = kinds(&ws);
    assert!(
        found.contains(&(AuditKind::NestedGit, "_checkout_root_".to_owned())),
        "{found:?}"
    );
    assert!(
        found.contains(&(AuditKind::NestedGit, "vendor/dep".to_owned())),
        "{found:?}"
    );
    assert!(
        found.iter().any(|(k, _)| *k == AuditKind::EscapingSymlink),
        "the fixture's links to the host canary are rejected too: {found:?}"
    );
    assert!(
        hostile.markers_present().is_empty(),
        "a hostile command ran: {:?}",
        hostile.markers_present()
    );

    // A second sandbox only plants a hostile attributes file and a submodule file, and edits a
    // source file. The host runs its normal read-tree, diff and commit over the audited bytes.
    let (clean, _) = world.open(2).await;
    let dir = clean.mounts().workspace;
    fs::write(dir.join(".gitattributes"), "* filter=evil diff=evil\n").expect("attributes");
    fs::write(dir.join(".gitmodules"), "[submodule \"x\"]\n\tpath = x\n").expect("modules");
    fs::write(dir.join("src/lib.rs"), "pub fn answer() -> u32 { 7 }\n").expect("edit");
    assert!(
        matches!(
            clean.ingest(&FakeCancel::new()).await,
            Err(WorkspaceError::Gitlink(_))
        ),
        "a .gitmodules file is refused like a gitlink"
    );
    fs::remove_file(dir.join(".gitmodules")).expect("remove");
    let change = clean.ingest(&FakeCancel::new()).await.expect("ingest");
    let commit = clean
        .commit(&change, commit_request("Edit with hostile attributes"))
        .await
        .expect("commit");
    let repo = world
        .provider
        .repo(crate::support::job(2))
        .await
        .expect("the store");
    let patch = repo
        .export_patch(clean.base(), &commit, 1 << 20, &FakeCancel::new())
        .await
        .expect("export");
    assert_eq!(patch.changes.len(), 2, "{:?}", patch.changes);

    assert!(hostile.markers_present().is_empty());
    let records = recording.records();
    assert!(
        records.len() >= 15,
        "git was really recorded: {}",
        records.len()
    );
    let writable: Vec<PathBuf> = vec![checkout.clone(), dir.clone()];
    let writable: Vec<&Path> = writable.iter().map(PathBuf::as_path).collect();
    assert_eq!(problems(&records, &writable), Vec::<String>::new());
    recording.recorder.assert_clean();
}

// ---- NT-SBX-09: every hostile entry is rejected, with its reason, and nothing hangs ---------------

/// The number of objects in a store, so a test can show that nothing was written to it.
async fn object_count(git: &TestGit, store: &Path) -> String {
    git.run(store, &["count-objects", "-v"]).await
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_09_every_hostile_entry_is_rejected_with_its_reason() {
    let limits = AuditLimits {
        max_entries: 500,
        ..AuditLimits::default()
    };
    let world = World::with(Options {
        limits,
        ..Options::default()
    })
    .await;
    let (ws, _) = world.open(1).await;
    let checkout = ws.mounts().workspace;
    let canaries = CanarySet::generate();
    let canary = canaries
        .get(CanaryKind::SecondTenantString)
        .value()
        .to_owned();
    let outside = world.scratch.path().join("outside-the-job.txt");
    fs::write(&outside, format!("host only: {canary}\n")).expect("an outside file");
    let report = plant_ingestion_attacks(
        &checkout,
        &outside,
        &AttackOptions {
            oversize_bytes: AuditLimits::default().max_file_bytes + 1,
            tiny_files: 1_000,
        },
    );
    assert!(
        report.unsupported.iter().all(|(kind, _)| matches!(
            kind,
            AttackKind::Socket
                | AttackKind::InvalidUtf8Name
                | AttackKind::OverlongName
                | AttackKind::OverlongPath
        )),
        "{:?}",
        report.unsupported
    );
    if report
        .unsupported
        .iter()
        .any(|(k, _)| *k == AttackKind::Socket)
    {
        plant_socket(&checkout);
    }
    fs::create_dir_all(checkout.join("aaa/x/.git")).expect("a nested repository");
    fs::write(checkout.join("aaa/x/.git/config"), "[core]\n").expect("its config");

    let git = TestGit::new(Arc::new(SystemProcessRunner::new()));
    let store = world
        .root
        .join("jobs")
        .join(support_job(1))
        .join("store.git");
    let before = object_count(&git, &store).await;
    let started = Instant::now();
    let error = ingest_error(&ws).await;
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the FIFO did not hang the audit: {:?}",
        started.elapsed()
    );
    assert!(matches!(error, WorkspaceError::NestedGit(_)), "{error:?}");
    let found = kinds(&ws);
    let has = |kind: AuditKind, path: &str| found.contains(&(kind, path.to_owned()));
    assert!(has(AuditKind::NestedGit, "aaa/x"), "{found:?}");
    assert!(has(AuditKind::SpecialFile, "pipe"), "a FIFO: {found:?}");
    assert!(has(AuditKind::SpecialFile, "sock"), "a socket: {found:?}");
    assert!(
        has(AuditKind::HardLink, "hardlink-to-outside"),
        "a hard link to a file outside the job: {found:?}"
    );
    assert!(has(AuditKind::SetuidMode, "setuid-file"), "{found:?}");
    assert!(has(AuditKind::FileTooLarge, "oversize.bin"), "{found:?}");
    assert!(
        found
            .iter()
            .filter(|(k, _)| *k == AuditKind::UnsafeName)
            .count()
            >= 2,
        "a newline and ANSI codes in a name: {found:?}"
    );
    assert!(
        found.iter().any(|(k, _)| *k == AuditKind::TooManyEntries),
        "300,000 tiny files, scaled down: {found:?}"
    );
    // No reason carries a raw control character.
    assert!(
        found.iter().all(|(_, p)| !p.chars().any(char::is_control)),
        "{found:?}"
    );

    // Nothing was read into the store, and the host file's content is in no sink.
    assert_eq!(
        object_count(&git, &store).await,
        before,
        "the store did not change"
    );
    let sweeper = Sweeper::new(&canaries);
    let mut hits = sweeper.scan("error", format!("{error:?}").as_bytes());
    hits.extend(sweeper.scan("report", format!("{:?}", ws.last_audit_report()).as_bytes()));
    assert!(hits.is_empty(), "{hits:?}");
}

/// A socket file in `dir`. The checkout path is longer than a socket address can be, so the
/// socket is bound through a short link to the directory.
fn plant_socket(dir: &Path) {
    let short = PathBuf::from(format!(
        "/tmp/wsk-{}-{}",
        std::process::id(),
        dir.display().to_string().len()
    ));
    let _ = fs::remove_file(&short);
    symlink(dir, &short).expect("a short link");
    let bound = std::os::unix::net::UnixListener::bind(short.join("sock"));
    fs::remove_file(&short).expect("remove the short link");
    drop(bound.expect("a socket file"));
}

fn support_job(n: u128) -> String {
    crate::support::job(n).as_text()
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_09_a_link_to_a_host_canary_is_never_read() {
    let recording = Recording::new();
    let world = World::with(Options {
        runner: Some(Arc::clone(&recording.runner) as _),
        ..Options::default()
    })
    .await;
    let canaries = CanarySet::generate();
    let canary = canaries
        .get(CanaryKind::SecondTenantString)
        .value()
        .to_owned();
    let outside = world.scratch.path().join("host-canary.txt");
    fs::write(&outside, format!("host only: {canary}\n")).expect("an outside file");

    let (ws, _) = world.open(1).await;
    let mounts = ws.mounts();
    // In the worktree: an absolute link to the host file, and a relative one that climbs out.
    symlink(&outside, mounts.workspace.join("absolute-link")).expect("link");
    symlink(
        "../../../../../../etc/hosts",
        mounts.workspace.join("relative-link"),
    )
    .expect("link");
    // In the output directory: the same attack.
    symlink(&outside, mounts.out.join("report.txt")).expect("link");
    fs::write(mounts.out.join("fine.txt"), "all good\n").expect("a fine file");

    let error = ingest_error(&ws).await;
    assert!(
        matches!(error, WorkspaceError::EscapingSymlink(_)),
        "{error:?}"
    );
    let found = kinds(&ws);
    assert!(found.contains(&(AuditKind::EscapingSymlink, "absolute-link".to_owned())));
    assert!(found.contains(&(AuditKind::EscapingSymlink, "relative-link".to_owned())));

    let stop = std::sync::atomic::AtomicBool::new(false);
    let rejected = audit_output(&mounts.out, &AuditLimits::default(), &stop)
        .expect_err("the output directory holds a link out");
    let report = rejected.expect("a report");
    assert_eq!(report.of_kind(AuditKind::EscapingSymlink).len(), 1);
    fs::remove_file(mounts.out.join("report.txt")).expect("remove the link");
    let files = audit_output(&mounts.out, &AuditLimits::default(), &stop).expect("now fine");
    assert_eq!(files.len(), 1);
    assert_eq!(
        read_output_file(&mounts.out, &files[0], 1024).expect("read"),
        b"all good\n"
    );
    assert_eq!(
        read_output_file(&mounts.out, &files[0], 3),
        Err(WorkspaceError::TooLarge)
    );

    // The canary is in no sink: not in the errors, not in anything git was asked to run.
    let sweeper = Sweeper::new(&canaries);
    let records = serde_json::to_string(&recording.recorder.to_json()).expect("json");
    let mut hits = sweeper.scan("error", format!("{error:?}").as_bytes());
    hits.extend(sweeper.scan("report", format!("{report:?}").as_bytes()));
    hits.extend(sweeper.scan("spawn records", records.as_bytes()));
    assert!(hits.is_empty(), "{hits:?}");
    assert_eq!(
        problems(&recording.records(), &[&mounts.workspace, &mounts.out]),
        Vec::<String>::new()
    );
}

/// What an extractor that trusts the archive does: it joins the name to the target directory, so
/// `..` climbs out, writes a link as given, and makes a hard link to whatever the archive names.
fn unsafe_extract(bytes: &[u8], into: &Path) {
    let text = |slice: &[u8]| {
        let end = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..end]).into_owned()
    };
    let mut offset = 0;
    let mut long_name = None;
    while offset + 512 <= bytes.len() {
        let header = &bytes[offset..offset + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let name = text(&header[0..100]);
        let size = usize::from_str_radix(text(&header[124..136]).trim(), 8).expect("a size");
        let flag = header[156];
        let link = text(&header[157..257]);
        offset += 512;
        let data = &bytes[offset..offset + size];
        offset += size.div_ceil(512) * 512;
        if flag == b'L' {
            long_name = Some(text(data));
            continue;
        }
        let name = long_name.take().unwrap_or(name);
        let at = into.join(&name);
        if let Some(parent) = at.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match flag {
            b'0' => fs::write(&at, data).expect("a file"),
            b'5' => fs::create_dir_all(&at).expect("a directory"),
            b'2' => symlink(&link, &at).expect("a link"),
            b'1' => fs::hard_link(into.join(&link), &at).expect("a hard link"),
            _ => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_nt_sbx_09_an_archive_entry_that_escapes_and_a_tar_bomb_are_refused() {
    let world = World::with(Options {
        limits: AuditLimits {
            max_entries: 2_000,
            max_total_bytes: 2 * 1024 * 1024,
            ..AuditLimits::default()
        },
        ..Options::default()
    })
    .await;
    let canaries = CanarySet::generate();
    let canary = canaries
        .get(CanaryKind::SecondTenantString)
        .value()
        .to_owned();
    let outside = world.scratch.path().join("outside.txt");
    fs::write(&outside, format!("host only: {canary}\n")).expect("an outside file");

    // An archive that climbs out of the directory, links to the host, and hard-links to a file
    // outside the job.
    let (ws, _) = world.open(1).await;
    let checkout = ws.mounts().workspace;
    let attempt_dir = checkout
        .parent()
        .expect("the attempt directory")
        .to_path_buf();
    // From the checkout up to the scratch directory that holds the outside file.
    let depth = checkout.components().count() - world.scratch.path().components().count();
    let climb = format!("{}outside.txt", "../".repeat(depth));
    let escaping = archive::tar(&[
        Entry::file("../escaped-by-the-archive.txt", b"outside the checkout\n"),
        Entry::symlink("evil", &outside.display().to_string()),
        Entry::hardlink("hard", &climb),
        Entry::file("fine.txt", b"fine\n"),
    ]);
    unsafe_extract(&escaping, &checkout);
    assert!(
        attempt_dir.join("escaped-by-the-archive.txt").exists(),
        "the unsafe extractor really wrote outside the checkout"
    );
    let error = ingest_error(&ws).await;
    assert!(
        matches!(error, WorkspaceError::EscapingSymlink(_)),
        "{error:?}"
    );
    assert!(kinds(&ws).contains(&(AuditKind::EscapingSymlink, "evil".to_owned())));
    let sweeper = Sweeper::new(&canaries);
    assert!(
        sweeper
            .scan("error", format!("{error:?}").as_bytes())
            .is_empty()
    );

    // A tar bomb: thousands of entries and a payload over the byte limit.
    let (bomb, _) = world.open(2).await;
    let mut entries: Vec<Entry> = (0..2_500)
        .map(|n| Entry::file(&format!("bomb/f{n}"), b"x"))
        .collect();
    entries.push(Entry::file("bomb/payload.bin", &vec![b'z'; 2_300_000]));
    unsafe_extract(&archive::tar(&entries), &bomb.mounts().workspace);
    let error = ingest_error(&bomb).await;
    assert_eq!(error, WorkspaceError::TooLarge, "the bomb is refused");
    assert!(
        kinds(&bomb)
            .iter()
            .any(|(k, _)| matches!(k, AuditKind::TooManyEntries | AuditKind::TreeTooLarge))
    );
}

// ---- the credential travels in the environment only --------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_reaches_git_through_the_environment_and_nowhere_else() {
    use factory_ports::paths::BranchName;
    use factory_ports::workspace::{FetchCredential, FetchTarget};
    use factory_sandbox::workspace::{RemoteLocation, WorkspaceSettings};

    let recording = Recording::new();
    let scratch = crate::support::Scratch::new("ws-credential");
    // Nothing listens on this loopback port, so the fetch fails at once and reaches no network.
    let settings = WorkspaceSettings::new(
        scratch.path().join("root"),
        RemoteLocation::Https {
            host: "127.0.0.1:9".to_owned(),
        },
    );
    let artifacts = Arc::new(factory_testkit::artifact::InMemoryArtifactStore::new());
    let provider = crate::harness::provider_over(
        settings,
        Arc::clone(&recording.runner) as _,
        artifacts,
        factory_ports::paths::PathRules::default(),
    );
    let secret = format!("{}-{}", "token", "for-the-test-only");
    let target = FetchTarget {
        repo: factory_ports::paths::RepoRef::parse("example-org/fixture").expect("repo"),
        credential: FetchCredential::new(secret.clone()),
    };
    let result = provider
        .fetch(
            crate::support::job(1),
            &target,
            &BranchName::new("main").expect("a branch"),
            &FakeCancel::new(),
        )
        .await;
    let error = result.expect_err("nothing listens there");
    assert!(!format!("{error:?}").contains(&secret));
    assert!(!format!("{target:?}").contains(&secret));
    let records = recording.records();
    assert!(!records.is_empty());
    for record in &records {
        assert!(
            record.argv.iter().all(|a| !a.contains(&secret)),
            "{:?}",
            record.argv
        );
    }
    let carrying: Vec<&SpawnRecord> = records
        .iter()
        .filter(|r| r.env.contains_key("GIT_CONFIG_VALUE_0"))
        .collect();
    assert!(
        !carrying.is_empty(),
        "the credential travelled in the environment"
    );
    assert!(
        problems(&records, &[]).is_empty(),
        "{:?}",
        problems(&records, &[])
    );
}
