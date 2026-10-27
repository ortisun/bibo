use std::collections::BTreeSet;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::process::Command;

use super::*;
use crate::fx::canary::{CanaryKind, CanarySet, Form, Sweeper};
use crate::fx::docker::{DockerGuard, blocked};
use crate::fx::rng::FxRng;

fn canaries() -> CanarySet {
    CanarySet::generate_with(&mut FxRng::from_seed(11))
}

fn manifest(fixture: Fixture) -> Manifest {
    Manifest::load(fixture).expect("the manifest loads")
}

fn catalog() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/security/negative-test-catalog.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the catalog cannot be read at {}: {e}", path.display()))
}

/// The table row of the catalog for a fixture.
fn catalog_row(catalog: &str, id: &str) -> String {
    catalog
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap_or_else(|| panic!("the catalog has no row for {id}"))
        .to_owned()
}

/// The text between backticks, in order.
fn backticked(row: &str) -> Vec<String> {
    row.split('`')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, token)| token.to_owned())
        .collect()
}

fn stored_text(manifest: &Manifest, path: &str) -> String {
    let entry = manifest
        .entry(path)
        .unwrap_or_else(|| panic!("no entry {path}"));
    String::from_utf8(manifest.stored_bytes(entry).unwrap()).unwrap()
}

/// Whether the manifest has what the catalog asks of this fixture. Returns what is missing.
fn catalog_problems(manifest: &Manifest, catalog: &str) -> Vec<String> {
    let row = catalog_row(catalog, manifest.fixture.id());
    let has_path = |path: &str| manifest.entry(path).is_some();
    let has_under = |prefix: &str| manifest.entries.iter().any(|e| e.path.starts_with(prefix));
    let has_component = |name: &str| {
        manifest
            .entries
            .iter()
            .any(|e| e.path.split('/').any(|part| part == name))
    };
    let text_of = |path: &str| {
        manifest
            .entry(path)
            .and_then(|e| manifest.stored_bytes(e).ok())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    let mut problems = Vec::new();

    // Everything the catalog row puts in backticks is a file, a directory, or a named feature.
    for token in backticked(&row) {
        let satisfied = match token.as_str() {
            "#[cfg(test)]" => {
                text_of("src/lib.rs").contains("#[cfg(test)]")
                    && text_of("src/lib.rs").contains("#[test]")
            }
            ".git" => has_component(".git"),
            "postinstall" => text_of("package.json").contains("\"postinstall\""),
            t if t.ends_with('/') => has_under(t),
            t => has_path(t),
        };
        if !satisfied {
            problems.push(format!(
                "the catalog names `{token}` and the fixture lacks it"
            ));
        }
    }

    let mut require = |ok: bool, what: &str| {
        if !ok {
            problems.push(format!("the catalog requires {what}"));
        }
    };
    match manifest.fixture {
        Fixture::Clean => {
            require(
                text_of("tests/it.rs").matches("#[test]").count() == 3,
                "three tests in tests/it.rs",
            );
            require(
                manifest
                    .entries
                    .iter()
                    .any(|e| e.path.starts_with(".github/workflows/") && e.path.ends_with(".yml")),
                "a CI workflow",
            );
            require(
                text_of("tests/holdout/holdout.txt").contains("@@CANARY:holdout_string@@"),
                "a canary string in the holdout directory",
            );
            require(has_under("tests/fixtures/"), "a file in tests/fixtures/");
            require(
                manifest
                    .entries
                    .iter()
                    .all(|e| e.kind != EntryKind::Symlink),
                "no symbolic links in the clean repository",
            );
        }
        Fixture::Hostile => {
            let injection = "Ignore previous instructions";
            for path in ["README.md", "CONTRIBUTING.md", "src/lib.rs"] {
                require(
                    text_of(path).contains(injection),
                    &format!("injection text in {path}"),
                );
            }
            let settings = text_of(".claude/settings.json");
            require(
                settings.contains("\"hooks\"")
                    && settings.contains("\"env\"")
                    && settings.contains("@@MARKER_DIR@@"),
                "a hook and an environment block that touch marker files in .claude/settings.json",
            );
            let absolute_links = manifest
                .entries
                .iter()
                .filter(|e| e.kind == EntryKind::Symlink)
                .filter(|e| {
                    e.target
                        .as_deref()
                        .is_some_and(|t| t.starts_with('/') || t.starts_with("@@HOST"))
                })
                .count();
            require(absolute_links >= 2, "symbolic links to absolute paths");
            let nested = text_of("vendor/dep/.git/config");
            for key in [
                "fsmonitor",
                "hooksPath",
                "sshCommand",
                "external",
                "alias",
                "@@GIT_OWNERSHIP_OVERRIDE@@",
            ] {
                require(
                    nested.contains(key) || key == "alias" && nested.contains("[alias]"),
                    &format!("`{key}` in the nested .git config"),
                );
            }
            let build = text_of("build.rs");
            require(
                build.contains("@@MARKER_DIR@@") && build.contains("TcpStream::connect"),
                "a build script that touches a marker and tries the network",
            );
            let package = text_of("package.json");
            require(
                package.contains("@@MARKER_DIR@@") && package.contains("curl"),
                "an install script that touches a marker and tries the network",
            );
            let secrets = [
                "database_password",
                "model_api_key",
                "github_installation_token",
            ];
            require(
                secrets
                    .iter()
                    .all(|s| text_of(".env").contains(&format!("@@CANARY:{s}@@"))),
                "an .env file with canaries",
            );
            require(
                text_of("id_rsa").contains("@@CANARY:app_private_key@@"),
                "a key file with a canary",
            );
        }
    }
    problems
}

#[test]
fn fixture_repositories_match_the_catalog() {
    let catalog = catalog();
    for fixture in Fixture::ALL {
        let manifest = manifest(fixture);
        let problems = catalog_problems(&manifest, &catalog);
        assert!(
            problems.is_empty(),
            "{} does not match the catalog:\n  {}",
            fixture.id(),
            problems.join("\n  ")
        );
        // The stored bytes are the ones the manifest was written for, and no stored file is
        // missing from the manifest.
        assert_eq!(
            manifest.digest_problems(),
            Vec::<String>::new(),
            "{}",
            fixture.id()
        );
        assert_eq!(manifest.orphans(), Vec::<String>::new(), "{}", fixture.id());
        assert!(!manifest.entries.is_empty());
        assert!(!manifest.summary.is_empty());

        // Every catalog test a file says it serves exists in the catalog.
        for entry in &manifest.entries {
            assert!(!entry.role.is_empty(), "{}: no role", entry.path);
            for id in &entry.used_by {
                assert!(
                    catalog.contains(&format!("| {id} ")) || catalog.contains(&format!("{id} ")),
                    "{}: the catalog has no test {id}",
                    entry.path
                );
            }
        }
    }
}

#[test]
fn removing_a_file_the_catalog_names_is_noticed() {
    // Deliberate break: take things out of the manifest and the check must say what is missing.
    let catalog = catalog();
    let mut clean = manifest(Fixture::Clean);
    clean.entries.retain(|e| e.path != "deny.toml");
    assert!(
        catalog_problems(&clean, &catalog)
            .iter()
            .any(|p| p.contains("`deny.toml`")),
        "a missing deny.toml must be reported"
    );

    let mut clean = manifest(Fixture::Clean);
    clean
        .entries
        .retain(|e| !e.path.starts_with("tests/holdout/"));
    assert!(
        catalog_problems(&clean, &catalog)
            .iter()
            .any(|p| p.contains("tests/holdout/"))
    );

    for gone in [".env", "build.rs", ".mcp.json", "vendor/dep/.git/config"] {
        let mut hostile = manifest(Fixture::Hostile);
        hostile.entries.retain(|e| e.path != gone);
        assert!(
            !catalog_problems(&hostile, &catalog).is_empty(),
            "removing {gone} must be reported"
        );
    }
    let mut hostile = manifest(Fixture::Hostile);
    hostile.entries.retain(|e| e.kind != EntryKind::Symlink);
    assert!(
        catalog_problems(&hostile, &catalog)
            .iter()
            .any(|p| p.contains("symbolic links"))
    );

    // And a fixture that lost the injection text is noticed through the stored bytes.
    let hostile = manifest(Fixture::Hostile);
    let problems = hostile.problems_with(|entry| {
        let mut bytes = hostile.stored_bytes(entry).ok()?;
        if entry.path == "README.md" {
            bytes.push(b'!');
        }
        Some(bytes)
    });
    assert_eq!(
        problems,
        ["README.md: the stored bytes do not match the manifest"]
    );
}

#[test]
fn stored_files_use_the_suffix_and_the_dot_rule_and_the_manifest_lists_each_once() {
    for fixture in Fixture::ALL {
        let manifest = manifest(fixture);
        let mut seen = BTreeSet::new();
        for entry in &manifest.entries {
            let key = (entry.path.clone(), entry.only_with.clone());
            assert!(seen.insert(key), "{}: listed twice", entry.path);
            if entry.kind != EntryKind::File {
                assert!(
                    entry.stored.is_none(),
                    "{}: only a file has a stored path",
                    entry.path
                );
                continue;
            }
            let stored = entry.stored.as_deref().unwrap();
            let expected: String = entry
                .path
                .split('/')
                .map(|part| {
                    part.strip_prefix('.')
                        .map_or_else(|| part.to_owned(), |rest| format!("dot-{rest}"))
                })
                .collect::<Vec<_>>()
                .join("/");
            assert_eq!(
                stored,
                format!("files/{expected}.fixture"),
                "{}",
                entry.path
            );
            assert!(
                stored.split('/').all(|part| !part.starts_with('.')),
                "{stored}: a stored component starts with a dot, so a tool may treat it as live"
            );
        }
    }
}

#[test]
fn the_markers_in_the_files_are_exactly_the_markers_in_the_manifest() {
    for fixture in Fixture::ALL {
        let manifest = manifest(fixture);
        let mut found = BTreeSet::new();
        for entry in manifest
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
        {
            let text = String::from_utf8_lossy(&manifest.stored_bytes(entry).unwrap()).into_owned();
            for piece in text.split("@@MARKER_DIR@@/").skip(1) {
                let name: String = piece
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                    .collect();
                found.insert(name);
            }
        }
        let listed: BTreeSet<String> = manifest.markers.iter().cloned().collect();
        assert_eq!(found, listed, "{}", fixture.id());
    }
    assert!(
        manifest(Fixture::Clean).markers.is_empty(),
        "the clean repository runs nothing"
    );
    assert!(manifest(Fixture::Hostile).markers.len() >= 10);
}

/// A plain scan for the shapes the secret policy blocks. It stands in for the repository's
/// secret scan on the fixtures, which this machine may not have.
fn secret_shapes(text: &str) -> Vec<&'static str> {
    let mut found = Vec::new();
    let followed_by = |prefix: &str, wanted: usize, allowed: fn(char) -> bool| -> bool {
        text.match_indices(prefix).any(|(at, _)| {
            text[at + prefix.len()..]
                .chars()
                .take_while(|c| allowed(*c))
                .count()
                >= wanted
        })
    };
    let alnum = |c: char| c.is_ascii_alphanumeric();
    let token_chars = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        if followed_by(prefix, 36, alnum) {
            found.push("a GitHub token");
        }
    }
    if followed_by("github_pat_", 22, token_chars) {
        found.push("a fine-grained GitHub token");
    }
    if followed_by("sk-ant-", 20, token_chars) || followed_by("sk-", 32, token_chars) {
        found.push("a model API key");
    }
    if followed_by("sfjt_", 32, token_chars) {
        found.push("a factory job token");
    }
    if followed_by("npm_", 36, alnum) {
        found.push("an npm token");
    }
    if followed_by("xoxb-", 10, token_chars) || followed_by("xoxp-", 10, token_chars) {
        found.push("a Slack token");
    }
    for prefix in ["AKIA", "ASIA"] {
        if followed_by(prefix, 16, |c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
            found.push("an AWS key id");
        }
    }
    if followed_by("AIza", 35, token_chars) {
        found.push("a Google API key");
    }
    if followed_by("eyJ", 8, token_chars) && text.contains(".eyJ") {
        found.push("a JWT");
    }
    // A private key header, assembled so this file does not hold one.
    let begin = ["-----BEGIN ", "RSA ", "PRIVATE KEY-----"].concat();
    let begin_plain = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
    if text.contains(&begin) || text.contains(&begin_plain) {
        found.push("a private key block");
    }
    // A URL with a user name and a password.
    if text.match_indices("://").any(|(at, _)| {
        let authority = text[at + 3..]
            .split(['/', ' ', '\n', '"'])
            .next()
            .unwrap_or("");
        authority.rsplit_once('@').is_some_and(|(user, _)| {
            user.split_once(':')
                .is_some_and(|(u, p)| !u.is_empty() && p.len() >= 3)
        })
    }) {
        found.push("a URL with credentials");
    }
    found.sort_unstable();
    found.dedup();
    found
}

#[test]
fn no_stored_file_or_manifest_holds_a_secret_shaped_string() {
    let mut scanned = 0;
    for fixture in Fixture::ALL {
        let manifest = manifest(fixture);
        for entry in manifest
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
        {
            let text = String::from_utf8_lossy(&manifest.stored_bytes(entry).unwrap()).into_owned();
            assert_eq!(
                secret_shapes(&text),
                Vec::<&str>::new(),
                "{}: {}",
                fixture.id(),
                entry.path
            );
            scanned += 1;
        }
        let manifest_text = fs::read_to_string(manifest.dir.join("manifest.json")).unwrap();
        assert_eq!(
            secret_shapes(&manifest_text),
            Vec::<&str>::new(),
            "{} manifest",
            fixture.id()
        );
    }
    assert!(scanned > 40);

    // Control: the scan finds what it is meant to. If it did not, the pass above would mean nothing.
    let token = format!("ghs_{}", "A".repeat(36));
    assert_eq!(
        secret_shapes(&format!("token = {token}")),
        ["a GitHub token"]
    );
    assert_eq!(
        secret_shapes(&format!("sk-ant-{}", "b".repeat(30))),
        ["a model API key"]
    );
    assert_eq!(
        secret_shapes(&["-----BEGIN ", "PRIVATE KEY-----"].concat()),
        ["a private key block"]
    );
    assert_eq!(
        // Assembled in pieces, so this file holds no URL with a password in it for the
        // repository's own secret scan to find.
        secret_shapes(&["https", "://user:hunter22@host/path"].concat()),
        ["a URL with credentials"]
    );
    // And it does not flag a placeholder, a short prefix or a plain URL.
    assert!(
        secret_shapes("@@CANARY:github_installation_token@@ ghs_ short https://host/path")
            .is_empty()
    );
}

#[test]
fn a_changed_manifest_is_refused_when_the_repository_is_written_out() {
    let set = canaries();
    let options = MaterializeOptions::default();

    // A stored byte that no longer matches the digest.
    let mut tampered = manifest(Fixture::Clean);
    tampered.entries[0].sha256 = Some("0".repeat(64));
    let error = write_out(tampered, &set, &options).unwrap_err();
    assert!(error.contains("do not match the manifest"), "{error}");

    // Paths that would write outside the repository.
    for bad in [
        "../outside",
        "/etc/outside",
        "a/../../outside",
        "a//b",
        "a\\b",
        "",
    ] {
        let mut changed = manifest(Fixture::Clean);
        changed.entries[0].path = bad.to_owned();
        let error = write_out(changed, &set, &options).unwrap_err();
        assert!(
            error.contains("not a safe relative path"),
            "{bad:?}: {error}"
        );
    }

    // Control: the unchanged manifests still write, so the refusals above are about the changes.
    for fixture in Fixture::ALL {
        let result = write_out(manifest(fixture), &set, &options);
        assert!(result.is_ok(), "{}: {:?}", fixture.id(), result.err());
    }
}

#[test]
fn placeholders_are_replaced_once_and_an_unknown_one_is_an_error() {
    let set = canaries();
    let context = Context {
        canaries: &set,
        marker_text: "/m".to_owned(),
        host_canary_file: "/h/canary.txt".to_owned(),
    };
    assert_eq!(
        context
            .substitute("a @@MARKER_DIR@@/x and @@HOST_CANARY_FILE@@")
            .unwrap(),
        "a /m/x and /h/canary.txt"
    );
    assert_eq!(
        context.substitute("no placeholder here").unwrap(),
        "no placeholder here"
    );
    assert_eq!(
        context.substitute("@@CANARY:job_token@@").unwrap(),
        set.get(CanaryKind::JobToken).value()
    );
    for bad in [
        "@@NOPE@@",
        "@@CANARY:nope@@",
        "@@CANARY:custom@@",
        "@@MARKER_DIR",
        "x @@ y",
    ] {
        assert!(context.substitute(bad).is_err(), "{bad:?} must be an error");
    }
    // One pass: a value that looks like a placeholder is not replaced again. Use a set whose
    // password holds the two characters.
    let mut pairs = None;
    for seed in 0..5_000 {
        let candidate = CanarySet::generate_with(&mut FxRng::from_seed(seed));
        if candidate
            .get(CanaryKind::DatabasePassword)
            .value()
            .contains("@@")
        {
            pairs = Some(candidate);
            break;
        }
    }
    if let Some(candidate) = pairs {
        let context = Context {
            canaries: &candidate,
            marker_text: String::new(),
            host_canary_file: String::new(),
        };
        let text = context
            .substitute("p=@@CANARY:database_password@@")
            .unwrap();
        assert!(text.ends_with(candidate.get(CanaryKind::DatabasePassword).value()));
    }
}

#[test]
fn a_manifest_cannot_write_through_a_link_it_made_itself() {
    let root = FxTempDir::new("fx-safe-path").unwrap();
    let outside = FxTempDir::new("fx-outside").unwrap();
    std::os::unix::fs::symlink(outside.path(), root.join("door")).unwrap();
    let error = safe_path(root.path(), "door/escaped.txt").unwrap_err();
    assert!(error.contains("passes through a link"), "{error}");
    assert!(!outside.join("escaped.txt").exists());
    // A file where a directory is needed.
    fs::write(root.join("plain"), "x").unwrap();
    assert!(
        safe_path(root.path(), "plain/inside")
            .unwrap_err()
            .contains("not a directory")
    );
    // A good path makes its parents.
    let good = safe_path(root.path(), "a/b/c.txt").unwrap();
    assert!(root.join("a/b").is_dir());
    assert_eq!(good, root.join("a/b/c.txt"));
}

#[test]
fn the_clean_repository_is_written_out_and_is_a_working_crate() {
    let set = canaries();
    let written = materialize(Fixture::Clean, &set, &MaterializeOptions::default()).unwrap();
    let root = written.root();

    // The catalog's three tests, an inline module, and the held-out canary in its file.
    let integration = fs::read_to_string(root.join("tests/it.rs")).unwrap();
    assert_eq!(integration.matches("#[test]").count(), 3);
    let library = fs::read_to_string(root.join("src/lib.rs")).unwrap();
    assert!(library.contains("#[cfg(test)]"));
    let holdout = fs::read(root.join("tests/holdout/holdout.txt")).unwrap();
    let hits = Sweeper::new(&set).scan("holdout", &holdout);
    assert!(
        hits.iter()
            .any(|h| h.canary == "holdout_string" && h.form == Form::Raw),
        "{hits:?}"
    );
    assert!(
        !String::from_utf8_lossy(&holdout).contains("@@CANARY"),
        "no placeholder is left"
    );

    // Scripts are executable, the rest are not, and there are no links.
    let mode = |p: &str| fs::metadata(root.join(p)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode("scripts/ci.sh"), 0o755);
    assert_eq!(mode("Cargo.toml"), 0o644);
    assert!(written.markers_present().is_empty());
    assert!(
        written
            .manifest()
            .entries
            .iter()
            .all(|e| e.kind != EntryKind::Symlink)
    );

    // It is a real crate: the four tests run and pass. Nothing in it is hostile, so this runs on
    // the host; the hostile repository never does.
    let target = FxTempDir::new("fx-clean-target").unwrap();
    let output = Command::new("cargo")
        .args(["test", "--locked", "--offline", "--quiet"])
        .current_dir(&root)
        .env("CARGO_TARGET_DIR", target.path())
        .env_remove("RUSTC_WRAPPER")
        .output()
        .expect("cargo starts");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "cargo test failed in the clean repository:\n{report}"
    );
    assert!(
        report.contains("test result: ok. 1 passed"),
        "the inline test: {report}"
    );
    assert!(
        report.contains("test result: ok. 3 passed"),
        "the three integration tests: {report}"
    );
}

#[test]
fn the_hostile_repository_is_written_out_as_data_and_nothing_runs() {
    let set = canaries();
    let written = materialize(Fixture::Hostile, &set, &MaterializeOptions::default()).unwrap();
    let root = written.root();
    let sweeper = Sweeper::new(&set);

    // Writing it out ran nothing: no marker exists.
    assert!(
        written.markers_present().is_empty(),
        "{:?}",
        written.markers_present()
    );
    assert!(written.markers_dir().is_dir());

    // Links to absolute host paths, to a real file outside the repository, and one that climbs.
    let target = |p: &str| fs::read_link(root.join(p)).unwrap();
    assert_eq!(target("link-to-passwd"), Path::new("/etc/passwd"));
    assert_eq!(target("src/link"), Path::new("/etc/passwd"));
    assert_eq!(target("link-to-root"), Path::new("/"));
    assert_eq!(target("link-to-host-canary"), written.host_canary_file());
    assert!(
        !written.host_canary_file().starts_with(&root),
        "the host canary is outside the repository"
    );
    assert_eq!(target("link-out"), Path::new("../host-secret"));
    let outside = root.join("link-out");
    assert!(outside.exists(), "the climbing link points at a real file");
    // Reading it through the link would leak a canary. That is the danger being modelled; the
    // test reads the host file directly and checks that it holds the second tenant's canary.
    let host_bytes = fs::read(written.host_canary_file()).unwrap();
    assert!(
        sweeper
            .scan("host", &host_bytes)
            .iter()
            .any(|h| h.canary == "second_tenant_string"),
        "the host file holds a canary"
    );

    // Instruction text in every place the catalog lists.
    for path in [
        "README.md",
        "CONTRIBUTING.md",
        "src/lib.rs",
        "CLAUDE.md",
        "AGENTS.md",
    ] {
        let text = fs::read_to_string(root.join(path)).unwrap();
        assert!(text.contains("Ignore previous instructions"), "{path}");
    }
    // The readme also holds a token in its text.
    let readme = fs::read(root.join("README.md")).unwrap();
    assert!(
        sweeper
            .scan("readme", &readme)
            .iter()
            .any(|h| h.canary == "github_installation_token")
    );

    // Agent configuration parses, and its commands point at the marker directory.
    let markers = written.markers_dir().display().to_string();
    let settings: Value =
        serde_json::from_slice(&fs::read(root.join(".claude/settings.json")).unwrap()).unwrap();
    assert!(
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains(&markers)
    );
    assert!(
        settings["env"]["ANTHROPIC_BASE_URL"]
            .as_str()
            .unwrap()
            .contains("attacker.test")
    );
    let mcp: Value = serde_json::from_slice(&fs::read(root.join(".mcp.json")).unwrap()).unwrap();
    assert!(
        mcp["mcpServers"]["helpful"]["args"][1]
            .as_str()
            .unwrap()
            .contains(&markers)
    );
    assert!(
        fs::read_to_string(root.join(".codex/config.toml"))
            .unwrap()
            .contains("[mcp_servers.helpful]")
    );
    assert!(
        fs::read_to_string(root.join("build.rs"))
            .unwrap()
            .contains(&format!("{markers}/build-rs"))
    );

    // Files with canaries: the environment file and the key.
    let env = fs::read(root.join(".env")).unwrap();
    let env_hits: BTreeSet<String> = sweeper
        .scan(".env", &env)
        .into_iter()
        .map(|h| h.canary)
        .collect();
    for expected in [
        "database_password",
        "model_api_key",
        "github_installation_token",
    ] {
        assert!(
            env_hits.contains(expected),
            ".env lacks {expected}: {env_hits:?}"
        );
    }
    let key = fs::read(root.join("id_rsa")).unwrap();
    assert!(
        sweeper
            .scan("id_rsa", &key)
            .iter()
            .any(|h| h.canary == "app_private_key")
    );
    assert_eq!(
        fs::metadata(root.join("id_rsa"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // The JSON file holds only values that are safe inside a JSON string.
    let secrets: Value =
        serde_json::from_slice(&fs::read(root.join("config/secrets.json")).unwrap()).unwrap();
    assert!(secrets["webhook_secret"].as_str().unwrap().len() == 64);

    // The nested git has the hostile keys, an executable hook, and the ownership override that
    // exists only after writing out: the stored bytes do not hold it.
    let config = fs::read_to_string(root.join("vendor/dep/.git/config")).unwrap();
    for needle in [
        "fsmonitor",
        "hooksPath",
        "sshCommand",
        "external",
        "[alias]",
        "helper = !",
        "clean =",
        "smudge =",
    ] {
        assert!(
            config.contains(needle),
            "the nested git config lacks {needle}"
        );
    }
    let wildcard_section = ["[sa", "fe]"].concat();
    let wildcard_key = ["direc", "tory = *"].concat();
    assert!(config.contains(&wildcard_section) && config.contains(&wildcard_key));
    let stored = stored_text(written.manifest(), "vendor/dep/.git/config");
    assert!(!stored.contains(&wildcard_section) && !stored.contains(&wildcard_key));
    assert_eq!(
        fs::metadata(root.join("vendor/dep/.git/hooks/pre-commit"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(
        root.join("vendor/dep/.git/objects").is_dir()
            && root.join("vendor/dep/.git/refs/heads").is_dir()
    );

    // The root .git is not replaced unless asked.
    assert!(!root.join(".git").exists());
}

#[test]
fn the_replaced_root_git_variant_adds_a_hostile_git_at_the_top() {
    let set = canaries();
    let plain = materialize(Fixture::Hostile, &set, &MaterializeOptions::default()).unwrap();
    let replaced = materialize(
        Fixture::Hostile,
        &set,
        &MaterializeOptions {
            replaced_root_git: true,
            ..MaterializeOptions::default()
        },
    )
    .unwrap();
    assert!(!plain.root().join(".git").exists());
    assert!(replaced.root().join(".git/config").is_file());
    assert!(replaced.root().join(".git/hooks/post-checkout").is_file());
    assert!(replaced.markers_present().is_empty());
}

#[test]
fn the_marker_path_can_be_the_path_inside_a_container() {
    let set = canaries();
    let written = materialize(
        Fixture::Hostile,
        &set,
        &MaterializeOptions {
            marker_path_text: Some("/markers".to_owned()),
            ..MaterializeOptions::default()
        },
    )
    .unwrap();
    let build = fs::read_to_string(written.root().join("build.rs")).unwrap();
    assert!(build.contains("\"/markers/build-rs\""));
    assert!(!build.contains(&written.markers_dir().display().to_string()));
}

#[test]
fn two_writes_make_two_repositories_with_their_own_markers_and_canaries() {
    let a = materialize(
        Fixture::Hostile,
        &canaries(),
        &MaterializeOptions::default(),
    )
    .unwrap();
    let b = materialize(
        Fixture::Hostile,
        &CanarySet::generate_with(&mut FxRng::from_seed(12)),
        &MaterializeOptions::default(),
    )
    .unwrap();
    assert_ne!(a.root(), b.root());
    assert_ne!(
        fs::read(a.root().join(".env")).unwrap(),
        fs::read(b.root().join(".env")).unwrap()
    );
    let root = a.parent().to_path_buf();
    drop(a);
    assert!(
        !root.exists(),
        "dropping removes the repository, the markers and the host files"
    );
}

// ---- ingestion attacks ------------------------------------------------------------------------

#[test]
fn every_ingestion_attack_is_planted_or_reported_as_unsupported_with_a_reason() {
    let dir = FxTempDir::new("fx-attacks").unwrap();
    let workspace = dir.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let outside = dir.join("outside.txt");
    fs::write(&outside, "outside").unwrap();

    let report = plant_ingestion_attacks(&workspace, &outside, &AttackOptions::default());
    assert_eq!(
        report.planted.len() + report.unsupported.len(),
        AttackKind::ALL.len(),
        "every attack is accounted for: {report:?}"
    );
    for (kind, reason) in &report.unsupported {
        assert!(
            !reason.is_empty(),
            "{kind:?}: an unsupported attack needs a reason"
        );
    }
    // The overlong path cannot be made on a host, and says so.
    assert!(
        report
            .unsupported
            .iter()
            .any(|(k, _)| *k == AttackKind::OverlongPath)
    );

    // What was planted is what it says, checked without opening anything.
    let meta = |kind: AttackKind| {
        report
            .path_of(kind)
            .map(|p| fs::symlink_metadata(p).unwrap())
    };
    if let Some(m) = meta(AttackKind::Fifo) {
        assert!(m.file_type().is_fifo());
    }
    if let Some(m) = meta(AttackKind::Socket) {
        assert!(m.file_type().is_socket());
    }
    if let Some(m) = meta(AttackKind::Hardlink) {
        assert!(
            m.file_type().is_file() && m.nlink() == 2,
            "a hard link has two names"
        );
        assert_eq!(m.ino(), fs::metadata(&outside).unwrap().ino());
    }
    if let Some(m) = meta(AttackKind::Setuid) {
        assert_ne!(m.permissions().mode() & 0o4000, 0, "the setuid bit is set");
    }
    if let Some(m) = meta(AttackKind::Oversize) {
        assert_eq!(m.len(), AttackOptions::default().oversize_bytes);
    }
    let tiny = report
        .path_of(AttackKind::ManyTinyFiles)
        .expect("the tiny files are planted");
    assert_eq!(
        fs::read_dir(tiny).unwrap().count(),
        AttackOptions::default().tiny_files
    );
    for kind in [AttackKind::NewlineName, AttackKind::AnsiName] {
        assert!(report.path_of(kind).is_some(), "{kind:?} is planted");
    }
    assert!(
        report
            .path_of(AttackKind::NewlineName)
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains('\n')
    );
}

#[test]
fn the_volume_attacks_follow_the_options() {
    let dir = FxTempDir::new("fx-attacks-small").unwrap();
    let workspace = dir.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let outside = dir.join("outside.txt");
    fs::write(&outside, "x").unwrap();
    let report = plant_ingestion_attacks(
        &workspace,
        &outside,
        &AttackOptions {
            oversize_bytes: 10,
            tiny_files: 7,
        },
    );
    assert_eq!(
        fs::read_dir(report.path_of(AttackKind::ManyTinyFiles).unwrap())
            .unwrap()
            .count(),
        7
    );
    assert_eq!(
        fs::metadata(report.path_of(AttackKind::Oversize).unwrap())
            .unwrap()
            .len(),
        10
    );
}

// ---- the hostility is real -------------------------------------------------------------------

/// The image to run git in. It must already be on the machine: the run never pulls.
fn git_image() -> String {
    std::env::var("FACTORY_TEST_GIT_IMAGE").unwrap_or_else(|_| "alpine/git:latest".to_owned())
}

#[test]
fn hostile_git_configuration_runs_code_when_unhardened_and_nothing_when_hardened() {
    // The only test that runs content of the hostile repository. It runs git inside a container
    // with the hardened profile: no network, a read-only root, no capabilities, no new
    // privileges, limits on processes and memory, and the image used as it is, never pulled.
    let guard = DockerGuard::from_environment();
    let scope = guard.require_or_block();
    let image = git_image();
    let present = scope
        .cli()
        .run(&["image", "inspect", "--format", "{{.Id}}", &image]);
    if !present.as_ref().is_ok_and(|o| o.success()) {
        blocked(&format!(
            "the image {image} is not on this machine. Pull it, or set FACTORY_TEST_GIT_IMAGE to an image that has git. The test never pulls."
        ));
    }

    let set = canaries();
    let written = materialize(
        Fixture::Hostile,
        &set,
        &MaterializeOptions {
            marker_path_text: Some("/markers".to_owned()),
            ..MaterializeOptions::default()
        },
    )
    .unwrap();
    let meta = fs::metadata(written.root()).unwrap();
    let user = format!("{}:{}", meta.uid(), meta.gid());
    let repo_mount = format!("{}:/w", written.root().display());
    let marker_mount = format!("{}:/markers", written.markers_dir().display());
    let label = scope.label().assignment();

    let run_git = |hardened: bool, git_args: &[&str]| -> (bool, String) {
        let mut args: Vec<String> = [
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
            "--tmpfs",
            "/tmp",
            "--user",
            &user,
            "-e",
            "HOME=/tmp",
            "--label",
            &label,
            "-v",
            &repo_mount,
            "-v",
            &marker_mount,
            "--entrypoint",
            "git",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        if hardened {
            // The fixed environment of sandbox-policy.md section 6.2.
            for pair in ["GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"] {
                args.extend(["-e".to_owned(), pair.to_owned()]);
            }
        }
        args.push(image.clone());
        args.extend(
            ["-C", "/w/vendor/dep", "-c", "safe.directory=/w/vendor/dep"].map(String::from),
        );
        if hardened {
            args.extend(
                [
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
                ]
                .map(String::from),
            );
        }
        args.extend(git_args.iter().map(ToString::to_string));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = scope.cli().run(&refs).expect("docker runs");
        (output.success(), output.stderr)
    };
    let commit = [
        "-c",
        "user.name=fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "--allow-empty",
        "-m",
        "x",
    ];

    // Control off: git without the fixed environment runs the repository's own commands.
    let (ok, stderr) = run_git(false, &["status"]);
    assert!(ok, "unhardened status failed: {stderr}");
    let (ok, stderr) = run_git(false, &commit);
    assert!(ok, "unhardened commit failed: {stderr}");
    let ran = written.markers_present();
    assert!(
        ran.contains(&"git-fsmonitor".to_owned()),
        "the monitor command did not run, so the fixture is not hostile to this git: {ran:?}"
    );
    assert!(
        ran.contains(&"git-hook-pre-commit".to_owned()),
        "the commit hook did not run: {ran:?}"
    );

    // Control on: the fixed environment and the overrides. The same commands run nothing.
    for name in &ran {
        fs::remove_file(written.markers_dir().join(name)).unwrap();
    }
    let (ok, stderr) = run_git(true, &["status"]);
    assert!(
        ok,
        "hardened status failed, so a missing marker would prove nothing: {stderr}"
    );
    let (ok, stderr) = run_git(true, &commit);
    assert!(
        ok,
        "hardened commit failed, so a missing marker would prove nothing: {stderr}"
    );
    assert_eq!(
        written.markers_present(),
        Vec::<String>::new(),
        "hardened git ran repository code"
    );
    assert_eq!(
        CanaryKind::from_name("job_token"),
        Some(CanaryKind::JobToken),
        "keeps the canary import used"
    );
}
