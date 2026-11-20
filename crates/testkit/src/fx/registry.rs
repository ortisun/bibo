//! FX-REG: a fake package registry for crates and npm packages.
//!
//! The supply-chain tests (NT-SUP-01 to NT-SUP-03) need a registry they can shape: a package
//! first published three days ago, one with an install script, a name one letter away from a
//! popular one, one that shares its name with an internal package. This file serves those over
//! HTTP, in the formats the real clients read, with real tarballs so a package manager can
//! install them in a sandbox:
//!
//! * **npm**: `GET /<name>` returns the packument (`dist-tags`, `versions` with `scripts` and
//!   `dist.tarball` and `dist.shasum`, and `time.created`); `GET /<name>/-/<file>.tgz` returns the
//!   tarball. Scoped names work as `/@scope%2Fname` and `/@scope/name`.
//! * **crates**: the sparse index (`/config.json` and the index files, one JSON line per version
//!   with its SHA-256 checksum), the crates.io style metadata at `/api/v1/crates/<name>`, and the
//!   `.crate` download at `/api/v1/crates/<name>/<version>/download`.
//!
//! # Install scripts are data
//!
//! A package's script (`postinstall` for npm, a `build.rs` for a crate) is a string in the
//! package. The registry stores it, serves it inside the tarball and in the metadata, and never
//! runs it. Running one is for the sandbox tests, inside a container with no network.
//!
//! # What the tests ask of it
//!
//! * [`PackageSpec`] sets the first-publish time, the versions, the script and the yanked flag.
//! * [`FakeRegistry::download_count`] says whether a package was ever fetched, so a test can
//!   assert that nothing was downloaded before a human decided.
//! * [`FakeRegistry::lookalikes`] and [`typosquats_of`] give the name-similarity side: the first
//!   finds registered names within one edit of a name, the second makes candidate misspellings.
//!
//! Every response carries the fake labels from the HTTP server, and the npm packument has a
//! `_factory_fidelity` key.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::{Value, json};

use super::archive::{Entry, tar_gz};
use super::digest::{sha1, sha256};
use super::encoding::hex_encode;
use super::http::{HttpRequest, HttpResponse, HttpServer, percent_decode};
use super::timeutil::format_rfc3339;

/// Which package manager a package is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    /// A Rust crate.
    Crates,
    /// An npm package.
    Npm,
}

/// One version of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSpec {
    /// The version, such as `1.2.3`.
    pub version: String,
    /// The install script: `postinstall` text for npm, the body of `build.rs` for a crate.
    pub script: Option<String>,
    /// For a crate: yanked. For npm: deprecated.
    pub yanked: bool,
    /// Seconds since the epoch when this version was published.
    pub published: i64,
}

/// A package to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSpec {
    /// The package manager.
    pub ecosystem: Ecosystem,
    /// The name.
    pub name: String,
    /// Seconds since the epoch when the package first appeared. Controls the age rule.
    pub first_published: i64,
    /// The versions, oldest first.
    pub versions: Vec<VersionSpec>,
    /// The download count the metadata reports (a popularity signal), not the fake's own count.
    pub reported_downloads: u64,
}

impl PackageSpec {
    /// A package with one version, `1.0.0`, and no script.
    #[must_use]
    pub fn new(ecosystem: Ecosystem, name: &str, first_published: i64) -> Self {
        Self {
            ecosystem,
            name: name.to_owned(),
            first_published,
            versions: vec![VersionSpec {
                version: "1.0.0".to_owned(),
                script: None,
                yanked: false,
                published: first_published,
            }],
            reported_downloads: 0,
        }
    }

    /// A crate, first published at this time.
    #[must_use]
    pub fn crate_named(name: &str, first_published: i64) -> Self {
        Self::new(Ecosystem::Crates, name, first_published)
    }

    /// An npm package, first published at this time.
    #[must_use]
    pub fn npm_named(name: &str, first_published: i64) -> Self {
        Self::new(Ecosystem::Npm, name, first_published)
    }

    /// Adds a version, published one day after the previous one.
    #[must_use]
    pub fn with_version(mut self, version: &str) -> Self {
        let published = self
            .versions
            .last()
            .map_or(self.first_published, |v| v.published)
            + 86_400;
        self.versions.push(VersionSpec {
            version: version.to_owned(),
            script: None,
            yanked: false,
            published,
        });
        self
    }

    /// Gives the newest version an install script.
    ///
    /// # Panics
    /// Panics when the package has no version, which `new` never allows.
    #[must_use]
    pub fn with_install_script(mut self, script: &str) -> Self {
        self.versions
            .last_mut()
            .expect("a package has a version")
            .script = Some(script.to_owned());
        self
    }

    /// Marks a version yanked (crates) or deprecated (npm).
    #[must_use]
    pub fn yanked(mut self, version: &str) -> Self {
        for v in &mut self.versions {
            if v.version == version {
                v.yanked = true;
            }
        }
        self
    }

    /// Sets the popularity signal the metadata reports.
    #[must_use]
    pub fn with_reported_downloads(mut self, downloads: u64) -> Self {
        self.reported_downloads = downloads;
        self
    }

    /// The newest version that is not yanked, if any.
    #[must_use]
    pub fn latest(&self) -> Option<&VersionSpec> {
        self.versions.iter().rev().find(|v| !v.yanked)
    }

    fn version(&self, version: &str) -> Option<&VersionSpec> {
        self.versions.iter().find(|v| v.version == version)
    }

    /// The tarball of one version: `package/…` for npm, `<name>-<version>/…` for a crate.
    fn tarball(&self, version: &VersionSpec) -> Vec<u8> {
        match self.ecosystem {
            Ecosystem::Npm => {
                let mut manifest = json!({
                    "name": self.name,
                    "version": version.version,
                    "description": "A fake package from factory-testkit. FAKE.",
                    "main": "index.js",
                });
                if let Some(script) = &version.script {
                    manifest["scripts"] = json!({"postinstall": script});
                }
                tar_gz(&[
                    Entry::file(
                        "package/package.json",
                        serde_json::to_string_pretty(&manifest)
                            .expect("JSON writes")
                            .as_bytes(),
                    ),
                    Entry::file("package/index.js", b"module.exports = 'FAKE';\n"),
                ])
            }
            Ecosystem::Crates => {
                let root = format!("{}-{}", self.name, version.version);
                let mut manifest = format!(
                    "[package]\nname = \"{}\"\nversion = \"{}\"\nedition = \"2021\"\ndescription = \"A fake crate from factory-testkit. FAKE.\"\n",
                    self.name, version.version
                );
                let mut entries = vec![Entry::file(
                    &format!("{root}/src/lib.rs"),
                    b"pub fn fake() {}\n",
                )];
                if let Some(script) = &version.script {
                    manifest.push_str("build = \"build.rs\"\n");
                    entries.push(Entry::file(&format!("{root}/build.rs"), script.as_bytes()));
                }
                entries.insert(
                    0,
                    Entry::file(&format!("{root}/Cargo.toml"), manifest.as_bytes()),
                );
                tar_gz(&entries)
            }
        }
    }
}

/// One request the registry received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRequest {
    /// 1 for the first request.
    pub seq: u64,
    /// The method.
    pub method: String,
    /// The path.
    pub path: String,
    /// What kind of request it was: `packument`, `tarball`, `index`, `crate_metadata`,
    /// `crate_download`, `config` or `unrouted`.
    pub kind: &'static str,
    /// The package the request was about, if any.
    pub package: Option<String>,
    /// The version, for a download.
    pub version: Option<String>,
    /// The status answered.
    pub status: u16,
}

#[derive(Debug, Default)]
struct RegistryState {
    packages: BTreeMap<(Ecosystem, String), PackageSpec>,
    requests: Vec<RegistryRequest>,
    downloads: BTreeMap<(Ecosystem, String, String), u32>,
}

/// A fake registry. Cloning gives another handle to the same registry.
#[derive(Debug, Clone, Default)]
pub struct FakeRegistry {
    state: Arc<Mutex<RegistryState>>,
}

impl FakeRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .expect("the registry lock is never poisoned")
    }

    /// Adds or replaces a package. Crate names are kept in lower case, as the index does.
    pub fn publish(&self, mut spec: PackageSpec) {
        if spec.ecosystem == Ecosystem::Crates {
            spec.name = spec.name.to_ascii_lowercase();
        }
        self.lock()
            .packages
            .insert((spec.ecosystem, spec.name.clone()), spec);
    }

    /// The package with this name.
    #[must_use]
    pub fn package(&self, ecosystem: Ecosystem, name: &str) -> Option<PackageSpec> {
        self.lock()
            .packages
            .get(&(ecosystem, normalise(ecosystem, name)))
            .cloned()
    }

    /// The names of every package of an ecosystem.
    #[must_use]
    pub fn names(&self, ecosystem: Ecosystem) -> Vec<String> {
        self.lock()
            .packages
            .keys()
            .filter(|(e, _)| *e == ecosystem)
            .map(|(_, n)| n.clone())
            .collect()
    }

    /// The registered names that are one edit away from `name` (a letter added, dropped or
    /// changed, or two neighbours swapped), but are not `name`.
    #[must_use]
    pub fn lookalikes(&self, ecosystem: Ecosystem, name: &str) -> Vec<String> {
        let name = normalise(ecosystem, name);
        self.names(ecosystem)
            .into_iter()
            .filter(|candidate| within_one_edit(candidate, &name))
            .collect()
    }

    /// How many times a version of this package was downloaded. Metadata requests do not count.
    #[must_use]
    pub fn download_count(&self, ecosystem: Ecosystem, name: &str) -> u32 {
        let name = normalise(ecosystem, name);
        self.lock()
            .downloads
            .iter()
            .filter(|((e, n, _), _)| *e == ecosystem && *n == name)
            .map(|(_, count)| *count)
            .sum()
    }

    /// How many downloads of any package were made.
    #[must_use]
    pub fn total_downloads(&self) -> u32 {
        self.lock().downloads.values().sum()
    }

    /// Every request, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<RegistryRequest> {
        self.lock().requests.clone()
    }

    /// The registry as JSON, with the fidelity label.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let state = self.lock();
        json!({
            "fidelity": "fake",
            "server": "factory-testkit-fake (registry)",
            "packages": state.packages.keys().map(|(e, n)| format!("{e:?}:{n}")).collect::<Vec<_>>(),
            "requests": state.requests.iter().map(|r| json!({
                "fidelity": "fake", "seq": r.seq, "method": r.method, "path": r.path,
                "kind": r.kind, "package": r.package, "version": r.version, "status": r.status,
            })).collect::<Vec<_>>(),
            "downloads": state.downloads.values().sum::<u32>(),
        })
    }

    /// Starts an HTTP server on `127.0.0.1` that answers with this registry.
    ///
    /// # Errors
    /// Returns the I/O error when the socket cannot be bound.
    pub fn serve(&self) -> io::Result<RegistryServer> {
        let registry = self.clone();
        let server = HttpServer::start("registry", move |request| registry.handle(request))?;
        Ok(RegistryServer {
            server,
            registry: self.clone(),
        })
    }

    /// Answers one request.
    #[must_use]
    pub fn handle(&self, request: &HttpRequest) -> HttpResponse {
        let mut state = self.lock();
        let (kind, package, version, response) = route(&mut state, request);
        let seq = state.requests.len() as u64 + 1;
        state.requests.push(RegistryRequest {
            seq,
            method: request.method.clone(),
            path: request.path().to_owned(),
            kind,
            package,
            version,
            status: response.status,
        });
        response
    }
}

/// A running fake registry server.
#[derive(Debug)]
pub struct RegistryServer {
    server: HttpServer,
    registry: FakeRegistry,
}

impl RegistryServer {
    /// `http://127.0.0.1:<port>`. For npm, pass it as `--registry`. For cargo, use
    /// `sparse+http://127.0.0.1:<port>/`.
    #[must_use]
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// The address.
    #[must_use]
    pub fn addr(&self) -> std::net::SocketAddr {
        self.server.addr()
    }

    /// The registry behind the server.
    #[must_use]
    pub fn registry(&self) -> &FakeRegistry {
        &self.registry
    }
}

fn normalise(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::Crates => name.to_ascii_lowercase(),
        Ecosystem::Npm => name.to_owned(),
    }
}

type Routed = (&'static str, Option<String>, Option<String>, HttpResponse);

fn not_found(kind: &'static str, package: Option<String>) -> Routed {
    (
        kind,
        package,
        None,
        HttpResponse::json(404, &json!({"error": "Not found"})),
    )
}

fn route(state: &mut RegistryState, request: &HttpRequest) -> Routed {
    if request.method != "GET" {
        return (
            "unrouted",
            None,
            None,
            HttpResponse::json(405, &json!({"error": "method not allowed"})),
        );
    }
    let path = request.path();
    let segments: Vec<String> = path
        .trim_matches('/')
        .split('/')
        .map(|s| percent_decode(&s.replace('+', "%2B")))
        .collect();
    let s: Vec<&str> = segments.iter().map(String::as_str).collect();
    let base = format!("http://{}", request.header("host").unwrap_or("127.0.0.1"));
    match s.as_slice() {
        ["config.json"] => (
            "config",
            None,
            None,
            HttpResponse::json(
                200,
                &json!({"dl": format!("{base}/api/v1/crates"), "api": base}),
            ),
        ),
        ["api", "v1", "crates", name] => crate_metadata(state, name),
        ["api", "v1", "crates", name, version, "download"] => {
            download(state, Ecosystem::Crates, name, version)
        }
        // Sparse index files: 1/a, 2/ab, 3/a/abc, ab/cd/abcd...
        ["1", name] | ["2", name] | ["3", _, name] | [_, _, name]
            if index_path_matches(&s, name) =>
        {
            crate_index(state, name)
        }
        // npm tarball: /<name>/-/<file>.tgz or /@scope/name/-/<file>.tgz
        [name, "-", file] => npm_tarball(state, name, file),
        [scope, name, "-", file] if scope.starts_with('@') => {
            npm_tarball(state, &format!("{scope}/{name}"), file)
        }
        // npm packument: /<name> or /@scope/name (or the encoded form, already decoded above).
        [name] => npm_packument(state, name, &base),
        [scope, name] if scope.starts_with('@') => {
            npm_packument(state, &format!("{scope}/{name}"), &base)
        }
        _ => not_found("unrouted", None),
    }
}

/// Checks that a path is where the sparse index would put the crate.
fn index_path_matches(segments: &[&str], name: &str) -> bool {
    index_path(name).split('/').collect::<Vec<_>>() == segments
}

/// Where the sparse index keeps the file for a crate (cargo's rule).
#[must_use]
pub fn index_path(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    match name.len() {
        0 => String::new(),
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

fn crate_index(state: &RegistryState, name: &str) -> Routed {
    let key = (Ecosystem::Crates, name.to_ascii_lowercase());
    let Some(package) = state.packages.get(&key) else {
        return not_found("index", Some(name.to_owned()));
    };
    let lines: Vec<String> = package
        .versions
        .iter()
        .map(|v| {
            json!({
                "name": package.name,
                "vers": v.version,
                "deps": [],
                "cksum": hex_encode(&sha256(&package.tarball(v)), false),
                "features": {},
                "yanked": v.yanked,
                "links": null,
                "v": 2,
            })
            .to_string()
        })
        .collect();
    (
        "index",
        Some(package.name.clone()),
        None,
        HttpResponse::empty(200)
            .with_header("Content-Type", "text/plain; charset=utf-8")
            .with_body(format!("{}\n", lines.join("\n")).into_bytes()),
    )
}

fn crate_metadata(state: &RegistryState, name: &str) -> Routed {
    let key = (Ecosystem::Crates, name.to_ascii_lowercase());
    let Some(package) = state.packages.get(&key) else {
        return not_found("crate_metadata", Some(name.to_owned()));
    };
    let newest = package.latest().map(|v| v.version.clone());
    let body = json!({
        "crate": {
            "id": package.name,
            "name": package.name,
            "created_at": format_rfc3339(package.first_published),
            "updated_at": format_rfc3339(package.versions.last().map_or(package.first_published, |v| v.published)),
            "downloads": package.reported_downloads,
            "max_version": newest,
            "newest_version": newest,
        },
        "versions": package.versions.iter().map(|v| json!({
            "num": v.version,
            "created_at": format_rfc3339(v.published),
            "yanked": v.yanked,
            "crate_size": package.tarball(v).len(),
        })).collect::<Vec<_>>(),
    });
    (
        "crate_metadata",
        Some(package.name.clone()),
        None,
        HttpResponse::json(200, &body),
    )
}

fn download(state: &mut RegistryState, ecosystem: Ecosystem, name: &str, version: &str) -> Routed {
    let kind = if ecosystem == Ecosystem::Crates {
        "crate_download"
    } else {
        "tarball"
    };
    let key = (ecosystem, normalise(ecosystem, name));
    let Some(package) = state.packages.get(&key) else {
        return not_found(kind, Some(name.to_owned()));
    };
    let Some(found) = package.version(version) else {
        return not_found(kind, Some(name.to_owned()));
    };
    let bytes = package.tarball(found);
    let (package_name, version_text) = (package.name.clone(), found.version.clone());
    *state
        .downloads
        .entry((ecosystem, package_name.clone(), version_text.clone()))
        .or_insert(0) += 1;
    (
        kind,
        Some(package_name),
        Some(version_text),
        HttpResponse::empty(200)
            .with_header("Content-Type", "application/octet-stream")
            .with_body(bytes),
    )
}

fn npm_tarball(state: &mut RegistryState, name: &str, file: &str) -> Routed {
    // The file is `<unscoped name>-<version>.tgz`.
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    let Some(version) = file
        .strip_prefix(&format!("{unscoped}-"))
        .and_then(|rest| rest.strip_suffix(".tgz"))
    else {
        return not_found("tarball", Some(name.to_owned()));
    };
    download(state, Ecosystem::Npm, name, version)
}

fn npm_packument(state: &RegistryState, name: &str, base: &str) -> Routed {
    let key = (Ecosystem::Npm, name.to_owned());
    let Some(package) = state.packages.get(&key) else {
        return not_found("packument", Some(name.to_owned()));
    };
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    let mut versions = serde_json::Map::new();
    let mut times = serde_json::Map::new();
    times.insert(
        "created".to_owned(),
        json!(format_rfc3339(package.first_published)),
    );
    times.insert(
        "modified".to_owned(),
        json!(format_rfc3339(
            package
                .versions
                .last()
                .map_or(package.first_published, |v| v.published)
        )),
    );
    for version in &package.versions {
        let tarball = package.tarball(version);
        let mut entry = json!({
            "name": package.name,
            "version": version.version,
            "dist": {
                "tarball": format!("{base}/{}/-/{unscoped}-{}.tgz", package.name, version.version),
                "shasum": hex_encode(&sha1(&tarball), false),
            },
        });
        if let Some(script) = &version.script {
            entry["scripts"] = json!({"postinstall": script});
        }
        if version.yanked {
            entry["deprecated"] = json!("This version is deprecated. FAKE.");
        }
        versions.insert(version.version.clone(), entry);
        times.insert(
            version.version.clone(),
            json!(format_rfc3339(version.published)),
        );
    }
    let body = json!({
        "_id": package.name,
        "name": package.name,
        "description": "A fake package from factory-testkit. FAKE.",
        "dist-tags": {"latest": package.latest().map(|v| v.version.clone())},
        "versions": versions,
        "time": times,
        "_factory_fidelity": "fake",
        "_factory_reported_downloads": package.reported_downloads,
    });
    (
        "packument",
        Some(package.name.clone()),
        None,
        HttpResponse::json(200, &body),
    )
}

/// True when the two names differ by one letter added, dropped or changed, or by two neighbouring
/// letters swapped. Equal names are not "within one edit".
#[must_use]
pub fn within_one_edit(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    match a.len().abs_diff(b.len()) {
        0 => {
            let differing: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
            differing.len() == 1
                || (differing.len() == 2
                    && differing[1] == differing[0] + 1
                    && a[differing[0]] == b[differing[1]]
                    && a[differing[1]] == b[differing[0]])
        }
        1 => {
            let (long, short) = if a.len() > b.len() {
                (&a, &b)
            } else {
                (&b, &a)
            };
            (0..long.len()).any(|skip| {
                long.iter()
                    .enumerate()
                    .filter(|(i, _)| *i != skip)
                    .map(|(_, c)| c)
                    .eq(short.iter())
            })
        }
        _ => false,
    }
}

/// Misspellings of `name` that a squatter would register: each pair of neighbours swapped, each
/// letter dropped (for names over three letters), each letter doubled, and `-` and `_` exchanged.
/// The name itself is not in the list.
#[must_use]
pub fn typosquats_of(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut out: Vec<String> = Vec::new();
    for i in 0..chars.len().saturating_sub(1) {
        if chars[i] != chars[i + 1] {
            let mut swapped = chars.clone();
            swapped.swap(i, i + 1);
            out.push(swapped.into_iter().collect());
        }
    }
    if chars.len() > 3 {
        for i in 0..chars.len() {
            let mut shorter = chars.clone();
            shorter.remove(i);
            out.push(shorter.into_iter().collect());
        }
    }
    for i in 0..chars.len() {
        let mut longer = chars.clone();
        longer.insert(i, chars[i]);
        out.push(longer.into_iter().collect());
    }
    if name.contains('-') {
        out.push(name.replace('-', "_"));
    }
    if name.contains('_') {
        out.push(name.replace('_', "-"));
    }
    out.retain(|candidate| candidate != name);
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests;
