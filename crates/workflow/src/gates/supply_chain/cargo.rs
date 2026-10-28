//! The Cargo format: `Cargo.lock`, `Cargo.toml` and `.cargo/config.toml`.
//!
//! This is the only ecosystem implemented in this slice. The parts that are Cargo-specific are
//! here and in [`tools`](super::tools): the lockfile layout (versions 2 to 4), the dependency
//! tables of a manifest (including `target.<cfg>.*`, the workspace table and `[patch]`), and the
//! keys of the configuration file that decide where packages come from and what cargo runs.

use factory_domain::policy::dependency::Ecosystem;

use super::model::{
    BuildConfig, ConfigClass, ConfigEntry, Declared, DeclaredSource, DependencyFormat, FileKind,
    LockedPackage, LockedRef, Lockfile, Manifest, Origin, ParseError, plain,
};
use super::toml::{self, Table, Value};

/// The index of the default registry, in the two spellings cargo writes.
const DEFAULT_INDEXES: [&str; 2] = [
    "https://github.com/rust-lang/crates.io-index",
    "https://index.crates.io/",
];

/// Between a key and its value in a flattened line. A character that cannot be in a key that
/// matters, so a quoted key with an equals sign in it cannot move the split.
const SEP: char = '\u{1f}';

/// The dependency tables of a manifest or a target table.
const DEPENDENCY_TABLES: [&str; 5] = [
    "dependencies",
    "dev-dependencies",
    "build-dependencies",
    "dev_dependencies",
    "build_dependencies",
];

/// The Cargo reader.
#[derive(Debug, Clone, Copy, Default)]
pub struct CargoFormat;

impl DependencyFormat for CargoFormat {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn registry_label(&self) -> &'static str {
        "crates.io"
    }

    fn kind_of(&self, path: &str) -> Option<FileKind> {
        let name = path.rsplit('/').next().unwrap_or(path);
        let in_cargo_dir = path
            .strip_suffix(name)
            .is_some_and(|dir| dir.ends_with(".cargo/"));
        match name {
            "Cargo.lock" => Some(FileKind::Lockfile),
            "Cargo.toml" => Some(FileKind::Manifest),
            "config.toml" | "config" if in_cargo_dir => Some(FileKind::BuildConfig),
            _ => None,
        }
    }

    fn parse_lockfile(&self, text: &str) -> Result<Lockfile, ParseError> {
        let doc = toml::parse(text)?;
        match doc.get("version") {
            None => {}
            Some(Value::Int(2..=4)) => {}
            Some(_) => return Err(ParseError::Unsupported),
        }
        // The first lockfile layout kept the checksums in a `[metadata]` table. It is not read,
        // because a checksum this reader cannot see is a checksum nobody compares.
        if doc
            .get("metadata")
            .and_then(Value::as_table)
            .is_some_and(|metadata| metadata.keys().any(|key| key.starts_with("checksum ")))
        {
            return Err(ParseError::Unsupported);
        }
        let packages = match doc.get("package") {
            None => Vec::new(),
            Some(Value::Array(items)) => {
                items.iter().map(locked_package).collect::<Result<_, _>>()?
            }
            Some(_) => return Err(ParseError::Unsupported),
        };
        Ok(Lockfile { packages })
    }

    fn parse_manifest(&self, text: &str) -> Result<Manifest, ParseError> {
        let doc = toml::parse(text)?;
        let mut manifest = Manifest {
            name: doc
                .get("package")
                .and_then(Value::as_table)
                .and_then(|package| package.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            ..Manifest::default()
        };
        collect_tables(&doc, "", &mut manifest.declared)?;
        if let Some(Value::Table(targets)) = doc.get("target") {
            for (cfg, table) in targets {
                let Value::Table(table) = table else {
                    return Err(ParseError::Unsupported);
                };
                collect_tables(table, &format!("target.{cfg}."), &mut manifest.declared)?;
            }
        }
        if let Some(Value::Table(workspace)) = doc.get("workspace")
            && let Some(Value::Table(table)) = workspace.get("dependencies")
        {
            for (key, spec) in table {
                manifest
                    .workspace_declared
                    .push(declared("workspace.dependencies", key, spec)?);
            }
        }
        for section in ["patch", "replace"] {
            if let Some(value) = doc.get(section) {
                flatten(section, value, &mut manifest.patches);
            }
        }
        manifest.build_script = doc
            .get("package")
            .and_then(Value::as_table)
            .and_then(|package| package.get("build"))
            .is_some_and(|build| build.as_bool() != Some(false));
        manifest.proc_macro = doc.get("lib").and_then(Value::as_table).is_some_and(|lib| {
            lib.get("proc-macro")
                .or_else(|| lib.get("proc_macro"))
                .and_then(Value::as_bool)
                == Some(true)
        });
        Ok(manifest)
    }

    fn parse_build_config(&self, text: &str) -> Result<BuildConfig, ParseError> {
        let doc = toml::parse(text)?;
        let mut leaves = Vec::new();
        for (key, value) in &doc {
            flatten(key, value, &mut leaves);
        }
        let entries = leaves
            .into_iter()
            .map(|line| {
                let (key, value) = line.split_once(SEP).unwrap_or((&line, ""));
                ConfigEntry {
                    class: classify_key(key),
                    key: key.to_owned(),
                    value: value.to_owned(),
                }
            })
            .collect();
        Ok(BuildConfig { entries })
    }
}

fn locked_package(value: &Value) -> Result<LockedPackage, ParseError> {
    let table = value.as_table().ok_or(ParseError::Unsupported)?;
    let text = |key: &str| table.get(key).and_then(Value::as_str);
    let name = text("name").ok_or(ParseError::Unsupported)?.to_owned();
    let version = text("version").ok_or(ParseError::Unsupported)?.to_owned();
    let origin = match text("source") {
        None => Origin::Path,
        Some(source) => origin_of(source),
    };
    let dependencies = match table.get("dependencies") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(reference).ok_or(ParseError::Unsupported))
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(ParseError::Unsupported),
    };
    Ok(LockedPackage {
        name,
        version,
        origin,
        checksum: text("checksum").map(str::to_owned),
        dependencies,
    })
}

/// `name`, `name 1.2.3` or `name 1.2.3 (source)`. The source is kept: it is what tells a
/// workspace member from a registry package of the same name and version.
fn reference(text: &str) -> LockedRef {
    let mut words = text.splitn(3, ' ');
    LockedRef {
        name: words.next().unwrap_or_default().to_owned(),
        version: words.next().map(str::to_owned),
        origin: words
            .next()
            .map(|source| origin_of(source.trim_start_matches('(').trim_end_matches(')'))),
    }
}

fn origin_of(source: &str) -> Origin {
    if let Some(index) = source
        .strip_prefix("registry+")
        .or_else(|| source.strip_prefix("sparse+"))
    {
        return if DEFAULT_INDEXES.contains(&index) {
            Origin::Registry
        } else {
            Origin::OtherRegistry(host_of(index))
        };
    }
    if let Some(url) = source.strip_prefix("git+") {
        return Origin::Git(host_of(url));
    }
    Origin::Unknown
}

/// The host of a URL, without credentials, port, path or query.
fn host_of(url: &str) -> String {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let host = host.split(':').next().unwrap_or_default();
    if host.is_empty() {
        "unknown host".to_owned()
    } else {
        plain(host, 100)
    }
}

/// Collects the dependency tables found directly in `table`.
fn collect_tables(table: &Table, prefix: &str, out: &mut Vec<Declared>) -> Result<(), ParseError> {
    for name in DEPENDENCY_TABLES {
        match table.get(name) {
            None => {}
            Some(Value::Table(entries)) => {
                for (key, spec) in entries {
                    out.push(declared(&format!("{prefix}{name}"), key, spec)?);
                }
            }
            Some(_) => return Err(ParseError::Unsupported),
        }
    }
    Ok(())
}

fn declared(section: &str, key: &str, spec: &Value) -> Result<Declared, ParseError> {
    let (source, name) = match spec {
        Value::Str(_) => (DeclaredSource::Registry, key.to_owned()),
        Value::Table(table) => {
            let source = if table.get("workspace").and_then(Value::as_bool) == Some(true) {
                DeclaredSource::Workspace
            } else if table.contains_key("git") {
                DeclaredSource::Git
            } else if table.contains_key("path") {
                DeclaredSource::Path
            } else if table.contains_key("registry") || table.contains_key("registry-index") {
                DeclaredSource::AlternateRegistry
            } else {
                DeclaredSource::Registry
            };
            let name = table
                .get("package")
                .and_then(Value::as_str)
                .unwrap_or(key)
                .to_owned();
            (source, name)
        }
        _ => return Err(ParseError::Unsupported),
    };
    Ok(Declared {
        section: section.to_owned(),
        key: key.to_owned(),
        name,
        source,
        canonical: format!("{section}|{key}|{}", spec.canonical()),
    })
}

/// Writes every leaf below `value` as `dotted.key`, [`SEP`] and the canonical value.
fn flatten(prefix: &str, value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Table(table) if !table.is_empty() => {
            for (key, inner) in table {
                flatten(&format!("{prefix}.{key}"), inner, out);
            }
        }
        other => out.push(format!("{prefix}{SEP}{}", other.canonical())),
    }
}

/// What a key of `.cargo/config.toml` can do. A key that is not on the list of harmless ones is
/// [`ConfigClass::Unrecognized`], which the gate treats as unsafe.
fn classify_key(key: &str) -> ConfigClass {
    let under = |prefix: &str| key == prefix || key.starts_with(&format!("{prefix}."));
    if [
        "source",
        "registries",
        "registry",
        "patch",
        "net",
        "http",
        "paths",
        "credential-alias",
    ]
    .iter()
    .any(|prefix| under(prefix))
    {
        return ConfigClass::Redirect;
    }
    let runs_code = [
        "build.rustc",
        "build.rustc-wrapper",
        "build.rustc-workspace-wrapper",
        "build.rustdoc",
        "build.rustflags",
        "build.rustdocflags",
        "target",
        "env",
        "alias",
        "install",
        "doc",
        "unstable",
        "include",
    ];
    if runs_code.iter().any(|prefix| under(prefix)) || key.ends_with(".rustflags") {
        return ConfigClass::Execution;
    }
    let harmless = [
        "term",
        "build.jobs",
        "build.target-dir",
        "build.incremental",
        "cargo-new",
        "future-incompat-report",
        "profile",
    ];
    if harmless.iter().any(|prefix| under(prefix)) {
        return ConfigClass::Benign;
    }
    ConfigClass::Unrecognized
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

    #[test]
    fn a_lockfile_gives_packages_sources_checksums_and_edges() {
        // The credentials are put together here, so that no file holds a URL with a password.
        let credentials = ["us", "er:p", "w"].concat();
        let text = format!(
            "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"serde\", \"log 0.4.0\"]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"{CRATES_IO}\"\nchecksum = \"{}\"\n\n[[package]]\nname = \"odd\"\nversion = \"1.0.0\"\nsource = \"git+https://{credentials}@example.test:8080/org/odd?rev=1#abc\"\n",
            "a".repeat(64)
        );
        let lock = CargoFormat.parse_lockfile(&text).expect("a lockfile");
        assert_eq!(lock.packages.len(), 3);
        assert_eq!(lock.packages[0].origin, Origin::Path);
        assert_eq!(
            lock.packages[0].dependencies[1].version.as_deref(),
            Some("0.4.0")
        );
        assert_eq!(lock.packages[1].origin, Origin::Registry);
        assert_eq!(
            lock.packages[1].checksum.as_deref(),
            Some("a".repeat(64).as_str())
        );
        // The host is kept; the credential, the port and the path are not.
        assert_eq!(
            lock.packages[2].origin,
            Origin::Git("example.test".to_owned())
        );
        assert_eq!(lock.members().count(), 1);
    }

    #[test]
    fn a_reference_keeps_its_source_so_a_member_and_a_registry_package_are_told_apart() {
        let text = format!(
            "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"evil 0.1.0 ({CRATES_IO})\", \"serde\", \"log 0.4.0\"]\n\n[[package]]\nname = \"evil\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"evil\"\nversion = \"0.1.0\"\nsource = \"{CRATES_IO}\"\nchecksum = \"{}\"\n",
            "e".repeat(64)
        );
        let lock = CargoFormat.parse_lockfile(&text).expect("a lockfile");
        let refs = &lock.packages[0].dependencies;
        assert_eq!(refs[0].origin, Some(Origin::Registry));
        assert_eq!(refs[1].origin, None);
        assert_eq!(refs[2].version.as_deref(), Some("0.4.0"));
        let index = lock.index();
        match index.resolve(&refs[0]) {
            super::super::model::Resolved::One(package) => {
                assert_eq!(package.origin, Origin::Registry);
            }
            other => panic!("expected one package, got {other:?}"),
        }
        // The same reference without its source names both and is not resolved.
        let bare = LockedRef {
            origin: None,
            ..refs[0].clone()
        };
        assert_eq!(
            index.resolve(&bare),
            super::super::model::Resolved::Ambiguous
        );
    }

    #[test]
    fn the_sparse_index_is_the_default_registry_and_another_index_is_not() {
        for (source, registry) in [
            ("sparse+https://index.crates.io/", true),
            (
                "registry+https://github.com/rust-lang/crates.io-index",
                true,
            ),
            ("sparse+https://index.crates.io.evil.test/", false),
            ("registry+https://corp.test/index", false),
        ] {
            let text = format!(
                "version = 3\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"{source}\"\n"
            );
            let lock = CargoFormat.parse_lockfile(&text).expect("a lockfile");
            assert_eq!(
                lock.packages[0].origin.is_default_registry(),
                registry,
                "{source}"
            );
        }
    }

    #[test]
    fn an_old_or_unknown_lockfile_layout_is_not_read() {
        assert_eq!(
            CargoFormat.parse_lockfile("version = 9\n"),
            Err(ParseError::Unsupported)
        );
        assert_eq!(
            CargoFormat.parse_lockfile("[metadata]\n\"checksum a 1.0.0 (x)\" = \"abc\"\n"),
            Err(ParseError::Unsupported)
        );
        assert!(CargoFormat.parse_lockfile("[[package]\n").is_err());
    }

    #[test]
    fn a_manifest_gives_every_dependency_with_its_source() {
        let text = "[package]\nname = \"app\"\nbuild = \"build.rs\"\n\n[dependencies]\nserde = \"1\"\nfoo = { git = \"https://x.test/foo\" }\nbar = { path = \"../bar\", version = \"0.1\" }\nbaz = { version = \"1\", registry = \"corp\" }\nrenamed = { package = \"real-name\", version = \"1\" }\n\n[target.'cfg(unix)'.dev-dependencies]\nlibc = \"0.2\"\n\n[workspace.dependencies]\nshared = \"2\"\n\n[patch.crates-io]\nserde = { git = \"https://x.test/serde\" }\n\n[lib]\nproc-macro = true\n";
        let manifest = CargoFormat.parse_manifest(text).expect("a manifest");
        let by_key = |key: &str| {
            manifest
                .declared
                .iter()
                .find(|d| d.key == key)
                .unwrap_or_else(|| panic!("no {key}"))
        };
        assert_eq!(by_key("serde").source, DeclaredSource::Registry);
        assert_eq!(by_key("foo").source, DeclaredSource::Git);
        assert_eq!(by_key("bar").source, DeclaredSource::Path);
        assert_eq!(by_key("baz").source, DeclaredSource::AlternateRegistry);
        assert_eq!(by_key("renamed").name, "real-name");
        assert_eq!(by_key("libc").section, "target.cfg(unix).dev-dependencies");
        assert_eq!(manifest.workspace_declared.len(), 1);
        assert_eq!(manifest.patches.len(), 1);
        assert!(manifest.build_script && manifest.proc_macro);
    }

    #[test]
    fn a_dependency_written_in_a_form_that_is_not_known_is_refused() {
        assert_eq!(
            CargoFormat.parse_manifest("[dependencies]\nfoo = 3\n"),
            Err(ParseError::Unsupported)
        );
    }

    #[test]
    fn config_keys_are_classified_and_unknown_keys_are_not_trusted() {
        let text = "[registries.corp]\nindex = \"sparse+https://corp.test/\"\n[source.crates-io]\nreplace-with = \"mirror\"\n[build]\nrustc-wrapper = \"/x\"\njobs = 4\n[env]\nA = \"1\"\n[term]\ncolor = \"never\"\n[something]\nnew = 1\n";
        let config = CargoFormat.parse_build_config(text).expect("a config");
        let class = |key: &str| {
            config
                .entries
                .iter()
                .find(|e| e.key == key)
                .unwrap_or_else(|| panic!("no {key}"))
                .class
        };
        assert_eq!(class("registries.corp.index"), ConfigClass::Redirect);
        assert_eq!(
            class("source.crates-io.replace-with"),
            ConfigClass::Redirect
        );
        assert_eq!(class("build.rustc-wrapper"), ConfigClass::Execution);
        assert_eq!(class("env.A"), ConfigClass::Execution);
        assert_eq!(class("build.jobs"), ConfigClass::Benign);
        assert_eq!(class("term.color"), ConfigClass::Benign);
        assert_eq!(class("something.new"), ConfigClass::Unrecognized);
    }

    #[test]
    fn only_dependency_files_are_recognised() {
        let kind = |path: &str| CargoFormat.kind_of(path);
        assert_eq!(kind("Cargo.lock"), Some(FileKind::Lockfile));
        assert_eq!(kind("crates/a/Cargo.toml"), Some(FileKind::Manifest));
        assert_eq!(kind(".cargo/config.toml"), Some(FileKind::BuildConfig));
        assert_eq!(kind("sub/.cargo/config"), Some(FileKind::BuildConfig));
        assert_eq!(kind("config.toml"), None);
        assert_eq!(kind("src/Cargo.toml.bak"), None);
    }
}
