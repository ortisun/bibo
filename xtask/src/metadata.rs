//! The real dependency graph, from `cargo metadata`.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepKind {
    Normal,
    Dev,
    Build,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    /// The package name, not the local alias.
    pub name: String,
    pub kind: DepKind,
    /// True for a dependency on a local path. A workspace edge is one of these that names a
    /// workspace member.
    pub is_path: bool,
    /// The directory a path dependency points at, as Cargo reports it.
    pub path: Option<PathBuf>,
    /// Where the package comes from: `registry+https://...` or `git+https://...`. `None` for a
    /// path dependency.
    pub source: Option<String>,
    pub uses_default_features: bool,
    pub features: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    /// The directory of the member's `Cargo.toml`, as Cargo reports it.
    pub dir: PathBuf,
    pub dependencies: Vec<Dependency>,
    /// The root source file of every target that ships: library, binary, procedural macro and
    /// build script. Tests, benches and examples are left out. A root can sit outside `src`
    /// when the manifest sets a `path`.
    pub production_targets: Vec<PathBuf>,
    /// The root source file of every binary target. A library that must not be a program (the
    /// composition library, DEP-11) has none.
    pub binary_targets: Vec<PathBuf>,
    /// For each package this member depends on, the features Cargo resolved for it with the
    /// whole workspace unified (`resolve.nodes[].features`). A crate that enables a feature in
    /// its own manifest changes this set for every other crate that uses the package.
    pub resolved_dependency_features: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone)]
pub struct Workspace {
    pub root: PathBuf,
    pub members: Vec<Member>,
    /// For every package in the resolved graph, its feature table, merged across versions.
    pub package_features: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl Workspace {
    pub fn member_names(&self) -> BTreeSet<&str> {
        self.members.iter().map(|m| m.name.as_str()).collect()
    }

    /// The directory of a member relative to the workspace root, with forward slashes.
    pub fn relative_dir(&self, member: &Member) -> String {
        member
            .dir
            .strip_prefix(&self.root)
            .unwrap_or(&member.dir)
            .to_string_lossy()
            .replace('\\', "/")
    }
}

/// Run `cargo metadata` for the workspace that holds `manifest_path`.
pub fn load(manifest_path: &Path) -> Result<Workspace, String> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
        .args(["metadata", "--format-version", "1", "--manifest-path"])
        .arg(manifest_path)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", Path::new(&cargo).display()))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed for {}:\n{}",
            manifest_path.display(),
            String::from_utf8_lossy(&output.stderr).trim_end()
        ));
    }
    parse(&String::from_utf8_lossy(&output.stdout))
}

pub fn parse(json: &str) -> Result<Workspace, String> {
    let doc: Value =
        serde_json::from_str(json).map_err(|e| format!("cargo metadata is not JSON: {e}"))?;
    let missing = |what: &str| format!("cargo metadata output has no {what}");

    let root = PathBuf::from(
        doc["workspace_root"]
            .as_str()
            .ok_or_else(|| missing("workspace_root"))?,
    );
    let member_ids: BTreeSet<&str> = doc["workspace_members"]
        .as_array()
        .ok_or_else(|| missing("workspace_members"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();

    let mut members = Vec::new();
    let mut package_features: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for package in doc["packages"]
        .as_array()
        .ok_or_else(|| missing("packages"))?
    {
        let name = package["name"]
            .as_str()
            .ok_or_else(|| missing("package name"))?;

        let table = package_features.entry(name.to_string()).or_default();
        for (feature, implied) in package["features"].as_object().into_iter().flatten() {
            let implied = implied
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            table
                .entry(feature.clone())
                .or_default()
                .extend(implied.map(str::to_string));
        }

        let id = package["id"].as_str().unwrap_or_default();
        if !member_ids.contains(id) {
            continue;
        }
        let manifest = package["manifest_path"]
            .as_str()
            .ok_or_else(|| missing("manifest_path"))?;
        let dir = Path::new(manifest)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();

        let mut dependencies = Vec::new();
        for d in package["dependencies"].as_array().into_iter().flatten() {
            let kind = match d["kind"].as_str() {
                None | Some("normal") => DepKind::Normal,
                Some("dev") => DepKind::Dev,
                Some("build") => DepKind::Build,
                Some(other) => {
                    return Err(format!("cargo metadata: unknown dependency kind {other:?}"));
                }
            };
            dependencies.push(Dependency {
                name: d["name"]
                    .as_str()
                    .ok_or_else(|| missing("dependency name"))?
                    .to_string(),
                kind,
                is_path: d["path"].is_string(),
                path: d["path"].as_str().map(PathBuf::from),
                source: d["source"].as_str().map(str::to_string),
                uses_default_features: d["uses_default_features"].as_bool().unwrap_or(true),
                features: d["features"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
            });
        }
        let production_targets = package["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|t| {
                t["kind"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .any(|k| {
                        matches!(
                            k,
                            "lib"
                                | "bin"
                                | "proc-macro"
                                | "cdylib"
                                | "dylib"
                                | "rlib"
                                | "staticlib"
                                | "custom-build"
                        )
                    })
            })
            .filter_map(|t| t["src_path"].as_str())
            .map(PathBuf::from)
            .collect();
        let binary_targets = package["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|t| {
                t["kind"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .any(|k| k == "bin")
            })
            .filter_map(|t| t["src_path"].as_str())
            .map(PathBuf::from)
            .collect();
        members.push(Member {
            name: name.to_string(),
            dir,
            dependencies,
            production_targets,
            binary_targets,
            resolved_dependency_features: resolved_features_of(&doc, id),
        });
    }
    members.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Workspace {
        root,
        members,
        package_features,
    })
}

/// The resolved features of every package that the package `member_id` depends on.
fn resolved_features_of(doc: &Value, member_id: &str) -> BTreeMap<String, BTreeSet<String>> {
    let nodes = doc["resolve"]["nodes"].as_array();
    let name_of = |id: &str| -> Option<String> {
        doc["packages"]
            .as_array()?
            .iter()
            .find(|p| p["id"].as_str() == Some(id))
            .and_then(|p| p["name"].as_str().map(str::to_string))
    };
    let features_of = |id: &str| -> BTreeSet<String> {
        nodes
            .into_iter()
            .flatten()
            .find(|n| n["id"].as_str() == Some(id))
            .map(|n| {
                n["features"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut resolved: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let node = nodes
        .into_iter()
        .flatten()
        .find(|n| n["id"].as_str() == Some(member_id));
    for dep in node
        .and_then(|n| n["deps"].as_array())
        .into_iter()
        .flatten()
    {
        let Some(id) = dep["pkg"].as_str() else {
            continue;
        };
        if let Some(name) = name_of(id) {
            resolved.entry(name).or_default().extend(features_of(id));
        }
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "workspace_root": "/w",
      "workspace_members": ["path+file:///w/a#a@0.1.0"],
      "packages": [
        {"id": "path+file:///w/a#a@0.1.0", "name": "a", "manifest_path": "/w/crates/a/Cargo.toml", "features": {},
         "dependencies": [
           {"name": "b", "kind": null, "path": "/w/crates/b", "uses_default_features": true, "features": []},
           {"name": "tokio", "kind": "dev", "uses_default_features": false, "features": ["fs"]},
           {"name": "cc", "kind": "build", "features": []}
         ]},
        {"id": "registry+x#tokio@1.0.0", "name": "tokio", "manifest_path": "/r/tokio/Cargo.toml",
         "features": {"fs": [], "full": ["fs"]}, "dependencies": []}
      ]
    }"#;

    #[test]
    fn it_reads_members_dependency_kinds_paths_and_features() {
        let ws = parse(SAMPLE).expect("parse");
        assert_eq!(ws.root, PathBuf::from("/w"));
        assert_eq!(ws.members.len(), 1);
        let deps = &ws.members[0].dependencies;
        assert_eq!(
            (deps[0].name.as_str(), deps[0].kind, deps[0].is_path),
            ("b", DepKind::Normal, true)
        );
        assert_eq!(
            (
                deps[1].kind,
                deps[1].uses_default_features,
                deps[1].features.clone()
            ),
            (DepKind::Dev, false, vec!["fs".to_string()])
        );
        assert_eq!(deps[2].kind, DepKind::Build);
        assert_eq!(ws.relative_dir(&ws.members[0]), "crates/a");
    }

    #[test]
    fn it_keeps_the_feature_table_of_packages_outside_the_workspace() {
        let ws = parse(SAMPLE).expect("parse");
        assert_eq!(ws.package_features["tokio"]["full"], ["fs"]);
    }

    #[test]
    fn output_that_is_not_cargo_metadata_is_an_error() {
        assert!(parse("{}").is_err());
        assert!(parse("not json").is_err());
    }
}
