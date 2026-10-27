//! Fixture workspaces for the architecture check.
//!
//! Each test builds a small Cargo workspace in a temporary directory, together with its own
//! rules file, and runs the real `xtask` binary against it. The baseline fixture satisfies every
//! rule. A test changes one thing and expects the check to fail with that rule's id.
//!
//! External crates are stub packages in a sibling `ext` directory, so `cargo metadata` needs no
//! network.
#![allow(dead_code)]

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// The real rules file, parsed.
pub fn real_rules() -> xtask::rules::Rules {
    xtask::rules::Rules::load(&real_rules_path()).expect("the real rules file loads")
}

pub fn real_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/architecture/crate-dependency-rules.json")
}

/// The `source_scans` section of the real rules file. The fixtures run the real lists, so a
/// fixture that passes proves the real data accepts it.
fn real_source_scans() -> Value {
    let text = fs::read_to_string(real_rules_path()).expect("read the real rules file");
    let doc: Value = serde_json::from_str(&text).expect("the real rules file is JSON");
    doc["source_scans"].clone()
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Normal,
    Dev,
    Build,
}

struct Edge {
    kind: Kind,
    /// Package name, for example `factory-domain` or `tokio`.
    package: String,
    features: Vec<String>,
}

struct Member {
    path: String,
    package: String,
    is_app: bool,
    edges: Vec<Edge>,
    /// The lints table of the manifest. `None` leaves the crate without one.
    lints: Option<String>,
}

struct External {
    features: Vec<(String, Vec<String>)>,
}

/// The result of one run of the check.
pub struct Run {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    fn report(&self) -> String {
        format!(
            "exit code {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }

    pub fn assert_passes(&self) {
        assert_eq!(
            self.code,
            Some(0),
            "expected the check to pass:\n{}",
            self.report()
        );
    }

    /// The check must exit with 1 and name the rule.
    pub fn assert_violation(&self, rule: &str) {
        assert_eq!(
            self.code,
            Some(1),
            "expected a rule violation:\n{}",
            self.report()
        );
        let tag = format!("error[{rule}]");
        assert!(
            self.stderr.contains(&tag),
            "expected {tag} in stderr:\n{}",
            self.report()
        );
    }

    /// The check must exit with 1 and report `rule` with a message that contains `text`.
    pub fn assert_violation_mentions(&self, rule: &str, text: &str) {
        self.assert_violation(rule);
        let hit = self
            .stderr
            .lines()
            .any(|line| line.contains(&format!("error[{rule}]")) && line.contains(text));
        assert!(
            hit,
            "expected an {rule} line that mentions {text:?}:\n{}",
            self.report()
        );
    }

    /// The check must not report `rule` at all.
    pub fn assert_no_violation(&self, rule: &str) {
        let tag = format!("error[{rule}]");
        assert!(
            !self.stderr.contains(&tag),
            "did not expect {tag}:\n{}",
            self.report()
        );
    }

    /// The check could not run (exit code 2).
    pub fn assert_error(&self, text: &str) {
        assert_eq!(
            self.code,
            Some(2),
            "expected an error exit:\n{}",
            self.report()
        );
        assert!(
            self.stderr.contains(text),
            "expected {text:?} in stderr:\n{}",
            self.report()
        );
    }
}

pub struct Fixture {
    dir: PathBuf,
    rules: Value,
    members: BTreeMap<String, Member>,
    externals: BTreeMap<String, External>,
    files: Vec<(String, String)>,
    skip_clippy_toml: Vec<String>,
    /// The `[workspace.lints]` tables of the root manifest.
    root_lints: Option<String>,
}

const MEMBER_LINTS: &str = "\n[lints]\nworkspace = true\n";
const ROOT_LINTS: &str = "\n[workspace.lints.rust]\nunsafe_code = \"forbid\"\n";

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn crate_rule(
    name: &str,
    ring: u8,
    layer: &str,
    depends_on: &[&str],
    dev_depends_on: &[&str],
    allow: &[&str],
) -> Value {
    json!({
        "name": name,
        "ring": ring,
        "layer": layer,
        "path": format!("crates/{name}"),
        "slice": 0,
        "depends_on": depends_on,
        "dev_depends_on": dev_depends_on,
        "external_allow": allow,
        "responsibility": "fixture"
    })
}

impl Fixture {
    /// A workspace that satisfies every rule: a domain, ports, two application crates, five
    /// adapters, a testkit, and one binary.
    pub fn baseline(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "xtask-fixture-{}-{}-{label}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create the fixture directory");

        let app = |n: &str| json!({"name": n, "path": format!("apps/{n}"), "slice": 1, "responsibility": "fixture"});
        let rule = |id: &str| {
            let enforced_by = if id == "DEP-06" {
                "workspace lint unsafe_code = forbid"
            } else {
                "fixture"
            };
            json!({"id": id, "statement": format!("fixture statement for {id}"), "enforced_by": enforced_by})
        };
        let rule_list: Vec<Value> = [
            "DEP-01", "DEP-02", "DEP-03", "DEP-04", "DEP-05", "DEP-06", "DEP-07", "DEP-08",
            "DEP-09", "DEP-10",
        ]
        .iter()
        .map(|id| rule(id))
        .collect();
        let rules = json!({
            "schema_version": 1,
            "package_prefix": "factory-",
            "rings": [],
            "crates": [
                crate_rule("domain", 0, "domain", &[], &[], &["serde_json"]),
                crate_rule("ports", 1, "ports", &["domain"], &[], &["serde_json"]),
                crate_rule("workflow", 2, "application", &["domain", "ports"], &["testkit"], &["serde_json", "tokio[sync,time]"]),
                crate_rule("spec_adapter", 2, "application", &["domain", "ports"], &["testkit"], &["serde_json"]),
                crate_rule("storage", 2, "adapter", &["domain", "ports"], &["testkit"], &["serde_json"]),
                crate_rule("sandbox", 2, "adapter", &["domain", "ports"], &["testkit"], &["serde_json"]),
                crate_rule("runtime", 2, "adapter", &["domain", "ports"], &["testkit"], &["serde_json"]),
                crate_rule("github", 2, "adapter", &["domain", "ports"], &["testkit"], &["serde_json"]),
                crate_rule("observability", 2, "adapter", &[], &[], &[]),
                crate_rule("testkit", 2, "test-support", &["domain", "ports"], &[], &["serde_json"]),
            ],
            "apps": [app("api"), app("worker")],
            "tooling": [{"name": "xtask", "path": "xtask", "slice": 0, "responsibility": "fixture"}],
            "rules": rule_list,
            "source_scans": real_source_scans(),
            "deferred": []
        });

        let mut fixture = Self {
            dir,
            rules,
            members: BTreeMap::new(),
            externals: BTreeMap::new(),
            files: Vec::new(),
            skip_clippy_toml: Vec::new(),
            root_lints: Some(ROOT_LINTS.to_string()),
        };
        for c in fixture.rules["crates"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let name = c["name"].as_str().unwrap_or_default().to_string();
            fixture.add_member(&name, false);
        }
        fixture.add_member("api", true);
        fixture.add_member("worker", true);

        fixture.add_external("serde_json", &[]);
        fixture.add_external(
            "tokio",
            &[
                ("sync", &[]),
                ("time", &[]),
                ("rt", &[]),
                ("fs", &[]),
                ("net", &[]),
                ("full", &["sync", "time", "rt", "fs", "net"]),
            ],
        );
        fixture.add_external("reqwest", &[]);

        // Dependencies exactly as the baseline rules allow them.
        for c in fixture.rules["crates"]
            .clone()
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let name = c["name"].as_str().unwrap_or_default().to_string();
            for dep in c["depends_on"].as_array().cloned().unwrap_or_default() {
                fixture.depend(&name, dep.as_str().unwrap_or_default());
            }
            for dep in c["dev_depends_on"].as_array().cloned().unwrap_or_default() {
                fixture.dev_depend(&name, dep.as_str().unwrap_or_default());
            }
        }
        fixture.external("domain", "serde_json", &[]);
        fixture.external("workflow", "tokio", &["sync", "time"]);
        // The binary wires the adapters and the application crates.
        for lib in [
            "workflow", "storage", "sandbox", "runtime", "github", "domain", "ports",
        ] {
            fixture.depend("api", lib);
        }
        fixture.dev_depend("api", "testkit");
        fixture
    }

    fn add_member(&mut self, rules_name: &str, is_app: bool) {
        let (path, package) = if is_app {
            (
                format!("apps/{rules_name}"),
                format!("factory-{rules_name}"),
            )
        } else {
            (
                format!("crates/{rules_name}"),
                format!("factory-{rules_name}"),
            )
        };
        self.members.insert(
            rules_name.to_string(),
            Member {
                path,
                package,
                is_app,
                edges: Vec::new(),
                lints: Some(MEMBER_LINTS.to_string()),
            },
        );
    }

    fn add_external(&mut self, name: &str, features: &[(&str, &[&str])]) {
        self.externals.insert(
            name.to_string(),
            External {
                features: features
                    .iter()
                    .map(|(f, implied)| {
                        (
                            (*f).to_string(),
                            implied.iter().map(|s| (*s).to_string()).collect(),
                        )
                    })
                    .collect(),
            },
        );
    }

    /// Add an external stub crate with the given features, for example `("fs", &[])`.
    pub fn external_stub(&mut self, name: &str, features: &[(&str, &[&str])]) -> &mut Self {
        self.add_external(name, features);
        self
    }

    fn edge(&mut self, from: &str, kind: Kind, package: String, features: &[&str]) {
        let member = self
            .members
            .get_mut(from)
            .unwrap_or_else(|| panic!("no fixture member {from}"));
        member
            .edges
            .retain(|e| !(e.kind == kind && e.package == package));
        member.edges.push(Edge {
            kind,
            package,
            features: features.iter().map(|s| (*s).to_string()).collect(),
        });
    }

    /// A normal dependency of `from` on the workspace member `on`.
    pub fn depend(&mut self, from: &str, on: &str) -> &mut Self {
        let package = self.package_of(on);
        self.edge(from, Kind::Normal, package, &[]);
        self
    }

    pub fn dev_depend(&mut self, from: &str, on: &str) -> &mut Self {
        let package = self.package_of(on);
        self.edge(from, Kind::Dev, package, &[]);
        self
    }

    pub fn build_depend(&mut self, from: &str, on: &str) -> &mut Self {
        let package = self.package_of(on);
        self.edge(from, Kind::Build, package, &[]);
        self
    }

    /// Remove every workspace dependency of `from` on `on`, whatever the kind.
    pub fn remove_dependency(&mut self, from: &str, on: &str) -> &mut Self {
        let package = self.package_of(on);
        self.members
            .get_mut(from)
            .expect("fixture member")
            .edges
            .retain(|e| e.package != package);
        self
    }

    /// A normal dependency of `from` on an external stub crate.
    pub fn external(&mut self, from: &str, name: &str, features: &[&str]) -> &mut Self {
        assert!(
            self.externals.contains_key(name),
            "declare the stub {name} first"
        );
        self.edge(from, Kind::Normal, name.to_string(), features);
        self
    }

    pub fn dev_external(&mut self, from: &str, name: &str, features: &[&str]) -> &mut Self {
        assert!(
            self.externals.contains_key(name),
            "declare the stub {name} first"
        );
        self.edge(from, Kind::Dev, name.to_string(), features);
        self
    }

    fn package_of(&self, rules_name: &str) -> String {
        self.members
            .get(rules_name)
            .unwrap_or_else(|| panic!("no fixture member {rules_name}"))
            .package
            .clone()
    }

    /// A workspace member that the rules file does not list.
    pub fn unlisted_crate(&mut self, name: &str) -> &mut Self {
        self.add_member(name, false);
        self
    }

    /// Leave a listed crate out of the workspace, as if it had not been created yet.
    pub fn omit_from_workspace(&mut self, name: &str) -> &mut Self {
        self.members.remove(name);
        self
    }

    /// Put a member in a different directory than the rules file says.
    pub fn relocate(&mut self, name: &str, path: &str) -> &mut Self {
        self.members.get_mut(name).expect("fixture member").path = path.to_string();
        self
    }

    /// The rules file, for tests that change what is allowed.
    pub fn rules_mut(&mut self) -> &mut Value {
        &mut self.rules
    }

    /// Let `from` depend on `on` in the rules file, so a test can isolate one rule.
    pub fn allow_in_rules(&mut self, from: &str, on: &str) -> &mut Self {
        let list = self.crate_rule_mut(from)["depends_on"]
            .as_array_mut()
            .expect("depends_on");
        list.push(json!(on));
        self
    }

    pub fn allow_dev_in_rules(&mut self, from: &str, on: &str) -> &mut Self {
        let list = self.crate_rule_mut(from)["dev_depends_on"]
            .as_array_mut()
            .expect("dev_depends_on");
        list.push(json!(on));
        self
    }

    pub fn allow_external_in_rules(&mut self, from: &str, entry: &str) -> &mut Self {
        let list = self.crate_rule_mut(from)["external_allow"]
            .as_array_mut()
            .expect("external_allow");
        list.push(json!(entry));
        self
    }

    fn crate_rule_mut(&mut self, name: &str) -> &mut Value {
        self.rules["crates"]
            .as_array_mut()
            .and_then(|crates| crates.iter_mut().find(|c| c["name"] == name))
            .unwrap_or_else(|| panic!("no rules entry for {name}"))
    }

    /// Write a file relative to the member's directory, for example `src/exec.rs`.
    pub fn source(&mut self, member: &str, relative: &str, content: &str) -> &mut Self {
        let path = format!("{}/{relative}", self.members[member].path);
        self.file(&path, content)
    }

    /// Write a file relative to the workspace root.
    pub fn file(&mut self, relative: &str, content: &str) -> &mut Self {
        self.files.retain(|(p, _)| p != relative);
        self.files.push((relative.to_string(), content.to_string()));
        self
    }

    /// Replace the lints table of a member's manifest. `None` removes it.
    pub fn lints_block(&mut self, member: &str, block: Option<&str>) -> &mut Self {
        self.members.get_mut(member).expect("fixture member").lints = block.map(str::to_string);
        self
    }

    /// Replace the `[workspace.lints]` tables of the root manifest. `None` removes them.
    pub fn root_lints_block(&mut self, block: Option<&str>) -> &mut Self {
        self.root_lints = block.map(str::to_string);
        self
    }

    /// Do not write the canonical clippy.toml for this crate.
    pub fn without_clippy_toml(&mut self, member: &str) -> &mut Self {
        self.skip_clippy_toml.push(member.to_string());
        self
    }

    pub fn workspace_dir(&self) -> PathBuf {
        self.dir.join("ws")
    }

    pub fn rules_path(&self) -> PathBuf {
        self.dir.join("rules.json")
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.workspace_dir().join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("create directories");
        fs::write(path, content).expect("write a fixture file");
    }

    fn write_to_disk(&self) {
        let ws = self.workspace_dir();
        let _ = fs::remove_dir_all(&ws);
        fs::create_dir_all(&ws).expect("create the workspace directory");

        // External stub crates live next to the workspace, not inside it.
        for (name, ext) in &self.externals {
            let root = self.dir.join("ext").join(name);
            fs::create_dir_all(root.join("src")).expect("create a stub");
            let mut manifest = format!(
                "[package]\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"2024\"\n\n[features]\n"
            );
            for (feature, implied) in &ext.features {
                let list: Vec<String> = implied.iter().map(|i| format!("\"{i}\"")).collect();
                manifest.push_str(&format!("{feature} = [{}]\n", list.join(", ")));
            }
            fs::write(root.join("Cargo.toml"), manifest).expect("write a stub manifest");
            fs::write(root.join("src/lib.rs"), "").expect("write a stub source");
        }

        // The workspace root, with inherited dependencies like the real repository.
        let mut root = String::from("[workspace]\nresolver = \"3\"\nmembers = [");
        let paths: Vec<String> = self
            .members
            .values()
            .map(|m| format!("\"{}\"", m.path))
            .collect();
        root.push_str(&paths.join(", "));
        root.push_str("]\n\n[workspace.dependencies]\n");
        for m in self.members.values().filter(|m| !m.is_app) {
            root.push_str(&format!("{} = {{ path = \"{}\" }}\n", m.package, m.path));
        }
        for name in self.externals.keys() {
            root.push_str(&format!("{name} = {{ path = \"../ext/{name}\" }}\n"));
        }
        root.push_str(self.root_lints.as_deref().unwrap_or_default());
        self.write("Cargo.toml", &root);

        for m in self.members.values() {
            let mut manifest = format!(
                "[package]\nname = \"{}\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n",
                m.package
            );
            for (kind, table) in [
                (Kind::Normal, "dependencies"),
                (Kind::Dev, "dev-dependencies"),
                (Kind::Build, "build-dependencies"),
            ] {
                let edges: Vec<&Edge> = m.edges.iter().filter(|e| e.kind == kind).collect();
                if edges.is_empty() {
                    continue;
                }
                manifest.push_str(&format!("\n[{table}]\n"));
                for e in edges {
                    let features = if e.features.is_empty() {
                        String::new()
                    } else {
                        let list: Vec<String> =
                            e.features.iter().map(|f| format!("\"{f}\"")).collect();
                        format!(", features = [{}]", list.join(", "))
                    };
                    manifest.push_str(&format!(
                        "{} = {{ workspace = true{features} }}\n",
                        e.package
                    ));
                }
            }
            manifest.push_str(m.lints.as_deref().unwrap_or_default());
            self.write(&format!("{}/Cargo.toml", m.path), &manifest);
            let entry = if m.is_app {
                "src/main.rs"
            } else {
                "src/lib.rs"
            };
            let body = if m.is_app { "fn main() {}\n" } else { "" };
            self.write(&format!("{}/{entry}", m.path), body);
        }

        self.write_clippy_tomls();

        for (relative, content) in &self.files {
            self.write(relative, content);
        }
        fs::write(
            self.rules_path(),
            serde_json::to_string_pretty(&self.rules).expect("rules json"),
        )
        .expect("write the rules file");
    }

    /// The four inner crates carry the ban list, as the rules file requires.
    fn write_clippy_tomls(&self) {
        let inner = self.rules["source_scans"]["dep_05"]["inner_crates"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for name in inner.iter().filter_map(Value::as_str) {
            if let Some(member) = self.members.get(name)
                && !self.skip_clippy_toml.iter().any(|s| s == name)
            {
                self.write(
                    &format!("{}/clippy.toml", member.path),
                    &xtask::clippy_bans::render_clippy_toml(),
                );
            }
        }
    }

    /// Run with `--allow-missing-crates`: the fixtures list far fewer crates than the real rules.
    pub fn run(&self) -> Run {
        self.run_with(&["--allow-missing-crates"])
    }

    /// Run the default mode, which requires every crate the rules file lists.
    pub fn run_default(&self) -> Run {
        self.run_with(&[])
    }

    pub fn run_with(&self, extra: &[&str]) -> Run {
        self.write_to_disk();
        let manifest = self.workspace_dir().join("Cargo.toml");
        let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .arg("check-architecture")
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--rules")
            .arg(self.rules_path())
            .args(extra)
            .current_dir(&self.dir)
            .env("CARGO_NET_OFFLINE", "true")
            .output()
            .expect("run the xtask binary");
        Run {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}
