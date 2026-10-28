//! The repository map: what the stage learned about a repository, with where it learned each
//! fact, and the strict check that a map has the shape the schema describes.
//!
//! The map is JSON. `repository-map.v1.schema.json`, next to this file, is its schema, and
//! `repository-map.example.json` is a map that the tests of `factory-contracts` check against that
//! schema. [`validate`] is the same check in code that `workflow` can run: it refuses any field the
//! schema does not name, any value of the wrong kind, and any claim that has no provenance. Every
//! claim carries `path`, `commit_sha` and `line_range`, and the commit is the one in the map.

use factory_ports::paths::RepoPath;
use serde_json::{Map, Value, json};

use super::codeowners::OwnerRule;
use super::detect::{CommandChoice, Detection, NoCommand, Place};

/// The schema version of the map.
pub const SCHEMA_VERSION: u64 = 1;

/// The most entries of the file list. A repository with more is truncated and says so.
pub const MAX_LISTED_FILES: usize = 400;

/// What kind of kind a value must be.
enum Shape {
    Text,
    Number,
    Flag,
    Commit,
    Place,
    List(&'static Shape),
    Object(&'static [(&'static str, Shape)]),
    Optional(&'static Shape),
    OneOf(&'static [&'static str]),
}

const TEXT_LIST: Shape = Shape::List(&Shape::Text);

const NAMED_PLACE: Shape = Shape::Object(&[("name", Shape::Text), ("evidence", Shape::Place)]);
const LANGUAGE: Shape = Shape::Object(&[
    ("name", Shape::Text),
    ("files", Shape::Number),
    ("evidence", Shape::Place),
]);
const COMMAND: Shape = Shape::Object(&[
    ("role", Shape::OneOf(&["build", "test"])),
    ("argv", TEXT_LIST),
    ("origin", Shape::OneOf(&["project-manifest", "detected"])),
    ("timeout_seconds", Shape::Number),
    ("evidence", Shape::Place),
]);
const OWNER: Shape = Shape::Object(&[
    ("pattern", Shape::Text),
    ("owners", TEXT_LIST),
    ("evidence", Shape::Place),
]);
const PROTECTED: Shape = Shape::Object(&[
    ("pattern", Shape::Text),
    (
        "mode",
        Shape::OneOf(&["deny_write", "append_only", "additions_only", "sensitive"]),
    ),
    ("origin", Shape::OneOf(&["project-manifest", "policy"])),
    ("evidence", Shape::Optional(&Shape::Place)),
]);
const FILE: Shape = Shape::Object(&[
    ("path", Shape::Text),
    (
        "role",
        Shape::OneOf(&["manifest", "source", "test", "document", "configuration"]),
    ),
    ("evidence", Shape::Place),
]);
const TEST_LINK: Shape = Shape::Object(&[
    ("test", Shape::Text),
    ("covers", TEXT_LIST),
    ("evidence", Shape::Place),
]);
const DOCUMENT: Shape = Shape::Object(&[
    ("path", Shape::Text),
    (
        "kind",
        Shape::OneOf(&["readme", "decision", "guide", "contributing"]),
    ),
    ("title", Shape::Optional(&Shape::Text)),
    ("evidence", Shape::Place),
]);
const EXCLUDED: Shape = Shape::Object(&[
    ("path", Shape::Text),
    ("reason", Shape::OneOf(&["hidden-by-policy"])),
]);
const MANIFEST: Shape = Shape::Object(&[
    ("path", Shape::Text),
    ("sha256", Shape::Text),
    ("evidence", Shape::Place),
]);
const BLOCKED: Shape = Shape::Object(&[("code", Shape::Text), ("missing", Shape::Text)]);
const BASELINE: Shape = Shape::Object(&[
    ("status", Shape::OneOf(&["ready", "blocked"])),
    ("toolchain", Shape::Optional(&Shape::Text)),
    ("blocked", Shape::Optional(&BLOCKED)),
]);
const COUNTS: Shape = Shape::Object(&[
    ("files_seen", Shape::Number),
    ("files_listed", Shape::Number),
    ("truncated", Shape::Flag),
]);

const MAP: Shape = Shape::Object(&[
    ("schema_version", Shape::Number),
    ("repository", Shape::Text),
    ("commit_sha", Shape::Commit),
    ("languages", Shape::List(&LANGUAGE)),
    ("build_systems", Shape::List(&NAMED_PLACE)),
    ("commands", Shape::List(&COMMAND)),
    ("codeowners", Shape::List(&OWNER)),
    ("protected_paths", Shape::List(&PROTECTED)),
    ("files", Shape::List(&FILE)),
    ("test_mapping", Shape::List(&TEST_LINK)),
    ("documents", Shape::List(&DOCUMENT)),
    ("excluded_paths", Shape::List(&EXCLUDED)),
    ("project_manifest", Shape::Optional(&MANIFEST)),
    ("baseline", BASELINE),
    ("counts", COUNTS),
]);

/// Why a map is not accepted. The set is closed and carries no text of the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MapProblem {
    /// A field is missing, unknown, or of the wrong kind, or a value is outside its set.
    #[error("the repository map does not have the shape of its schema")]
    Shape,
    /// A claim has no provenance, or its provenance names another commit or an unsafe path.
    #[error("a claim of the repository map has no usable provenance")]
    Provenance,
}

fn conforms(shape: &Shape, value: &Value, commit: &str) -> Result<(), MapProblem> {
    match shape {
        Shape::Text => value.as_str().map(|_| ()).ok_or(MapProblem::Shape),
        Shape::Number => value.as_u64().map(|_| ()).ok_or(MapProblem::Shape),
        Shape::Flag => value.as_bool().map(|_| ()).ok_or(MapProblem::Shape),
        Shape::Commit => {
            let text = value.as_str().ok_or(MapProblem::Shape)?;
            if text.len() == 40
                && text
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                Ok(())
            } else {
                Err(MapProblem::Shape)
            }
        }
        Shape::Place => place(value, commit),
        Shape::List(inner) => {
            let items = value.as_array().ok_or(MapProblem::Shape)?;
            items
                .iter()
                .try_for_each(|item| conforms(inner, item, commit))
        }
        Shape::Object(fields) => {
            let object = value.as_object().ok_or(MapProblem::Shape)?;
            if object
                .keys()
                .any(|key| !fields.iter().any(|(name, _)| name == key))
            {
                return Err(MapProblem::Shape);
            }
            for (name, inner) in *fields {
                match object.get(*name) {
                    Some(found) => conforms(inner, found, commit)?,
                    None if matches!(inner, Shape::Optional(_)) => {}
                    None => return Err(MapProblem::Shape),
                }
            }
            Ok(())
        }
        Shape::Optional(inner) => conforms(inner, value, commit),
        Shape::OneOf(words) => value
            .as_str()
            .filter(|text| words.contains(text))
            .map(|_| ())
            .ok_or(MapProblem::Shape),
    }
}

fn place(value: &Value, commit: &str) -> Result<(), MapProblem> {
    let object = value.as_object().ok_or(MapProblem::Provenance)?;
    if object.len() != 3 {
        return Err(MapProblem::Provenance);
    }
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or(MapProblem::Provenance)?;
    RepoPath::new(path).map_err(|_| MapProblem::Provenance)?;
    if object.get("commit_sha").and_then(Value::as_str) != Some(commit) {
        return Err(MapProblem::Provenance);
    }
    let range = object
        .get("line_range")
        .and_then(Value::as_object)
        .ok_or(MapProblem::Provenance)?;
    let start = range.get("start").and_then(Value::as_u64);
    let end = range.get("end").and_then(Value::as_u64);
    match (start, end) {
        (Some(start), Some(end)) if range.len() == 2 && start >= 1 && end >= start => Ok(()),
        _ => Err(MapProblem::Provenance),
    }
}

/// Checks that `value` is a repository map.
///
/// # Errors
/// [`MapProblem`].
pub fn validate(value: &Value) -> Result<(), MapProblem> {
    if value.get("schema_version").and_then(Value::as_u64) != Some(SCHEMA_VERSION) {
        return Err(MapProblem::Shape);
    }
    let commit = value
        .get("commit_sha")
        .and_then(Value::as_str)
        .ok_or(MapProblem::Shape)?
        .to_owned();
    conforms(&MAP, value, &commit)?;
    // A path in the file list, the documents and the excluded list must be safe as well.
    for key in ["files", "documents", "excluded_paths"] {
        for item in value
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let path = item
                .get("path")
                .and_then(Value::as_str)
                .ok_or(MapProblem::Shape)?;
            RepoPath::new(path).map_err(|_| MapProblem::Provenance)?;
        }
    }
    Ok(())
}

/// A place as the JSON of the map.
#[must_use]
pub fn evidence(place: &Place, commit: &str) -> Value {
    json!({
        "path": place.path,
        "commit_sha": commit,
        "line_range": { "start": place.start, "end": place.end },
    })
}

/// A command as the JSON of the map.
#[must_use]
pub fn command_json(command: &CommandChoice, commit: &str) -> Value {
    json!({
        "role": command.role,
        "argv": command.argv,
        "origin": command.origin,
        "timeout_seconds": command.timeout_seconds,
        "evidence": evidence(&command.place, commit),
    })
}

/// The owners of a CODEOWNERS file as the JSON of the map.
#[must_use]
pub fn owners_json(path: &str, rules: &[OwnerRule], commit: &str) -> Vec<Value> {
    rules
        .iter()
        .map(|rule| {
            json!({
                "pattern": rule.pattern,
                "owners": rule.owners,
                "evidence": evidence(
                    &Place { path: path.to_owned(), start: rule.line, end: rule.line },
                    commit,
                ),
            })
        })
        .collect()
}

/// The part of detection that goes in the map before the commands are settled.
#[must_use]
pub fn detection_json(detection: &Detection, commit: &str) -> (Vec<Value>, Vec<Value>) {
    let languages = detection
        .languages
        .iter()
        .map(|(name, files, place)| {
            json!({ "name": name, "files": files, "evidence": evidence(place, commit) })
        })
        .collect();
    let systems = detection
        .systems
        .iter()
        .map(|(name, place)| json!({ "name": name, "evidence": evidence(place, commit) }))
        .collect();
    (languages, systems)
}

/// The baseline section of the map.
#[must_use]
pub fn baseline_json(commands: &[CommandChoice], none: Option<NoCommand>) -> Value {
    let mut section = Map::new();
    match (commands.first(), none) {
        (Some(first), _) => {
            section.insert("status".into(), json!("ready"));
            section.insert("toolchain".into(), json!(first.toolchain));
        }
        (None, reason) => {
            let reason = reason.unwrap_or(NoCommand::NothingRecognised);
            section.insert("status".into(), json!("blocked"));
            section.insert(
                "blocked".into(),
                json!({ "code": reason.code(), "missing": reason.missing() }),
            );
        }
    }
    Value::Object(section)
}

fn cite(value: &Value) -> String {
    let path = value["path"].as_str().unwrap_or("?");
    let start = value["line_range"]["start"].as_u64().unwrap_or(1);
    let end = value["line_range"]["end"].as_u64().unwrap_or(start);
    if start == end {
        format!("[{path}:{start}]")
    } else {
        format!("[{path}:{start}-{end}]")
    }
}

/// A compact summary of the map in Markdown, with a citation after each fact. It is built from the
/// map and from nothing else, and it holds the names of files the model may not read but never
/// their content.
#[must_use]
pub fn summary(map: &Value, readme_title: Option<&str>) -> String {
    let mut text = String::new();
    let repository = map["repository"].as_str().unwrap_or("the repository");
    let commit = map["commit_sha"].as_str().unwrap_or("");
    text.push_str(&format!(
        "# Repository summary\n\nThis summary describes {repository} at commit {}. Each fact ends with the file and lines it was read from.\n\n",
        commit.get(..10).unwrap_or(commit)
    ));
    for language in map["languages"].as_array().into_iter().flatten().take(5) {
        text.push_str(&format!(
            "- Language: {} ({} files) {}\n",
            language["name"].as_str().unwrap_or("?"),
            language["files"],
            cite(&language["evidence"])
        ));
    }
    for system in map["build_systems"].as_array().into_iter().flatten() {
        text.push_str(&format!(
            "- Build system: {} {}\n",
            system["name"].as_str().unwrap_or("?"),
            cite(&system["evidence"])
        ));
    }
    for command in map["commands"].as_array().into_iter().flatten() {
        let argv: Vec<&str> = command["argv"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        text.push_str(&format!(
            "- {} command: `{}` ({}) {}\n",
            capitalise(command["role"].as_str().unwrap_or("?")),
            argv.join(" "),
            command["origin"].as_str().unwrap_or("?"),
            cite(&command["evidence"])
        ));
    }
    if let Some(blocked) = map["baseline"]["blocked"].as_object() {
        text.push_str(&format!(
            "- No build or test command could be found: {}\n",
            blocked
                .get("missing")
                .and_then(Value::as_str)
                .unwrap_or("?")
        ));
    }
    for owner in map["codeowners"].as_array().into_iter().flatten().take(8) {
        let owners: Vec<&str> = owner["owners"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        text.push_str(&format!(
            "- Owners of `{}`: {} {}\n",
            owner["pattern"].as_str().unwrap_or("?"),
            owners.join(", "),
            cite(&owner["evidence"])
        ));
    }
    let protected: Vec<&str> = map["protected_paths"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p["pattern"].as_str())
        .take(12)
        .collect();
    if !protected.is_empty() {
        text.push_str(&format!("- Protected paths: {}\n", protected.join(", ")));
    }
    for document in map["documents"].as_array().into_iter().flatten().take(8) {
        text.push_str(&format!(
            "- Document: {} ({}) {}\n",
            document["path"].as_str().unwrap_or("?"),
            document["kind"].as_str().unwrap_or("?"),
            cite(&document["evidence"])
        ));
    }
    if let Some(title) = readme_title {
        text.push_str(&format!("- The README begins: {title}\n"));
    }
    let excluded = map["excluded_paths"].as_array().map_or(0, Vec::len);
    if excluded > 0 {
        text.push_str(&format!(
            "\n{excluded} paths are kept out of model context because the policy hides them. Only their names are in the map.\n"
        ));
    }
    text
}

fn capitalise(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}
