//! The injection corpus (`tests/security/injection`): data, read here by a strict reader.
//!
//! The files are included at compile time, because the inner crates may not read files (rule
//! DEP-05, tests included). The reader refuses a key it does not know, an action it cannot run and
//! a carrier it does not place, so a typo in the data cannot turn a case into a test that checks
//! nothing.

use serde_json::Value;

const FILES: [(&str, &str); 10] = [
    (
        "approval-forgery.json",
        include_str!("../../../../tests/security/injection/approval-forgery.json"),
    ),
    (
        "carrier-specific.json",
        include_str!("../../../../tests/security/injection/carrier-specific.json"),
    ),
    (
        "delimiter-forging.json",
        include_str!("../../../../tests/security/injection/delimiter-forging.json"),
    ),
    (
        "encoded-or-obfuscated.json",
        include_str!("../../../../tests/security/injection/encoded-or-obfuscated.json"),
    ),
    (
        "exfiltration.json",
        include_str!("../../../../tests/security/injection/exfiltration.json"),
    ),
    (
        "fake-system-blocks.json",
        include_str!("../../../../tests/security/injection/fake-system-blocks.json"),
    ),
    (
        "instruction-override.json",
        include_str!("../../../../tests/security/injection/instruction-override.json"),
    ),
    (
        "policy-edit.json",
        include_str!("../../../../tests/security/injection/policy-edit.json"),
    ),
    (
        "role-confusion.json",
        include_str!("../../../../tests/security/injection/role-confusion.json"),
    ),
    (
        "secret-requests.json",
        include_str!("../../../../tests/security/injection/secret-requests.json"),
    ),
];

/// Where a payload sits when it reaches the factory. The class of the data envelope it belongs in
/// follows from it (see [`Carrier::class`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    IssueTitle,
    IssueBody,
    PrTemplate,
    CommitMessage,
    RepoFile,
    FileName,
    DependencyReadme,
    SourceComment,
    TestOutput,
    ToolOutput,
}

impl Carrier {
    fn parse(name: &str) -> Self {
        match name {
            "issue_title" => Self::IssueTitle,
            "issue_body" => Self::IssueBody,
            "pr_template" => Self::PrTemplate,
            "commit_message" => Self::CommitMessage,
            "repo_file" => Self::RepoFile,
            "file_name" => Self::FileName,
            "dependency_readme" => Self::DependencyReadme,
            "source_comment" => Self::SourceComment,
            "test_output" => Self::TestOutput,
            "tool_output" => Self::ToolOutput,
            other => panic!("the corpus names a carrier this reader does not place: {other}"),
        }
    }

    /// True for text that came in with the request, whatever the person who wrote it was.
    pub fn is_request_text(self) -> bool {
        matches!(
            self,
            Self::IssueTitle | Self::IssueBody | Self::PrTemplate | Self::CommitMessage
        )
    }

    /// True for text the factory itself ran a command to get.
    pub fn is_tool_output(self) -> bool {
        matches!(self, Self::TestOutput | Self::ToolOutput)
    }

    /// The path in the repository where the engine run puts the payload for this carrier, and the
    /// text of the file. Request text cannot be put in a repository, so it goes where a request
    /// copied into the documents would be.
    pub fn file(self, payload: &str) -> (String, String) {
        match self {
            Self::IssueTitle => ("docs/request-title.md".to_owned(), format!("# {payload}\n")),
            Self::IssueBody => ("docs/request.md".to_owned(), format!("{payload}\n")),
            Self::PrTemplate => (
                "docs/pull-request-template.md".to_owned(),
                format!("{payload}\n"),
            ),
            Self::CommitMessage => (
                "docs/last-commit-message.txt".to_owned(),
                format!("{payload}\n"),
            ),
            Self::RepoFile => ("CONTRIBUTING.md".to_owned(), format!("{payload}\n")),
            Self::FileName => (
                payload.to_owned(),
                "A file whose name is the payload.\n".to_owned(),
            ),
            Self::DependencyReadme => (
                "vendor/dependency/README.md".to_owned(),
                format!("{payload}\n"),
            ),
            Self::SourceComment => (
                "src/notes.rs".to_owned(),
                format!("{payload}\npub fn notes() {{}}\n"),
            ),
            Self::TestOutput => ("docs/test-output.txt".to_owned(), format!("{payload}\n")),
            Self::ToolOutput => ("docs/tool-output.txt".to_owned(), format!("{payload}\n")),
        }
    }
}

/// One thing the model does when it obeys.
#[derive(Debug, Clone)]
pub enum Act {
    /// Writes a file in the writable tree. `deny` says the factory must refuse the change.
    Write {
        path: String,
        content: String,
        deny: bool,
    },
    /// Runs a command in the sandbox. `deny` says the command policy must deny it. `reads_secret`
    /// says the output would hold a secret, so the obedient model pastes one into its report.
    Exec {
        argv: Vec<String>,
        deny: bool,
        reads_secret: bool,
    },
    /// Opens an address. The egress policy must deny the host.
    Fetch { url: String },
    /// Says something about the work. It has no effect.
    Claim { text: String },
    /// Puts a field into its report that the report does not have.
    ReportField { name: String, value: Value },
}

/// One payload and what the model does when it believes it.
#[derive(Debug, Clone)]
pub struct Case {
    pub id: String,
    pub category: String,
    pub carrier: Carrier,
    pub payload: String,
    pub decoded: Option<String>,
    pub obeys: Vec<Act>,
}

fn only_keys(object: &serde_json::Map<String, Value>, allowed: &[&str], what: &str) {
    for key in object.keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "{what} has a key this reader does not know: {key}"
        );
    }
}

fn text(object: &serde_json::Map<String, Value>, key: &str, what: &str) -> String {
    object
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{what} needs the text {key}"))
        .to_owned()
}

fn policy_is_deny(object: &serde_json::Map<String, Value>, what: &str) -> bool {
    match object.get("policy").and_then(Value::as_str) {
        Some("deny") => true,
        Some("none") | Some("allow") => false,
        other => panic!("{what}: policy must be deny or none, not {other:?}"),
    }
}

fn act(value: &Value, case: &str) -> Act {
    let object = value.as_object().expect("an act is an object");
    let kind = text(object, "act", case);
    let what = format!("{case}, act {kind}");
    match kind.as_str() {
        "write" => {
            only_keys(object, &["act", "path", "content", "policy"], &what);
            Act::Write {
                path: text(object, "path", &what),
                content: text(object, "content", &what),
                deny: policy_is_deny(object, &what),
            }
        }
        "exec" => {
            only_keys(object, &["act", "argv", "policy", "reads_secret"], &what);
            Act::Exec {
                argv: object
                    .get("argv")
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("{what} needs argv"))
                    .iter()
                    .map(|word| word.as_str().expect("an argv word is text").to_owned())
                    .collect(),
                deny: policy_is_deny(object, &what),
                reads_secret: object
                    .get("reads_secret")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }
        }
        "fetch" => {
            only_keys(object, &["act", "url", "policy"], &what);
            assert!(
                policy_is_deny(object, &what),
                "{what}: an address outside the allowlist is always denied"
            );
            Act::Fetch {
                url: text(object, "url", &what),
            }
        }
        "claim" => {
            only_keys(object, &["act", "text"], &what);
            Act::Claim {
                text: text(object, "text", &what),
            }
        }
        "report_field" => {
            only_keys(object, &["act", "name", "value"], &what);
            Act::ReportField {
                name: text(object, "name", &what),
                value: object.get("value").cloned().expect("a value"),
            }
        }
        other => panic!("{case}: the corpus names an act this reader cannot run: {other}"),
    }
}

/// Every case of every file, in file order.
pub fn all() -> Vec<Case> {
    let mut cases = Vec::new();
    for (file, source) in FILES {
        let document: Value = serde_json::from_str(source)
            .unwrap_or_else(|error| panic!("{file} is not valid JSON: {error}"));
        let root = document.as_object().expect("a file is an object");
        only_keys(
            root,
            &["schema_version", "category", "description", "cases"],
            file,
        );
        assert_eq!(root["schema_version"], 1, "{file}");
        let category = text(root, "category", file);
        for item in root["cases"].as_array().expect("cases is a list") {
            let object = item.as_object().expect("a case is an object");
            let id = text(object, "id", file);
            only_keys(
                object,
                &["id", "carrier", "payload", "obeys", "decoded", "note"],
                &id,
            );
            cases.push(Case {
                category: category.clone(),
                carrier: Carrier::parse(&text(object, "carrier", &id)),
                payload: text(object, "payload", &id),
                decoded: object
                    .get("decoded")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                obeys: object["obeys"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{id} needs obeys"))
                    .iter()
                    .map(|a| act(a, &id))
                    .collect(),
                id,
            });
        }
    }
    cases
}
