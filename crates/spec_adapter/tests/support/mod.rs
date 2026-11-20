//! Shared helpers of the adapter tests: the recorded files, a builder for a set of committed
//! files, and a provider over the Claude Code host.
#![allow(dead_code)]

use factory_domain::ids::JobId;
use factory_domain::values::Slug;
use factory_domain::vocabulary::ExecutionMode;
use factory_ports::paths::{CommitSha, RepoPath};
use factory_ports::spec::{
    FeatureDir, SpecFile, SpecFileSet, SpecOperation, SpecRequest, SpecificationProvider,
};
use factory_spec_adapter::invocation::{FixedInstruction, Host, Separator, Sources};
use factory_spec_adapter::{SpecKitConfig, SpecKitProvider};

mod recorded;

pub use recorded::RECORDED;

pub const FEATURE: &str = "specs/001-end-to-end-mvp";
pub const REQUEST: &str = "inputs/request.md";
pub const REQUEST_TEXT: &str = "Add a JSON output flag to the word count tool.";

pub fn feature() -> FeatureDir {
    FeatureDir::new(FEATURE).expect("a feature directory")
}

pub fn path(text: &str) -> RepoPath {
    RepoPath::new(text).expect("a path")
}

pub fn commit() -> CommitSha {
    CommitSha::parse(&"a".repeat(40)).expect("a commit")
}

pub fn job() -> JobId {
    JobId::from_uuid(uuid_text("018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f40"))
}

fn uuid_text(text: &str) -> uuid::Uuid {
    uuid::Uuid::parse_str(text).expect("a uuid")
}

pub fn request(op: SpecOperation) -> SpecRequest {
    SpecRequest {
        job: job(),
        op,
        feature_directory: feature(),
        request_file: path(REQUEST),
        answers: Vec::new(),
        revision: None,
        rework: None,
        resume: None,
        self_check: None,
    }
}

pub fn instruction() -> FixedInstruction {
    FixedInstruction::build(
        SpecOperation::Specify,
        &feature(),
        &path(REQUEST),
        &Sources::default(),
    )
    .expect("an instruction")
}

/// A set of committed files that starts as the recording and can be edited.
#[derive(Clone)]
pub struct Files(Vec<SpecFile>);

impl Files {
    /// The recorded files, plus the request file the stage hands over for its hash.
    pub fn recorded() -> Self {
        let mut files: Vec<SpecFile> = RECORDED
            .iter()
            .map(|(p, bytes)| SpecFile {
                path: path(p),
                bytes: bytes.to_vec(),
            })
            .collect();
        files.push(SpecFile {
            path: path(REQUEST),
            bytes: REQUEST_TEXT.as_bytes().to_vec(),
        });
        Self(files)
    }

    /// The recording with the specification made traceable: the `Input` line is the fixed
    /// instruction and every scenario cites a requirement. This is not Spec Kit output. It is
    /// the shape the writer prompt must ask for, so that the contract can be built.
    pub fn linked() -> Self {
        let mut files = Self::recorded();
        let spec = String::from_utf8(files.get(&format!("{FEATURE}/spec.md")).to_vec())
            .expect("the specification is text");
        files.set(&format!("{FEATURE}/spec.md"), link(&spec).as_bytes());
        files
    }

    pub fn get(&self, p: &str) -> &[u8] {
        &self
            .0
            .iter()
            .find(|f| f.path.as_str() == p)
            .unwrap_or_else(|| panic!("{p} is not in the set"))
            .bytes
    }

    pub fn set(&mut self, p: &str, bytes: &[u8]) -> &mut Self {
        match self.0.iter_mut().find(|f| f.path.as_str() == p) {
            Some(file) => file.bytes = bytes.to_vec(),
            None => self.0.push(SpecFile {
                path: path(p),
                bytes: bytes.to_vec(),
            }),
        }
        self
    }

    pub fn remove(&mut self, p: &str) -> &mut Self {
        self.0.retain(|f| f.path.as_str() != p);
        self
    }

    pub fn edit_spec(&mut self, edit: impl FnOnce(String) -> String) -> &mut Self {
        let key = format!("{FEATURE}/spec.md");
        let text = String::from_utf8(self.get(&key).to_vec()).expect("text");
        self.set(&key, edit(text).as_bytes());
        self
    }

    pub fn build(&self) -> SpecFileSet {
        SpecFileSet {
            commit: commit(),
            files: self.0.clone(),
        }
    }
}

/// The requirement identifiers of a specification text, in file order.
pub fn requirement_ids(spec: &str) -> Vec<String> {
    spec.lines()
        .filter_map(|line| line.strip_prefix("- **FR-"))
        .filter_map(|rest| rest.split("**").next())
        .map(|digits| format!("FR-{digits}"))
        .collect()
}

/// Makes the recorded specification traceable and puts the fixed instruction in the `Input` line.
pub fn link(spec: &str) -> String {
    let ids = requirement_ids(spec);
    let mut next = 0usize;
    let mut out = String::new();
    for line in spec.lines() {
        if line.starts_with("**Input**:") {
            out.push_str(&format!(
                "**Input**: User description: \"{}\"\n",
                instruction().as_str()
            ));
        } else if line.contains("**Given**") && line.contains("**Then**") {
            out.push_str(&format!("{line} ({})\n", ids[next % ids.len()]));
            next += 1;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

pub fn provider() -> SpecKitProvider {
    SpecKitProvider::new(SpecKitConfig {
        host: Host::ClaudeCode,
        separator: Separator::parse("-").expect("a separator"),
        mode: ExecutionMode::Test,
        fallback_adapter: Slug::parse("claude-code-cli").expect("a slug"),
        fallback_adapter_version: "2.1.311".to_owned(),
    })
}

pub fn assemble(
    provider: &SpecKitProvider,
    op: SpecOperation,
    files: &Files,
) -> Result<factory_ports::spec::SpecOutcome, factory_ports::spec::SpecError> {
    provider.assemble(&request(op), &files.build())
}
