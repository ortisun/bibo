//! Every public trait of the ports states its contract: preconditions, postconditions, closed
//! error set, idempotency, and (since ports v1.1) cancellation and timeouts (done criterion 5 of
//! work package `s0-ports-and-testkit`).
//!
//! The test reads the port sources, finds each `pub trait` and checks its documentation for five
//! headings, each followed by text. The sources are embedded with `include_str!`, so the test does
//! no file I/O. The checker has tests of its own, so it is known to fail on a bad trait.

const SOURCES: [(&str, &str); 11] = [
    ("agent.rs", include_str!("../src/agent.rs")),
    ("artifact.rs", include_str!("../src/artifact.rs")),
    ("clock.rs", include_str!("../src/clock.rs")),
    ("githost.rs", include_str!("../src/githost.rs")),
    ("paths.rs", include_str!("../src/paths.rs")),
    ("process.rs", include_str!("../src/process.rs")),
    ("registry.rs", include_str!("../src/registry.rs")),
    ("sandbox.rs", include_str!("../src/sandbox.rs")),
    ("spec.rs", include_str!("../src/spec.rs")),
    ("store.rs", include_str!("../src/store.rs")),
    ("workspace.rs", include_str!("../src/workspace.rs")),
];

/// The ports of work package `s0-ports-and-testkit`, plus the parts of `Tx`, and what ports v1.1
/// adds: the read-only system transaction, the job repository, the process runner, the webhook
/// verifier and the metering seam.
const EXPECTED_TRAITS: [&str; 37] = [
    "Clock",
    "IdGenerator",
    "CancelSignal",
    "Store",
    "SystemTx",
    "Tx",
    "JobOps",
    "RequestOps",
    "DeliveryOps",
    "RepositoryOps",
    "StageRunOps",
    "AttemptOps",
    "TaskNodeOps",
    "StageArtifactOps",
    "ApprovalOps",
    "LedgerOps",
    "OutboxOps",
    "AuditOps",
    "ArtifactIndexOps",
    "PrincipalOps",
    "ArtifactStore",
    "SandboxProvider",
    "SandboxSession",
    "WorkspaceProvider",
    "JobRepo",
    "Workspace",
    "ProcessRunner",
    "WebhookVerifier",
    "MeteringOps",
    "AgentRuntime",
    "ModelRouter",
    "ModelBroker",
    "AgentRegistry",
    "OutputValidator",
    "SpecificationProvider",
    "IssueSource",
    "ChangeHost",
];

const HEADINGS: [&str; 5] = [
    "# Preconditions",
    "# Postconditions",
    "# Errors",
    "# Idempotency",
    "# Cancellation and timeouts",
];

/// One public trait found in a source, with its documentation text.
struct DocumentedTrait {
    name: String,
    doc: Vec<String>,
}

fn find_traits(source: &str) -> Vec<DocumentedTrait> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(rest) = line.trim_start().strip_prefix("pub trait ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        // Walk upward over attribute lines, then collect the `///` lines directly above.
        let mut doc = Vec::new();
        let mut above = index;
        while above > 0 {
            let previous = lines[above - 1].trim_start();
            if previous.starts_with("#[") {
                above -= 1;
            } else if let Some(text) = previous.strip_prefix("///") {
                doc.push(text.trim().to_owned());
                above -= 1;
            } else {
                break;
            }
        }
        doc.reverse();
        found.push(DocumentedTrait { name, doc });
    }
    found
}

/// Problems with the documentation of the traits in `source`, in plain English.
fn trait_doc_problems(source: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for item in find_traits(source) {
        for heading in HEADINGS {
            match item.doc.iter().position(|line| line == heading) {
                None => problems.push(format!("trait {} has no `{heading}` section", item.name)),
                Some(at) => {
                    let has_text = item.doc[at + 1..]
                        .iter()
                        .take_while(|line| !line.starts_with("# "))
                        .any(|line| !line.is_empty());
                    if !has_text {
                        problems.push(format!(
                            "trait {} has an empty `{heading}` section",
                            item.name
                        ));
                    }
                }
            }
        }
    }
    problems
}

#[test]
fn trait_docs_state_the_contract() {
    let mut problems = Vec::new();
    let mut seen = Vec::new();
    for (file, source) in SOURCES {
        problems.extend(
            trait_doc_problems(source)
                .into_iter()
                .map(|problem| format!("{file}: {problem}")),
        );
        seen.extend(find_traits(source).into_iter().map(|item| item.name));
    }
    for expected in EXPECTED_TRAITS {
        if !seen.iter().any(|name| name == expected) {
            problems.push(format!("the port trait {expected} was not found"));
        }
    }
    for name in &seen {
        if !EXPECTED_TRAITS.contains(&name.as_str()) {
            problems.push(format!(
                "trait {name} is public but not in the list of ports this test knows; add it so its contract is checked"
            ));
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn the_checker_reports_a_trait_with_no_documentation() {
    let source = "pub trait Bare {\n    fn go(&self);\n}\n";
    let problems = trait_doc_problems(source);
    assert_eq!(problems.len(), 5, "{problems:?}");
    assert!(problems[0].contains("trait Bare has no `# Preconditions`"));
}

#[test]
fn the_checker_reports_a_missing_idempotency_section() {
    let source = "\
/// Does a thing.
///
/// # Preconditions
/// None.
///
/// # Postconditions
/// Done.
///
/// # Errors
/// None.
///
/// # Cancellation and timeouts
/// None.
pub trait Almost {}
";
    let problems = trait_doc_problems(source);
    assert_eq!(
        problems,
        vec!["trait Almost has no `# Idempotency` section"]
    );
}

#[test]
fn the_checker_reports_an_empty_section() {
    let source = "\
/// Does a thing.
///
/// # Preconditions
/// None.
///
/// # Postconditions
///
/// # Errors
/// None.
///
/// # Idempotency
/// Yes.
///
/// # Cancellation and timeouts
/// None.
pub trait Hollow {}
";
    let problems = trait_doc_problems(source);
    assert_eq!(
        problems,
        vec!["trait Hollow has an empty `# Postconditions` section"]
    );
}

#[test]
fn the_checker_reads_through_attributes_and_accepts_a_full_contract() {
    let source = "\
/// Does a thing.
///
/// # Preconditions
/// None.
///
/// # Postconditions
/// Done.
///
/// # Errors
/// None.
///
/// # Idempotency
/// Yes.
///
/// # Cancellation and timeouts
/// None.
#[async_trait]
pub trait Whole {}
";
    assert!(trait_doc_problems(source).is_empty());
}

#[test]
fn the_checker_reports_a_missing_cancellation_section() {
    let source = "\
/// Does a thing.
///
/// # Preconditions
/// None.
///
/// # Postconditions
/// Done.
///
/// # Errors
/// None.
///
/// # Idempotency
/// Yes.
pub trait Unbounded {}
";
    assert_eq!(
        trait_doc_problems(source),
        vec!["trait Unbounded has no `# Cancellation and timeouts` section"]
    );
}
