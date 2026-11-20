//! A stage must not require a capability that no real adapter ever reports.
//!
//! The live-adapters run found that every stage asked the router for `JsonSchemaOutput`, while both
//! real adapters (`claude-code-cli` and `codex-cli`) report it as unsupported, on purpose: the tools
//! reject the factory's schemas, and the engine validates the bytes of the output (spike section
//! 4.7). With the capabilities a person declares (`runtimes.declare_capabilities`) the router found
//! a runtime, so the mismatch showed only with a real probe, and then no stage could be routed.
//!
//! This is a scan of the stage sources: no line of code of a stage may name `JsonSchemaOutput`, in
//! the `RoutingNeed` it builds, in the capabilities it checks the probe for when it opens its
//! sandbox, or in the fact it reports to the guard of the sandbox (`probe_satisfies_stage`). The enforcement of the output schema is the engine's own check
//! (`AgentOutputCheck`), which no capability stands for. The live test
//! `apps/api/tests/live_run.rs` routes every agent stage through the real probes. The scan sits in the
//! composition crate because the workflow crate does no file I/O, in its tests either.

use std::path::{Path, PathBuf};

fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a readable directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn no_stage_requires_the_capability_no_real_adapter_reports() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../workflow/src/stages");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(
        files.len() > 40,
        "the scan found the stages: {}",
        files.len()
    );
    let mut offenders = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a source file");
        for (number, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or(line);
            // A need, a sandbox check of the probe, or a guard fact: none may name it.
            if code.contains("JsonSchemaOutput") {
                offenders.push(format!("{}:{}", file.display(), number + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a stage requires JsonSchemaOutput, which no real adapter reports: {offenders:?}"
    );
}

#[test]
fn the_scan_sees_the_needs_it_guards() {
    // Break: the scan must be able to find a need at all, or it would pass on an empty search.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../workflow/src/stages");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let needs = files
        .iter()
        .map(|file| std::fs::read_to_string(file).expect("a source file"))
        .flat_map(|text| text.lines().map(str::to_owned).collect::<Vec<_>>())
        .filter(|line| line.contains("required:") && line.contains("Capability::"))
        .count();
    // Two today: the specification writer's need (one place since the writer and the reviewer of
    // the specification are built by `SpecificationHandler`) and the documenting writer's.
    assert!(
        needs >= 2,
        "the scan saw {needs} needs that name a capability"
    );
}
