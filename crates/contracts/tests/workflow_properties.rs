//! Properties of the workflow classifier (threat T-48) over generated input: it never panics,
//! whatever the text, and a text it calls exposed always has a reason.

use factory_contracts::workflows::{classify, exposed_workflows};
use factory_ports::githost::WorkflowFile;
use proptest::prelude::*;

/// Pieces of real workflows and of YAML that the reader refuses, to reach the classifier's
/// branches more often than plain noise does.
fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("on:\n".to_owned()),
        Just("on: push\n".to_owned()),
        Just("  push:\n".to_owned()),
        Just("  pull_request:\n".to_owned()),
        Just("  pull_request_target:\n".to_owned()),
        Just("    branches: [main, 'factory/**']\n".to_owned()),
        Just("    branches-ignore:\n      - 'factory/**'\n".to_owned()),
        Just("permissions:\n  contents: read\n".to_owned()),
        Just("permissions: write-all\n".to_owned()),
        Just("jobs:\n".to_owned()),
        Just("  build:\n".to_owned()),
        Just("    runs-on: ubuntu-latest\n".to_owned()),
        Just("    runs-on: [self-hosted]\n".to_owned()),
        Just("    runs-on: ${{ matrix.os }}\n".to_owned()),
        Just("    uses: ./.github/workflows/x.yml\n    secrets: inherit\n".to_owned()),
        Just("    env:\n      KEY: ${{ secrets.KEY }}\n".to_owned()),
        Just("x: &a 1\ny: *a\n".to_owned()),
        Just("---\n".to_owned()),
        Just("? [a, b]\n: c\n".to_owned()),
        "\\PC{0,24}\n?",
        "[ \\t{}\\[\\]:,'\"|>&*!%#-]{0,12}",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn workflow_classifier_never_panics_on_arbitrary_text(
        text in "\\PC{0,400}",
        branch in "\\PC{0,20}",
    ) {
        if let Some(exposed) = classify(".github/workflows/w.yml", Some(&text), &branch) {
            prop_assert!(!exposed.reasons.is_empty());
        }
    }

    #[test]
    fn workflow_classifier_never_panics_on_pieces_of_workflows(
        pieces in prop::collection::vec(fragment(), 0..24),
        branch in "[a-z/*?!\\[\\]+.-]{0,12}",
    ) {
        let text = pieces.concat();
        let files = [
            WorkflowFile { path: "b.yml".to_owned(), text: Some(text) },
            WorkflowFile { path: "a.yml".to_owned(), text: None },
        ];
        let exposed = exposed_workflows(&files, &branch);
        prop_assert!(exposed.iter().all(|workflow| !workflow.reasons.is_empty()));
        // The file with no text is always exposed, and the list is ordered by path.
        prop_assert_eq!(exposed.first().map(|workflow| workflow.path.as_str()), Some("a.yml"));
    }
}
