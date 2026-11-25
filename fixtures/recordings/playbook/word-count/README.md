# Scripted playbook for the word-count fixture

These files are what a competent agent would answer, for each of the nine agents of the factory,
when the request is the one the fixture is used for: add a `--json` option to the `word-count`
tool. They are **scripted**. No model wrote them and no model is called when they are used. A
run that hands them out says so: the runtime that plays them reports itself as a stand-in.

The loader and the runtime that play them are in `apps/api/tests/playbook/`. The runtime gives
each agent its answer by role, writes the files the agent would write into the checkout of its
sandbox, and stops the test with a plain message when it is asked for something these files do
not hold.

| Path | What it is |
|---|---|
| `constitution.md` | The project constitution the fixture repository must hold before the specification stage runs. The factory only checks that it exists; a person owns it. |
| `specification/` | The Spec Kit files the specify and checklist skills leave: `spec.md`, the two checklists and the active-feature pointer. Words in double braces are filled in by the runtime (the feature directory, the title, the fixed instruction the skill was given). |
| `agent-output/*.json` | The final answer of each agent, in the form of its own output schema. `builder.<task>.json` is one per task of the plan. The planner's answer takes its metadata and its scenario identifiers from the prompt it receives, as a real planner is told to. |
| `patch/` | The builder's change to the fixture: whole files, as they are once the task is done. The change was run against the fixture's own checks (formatting, the linter with warnings as errors, build and tests) on a real toolchain when it was written. |
| `docs/` | The README and the changelog the documentation writer leaves. |
| `sandbox/` | What the programs of the verify image printed, recorded from a real run of the patched tool and of the unpatched one. The scripted sandbox plays them back. `word-count-notes.txt`, `word-count--json-notes.txt` and `word-count-stdin.txt` are the patched tool's output for the three examples of the README, run from the root of the fixture with its `notes.txt`, as the documentation gate runs them (documentation policy 9.10). |

## How the files were made

The patch and the recorded outputs come from real commands: `cargo fmt --check`,
`cargo clippy --all-targets --locked -- -D warnings`, `cargo build --locked` and
`cargo test --locked` on a copy of `fixtures/repos/word-count` with the patch applied, with the
network off. The host paths in the recorded output were replaced by the paths of the verify
sandbox (`/workspace`, `/out/target`).

Nothing here is a secret, and no file holds a token, a key or a URL with a password.
