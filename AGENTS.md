# AGENTS.md

Instructions for any agent that implements tasks in this repository.

## Finishing the work

Stay in the loop until all the work of the task is done. Do not stop at a partial result, and do
not hand the task back while a step you can do yourself is still open. Stop early only when the
task cannot move without the owner: a decision that is theirs alone, an access that was withheld
on purpose, or an action that is destructive or hard to reverse.

## Making decisions

At each design decision, list the real options and weigh every one of them. Choose the option
that gives the best architectural and business advantage. Do not choose an option only because
it is the simplest; simplicity counts when it serves the architecture or the business, and not
as a reason in itself. Record the options considered and the reason for the choice in the task
report or in an ADR.

## Documentation comes first

The `docs/` directory is the source of truth for the project. It holds all of the documentation:
the specifications, the architecture, the decisions (ADRs), the diagrams, the guides and the
reference. The code follows the documents, never the other way round.

- **Document first, then code.** Before you change code, or add or change a rule, update the
  documents that describe it. Then change the code to match. A change whose documents were not
  updated first is not done.
- **Keep it current.** When code and documents disagree, the documents describe the intent: fix
  the code, or, if the intent itself changed, update the documents first and then the code. Never
  leave a document that describes behaviour the code no longer has.
- **Organized.** Every document has one clear place in `docs/`, a clear title and a link from the
  index of its section. Do not scatter documents elsewhere in the repository, and do not keep two
  documents that say the same thing.
- **Written for humans.** Write for a person who reads the document for the first time: plain
  language, short sentences, the purpose first, then the details. Explain why, not only what.
  Prefer a diagram where it shows a flow or a structure better than prose, and keep its source
  in `docs/` beside the text.

## Code quality

The code must be:

- **Flexible and adaptable.** A new requirement should land as an addition or a replacement
  behind an existing boundary, not as a rewrite of its callers.
- **Cohesive.** Each module, type and function has one responsibility, and the things that
  change together live together.
- **Free of calculation errors.** This comes first. For every calculation, state the units,
  the rounding rule and the valid range; use types that cannot lose precision or overflow
  silently (no floating point for money or counts, checked or saturating integer arithmetic);
  and cover the boundaries with tests: zero, one, the maximum, negative input and the
  rounding edge.

## Testing while implementing a task

Run unit and integration tests only for what the task changed and for what is tied to it by a
dependency. Do not run the whole workspace suite during implementation. The owner set this rule
to shorten development time.

**In scope for a test run**

- The files, types (structs, classes, traits) and functions or methods the task changed.
- Their dependencies: the code the changed code calls, and the code that calls or depends on the
  changed code.
- The integration tests that exercise any of the above.

**Out of scope**

- Tests of crates, modules and files with no dependency link to the change.
- `cargo nextest run --workspace` and `cargo test --workspace` as a routine step of a task.

**How to narrow the run**

Use the narrowest selection that still covers the change:

| The change touches | Command |
|---|---|
| One function or module | `cargo nextest run -p <crate> <test-name-filter>` |
| One crate | `cargo nextest run -p <crate>` |
| A crate that other crates depend on | `cargo nextest run -E 'rdeps(<crate>)'` |
| Code covered by one integration test file | `cargo nextest run -p <crate> --test <file>` |
| Doc examples in a crate | `cargo test --doc -p <crate>` |

Find the changed files with `git diff --name-only <base>...HEAD` plus the uncommitted changes,
and map each one to its crate and tests before choosing the command.

**Reporting**

State in the task report which tests ran and how they were selected, so a reader can see that the
run was a targeted one and not the full suite. The full workspace suite stays in CI
(`scripts/ci.sh`).
