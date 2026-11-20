# Rules for agents

These are the rules for every agent that works on this project: the agents of the software
factory, and any other coding agent. The factory installed them and keeps them up to date. The
rules of this project's own people follow after the factory's part of this file.

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
report or in a decision record under `docs/adr/`.

## Documentation comes first

The `docs/` directory is the source of truth for the project. It holds all of the documentation:
the specifications, the architecture, the decisions (decision records), the diagrams, the guides
and the reference. The code follows the documents, never the other way round.

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
- **Full words, not abbreviations.** In documentation and in code comments, write the whole word
  instead of a short form: "Rule", not "R"; "Test", not "T"; "Requirement", not "Req". Write
  each term the same way everywhere. A short identifier that the project itself defines (such as
  a requirement number or a decision record number) may be cited, but say once, in plain words,
  what it stands for.

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
dependency. Do not run the whole test suite of the project as a routine step of a task; the
full suite runs in the project's continuous integration.

**In scope for a test run**

- The files, types and functions or methods the task changed.
- Their dependencies: the code the changed code calls, and the code that calls or depends on the
  changed code.
- The integration tests that exercise any of the above.

**Out of scope**

- Tests of modules, packages and files with no dependency link to the change.

**How to narrow the run**

Take the test commands from the project: the commands of `.factory/project.yaml` when the
project has one, or else the project's build files. Use the narrowest selection those commands
allow that still covers the change: one test name or one test file, then one module or package,
then the packages that depend on a changed package. Find the changed files from the difference
with the base of the task, plus the uncommitted changes, and map each one to its tests before
you choose.

**Reporting**

State in the task report which tests ran and how they were selected, so a reader can see that the
run was a targeted one and not the full suite.
