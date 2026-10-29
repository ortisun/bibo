# Documentation checks

- Status: describes `scripts/docs-check.sh` and `docs/reference/tools/docs_check.py` as they are on 2026-10-29.
- Form: reference.
- Goal: say what each check reads, what it accepts, and how to write a page so that it passes.

The factory applies a documentation gate to the documents it writes for others. `scripts/docs-check.sh` applies the same kind of gate to the documents of this repository that the documentation work package owns: `README.md`, and every Markdown file under `docs/guides`, `docs/runbooks`, `docs/reference` and `docs/walkthroughs`. The [documentation policy](documentation-policy.md) says why.

## The modes

| Mode | What it checks |
|---|---|
| none | Every check below except `--quickstart`. |
| `--links` | Every relative link resolves, with `cargo xtask check-links`. |
| `--snippets` | Every shell block is marked, and every block marked `run` executes and prints what the page says. |
| `--commands` | Every command, option, endpoint, decision verb, exit code and path that the pages name exists. |
| `--config-keys` | Every configuration key in the code is documented and every documented key exists. |
| `--walkthrough` | Every step of the walkthrough cites a recorded file or ledger entry that holds what the step says. |
| `--readability` | The factory's readability gate reports no blocking finding and no warning. |
| `--self-test` | Each check fails on an input that is broken on purpose. |
| `--quickstart` | A clone of the repository runs the steps of the quickstart. |
| `--refresh-walkthrough` | Rewrites the ids and hashes of the ledger citations after the recordings change. |

Each check ends as `PASSED`, `FAILED`, `BLOCKED` or `NOT_APPLICABLE`, with the meaning that `scripts/ci.sh` gives them. The exit code is 0 when all passed, 1 when one failed, 2 for wrong use and 3 when nothing failed and something is BLOCKED. A check that cannot run is never a pass.

## Marking a shell block

A fenced block in `bash`, `sh`, `shell`, `zsh` or `console` must say what happens to it. The words go after the language.

| Mark | Meaning |
|---|---|
| `run` | `--snippets` runs the block in the repository root with `bash -euo pipefail`. |
| `quickstart` | `--quickstart` runs the block in a clean clone, in document order. |
| `no-run reason="..."` | The block is not run, and the reason says why. A `no-run` with no reason fails. |

Other words give details.

| Word | Meaning |
|---|---|
| `expect="text"` | The output must contain the text. Give it more than once to require more than one text. |
| `exit=N` | The block must end with this exit code. The default is 0. |
| `timeout=N` | The most seconds the block may take. The default is 120 for `run` and 1200 for `quickstart`. |
| `needs=docker` | The Docker daemon must answer. If it does not, the block is BLOCKED. |
| `needs=docker-cli` | The `docker` command and its Compose plugin must exist. |
| `needs=postgres` | PostgreSQL 18 binaries, or `FACTORY_DB_ADMIN_URL`, must exist. |
| `step=name` | The name shown in the result of `--quickstart`. |

## What `--commands` reads

It reads the command lines in shell blocks and the inline code that starts like a command: `factory-cli`, `factory-worker`, `factory-api`, `factory-egress-sidecar`, `scripts/`, `cargo` and `python3 -I`. For each line it checks the following.

- `factory-cli`: the command exists in `factory-cli --help`, and every option is on the help line of that command.
- A script named `scripts/<name>.sh`: the script exists, and every option is in the output of its `--help`.
- `cargo xtask`: the command and its options are in `cargo xtask --help`.
- `cargo`: the subcommand is in `cargo --list`.
- Any path that starts with a repository directory exists.

It also reads four tables of `docs/reference/commands.md`, in both directions. The first cell of each table names it.

| First cell | Compared with |
|---|---|
| `Command` | The commands and options of `factory-cli --help`. |
| `Endpoint` | The paths and methods of `apps/api/openapi.json`. |
| `Verb` | The decision verbs of the `Decision` schema in `apps/api/openapi.json`. |
| `Exit code` | The exit codes in the help text of `factory-cli`. |
| `Worker line` | The `BLOCKED:` lines that the worker prints, from the two lists in `crates/composition/src/assemble.rs`. |

## What `--config-keys` reads

It reads the Rust structures that derive `Deserialize` in `crates/composition/src/config.rs` and `apps/api/src/config.rs`, starting from `FactoryConfig` for the worker and `ApiConfig` for the API. It follows the field types and builds the list of dotted keys. It compares that list with the tables of `docs/reference/configuration.md` in both directions.

A table is read when its first header cell is `Key`. A table under a heading that starts with "Worker" belongs to the worker, and one under "API" to the API. Each row needs the columns `Type`, `Required` and `Default`. For a key that exists in both places the check compares:

- the type, using the words `text`, `path`, `secret file`, `whole number`, `number`, `true or false`, `address`, `profile`, `table`, `map of text to text` and `list of ...`;
- whether the key is required: `yes` when the code gives it no default, and `no` or `production` otherwise;
- the default, when a function with a plain number or word gives it.

The environment variables are the `FACTORY_` names written as string literals in the configuration and application sources. The table under the heading "Environment variables" lists them.

## What `--walkthrough` reads

A walkthrough page carries the words `TEST MODE` in its first 12 lines. Each step is a `###` heading. A step must cite at least one recorded file or ledger entry. A citation is an inline code span in one of these forms.

| Form | Checks |
|---|---|
| `ledger E4 #13 id=7d7c9a6c hash=725b2e2a0a62 has="text"` | The ledger of scenario E4 has an entry with sequence 13, an identifier that starts with the id, a hash that starts with the hash, and, when `has` is given, a statement that contains the text. |
| `timeline E4 #29 stage_run.waiting_for_human` | The timeline of scenario E4 has this event or action at this position. |
| `json E4/mode.json cost_micro_usd=0` | The file `fixtures/recordings/e2e/E4/mode.json` holds this value at this dotted path. A list index is a number. |

Any path that starts with `fixtures/recordings/` in the text must exist. After a new run of `scripts/e2e.sh` writes the recordings again, run `scripts/docs-check.sh --refresh-walkthrough`. It rewrites the id and the hash of each ledger citation from its sequence number. A person then reads the diff, because a recording that changed shape can make a sentence untrue.

## What `--quickstart` does

It clones the repository into a scratch directory at the commit of the current checkout, checks out that commit, and runs each block marked `quickstart` in order, with the clone as the working directory. The build directory is inside the clone unless `DOCS_CHECK_TARGET_DIR` names another. Uncommitted changes are not in the clone, so commit before you run it.

A block that needs Docker or PostgreSQL is BLOCKED when the program is missing or does not answer. If no block failed and one is BLOCKED, the check is BLOCKED. On the machine used to write this page, the Docker daemon did not answer and the check ended BLOCKED with every other step passed.

## In CI

`scripts/ci/steps.d/47-docs-check.step` runs the default checks, and `scripts/ci/steps.d/48-docs-quickstart.step` runs the quickstart. A step file in that directory is a protected path and needs a code owner's review.
