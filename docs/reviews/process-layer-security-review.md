# Process layer security review: installer, issue-workflow Action, project board step, Codex config editor

- Scope: the tooling that is installed into other people's repositories and runs on their machines and runners. `scripts/install.sh`; `scripts/lib/issue_workflow.py`, `project_board.py`, `project_map.py`, `codex_config.py`; `onboarding/github/workflows/issue-workflow.yml`, `onboarding/github/ISSUE_TEMPLATE/*.yml` and the two rendered JSON files; `policies/issue-workflow.yaml`, `policies/project-board.yaml`; ADRs 0016, 0018, 0019; the guides `onboarding.md`, `design-with-egm.md`, `project-board.md`, `claude-and-codex.md`. Trust model: `docs/security/threat-model.md` (T-23, T-01, T-02, T-04, T-12, T-15).
- Date: 2026-11-02. Reviewed commit: `7e58ec9` (`feat/slice-0-foundation`). Reviewer: the independent security reviewer. I did not build any of this and I changed none of it. The only file I wrote in the repository is this one.
- Environment: one macOS laptop. `/bin/bash` 3.2.57 for every installer run. Python 3.15.0 (Homebrew) and Python 3.9.6 (`/usr/bin/python3`, which has no `tomllib`). git 2.50.1. shellcheck 0.11.0 and actionlint, both clean on the files they cover. Fake `claude`, `codex` and `gh` programs taken from `scripts/tests/test_install.py`. No real GitHub, no network, no model calls, no Docker, no `cargo`. I did not run the repository's own test suites.
- Evidence: every scenario marked "ran" below was run in a throw-away directory in the session scratchpad. A claim marked **unverified** was reasoned from the code or from documented platform behaviour and not run.

## 1. Verdicts

| Scope | Verdict |
|---|---|
| A. The Action and the board step (what a labeler or an outside author can make them do) | **PASS WITH CONDITIONS** |
| B. The installer and its helpers on a hostile checkout | **PASS WITH CONDITIONS** |
| C. The documents | **Overstated in nine places** (PL-16) |

**Why not PASS, and why not worse.** I found no way for a person who can only apply labels or write issue text to run code, read a secret, apply or remove the `factory` trigger label, write a file in the repository, or change a GraphQL query. The decision function held up: 139,200 randomized cases, no operation on the trigger label and no illegal design move accepted. The arguments to `gh` are built as lists, URL-encoded and never reach a shell, and the two credentials reach only the steps that need them. There is no BLOCKER.

But four findings make the tooling weaker than its own documents say, and a person other than the builders can hit each one in ordinary use:

1. **PL-1.** The per-issue concurrency group drops queued runs, and the rules are enforced per event. Three label changes in quick succession (or one bulk edit in the web page) can leave a hand-set `factory:` label or an unjustified `design: approved` in place, and the board then follows it.
2. **PL-2.** Any issue author can make the board credential write to the organisation's board by closing their own issue. The documents say an issue on no track is never added.
3. **PL-3.** `install.sh --check`, the first thing the onboarding guide tells a person to run because "it changes nothing", writes `.github/project-board.json`.
4. **PL-4.** The installer writes through symbolic links of the checkout. With a hostile repository it creates or overwrites files outside the checkout, and rewrites an outside JSON or TOML file.

**Conditions.** Close PL-1 to PL-4 before the first person who is not a builder installs this. The MINOR findings can wait for the next slice, except that PL-5 (a token in the shell trace) and PL-6 (a redirected MCP entry reported as READY) are cheap and should go in the same change.

**What the verdict does not cover.** Anything that needs a real GitHub, a real Claude Code or Codex, a Linux runner, or the Rust side. See section 6.

## 2. Severity scale

BLOCKER: a low-privilege party runs code, reads a secret, or applies the trigger label. None found. MAJOR: a documented promise about safety or authority is false in a way that an ordinary user or a low-privilege party reaches without special effort. MINOR: hostile-input robustness, defence in depth, or a document that overstates, with a small and bounded effect. NOTE: worth knowing, no action needed now.

## 3. Findings

Commands run from the repository root unless stated. "The fakes" means the programs in `scripts/tests/test_install.py` (`FAKE_CLAUDE`, `FAKE_GH`, `FAKE_CODEX`) written to a scratch `bin/` directory and put first on a minimal `PATH`.

| ID | Severity | Area | Finding |
|---|---|---|---|
| PL-1 | MAJOR | Action | Queued runs are dropped by the concurrency group and rules are per event, so an illegal `design:` label or a hand-set `factory:` label can persist and drive the board |
| PL-2 | MAJOR | Board step | Any issue author can make the board credential add an unlabeled issue to the board by closing it; the documents say the opposite |
| PL-3 | MAJOR | Installer | `--check` writes `.github/project-board.json` |
| PL-4 | MAJOR | Installer | Writes follow symbolic links of the checkout: files created or overwritten outside it |
| PL-5 | MINOR | Installer | `bash -x` prints the value of `FACTORY_GITHUB_MCP_TOKEN`; every child process inherits it |
| PL-6 | MINOR | Installer | A `github` MCP entry that points to another host and carries the token variable ends in `READY`, exit 0; tokens in `url`, `args` or `env` are not recognised as credentials |
| PL-7 | MINOR | `codex_config.py` | Cubic and quadratic regular expressions: a few kilobytes in `.codex/config.toml` hang the installer |
| PL-8 | MINOR | `codex_config.py` | `--replace` deletes the comments above the next table and, in one form, the whole next table; the file mode becomes 0600 |
| PL-9 | MINOR | `codex_config.py` | The "parse again" safety net does not exist on Python below 3.11 (stock macOS); a table with a token and a `command` is replaced, not refused |
| PL-10 | MINOR | `project_map.py`, installer | `git ls-files` and `git status` run on the checkout execute a `core.fsmonitor` command from the checkout's `.git/config` |
| PL-11 | MINOR | Board | The board config is not bound to the repository's owner; the credential model is wider than the documents say |
| PL-12 | MINOR | Design gate | The gate checks that some file exists in `docs/designs/`; any commenter can silence its warning; nothing tells the owner to require reviewed merges |
| PL-13 | MINOR | Installer | The EGM plugin is installed from a moving ref and reported `ADDED` with no version check |
| PL-14 | MINOR | Installer | Values from a hostile `.github/project-board.json` are passed to `gh` unvalidated and printed raw, escape sequences included |
| PL-15 | MINOR | Installer | In-place writes, aborts with a traceback and no summary, and a `--create-project` that is not safe to repeat |
| PL-16 | MINOR | Documents | Nine statements that the code or the tests do not support |
| PL-17 | NOTE | Action | The copied `.github/issue-workflow.json` is trusted at runtime: edited, it makes the Action remove the trigger label |
| PL-18 | NOTE | `project_map.py` | Quadratic `.egmignore` matching, unbounded walk, and a check that `.egmignore` satisfies by itself |
| PL-19 | NOTE | Action | Platform behaviours the code relies on and nothing tests |
| PL-20 | NOTE | Supply chain | Pins cannot be checked offline; the shipped workflow sits outside the repository's own workflow policy |
| PL-21 | NOTE | Action | With `FACTORY_BOT_LOGIN` unset the Action reverts the factory's own status labels and posts a comment each time |

### PL-1. Queued runs are dropped; the rules judge one label per event (MAJOR)

- **Evidence.** `onboarding/github/workflows/issue-workflow.yml:29-32` groups runs by issue number with `cancel-in-progress: false`, and the comment on line 29 says "two quick label changes are handled in order". `decide` (`scripts/lib/issue_workflow.py:305-372`) judges only the label of its own event: any label outside the two namespaces returns `[]` at lines 331-332, so a later event never repairs an earlier one. The board step re-reads the labels (`project_board.py:343-347`) and places the card by whatever is there.
- **Platform behaviour (documented by GitHub, not run here: unverified by execution).** With one run in progress and one pending in a group, a newly queued run replaces the pending one, which is cancelled. `cancel-in-progress: false` protects only the run already in progress. Three events inside the time of one run therefore lose the middle one.
- **Scenario.** A triager adds `design: approved` to an issue that has no design document, then two more labels (or does it in one edit in the web page, which sends one event per label). The run for the `design: approved` event is the pending one and is cancelled. The label stays. A hand-set `factory: done` behaves the same way, and the surviving run's board step moves the card to "In review" because of it.
- **Ran.** `decide(config, action="labeled", label="bug", current={"factory: done", "design: approved", "bug"}, ...)` returns `[]`: a later unrelated event changes nothing.
- **Why the tests do not catch it.** `scripts/tests/test_issue_workflow.py` calls `apply_event` for one event at a time against a fake GitHub. Nothing models a queue. The workflow-file tests (lines 467-497) check permissions, pins and where secrets go.
- **Impact.** No authority is gained: the engine does not act on `design:` labels (grep over `crates` and `apps` finds the policy loader, `crates/domain/src/policy/issue_workflow.rs`, which only validates the file, and tests; no intake code uses the design track, as the policy header says) and a label alone never authorizes work. But two invariants that the policy and the guides state flatly, "an edit by anyone else is reverted" and "the Action removes the label again", fail under bulk edits, and the board displays the result.
- **Fix.** Make every run reconcile the whole issue, not the event's label: sweep both namespaces in `current` each time, so any surviving run heals what a dropped run left. Correct the comment on line 29 and the guide sentences (PL-16).

### PL-2. Any issue author can make the board credential write (MAJOR)

- **Evidence.** `policies/project-board.yaml:90` is `{ stage: done, issue_closed: true }` with no label condition. `stage_for` (`project_board.py:204-212`) returns `done` for any closed issue. `sync` then makes three board calls with the credential (lines 355-365). The workflow runs on `closed` for every issue (`issue-workflow.yml:21`). The documents say otherwise: `project_board.py:24` ("Only an issue on a track is added to the board"), ADR 0018 ("It adds an issue to the board only when the issue is on a track"), `docs/guides/project-board.md:25`. The test `scripts/tests/test_project_board.py:198` asserts the opposite and states it: "a closed issue is done even with no label".
- **Ran.** `project_board.sync` with an issue that is closed and has no labels, a valid board config and a fake `run`: it returned `moved to 'Done' (stage done)` and made one REST read with the repository token and three GraphQL calls with the board token (read the project, add the item, set the option).
- **Who can do it.** The author of an issue can close it. In a public repository that is any GitHub account. The result is an item with attacker-chosen text (the title) in the organisation's project, one per issue, at the cost of one Action run each. The new-solution form applies `design: proposed` by itself (`ISSUE_TEMPLATE/new-solution.yml:3-4`), so the same author also gets a card in "Idea" if GitHub sends a `labeled` event for form labels (unverified; PL-19).
- **Why the tests do not catch it.** The "no track" test (`test_project_board.py:411`) uses an open issue with a label. The one test of a closed issue (line 422) carries `factory: done`.
- **Fix.** Apply the `issue_closed` rule only when the issue also carries a label of the policy, or is already an item of the board. Decide, in the ADR, whether an outside author's form should reach the board at all, and if not, check the sender's permission on the repository before any board write.

### PL-3. `--check` writes a file (MAJOR)

- **Evidence.** `scripts/install.sh:8` ("Show what would change. Change nothing. Safe to run any time.") and line 981 ("Checking only. Nothing will be changed."). In `step_board` the only `check_only` guard is the one for `--create-project` (line 839). When a board is given or found, execution reaches `mkdir -p` and `cp "$tmp/board.json" "$config"` (lines 919-920) in check mode.
- **Ran.** A fresh checkout with `README.md` only. The fake `gh` reports one linked board `acme/3` with a `Status` field. `bash scripts/install.sh --check --checkout c --repo acme/widgets --agent claude --no-mcp` printed `Checking only. Nothing will be changed.` and then `ADDED project-board wrote .github/project-board.json ...`. The file existed afterwards, and the run ended with `NOT READY`.
- **Why the tests do not catch it.** The only board test with `--check` (`test_install.py:675`) also passes `--create-project`, which takes the guarded path.
- **Impact.** A small file, reviewed later in a pull request. But onboarding step 1 tells the person to "look first" because the run "changes nothing", and a person who runs it on a repository they do not own has been told something false. It also adds to PL-4: the write goes through links.
- **Fix.** Guard lines 919-926 with `check_only` and report `WOULD_ADD`. Add a test that lists the checkout before and after every `--check` variant.

### PL-4. Writes follow symbolic links of the checkout (MAJOR)

- **Evidence.** Nothing in `install.sh` tests for a link. `copy_one` (lines 634-650) uses `[ ! -e "$dst" ]` (false for a dangling link, so the file is created through it), then `mkdir -p` and `cp`, and with `--update` `cp` over the link's target. `mcp_entry` writes with `open(path, "w")` (line 525), which follows a link. `step_board` writes `.github/project-board.json` the same way. `codex_config.py` replaces the link itself with `os.replace` (line 190, so a link at the file does not leak a write) but a **directory** link `.codex` is followed by `os.makedirs` and `mkstemp`. A link at `.codex/config.toml` itself is read through (`_read`), so the target's text is classified and, on a write, copied into the new regular file that replaces the link (by reading; not run). The only symbolic-link test in the repository is for the design document (`test_issue_workflow.py:383`).
- **Ran, all with the fakes, destinations in a sibling "victim" directory:**
  1. `.mcp.json` a link to a JSON file outside the checkout (stand-in for a user's `~/.claude.json`, with unrelated keys). `install.sh --checkout c2 --agent claude --no-board` printed `ADDED github-mcp`. The outside file was rewritten, keys sorted and indentation changed, with the `github` server added. The link stayed a link.
  2. `.codex` a link to a directory holding a `config.toml` with a comment and a `[tui]` table. `--agent codex` appended the `[mcp_servers.github]` table to the outside file and set its mode from 0644 to 0600.
  3. `.github` a link to an outside directory. All eight files were created there (`workflows/`, `scripts/`, `ISSUE_TEMPLATE/`, the JSON files).
  4. `.github/workflows/issue-workflow.yml` a dangling link to a path that does not exist. The installer reported `ADDED` and the file was created at the link's target (macOS `cp`; GNU `cp` refuses a dangling link, not run).
  5. `.github/issue-workflow.json` a link to an existing file. The installer said `DRIFT ... kept (use --update to replace)`. With `--update`, the outside file was overwritten with the factory's JSON. The installer's own advice after a DRIFT is to run `--update`.
- **Impact.** The attacker picks the directory and the file name; the content is the factory's fixed content, or a reformatted copy of a JSON or TOML file that the person owns. No code execution. But the effect is real: `.codex -> ../../.codex` or `.mcp.json -> ../../.claude.json` are plausible for a clone two levels below the home folder; a rewrite of an application's live settings file is non-atomic; and case 5 destroys an existing file after the installer itself advises `--update`.
- **Fix.** Before any write, resolve the destination with `realpath` and require that it stays under the resolved checkout; refuse (report `BLOCKED`) when any component below the checkout is a link. Use `cp -P` into a temporary file in the same directory and `mv`. In Python, open with `O_NOFOLLOW` and check `os.path.realpath`. Add a test per case above.

### PL-5. The shell trace prints the token (MINOR)

- **Evidence.** `install.sh:625` is `if [ -z "${!MCP_TOKEN_VAR:-}" ]; then`. The promise in the header (lines 28-30), ADR 0016 and the onboarding guide is that the script "does not read" the value.
- **Ran.** `FACTORY_GITHUB_MCP_TOKEN=PLACEHOLDER_NOT_A_SECRET_1234 /bin/bash -x scripts/install.sh --check --checkout c --agent claude --no-board 2>&1 | grep -n PLACEHOLDER` printed line 205: `+ '[' -z PLACEHOLDER_NOT_A_SECRET_1234 ']'`. A normal run (`--agent both`, same placeholder) printed it zero times. I did not exercise error paths with the token set; by reading, line 625 is the only place that expands it.
- **Also.** The variable is exported by the person, so `claude`, `codex`, `gh`, `git` and `python3` inherit it (read from the code; bash exports the inherited environment; I did not capture it in a child). `claude plugin install` and `codex plugin add` run third-party code with it in the environment.
- **Why the tests do not catch it.** `DUMMY_TOKEN` is checked against the output of normal runs, never against a trace.
- **Fix.** Test with `[ -n "${!MCP_TOKEN_VAR:+x}" ]` (the trace shows `x`, not the value), run `{ set +x; } 2>/dev/null` at the top, and start children with `env -u FACTORY_GITHUB_MCP_TOKEN` (or `unset` once the check is done).

### PL-6. A redirected MCP entry is reported READY (MINOR)

- **Evidence.** In `step_mcp_claude` the `different` branch without `--update` only calls `report DRIFT` (line 549) and adds no `needs_you`, unlike `workflow-files` (line 681) and the Codex `unsafe` branch. `mcp_entry` (line 494) classes an entry as `credential` only when a header value lacks `${` (line 519). T-04 names this file as an attack path.
- **Ran.** `.mcp.json` with `url` set to an attacker host and `Authorization: Bearer ${FACTORY_GITHUB_MCP_TOKEN}`, everything else installed and committed. Output: `DRIFT github-mcp ... differs from the factory's; kept (use --update to replace)`, then `READY`, exit code 0. When the person next opens the project in Claude Code and approves the server, their token goes to that host. The variable name is the documented, predictable one, so any repository's `.mcp.json` or `.codex/config.toml` can name it (T-04; mitigated only by the approval prompt and by the advice to use a one-repository token).
- **Ran.** An entry whose `url` carries `?access_token=...`, and a `stdio` entry with the token in `args` and `env`: both are `different`, not `credential`, so there is no "remove it and rotate it" advice.
- **Why the tests do not catch it.** `test_install.py:395` asserts the DRIFT line for a token header; no test checks the exit code or the closing line for a redirected entry.
- **Fix.** Treat a `github` entry whose URL host is not `api.githubcopilot.com` and whose text names the variable as `credential` (NEEDS), and a `different` entry as NEEDS too, so READY is impossible. Scan `url`, `args` and `env` for token shapes.

### PL-7. Regular-expression denial of service in the Codex config editor (MINOR)

- **Evidence.** `scripts/lib/codex_config.py:37` `HEADER_LINE = ^\s*(\[\[?)\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$`: the lazy group and the surrounding `\s*` both match spaces. `KEY_LINE` (line 38, `(.*?)\s*$`) and `re.sub(r"\s+#.*$", ...)` (line 102) are quadratic on trailing spaces. `inspect` runs on `--check` too, with no timeout.
- **Ran (Python 3.15).** A line of `[`, N spaces and `x`: 0.03 s at N=250, 0.20 s at N=500, 2.3 s at N=1,000 and 7.2 s at N=2,000 (the machine was busy, so single timings are rough; from 250 to 1,000 the time grew 77 times for a fourfold length). N=8,000 did not finish in two minutes. A line `url = "x"`, 32,000 spaces and `y`: 12.6 s. A hostile file of a few kilobytes keeps the installer at full CPU for minutes to hours. Python 3.9.6 not timed.
- **Why the tests do not catch it.** `test_codex_config.py` has no long-line case.
- **Fix.** Reject lines longer than 4 KB as `unsafe` before any regular expression, and replace the header match with `line.strip()` plus explicit `[`/`]` handling.

### PL-8. The editor deletes comments and, in one form, a whole table (MINOR)

- **Evidence.** `codex_config.py:144-151` replaces `lines[start:end]`, where `end` is the next line that `HEADER_LINE` recognises. Lines between the table's last key and the next header, including the comments that introduce the next table, are consumed; only one blank line is kept. `HEADER_LINE` does not match a header whose quoted key contains `]`, so that table is swallowed into the github table's range. The temporary file comes from `mkstemp` (line 187), so the mode becomes 0600, and nothing removes it if the write fails (lines 187-190).
- **Ran** with `--replace` (the `--update` path):
  1. A comment `# --- Linear: do not touch, see wiki ---` and its blank line above `[mcp_servers.linear]` were gone. The mode of a 0664 file became 0600.
  2. `[projects."/Users/me/code/app[1]"]` with `trust_level = "trusted"`, placed right after the github table, was deleted. The result is valid TOML and the github table is right, so the `tomllib` check passes.
- **Contradicts.** ADR 0019 ("The editor cannot lose a person's comments or other servers") and `claude-and-codex.md` ("keeps everything else in the file: other tables, comments and blank lines").
- **Why the tests do not catch it.** `test_codex_config.py:106` uses a fixture whose next table has no comment above it and no `]` in a header.
- **Fix.** Treat any line that starts with `[` after whitespace as a boundary, and move trailing comment lines after the new block. Refuse (`unsafe`) a header that contains a quote. Copy the mode with `shutil.copymode`, and remove the temporary file in a `finally`.

### PL-9. The second parse is missing on Python below 3.11, and "unsafe" is a spelling check (MINOR)

- **Evidence.** `codex_config.py:120-126` skips the check when `tomllib` is missing (ADR 0019 says "where it exists"). `/usr/bin/python3` on a Mac with the Xcode tools is 3.9.6 and has no `tomllib`; the installer calls plain `python3`. `inspect_text` returns `credential` (line 107) before it looks for `command`, `args` and `env` (line 109).
- **Ran.** `[mcp_servers."github"]` with `command = "evil"` (a quoted key written with a unicode escape is the same table as `github` in TOML). On 3.15: `FAIL ... TOMLDecodeError`, exit 1, file untouched. On 3.9.6: exit 0, and the installer appended a second `[mcp_servers.github]` table, so Codex gets a file with a duplicate table and a command-running table the editor never classed as unsafe.
- **Ran.** A `github` table with `command = "docker"`, `args` and an `env` that holds a value shaped like a classic GitHub token: `inspect` says `credential`, and `--replace` replaced the whole table, command included. ADR 0019 says such an entry "is never edited, even with `--update`". Replacing it removes a token, which is arguably wanted; the document and the code disagree.
- **Fix.** If `tomllib` is missing, make `write` refuse and report `BLOCKED: needs Python 3.11` (or vendor a small parser). Check executing keys before credentials and report both. Or change the documents.

### PL-10. Running git on the checkout runs the checkout's `core.fsmonitor` (MINOR)

- **Evidence.** `project_map.py:47` runs `git -C <root> ls-files --cached --others --exclude-standard -z`. `install.sh:971` runs `git -C "$checkout" status --porcelain`.
- **Ran** in a throw-away repository with `git config core.fsmonitor <script that touches a marker file>`: `git ls-files --cached --others --exclude-standard` ran the script, `git status --porcelain` ran it, `git rev-parse --is-inside-work-tree` did not. With `-c core.fsmonitor=false` none ran.
- **Precondition.** The attacker controls the `.git/config` of the directory, for example a tarball or zip of a working tree that includes `.git`, or a shared volume. `git clone` does not copy configuration, so a normal clone is not affected.
- **Fix.** Pass `-c core.fsmonitor=false` (and `-c core.hooksPath=/dev/null` as a habit) in both places.

### PL-11. The board is not bound to the repository's owner (MINOR)

- **Evidence.** `validate_board_config` (`project_board.py:264-291`) checks shape only: the owner against a login pattern, the number as a positive integer, the field and option names as free text. `sync` (lines 338-366) never compares the owner with the repository's owner and never checks that the project is linked to the repository. Whoever merges a change to `.github/project-board.json` can aim the credential at any project it can write, and at any single-select field in it (the field name is free text, so "Priority" is as good as "Status").
- **Reach.** App token: `create-github-app-token` gets no `owner` input (`issue-workflow.yml:70-76`), so by its documented defaults it is minted for the installation of the repository's owner (unverified here), which still covers all of that organisation's projects; the permission cannot be narrowed to one project. Classic token (the documented path for a personal board): every project of the person.
- **What a holder can do beyond moving cards.** With organisation Projects write or the `project` scope: create and delete projects, rename and delete fields and options, add and remove any item, read every field and draft item, change visibility. "Additive only" (ADR 0018) describes this code, not the credential.
- **Where the secrets live.** They are repository secrets. Any workflow that can run in the repository, including one pushed on a branch by a collaborator with write access, can read `FACTORY_BOARD_TOKEN` or the App's private key. The narrowing at `issue-workflow.yml:74-75` applies to the minted token, not to the key. Neither the installer nor `project-board.md` suggests environment secrets limited to the default branch, or a CODEOWNERS entry for `.github/project-board.json` and `.github/workflows/`.
- **Fix.** Add a runtime check that `project.owner` equals the repository owner (or is listed in a repository variable), keep the project node id in a variable rather than a file, and write the environment and CODEOWNERS advice into the guide.

### PL-12. The design gate is thinner than the guides read (MINOR)

- **Evidence.** `apply_event` (`issue_workflow.py:403-405`) asks only whether `<docs-root>/<path>` is a regular file that is not a link. `design_document_path` accepts any name matching `docs/designs/<[A-Za-z0-9._-]+>.md`.
- **Ran.** Of 24 adversarial bodies (CRLF and bare CR, `..` in the name, traversal, sub-directories, upper-case `.MD`, non-ASCII look-alikes, NUL, vertical tab, U+2028, non-breaking space, markdown emphasis, a quoted line, two matching lines) none yielded a path outside the pattern; the first matching line wins. `Design document: docs/designs/README.md` is accepted, as is `docs/designs/.md.md`.
- **What follows.** The document need not belong to the issue, may be any existing file, and the line can sit inside any textarea of the form, so the author, not the approver, chooses it. The check runs when the label is applied; a later edit of the body or deletion of the file changes nothing. The "merged pull request is the approval" claim (ADR 0016, `design-with-egm.md` step 5) holds only if the default branch requires reviewed pull requests, which nothing in the installer or the guides asks for (grep for branch protection in those files: no match). A symbolic link is refused only at the last path component (line 405); a linked `docs/designs` directory is not (needs default-branch write).
- **Marker.** `apply_event` (lines 423-426) skips the gate comment when the raw JSON of any comment contains the marker, so any commenter can silence the warning by pasting it. The test (`test_issue_workflow.py:401`) uses an unattributed "earlier" comment.
- **Quirk.** `decide` accepts a move when any one design label present allows it (line 363); with two design labels already present, a move legal from one of them is accepted.
- **Severity.** MINOR because the gate is advisory, the engine does not read `design:` labels, and every document says so (ADR 0016 "Costs", `design-with-egm.md:93`).
- **Fix.** Say in the guide what branch protection the owner must set; require the document to name the issue number; match the marker only in comments written by `github-actions[bot]`.

### PL-13. The EGM plugin comes from a moving ref and is reported ADDED unchecked (MINOR)

- **Evidence.** `install.sh:370` and `:455` add the marketplace `google/elephant-goldfish-model` with no ref, then install `egm@egm`. After a fresh install the script reports `ADDED` whatever version it got (lines 385 and 470); the comparison with `EGM_EXPECTED_VERSION` happens only on a later run (`DRIFT`). ADR 0016 verified commit `f0ba151`; the installer does not enforce it. The plugin is installed in the user scope of each agent, so it applies to every project of the person, and the person's environment may hold the MCP token (PL-5).
- **Severity.** MINOR: a named third-party plugin, an install the person asked for, and ADR 0016 lists it as a known cost.
- **Fix.** Pin the marketplace to the reviewed commit or tag if the CLI allows it (unverified), otherwise compare the installed version after the install and report `NEEDS` on a mismatch.

### PL-14. Values from a hostile `project-board.json` reach `gh` and the terminal (MINOR)

- **Evidence.** `install.sh:805-818`: `board_config_field` prints `owner`, `number` and `status_field` from the checkout's file. They are passed to `gh project field-list "$number" --owner "$owner"` before any validation, with the person's credentials. `validate` (which has the login pattern) runs only afterwards. The `field` is printed raw on the `PRESENT` line.
- **Ran.** A checkout whose file names owner `attacker-org`, project 5 and a field whose name contains an operating-system-command escape. The fake `gh` log shows `gh project field-list 5 --owner attacker-org ...` was run, and the output line `PRESENT project-board ... field '^[]0;INJECTED-TITLE^GStage'` carried the raw ESC and BEL bytes (shown with `cat -v`). A number that starts with `-` would be read by `gh` as a flag (not tried). Directory names (`project_map.py:119`), option names (`NOTE` lines) and plugin versions are also printed raw.
- **Impact.** A read of a project the person can already read, and terminal control sequences from repository content. No execution found.
- **Fix.** Run `validate` first and use only the validated values; strip bytes below 0x20 in `report`.

### PL-15. In-place writes, silent aborts and a repeat that duplicates (MINOR)

- **Evidence and ran.**
  1. A `.mcp.json` that is not strict JSON (a comment): `state=$(mcp_entry ...)` under `set -e` ends the script with a Python traceback and no summary (`install.sh`, `mcp_entry`, lines 494-528). Nothing is written in that case.
  2. The `mcp_entry` write (lines 525-527) truncates `.mcp.json` and then dumps, with `sort_keys=True` and the default ASCII escaping: a failure between the two leaves an empty file, and a success reorders and re-escapes the person's whole file. `copy_one` overwrites with `cp` in place (lines 642 and 648).
  3. `--create-project`: if `gh project link` or `field-create` fails after `gh project create`, the script sets `FAILED` and stops (lines 875-886). A rerun creates another board, because nothing looks for the first one.
  4. `owner=$(gh api user | python3 ...)` (line 871) aborts silently under `pipefail` when `gh` fails.
- **Fix.** Catch `ValueError` in `mcp_entry` and report `BLOCKED` with a sentence; write to a temporary file and rename; on a failure after `project create`, print the project number and the exact command to resume.

### PL-16. Statements the code or the tests do not support (MINOR)

| # | Where | Claim | What I found |
|---|---|---|---|
| 1 | `install.sh:8`, `onboarding.md` step 1 | `--check` changes nothing | PL-3 |
| 2 | `project_board.py:24`, ADR 0018, `project-board.md:25` | Only an issue on a track is added to the board | PL-2; `test_project_board.py:198` asserts the opposite |
| 3 | `issue-workflow.yml:29`, `design-with-egm.md:57,98` | Quick label changes are handled in order; the Action removes the label again; "if you set one by hand, the Action removes it"; at most one label of each kind | PL-1 |
| 4 | ADR 0019 "Good", `claude-and-codex.md` | The editor cannot lose comments or other servers | PL-8 |
| 5 | ADR 0019, `claude-and-codex.md` | An entry that runs a command is never edited, even with `--update` | PL-9: a table that also holds a token-shaped value is replaced |
| 6 | `install.sh:974` | "The factory does not enable a repository whose map is not on its default branch" | ADR 0016 (revision note) and onboarding step 8 say the opposite: the engine records a person's statement and cannot see the repository |
| 7 | ADR 0018 "Good" | A stolen board credential cannot write code or labels | Its own "What was checked" says a user-owned project needs a classic token with `repo` and `project` scopes, which can write code. The installer note and the guide say `project` only. Both cannot hold; which scope is needed was not verified |
| 8 | ADR 0016 "Rules that hold everywhere" | The document is accepted "with no symbolic link" | Only the last path component is tested (`issue_workflow.py:405`) |
| 9 | `install.sh:18` | Creating labels "is the one step that changes GitHub" | `--create-project` also creates and links a project and adds a field (lines 875-886); line 25 of the same header says "This changes GitHub" for it |

Statements I checked and found supported: the design gate is advisory (ADR 0016, the policy header, the Action header and `design-with-egm.md:93` agree, and no engine code reads the design track); the engine never writes a board (grep for `projectV2`, `addProjectV2` and `project_board` over `crates` and `apps`: no match); the installer never commits or pushes (the only git calls are `rev-parse` and `status`, `install.sh:968,971`, and `ls-files` in `project_map.py`), subject to PL-10; the shipped renderings are current (the SHA-256 recorded in each JSON file equals the hash of its policy file). The "tested against fakes only" labels on the guides and the ADRs are honest.

### PL-17. The copied config is trusted at runtime (NOTE)

`apply_event` takes `trigger`, both prefixes, the transitions and the document glob from `.github/issue-workflow.json` and checks only the schema string (`load_config`, line 274). The rule "the Action never adds or removes the trigger label" is enforced by `check_policy` in the factory's own CI, not in the target repository. **Ran:** with `factory.prefix` set to `factory` and `trigger` set to another name, `decide` returns `("remove_label", "factory")` when a person applies the label. Whoever can change the file already controls the workflow, so this is defence in depth. A two-line assertion at the start of `apply_event` (the trigger starts with neither prefix) closes it.

### PL-18. `project_map.py` (NOTE)

- Reads no file contents, with one exception: `.egmignore` (line 67) is opened, follows a link, and its lines become `fnmatch` patterns that are never printed. **Ran** on a non-git tree with a symlink loop, a link to a directory, a FIFO named `pipe.py`, a file name containing a newline and `.egmignore` linked to `/etc/hosts`: finished in 0.14 s, no hang, nothing read from the FIFO (`isfile` is false), the directory link was not followed.
- `_ignored` is files times patterns times path depth, and the module computes the set twice: 1,000 files and 1,000 patterns took 5 s, so 20,000 of each would take about half an hour. The non-git walk has no cap.
- A pattern `*` in `.egmignore` makes any tree "MAPPED" with only a root `README.md`. That matches EGM's own rule, but the check cannot be called a safeguard; the human attestation (ADR 0016 revision) is the control.

### PL-19. Platform behaviour that the code assumes and nothing tests (NOTE)

All unverified: that GitHub sends a `labeled` event for labels applied by an issue form; that `gh api -X DELETE .../labels/design%3A%20approved` reaches GitHub with the percent-encoding intact; that deleting a label that is already gone returns 404, which fails the run and skips the board step (the worker removes `factory:` labels in the same moments, so this race is likely); that GitHub rejects control characters and newlines in label names (`_cmd_apply` prints a label name in the log without cleaning it, so a newline followed by `::` would be read as a workflow command; the printed line starts with `remove_label` or `add_label`, so without a newline it cannot be). The tests use fake GitHub objects that return what the author expects.

### PL-20. Supply chain (NOTE)

See question 7. The pins cannot be checked offline. The shipped workflow is outside the repository's `workflow-policy` step (`scripts/ci.sh:878-975` reads `.github/` by default); its own test checks only that `uses:` ends in 40 hex digits (`test_issue_workflow.py:476`), and `persist-credentials: false` (present, line 45) is not tested. The Action copies `issue_workflow.py` and `project_board.py` with no version stamp, so a fix in the factory reaches an installed repository only when its owner reruns the installer with `--update`.

### PL-21. `FACTORY_BOT_LOGIN` unset (NOTE)

Until the variable exists, the Action treats the factory's own status label as foreign: it removes it and posts "Labels that start with `factory:` ... That label was removed" on every state change (`decide`, lines 336-342). The onboarding guide calls this "the safe default" in step 6 and does not say that the status writer built in ADR 0017 will look broken until then. Also, `--repo -x/y` passes the installer's pattern (a leading `-`); harmless, since the value follows a flag, but the pattern should require a leading letter or digit.

## 4. Answers to the seven questions

**1. The Action.** *Verdict: no BLOCKER. A labeler or outside author cannot run code, read a secret, apply the trigger label or write outside the issue, its labels, its comments and the board. They can approve a design without a merged document, and can leave a `factory:` label, in the ways given in PL-1 and PL-12.*
- `${{ }}`: line 31 (issue number, an integer, in `concurrency`), lines 55-57 and 80-82 (`github.token`, `vars.FACTORY_BOT_LOGIN`, `github.repository`, in `env:` only), line 69 (`vars`), lines 72-73 (`vars`, `secrets`, in `with:` of the pinned action) and line 81 (the board token, in the board step's `env:`). None is inside a `run:`. Both commands read `"$GITHUB_EVENT_PATH"` and `"$REPOSITORY"` quoted. `actionlint` is clean.
- Event file: used for the action name, `issue.number`, `label.name`, `sender.login` and `sender.type`. The labels and the body are read again from the API. Label names reach only a URL (percent-encoded with `safe=""`, so `/` becomes `%2F`) and equality tests. No comment text includes issue text.
- `gh api`: argument lists (`gh_api`, lines 379-389), `-f` (raw string, no file reads), the repository checked against a pattern that rejects `.` and `..`. `shell=False` throughout.
- `design_document_path`: 24 hostile inputs (listed under PL-12); none escaped the pattern. `$` in a pattern could match before a trailing newline, but `\S+` cannot contain one. CRLF and bare CR are normalised first.
- Sparse checkout: `.github` and `docs/designs` of the default branch, `persist-credentials: false`, `contents: read`. The scripts write no file, so nothing can be written outside `docs/designs` because nothing is written.
- `decide`: a fuzz of 139,200 combinations (4 actions, 29 labels including case variants, 5 senders, 2 bot settings, random current sets, document present or absent) found no `add_label` or `remove_label` on the trigger and no accepted design move that the policy's transitions or the start states do not allow. The trigger is returned from before any namespace logic (line 320). A configuration that has been edited is a different matter (PL-17).
- Concurrency: PL-1.

**2. The board step and its credential.** *Verdict: the credential reaches only the board step; issue text cannot change a query; the file and the credential model are wider than the documents say (PL-2, PL-11).*
- Reach: `BOARD_TOKEN` is set in the `env:` of the board step only (line 81). The minted token is an output consumed only there. The App key is read only by the pinned action (line 73). `test_issue_workflow.py:481-497` checks this, and my reading agrees.
- GraphQL: the query text is a constant with only `organization` or `user` substituted, and that word is derived from a validated two-value field (`project_board.py:318-325`, 354). Every other value is a variable (`-f` for strings, `-F` for the integer only, lines 328-331). The node id must match `^[A-Za-z0-9_=-]{1,200}$` (line 57), the owner a login pattern (58), the number a positive integer that is not a boolean (279). The status field and option names are only compared in Python. A test builds hostile label names and checks they are absent from the query text (`test_project_board.py:405`).
- Beyond moving cards, and what a changed `project-board.json` can do: PL-11.
- Failure output: `run_gh` does not include `gh`'s stderr in its error (line 314), and GraphQL error messages are cut at 120 characters, so the token does not reach the log through these.

**3. The installer.** *Verdict: no shell injection found; four MAJOR and several MINOR findings.*
- Injection: I created a checkout directory named `a b;touch PWNED_1;$(touch PWNED_2)` followed by a backtick `touch` command, and passed `--repo`, `--project` and `--board-field` values with `;`, `$()` and spaces. Three `--repo` values, one `--project` value and three `--board-field` values with those characters were refused by the pattern checks; the directory itself, with clean arguments, was handled; no file named `PWNED*` was created. `--board-field --help` passes the pattern and is passed on to the mapper as a field name, which is harmless. Every expansion I read is quoted. `-x/y` is accepted as a repository name (PL-21) and is harmless.
- Links: PL-4. Overwrites and truncation: PL-3, PL-4, PL-15. Temporary files: `mktemp -d` (mode 0700) with an `EXIT` trap; I sent INT, TERM and HUP to a script with the same two lines on bash 3.2 and the directory was removed each time.
- `set -e`: PL-15. Word splitting and bash 3.2: every run above used `/bin/bash` 3.2.57; `${!VAR:-}` works; I found no unquoted expansion and no empty-array expansion (grep for `[@]` found none). shellcheck is clean.
- Token: PL-5. Nothing else prints it. Unexpected output from `python3`, `gh`, `claude`: invalid JSON in `.mcp.json` aborts with a traceback (PL-15); a non-JSON `claude plugin list` is read as "absent" and the install is attempted; `gh` listing failures are reported `BLOCKED`.

**4. `.mcp.json` and `.codex/config.toml`.** *Verdict: the installer never writes a token and never runs a project file's command; it can reformat or lose parts of the person's other settings.*
- The entry is a constant that names a variable (`mcp_entry`, lines 494-528; `expected_block`). A token already in the file is not copied. It is replaced only with `--update`.
- Corruption: PL-4 (outside files), PL-8 (comments, a whole table, mode), PL-9 (duplicate table on old Python), PL-15 (whole-file reformat of `.mcp.json`, truncation window).
- Wrong "same": I tried a duplicate-key table, an escaped quoted key, a `[[...]]` array header, a multi-line string holding a header-looking line and dotted keys. The only wrong answers are in PL-9 (an escaped key is not seen as the same table) and PL-6 (token in `url`, `args`, `env` is `different`). A duplicate key before a good one is read as `same` (the later key wins in the dictionary), though TOML itself would reject the file; this fails safe because Codex refuses to load it.
- Regular-expression denial of service: PL-7. Half-written file: `os.replace` of a temporary file is atomic, so no half-written `config.toml` appears; a temporary `.config.toml.*` may be left behind on a failed write (PL-8).

**5. `project_map.py`.** *Verdict: no finding of weight (PL-10, PL-18).* It reads no file content except `.egmignore`. Loops, special files, newline names and `..`: handled in the non-git path as ran (PL-18). In a git work tree it trusts the output of `git ls-files`; a hostile index could list names with `..`, which are only tested with `isfile` and printed, never read. Cost and git configuration: PL-10 and PL-18.

**6. Honesty of the documents.** PL-16 lists nine overstatements. In addition: the "verified" in ADR 0018 for `actions/create-github-app-token` v3.3.0 (the `client-id` input) cannot be reproduced from anything in the repository; every installer "verified" in the ADRs and guides was run against fakes, and the documents say so; the "not shown to work" lists in ADR 0018, ADR 0019 and `claude-and-codex.md` are honest but incomplete: they omit the concurrency behaviour, the form-label event, the dangling-link behaviour, the `--check` board write, and the Python 3.9 path of the TOML editor (PL-19, PL-1, PL-4, PL-3, PL-9). The statements about the design gate being advisory, the engine never writing a board and the installer never committing hold (PL-16, last paragraph).

**7. Supply chain.** *Verdict: pins unverified; the installer fetches nothing by itself.*
- `actions/checkout@3d3c42e5...` (`# v7.0.1`, line 43) is the same commit as in the repository's own `ci.yml:52` and as the fixture in `scripts/ci.sh:1730`. That shows consistency, not that the commit is the tag. `actions/create-github-app-token@64ab729a...` (`# v3.3.0`, line 70) appears nowhere else. I cannot tell offline whether either commit belongs to its tag, so **both are unverified**; a person with network access should run `git ls-remote` for each tag and compare, and should check that `client-id` and the `permission-*` inputs exist at that commit.
- The installer has no `curl`, `wget`, `pip`, `npx`, `git clone`, `eval` or `source` (grep). Network reach is through `claude plugin marketplace add` and `plugin install`, `codex plugin marketplace add` and `plugin add` (PL-13: moving ref, user scope) and `gh`. The helper scripts import the standard library only (tested by `StandardLibraryOnly`). PL-20 covers the rest.

## 5. What worked

- No `${{ }}` in a command; secrets only in the steps that use them; `persist-credentials: false`; `permissions` narrowed; pins by commit.
- Argument lists for every `gh` and `git` call from Python; URL encoding of label names; a repository pattern that rejects `.` and `..`; every GraphQL value a variable.
- `python3 -I` for every Python call in the installer.
- The decision function is pure and small; it was the easiest part to review and the hardest to fault.
- Honest status lines in the guides ("tested against fake `gh` programs only").

## 6. What I did not check

- Anything on a real GitHub: concurrency queueing (PL-1), events for form labels (PL-2, PL-19), `gh api` path encoding, `create-github-app-token` token scoping, whether a user-owned project needs the `repo` scope (PL-16 row 7), whether the `labeled` event carries the form author.
- The real `claude` and `codex` command lines, including what `plugin install` does with the environment.
- Linux behaviour of the installer (GNU `cp` on a dangling link, `mktemp`), bash 4 and 5, Windows, and Python 3.10 to 3.14. I used Python 3.9.6 and 3.15.0 only.
- The Rust side: the worker's status writer (ADR 0017), the engine's intake, and `policies/security.yaml` beyond the lines I quoted. I took "the engine does not read the design track" from a grep, not from the code.
- The EGM plugin itself, the contents of `docs/security/secrets-and-credentials.md`, and the CI step files beyond the ones named.
- The repository's own test suites: I read them and ran none.
- The issue forms beyond reading them. `blank_issues_enabled: true` lets anyone open an issue without a form; I took that as intended.

## 7. Fix status

Written by the engineer who built the process layer, on 2026-11-02, after the fixes. The reviewer's text above is unchanged. "Test" names the class or test that fails when the fix is removed. Everything was checked against fake `gh`, `claude` and `codex` programs and a fake GitHub object. **Nothing ran on a real GitHub**, and the events and permission calls the Action now makes are used as GitHub documents them, not observed.

| ID | Status | What was done, and the proof |
|---|---|---|
| PL-1 | FIXED | Every run of the Action checks the whole issue (`reconcile` in `scripts/lib/issue_workflow.py`): one label of each group, a `factory:` label only if the App applied it last (read from the issue events), `design: approved` only with a design document. Tests: `Reconcile`, `DroppedRuns`. The comment about "handled in order" is corrected in the workflow and the guides. A wrong label can still show until the next run. |
| PL-2 | FIXED | A closed issue is on a track only if it carries a label of the workflow, and a card moves only for the App or a person with triage rights (`stage_for`, `sender_may_move_cards` in `scripts/lib/project_board.py`). The test that asserted the opposite was corrected. Tests: `Stages`, `WhoMayMoveACard`. A lookup that fails is a no. |
| PL-3 | FIXED | `--check` writes nothing: the board step reports `WOULD_ADD`. Test: `CheckWritesNothing` snapshots the whole project before and after eight `--check` variants. |
| PL-4 | FIXED | The installer refuses a path that is, or goes through, a symbolic link, including a dangling one, for every file it writes (`path_has_link`, `refuse_link`). Copies are atomic. `codex_config.py` and `mcp_entry` refuse links as well. Tests: `Links` (six cases from the review, each checking the outside file), `OnDisk`. |
| PL-5 | FIXED | Tracing is switched off first, the test expands to `x` and not to the value, and the variable is unset, so the programs the installer starts do not see it. Tests: `TokenHygiene`, with a control that shows the fakes can see the variable. |
| PL-6 | FIXED | A new state `redirected` (the token variable with an address that is not GitHub's) and a token shape in the address, arguments or environment are credentials. A `github` entry that differs is `NEEDS`, never `READY`. Tests: `McpEntries`, `CodexEntries`. A heuristic of mine that called any header without `${` a credential, `X-MCP-Toolsets` included, was also wrong and is fixed. |
| PL-7 | FIXED | Linear parsing, a 4096-character limit before any pattern, no regular expression on a long line. Test: `Hostile` (100,000-character lines answer in under a second). |
| PL-8 | FIXED | Any line that starts with `[` ends a table; comments before the next table stay; the file mode is kept; the temporary file is removed in all cases. Tests: `Hostile`, `OnDisk`. |
| PL-9 | FIXED | The result is checked by structure on every Python, and also with `tomllib` where it exists; the test hides `tomllib` to prove it. An escaped or quoted spelling of `github` is unsafe. An entry that runs a command is unsafe even with a token in it. |
| PL-10 | FIXED | `git` is called with `core.fsmonitor=false` and `core.hooksPath=/dev/null` in `project_map.py` and `install.sh`. Tests: `HostileCheckout`, with a control that skips itself if this git does not run the command for the call. |
| PL-11 | FIXED, with a limit | The board must belong to the repository's owner or to an owner in `FACTORY_BOARD_OWNERS` (`board_owner_allowed`); the installer says to set the variable. Tests: `WhoseBoard`. The guide now tells the owner to use an environment limited to the default branch and code owner review. **The installer cannot set either, and the project node id is still in a file.** |
| PL-12 | PARTLY | Only comments by `github-actions[bot]` silence the gate comment. The guide says the owner must require reviewed pull requests, or a merge is not an approval. **Not done:** requiring the document to name the issue; the quirk that a move is accepted if any one of two design labels allows it (the new whole-issue check keeps one label, so the case is now short-lived). |
| PL-13 | FIXED, with a limit | After a fresh install the real version is read and a version other than the expected one is `DRIFT`, not `ADDED`. **Pinning the marketplace to a commit is not done**: the CLIs offer no ref for `marketplace add` that was verified here. |
| PL-14 | FIXED | The board file is validated before any value of it goes to `gh`, and every line from a checkout, a plugin or a board is stripped of control characters. Tests: `HostileCheckout`. |
| PL-15 | FIXED | A `.mcp.json` that is not plain JSON is a sentence and the summary, not a traceback; the write keeps order, characters and mode and replaces the file in one step; a failure after `gh project create` says how to finish and not to repeat; `gh api user` failing is handled. Tests: `McpEntries`, `CreateProjectFailures`. |
| PL-16 | FIXED | Nine statements: (1) `--check` now does change nothing; (2) the board adds only an issue on a track, now true; (3) the guides say what the Action does and does not; (4) comments and other servers are now kept, with tests; (5) an entry that runs a command is never edited, now true with tests; (6) the installer's text about the default branch says what the engine really does; (7) ADR 0018 no longer says a stolen credential cannot write code, and says which scope is unverified; (8) every part of the document path is checked for a link; (9) the header names `--create-project` as a step that changes GitHub. |
| PL-17 | FIXED | `apply_event` refuses a configuration in which a namespace swallows the trigger label. Test: `DroppedRuns`. |
| PL-18 | FIXED, with a limit | `.egmignore` is not followed if it is a link and is capped in size, number and length of patterns; the walk of a tree without git has a file cap; the tree is walked once. Tests: `HostileCheckout`. **A pattern `*` in `.egmignore` still makes a project "mapped"**: that is EGM's rule, and the attestation by a person is the control. |
| PL-19 | PARTLY | Deleting a label that is already gone no longer fails the run (`NotFound`), and a label name is cleaned before it is printed. **Still unverified on GitHub:** a `labeled` event for form labels; the encoding of the delete path; that GitHub rejects control characters in a label name. |
| PL-20 | PARTLY | Both pins were checked on 2026-11-02 with `gh api repos/.../git/ref/tags/...`: `actions/checkout` v7.0.1 and `actions/create-github-app-token` v3.3.0 resolve to the commits that are pinned. **The shipped workflow is still outside the repository's own workflow-policy step**; a unit test checks its pins and permissions instead. |
| PL-21 | PARTLY | The installer notes a missing `FACTORY_BOT_LOGIN`. The Action still removes the factory's status labels, and posts a comment, while the variable is unset. That is the safe side by design and is now stated in the guide. |
