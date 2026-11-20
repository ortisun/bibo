# The first real run

This guide is for the owner. It lists, in order, what you do once so that the factory can run scenario E1 for real, and the one command that runs it.

E1 is the end-to-end proof of Slice 1. An issue on a real GitHub repository goes through intake, the Spec Kit specification, the plan, the sandboxed builder, the checks, the review, the documentation, a draft pull request, and your approval. Nothing is merged. The harness then judges the run with the assertions A1 to A14 of [`tests/end_to_end/README.md`](../../tests/end_to_end/README.md).

The run uses subscription mode, the factory's default, as [the decision record on subscription mode](../adr/0020-subscription-mode-by-default.md) describes. The model credential is your Claude subscription token. The broker holds it, and no sandbox ever sees it. Codex does not run in this mode.

## What is real in the run

| Part | In this run |
|---|---|
| GitHub | `api.github.com` and `github.com`, through your GitHub App and its installation on your fixture repository. |
| The model | `api.anthropic.com`, through the factory's broker, signed with your subscription token. |
| The sandbox | The hardened Docker containers of the pinned images, on your Mac. |
| The registry | `crates.io`. |
| The factory | The real engine, API server, worker loop, thirteen stage handlers and PostgreSQL, in the production profile. |

Three things are not real, and the evidence says so in its list of limitations:

- The database is a private copy made for the run. Your fixture repository is written in it as registered, attested and enabled by you. The registration commands are not part of E1.
- The App cannot read the bypass list of a ruleset. The run records your statement that the App is not on it. The setup script makes the ruleset with nobody on the bypass list.
- The advisory database is a stand-in. The change the issue asks for adds no dependency.

One thing is real and weaker than the policy's best: every review is made by another Claude model, not by a model of another family. See [Who reviews the code](#who-reviews-the-code).

## Who does what

You work alone, so you are the requester and the approver. The approval policy allows this for a low-risk change (`policies/approval.yaml`, `approver_may_equal_requester_when_low_risk: true`). The word-count change is meant to be low risk. The harness accepts your approval of your own request only when the job's recorded risk is low.

There is no public webhook endpoint. The run files the issue and applies the `factory` label with your own `gh` login, because the App has no permission to create issues. It then starts the job through the factory's API (`POST /v1/jobs`), as `factory-cli submit` does. The API checks you by your numeric GitHub id against your allowlist. The intake stage checks you again. It also compares the job's text with the live text of the issue, and refuses a job whose text differs.

The run never decides for you. When a stage waits for a person, it prints the exact `factory-cli` command, and it waits.

## Before you start

You need these on your Mac:

- Docker Desktop, running, with the factory's sandbox images built. Build them with `infra/sandbox-images/build.sh`.
- The GitHub command line, `gh`, logged in as you. Run `gh auth login` once.
- Rust (the repository pins the version) and Python 3.
- PostgreSQL. Set `FACTORY_DB_ADMIN_URL` to a server the run may make a database on, or install PostgreSQL 16 or later so the run can start a private one.
- Your Claude subscription token in `~/claud-oauth-token.txt`, as one line, with mode `600`. The section "How the owner turns it on" of the decision record on subscription mode says how to make it. The live check `cargo test -p factory-egress --test live_subscription -- --ignored` already passed with it.
- A GitHub account or organization where you may create a repository. The fixture repository is **public** by default, because GitHub Free offers rulesets only on public repositories and the factory needs the ruleset. The `ortisun` organization is on GitHub Free. On GitHub Pro, Team or Enterprise you may make it private with `--private`.

## The steps, in order

### 1. Confirm the routing policy

The run is in the production profile. That profile refuses `policies/model_routing.yaml` while it waits for your confirmation.

Done on 2026-11-13: the prices were read from the Anthropic and OpenAI price pages, each model names its page and the date, and `policy.status` is `enforced`. When a price changes, read it again, write the new price and date, and keep the status. In subscription mode the prices do not set what you pay. They set how much of your plan one job may use, counted in dollars at list price.

The job budget is `job.max_micro_usd` in the same file: 10 dollars today. The run prints it when the job starts. To give one run less, set `FACTORY_E2E_JOB_BUDGET_USD`, for example `export FACTORY_E2E_JOB_BUDGET_USD=5`. A run can lower the budget and never raise it.

### 2. Know who reviews

Read [Who reviews the code](#who-reviews-the-code) below. In subscription mode another Claude model reviews each piece of work, and the evidence records that as a weaker check than a review by another family. Make sure the broker serves both Claude models (the `anthropic` entry of `broker.upstreams` lists no models, or lists both `claude-sonnet-5-5` and `claude-opus-5-5`); otherwise the reviews wait for a person.

### 3. Make the GitHub App

```bash no-run reason="it opens a page that creates an App on your GitHub account"
scripts/github_app_manifest.py serve --name software-factory-YOURNAME
```

The script writes a manifest from `policies/security.yaml`, `credentials.github_app.permissions_required`. The App asks for these permissions and no others: Metadata read, Contents write, Pull requests write, Issues write, Checks write, Commit statuses write, Actions read, and Administration read. It has no webhook and subscribes to no event, because nothing in the run needs one. It is private.

Open the address it prints, check the list, and press the button. GitHub shows you the App before it creates it. Press "Create GitHub App". GitHub sends your browser back to the script. The script fetches the App's id and private key, writes the key to `~/.config/software-factory/github-app/github-app.private-key.pem` with mode `600`, and prints the id. It never prints the key.

App names are unique on GitHub. Give your own name with `--name`. For an App owned by an organization, add `--org ORG`.

If you would rather not run a local server, use `render` and then `convert`:

```bash no-run reason="it creates an App on your GitHub account; CODE comes from the address GitHub sends you to"
scripts/github_app_manifest.py render --name software-factory-YOURNAME
scripts/github_app_manifest.py convert CODE
```

`render` writes the page `create-github-app.html` next to the manifest. After you create the App, copy the `code` from the address bar and run `convert` within the hour. To see the permissions without creating anything, run `scripts/github_app_manifest.py check`.

### 4. Make the fixture repository

The factory's fixture repository is `ortisun/factory-fixture-word-count`. Look first. The `--check` mode makes no call to GitHub and changes nothing:

```bash no-run reason="it reads the App id of your App"
scripts/setup-fixture-repository.sh --check --app-id APP_ID ortisun/factory-fixture-word-count
```

Then make it:

```bash no-run reason="it creates a public repository in the ortisun organization"
scripts/setup-fixture-repository.sh --app-id APP_ID ortisun/factory-fixture-word-count
```

**The repository is public.** GitHub Free offers rulesets only on public repositories, and the `ortisun` organization is on GitHub Free, so `--public` is the default. Anyone can then read the fixture's code, its issues, its pull requests, the factory's check runs and the factory's comments. Put nothing private in the repository, and nothing private in a test issue: no token, no key, no password, no personal data, no text you would not publish. The factory does its part: it never writes a credential into the repository or an issue, the run files the issue from the tracked file `tests/end_to_end/issues/json-output-en.json`, the token of your subscription is registered with the redactor before anything can print it, and the pull request's title, body and the reviewer's words are redacted before they are stored or sent. The script also refuses to push a copy that holds anything that looks like a secret (a private key, a provider key, a GitHub token, or a file named `.env`, `*.pem` or `*.key`). On GitHub Pro, Team or Enterprise you may pass `--private` instead.

The script makes these `gh` calls, in this order, and no others:

| Step | Call |
|---|---|
| Who you are, when you give no `--owner` | `gh api user --jq .login` |
| The repository, public unless you pass `--private`, with the copy pushed | `gh repo create OWNER/NAME --public --description ... --source DIR --remote origin --push` |
| The label the factory starts on | `gh label create factory --repo OWNER/NAME --color 5319e7 --description ...` |
| The ruleset | `gh api --method POST repos/OWNER/NAME/rulesets --input RULESET.json` |
| The ruleset, read back | `gh api repos/OWNER/NAME/rulesets` |

The copy is the word-count fixture, the Spec Kit files of this checkout, and a starting constitution in `.specify/memory/constitution.md`. Read the constitution: it is yours. The copy's `CODEOWNERS` names you, or the owners you give with `--owner`, on every line. No `@example-org` placeholder is left.

The ruleset protects the default branch the way the protection preflight requires (`policies/security.yaml`, `credentials.repository_requirements`):

- a pull request with one approving review and a code owner's review;
- approvals dismissed by a new push;
- no force push and no deletion;
- the checks `factory-validation` and `factory-review` required and pinned to your App;
- nobody on the bypass list.

The script keeps its copy in `target/e2e-fixture/OWNER/NAME`. The harness reads its `CODEOWNERS` from there.

### 5. Install the App on the fixture repository

Open your App's settings page (the script of step 3 printed it). Choose "Install App", and install it on the fixture repository only. The run finds the installation itself.

Then make the ruleset: `scripts/setup-fixture-repository.sh --ruleset-only --app-id ID OWNER/NAME`. GitHub refuses a ruleset whose required checks name an App that is not installed on the repository yet ("Invalid integration ids", seen on the real GitHub on 2026-11-13), so the first run of the script in step 4 stops at the ruleset, with the repository made and pushed. That is expected.

### 6. Write your allowlist

The allowlist names the people the factory knows, by numeric GitHub id. Write one entry for yourself. `gh api user --jq .id` prints your numeric id. The tenant is any UUID; make one with `uuidgen | tr A-Z a-z`. Keep the file outside the repository.

```yaml
version: 1
entries:
  - tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60
    github_user_id: 1234567
    login: YOURNAME
    designations: [requester, approver, operator]
```

### 7. Run E1

```bash no-run reason="it calls GitHub and the model provider with your credentials"
export FACTORY_E2E_GITHUB_APP_ID=APP_ID
export FACTORY_E2E_GITHUB_APP_KEY_FILE=~/.config/software-factory/github-app/github-app.private-key.pem
export FACTORY_E2E_FIXTURE_REPO=ortisun/factory-fixture-word-count
export FACTORY_E2E_REQUESTER_ALLOWLIST=~/factory-allowlist.yaml
scripts/e2e.sh --scenario E1
```

Run it in a terminal, and keep that terminal open. The first time, it builds the factory, which takes a while.

The harness first checks everything it can on your Mac. It names each missing item on its own `BLOCKED:` line and exits with code 3. A `BLOCKED` run has passed nothing. Then it calls the factory's composed wiring program, `scripts/e2e-composed.sh`, twice:

1. `protection` reads the protection of your default branch through the App. The harness refuses to go on if it falls short.
2. `run E1` files the issue as you, starts the job, and drives it to its end.

## During the run

The run talks to you on the terminal, and it writes the same lines to `target/e2e-real/latest/next-step.txt`. Each wait shows the command to type in another terminal. The commands use the run's own API on `127.0.0.1` and your token for it in `target/e2e-real/latest/owner-api-token`. That token opens only the run's private database, which is thrown away.

| When | What you do |
|---|---|
| The specification draft waits | Read it with `factory-cli show-draft`. Approve it with `factory-cli approve JOB STAGE_RUN head=H evidence=sha256:D`, or reject it with `factory-cli reject`. The run prints the exact values. |
| The specification asked questions | `factory-cli show-draft` lists them (`Q-001: ...`). Answer them with `factory-cli answer JOB STAGE_RUN -- Q-001: <answer> Q-002: <answer>`; the stage runs again with the answers. The run prints the command and the questions on its `Answer it:` line. |
| A review waits (rare: only when no other Claude model is served) | See the next section. The factory refuses an approval there. |
| The draft pull request waits | Read it on GitHub. Approve it with `factory-cli approve`, or reject it. Approving merges nothing: the pull request stays a draft. |

A decision may wait 240 minutes. Set `FACTORY_E2E_HUMAN_WAIT_MINUTES` to change that. When the time is up, the run stops and records what it has.

## Who reviews the code

The policy wants every reviewer to be another model than the one that wrote the work (`policies/model_routing.yaml`, section 4, `independence`, `must_differ_by: model`). In subscription mode only Claude runs, so no reviewer of another model family exists. The owner decided on 2026-11-13 that another Claude model reviews instead ([the decision record on subscription mode](../adr/0020-subscription-mode-by-default.md), amendment of 2026-11-13):

- Claude Opus reviews what Claude Sonnet wrote, and Claude Sonnet reviews what Claude Opus wrote.
- This holds for the code review, the documentation review and the specification review. The documenting stage records which model wrote the documentation, and the specification reviewer is routed against the specification writer's model.
- The policy lists Claude Opus only at the large tier, so the router looks there when the standard tier offers only the author's own model.

A review by another model of the same family is a **weaker check** than a review by another family: two models of one family tend to share blind spots. The run says so each time:

- the audit log has a record `review-independence same-family-other-model: <reviewer> reviews the work of <author> in <stage>` for each such review;
- the evidence manifest of the pull request lists the code review and the documentation review among its limitations, with both models named;
- the run's own list of limitations (`mode.json`) says it.

The review waits for a person, with the reason `independent-reviewer-unavailable`, only when no model other than the author's own is served at any tier. In this run that means the broker does not serve both Claude models. From that wait you can send the work back (`factory-cli rework JOB STAGE_RUN target=IMPLEMENTATION ...`), reject the job (`factory-cli reject`), or cancel it (`factory-cli cancel`). The factory refuses an approval there, because it would pass the review with no review verdict, and it records the refusal in the audit log.

In `api_key` mode, with both providers served, the reviewing routes list the model of the other family first, so the reviewer is still of another family. A project that wants that strength always can set `must_differ_by: family` in its own routing policy; in subscription mode its reviews then wait for a person.

## What the run writes

Everything goes under `target/e2e-real/`. The newest run is `target/e2e-real/latest`.

| File | What it holds |
|---|---|
| `answer.json` | What the program printed: the protection, or the evidence of the run. |
| `blocked.txt` | Why the run could not go on, one reason per line, when it could not. |
| `next-step.txt` | What the run asked you to do, with the exact commands. |
| `owner-api-token` | Your token for the run's own API (mode `600`). |
| `recording/E1/` | The evidence the harness judged: `evidence.json`, the ledger and its head, the timeline as the API served it, every gate report, the stage outputs, the timings, the adapters and limitations of the run in `mode.json`, and `MANIFEST.json` with the SHA-256 of each file. |
| `run.log` | The output of the run. |

The evidence holds the job, its stage runs and attempts, the evidence ledger (its chain is verified when it is written), the audit stream, the timeline, the specification and the task graph, every gate report, the pull request and its commits as GitHub holds them, every GitHub request the App sent (the method and path only), the permissions and repository of every installation token it asked for (never a token), the spans and the correlation ids, and what the job spent at list price against its budget.

To keep the evidence, pass `--evidence-dir DIR` to `scripts/e2e.sh`. It writes the harness's verdicts there too.

## If the run says BLOCKED

Each line names one item. The items only you can provide are: the App id, the App's key file, the fixture repository, the allowlist, and the confirmation of the routing policy. Anything else that is `BLOCKED` is a problem of this machine or of the factory, and the line says which.
