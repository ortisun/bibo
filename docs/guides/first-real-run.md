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
- A GitHub plan that has rulesets on private repositories: GitHub Pro, Team or Enterprise. On GitHub Free, step 4 stops at the ruleset.

## The steps, in order

### 1. Confirm the routing policy

The run is in the production profile. That profile refuses `policies/model_routing.yaml` while it waits for your confirmation.

Done on 2026-11-13: the prices were read from the Anthropic and OpenAI price pages, each model names its page and the date, and `policy.status` is `enforced`. When a price changes, read it again, write the new price and date, and keep the status. In subscription mode the prices do not set what you pay. They set how much of your plan one job may use, counted in dollars at list price.

The job budget is `job.max_micro_usd` in the same file: 10 dollars today. The run prints it when the job starts. To give one run less, set `FACTORY_E2E_JOB_BUDGET_USD`, for example `export FACTORY_E2E_JOB_BUDGET_USD=5`. A run can lower the budget and never raise it.

### 2. Decide what happens at the review

Read [The review waits for a person](#the-review-waits-for-a-person) below. With today's policy, E1 stops at the code review and cannot complete in subscription mode. Decide before the run whether that is the run you want.

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

Look first. The `--check` mode makes no call to GitHub and changes nothing:

```bash no-run reason="it reads the App id of your App; the repository name is yours"
scripts/setup-fixture-repository.sh --check --app-id APP_ID YOURNAME/word-count-fixture
```

Then make it:

```bash no-run reason="it creates a private repository on your GitHub account"
scripts/setup-fixture-repository.sh --app-id APP_ID YOURNAME/word-count-fixture
```

The script makes these `gh` calls, in this order, and no others:

| Step | Call |
|---|---|
| Who you are, when you give no `--owner` | `gh api user --jq .login` |
| The private repository, with the copy pushed | `gh repo create OWNER/NAME --private --description ... --source DIR --remote origin --push` |
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
export FACTORY_E2E_FIXTURE_REPO=YOURNAME/word-count-fixture
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
| The code review waits | See the next section. |
| The draft pull request waits | Read it on GitHub. Approve it with `factory-cli approve`, or reject it. Approving merges nothing: the pull request stays a draft. |

A decision may wait 240 minutes. Set `FACTORY_E2E_HUMAN_WAIT_MINUTES` to change that. When the time is up, the run stops and records what it has.

## The review waits for a person

The policy wants the code reviewer to be a model of another family than the builder (`policies/model_routing.yaml`, section 4, `independence`). In subscription mode only Claude runs. So no model may review the builder's work, and the policy says the review then waits for a person.

The factory now does exactly that. The review stage run and the job go to `WAITING_FOR_HUMAN`, with the reason `independent-reviewer-unavailable` in the audit record. Before this work, the job failed there instead.

From that wait you can send the work back (`factory-cli rework JOB STAGE_RUN target=IMPLEMENTATION ...`), reject the job (`factory-cli reject`), or cancel it (`factory-cli cancel`). There is no command that lets a person approve the review in the model's place, so the job cannot get past the review. E1 then ends without a pull request, and the harness reports it as failed. It says which assertions failed, which is the honest answer.

To let E1 complete on Claude alone, you have to decide one of these first:

- **Pay for an independent reviewer.** Switch `credentials.model_providers.mode` in `policies/security.yaml` to `api_key`, and give the broker an OpenAI key and an Anthropic key, each with a spend limit at the provider. The reviewers then run on an OpenAI model. This run's program does not support that mode yet; it stops with a `BLOCKED` line.
- **Accept a reviewer of the same family but another model.** Change the two rules `code_review_not_by_the_builders_family` and `documentation_review_not_by_the_writers_family` to `must_differ_by: model`. The policy's own check accepts that. It is not enough alone: the review stages ask for the standard tier, and the only other Claude model is Claude Opus, which the policy lists at the large tier. The review stage would also have to ask for the large tier when no standard model is independent. That is a code change, which needs your decision first.
- **Let a person stand in for the reviewer.** A new decision that records a person's review verdict, and that the delivery stage accepts in place of the model's. That is a larger change, and it puts a person's judgment in the evidence where the policy expects a model's.

Two more reviewers do not apply the independence rule today, in either mode. The documentation reviewer is routed without the writer's model, because the documenting stage does not record which model wrote the documentation. The specification reviewer shares one stage and one job token with the specification writer, so it always runs on the writer's model. The evidence of the run lists this among its limitations.

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
