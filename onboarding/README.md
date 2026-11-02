# Files that the installer copies into other projects

These files are not part of this repository's own build. `scripts/install.sh` copies them into the project that the factory will serve, and the project's owners review them in a pull request.

| Path | What it is |
|---|---|
| `github/issue-workflow.json` | The labels and the allowed moves, rendered from [`policies/issue-workflow.yaml`](../policies/issue-workflow.yaml). Do not edit it by hand: `scripts/lib/issue_workflow.py render --out` rewrites it, and a check fails when it is stale. |
| `github/workflows/issue-workflow.yml` | The Action that keeps the labels of an issue consistent. It runs `.github/scripts/issue_workflow.py`, which is a copy of [`scripts/lib/issue_workflow.py`](../scripts/lib/issue_workflow.py). |
| `github/ISSUE_TEMPLATE/` | The two issue forms: propose a new solution, and request a small, clear change. |

Read the [onboarding guide](../docs/guides/onboarding.md) for how to install them, and [ADR 0016](../docs/adr/0016-design-phase-onboarding-and-issue-workflow.md) for why they are built this way.
