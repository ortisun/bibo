# Files that the installer copies into other projects

These files are not part of this repository's own build. `scripts/install.sh` copies them into the project that the factory will serve, and the project's owners review them in a pull request.

| Path | What it is |
|---|---|
| `github/issue-workflow.json` | The labels and the allowed moves, rendered from [`policies/issue-workflow.yaml`](../policies/issue-workflow.yaml). Do not edit it by hand: `scripts/lib/issue_workflow.py render --out` rewrites it, and a check fails when it is stale. |
| `github/workflows/issue-workflow.yml` | The Action that keeps the labels of an issue consistent. It runs `.github/scripts/issue_workflow.py`, a copy of [`scripts/lib/issue_workflow.py`](../scripts/lib/issue_workflow.py), and then `.github/scripts/project_board.py`, a copy of [`scripts/lib/project_board.py`](../scripts/lib/project_board.py), which moves the issue on a GitHub Projects board if the project has one. |
| `github/project-board-policy.json` | The nine board stages, the names they match on an existing board, and the rules that choose a stage, rendered from [`policies/project-board.yaml`](../policies/project-board.yaml). Do not edit it by hand. |
| `github/ISSUE_TEMPLATE/` | The two issue forms: propose a new solution, and request a small, clear change. |

The installer does not register the repository with the factory. A person does, with `factory-cli repository register`, `confirm-map` and `enable`, and the person who enables a repository is not the person who confirmed its map. A project owner who works alone registers the repository with `--single-maintainer`, once, and the audit log records it: see "A single-maintainer repository" in the onboarding guide.

Read the [onboarding guide](../docs/guides/onboarding.md) for how to install them, the [board guide](../docs/guides/project-board.md) for the board, and the decision records [0016](../docs/adr/0016-design-phase-onboarding-and-issue-workflow.md) and [0018](../docs/adr/0018-project-board-mirror-that-adapts.md) for why they are built this way.
