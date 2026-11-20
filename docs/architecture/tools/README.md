# Architecture checking tools

Small scripts that keep the architecture documents honest. They check the JSON sources, regenerate the tables in the documents, and prove the rules the documents state. Nothing here is part of the product.

Run every command from the repository root.

| Script | What it checks | Command |
|---|---|---|
| `render_state_machine.py` | `state-machine.json` is deterministic, has no dead end or unreachable state, and `state-machine.md` is in sync | `python3 -I docs/architecture/tools/render_state_machine.py --check` |
| `check_crate_rules.py` | `crate-dependency-rules.json` points inward, has no cycle, and the crate tables and graph in `overview.md` are in sync | `python3 -I docs/architecture/tools/check_crate_rules.py --check` |
| `check_work_packages.py` | `work-packages.json`: concurrent packages own disjoint paths, the graph has no cycle, port lists agree, every P0 negative test in the security catalog has an owner, and `slice-plan.md` is in sync. `--summary` prints the waves and the critical path | `python3 -I docs/architecture/tools/check_work_packages.py --check` |
| `check-mermaid.sh` | Every Mermaid block in the given Markdown files parses with Mermaid's own parser. Syntax only: it does not render | `docs/architecture/tools/check-mermaid.sh docs/architecture/overview.md docs/architecture/state-machine.md docs/architecture/slice-plan.md` |

Add `--write` to the three Python scripts to regenerate the document sections between the `GENERATED` markers. Never edit those sections by hand.

## Requirements

- Python 3 for the three scripts. They use only the standard library.
- Node and npm for the Mermaid check.
- `pyright` to type-check the scripts: `pyright docs/architecture/tools/*.py`.

## About `npm ci`

The Mermaid check needs two npm packages, pinned in `package.json` and `package-lock.json`. `check-mermaid.sh` copies those files and `check-mermaid.mjs` into a temporary directory, runs `npm ci --ignore-scripts` there, runs the check, and deletes the directory. No `node_modules` folder is created in the repository, and none should be committed. If you run `npm ci` in this directory by hand, delete the `node_modules` folder afterwards.

To inspect the installed packages once:

```bash
tmp="$(mktemp -d)" && cp docs/architecture/tools/package*.json docs/architecture/tools/check-mermaid.mjs "$tmp" \
  && (cd "$tmp" && npm ci --ignore-scripts && node check-mermaid.mjs "$OLDPWD/docs/architecture/overview.md")
```

## Limits

The scripts check structure and consistency. They do not judge whether a design is right, whether prose is clear, or how a diagram looks. Mermaid's C4 diagram type is experimental, and the parse check cannot tell whether it renders well.
