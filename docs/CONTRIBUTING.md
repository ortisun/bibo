# Contributing

- Form: how-to guide.
- Reader: a person who wants to change Bibo itself. To use Bibo on your own project, start with the [quickstart](guides/quickstart.md) instead.

Thank you for helping. This page says how a change is made, checked and proposed. The rules for agents that work in this repository are in [`AGENTS.md`](../AGENTS.md); they apply to people too.

## Documents come first

The `docs/` directory is the source of truth. Before you change code or a rule, update the document that describes it, then change the code to match. A change whose documents were not updated first is not done. A decision that is hard to reverse gets a [decision record](adr/README.md).

Write in plain English, in short sentences, for a reader who sees the page for the first time. The [documentation policy](reference/documentation-policy.md) holds the full rules.

## Branches and commits

The repository follows gitflow:

| Branch | Starts from | Merges into |
|---|---|---|
| `feature/<name>` | `develop` | `develop` |
| `bugfix/<name>` | `develop` | `develop` |
| `release/<version>` | `develop` | `main` and `develop` |
| `hotfix/<name>` | `main` | `main` and `develop` |

Nobody commits directly on `main` or `develop`. Every change reaches them through a pull request.

Every commit message is a [Conventional Commit](https://www.conventionalcommits.org/): `type(scope): subject`, where the type is one of `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style` or `test`. The body says why the change was made. A breaking change carries `!` after the type and a `BREAKING CHANGE:` footer.

## Set up the tools

The Rust toolchain is pinned in `rust-toolchain.toml`. The check tools are pinned in `scripts/lib/tool-pins.sh`:

```bash no-run reason="installs tools into .tools/bin; the result depends on the machine"
scripts/setup-tools.sh --check
scripts/setup-tools.sh
```

The first command shows what is missing and changes nothing. The second installs the missing tools into `.tools/bin`.

## Check a change

`scripts/ci.sh` runs every check, on a laptop and in CI alike. A step whose tool is missing is reported as BLOCKED, never as passed.

```bash no-run reason="runs the full check suite, which takes many minutes and needs Docker and PostgreSQL"
scripts/ci.sh
```

While you work, run only the tests of what you changed and of the code tied to it. [`AGENTS.md`](../AGENTS.md) shows how to narrow a run. The full suite runs in CI.

To check the documents the way the factory checks the documents of others:

```bash no-run reason="builds the factory's command line to compare the documents with its help output"
scripts/docs-check.sh
```

## Preview the documentation site

This site is built from `docs/` with MkDocs and the Material theme, at versions pinned by hash. [ADR 0033](adr/0033-documentation-site-on-github-pages.md) records why.

```bash no-run reason="starts a local web server that runs until it is stopped"
scripts/docs-site.sh serve
```

The preview is at `http://127.0.0.1:8000` and reloads when a file changes. `scripts/docs-site.sh build` builds the site once, with every warning treated as an error. A new page needs an entry in the `nav` section of `mkdocs.yml`, or the build fails.

## Propose the change

1. Push your branch and open a pull request into `develop`.
2. Give it a Conventional Commit title and say in the body what changed, why, and how you checked it.
3. CI must pass. A reviewer from [`CODEOWNERS`](../.github/CODEOWNERS) reviews it.

## License of contributions

Bibo is released under the [MIT License](../LICENSE). By opening a pull request, you agree that your contribution is released under the same license.

## Report a vulnerability

Do not open a public issue for a security problem. Follow the [security policy](SECURITY.md).
