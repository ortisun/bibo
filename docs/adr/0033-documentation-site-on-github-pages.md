# 0033: Publish the documentation as a site on GitHub Pages, built from docs/ with MkDocs Material

- Status: **Decided by the owner on 2026-11-21** (a public repository and a public site); the engineer chose the tools and the workflow. No independent review has covered it.
- Date: 2026-11-21
- Deciders: the owner chose to make the repository public and to publish the documentation like an open-source project; the engineer weighed how.
- Related: the documentation policy ([documentation-policy.md](../reference/documentation-policy.md)), the workflow rules checked by `scripts/ci.sh` (negative test ST-10 in the [negative test catalog](../security/negative-test-catalog.md)), [`AGENTS.md`](../../AGENTS.md) (documents first).

## Context and problem statement

The documentation lives in `docs/` as Markdown: 162 pages of guides, reference, runbooks, architecture, decision records, reviews and reports. It reads well on GitHub one file at a time, but it has no front page, no navigation across sections and no search. A newcomer cannot see where to start.

On 2026-11-21 the owner asked (in Portuguese) to make the project available as documentation on GitHub Pages, chose to make the repository `ortisun/bibo` public, and asked for "a professional quickstart documentation, like other open-source projects do".

Three facts bound the choice:

1. The organization is on GitHub's free plan. There, GitHub Pages serves only a public repository, and every Pages site is public.
2. `docs/` is the source of truth ([`AGENTS.md`](../../AGENTS.md)). A second copy of the documents for the site would be a near-duplicate, which the documentation policy calls a defect.
3. The workflow rules in `scripts/ci.sh` refuse any workflow that asks for a write permission. Deploying to Pages needs `pages: write` and `id-token: write`.

## Considered options

### The site generator

1. **MkDocs with the Material theme** (chosen). Reads `docs/` as it is, renders the Mermaid diagrams the documents already use, has search, light and dark themes, an edit link to each page and a navigation written in one file. Python, the language of the repository's other tooling, pinned by hash.
2. **Docusaurus.** A strong site generator, but it needs Node.js, a React build and MDX, which treats some plain Markdown as code and would need changes to the documents.
3. **mdBook.** Native to Rust, but no built-in Mermaid, a weaker search and no tabs or cards for a front page.
4. **GitHub's built-in Jekyll build.** Nothing to install, but no navigation across 162 pages, no Mermaid and no strict check of links.

### How the site is deployed

1. **A Pages artifact deployed by the official `actions/deploy-pages` action** (chosen). No generated files enter the repository. The deploy job alone holds `pages: write` and `id-token: write`, and only on a push to `develop`.
2. **A `gh-pages` branch written by the workflow.** Needs `contents: write`, which can change any branch, and keeps generated HTML in the history.
3. **Versioned documents with `mike`.** One site per release. Worth it once releases exist; today `main` holds no release, and `mike` also needs a `gh-pages` branch.

### Which branch is published

1. **`develop`** (chosen). It holds all the current work and documents; `main` stays at the first commit until the first release, under the gitflow rule. The front page says the project is not yet proven live.
2. **`main`.** Would publish an empty site until the first release.

## Decision outcome

- **Build.** `mkdocs.yml` at the root of the repository builds the site from `docs/`. `scripts/docs-site.sh build` installs MkDocs and the Material theme into `.tools/docs-site/` with `uv pip sync --require-hashes`, from `.github/tools/mkdocs/requirements.txt`, and runs `mkdocs build --strict`. A broken link, a broken anchor or a page missing from the navigation fails the build. The same command runs on a laptop, in `scripts/ci.sh` (step `docs-site`) and in the Pages workflow.
- **Pinned tools.** The requirements are compiled for Python 3.12 with a hash for every package, and with `--exclude-newer` set 14 days before the compile date, so a package published in the last two weeks is never picked up.
- **The documents stay as they are.** A hook, `.github/tools/mkdocs/hooks.py`, changes two things in the rendered copy and nothing on disk. A relative link to a file outside `docs/`, such as a source file, becomes a link to that file on GitHub; a link to a folder in `docs/` becomes a link to its `README.md`. A code fence marked for `scripts/docs-check.sh`, such as `bash quickstart step=build`, keeps only its language, because the extra words are for the check and not for the reader. The hook never hides a broken link.
- **New pages.** A front page (`docs/index.md`), a page of core concepts (`docs/concepts.md`), a contributing guide (`docs/CONTRIBUTING.md`) and a security policy (`docs/SECURITY.md`). GitHub also shows the last two as the repository's contributing guide and security policy.
- **Deploy.** `.github/workflows/pages.yml` runs on a push to `develop` and when started by hand. Its build job reads the repository only. Its deploy job asks for `pages: write` and `id-token: write`, uses the `github-pages` environment, and deploys the artifact of the build job.
- **The workflow rule changes, narrowly.** The rule "a workflow may not request write permission" gets one exception. A workflow may ask for `pages: write` and `id-token: write`, and nothing else, when no `pull_request` trigger can start it. Every other write permission is still refused in every workflow, and a workflow that pull requests can start still gets no write permission at all. `scripts/ci.sh --self-test-pinning` holds a case for each side of the exception.
- **License.** A public repository without a license is not open source: nobody may use, copy or change the code. The owner chose the MIT License on 2026-11-21, over Apache-2.0, AGPL-3.0 and no license. `LICENSE` holds it, for "The Bibo Authors". The workspace crates stay unpublished (`publish = false`), so their manifests carry no `license` field and `deny.toml` keeps ignoring them as private.
- **Logo.** Bibo is a grey Pomeranian. The logo, `docs/assets/bibo-logo.svg`, is drawn by hand as SVG. The site uses it as its logo and as its icon, and takes its colours from it.

## Consequences

- Good: one front page, a navigation over every section, search, and an edit link on every page. The documents stay the single source, and a broken link now fails a check.
- Good: the only write permissions in the repository's workflows are the two that Pages needs, held by one job that a pull request cannot start.
- Bad: the site shows `develop`, which may hold documents of work that is not released. The front page states the status. When the first release exists, a new record should decide between publishing `main` and versioned documents.
- Bad: the security reviews, the threat model and every finding become public with the repository. The owner accepted this when choosing a public repository.
- Neutral: a new page needs a line in the `nav` of `mkdocs.yml`; the strict build says so when it is missing.

## What was checked and what was not

- Checked: `scripts/docs-site.sh build` passes in strict mode on the branch that added this record. The workflow rules pass on `.github/workflows/`, and the self-test cases for the new exception pass.
- Not checked: the first deploy to GitHub Pages runs only after the repository is public and this record is merged into `develop`.
