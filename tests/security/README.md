# Security test tools

Status: written on 2026-10-29 by the `s1-security-review-and-tests` work package. An independent review has not happened yet.
Form: reference.

This folder holds the tools that the cross-cutting security tests need and that are not Rust tests themselves.

| File | What it is |
|---|---|
| `mutations.py` | Control-off variants. Each removes one control from the sources, runs the tests that depend on it, writes down which of them failed, and puts the sources back. `--record` copies the result into `docs/security/p0-coverage.json`. It can also run the variants of another package with `--script` |

The tests themselves are in `crates/workflow/tests/security/` and run with `cargo nextest run -p factory-workflow negative_nt_`. The injection corpus is in [`injection/`](injection/README.md). The matrix that says which P0 test has which control-off variant is [`docs/security/p0-coverage.md`](../../docs/security/p0-coverage.md).

The work package `s0-security-baseline` names `tests/security/injection` as the place of a corpus of at least ten cases, and its check is `find tests/security/injection -type f`. The corpus lives there: fifty cases in ten files, and a README. It was first built in `fixtures/injection/`, a folder that no work package owns. Both packages that touch the corpus (`s0-security-baseline` and `s1-security-review-and-tests`) own `tests/security/**`, so the files were moved and the paths in the runner (`crates/workflow/tests/security/corpus.rs`) changed. Changing the check instead would have meant editing the work package source and the slice plan, which belong to other packages.
