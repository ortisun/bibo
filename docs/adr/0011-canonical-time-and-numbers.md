# 0011: Compare timestamps by instant, write them in the shortest form, and keep ledger integers within 2^53 - 1

- Status: Accepted by the architect. The defaults are **pending human confirmation** and are listed in [ADR 0009](0009-operating-defaults-pending-confirmation.md), item 12.
- Date: 2026-10-27
- Deciders: software_architect
- Related: [ADR 0008](0008-artifact-store-and-evidence-ledger.md), [`schemas/README.md`](../../schemas/README.md), [`evidence-ledger-entry` schema](../../schemas/evidence-ledger-entry.schema.json)

## Context and problem statement

The ledger hash chain (ADR 0008) takes the SHA-256 of the RFC 8785 canonical JSON of each entry. Canonical JSON fixes key order, string escapes and number spelling, but it does not know what a timestamp is. Two implementation details decide whether a hash can be reproduced:

1. **Time.** The schemas accept `2026-10-27T10:00:00Z` and `2026-10-27T10:00:00.000Z` (one to nine fraction digits). They are the same instant and different text. The domain type `Timestamp` keeps the spelling, so a document reads back as it was written. It derives `PartialEq`, `Eq`, `Hash`, `PartialOrd` and `Ord`, and the derive compares the instant first and then the number of fraction digits. So the two spellings are unequal, they hash differently, and one sorts before the other. Code that asks "is this the same moment" gets the wrong answer, and a set of timestamps can hold both.
2. **Numbers.** RFC 8785 writes every number as a 64-bit float. An integer above 2^53 - 1 is rounded, so the hash would cover a number different from the one stored. The `seeds` of an experiment are the one place in a ledger entry where a large integer is plausible, and the schema allowed any integer.

## What was checked

On 2026-10-27, in this repository.

- `crates/domain/src/values/timestamp.rs`: the struct holds a `PrimitiveDateTime` and `fraction_digits`, and derives the five traits. The first description of this problem said the derive "orders over the text". It does not. It orders by the instant and then by the digit count, which still gives the unequal and mis-ordered pair described above.
- `Timestamp::from_utc` already writes the shortest form (it drops trailing zero digits). `Timestamp::parse` keeps what it reads. The example `build-and-test-passed.json` has `09:16:31.250Z`, so the existing documents use both forms.
- `crates/domain/src/ledger.rs` refuses a number above 2^53 - 1 when it computes the hash (`LedgerError::IntegerNotRepresentable`). The hash function therefore already protects the chain. The schema did not say so.
- The only integer without a bound in the ledger entry schema was `seeds[]`. `sequence`, `line_start` and `line_end` had a minimum and no maximum.
- RFC 8785's number rule is stated here from the standard as the code comment quotes it, and the `serde_jcs` crate was not tested on a large integer by the architect. The Rust test that already covers the refusal is the evidence.

## Considered options

For time:

1. **Normalize on read.** Rewrite every timestamp to the shortest form when it is parsed. A document no longer reads back as written, so the hash of a document received from outside (a specification contract from the Spec Kit adapter, an agent's output) changes when the factory parses and writes it again.
2. **Reject the long form in the schema.** Tighten the pattern to forbid trailing zeros. This breaks existing examples, needs a new schema version for every schema, and rejects timestamps from tools that print `.000Z`.
3. **Keep the spelling, compare the instant, write the shortest form.**

For numbers:

1. **A schema bound on every integer in a ledger entry.**
2. **A note in the ADR only,** and the hash function as the only guard. A bad value would be found late, when an entry is hashed, instead of when the document is validated.

## Decision outcome

Chosen: **option 3 for time and option 1 for numbers.**

1. **A document keeps its spelling.** `Timestamp` reads and writes the text it was given, and the hash is always taken over the stored text, never over a re-rendered instant. This is already true and stays true.
2. **Equality, hashing and order use the instant only.** `Timestamp` implements `PartialEq`, `Eq`, `Hash`, `PartialOrd` and `Ord` by hand on the instant (seconds and nanoseconds), not by derive. `10:00:00Z` equals `10:00:00.000Z`, and sorting never depends on the spelling. Code that needs to compare text, such as a byte-identical document check, calls `as_text()`.
3. **The factory writes the shortest spelling.** `Timestamp::from_utc` is the only way to make a new value, and it drops trailing zero digits. So two timestamps that the factory wrote for the same instant are byte-identical, and the chain hash of an entry the factory built can be reproduced from the instant alone. A timestamp from outside keeps whatever spelling it had.
4. **Every integer in a ledger entry is between -9007199254740991 and 9007199254740991.** The schema says so for `seeds`, `sequence`, `line_start` and `line_end`. The hash function keeps its own refusal as the second layer. A larger seed belongs in the experiment's stored artifact.
5. **Where it is enforced.**

| Rule | Enforced by |
|---|---|
| Spelling is kept on read and write | A domain round-trip test over every example |
| Equal instants are equal and hash alike | A domain test with both spellings, in `values` |
| New values are in the shortest form | A domain test that `from_utc` output has no trailing zero, and the clippy ban on `now_utc` (the `time` crate's `std` feature stays off, rule DEP-04) |
| Integers within 2^53 - 1 | The schema, the invalid example `seed-above-the-largest-exact-integer`, and a domain test that the schema maximum equals `LARGEST_EXACT_INTEGER` |
| The ledger hash covers the stored text | The independent Python oracle and its fixture (`ledger_chain_oracle.py --check`) |

The schema change is made inside version 1 without a new version, which the README rule on tightening would normally require. The reason is that no ledger entry exists outside the examples, and the code already refused the same numbers. The README records the exception.

## Consequences

- Good: "same instant" means equal, in sets, maps and comparisons, with no helper function that every caller must remember.
- Good: a bad seed is found when the document is validated.
- Bad: `Eq` ignores the spelling while `Serialize` does not, so two equal values can serialize differently. This is documented on the type. A test that compares serialized output must compare text.
- Bad: the manual trait implementations are four small functions that must stay consistent with each other. A test checks `Eq`, `Hash` and `Ord` agree.
- Neutral: the guard code in `machines/guards` uses a helper `instant(...)` to work around the derive. It can go once the traits compare instants.
- Loose end: the gate report field `evidence_hash` says "hash over the canonical form of commands, logs and failures" and does not name the canonical form. The default is RFC 8785 through the same domain function. The owner of `s1-trusted-gates-and-validation` fixes the exact field set in that package, and the security specialist reviews it.

## Confirmation

The domain tests in the table above, `schemas/validate.sh`, and `python3 -I crates/domain/tests/oracle/ledger_chain_oracle.py --check`.
