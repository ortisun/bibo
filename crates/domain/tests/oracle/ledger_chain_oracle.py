#!/usr/bin/env python3
"""An independent computation of the evidence ledger hash chain.

This script is the oracle for the Rust function `factory_domain::ledger::chain_hash`. It is
written from the wording of ADR 0008 and shares no code with the Rust crate. It uses the Python
standard library only.

ADR 0008 says: "`entry_hash` is the SHA-256 of the previous entry's hash text (empty for the first
entry), a newline, and the RFC 8785 canonical JSON of the entry without its `entry_hash`."

Reading of that sentence, used here and in the Rust code:

* The previous entry's hash text is the whole `entry_hash` string of the previous entry, with its
  `sha256:` prefix, as stored.
* The entry that is canonicalized still contains its own `prev_entry_hash` field. Only
  `entry_hash` is removed.
* The result is written back as `sha256:` followed by 64 lowercase hex characters.

RFC 8785 for these documents: object keys sorted, no insignificant whitespace, strings escaped
with only the two-character forms for quote, backslash, backspace, form feed, newline, carriage
return and tab and `\\u00xx` (lower case) for other control characters below U+0020, and no
escaping of anything else. Ledger entries hold integers and no floating-point numbers (ADR 0008),
and the oracle refuses integers that a 64-bit float cannot hold exactly, because RFC 8785 would
round them. Python sorts keys by code point where RFC 8785 sorts by UTF-16 code unit. The two
orders differ only for keys outside the Basic Multilingual Plane, and ledger entries have a fixed
set of ASCII keys, so they agree here.

Usage:

    python3 -I ledger_chain_oracle.py            # rewrite the chain fixture
    python3 -I ledger_chain_oracle.py --check    # fail if the committed fixture differs
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT = os.path.join(HERE, '..', 'fixtures', 'ledger_chain_input.json')
OUTPUT = os.path.join(HERE, '..', 'fixtures', 'ledger_chain.json')

SAFE_INTEGER = 2**53 - 1


def reject_unsafe_numbers(node):
    if isinstance(node, bool):
        return
    if isinstance(node, float):
        raise ValueError('a ledger entry must not hold a floating-point number')
    if isinstance(node, int) and abs(node) > SAFE_INTEGER:
        raise ValueError(f'the integer {node} is beyond what a 64-bit float holds exactly')
    if isinstance(node, dict):
        for value in node.values():
            reject_unsafe_numbers(value)
    if isinstance(node, list):
        for value in node:
            reject_unsafe_numbers(value)


def canonical_json(document):
    reject_unsafe_numbers(document)
    return json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def chain_hash(previous_hash_text, canonical):
    data = (previous_hash_text or '').encode('utf-8') + b'\n' + canonical
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def build_chain():
    with open(INPUT, encoding='utf-8') as handle:
        entries = json.load(handle)
    chain = []
    previous = None
    for index, body in enumerate(entries, start=1):
        assert body['metadata']['sequence'] == index, 'the input must be in sequence order'
        assert 'entry_hash' not in body and 'prev_entry_hash' not in body
        entry = dict(body)
        entry['prev_entry_hash'] = previous
        entry['entry_hash'] = chain_hash(previous, canonical_json(entry))
        chain.append(entry)
        previous = entry['entry_hash']
    return chain


def render(chain):
    return json.dumps(chain, indent=2, sort_keys=True, ensure_ascii=False) + '\n'


def main():
    text = render(build_chain())
    if '--check' in sys.argv:
        with open(OUTPUT, encoding='utf-8') as handle:
            current = handle.read()
        if current != text:
            sys.exit('ledger_chain.json differs from what the oracle computes')
        print('ledger_chain.json matches the oracle')
        return
    with open(OUTPUT, 'w', encoding='utf-8') as handle:
        handle.write(text)
    print(f'wrote {OUTPUT}')


if __name__ == '__main__':
    main()
