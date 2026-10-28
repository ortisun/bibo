"""Known-answer vectors for the webhook verifier, computed with the Python standard library.

The Rust verifier and this script share no code, so a vector that both agree on is an independent
check of the HMAC-SHA256 construction and of the `sha256=` header format.

    python3 -I crates/github/tests/vectors/make_webhook_vectors.py            # rewrite the file
    python3 -I crates/github/tests/vectors/make_webhook_vectors.py --check    # fail if it differs

The keys are plain sentences made for this file. They are not credentials and protect nothing.
"""

import hashlib
import hmac
import json
import pathlib
import sys

CASES = [
    (
        "short object",
        "known answer vector one, thirty-two bytes plus",
        '{"action":"edited","installation":{"id":42}}',
    ),
    (
        "pretty printed with a newline at the end",
        "known answer vector two, a longer sentence than the first one is",
        '{\n  "action": "labeled",\n  "installation": {"id": 7},\n  "label": {"name": "factory"}\n}\n',
    ),
    (
        "non-ascii text in the body",
        "known answer vector three, with words only and no digits at all here",
        '{"action":"edited","installation":{"id":1},"issue":{"title":"café ☃ 中文"}}',
    ),
    (
        "body at the size limit",
        "known answer vector four, the key is a sentence of plain words",
        None,
    ),
]

LIMIT = 1_048_576


def body_for(text):
    if text is not None:
        return text
    base = '{"action":"edited","installation":{"id":9}}'
    return base + " " * (LIMIT - len(base.encode("utf-8")))


def build():
    vectors = []
    for name, key, body in CASES:
        text = body_for(body)
        mac = hmac.new(key.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()
        entry = {"name": name, "key_text": key, "mac_hex": mac}
        if body is None:
            entry["body_pad_to"] = LIMIT
            entry["body_start"] = '{"action":"edited","installation":{"id":9}}'
        else:
            entry["body_text"] = text
        vectors.append(entry)
    return {"generator": "make_webhook_vectors.py (python hmac + hashlib)", "vectors": vectors}


def main():
    path = pathlib.Path(__file__).with_name("webhook_known_answers.json")
    text = json.dumps(build(), indent=2, ensure_ascii=True) + "\n"
    if "--check" in sys.argv:
        if not path.exists() or path.read_text() != text:
            print(f"{path} is out of date; run this script without --check")
            sys.exit(1)
        print("the known-answer vectors are up to date")
        return
    path.write_text(text)
    print(f"wrote {path}")


main()
