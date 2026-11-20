#!/usr/bin/env python3
"""Print the SCRAM-SHA-256 verifier of a password read from a file, for CREATE ROLE ... PASSWORD.

    python3 scripts/scram-verifier.py PASSWORD_FILE [--iterations N]

PostgreSQL stores a password given as a SCRAM verifier as it is, so the SQL text that creates the
login (and the server log, and pg_stat_statements, which keep that text) holds the verifier, never
the password (TR-10 of docs/reviews/troubleshooter-security-review.md). The verifier is computed
here, on the client, as RFC 5802 and RFC 7677 define it and as PostgreSQL's own client libraries do:

    SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>

The password is the first line of the file, without its line end. The file must not be readable by
group or others (chmod 600). Only printable ASCII is accepted: PostgreSQL applies SASLprep to other
characters, and this script does not, so it refuses rather than make a verifier that never matches.
A verifier is still a hash of the password: with a weak password it can be attacked offline, so
use a random one (`openssl rand -hex 24`).

Only the Python standard library is used.
"""

import base64
import hashlib
import hmac
import os
import stat
import sys

DEFAULT_ITERATIONS = 4096  # PostgreSQL's scram_iterations default
SALT_BYTES = 16  # what PostgreSQL uses


def fail(message):
    sys.stderr.write(f"scram-verifier: {message}\n")
    sys.exit(2)


def read_password(path):
    try:
        info = os.stat(path)
    except OSError:
        fail(f"the password file {path} cannot be read")
    if not stat.S_ISREG(info.st_mode):
        fail(f"the password file {path} is not a regular file")
    if info.st_mode & 0o077:
        fail(f"the password file {path} has mode {info.st_mode & 0o777:o}; it must not be readable by group or others (chmod 600)")
    with open(path, "rb") as handle:
        first = handle.readline()
    password = first.rstrip(b"\r\n")
    if not password:
        fail(f"the password file {path} is empty")
    if any(byte < 0x20 or byte > 0x7E for byte in password):
        fail("the password holds a character that is not printable ASCII; this script does not apply SASLprep")
    return password


def verifier(password, salt, iterations):
    salted = hashlib.pbkdf2_hmac("sha256", password, salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    encode = lambda raw: base64.b64encode(raw).decode("ascii")
    return f"SCRAM-SHA-256${iterations}:{encode(salt)}${encode(stored_key)}:{encode(server_key)}"


def main(argv):
    args = list(argv)
    iterations = DEFAULT_ITERATIONS
    if "--iterations" in args:
        at = args.index("--iterations")
        try:
            iterations = int(args[at + 1])
        except (IndexError, ValueError):
            fail("--iterations needs a number")
        del args[at:at + 2]
        if iterations < DEFAULT_ITERATIONS:
            fail(f"--iterations must be at least {DEFAULT_ITERATIONS}")
    if len(args) != 1 or args[0].startswith("-"):
        fail("usage: scram-verifier.py PASSWORD_FILE [--iterations N]")
    password = read_password(args[0])
    print(verifier(password, os.urandom(SALT_BYTES), iterations))


if __name__ == "__main__":
    main(sys.argv[1:])
