"""Prove what the secret scan of fsaudit.py reads and what it leaves unread, with no Docker.

    python3 -I infra/sandbox-images/tools/selftest-fsaudit.py

The scan does not read the content of distro documentation (`/usr/share/doc/`,
`/usr/share/common-licenses/`, `/usr/share/man/`) when the file is owned by root and nobody else
can write it. This test builds small image file systems as tar streams, runs `fsaudit.py fs` on
them, and shows:

  * a Debian-style documentation file with an anonymous CVS address is not a finding;
  * the same text anywhere else is a finding, and so is a real secret shape;
  * a file under the three trees that the sandbox user owns, or that others can write, or that
    carries a set-id bit, is scanned, and a path that only looks like it is under them (a lookalike
    prefix, a `..` that leaves, a doubled slash) is scanned;
  * the exemption cannot hide a credential by name (`id_rsa`, `.env`, `*.key` under
    /usr/share/doc are still findings), a mode (a world-writable or set-id file), a device node, or
    an agent tool;
  * the list of exempt trees is exactly those three prefixes, so a fourth cannot be added without
    changing this test;
  * `documentation.txt` and `summary.txt` say how much was left unread.

Every secret shape is made at run time from parts. Standard library only.
Exit code 0 when every case behaved, 1 when one did not.
"""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Callable, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
POLICY = REPOSITORY / "policies" / "security.yaml"
FORBIDDEN = HERE.parent / "lib" / "forbidden-binaries.txt"
SHELLS = HERE.parent / "lib" / "shells.txt"
ROOT = 0
SANDBOX_USER = 10001

# Built from parts: no secret-shaped literal sits in this file.
SECRET = "gh" + "p_" + "A1b2" * 9
CVS_ADDRESS = "cvs://:" + "pserver:anoncvs" + "@cvs.example.org:/cvsroot/project"


def load_module():
    spec = importlib.util.spec_from_file_location("fsaudit", HERE / "fsaudit.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["fsaudit"] = module
    spec.loader.exec_module(module)
    return module


class Entry:
    def __init__(
        self,
        path: str,
        data: bytes = b"",
        uid: int = ROOT,
        mode: int = 0o644,
        kind: bytes = tarfile.REGTYPE,
        link: str = "",
    ) -> None:
        self.path, self.data, self.uid, self.mode, self.kind, self.link = path, data, uid, mode, kind, link


def tar_of(entries: List[Entry]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for entry in entries:
            info = tarfile.TarInfo(entry.path)
            info.uid, info.gid, info.mode, info.type = entry.uid, entry.uid, entry.mode, entry.kind
            if entry.kind == tarfile.REGTYPE:
                info.size = len(entry.data)
                archive.addfile(info, io.BytesIO(entry.data))
            else:
                info.linkname = entry.link
                archive.addfile(info)
    return buffer.getvalue()


def audit(entries: List[Entry]) -> dict:
    """Runs `fsaudit.py fs` on the entries and returns the finding files, by name."""
    with tempfile.TemporaryDirectory(prefix="sbx-fsaudit-") as scratch:
        out = Path(scratch) / "out"
        done = subprocess.run(
            [
                sys.executable,
                "-I",
                str(HERE / "fsaudit.py"),
                "fs",
                "--out-dir",
                str(out),
                "--forbidden",
                str(FORBIDDEN),
                "--shells",
                str(SHELLS),
                "--policy",
                str(POLICY),
            ],
            input=tar_of(entries),
            capture_output=True,
            check=False,
        )
        if done.returncode != 0:
            raise SystemExit(f"fsaudit failed: {done.stderr.decode(errors='replace')}")
        return {p.name: p.read_text(encoding="utf-8") for p in out.iterdir()}


FAILED: List[str] = []


def expect(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"ok    {label}")
    else:
        print(f"FAIL  {label} {detail}")
        FAILED.append(label)


def mentions(found: dict, name: str, path: str) -> bool:
    return any(line.startswith(path) for line in found[name].splitlines())


def main() -> int:
    module = load_module()

    # The list of exempt trees is exactly these three, each with its trailing slash.
    expect(
        "the exempt trees are exactly /usr/share/doc/, /usr/share/common-licenses/ and /usr/share/man/",
        module.DOCUMENTATION_PREFIXES
        == ("/usr/share/doc/", "/usr/share/common-licenses/", "/usr/share/man/"),
        repr(module.DOCUMENTATION_PREFIXES),
    )

    document = f"Upstream: {CVS_ADDRESS}\n".encode()
    stock = audit(
        [
            Entry("./usr/share/doc/libexample/README", document),
            Entry("./usr/share/common-licenses/Example", document),
            Entry("./usr/share/man/man1/example.1", document),
        ]
    )
    expect("a root-owned documentation file with an anonymous CVS address is not a finding", stock["secrets.txt"] == "", stock["secrets.txt"])
    expect(
        "the three trees are counted as left unread",
        "3 distro documentation file(s)" in stock["documentation.txt"]
        and "documentation_files_not_read 3" in stock["summary.txt"],
        stock["documentation.txt"],
    )

    # The same text elsewhere is a finding: the pattern did not change.
    elsewhere = audit(
        [
            Entry("./etc/example/README", document),
            Entry("./opt/leftover.conf", f"token={SECRET}\n".encode()),
        ]
    )
    expect(
        "the same address outside the documentation trees is a finding",
        mentions(elsewhere, "secrets.txt", "/etc/example/README"),
        elsewhere["secrets.txt"],
    )
    expect(
        "a real secret shape outside the documentation trees is a finding",
        mentions(elsewhere, "secrets.txt", "/opt/leftover.conf"),
        elsewhere["secrets.txt"],
    )

    # Files under the trees that the sandbox user could have written are scanned.
    planted = audit(
        [
            Entry("./usr/share/doc/x/owned-by-the-sandbox-user", f"{SECRET}\n".encode(), uid=SANDBOX_USER),
            Entry("./usr/share/doc/x/world-writable", f"{SECRET}\n".encode(), mode=0o666),
            Entry("./usr/share/doc/x/group-writable", f"{SECRET}\n".encode(), mode=0o664),
            Entry("./usr/share/doc/x/setuid", f"{SECRET}\n".encode(), mode=0o4755),
            Entry("./usr/share/man/man1/owned-by-the-sandbox-user.1", f"{SECRET}\n".encode(), uid=SANDBOX_USER),
            Entry("./usr/share/common-licenses/owned-by-the-sandbox-user", f"{SECRET}\n".encode(), uid=SANDBOX_USER),
        ]
    )
    for name in (
        "/usr/share/doc/x/owned-by-the-sandbox-user",
        "/usr/share/doc/x/world-writable",
        "/usr/share/doc/x/group-writable",
        "/usr/share/doc/x/setuid",
        "/usr/share/man/man1/owned-by-the-sandbox-user.1",
        "/usr/share/common-licenses/owned-by-the-sandbox-user",
    ):
        expect(f"{name} is scanned and the secret is found", mentions(planted, "secrets.txt", name), planted["secrets.txt"])
    expect(
        "none of them is counted as left unread",
        "0 distro documentation file(s)" in planted["documentation.txt"],
        planted["documentation.txt"],
    )

    # A path that only looks like it is under a tree is not under it.
    lookalikes = audit(
        [
            Entry("./usr/share/docs/x", f"{SECRET}\n".encode()),
            Entry("./usr/share/doc-base/x", f"{SECRET}\n".encode()),
            Entry("./usr/share/doc", f"{SECRET}\n".encode()),
            Entry("./opt/usr/share/doc/x", f"{SECRET}\n".encode()),
            Entry("./home/agent/usr/share/doc/x", f"{SECRET}\n".encode()),
            Entry("./usr/share/doc/../../../tmp/x", f"{SECRET}\n".encode()),
            Entry("./usr/share/doc//x", f"{SECRET}\n".encode()),
            Entry("./usr/share/doc/./x", f"{SECRET}\n".encode()),
            Entry("./usr/share/man/../doc-extra/x", f"{SECRET}\n".encode()),
        ]
    )
    for name in (
        "/usr/share/docs/x",
        "/usr/share/doc-base/x",
        "/usr/share/doc",
        "/opt/usr/share/doc/x",
        "/home/agent/usr/share/doc/x",
    ):
        expect(f"{name} is not under a tree and is scanned", mentions(lookalikes, "secrets.txt", name), lookalikes["secrets.txt"])
    expect(
        "a path with .. or . or a doubled slash is scanned, not trusted",
        lookalikes["documentation.txt"].startswith("0 distro documentation file(s)"),
        lookalikes["documentation.txt"],
    )

    # The exemption hides a content read and nothing else.
    names = audit(
        [
            Entry("./usr/share/doc/x/id_rsa", b"not a key\n"),
            Entry("./usr/share/doc/x/.env", b"A=1\n"),
            Entry("./usr/share/doc/x/server.key", b"x\n"),
            Entry("./usr/share/doc/x/.ssh/", kind=tarfile.DIRTYPE, mode=0o755),
            Entry("./usr/share/doc/x/device", kind=tarfile.CHRTYPE, mode=0o644),
            Entry("./usr/share/doc/x/writable-by-all", b"text\n", mode=0o666),
            Entry("./usr/share/doc/x/setid", b"text\n", mode=0o4755),
            Entry("./usr/share/doc/x/claude", b"text\n", mode=0o711),
        ]
    )
    for name in ("/usr/share/doc/x/id_rsa", "/usr/share/doc/x/.env", "/usr/share/doc/x/server.key"):
        expect(f"{name} is still found by its name", mentions(names, "credential-names.txt", name), names["credential-names.txt"])
    expect("a .ssh directory under the tree is still found", mentions(names, "credential-names.txt", "/usr/share/doc/x/.ssh"), names["credential-names.txt"])
    expect("a device node under the tree is still found", mentions(names, "special.txt", "/usr/share/doc/x/device"), names["special.txt"])
    expect("a world-writable file under the tree is still found by its mode", mentions(names, "world-writable.txt", "/usr/share/doc/x/writable-by-all"), names["world-writable.txt"])
    expect("a set-id file under the tree is still found by its mode", mentions(names, "setid.txt", "/usr/share/doc/x/setid"), names["setid.txt"])
    expect("an agent tool under the tree is still hashed", mentions(names, "agent-tools.txt", "/usr/share/doc/x/claude"), names["agent-tools.txt"])

    # A symbolic link into the tree reads nothing and hides nothing: the scan reads regular files.
    linked = audit(
        [
            Entry("./etc/leak", f"{SECRET}\n".encode()),
            Entry("./usr/share/doc/link", kind=tarfile.SYMTYPE, link="/etc/leak"),
        ]
    )
    expect("a link into the tree does not hide the file it points to", mentions(linked, "secrets.txt", "/etc/leak"), linked["secrets.txt"])

    if FAILED:
        print(f"\n{len(FAILED)} case(s) did not behave: {FAILED}")
        return 1
    print("\nevery case behaved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
