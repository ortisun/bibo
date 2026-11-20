"""Static checks of the service images: what can be judged from the files, with no Docker daemon.

    check_static.py [--root DIR]      judge the files; exit 0 passed, 1 a rule failed
    check_static.py --self-test       damage a copy of the files in memory, one rule at a time, and
                                      require that exactly that rule complains; exit 0 when every
                                      damage is caught

The files are infra/service-images/Dockerfile and build.sh, the .dockerignore at the repository
root, infra/sandbox-images/pins.env and infra/compose/local.yml. The rules are the promises the
README makes: bases pinned by digest, the locked release build, a numeric non-root user, no shell
step in a final image, no credential, a deny-all build context, and a compose file that runs what
the build script makes.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FILES = {
    "dockerfile": "infra/service-images/Dockerfile",
    "build": "infra/service-images/build.sh",
    "ignore": ".dockerignore",
    "pins": "infra/sandbox-images/pins.env",
    "compose": "infra/compose/local.yml",
}

# What the build context may hold: the allow list of the .dockerignore, exactly.
ALLOWED = {
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/",
    "crates/",
    "apps/",
    "xtask/",
    "schemas/",
    "migrations/",
    "docs/database/tests/role_readiness.sql",
    "fixtures/readability/rules.json",
}
# Paths that must never be let back in, however they are spelled.
NEVER = (".git", ".env", "infra/compose/secrets", "target", ".claude")

# What the .dockerignore says after the allow list, line by line and in this order (DR-7): the names
# of credentials left out of what was let in, the sources that are named like one and are code, then
# the folders, which come last because the last rule wins. The audit of the image file systems calls
# the same names credentials (fsaudit.py CREDENTIAL_NAMES and CREDENTIAL_DIRS).
DENIED_NAMES = (
    "**/.DS_Store",
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/*secret*",
    "**/*credential*",
    "**/id_rsa*",
    "**/id_dsa*",
    "**/id_ecdsa*",
    "**/id_ed25519*",
    "**/*.p12",
    "**/*.pfx",
    "**/*.kdbx",
    "**/*.jks",
    "**/*.keystore",
    "**/.netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/.git-credentials",
    "**/.gitconfig",
    "**/auth.json",
)
SOURCES_BACK = ("!**/*secret*.rs", "!**/*credential*.rs")
DENIED_FOLDERS = ("**/target", "**/.aws", "**/.ssh", "**/.gnupg", "**/.docker", "**/.kube")
AFTER_THE_ALLOW_LIST = DENIED_NAMES + SOURCES_BACK + DENIED_FOLDERS
SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|API_?KEY)", re.IGNORECASE)


def instructions(text: str) -> list[tuple[int, str]]:
    """The Dockerfile instructions with their line numbers, continuation lines joined."""
    out: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        out.append((start, (pending + line).strip()))
        pending = ""
    return out


def stages(text: str) -> dict[str, list[tuple[int, str]]]:
    """The instructions of each stage, by stage name. Instructions before the first FROM are 'global'."""
    result: dict[str, list[tuple[int, str]]] = {"global": []}
    current = "global"
    for number, line in instructions(text):
        word = line.split(None, 1)[0].upper()
        if word == "FROM":
            match = re.search(r"\sAS\s+(\S+)\s*$", line, re.IGNORECASE)
            current = match.group(1) if match else f"stage{number}"
            result[current] = [(number, line)]
        else:
            result[current].append((number, line))
    return result


def pins_of(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        if re.fullmatch(r"[A-Za-z0-9_]+=[A-Za-z0-9._:/@+-]*", line.strip()):
            name, _, value = line.strip().partition("=")
            values[name] = value
    return values


def judge(files: dict[str, str]) -> dict[str, list[str]]:
    """Rule id -> problems. A rule with no problem is passed."""
    problems: dict[str, list[str]] = {}

    def fail(rule: str, text: str) -> None:
        problems.setdefault(rule, []).append(text)

    docker = files["dockerfile"]
    by_stage = stages(docker)
    pins = pins_of(files["pins"])

    # BASES-PINNED: every FROM takes its image from an ARG, and pins.env pins both by digest.
    for name, body in by_stage.items():
        for number, line in body:
            if line.upper().startswith("FROM "):
                image = line.split()[1]
                if image not in ("${RUST_BASE}", "${DISTROLESS_BASE}"):
                    fail("BASES-PINNED", f"Dockerfile:{number}: FROM {image} is not one of the two pinned ARGs")
    for name in ("RUST_BASE", "DISTROLESS_BASE"):
        if not re.search(r"@sha256:[0-9a-f]{64}$", pins.get(name, "")):
            fail("BASES-PINNED", f"pins.env: {name} is not pinned by a sha256 digest")
    if "digest" not in files["build"] or "@sha256:" not in files["build"]:
        fail("BASES-PINNED", "build.sh does not check that both bases are pinned by digest")

    # LOCKED-RELEASE: the compile is a release build of the locked versions.
    builds = [line for _, line in by_stage.get("build", []) if "cargo build" in line]
    if not builds:
        fail("LOCKED-RELEASE", "the build stage has no cargo build")
    for line in builds:
        for flag in ("--release", "--locked"):
            if flag not in line.split():
                fail("LOCKED-RELEASE", f"the cargo build lacks {flag}")
    if "rust-toolchain.toml" in "".join(line for _, line in by_stage.get("build", []) if line.startswith("COPY")):
        fail("LOCKED-RELEASE", "rust-toolchain.toml is copied: rustup would download components during the build")

    # REPRODUCIBLE: a fixed clock, remapped paths, clamped file times.
    build_text = " ".join(line for _, line in by_stage.get("build", []))
    if "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" not in build_text:
        fail("REPRODUCIBLE", "the build stage does not set SOURCE_DATE_EPOCH from the pin")
    if "--remap-path-prefix=/src=" not in build_text:
        fail("REPRODUCIBLE", "the source path is not remapped out of the binary")
    if "rewrite-timestamp=true" not in files["build"] or "--provenance=false" not in files["build"]:
        fail("REPRODUCIBLE", "build.sh does not clamp file times or does not switch provenance off")

    # FINAL-STAGES: numeric non-root user, exec-form entry point, nothing that needs a shell.
    for role in ("api", "worker"):
        body = by_stage.get(role)
        if not body:
            fail("FINAL-STAGES", f"no final stage named {role}")
            continue
        words = [(n, line.split(None, 1)[0].upper(), line) for n, line in body]
        if not any(w == "USER" and line.split(None, 1)[1] == "${SERVICE_UID}:${SERVICE_GID}" for _, w, line in words):
            fail("FINAL-STAGES", f"{role}: no USER ${{SERVICE_UID}}:${{SERVICE_GID}}")
        entry = [line for _, w, line in words if w == "ENTRYPOINT"]
        if len(entry) != 1 or not entry[0].split(None, 1)[1].startswith(f'["/usr/local/bin/factory-{role}"'):
            fail("FINAL-STAGES", f"{role}: the entry point is not the program in exec form")
        for number, word, line in words:
            if word in ("RUN", "HEALTHCHECK", "SHELL", "VOLUME", "ADD") or (word == "CMD" and not line.split(None, 1)[1].startswith("[")):
                fail("FINAL-STAGES", f"Dockerfile:{number}: {word} in the {role} image (it has no shell)")
            if word == "COPY" and ("--from=build" not in line or "--chown=0:0" not in line or "--chmod=0555" not in line):
                fail("FINAL-STAGES", f"Dockerfile:{number}: a COPY into {role} that is not root-owned and mode 0555 from the build stage")
    uid = re.search(r"^SERVICE_UID=(\d+)$", files["build"], re.MULTILINE)
    gid = re.search(r"^SERVICE_GID=(\d+)$", files["build"], re.MULTILINE)
    if not uid or not gid or int(uid.group(1)) < 10000 or int(gid.group(1)) < 10000:
        fail("FINAL-STAGES", "build.sh does not fix SERVICE_UID and SERVICE_GID at 10000 or higher")

    # NO-CREDENTIAL: no variable that looks like a secret, no ADD, no copy of the whole context.
    for name, body in by_stage.items():
        for number, line in body:
            word = line.split(None, 1)[0].upper()
            if word in ("ARG", "ENV") and SECRET_NAME.search(line.split(None, 1)[1].split("=")[0]):
                fail("NO-CREDENTIAL", f"Dockerfile:{number}: {word} with a secret-looking name")
            if word == "ADD":
                fail("NO-CREDENTIAL", f"Dockerfile:{number}: ADD (a download or an unpack nobody pinned)")
            if word == "COPY" and re.search(r"^COPY\s+(--\S+\s+)*\.(/)?\s", line + " "):
                fail("NO-CREDENTIAL", f"Dockerfile:{number}: COPY of the whole context")
            if "--secret" in line or "--ssh" in line:
                fail("NO-CREDENTIAL", f"Dockerfile:{number}: a secret or ssh mount")
    copies = [line for _, line in by_stage.get("build", []) if line.startswith("COPY ") and "--from" not in line]
    sent = {
        source
        for line in copies
        for source in [word for word in line.split()[1:] if not word.startswith("--")][:-1]
    }
    for path in sorted(sent):
        if path.rstrip("/") + "/" not in ALLOWED and path not in ALLOWED:
            fail("NO-CREDENTIAL", f"Dockerfile copies {path}, which is not in the allow list")

    # DENY-ALL-CONTEXT: the .dockerignore leaves everything out and lets back in only the allow list.
    rules = [line.strip() for line in files["ignore"].splitlines() if line.strip() and not line.strip().startswith("#")]
    if not rules or rules[0] != "*":
        fail("DENY-ALL-CONTEXT", ".dockerignore does not start with '*'")
    # The allow list is the run of "!" lines right after "*"; what follows is the deny part, which
    # must be exactly AFTER_THE_ALLOW_LIST: no name missing, none added, none moved.
    allow_end = 1
    while allow_end < len(rules) and rules[allow_end].startswith("!"):
        allow_end += 1
    let_in = {rule[1:] for rule in rules[1:allow_end]}
    if let_in != ALLOWED:
        extra, missing = sorted(let_in - ALLOWED), sorted(ALLOWED - let_in)
        fail("DENY-ALL-CONTEXT", f".dockerignore lets in {extra or 'nothing extra'} and lacks {missing or 'nothing'}")
    for path in let_in:
        if any(path.rstrip("/") == bad.rstrip("/") or path.startswith(bad) for bad in NEVER):
            fail("DENY-ALL-CONTEXT", f".dockerignore lets in {path}")
    after = tuple(rules[allow_end:])
    if after != AFTER_THE_ALLOW_LIST:
        lacking = [rule for rule in AFTER_THE_ALLOW_LIST if rule not in after]
        added = [rule for rule in after if rule not in AFTER_THE_ALLOW_LIST]
        detail = f"lacks {lacking}" if lacking else (f"has {added} that is not on the list" if added else "has the lines in another order")
        fail("DENY-ALL-CONTEXT", f".dockerignore, after the allow list, {detail}; the lines must be exactly those of AFTER_THE_ALLOW_LIST in this order")

    # COMPOSE: the compose file runs the images build.sh makes, as the same user, with no override.
    compose = files["compose"]
    for role in ("api", "worker"):
        match = re.search(rf"^  {role}:\n(.*?)(?=^  \S|^\S|\Z)", compose, re.MULTILINE | re.DOTALL)
        if not match:
            fail("COMPOSE", f"local.yml has no service {role}")
            continue
        block = match.group(1)
        if f"image: ${{FACTORY_{role.upper()}_IMAGE:-factory-{role}:local}}" not in block:
            fail("COMPOSE", f"{role}: the default image is not factory-{role}:local, the tag build.sh makes")
        if "pull_policy: never" not in block:
            fail("COMPOSE", f"{role}: pull_policy is not never")
        if re.search(r"^    (entrypoint|command):", block, re.MULTILINE):
            fail("COMPOSE", f"{role}: overrides the entry point or the command of an image that has no shell")
        if re.search(r"^\s+DOCKER_(HOST|CONFIG):", block, re.MULTILINE):
            fail("COMPOSE", f"{role}: sets DOCKER_HOST or DOCKER_CONFIG, which the worker's docker client never reads (use sandbox.docker_host)")
    if "FACTORY_UID:-10010" not in compose or (uid and uid.group(1) != "10010"):
        fail("COMPOSE", "the user of the images (build.sh) and the default user of the services (local.yml) differ")
    return problems


def load(root: Path) -> dict[str, str]:
    return {key: (root / path).read_text() for key, path in FILES.items()}


# Each damage: (rule that must complain, file, old text, new text). The text must occur once.
DAMAGES = [
    ("BASES-PINNED", "dockerfile", "FROM ${DISTROLESS_BASE} AS api", "FROM gcr.io/distroless/cc-debian13:nonroot AS api"),
    ("BASES-PINNED", "pins", "RUST_BASE=rust:1.98.0-slim-trixie@sha256:", "RUST_BASE=rust:1.98.0-slim-trixie@sha257:"),
    ("LOCKED-RELEASE", "dockerfile", "cargo build --release --locked -p factory-api", "cargo build --release -p factory-api"),
    ("LOCKED-RELEASE", "dockerfile", "COPY Cargo.toml Cargo.lock ./", "COPY Cargo.toml Cargo.lock rust-toolchain.toml ./"),
    ("REPRODUCIBLE", "dockerfile", "ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \\", "ENV UNRELATED=1 \\"),
    ("REPRODUCIBLE", "build", "rewrite-timestamp=true", "rewrite-timestamp=false"),
    ("FINAL-STAGES", "dockerfile", "USER ${SERVICE_UID}:${SERVICE_GID}\nEXPOSE", "USER root\nEXPOSE"),
    ("FINAL-STAGES", "dockerfile", "WORKDIR /\nUSER ${SERVICE_UID}:${SERVICE_GID}\nENTRYPOINT [\"/usr/local/bin/factory-worker\"]", "RUN true\nUSER ${SERVICE_UID}:${SERVICE_GID}\nENTRYPOINT [\"/usr/local/bin/factory-worker\"]"),
    ("FINAL-STAGES", "dockerfile", "ENTRYPOINT [\"/usr/local/bin/factory-api\"]", "ENTRYPOINT /usr/local/bin/factory-api"),
    ("FINAL-STAGES", "dockerfile", "--chown=0:0 --chmod=0555 /out/factory-api", "--chmod=0777 /out/factory-api"),
    ("FINAL-STAGES", "build", "SERVICE_UID=10010", "SERVICE_UID=0"),
    ("NO-CREDENTIAL", "dockerfile", "ARG SOURCE_DATE_EPOCH\n", "ARG SOURCE_DATE_EPOCH\nARG REGISTRY_TOKEN\n"),
    ("NO-CREDENTIAL", "dockerfile", "COPY xtask xtask\n", "COPY xtask xtask\nCOPY infra/compose/secrets secrets\n"),
    ("NO-CREDENTIAL", "dockerfile", "COPY schemas schemas\n", "ADD https://example.org/x.tgz /x\n"),
    ("DENY-ALL-CONTEXT", "ignore", "*\n\n!Cargo.toml", "!Cargo.toml"),
    ("DENY-ALL-CONTEXT", "ignore", "!migrations/\n", "!migrations/\n!infra/compose/secrets/\n"),
    ("DENY-ALL-CONTEXT", "ignore", "**/*secret*\n**/*credential*\n", "**/*credential*\n**/*secret*\n"),
    ("DENY-ALL-CONTEXT", "ignore", "!**/*secret*.rs\n", "!**/*secret*\n"),
    ("DENY-ALL-CONTEXT", "ignore", "!**/*credential*.rs\n", ""),
    ("DENY-ALL-CONTEXT", "ignore", "**/target\n**/.aws\n", "**/.aws\n**/target\n!**/*.rs\n"),
    ("DENY-ALL-CONTEXT", "ignore", "**/.kube\n", "**/.kube\n**/.cache\n"),
] + [
    # One damage per line of the deny part: take it out, and the rule must say so.
    ("DENY-ALL-CONTEXT", "ignore", f"{line}\n", "")
    for line in AFTER_THE_ALLOW_LIST
    if line not in SOURCES_BACK
] + [
    ("COMPOSE", "compose", "image: ${FACTORY_API_IMAGE:-factory-api:local}", "image: ${FACTORY_API_IMAGE:-factory-api:latest}"),
    ("COMPOSE", "compose", "      FACTORY_CONFIG: /etc/factory/worker.yaml\n", "      FACTORY_CONFIG: /etc/factory/worker.yaml\n      DOCKER_HOST: tcp://elsewhere:2375\n"),
    ("COMPOSE", "compose", "    pull_policy: never\n    <<: *hardened\n    profiles: [factory]\n    # Exit code 3", "    pull_policy: always\n    <<: *hardened\n    profiles: [factory]\n    # Exit code 3"),
]


def preview(text: str, width: int) -> str:
    lines = text.strip().splitlines()
    return repr(lines[0][:width]) if lines else "''"


def self_test(files: dict[str, str]) -> int:
    clean = judge(files)
    if clean:
        print(f"the files as they are already fail: {clean}")
        return 1
    caught = 0
    for rule, key, old, new in DAMAGES:
        if files[key].count(old) != 1:
            print(f"WRONG    {rule}: the damaged text occurs {files[key].count(old)} times in {FILES[key]}: {old!r}")
            continue
        found = judge({**files, key: files[key].replace(old, new)})
        if rule in found:
            caught += 1
            print(f"ok       {rule}: caught  ({preview(old, 60)} -> {preview(new, 40)})")
        else:
            print(f"WRONG    {rule}: not caught  ({old[:60]!r} -> {new[:40]!r}); the rules that complained: {sorted(found)}")
    print(f"{caught} of {len(DAMAGES)} damages caught")
    return 0 if caught == len(DAMAGES) else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    try:
        files = load(args.root)
    except OSError as error:
        print(f"BLOCKED: cannot read {error.filename}: {error.strerror}")
        return 3
    if args.self_test:
        return self_test(files)
    problems = judge(files)
    for rule in ("BASES-PINNED", "LOCKED-RELEASE", "REPRODUCIBLE", "FINAL-STAGES", "NO-CREDENTIAL", "DENY-ALL-CONTEXT", "COMPOSE"):
        if rule in problems:
            for text in problems[rule]:
                print(f"FAIL  {rule:<18} {text}")
        else:
            print(f"PASS  {rule:<18}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
