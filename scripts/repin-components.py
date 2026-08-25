#!/usr/bin/env python3
"""Regenerate COMPONENTS.sha256 and the tree digests in COMPONENTS.lock.

The two files answer different questions. COMPONENTS.sha256 pins every
vendored file so an edit in place is visible. COMPONENTS.lock says which
upstream commit each vendored tree came from, which no digest can establish
from inside this repository -- so the lock also carries the digest of that
component's manifest lines, and supplychain/snapshot_test.go fails when the
two disagree. That is what stops the lock naming a commit whose code is not
the code that ships.

Commit IDs are not touched: this script cannot know which upstream commit a
tree came from, and guessing would defeat the point. Pass --commit
module=sha to set one when you vendor a new snapshot.
"""

import argparse
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "COMPONENTS.sha256"
LOCK = ROOT / "COMPONENTS.lock"


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rewrite_manifest() -> dict[str, list[str]]:
    lines = []
    for path in sorted(p for p in (ROOT / "components").rglob("*") if p.is_file()):
        relative = path.relative_to(ROOT).as_posix()
        lines.append(f"{digest(path)}  {relative}")
    MANIFEST.write_text("\n".join(lines) + "\n")
    grouped: dict[str, list[str]] = {}
    for line in lines:
        component = line.split("  ", 1)[1].split("/")[1]
        grouped.setdefault(component, []).append(line)
    return grouped


def rewrite_lock(grouped: dict[str, list[str]], commits: dict[str, str]) -> None:
    header, entries = [], {}
    for line in LOCK.read_text().splitlines():
        if line.startswith("#"):
            header.append(line)
            continue
        if not line.strip():
            continue
        fields = line.split()
        entries[fields[0]] = fields[1:]
    out = list(header)
    for component in sorted(grouped):
        module = f"github.com/Jtensetti/{component}"
        existing = entries.get(module)
        if existing is None and module not in commits:
            sys.exit(f"{module} ships but is not in the lock; pass --commit {module}=sha")
        commit = commits.get(module, existing[0])
        branch = existing[1] if existing else "claude/nomad-production-ready-dxv4ql"
        tree = hashlib.sha256(
            ("\n".join(sorted(grouped[component])) + "\n").encode()
        ).hexdigest()
        out.append(f"{module} {commit} {branch} {tree}")
    for module in entries:
        component = module.rsplit("/", 1)[1]
        if component not in grouped:
            sys.exit(f"the lock names {module}, which no longer ships")
    LOCK.write_text("\n".join(out) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", action="append", default=[],
                        metavar="MODULE=SHA",
                        help="set a component's upstream commit")
    arguments = parser.parse_args()
    commits = {}
    for pair in arguments.commit:
        module, _, sha = pair.partition("=")
        if not module or not sha:
            sys.exit(f"--commit wants MODULE=SHA, got {pair!r}")
        commits[module] = sha
    rewrite_lock(rewrite_manifest(), commits)
    print(f"repinned {MANIFEST.name} and the tree digests in {LOCK.name}")


if __name__ == "__main__":
    main()
