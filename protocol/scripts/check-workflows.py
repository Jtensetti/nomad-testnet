#!/usr/bin/env python3
"""Validate GitHub workflow files before they cost a CI run to validate.

A malformed workflow fails remotely in seconds, which reads like a broken
build and is not one. This is the layer-1 check for that: it parses every
workflow, rejects one with no jobs, and reports which ones can be superseded
by a newer push without cancelling the obsolete run.

Run it from a repository root, or pass paths. Exit status is non-zero when a
file is invalid; missing concurrency is reported, not enforced, because a
release workflow should not be cancellable and an event handler does not need
a group.

    scripts/check-workflows.py
    scripts/check-workflows.py ../nomad-testnet
"""

import pathlib
import sys

try:
    import yaml
except ImportError:
    print("pyyaml is required: pip install pyyaml", file=sys.stderr)
    raise SystemExit(2)


def workflows(root: pathlib.Path) -> list[pathlib.Path]:
    directory = root / ".github" / "workflows"
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir() if p.suffix in (".yml", ".yaml"))


def main() -> int:
    roots = [pathlib.Path(argument) for argument in sys.argv[1:]] or [pathlib.Path(".")]
    invalid = 0
    checked = 0
    for root in roots:
        for path in workflows(root):
            checked += 1
            try:
                loaded = yaml.safe_load(path.read_text())
            except yaml.YAMLError as failure:
                print(f"INVALID {path}: {failure}")
                invalid += 1
                continue
            if not isinstance(loaded, dict) or not loaded.get("jobs"):
                print(f"INVALID {path}: no jobs")
                invalid += 1
                continue
            # `on:` parses as the boolean True in YAML 1.1, which is a trap
            # worth naming rather than working around silently.
            if "on" not in loaded and True not in loaded:
                print(f"INVALID {path}: no triggers")
                invalid += 1
                continue
            concurrency = loaded.get("concurrency")
            if concurrency is None:
                print(f"{path}: no concurrency group -- a superseded run will keep going")
            elif not isinstance(concurrency, dict) or "group" not in concurrency:
                print(f"INVALID {path}: concurrency needs a group")
                invalid += 1
    print(f"checked {checked} workflow(s), {invalid} invalid")
    return 1 if invalid else 0


if __name__ == "__main__":
    raise SystemExit(main())
