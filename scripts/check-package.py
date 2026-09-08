#!/usr/bin/env python3
"""Check every imported source file against its pinned upstream snapshot."""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--status', action='store_true')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'PACKAGING.lock.json').read_text())
    registry = json.loads((ROOT / 'protocol/production/readiness.json').read_text())
    if args.status:
        counts = Counter(item['status'] for item in registry['criteria'])
        print('Nomad evaluation kit — production readiness from the pinned registry')
        print(' | '.join(f'{key}: {counts[key]}' for key in ['MET', 'PARTIAL', 'BLOCKED', 'NOT_MET']))
        print('This is a development/evaluation package, not an audited production release.')
        print('Snapshot date:', lock['assembled_on'])
        print('Registry: protocol/production/readiness.json')
        return
    errors = []
    checked = 0
    expected_repos = {
        'Jtensetti/Nomad-browser', 'Jtensetti/nomad-protocol',
        'Jtensetti/nomad-local-reconstruction', 'Jtensetti/nomad-anytrust-mix-sim',
        'Jtensetti/nomad-constant-rate-fabric', 'Jtensetti/nomad-rlnc',
        'Jtensetti/nomad-semantic-basins', 'Jtensetti/nomad-selection-firewall',
    }
    if {s['repository'] for s in lock['snapshots']} != expected_repos:
        errors.append('the eight imported core repositories are not all present')
    for snapshot in lock['snapshots']:
        directory = ROOT / snapshot['path']
        if len(snapshot['commit']) != 40:
            errors.append(f"{snapshot['path']}: upstream commit must be a full SHA")
        expected = {entry['path'] for entry in snapshot['files']}
        for entry in snapshot['files']:
            file = directory / entry['path']
            checked += 1
            if not file.is_file():
                errors.append(f'{file.relative_to(ROOT)}: missing')
            elif hashlib.sha256(file.read_bytes()).hexdigest() != entry['sha256']:
                errors.append(f'{file.relative_to(ROOT)}: differs from pinned source')
            elif bool(file.stat().st_mode & 0o111) != entry['executable']:
                errors.append(f'{file.relative_to(ROOT)}: executable mode differs')
        # Bytecode is a local side effect of the Python conformance checks.
        # All other extra source files in imported snapshots require a repin.
        actual = {
            p.relative_to(directory).as_posix() for p in directory.rglob('*')
            if p.is_file() and '__pycache__' not in p.parts
        }
        for path in sorted(actual - expected):
            errors.append(f"{snapshot['path']}/{path}: unpinned file")
        if not (directory / 'LICENSE').is_file():
            errors.append(f"{snapshot['path']}: licence missing")
    for required in ['nomad', 'README.md', 'COMPONENT_LICENSES.md',
                     'product/BUYER_BRIEF.md', 'product/STATUS.md', 'product/HANDOVER.md']:
        if not (ROOT / required).is_file():
            errors.append(f'{required}: missing')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        sys.exit(1)
    print(f'PASS: {checked} files in eight pinned upstream snapshots; runtime is the ninth core repository.')


if __name__ == '__main__':
    main()
