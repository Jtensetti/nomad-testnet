#!/usr/bin/env python3
"""Export a clean committed checkout, with licences and source pins included."""
from pathlib import Path
import hashlib
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def main():
    subprocess.run([sys.executable, str(ROOT / 'scripts/check-package.py')], check=True)
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
    if dirty.strip():
        sys.exit('Commit or remove uncommitted changes before exporting a handover package.')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    archive = output / f'nomad-evaluation-{commit[:12]}.zip'
    subprocess.run(['git', 'archive', '--format=zip', '--prefix=nomad/',
                    '-o', str(archive), commit], cwd=ROOT, check=True)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sums = archive.with_suffix('.zip.sha256')
    sums.write_text(f'{digest}  {archive.name}\n')
    print(archive)
    print(f'SHA-256: {digest}')
    print('Source only. No production keys, model weights or hosted services are included.')


if __name__ == '__main__':
    main()
