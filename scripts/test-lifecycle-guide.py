#!/usr/bin/env python3
"""Run every bash block of docs/guides/archive-lifecycle.md, in order, against a disposable Archive.

Uses the locally built binary (cargo build first). Everything is written under temporary
directories that are removed afterwards. Substitutions make the guide runnable without real disks:
  * /media/backup-disk is placed on /dev/shm, a filesystem separate from the main Location, since
    Archive Ledger refuses to register one filesystem as two Devices; other /media/... paths go
    under a temporary directory in ~/tmp;
  * collection/location init get --allow-unidentified-root, because temporary directories have no
    stable filesystem identity (the guide tells readers not to use that flag casually).
Archive Ledger exit code 10 means "findings" and is accepted; any other failure stops the run.
Also checks that every README anchor the guide links to exists.
"""

import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
GUIDE = REPO / 'docs' / 'guides' / 'archive-lifecycle.md'


def slug(heading):
    text = re.sub(r'[^\w\- ]', '', heading.strip().lower())
    return text.replace(' ', '-')


def check_readme_anchors(guide):
    readme = (REPO / 'README.md').read_text()
    anchors = {slug(line.lstrip('#')) for line in readme.splitlines() if line.startswith('#')}
    for anchor in re.findall(r'README\.md#([\w\-]+)', guide):
        if anchor not in anchors:
            raise AssertionError(f'README anchor not found: #{anchor}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=REPO / 'target' / 'debug' / 'archive')
    parser.add_argument('--verbose', action='store_true', help='Print the guide run output')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    guide = GUIDE.read_text()
    check_readme_anchors(guide)
    blocks = re.findall(r'```bash\n(.*?)```', guide, flags=re.S)
    staging = Path.home() / 'tmp'
    staging.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='archive-ledger-lifecycle-guide-', dir=staging) as scratch, \
            tempfile.TemporaryDirectory(prefix='archive-ledger-lifecycle-disk-', dir='/dev/shm') as disk:
        root = Path(scratch)
        home = root / 'home'
        (home / 'Documents').mkdir(parents=True)
        for name, text in [('letter.txt', 'Dear archive\n'), ('taxes/2025.txt', 'receipts\n')]:
            path = home / 'Documents' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        (root / 'media' / 'offsite-disk').mkdir(parents=True)
        script = [
            'set -euo pipefail',
            # Exit code 10 reports findings (for example at-risk Files) and is expected here.
            f'archive() {{ local code=0; {binary} "$@" || code=$?; '
            '[ "$code" -eq 0 ] || [ "$code" -eq 10 ] || return "$code"; }',
        ]
        for number, block in enumerate(blocks, 1):
            block = block.replace('/media/backup-disk', disk).replace('/media/', f'{root}/media/')
            block = re.sub(r'archive (collection|location) init ',
                           r'archive \1 init --allow-unidentified-root ', block)
            script += [f'echo "--- block {number}" >&2', block]
        env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(root / 'data'),
                   XDG_CONFIG_HOME=str(root / 'config'),
                   GIT_CONFIG_NOSYSTEM='1')
        result = subprocess.run(['bash', '-c', '\n'.join(script)], env=env, cwd=home,
                                text=True, capture_output=True)
        if args.verbose:
            print(result.stdout)
        if result.returncode != 0:
            raise RuntimeError(f'guide failed ({result.returncode})\n{result.stdout}\n{result.stderr}')
        final_status = result.stdout.rsplit('Archive:', 1)[-1]
        if 'not yet on a sync remote' in final_status:
            raise AssertionError(f'final status still warns about catalog protection:\n{final_status}')
        print(f'Ran {len(blocks)} bash blocks from {GUIDE.relative_to(REPO)} successfully.')


if __name__ == '__main__':
    main()
