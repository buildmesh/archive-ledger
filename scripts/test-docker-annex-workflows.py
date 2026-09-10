#!/usr/bin/env python3
"""Exercise the documented annex workflows in hardened, disposable Compose runs.

Requires Docker Compose, Python 3, and network access for image builds.
The supplied fixture is read-only; all writable fixture data and copies are disposable.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


REPO = Path(__file__).resolve().parents[1]


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def tree_digest(root):
    """Hash names, modes, file bytes and symlink targets without following links."""
    digest = hashlib.sha256()
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(dirs + files):
            path = Path(directory) / name
            digest.update(os.fsencode(str(path.relative_to(root))) + b'\0')
            digest.update(str(path.lstat().st_mode).encode() + b'\0')
            if path.is_symlink():
                digest.update(os.fsencode(os.readlink(path)))
            elif path.is_file():
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
    return digest.hexdigest()


def command(args, expected=0, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, cwd=REPO, **kwargs)
    if result.returncode != expected:
        raise RuntimeError(f'{args!r} exited {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--skip-build', action='store_true',
                        help='Use an existing archive-ledger:local image built from this checkout')
    args = parser.parse_args()
    fixture = args.fixture.expanduser().resolve(strict=True)
    check((fixture / '.git').is_dir(), 'Fixture must be a standalone Git Annex worktree')
    command(['docker', 'info', '--format', '{{.ServerVersion}}'])
    original = tree_digest(fixture)
    staging_parent = Path.home() / 'tmp'
    staging_parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='archive-ledger-annex-workflows-', dir=staging_parent) as scratch:
        root = Path(scratch)
        project = root.name.lower()
        state, locations = root / 'state', root / 'locations'
        state.mkdir()
        locations.mkdir()
        source, replica = locations / 'source', locations / 'replica'
        destination = locations / 'destination'
        destination.mkdir()
        shutil.copytree(fixture, source, symlinks=True)
        sha512_content = b'SHA512 migration fixture\n'
        sha512_digest = hashlib.sha512(sha512_content).hexdigest()
        for logical, content, backend, present_bytes in [
            ('sha512-present.txt', sha512_content, 'SHA512E', True),
            ('sha512-absent.txt', b'Absent SHA512 fixture\n', 'SHA512', False),
        ]:
            checksum = hashlib.sha512(content).hexdigest()
            key = f'{backend}-s{len(content)}--{checksum}' + ('.txt' if backend.endswith('E') else '')
            relative = Path('.git/annex/objects/aa/bb') / key / key
            if present_bytes:
                (source / relative).parent.mkdir(parents=True)
                (source / relative).write_bytes(content)
            (source / logical).symlink_to(relative)

        env = dict(os.environ, ARCHIVE_LEDGER_STATE_DIR=str(state),
                   ARCHIVE_LEDGER_LOCATIONS_DIR=str(locations),
                   ARCHIVE_LEDGER_CONTAINER_LOCATIONS_DIR='/locations',
                   ARCHIVE_LEDGER_UID=str(os.getuid()), ARCHIVE_LEDGER_GID=str(os.getgid()),
                   ARCHIVE_LEDGER_HOST_ID=project, ARCHIVE_LEDGER_NETWORK_MODE='none')
        compose = ['docker', 'compose', '--env-file', '/dev/null', '-p', project,
                   '-f', str(REPO / 'compose.yaml')]
        setup_name = project + '-setup'
        try:
            print('Preparing annex migration fixtures without git-annex...', flush=True)
            if not args.skip_build:
                command(compose + ['build'], env=env)
            # Generate legacy fixture metadata using Git plumbing only. The clone
            # models a previously initialized annex repository; no annex executable
            # is installed or invoked, including during fixture preparation.
            setup = """set -eu
export HOME=/work
if command -v git-annex; then echo 'git-annex must not be installed' >&2; exit 1; fi
for path in sha512-present.txt sha512-absent.txt; do
    oid=$(readlink -n "/work/locations/source/$path" | git -C /work/locations/source hash-object -w --stdin)
    git -C /work/locations/source update-index --add --cacheinfo "120000,$oid,$path"
done
tree=$(git -C /work/locations/source write-tree)
parent=$(git -C /work/locations/source rev-parse HEAD)
commit=$(printf 'SHA512 migration fixture\n' | git -C /work/locations/source -c user.name='Docker Test' -c user.email='docker-test@example.invalid' commit-tree "$tree" -p "$parent")
git -C /work/locations/source update-ref HEAD "$commit"
git -c protocol.file.allow=always clone --no-local /work/locations/source /work/locations/replica
git -C /work/locations/replica config annex.uuid 00000000-0000-4000-8000-000000000002
"""
            command(['docker', 'run', '--rm', '--name', setup_name,
                     '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop', 'ALL',
                     '--network', 'none', '--read-only',
                     '--tmpfs', '/tmp:mode=1777,noexec,nosuid,nodev',
                     '--security-opt', 'no-new-privileges:true',
                     '--mount', f'type=bind,src={root},dst=/work',
                     '--mount', f'type=bind,src={fixture},dst=/fixture,readonly',
                     '--entrypoint', '/bin/sh', 'archive-ledger:local', '-ec', setup])
            override = root / 'compose.test.json'
            override.write_text(json.dumps({'services': {'archive': {
                'working_dir': '/locations/source',
                'volumes': [
                    {'type': 'bind', 'source': str(destination), 'target': '/locations/destination',
                     'read_only': False, 'bind': {'create_host_path': False}},
                    {'type': 'bind', 'source': str(fixture), 'target': '/fixture',
                     'read_only': True, 'bind': {'create_host_path': False}},
                ],
            }}}))
            compose += ['-f', str(override)]

            def shell(script):
                return command(compose + ['run', '--rm', '-T', '--entrypoint', '/bin/sh',
                                          'archive', '-ec', script], env=env)

            def cli(*arguments, expected=0):
                return json.loads(command(compose + ['run', '--rm', '-T', 'archive',
                                                      '--json', *arguments], env=env, expected=expected))

            def pages(*arguments):
                items, tokens = [], set()
                continuation = []
                while True:
                    page = cli(*arguments, '--limit', '2', *continuation)
                    items.extend(page['items'])
                    token = page.get('next')
                    if not token:
                        return items
                    check(token not in tokens, 'Repeated continuation')
                    tokens.add(token)
                    continuation = ['--continue', token]

            def files():
                return {item['logical_path']['display']: item for item in
                        pages('file', 'find', '--collection', 'Fixture')}

            def below(count):
                # Same predicate and continuation loop as the documented jq workflow.
                return {path for path, item in files().items() if item['present_copy_count'] < count}

            shell('''
if command -v git-annex; then exit 1; fi
awk '/^Cap(Inh|Prm|Eff|Bnd|Amb):/ {if ($2 != "0000000000000000") exit 1; n++} END {if (n != 5) exit 1}' /proc/self/status
awk '/^NoNewPrivs:/ {if ($2 != 1) exit 1; n++} END {if (n != 1) exit 1}' /proc/self/status
test "$(ls /sys/class/net)" = lo
for mount in / /locations /fixture; do findmnt -n -o OPTIONS "$mount" | tr , '\\n' | grep -qx ro; done
for option in noexec nosuid nodev; do findmnt -n -o OPTIONS /tmp | tr , '\\n' | grep -qx "$option"; done
if touch /locations/source/.write-probe; then exit 1; fi
cp /bin/true /tmp/exec-probe
if /tmp/exec-probe; then exit 1; fi
touch /state/write-probe /locations/destination/write-probe
rm /state/write-probe /locations/destination/write-probe
''')
            check(shell('id -u').strip() == str(os.getuid()), 'Incorrect runtime UID')
            print('PASS runtime restrictions', flush=True)
            cli('init', 'Docker workflow test')
            print('PASS 1: create Archive', flush=True)
            cli('collection', 'init', '/locations/source', '--name', 'Fixture',
                '--device', 'Source disk', '--site', 'Test site', '--location-name', 'Source',
                '--import-annex', '--non-interactive', '--allow-unidentified-root')
            initial = files()
            present = {path for path, item in initial.items() if item['present_copy_count'] == 1}
            absent = set(initial) - present
            check(present and absent, 'Fixture must contain present and absent annex content')
            check(all(item['present_copy_count'] in (0, 1) for item in initial.values()),
                  'Unexpected initial copy counts')
            check(initial['sha512-present.txt']['object_id'] is not None, 'SHA512 content remains unresolved')
            for logical, backend in [('sha512-present.txt', 'SHA512E'), ('sha512-absent.txt', 'SHA512')]:
                review = cli('file', 'show', initial[logical]['file_ref_id'])['file_review']
                check(review['external_key'].startswith(backend + '-'), 'Original SHA512 key was lost')
            print(f'PASS 2: import {len(initial)} Files ({len(present)} present, {len(absent)} absent)', flush=True)
            result = cli('verify', 'Source', '--path', '/locations/source')
            check(result['summary']['confirmed_good'] == len(present), 'Full verify skipped present files')
            print('PASS 3: verify all Location content', flush=True)
            # Write new ordinary files only into our private source. A sibling proves
            # the subtree add does not accidentally inventory the entire Location.
            (source / 'new-subtree').mkdir()
            new_path = 'new-subtree/added.txt'
            (source / new_path).write_bytes(b'New file after annex import\n')
            (source / 'outside-subtree.txt').write_bytes(b'Not selected for inventory\n')
            result = cli('collection', 'add', '/locations/source/new-subtree')
            check(result['summary']['new_paths'] == 1, 'Subtree add missed new File')
            added = files()
            check(set(added) == set(initial) | {new_path}, 'Subtree add included unrelated files')
            check(added[new_path]['object_id'] and added[new_path]['present_copy_count'] == 1
                  and added[new_path]['last_verified_time_utc_ms'], 'New File lacks verified presence')
            print('PASS 4: subtree add hashes and records new content only', flush=True)
            replica_before = tree_digest(replica)
            source_before = tree_digest(source)
            cli('location', 'import-annex', '/locations/replica', '--collection', 'Fixture',
                '--device', 'Replica disk', '--site', 'Test site', '--location-name', 'Replica',
                '--non-interactive', '--allow-unidentified-root')
            imported = files()
            check(set(imported) == set(added), 'Clone import duplicated logical Files')
            check(all(imported[p]['object_id'] == item['object_id'] and
                      imported[p]['present_copy_count'] == item['present_copy_count']
                      for p, item in added.items()), 'Empty clone import changed identities/presence')
            print('PASS 5: import legacy annex clone as-is without git-annex', flush=True)
            check(below(2) == set(added), 'Pre-copy fewer-than-two query missed Files')
            check(below(1) == absent and not below(0), 'Copy threshold boundary incorrect')
            cli('location', 'init', '/locations/destination', '--collection', 'Fixture',
                '--device', 'Destination disk', '--site', 'Test site', '--location-name', 'Destination',
                '--non-interactive', '--allow-unidentified-root')
            selected = sorted(present | {new_path})
            destination_before = tree_digest(destination)
            cli('copy', '--from', 'Source', '--to', 'Destination', '--dry-run', *selected)
            check(tree_digest(destination) == destination_before, 'Dry run mutated destination')
            result = cli('copy', '--from', 'Source', '--to', 'Destination', '--yes', '--non-interactive', *selected)
            expected_objects = {added[path]['object_id'] for path in selected}
            check(result['summary']['copied_objects'] == len(expected_objects), 'Wrong copied Object count')
            after = files()
            for path in selected:
                check(after[path]['present_copy_count'] == 2, f'Missing second copy: {path}')
            # Physical copies are deduplicated by Object; logical Files share evidence.
            placed = [p for p in destination.rglob('*') if p.is_file()]
            check(len(placed) == len(expected_objects), 'Wrong number of physical destination files')
            for path in placed:
                check(not path.is_symlink(), 'Destination is not an ordinary file')
                check(path.read_bytes() == (source / path.relative_to(destination)).read_bytes(),
                      f'Copy bytes differ: {path.name}')
            check(hashlib.sha512((destination / 'sha512-present.txt').read_bytes()).hexdigest() == sha512_digest,
                  'Destination does not match original SHA512')
            check(tree_digest(replica) == replica_before, 'Imported legacy clone changed')
            copies_by_id = {}
            for path in selected:
                review = cli('file', 'show', after[path]['file_ref_id'])['file_review']
                check(not review['copies_truncated'], 'Fixture Copy details were truncated')
                for copy in review['copies']:
                    if copy['location_name'] == 'Destination' and copy['state'] == 'present':
                        copies_by_id[copy['copy_claim_id']] = copy
            copies = list(copies_by_id.values())
            check(len(copies) == len(expected_objects), 'Destination present claims do not match copied Objects')
            check(all(c['last_verification_result'] == 'ok' and c['last_verified_time_utc_ms']
                      and c['last_seen_time_utc_ms'] for c in copies), 'Copy lacks dated integrity/presence evidence')
            cli('verify', 'Destination', '--path', '/locations/destination')
            check(tree_digest(source) == source_before, 'Import or copy mutated source')
            print('PASS 6: ordinary-file copy, original SHA512 match, verified presence without git-annex', flush=True)
            check(below(2) == absent, 'Post-copy fewer-than-two query incorrect')
            check(below(3) == set(added), 'Fewer-than-three query missed Files')
            cli('policy', 'update', 'Two copies at two sites', '--copies', '3')
            risk = cli('report', 'risk', '--collection', 'Fixture', '--limit', '1000', expected=10)
            check(risk['files_at_risk'] == len(selected) and risk['files_uncertain'] == len(absent),
                  'Policy report did not flag underprotected/unresolved Files')
            findings = risk['collections'][0]['findings']
            check(len(findings) == len(added), 'Policy report omitted fixture findings')
            check(all(any('Policy requires 3' in reason for reason in finding['reasons'])
                      for finding in findings if finding['result'] == 'violated'),
                  'Policy did not apply the selected copy threshold')
            print('PASS 7: paginated copy thresholds and Policy requirement of three qualifying copies', flush=True)
            cli('events', 'verify')
            cli('fsck', '--full')
            print('PASS signed events and full catalog integrity', flush=True)
        finally:
            # Exact task-owned container, including cleanup if setup was interrupted.
            subprocess.run(['docker', 'rm', '-f', setup_name], capture_output=True)
            check(tree_digest(fixture) == original, 'Original fixture changed')
    print('PASS original fixture unchanged; disposable state and clone removed', flush=True)


if __name__ == '__main__':
    main()
