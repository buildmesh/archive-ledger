#!/usr/bin/env python3
"""Compare isolated rebuild prototypes against a completed annex benchmark fixture.

Use only disposable fixtures and a binary built with the accompanying experiment
patch; ARCHIVE_REBUILD_EXPERIMENT is not a product configuration interface.
See docs/benchmarks/2026-09-24-rebuild-batching.md for reproduction instructions.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('bench', Path(__file__).with_name('benchmark-annex-inventory.py'))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--fixture', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--variants', nargs='+', required=True)
a = p.parse_args()
a.binary = a.binary.resolve(strict=True)
a.fixture = a.fixture.resolve(strict=True)
a.output = a.output.resolve()
a.output.mkdir()
archive = a.fixture / 'data/archive-ledger/archives/arc_benchmark'
reference = archive / 'archive.db'
events = archive / 'canonical'
head = bench.git_commit_ref(events)
expected = bench.database_state(reference)
results = []
for index, variant in enumerate(a.variants):
    stage = a.output / f'variant-{index}'
    stage.mkdir()
    env = os.environ.copy()
    env.update(ARCHIVE_REBUILD_EXPERIMENT='' if variant in ('default', 'default-repeat') else variant,
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0',
               XDG_DATA_HOME=str(stage/'data'), XDG_CONFIG_HOME=str(stage/'config'))
    target = stage / 'archive.db'
    measured = bench.run_command([a.binary, '--json', '--database', reference, '--events', events,
                                  'db', 'rebuild', '--target', target], stage, 'rebuild', env, 600, stage, True)
    state = bench.database_state(target)
    assert state['counts'] == expected['counts']
    assert state['settings_on_observer_connection']['journal_mode'] == 'delete'
    assert not Path(str(target)+'-wal').exists()
    assert not Path(str(target)+'-shm').exists()
    connection = bench.connect_readonly(target)
    try:
        connection.execute('ATTACH DATABASE ? AS reference', (reference.as_uri()+'?mode=ro',))
        schema = "SELECT type, name, tbl_name, sql FROM {}.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        assert connection.execute(schema.format('main')).fetchall() == connection.execute(schema.format('reference')).fetchall(), 'Schema differs'
        for table in state['counts']:
            quoted = '"'+table.replace('"','""')+'"'
            for left, right in [('main', 'reference'), ('reference','main')]:
                assert connection.execute(f'SELECT * FROM {left}.{quoted} EXCEPT SELECT * FROM {right}.{quoted} LIMIT 1').fetchone() is None, (variant, table, left)
    finally:
        connection.close()
    assert bench.git_commit_ref(events) == head
    result = dict(variant=variant, seconds=measured['seconds'], peaks=measured['root_process_peaks'],
                  database_bytes=state['bytes'], integrity=True, schema_equal=True, all_rows_equal=True)
    results.append(result)
    (a.output/'results.json').write_text(json.dumps(results, indent=2)+'\n')
    print(json.dumps(result), flush=True)
