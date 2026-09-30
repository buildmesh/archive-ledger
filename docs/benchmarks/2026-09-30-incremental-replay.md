# Incremental import replay and interruption validation

Tracked by **al-kaq**, following the slow import investigation in **al-1x6**.
The baseline is `a87cd4e`; the candidate enables the existing bounded replay
transactions, prepared statements, and 64 MiB cache for incremental application,
while retaining its reporting indexes and SQLite durability settings.

## Same-history 10,000-file comparison

The fixture contains 10,000 distinct, valid SHA256E annex keys, each with
1,024 bytes of present content. The real `collection init --import-annex`
command hashes and verifies the content; it does not use `--inventory-only`.

A disposable canonical clone was checked out at the import commit's parent,
and the baseline binary rebuilt that predecessor's projection. After restoring
the import tip, each binary ran `db apply` against a separate copy of exactly
that base database. Timings exclude copying, integrity checks, and comparison.
GNU `time -v` supplied completed-process CPU, memory, and filesystem counters;
its output-block count is converted using Linux's 512-byte accounting units.

| Completed `db apply` measurement | Baseline | Candidate |
| --- | ---: | ---: |
| Elapsed time | 13.57 s | 2.93 s |
| User + system CPU | 9.75 s | 2.84 s |
| Filesystem output | 439,611,392 bytes | 60,354,560 bytes |
| Maximum RSS | 17,688 KiB | 76,276 KiB |
| Swaps | 0 | 0 |

This pair shows 4.63 times faster replay and 86.3% less accounted filesystem
output on this host. Every user-table row and schema definition matched exactly
between variants. Both passed SQLite integrity and foreign-key checks and
matched the full import's derived facts. Canonical HEAD and working files stayed
unchanged.

These are sequential, shared-host measurements on Amazon EBS exposed as NVMe,
with warm filesystem caches and varying host I/O pressure. They are not a
prediction for a spinning disk. GNU time includes the CLI's reaped descendants;
`db apply` here does not launch a Git publication subprocess. Output accounting
is not a measurement of physical flash or platter writes. Earlier 100 ms
`/proc` sampling missed candidate writes near process exit, so its smaller
write estimate is deliberately not used in this comparison.

## Larger verified-content workload

The baseline also completed a real 50,000-file collection import: 415.37 seconds
overall, with an approximately 205.17-second projection/finalization phase.
The phase boundary is sampled every 100 ms and includes finalization work.
Its subsequent rebuild took 68.93 seconds; exact derived facts, schema,
integrity, foreign keys, and fsck all passed.

The candidate applied that same 50,000-file canonical import onto a fresh copy
of its predecessor projection in 24.88 seconds. Completed GNU time accounting
reported 18.79 CPU seconds, 433,020,928 output bytes, 83,440 KiB maximum RSS, and
zero swaps. The resulting database was 300,347,392 bytes, exceeding the 64 MiB
cache. Its derived rows and schema exactly matched the original full import;
integrity and foreign-key checks passed, and canonical HEAD and working files
were unchanged.

This is larger-workload correctness and bounded-memory evidence. The baseline
50,000-file import phase includes different surrounding work and local job
state, so it is not used as a matched `db apply` speedup comparison.

## 100,000-file inventory check

The existing `v2_scale_100k` acceptance test completed inventory projection of
100,000 empty files: all file, copy, and verification rows were present, the job
was complete, applied and accepted frontiers matched, and local job files had
been cleaned up. The command then stalled before returning its completion
report. The pre-fix binary also exceeded a five-second limit on read-only
`background status` against this fixture, which shares one Object across all
100,000 paths. The unchanged verification-due reporting query is being
investigated separately in **al-a94**.

The full acceptance run was stopped and is **not a passing gate**. A separate
direct rebuild of its saved 127 canonical records completed successfully;
exact derived-row and schema comparison against the incremental database,
integrity checks, and foreign-key checks passed. This verifies the larger
projection result without claiming the downstream reporting checks completed.

## Interruption and resume

A separate real baseline `collection init` against the 10,000-file source was
interrupted with SIGINT after publication and 489 committed import items.
The candidate's `job resume job_benchmark` completed in 3.10 seconds, marked
the job complete, and projected all 10,000 file references, objects, and
verification results. Its derived rows and schema exactly matched a subsequent
rebuild of the same canonical history. Integrity, foreign-key checks, and
`fsck` passed. Resume did not advance canonical HEAD; every source file still
had its original SHA256 content and the source Git HEAD was unchanged.

The candidate was also interrupted during a replay transaction, leaving a
189,296-byte rollback journal and no committed import batch. Resuming with the
candidate recovered that journal and produced exactly the uninterrupted
baseline's rows and schema, with passing integrity and foreign-key checks.
These are disposable rehearsals; no live archive was stopped or modified.

## Reproduction and measurement scope

The retained benchmark script adds `--full-content`; its default remains
inventory-only. For example, with an existing disposable work directory:

```sh
python3 scripts/benchmark-annex-inventory.py \
  --binary /absolute/path/to/archive --work-dir /absolute/disposable/work \
  --full-content --sizes 10000 50000
```

The harness strips inherited `ARCHIVE_*` selectors and uses isolated XDG paths.
The existing default mode also passed a 20-entry inventory import, rebuild,
exact derived comparison, and fsck smoke check. Comparison and SIGINT drivers
were task-local; their method is described above rather than introducing new
product commands. The old cache-diagnostic mode now warns that explicit
application cache settings override its persistent default-cache variants.
