# Streaming foundation: 500,000-file measurement

Date: 2026-08-19

Scope: `al-e2s` streaming discovery, canonical batch append, checkpoint,
incremental SQLite projection, interruption/resume, status read, and replacement
rebuild. This is foundation evidence, not the later MVP release gate for complete
git-annex semantics, scan finalization, or policy evaluation.

## Reproduce

```bash
/usr/bin/time -v cargo test --release --test scale_500k -- \
  --ignored --nocapture --test-threads=1
```

`ARCHIVE_LEDGER_SCALE_FILES` may reduce the fixture during development. The gate
uses its default of 500,000 real empty files in 500 directories, streams them in
1,000-event batches, interrupts projection after ten transactions, resumes,
checkpoints, rebuilds to a replacement database, and compares final cursors.

Pass thresholds for this foundation gate are:

- exactly 500,000 files discovered and 500,000 per-item events appended;
- no more than two simultaneously open traversal directories for this fixture;
- at least three event segments with contiguous checkpoint coverage;
- resume reaches the exact canonical tail without duplicate operation keys;
- replacement rebuild reaches the same sequence/hash and passes SQLite integrity;
- test-process peak RSS below 64 MiB on this fixture;
- on comparable two-vCPU local SSD/ext4 hardware, discovery plus canonical append
  below 60 seconds, incremental apply below 60 seconds, and rebuild below 120
  seconds. These are regression ceilings, not user-facing performance promises.

## Environment

- Linux 6.8.0-1060-aws, x86-64
- 2 logical CPUs: Intel Xeon Platinum 8259CL at 2.50 GHz
- 3.7 GiB RAM
- ext4 storage
- Rust 1.97.1
- optimized test profile

## Result

The gate passed:

| Stage or artifact | Measurement |
| --- | ---: |
| Fixture creation | 10.794 s |
| Streaming discovery and canonical append | 13.206 s |
| Checkpoint | 4.253 s |
| Interrupted/resumed incremental apply | 18.116 s |
| Replacement rebuild | 84.018 s |
| Total test workload | 139.44 s |
| Test-process peak RSS (`VmHWM`) | 9,404 KiB |
| Canonical event repository | 292,782,721 bytes |
| SQLite database | 405,454,848 bytes |
| Rebuilt SQLite database | 405,454,848 bytes |

GNU `time` reported 259,892 KiB maximum RSS for the complete Cargo command. That
includes compiler and linker child processes and is not the application's
steady-state measurement; the test process records its own `VmHWM` separately.

The first measured implementation reopened and rescanned the current event
segment for every 1,000-event batch and took 396.944 seconds for discovery and
append. Reusing one locked writer state across the same bounded batches reduced
that stage to 13.206 seconds while preserving per-batch sync and the authoritative
rollover path. The optimized result is the retained implementation.
