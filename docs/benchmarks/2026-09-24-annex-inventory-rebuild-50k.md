# Annex inventory import and canonical rebuild: 5k–50k

Tracked by **al-j5k**. Baseline: `4b5f04d75a1441cd8f3b11f84b29cfd8caba8273`.

The user reported approximately 20 hours after enumeration when importing an
approximately 800,000-file annex repository on an older desktop. The exact phase,
storage, build, and timings are unknown. These smaller experiments confirm
declining projection throughput, but do not reproduce or explain the entire
reported duration. No 100k or 800k workload was run.

## Workload and environment

- Release CLI, built with `cargo build --release --locked`, one build job,
  release debug information disabled and incremental compilation disabled.
- Linux 6.8.0-1063-aws, two virtual CPUs (Xeon Platinum 8259CL, one core/two
  threads), approximately 3.8 GiB RAM, ext4 on a virtual NVMe device.
- Shared host: approximately 1 GiB RAM available initially; existing 2 GiB swap
  was almost full. Sampled benchmark CLI swap remained zero. This is not a
  controlled desktop storage comparison.
- Each fixture has distinct SHA256E annex keys, one dangling locked symlink per
  key, 1,000 entries per directory, and no file content. Real Git repositories and
  the real `collection init --import-annex --inventory-only` path are used.
  No git-annex installation or live archive is needed.
- Full `db rebuild` follows import, with warm filesystem caches. Cases run
  sequentially. Results are individual observations, not confidence intervals.

## Results

Times are seconds. Import phases are approximate, sampled every 100 ms. The
publication boundary is the canonical Git commit advancing, not merely the
frontier file being written. Preparation includes enumeration and spooling;
publication includes source rechecks and canonical verification. Those components
were not separately profiled. Projection includes finalization.

| Entries | Import total | Preparation | Publication | Projection + finalization | Full rebuild | Database MiB |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5,000 | 6.01 | 2.20 | 0.84 | 2.97 | 4.62 | 16.4 |
| 10,000 | 10.78 | 2.39 | 1.45 | 6.95 | 13.53 | 32.4 |
| 25,000 | 41.85 | 7.79 | 3.11 | 30.94 | 36.55 | 80.1 |
| 50,000 | 121.51 | 21.32 | 6.09 | 94.10 | 107.47 | 160.2 |

Within the 50k rebuild, committed batch progress moved from 0 to 10,223 items
in 7.57 seconds (about **1,350 items/second**). The final 10,191 items took
27.63 seconds (about **370 items/second**). Items include four bookkeeping
entries. Polling can miss intermediate commits, but the sustained decline is
clear. The final committed batch was observed at 97.64 seconds; rebuild checks
and finalization account for the remaining time.

The 50k rebuild used about 43.3 CPU seconds, with peak sampled CLI RSS of
17,420 KiB and no sampled process swap. `/proc/PID/io` recorded approximately
**2.90 GB of storage write traffic** for a 168 MB database, plus 6.77 GB of
requested write bytes across 2.91 million write calls. These counters cover the
root CLI; they are not device-level measurements. The disparity between elapsed
and CPU time and the write volume warrant further I/O investigation, but do not
prove a single cause of waiting.

Naively multiplying the 50k rebuild by sixteen gives about **29 minutes for
800k on this runner**. That is a conditional linear calculation, not a recovery
time prediction: throughput is still declining, and the extrapolated database
would occupy roughly 2.7 GB. Storage latency and cache pressure can change
substantially. A preliminary 10k rebuild also took 8.88 seconds rather than
13.53 seconds, demonstrating timing variability. Fitting a power law to these
four points would overstate what the experiment establishes.

## Diagnostic experiments

### Larger page cache and WAL

A clone of the 10k canonical repository was checked out at the commit preceding
the import, rebuilt, and restored to its tip. Each variant applied the identical
import onto a fresh copy of that baseline database using the unchanged CLI.
Normal FULL synchronization remained enabled.

| Configuration | Apply seconds |
| --- | ---: |
| Default DELETE journal, approximately 2 MiB cache | 7.15 |
| DELETE journal, 64 MiB cache | 8.75 |
| WAL, approximately 2 MiB cache | 8.33 |
| WAL, 64 MiB cache | 6.93 |
| Default repeated | 7.25 |

There is no convincing fix here. `default_cache_size` was used only to persist a
diagnostic cache setting into these disposable databases; it is deprecated and
is not a proposed production configuration.

### Statement journal writes

A separate `strace -yy -e trace=pwrite64,fdatasync,fsync -s 0` run of a 5k
rebuild produced the following breakdown. Traced elapsed time was excluded from
the timing results above.

| Destination | Write calls | Requested bytes |
| --- | ---: | ---: |
| Main database | 28,207 | 115,535,872 |
| Rollback journal | 19,570 | 26,495,260 |
| SQLite temporary statement journals (`etilqs`) | 199,428 | 409,442,400 |

Temporary statement journals accounted for about 81% of write calls and 74% of
requested bytes. Requested bytes are not physical disk traffic: the OS may
coalesce writes. Inspection of bundled SQLite (`libsqlite3-sys` 0.38.2) showed a
default 64 KiB statement-journal spill threshold. After spilling, the journal
can remain file-backed for subsequent statements in the transaction.

A temporary Rust helper called the existing projection apply API, with
`sqlite3_config(SQLITE_CONFIG_STMTJRNL_SPILL, 1_048_576_i32)` before SQLite
initialization. On the same 10k history, this bounded 1 MiB threshold reduced
write calls from about 528k to 157k and requested bytes from 1.23 GB to 0.47 GB.
One apply took 5.93 seconds versus default runs of 6.74 and 6.94 seconds.
Storage write traffic remained approximately 212 MB versus 213 MB. An unbounded
in-memory diagnostic took 8.23 seconds, further illustrating timing noise.

This isolates a source of syscall overhead, not a complete performance fix.
The setting is process-global and must precede SQLite initialization; its use
would need an explicit initialization contract and broader workload tests.
Unbounded memory journaling is unsuitable as a general fix because other
projection statements can update an entire location. The helper changed no
application source or production settings and was discarded after measurement.

Code inspection found keyed upserts across several tables and indexes, with
small default page caches and per-canonical-chunk transactions. No explicit
quadratic scan was demonstrated on this fresh inventory workload. The next
optimization should measure database/index write amplification and transaction
behavior, preserving bounded memory and recovery semantics. Retest through 50k
before deciding whether a 100k run provides useful additional evidence.

## Verification and reproduction

Every staged import and rebuild passed SQLite integrity and foreign-key checks,
equal before/after user-table counts, expected distinct file/key counts, zero
content objects and verification rows, and routine `fsck`. Full `fsck` on the
10k fixture additionally compared reconstructed event-derived table contents.
Count equality at the other sizes is not a row-by-row equivalence claim.
The harness and cache-comparison mode also passed a 20-entry smoke run.

Run from the repository using a release binary and a new, owned staging root:

```bash
benchmark_root=$(mktemp -d /home/ubuntu/tmp/archive-ledger-al-j5k-XXXXXX)
CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_INCREMENTAL=0 cargo build --release --locked
python3 scripts/benchmark-annex-inventory.py \
  --binary "$PWD/target/release/archive" \
  --work-dir "$benchmark_root" --sizes 5000 10000 25000 50000
python3 scripts/benchmark-annex-inventory.py \
  --binary "$PWD/target/release/archive" \
  --work-dir "$benchmark_root" --compare-cache-at 10000
```

The script requires Linux `/proc`, Python 3.9+, and Git. It creates exclusive
fixture directories, isolates archive configuration, and records timings,
sampled progress, process counters, command logs, and verification results under
the supplied directory. Commands have a configurable timeout. Reusing an
existing case directory fails rather than overwriting it. Preserve a concise
result and remove only the exact owned staging directory after the experiment.
Raw logs and synthetic fixtures from this run are not retained in the product
repository.
