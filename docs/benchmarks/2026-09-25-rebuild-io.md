# Investigating the 200k rebuild I/O increase

Tracked by **al-j5k**, following the [200k benchmark](2026-09-24-rebuild-200k.md).
This investigation reuses that disposable canonical history and database.
No larger fixture or real archive is used. Application source is unchanged.

## Existing rebuild telemetry

The first observed complete inventory batch was at 114.3 seconds in the
178.7-second successful rebuild. By that observation, approximately 2,284 MB
of the final 2,322 MB recorded writes had occurred. The remaining 64.4 seconds
accounted for approximately 1,948 MB of reads and only 38 MB of writes.
These are sampled progress boundaries, not exact instrumented boundaries
between replay, index construction, integrity checks, and canonical validation.
They nevertheless separate most write traffic from the later read-heavy work.

Production rebuild already uses a 64 MiB SQLite cache during both replay and
post-replay integrity/foreign-key checks. Routine `fsck` opens its read-only
connection without configuring the cache, leaving the SQLite default. Its order
is Git checking, canonical verification, publication inspection, SQLite
`quick_check`, foreign-key checking, alignment checks, and another canonical
verification when the projection is current. A stopped `fsck` cannot be assigned
to a particular phase from its incomplete output alone.

## Diagnostic method

The read-only [C diagnostic](../../scripts/benchmark-sqlite-checks.c) links the
same bundled SQLite 3.53.2 amalgamation as the application, using its bundled
build defines and `-O2`. It reports individual PRAGMA timings, SQLite page-cache
hits/misses, cache usage, peak RSS, and Linux process read/write counters.
`sizes` aggregates `dbstat` pages by B-tree and page type. Output-log and
temporary-query writes can appear in process write counters; the database is
opened read-only with `query_only` enabled. A cache miss counts a SQLite page
request even when the filesystem cache satisfies it without storage I/O.

Positive checks and a deliberately orphaned foreign key were tested on tiny
disposable databases, including a table-scoped check. Checks returned the
expected statuses/findings and left database hashes unchanged. The source passed
`cc -Wall -Wextra -Werror -fsyntax-only` against the bundled header.

The shared host initially had approximately 970 MiB available RAM and zero
memory PSI, insufficient for the earlier 896 MiB workload scope. These smaller
diagnostics instead use the previously tested 512 MiB hard / 384 MiB soft
scope, no swap, a 448 MiB early stop, 768 MiB available-RAM preflight (800 MiB
launcher margin), and the same 384 MiB host reserve and sustained memory-PSI
stop thresholds. Each query has its own guarded scope and fresh SQLite
connection. Filesystem caches are not flushed. Therefore elapsed times are
not directly comparable with the earlier full CLI rebuild or controlled
cold-cache timings; page-cache miss counts help interpret the mechanism.

## Measured storage footprint

| Component | Allocated MB |
| --- | ---: |
| Tables, including SQLite schema metadata | 399.09 |
| Indexes retained during replay | 229.54 |
| Deferred reporting indexes | 37.75 |

Deferring 26 indexes does not mean most populated index storage was deferred:
in this inventory fixture, deferred indexes occupy only about 14% of index
pages. Many reporting indexes are empty or small. The retained structures
include primary keys, uniqueness constraints, and scan lookups.

Each fresh entry still modifies 17 B-trees across six logical rows: external
identity (3), file reference (4), path observation (3), availability (2), copy
claim (4), and operation outcome (1). The largest individual structure is the
164.25 MB copy-claim table. Its indexes total 109.42 MB, including a 58.73 MB
active-path uniqueness index. That index alone nearly fills the rebuild's
64 MiB cache. The complete copy-claim table/index footprint is 273.67 MB.

As random-key leaf pages spread across a growing database, a fixed cache and
64-record transaction groups can revisit and spill dirty pages. Bundled
SQLite's `pagerStress` synchronizes the rollback journal when needed before
writing such a page. This is a concrete mechanism for write amplification;
it is not yet a measured count of production replay spills. The required
logical facts and uniqueness constraints cannot simply be omitted.

## Read-check measurements

The 64 MiB full foreign-key check passed in 43.49 seconds with 98,212 cache
misses and 567.47 MB of recorded reads. Those misses represent about 402 MB of
SQLite page requests: close to one pass through the populated child tables
and their parent-key indexes. More cache has limited room to eliminate that
necessary scanning in this particular check.

The 64 MiB full integrity check passed in 151.84 seconds with 412,997 cache
misses and 1,381.70 MB of recorded reads. That miss count is approximately
2.5 times the database's page count. It establishes repeated page requests
even with the production rebuild's larger cache.

The first 128 MiB integrity comparison stopped on global memory PSI after
11.66 seconds, at 225.33 MiB peak scope charge and without a soft-limit event.
It is not a completed timing or integrity result. The retry passed with the
same limits: 171.88 seconds, 327,639 cache misses, and 1,573.95 MB recorded
reads. Doubling the SQLite cache reduced misses by 20.7%, but elapsed time and
storage reads increased. The smaller allowance left for filesystem cache and
changing host load complicate that comparison. This is not evidence for an
end-to-end rebuild speedup from a 128 MiB setting.

The final 256 MiB check passed too. It reduced misses by only another 0.7%,
with greater elapsed time and roughly double the process RAM:

| Integrity cache | Seconds | Cache misses | Recorded reads, MB | Peak RSS, MiB |
| --- | ---: | ---: | ---: | ---: |
| 64 MiB | 151.84 | 412,997 | 1,381.70 | 69.9 |
| 128 MiB, successful retry | 171.88 | 327,639 | 1,573.95 | 136.4 |
| 256 MiB | 207.39 | 325,346 | 1,563.01 | 269.3 |

At 128 and 256 MiB the miss count is already close to twice the total database
page count. These measurements provide no elapsed-time case for raising the
rebuild's cache on this constrained runner. They do not establish the best
cache for replay, for an uncapped runner, or for HDD storage.

For routine-fsck behavior, a table-scoped foreign-key check isolates the 200k
`file_refs` rows and their parent-key lookups:

| Cache | Initial seconds | Initial reads, MB | Warm repeat seconds | Warm repeat reads, MB | Cache misses, both runs |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2 MiB | 9.557 | 78.84 | 0.590 | 0 | 176,217 |
| 32 MiB | 0.327 | 0 | 0.428 | 0 | 15,818 |

Execution order was 2, 32, 2, 32 MiB. Every check passed. The parent external
identity primary-key index alone occupies 10.03 MB; it exceeds the default
2 MiB cache. The larger cache reduces SQLite page requests by 91%, consistently
across both pairs. With the filesystem cache warm, the observed elapsed
improvement was only 1.38 times. The initial 29-times difference is mostly
cache-warming order and must not be presented as a product speedup. This check
does not measure all of routine fsck or change its production cache setting.

## Result and next discriminating measurement

The late read work is real, but simply enlarging the integrity-check cache did
not improve its measured elapsed time. Routine fsck has a separately demonstrated
small-cache inefficiency; a bounded 32 MiB read cache merits a product-level
test, with its entire command measured before claiming a speedup. Routine fsck
was not rerun in this investigation, so the previous incomplete result remains
explicitly unresolved.

Most recorded rebuild writes occur earlier. Before choosing a replay cache or
transaction size, measure `SQLITE_DBSTATUS_CACHE_WRITE` and
`SQLITE_DBSTATUS_CACHE_SPILL` per committed replay group, with timestamps for
index construction and each validation phase. A controlled 64/128/256 MiB
replay comparison would distinguish dirty-page spilling from commit/journal
traffic. The read-only checks here cannot supply those write counters or justify
removing required rows/constraints. No new end-to-end rebuild speedup is claimed.

All completed checks passed. The first 128 MiB attempt was explicitly stopped
on pressure. All 11 diagnostic/build guard reports were audited: zero hard-limit,
OOM, or OOM-kill events, and unchanged global OOM-kill counts at zero. Maximum
scope charge was 384.25 MiB; minimum available host RAM was 602.25 MiB during
compilation. Database size, modification time, and inode were unchanged, and
canonical Git HEAD and clean status were verified. Production source and
canonical history were not changed.

The [research-only instrumentation patch](2026-09-25-replay-instrumentation.patch)
prepares that next measurement against `93bd1e0`. It adds per-group SQLite
counters, process I/O snapshots, and monotonic phase timestamps to an isolated
copy. Its private `ARCHIVE_REBUILD_RESEARCH_CACHE_KIB` override accepts only
65536, 131072, or 262144 and affects rebuild connections. Normal defaults,
durability, replay order, constraints, and validation are preserved. The patch
is not applied to production; Rustfmt and `git apply --check` passed. Build and
replay execution require a separate successful resource preflight.

The attempted guarded release build never launched: the 180-second preflight
wait expired below its 1,240 MiB available-RAM threshold. Available RAM was
796 MiB afterward. The original 896/768 MiB hard/soft limits, zero-swap rule,
832 MiB early stop, and pressure/reserve thresholds were retained. Thus the
patch remains **unbuilt and unrun**; replay spill counts and a new full-rebuild
comparison remain outstanding. The temporary source copy was removed after
preserving the patch and preflight evidence.

## Reproduction and evidence

Build `scripts/benchmark-sqlite-checks.c` with the bundled `sqlite3.c`, its header,
and the defines in `libsqlite3-sys`'s `build.rs` (including
`SQLITE_ENABLE_DBSTAT_VTAB`). This run used SQLite 3.53.2, `cc -O2`, and linked
`libm`, `libdl`, and `libpthread`. Then, under the resource watchdog, use:

```sh
sqlite-checks /absolute/path/to/disposable/archive.db 65536 sizes
sqlite-checks /absolute/path/to/disposable/archive.db 65536 foreign_keys
sqlite-checks /absolute/path/to/disposable/archive.db 65536 integrity
sqlite-checks /absolute/path/to/disposable/archive.db 131072 integrity
sqlite-checks /absolute/path/to/disposable/archive.db 262144 integrity
sqlite-checks /absolute/path/to/disposable/archive.db 2048 foreign_keys file_refs
sqlite-checks /absolute/path/to/disposable/archive.db 32768 foreign_keys file_refs
```

Repeat the last pair in the same order to distinguish initial filesystem-cache
warming. Cache arguments are KiB; each invocation opens a fresh SQLite cache.
Schema/row contents are not printed by the check modes. `sizes` prints only
B-tree names and aggregate page statistics before its JSON metrics line.

Raw measurements and guard evidence are retained under
`/home/ubuntu/tmp/archive-ledger-al-j5k-200k-5p5ntku5/cache-diagnostics-20260925`,
owned by Codex for **al-j5k**, with the existing fixture's removal condition:
remove after follow-up comparisons are recorded or the fixture is explicitly
no longer needed. The separate temporary C-build staging root is removed after
preserving that evidence. The source and this report are the durable repository
artifacts.

The failed build preflight is retained alongside it at
`/home/ubuntu/tmp/archive-ledger-al-j5k-200k-5p5ntku5/replay-build-preflight-20260925`,
with the same owner and removal condition. No benchmark/build process remains
running.
