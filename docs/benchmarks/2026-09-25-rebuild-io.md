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
patch was **unbuilt and unrun** at that checkpoint; replay spill counts and a
new full-rebuild comparison remained outstanding. The temporary source copy was removed after
preserving the patch and preflight evidence.

## Instrumented replay follow-up

After the user closed unused coding sessions, the original 1,240 MiB preflight
passed. No remaining coding sessions or shared services were stopped. The patch
was applied only to a new disposable source copy and compiled in release mode
with one build job, one CPU core, and the original 896/768 MiB hard/soft limits,
zero scope swap, 832 MiB early stop, 384 MiB host reserve, and sustained memory
PSI stops. The first build stopped on PSI after 257.42 seconds; a retry reusing
compiled dependencies succeeded in 46.76 seconds. Neither had OOM or hard-limit
events. The production source remains unchanged.

Both cache settings completed replay of all 398 canonical records in seven
transaction groups. The following counters are differences between explicit
`replay_start` and `replay_complete` markers on the same connection. They exclude
initial verification, deferred index creation, and subsequent validation.

| Replay measurement | 64 MiB cache | 128 MiB cache |
| --- | ---: | ---: |
| Observed elapsed seconds | 92.17 | 87.99 |
| SQLite cache misses | 670,596 | 123,163 |
| SQLite dirty-page spills | 756,745 | 172,992 |
| SQLite page writes | 860,868 | 370,207 |
| Linux recorded write bytes, MB | 2,159.14 | 1,887.51 |
| Linux recorded read bytes, MB | 85.13 | 305.50 |
| Bytes passed to write syscalls, MB | 16,873.35 | 14,863.60 |

The larger cache reduced spills by **77.1%**, SQLite page writes by **57.0%**,
and recorded storage writes by only **12.6%**. Spill counts now establish the
replay mechanism directly, but more cache alone did not eliminate most write
traffic. SQLite counters, write-syscall bytes, and Linux storage accounting
measure different layers; repeated page writes can be combined by filesystem
caching. These results do not establish which remaining writes can be removed.

Spilling grows substantially through the stream, even within equal-size groups:

| Group | Cumulative records | Spills, 64 MiB | Spills, 128 MiB |
| --- | ---: | ---: | ---: |
| 1 | 64 | 1,849 | 0 |
| 2 | 128 | 16,943 | 2,468 |
| 3 | 192 | 54,965 | 9,934 |
| 4 | 256 | 142,469 | 19,246 |
| 5 | 320 | 242,976 | 44,929 |
| 6 | 384 | 251,391 | 85,871 |
| 7 | 398 | 46,152 | 10,544 |

Record counts include control events; they are not file counts. The final group
has only 14 records. These are per-group spill deltas, not cumulative totals.

**Neither full rebuild completed.** The 64 MiB run built all deferred indexes
in 43.16 seconds, then stopped on PSI during `optimize` at 160.00 seconds overall.
The 128 MiB run built indexes in 22.05 seconds, completed `optimize`, and passed
`integrity_check` in 57.81 seconds; it stopped on PSI during the foreign-key
check at 188.74 seconds overall. No complete FK result, installed database,
full equivalence check, or end-to-end speedup is claimed. Filesystem caches were
not flushed, and changing host load and reclaim complicate elapsed-time and
storage-read comparisons. The earlier successful 178.7-second rebuild remains
the last completed 200k end-to-end measurement.

Both replay scopes reached approximately 768.22 MiB, with 6,255 and 6,641
soft-limit events respectively. Available host RAM remained above 1,266 MiB
in sampled replay telemetry, yet PSI still crossed the stop thresholds; spare
host RAM does not eliminate reclaim pressure inside the capped workload. All
four build/replay guards reported zero hard-limit, OOM, and OOM-kill events,
with unchanged global OOM-kill counts. No guard thresholds were relaxed.

Both incomplete databases retained `user_version = 0`; neither was published
as a valid rebuild. Their exact owned paths and a small sidecar were removed,
recovering approximately 1,271 MiB. Reference database size, inode, modification
time, canonical Git HEAD, and clean Git status were unchanged. No benchmark
scope remains active.

At the user's request, retain the diagnostic build, compiled dependencies,
source copy, commands, guard reports, raw phase logs, and `replay-summary.json`
at `/home/ubuntu/tmp/archive-ledger-al-j5k-replay-xggzy6_z`, owned by Codex for
**al-j5k**. The executable is `target/release/archive`, SHA-256
`702a3df975b37abfc23a8424c577f4b09ac3b94fdef4d723a0de2ede191fa1c3`.
The source is the production projection at `251fe05` plus the retained research
patch. Remove this staging root only when the user ends the larger-batch
investigation or explicitly retires the build. Future unchanged-code tests can
reuse the executable; source edits can reuse the compiled dependencies. No
256 MiB cache or larger fixture was run in this follow-up.

## Quiet-host completion with more scope headroom

The user authorized stopping the Hermes gateway during a quiet period, then
rerunning the planned 200k comparison. The retained diagnostic executable above
was reused without compilation or production source changes. Both rebuilds
completed, including integrity/FK checks, the completion marker, installation,
and installed validation.

The revised guard requires 2,560 MiB available host RAM and quiet memory PSI
before launch. Its scope has a 1,536 MiB soft limit, 2,048 MiB hard limit, zero
swap, a 1,920 MiB early stop, and a 512 MiB host reserve. The existing sustained
memory-PSI stops, 1 GiB free-disk floor, single-core affinity, and low CPU/I/O
priority remain. Both successful execution and watchdog termination were
smoke-tested before the workloads; the termination test deliberately stopped
a sleeping process on timeout.

| Measurement | 64 MiB cache | 128 MiB cache |
| --- | ---: | ---: |
| Complete CLI rebuild, seconds | 103.61 | 102.31 |
| Replay, seconds | 73.34 | 74.06 |
| Deferred index creation, seconds | 2.04 | 1.77 |
| Integrity check, seconds | 7.32 | 7.55 |
| Foreign-key check, seconds | 1.68 | 1.79 |
| Peak CLI RSS, MiB | 95.5 | 171.3 |
| Peak scope charge including filesystem cache, MiB | 1,148.9 | 960.9 |
| Minimum available host RAM, MiB | 2,636.6 | 2,603.4 |
| Replay dirty-page spills | 756,745 | 172,992 |
| Replay recorded writes, MB | 1,748.97 | 1,809.59 |
| Complete rebuild recorded writes, MB | 1,790.18 | 1,850.80 |

SQLite replay miss, spill, and page-write counts exactly reproduce the earlier
instrumented runs. The larger cache again reduces spills by 77.1%, but here
recorded storage writes increase slightly and overall timing barely changes.
This does not justify changing the production 64 MiB setting. These sequential
runs used warmed filesystem caches: reference hashing also read the reference
before the first case. Neither cache-size timing differences nor comparison
with earlier constrained runs establish a controlled HDD speedup.

Both 666,390,528-byte outputs had schema version six, DELETE journaling, no
sidecars, and exact schema and row equality across **all 33 tables**, without
local-state exclusions, against the retained rebuilt reference. Each principal
inventory table contained 200,000 rows. The two streaming comparisons completed
in 44.20 and 37.75 seconds. Routine fsck of the 64 MiB output also completed:
92.30 scope seconds, healthy and current, with all requested checks passing.
Its SQLite quick check took 69.95 seconds. `fsck --full` was not run; the separate
exact comparisons provide the rebuild-equivalence evidence.

All seven guard reports, including both smoke tests, recorded zero soft-limit,
hard-limit, OOM, and OOM-kill events, zero scope swap, and unchanged global
OOM-kill counts. Minimum available host RAM across the actual workloads was
2,428.1 MiB. Reference SHA-256, size, inode, modification time, canonical Git
HEAD, and clean status were unchanged. No benchmark scope remains active.

A guarded **400k attempt is plausible, not yet demonstrated**. Process RAM is
modest, but scope cache demand and runtime need measurement at the larger size.
After deleting only these two verified disposable outputs (1,271.0 MiB), free
disk was 4,841 MiB. Linear sizing from the 200k fixture suggests about 3.3 GiB
for 400k canonical history and two database copies alone, excluding source
fixture, spool, journal, and temporary overhead. A larger run needs staged
space management or more disk; the stock complete harness should not be
launched assuming that 4.7 GiB is sufficient. No 400k fixture was run here.

Raw commands, revised guards, phase logs, exact comparisons, fsck result,
identity checks, cleanup record, and `summary.json` are retained at
`/home/ubuntu/tmp/archive-ledger-al-j5k-quiet-8ajvi1ws`, owned by Codex for
**al-j5k**. Remove this evidence when the user ends the larger-batch
investigation. The original 200k fixture and separately retained compiled
build remain available; Hermes was stopped during these measurements. The later
[400k and partial 800k results](2026-09-25-rebuild-400k.md) supersede the
400k feasibility assessment above. Further performance work is now deferred,
and the user has announced restarting Hermes.

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
