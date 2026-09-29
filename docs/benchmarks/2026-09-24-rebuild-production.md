# Production rebuild optimization and guarded scale validation

Tracked by **al-j5k**, following the [combination experiments](2026-09-24-rebuild-deeper.md).
The implementation promotes the fully durable candidate. It does not expose
the research flags or disable journaling or synchronization.

## Implemented behavior

New-database construction uses the existing projector with 64 canonical records
per transaction, a 64 MiB SQLite cache target, reusable annex/outcome statements,
and deferred construction of 26 nonunique reporting indexes. Primary-key,
uniqueness, and five replay lookup indexes remain active. All deferred indexes
are restored before integrity, foreign-key, and canonical-frontier validation.
Ordinary incremental apply still commits each record separately.

Unfinished construction keeps SQLite `user_version` at zero. Only after every
index and validation succeeds is the supported schema marker written. This
prevents a failed direct constructor from leaving a file that normal open can
accept without its deferred indexes. The replacement still follows the existing
durable sync/install path; canonical history and the previous target are kept
separate from construction.

## Server protection and measurement conditions

Before starting, the shared server had approximately 3.8 GiB RAM, 1.3 GiB
available, and most of its 2 GiB swap already occupied by other workloads.
Memory PSI was near zero; CPU and I/O pressure varied. Storage is ext4 on
virtual NVMe, not the user's spinning hard drive.

Builds and tests ran sequentially in task-owned systemd user scopes with:

- 896 MiB hard memory ceiling, 768 MiB soft limit, and no additional swap.
- One-core CPU affinity, one Cargo build job, reduced CPU priority, and idle
  I/O priority for the later lint/test and benchmark runs.
- At least 1,200 MiB available host RAM before build/test starts.
- A live watchdog reserving 384 MiB available host RAM, stopping on sustained
  memory PSI (`some avg10 > 5%` or `full avg10 > 2%` for five seconds), and
  reserving at least 1 GiB free disk space.

The first CLI build attempt was deliberately stopped by the watchdog at
771 MiB summed process RSS. Actual scope memory was only 653 MiB and host RAM
availability was still 845 MiB. The watchdog was corrected to use actual cgroup
charges, including every descendant process, with an early stop at 832 MiB.
The hard ceiling and host reserve were not increased. Earlier build-tree RSS
samples missed compiler children spawned from worker threads; use the recorded
cgroup charges, not those incomplete RSS values, for build-memory conclusions.
The baseline and library builds each peaked at approximately 768 MiB cgroup
charge; Clippy peaked at 675 MiB. Soft-limit reclaim was expected.

Release builds use `--locked`, one build job, no debug information, and no
incremental compilation. Small benchmarks ran sequentially with warm caches
inside a smaller scope: 512 MiB hard limit, 384 MiB soft limit, no swap, and an
early stop at 448 MiB actual scope charge, requiring 768 MiB available host RAM
before starting.

That smaller scope stopped the first 50k attempt during Git fixture creation
because memory PSI rose. Process RSS stayed below 94 MiB, host availability
stayed above 1,155 MiB, and there were no OOM/hard-limit events, but the scope
recorded 1,579 soft-limit events. Cache reclaim under the scope limit was a
plausible contributor to the stalls. The aborted fixture was removed and the
retry used the already-tested 896/768 MiB hard/soft limits, an 832 MiB early
stop, and a 1,200 MiB host-availability preflight. No swap was enabled and the
PSI/host-reserve thresholds were retained. A second fixture attempt also stopped
on PSI despite zero scope soft/hard-limit events. Its Git log showed automatic
background packing. Fixture configuration now disables both `gc.auto` and
`maintenance.auto`, keeping unmeasured background packing out of the experiment.
The watchdog was also tightened to stop every PID in its task-owned cgroup,
including subprocesses that create their own sessions. A timeout check verified
that a deliberately detached child was terminated. Neither of those attempts reached the SQLite import/rebuild measurement.
A third attempt, with Git maintenance disabled, also stopped on memory PSI
as import began. Background packing therefore was not the only contributor.
The completed 50k Git fixture was reused with a fresh archive after pressure
settled. Its import completed in 167.01 seconds, but the original rebuild was
stopped on PSI before completion (276.19 seconds for the enclosing run,
including import). Host available RAM stayed above 1,188 MiB and cgroup charge
peaked at 768 MiB, with 673 soft-limit events and no hard-limit/OOM events.
Aborted rebuilds are not timing results.

When host availability later fell below the 1,200 MiB preflight, the next
896 MiB scope correctly declined to launch. Standalone optimized rebuilds
then used the previously tested 512/384 MiB scope and 768 MiB preflight,
without filesystem fixture generation or import. The hard memory allowance
was reduced; the pressure thresholds and host reserve remained unchanged.

The watchdog stays active throughout fixture creation, import, rebuild, and
comparison. These constraints can affect elapsed time and filesystem-cache
behavior, so earlier unrestricted timings are context rather than a matched
control.

## Comparison method

The retained benchmark harness generates distinct annex keys and locked
symlinks, runs the real inventory-only CLI import, and rebuilds from canonical
history. Its optional `--baseline-binary` reconstructs the same history with
the original release binary built from `95d0d68`. Baseline and optimized
rebuilds are compared exactly, including every user-table row and schema.

The harness also preserves a SQLite backup of the completed incremental import
and compares its facts with the rebuild using the existing full-fsck boundary:
local `jobs`/`job_items` state, two apply-generation counters, and two locally
cached checkpoint markers are excluded. A 20-entry smoke check confirmed that
live job start times can differ from the canonically reconstructed job summary;
this is existing local-state behavior. The old/new rebuild comparison has no
exclusions, including for jobs. Integrity, foreign keys, canonical HEAD, and routine CLI
fsck are checked. Row/schema comparisons and the reference backup happen
outside the timed rebuilds. Linux process write counters measure accounted
write traffic, not HDD seeks.

## Verification

All 143 library tests and 26 CLI integration tests passed in release mode with
one test thread. The four explicitly ignored legacy/scale gates were left
disabled; the annex benchmarks below exercise distinct keys independently.
Formatting and Clippy (`--all-targets --all-features`, warnings denied) passed.
Independent review found the unfinished-constructor issue described above;
review of the completion-marker fix found no remaining actionable findings.

The new library tests cover more than 64 canonical records, resolved annex
identities followed by metadata reimports, completed-scan negatives, exact
schema/fact equivalence, current-group rollback, persisted cursors, ordinary
incremental transaction boundaries, preservation of the installed target on
failure, and rejection of incomplete direct-constructor output.

The 20-entry smoke fixture passed both the live-fact comparison and exact
baseline/optimized rebuild comparison. At 10,000 entries, the original rebuild
took 9.27 seconds and the implementation took 4.14 seconds. Recorded writes
fell from 218.09 MB to 37.32 MB; peak sampled CLI RSS rose from 16.7 MiB to
46.2 MiB. The surrounding guarded small-run scope stayed below its soft limit,
host available memory stayed above 1,228 MiB, and both scope and sampled global
OOM counters remained zero.

## Production measurements

| Entries | Original rebuild, seconds | Optimized rebuild, seconds | Original writes, MB | Optimized writes, MB | Optimized peak RSS, MiB |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10,000 | 9.27 | 4.14 | 218.09 | 37.32 | 46.2 |
| 50,000 | Aborted by pressure guard | 21.36 | Incomplete | 208.40 | 81.3 |

The 10k matched comparison is 2.24 times faster with 83% fewer recorded writes.
The completed 50k command used 17.90 CPU seconds, sampled zero process swap,
and produced a 166,772,736-byte database. All 50,000 external identities,
file references, copy claims, availability rows, and path observations matched
the completed incremental import; every derived table and the full schema were
compared. SQLite integrity and foreign-key checks passed and canonical HEAD
was unchanged. Local-state exclusions are described above.

The 50k row comparison completed successfully before a second rebuild started.
That repeat was stopped on sustained memory PSI; it is not a second timing or
equivalence result. The enclosing 98.89-second scope peaked at 384.17 MiB
actual memory charge and 120.1 MiB summed RSS, retained at least 979.8 MiB
available host RAM, and recorded 1,448 soft-limit events, zero hard-limit events,
and zero OOM events. The completed rebuild sampled unchanged global OOM counters
at zero. Much of this scope's elapsed time was validation outside the timed CLI.

For context, the earlier unrestricted 50k original measured 107.47 seconds and
2,908.8 MB writes; the new production observation is approximately five times
faster with 93% fewer writes relative to that historical result. This is not a
fresh matched comparison: scheduling, cache state, resource limits, and shared
host load differ. The production implementation is consistent with the earlier
18.33–19.05-second fully durable prototype observations.

Five times as many entries took 5.16 times as long in the successful production
observations (about 2,400 versus 2,340 entries/second). This is encouraging near
linear scaling through 50k, but two differently loaded observations do not prove
scaling at larger sizes or on HDD. The larger case was considered and deferred:
repeated memory-pressure stops and exhausted shared swap make 100k inappropriate
on this runner at that checkpoint. The subsequent authorized 100k run is
reported below; no 800k result is claimed. The optional synthetic
canonical-growth helper was drafted but never compiled or run and is not part
of the product or retained benchmark tooling.

The new failure-injection library test verifies rollback and old-target
preservation. A separate 50k production SIGKILL/retry experiment was prepared
but not run after the pressure stops; power-loss safety at final installation
was not newly established by these measurements. Initial inventory apply is
unchanged: the completed 50k import still took 167.01 seconds under this run's
constraints, with approximately 95.47 seconds after observed publication.
Practical HDD rebuild and initial-import timings remain work tracked by al-j5k.
Do not extrapolate the user's reported 20-hour import into a recovery-time claim.

## Reproduction

Build the baseline from `95d0d68` in a separate checkout and the production CLI
from this change using `cargo build --release --locked` with one build job.
On a runner with adequate headroom, the retained harness supports:

```sh
python3 scripts/benchmark-annex-inventory.py \
  --binary /absolute/path/to/production/archive \
  --baseline-binary /absolute/path/to/original/archive \
  --work-dir /absolute/path/to/owned-staging --sizes 10000 50000
```

The work directory must already exist; size subdirectories must be new. This
creates disposable locked-annex references, not actual archived file contents.
Use the resource limits and active memory/PSI watchdog described above on a
shared runner; a hard limit alone does not stop pressure before OOM. Run one
heavy command at a time and increase fixture size only after reviewing pressure.
A completed fixture can be repeated without generation/import using
`scripts/benchmark-rebuild-experiment.py --binary ... --fixture ... --output ...
--variants default default-repeat`. For this run, the successful 50k measurement
reused the completed import after the baseline abort, rebuilt into a separate
file, and compared with `assert_equivalent_databases(..., ignore_local_state=True)`.
The repeat harness normally expects a previously completed rebuild reference
and compares all rows without exclusions.

Raw fixtures, build outputs, watchdog logs, and the unrun helper were task-owned
scratch artifacts. Their relevant evidence is recorded here; they are removed
at completion rather than retained as product files.


## Subsequent guarded 100,000-entry run

After host pressure settled, the user authorized a 100k attempt. The production
source was unchanged at `1d258b9`. Initial sampling showed approximately
1.33 GiB available RAM, zero memory PSI, 56 MiB free swap, and 6.78 GiB free disk.
The rebuilt release binary's SHA-256 was
`647bcc0da5bac0d052449ee2e2fc28796e47df690a8cbe04dbf98aabb56e1975`.
It used the same locked release build settings, one build job, and one-core
affinity. No production settings or durability behavior were changed.

This fixture contains 100,000 distinct deterministic annex keys and locked
symlinks created by the retained benchmark helper. It is actual filesystem/Git
inventory through the CLI, not a cloned or synthetically duplicated event batch.
It represents metadata-only references, not the contents of 100,000 media files.

Each phase ran in a separate 896 MiB hard / 768 MiB soft / zero-swap scope with
the same 832 MiB early stop, 384 MiB host reserve, memory-PSI thresholds, disk
reserve, CPU affinity, and reduced priorities. Preflight required 1,200 MiB
available RAM and memory PSI some/full avg10 below 2%/1%. The watchdog was active
through setup, import, reconstruction, and validation.

The following stops and recoveries are material to interpreting the result:

- The clean build stopped on memory PSI after 307.22 seconds. Dependencies were
  preserved; the remaining application build succeeded in a fresh scope in
  50.08 seconds. Neither attempt recorded an OOM or hard-limit event.
- Fixture creation stopped after 54.71 seconds during the final Git command.
  The commit already existed; a separate guarded check verified 100,000 entries
  in both its tree and index and confirmed they matched. No regeneration or
  replacement fixture was used. The stopped command is not a fixture timing.
- The import stopped during projection after 406.29 seconds for its scope,
  including archive initialization. Canonical history and committed SQLite
  progress survived. Normal incremental `db apply` completed the projection
  in a separate 80.65-second scope. The reference then contained exactly
  100,000 identities, file references, copy claims, availability rows, and path
  observations, with zero objects or verification results. A SQLite backup
  preserved that completed reference. These interrupted stages are not an
  uninterrupted import timing.
- The first full rebuild stopped on memory PSI after 48.25 seconds. Its scope
  peaked at 577.1 MiB, with no soft-limit events, while host available RAM stayed
  above 1,115.5 MiB. Pressure was not simply exhaustion of this scope's allowance.
  Its unfinished database still had schema version zero and was removed. A
  fresh full rebuild succeeded after pressure settled, with unchanged limits.

### Successful reconstruction

| Entries | Rebuild seconds | CPU seconds | CLI peak RSS, MiB | CLI swap, MiB | Recorded writes, MB |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 50,000, earlier production observation | 21.36 | 17.90 | 81.3 | 0 | 208.40 |
| 100,000 | 45.11 | 34.31 | 84.8 | 0 | 679.85 |

The successful 100k command includes replay, deferred index construction,
validation, and installation. Its enclosing watchdog scope took 45.44 seconds,
peaked at 478.8 MiB actual charge including filesystem cache and 116.5 MiB summed
process RSS, and retained at least 1,246.8 MiB available host RAM. Memory PSI
some/full avg10 each stayed at or below 0.20%. Scope soft-limit, hard-limit, OOM,
and OOM-kill counters all remained zero. CLI RAM is sampled RSS, not a guaranteed
upper bound or the scope's cache-inclusive memory footprint.

Doubling entries took 2.11 times as long and 1.92 times the CPU, with only
3.5 MiB more CLI RSS. This supports approximately linear elapsed scaling through
100k in these observations. Recorded writes increased 3.26 times, however;
write traffic is already growing faster than entry count. These are sequential
warm-cache observations on a shared virtual-NVMe host with different scope
conditions, not statistical scaling proof or an HDD timing estimate. A larger
cache was not tested in this run, and this result does not justify an 800k
extrapolation without further measurement.

The phase wrapper reuses the retained fixture, command measurement, SQLite
backup, integrity, and exact comparison helpers. Separating the phases and
resuming incremental projection were task-local orchestration choices; no new
product command or runtime flag was added. On a sufficiently provisioned runner,
the reproduction command above accepts `--sizes 100000`; omit the optional
baseline binary to measure only production. This run did not time the original
100k rebuild.

### Final verification and limits

The rebuilt database was 333,348,864 bytes. The comparison checked every derived
table and the full schema against the preserved incremental reference, excluding
only the local tables and metadata keys documented above. SQLite integrity and
foreign-key checks passed, and canonical Git HEAD remained
`a637631a7c25345210f09586818c3f2fc6ad228e`.

The comparison scope reached `fsck` only after those assertions passed; it then
stopped on PSI at 135.37 seconds, with 768.2 MiB peak scope charge and 434
soft-limit events. The remaining routine `fsck` ran in a separate scope and
passed in 21.65 CLI seconds (21.82 seconds for the scope), with 201.9 MiB peak
scope charge and no soft-limit events. It reported healthy/current projection,
valid Git objects, 212 valid signed records in nine segments, matching cursors,
and no unpublished append artifacts. `fsck --full` was not additionally run;
the independent exact row/schema comparison already checked reconstruction
against the reference. No unit tests were rerun because production source did
not change; this follow-up changes only the benchmark report.

Across every setup, recovery, rebuild, and validation scope, hard-limit, OOM,
and OOM-kill counters remained zero. Sampled global OOM-kill counts also remained
zero. This was a successful guarded experiment with several pressure stops and
recoveries, not evidence that the shared server can run unrestricted 100k jobs.
The successful recovery timing is 45.11 seconds; fixture creation, the original
import, pauses, and external comparison are not included in it.

Task-owned staging `/home/ubuntu/tmp/archive-ledger-al-j5k-100k-5bek2zu8` held the
fixtures, binary, phase wrappers, and raw telemetry. Their evidence is captured
above and they are removed after verification. The initial-import bottleneck,
faster-than-linear write growth, larger histories, and representative HDD
measurements remain tracked by al-j5k.
