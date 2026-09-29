# Further rebuild experiments

Tracked by **al-j5k**, following the [bounded batching experiments](2026-09-24-rebuild-batching.md)
committed as `ebbf92e`. The user's approximately 800,000-file inventory import
ran on a spinning hard drive and took approximately 20 hours after enumeration.
That is not a measured standalone rebuild, and this virtual-NVMe experiment
cannot convert its speedup into a reliable HDD recovery time.

## Additional combinations

Production Rust source remains unchanged. The [complete unapplied research patch](2026-09-24-rebuild-deeper.patch)
extends the previous isolated prototype. It applies directly to `ebbf92e`;
do not apply both experiment patches. Private flags affect new-database
construction only. Normal incremental apply retains its existing behavior.

- **Prepared statements:** cache the repeated annex projection statements,
  identity lookup, and operation-outcome insertion. SQL and parameter bindings
  are unchanged. The fresh inventory path otherwise prepares approximately
  seven statements per entry: about 350,000 preparations at 50k.
- **Larger bounded transactions:** compare 64 canonical records per transaction
  with 16. Decode one record at a time in canonical order. At the existing
  record-size limit, 64 records bound canonical input per group to 64 MiB;
  neither total SQLite writes nor process RSS is bounded by that figure.
- **More page cache:** compare 256 MiB with 64 MiB. These are cache targets,
  not hard process-memory limits.
- **Defer intermediate syncs (`scratchsync`):** DELETE journaling remains active,
  but synchronous is OFF while constructing the disposable replacement.
- **Omit construction journals (`scratch`):** journal mode and synchronous are
  OFF while constructing the disposable replacement. This tests removal of
  rollback/statement-journal work as well as intermediate synchronization.

Both temporary durability experiments restore DELETE/FULL, check the settings,
validate foreign keys and integrity, validate canonical identity/frontier,
close the connections, and sync the finished database before returning it for
installation. Neither changes canonical history or the installed database's
ordinary write settings. Every primary key, uniqueness constraint, and foreign
key remains enforced during replay. The same 26 selected nonunique indexes are
deferred and restored as in the previous experiment.

These are research modes, not flags to enable on a real catalog. SQLite
[documents synchronous OFF for repeatable new-database creation](https://www.sqlite.org/pragma.html#pragma_synchronous),
but [journal OFF also removes rollback and can leave a corrupt database after an ordinary statement failure](https://www.sqlite.org/pragma.html#pragma_journal_mode).
Any such failure must abandon the entire unpublished file. The production
constructor is public and leaves failed files at its supplied path; promoting
this approach requires an enforced private temporary-file lifecycle, not just
a PRAGMA change. Existing final-installation crash boundaries also need testing.

## 10,000-entry results

All timings include reconstruction, index creation, validation, and installation.
Exact row/schema comparison is outside the timed command. Recorded writes are
Linux root-process `write_bytes`, in decimal MB, not measured device seeks.

| Configuration | Seconds | CPU seconds | Recorded writes, MB | Peak RSS, MiB |
| --- | ---: | ---: | ---: | ---: |
| Default | 12.08 | 8.61 | 217.8 | 16.8 |
| Previous best: cache64, group16, deferred indexes | 6.82 | 5.57 | 44.3 | 46.2 |
| Previous best + prepared statements | 6.92 | 4.29 | 44.4 | 45.5 |
| Cache64, group64, deferred indexes, prepared | 4.09 | 2.87 | 37.3 | 45.3 |
| Cache256, group64, deferred indexes, prepared | 3.68 | 2.63 | 37.3 | 45.4 |
| Cache64, group64, deferred indexes, prepared, scratchsync | 2.98 | 2.83 | 35.5 | 45.5 |
| Cache64, group64, deferred indexes, prepared, scratch | 2.78 | 2.46 | 33.7 | 45.4 |
| Previous best repeated | 6.28 | 4.99 | 44.3 | 46.1 |

Prepared statements alone reduced CPU consumption but did not establish an
elapsed-time improvement in this small comparison. Group64 was materially
faster. Cache256 did not increase resident memory here: the database fits inside
either cache target, so the timing difference is not evidence for needing more
RAM. The scratch variant reduced root write syscalls from 187,618 to 8,563
against its otherwise matching FULL-durability configuration. Many eliminated
calls belonged to temporary journal work, which does not all reach the device.

## 50,000-entry results

| Configuration | Seconds | CPU seconds | Recorded writes, MB | Peak RSS, MiB |
| --- | ---: | ---: | ---: | ---: |
| Default | 107.47 | 43.12 | 2,908.8 | 17.7 |
| Previous best: cache64, group16, deferred indexes | 40.97 | 32.32 | 435.0 | 82.6 |
| Previous best + prepared statements | 41.46 | 18.48 | 434.9 | 81.4 |
| Cache64, group64, deferred indexes, prepared | 18.33 | 16.71 | 208.1 | 81.4 |
| Cache256, group64, deferred indexes, prepared | 20.05 | 16.77 | 208.1 | 180.2 |
| Cache64, group64, deferred indexes, prepared, scratchsync | 25.80 | 21.17 | 206.6 | 81.2 |
| Cache64, group64, deferred indexes, prepared, scratch | 13.93 | 13.43 | 178.6 | 81.1 |
| Cache256, group64, deferred indexes, prepared, scratch | 14.15 | 13.89 | 166.8 | 180.0 |
| Cache64, group64, deferred indexes, prepared, scratch repeated | 23.83 | 14.00 | 185.6 | 81.1 |
| Cache64, group64, deferred indexes, prepared repeated | 19.05 | 16.83 | 208.2 | 81.2 |

Group64 plus prepared statements and deferred indexes achieved a **5.6–5.9-times**
speedup across two observations while retaining FULL synchronization and
normal rollback journaling. Its recorded write volume was **93% below default**.
Prepared statements alone reduced CPU time substantially without improving
elapsed time; larger transactions supplied the next observed elapsed-time gain.

The journal-free candidate was **4.5–7.7 times faster** across its two 64 MiB
observations, with **94% fewer recorded writes**. Its CPU consumption was much
steadier than elapsed time (13.43–14.00 seconds). This variation matters: the
measurements do not establish that it always beats the FULL-durability candidate
in wall time. The higher-cache candidate approximately wrote the finished
database once, but used over twice the resident memory and was not faster in
its observation. Simply deferring syncs while retaining journals did not win
at 50k. Neither larger RAM nor weaker intermediate durability automatically
produced better elapsed time.

There is a separate syscall reduction: the otherwise matched group64 FULL and
journal-free configurations made approximately **1.54 million versus 45,817**
root write calls, requesting 3.23 GB versus 188 MB. Their recorded device-bound
write counters were much closer, 208 MB versus 179 MB. This distinguishes
temporary journal/syscall work from bytes actually charged as storage writes;
neither counter alone measures HDD seeks. The final optimized database was
166.76 MB and retained the same logical schema and every row.

## Which stored facts can be omitted?

A fresh annex inventory normally projects six different facts per entry:
external identity, file reference, path observation, availability, copy claim,
and operation outcome. These have distinct active consumers. In particular,
operation outcomes prevent already-published work from being repeated on resume;
path observations also govern scan coverage and managed-symlink safety. Removing
these rows would change correctness, not merely reduce redundant storage.

An apparently redundant identity UPSERT is also less promising than it looks.
Bundled SQLite 3.53.2 compares same-size replacement payloads before dirtying a
page (`btreeOverwriteContent` in `libsqlite3-sys`'s SQLite source). An isolated
probe with the exact identity schema/UPSERT on system SQLite 3.37.2 performed
100 unchanged updates: each reported one changed row, but the pager reported
zero cache writes and the database hash remained unchanged. Changing the size
field produced two page writes. An explicit unchanged-value guard could save
some CPU on repeat imports; this is not evidence of avoidable disk writes in
the fresh distinct-key workload.

Verified imports have some insert-then-update paths that might be combined,
but those are not exercised by inventory-only imports. No per-entry job-item
or policy-generation update was found in this path. Query-plan inspection found
keyed lookups rather than a demonstrated quadratic scan; one foreign-key plan
contains a scan opcode guarded by the absence/presence of foreign-key debt.
Adding an index based only on that opcode would be premature.

SQLite `dbstat` quantifies the remaining storage. In the 167.93 MB baseline,
table pages occupy 99.87 MB, explicitly created indexes 42.46 MB, and automatic
primary-key/unique indexes 25.56 MB. Indexes therefore account for about **41%**
of the file. `copy_claims` is the largest table at 41.06 MB; its active-path
uniqueness index occupies another 14.71 MB. The optimized file has identical
table storage; building selected indexes after replay saves about 1.18 MB of
index space. Most of the speedup comes from avoiding repeated work, not omitting
stored facts or making the final catalog much smaller.

The two similarly sized path-observation indexes are not duplicates: the
primary key leads with file reference, while the lookup index leads with
location/path. Compact identifiers or a revised key/table layout could reduce
the measured index footprint, but require a separate schema design and consumer
verification. [`WITHOUT ROWID` is not automatically beneficial](https://www.sqlite.org/withoutrowid.html#when_to_use_without_rowid),
particularly for large rows. This experiment provides no timing evidence for
such a schema change.

## Verification and recommendation

Five new 20-entry smoke configurations, seven 10k comparisons, and nine 50k
comparisons passed exact row/schema equivalence, integrity, and foreign-key
checks. Final files used DELETE mode without WAL/SHM sidecars; canonical HEAD
stayed unchanged. The normal CLI import/rebuild fixtures also passed routine
fsck. No real archive was accessed.

The seven existing projection unit tests passed in release mode with both the
recommended FULL-durability candidate and the scratch candidate enabled in
separate runs, covering reconstruction, incremental recovery,
multiple origins, conflicting identities, schema rejection, and item defaults.
This is the focused projection suite, not the full test suite. A separate
application of the retained patch to clean production source reproduced the
exact benchmarked source (SHA-256
`980d9fd10664e5cf05efefa0b0fb4cf3988411cbd271dc22bb80a36a10a26913`).

A copied 10k archive received a newly signed, structurally valid batch that
reused an existing operation key. Canonical verification succeeded, then replay
failed with the expected `operation_outcomes` uniqueness violation. FULL,
scratchsync, and scratch configurations each returned failure, removed the
failed temporary replacement, and preserved the prior database byte-for-byte.

A separate 50k scratch-mode replacement was killed with SIGKILL after its
temporary output exceeded 8 MiB. The existing target remained byte-identical.
A fresh retry took 14.74 seconds and reproduced every user table and exact
schema, with clean integrity/FK checks and unchanged canonical HEAD. This
checks failure during construction. It does not simulate device power loss,
I/O errors, or every final-installation boundary. In particular, the existing
implementation moves the old target to a backup before renaming the replacement;
the interruption test does not establish recovery for that interval.

The strongest first implementation candidate is **group64 + cache64 + prepared
statements + deferred indexes**, preserving ordinary DELETE/FULL durability.
It repeated at 18–19 seconds and about 81 MiB sampled RSS, versus 107 seconds
and approximately 18 MiB for default. Its database exceeds the cache target,
so the result does not depend on retaining the whole catalog in SQLite's cache.
The same candidate grew from 4.09 seconds at 10k to 18–19 seconds at 50k,
showing much better scaling over the measured interval than default.

Journal-free construction is a credible further option, especially for an HDD,
because of its measured elimination of journal calls. Its extra safety contract
and less consistent wall-time advantage make it a separate implementation
decision. The current public constructor must not expose a reusable partial
database after failure; validation, final sync, publication, cleanup, and crash
recovery need an explicit tested lifecycle before promotion.

The remaining useful work is mixed-history validation (reimports, resolved and
conflicting identities, complete scans), then a 100k run and a disposable HDD
measurement. Neither 100k nor 800k was run here. No HDD completion time is
established, and dividing the reported desktop duration by these speedups
would not provide one. Index/key compaction is a measured storage opportunity,
but no schema redesign is justified by a timing result yet. Incremental import
also needs its own optimization: the research flags only accelerate new-database
construction, so they do not yet fix the originally reported import command.

## Measurement and reproduction

The shared runner has two virtual CPUs, approximately 3.8 GiB RAM, and ext4 on
virtual NVMe. Other workloads had already consumed almost all host swap; the
benchmark processes themselves reported no swap use. Cases run sequentially
with warm filesystem caches. Timings are observations, not controlled
distributions; CPU scheduling, cache eviction, and storage contention affect
elapsed time. Root-process counters omit reaped child-process I/O.

The same release binary supplies this round's baseline with experiment flags
unset. That path retains the original SQL, schema, transaction frequency, and
SQLite defaults. Previous-round comparisons independently checked the original
production binary. This round's fresh baseline was 12.08 seconds at 10k and
107.47 seconds at 50k, with approximately 218 MB and 2.91 GB recorded writes,
respectively. The latter agrees with the previous original-binary results.

From the repository, use a new task-owned staging directory and an isolated
source copy. The patch has zero context lines, so use `--unidiff-zero`:

```bash
benchmark_root=$(mktemp -d /home/ubuntu/tmp/archive-ledger-al-j5k-deeper-XXXXXX)
mkdir "$benchmark_root/source"
git archive ebbf92e | tar -x -C "$benchmark_root/source"
patch_path="$PWD/docs/benchmarks/2026-09-24-rebuild-deeper.patch"
(cd "$benchmark_root/source" && git apply --unidiff-zero "$patch_path")
export CARGO_TARGET_DIR="$benchmark_root/target"
export CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_INCREMENTAL=0
unset ARCHIVE_REBUILD_EXPERIMENT
cargo build --release --locked --manifest-path "$benchmark_root/source/Cargo.toml"
python3 -B scripts/benchmark-annex-inventory.py \
  --binary "$CARGO_TARGET_DIR/release/archive" --work-dir "$benchmark_root" \
  --sizes 20 10000 50000
python3 -B scripts/benchmark-rebuild-experiment.py \
  --binary "$CARGO_TARGET_DIR/release/archive" \
  --fixture "$benchmark_root/annex-10000" --output "$benchmark_root/compare-10k" \
  --variants cache64,group16,defer cache64,group16,defer,prepared \
    cache64,group64,defer,prepared cache256,group64,defer,prepared \
    cache64,group64,defer,prepared,scratchsync \
    cache64,group64,defer,prepared,scratch cache64,group16,defer
python3 -B scripts/benchmark-rebuild-experiment.py \
  --binary "$CARGO_TARGET_DIR/release/archive" \
  --fixture "$benchmark_root/annex-50000" --output "$benchmark_root/compare-50k" \
  --variants cache64,group16,defer cache64,group16,defer,prepared \
    cache64,group64,defer,prepared cache256,group64,defer,prepared \
    cache64,group64,defer,prepared,scratchsync \
    cache64,group64,defer,prepared,scratch \
    cache256,group64,defer,prepared,scratch \
    cache64,group64,defer,prepared,scratch
python3 -B scripts/benchmark-rebuild-experiment.py \
  --binary "$CARGO_TARGET_DIR/release/archive" \
  --fixture "$benchmark_root/annex-50000" --output "$benchmark_root/compare-50k-repeat" \
  --variants cache64,group64,defer,prepared
```

The comparison harness checks every user table in both directions, table
counts, exact schema, integrity, foreign keys, final DELETE mode, absent
WAL/SHM sidecars, and unchanged canonical HEAD. Preserve concise results and
remove only the exact task-owned staging directory after the experiment.
