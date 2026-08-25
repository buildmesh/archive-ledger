# Version 2 canonical storage: 100,000 Files

Date: 2026-08-25

Scope: measure the checked-out and Git-packed canonical cost of one resumable
100,000-File inventory and one repeated positive verification cycle. Both
fixtures use the same empty-file tree and bounded v2 composite batches. The
baseline writes explicit schema-1 item fields; the candidate uses schema-2,
item-kind-scoped defaults. All histories remain plain UTF-8 JSONL.

## Retained format change

Schema-2 batch starts store common values once under the applicable item kind.
The writer removes an item field only when its JSON value exactly equals that
default. Projection restores the defaults and then overlays explicit fields, so
annex representations, failures, non-UTF-8 paths, and other exceptions remain
lossless. Schema-1 batches still rebuild without inheritance. No immutable
segment is rewritten and there is no compressed or binary canonical artifact.

For the interrupted first cycle, the omitted field contributions were:

| Fields | Raw bytes avoided |
| --- | ---: |
| Collection and Location IDs | 10,800,000 |
| Device fingerprint, representation, item and outcome kinds | 13,400,000 |
| Job and scan identity/type | 9,100,000 |
| Common null SHA-256, external identity, and extension values | 6,800,000 |
| Common observation time for the resumed half | 1,850,000 |
| Total | 41,950,000 |

The first 50,000 items retain their earlier observation time explicitly after
resume; the second half inherits the resumed batch default. This demonstrates
that a default never erases an exception merely to save bytes.

## Measured canonical result

| First 100,000-File cycle | Explicit schema 1 | Kind defaults schema 2 | Change |
| --- | ---: | ---: | ---: |
| Inventory event bytes | 112,847,145 | 70,894,390 | -37.17% |
| Canonical repository file bytes | 123,364,669 | 80,761,311 | -34.53% |
| Full reachable Git pack | 8,763,785 | 8,490,895 | -3.11% |
| Inventory physical records | 111 | 103 | -7.21% |
| p95 physical line bytes, whole history | 1,040,418 | 727,401 | -30.08% |

The current complete history has 127 records: 24 setup records and 103 records
for 100,005 inventory items. Its event JSONL is 70,908,952 bytes including
setup. The largest line is 727,402 bytes, below both the 1 MiB hard bound and the
1,000-item bound.

## Repeated-cycle and synchronization cost

| Second 100,000-File cycle | Explicit schema 1 | Kind defaults schema 2 | Change |
| --- | ---: | ---: | ---: |
| Inventory event delta | 112,847,218 | 69,044,519 | -38.82% |
| Thin incremental Git pack | 8,742,814 | 8,473,066 | -3.09% |
| Full two-cycle reachable Git pack | 12,770,993 | 11,752,506 | -7.98% |
| Physical records | 111 | 103 | -7.21% |

Git already compresses repeated JSON well, so the network/sync reduction is
intentionally reported as modest. The material benefit is smaller checked-out
history, fewer bytes to parse and verify, and fewer bounded records. The repeated
scan completed in 149.65 seconds with 72,192 KiB maximum RSS and zero process
swaps.

## Current-build scale gate

The fresh, interrupted-and-resumed acceptance run completed in 290.01 seconds.
Publishing and applying the resumed inventory took 142.031 seconds; replacement
projection rebuild took 122.744 seconds; indexed Archive status took 0.484
seconds. Maximum RSS across the complete test workload was 165,084 KiB with zero
process swaps. The current compact SQLite projection was 288,448,512 bytes; that
database reduction is measured separately and is not attributed to canonical
defaults.

On the resulting two-cycle archive, routine fsck completed in 32.60 seconds at
83,120 KiB maximum RSS. Full fsck completed in 292.33 seconds at 83,132 KiB,
verified 230 signed records in ten segments, rebuilt into an isolated database,
and matched every event-derived logical table. Both commands recorded zero
process swaps, and full fsck's cleanup left its selected rebuild directory
empty.

Focused tests cover physical omission, exception overlay, schema-1 projection,
interrupted resume, replacement rebuild, snapshot clone, and transfer of a
schema-2 inventory batch through multi-origin sync. The retained two-cycle
fixture is `/tmp/.tmpzCx43m` on the measured host and is disposable.

## Reproduction

```bash
/usr/bin/time -v env ARCHIVE_LEDGER_V2_SCALE_FILES=100000 \
  ARCHIVE_LEDGER_SCALE_KEEP=1 cargo test --test v2_scale_100k \
  one_resumable_inventory_uses_one_commit_and_bounded_v2_records -- \
  --ignored --nocapture --test-threads=1

printf 'COMMIT\n' | git -C CANONICAL pack-objects --stdout --revs | wc -c
printf 'NEW\n^OLD\n' | \
  git -C CANONICAL pack-objects --stdout --revs --thin | wc -c
```

Pack measurements stream to `wc`; they do not run `git gc` or mutate the
retained canonical repository.
