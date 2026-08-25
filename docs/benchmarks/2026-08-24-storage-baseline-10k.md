# Current-format storage baseline: 10,000 files

Date: 2026-08-24

Scope: a preliminary attribution baseline before event batching, multi-origin
sync, or projection-format changes. This is not the 500,000-File release gate.
It uses the real discovery, scan, event, projection, missing-candidate, and
atomic-completion paths on 10,000 empty files distributed across ten
directories. One interrupted/resumed present scan is followed by one complete
missing scan.

## Reproduce

```bash
ARCHIVE_LEDGER_SCAN_SCALE_FILES=10000 \
ARCHIVE_LEDGER_SCALE_KEEP=1 \
cargo test --test scan_scale_500k -- --ignored --nocapture --test-threads=1
```

`ARCHIVE_LEDGER_SCALE_KEEP` preserves the disposable fixture and prints its
path. Run SQLite `dbstat`, `page_count`, and `freelist_count` against
`archive.db`. To measure Git's native compression separately from raw checked-
out canonical bytes, initialize a disposable Git repository in `canonical/`,
commit `events/`, and run `git gc --aggressive`.

## Result

| Artifact or count | Measurement |
| --- | ---: |
| Logical Files | 10,000 |
| Canonical events | 70,006 |
| Events per File | 7.00 |
| Raw canonical JSONL | 77,196,117 bytes |
| Raw canonical bytes per File | 7,720 bytes |
| Git object database after aggressive packing | 8.15 MiB |
| Packed canonical bytes per File | about 862 bytes |
| SQLite file | 164,769,792 bytes |
| SQLite file bytes per File | 16,477 bytes |
| SQLite page size / page count | 4,096 / 40,227 |
| SQLite freelist | 3,284 pages (13,451,264 bytes) |

The SQLite result closely reproduces the previously observed approximately
16.5 KiB per File at 500,000 Files. Empty file content causes all paths to share
one Object, so this fixture slightly understates Object-table cost while still
exercising per-File paths, copies, verification results, outcomes, and events.

## SQLite attribution

Percentages below use live `dbstat` allocation and exclude freelist pages.

| Category | Allocated bytes | Share |
| --- | ---: | ---: |
| Event mirror and indexes | 100,986,880 | 66.7% |
| Current content and verification | 21,987,328 | 14.5% |
| Operation outcomes and indexes | 18,907,136 | 12.5% |
| Scan state and missing candidates | 9,117,696 | 6.0% |
| Registry and other | 270,336 | 0.2% |
| Live local job state | 49,152 | less than 0.1% |

Completed job items are cleaned, but their former pages account for much of the
13.45 MB freelist/high-water gap. Automatic `VACUUM` is not justified: it would
need substantial temporary space and interruption safeguards on a real multi-
gigabyte catalog. A future rebuild into the next projection schema can reclaim
that space safely by atomic replacement.

## Canonical event attribution

| Event type | Count | Average complete JSONL line |
| --- | ---: | ---: |
| `copy_verified` | 10,000 | 1,478 bytes |
| `path_observed` | 10,000 | 1,170 bytes |
| `copy_observed` | 10,000 | 1,144 bytes |
| `file_ref_observed` | 10,000 | 1,132 bytes |
| `object_observed` | 10,000 | 980 bytes |
| `path_missing_candidate` | 10,000 | 908 bytes |
| `copy_missing_candidate` | 10,000 | 908 bytes |

One initially present File therefore produces five separate positive event
lines totaling roughly 5.9 KiB before Git packing. The missing scan adds two
more lines totaling about 1.8 KiB. This confirms that semantic batching and a
shared context/composite item representation offer much larger gains than key
shortening alone.

## Decisions supported by this baseline

- Preserve indexed current-state tables; together with verification history,
  they are only 14.5% of live allocation in this fixture and serve interactive
  reads directly.
- Make the event mirror/payload representation and its indexes the first
  projection-size target.
- Design compact canonical composite items and the next projection schema
  together so a single migration captures both gains.
- Treat completed local-state cleanup as already effective; reclaim its
  high-water pages through safe replacement rebuild, not routine in-place
  compaction.
- Measure both raw and Git-packed bytes. Git packing is highly effective, but
  sync and checkout still benefit from fewer semantic records and less repeated
  text.
