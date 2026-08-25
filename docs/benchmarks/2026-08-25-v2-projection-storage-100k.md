# Version 2 projection storage: 100,000 Files

Date: 2026-08-25

Scope: measure and remove redundant SQLite projection data without removing
query-serving content tables or latency-critical indexes. The retained real v2
fixture has 100,000 logical Files and two complete positive inventory/
verification cycles. Its canonical Git tree is unchanged at 247,234,167 bytes;
only disposable rebuilt databases are compared.

## Baseline attribution

The two-cycle projection had no freelist pages or WAL, so all 642,764,800 bytes
were live allocation rather than high-water waste.

| Structure | Allocated bytes | Reason |
| --- | ---: | --- |
| `records` | 226,009,088 | 246 rows duplicated complete, roughly 1 MiB canonical batch payloads |
| `verification_results` plus two indexes | 124,186,624 | 200,000 historical verification attempts |
| `operation_outcomes` plus two indexes | 74,719,232 | 200,004 idempotency outcomes with repeated descriptive text |
| `copy_claims` table | 45,629,440 | 100,000 current physical claims |
| `path_observations` table | 31,592,448 | 100,000 current path observations |
| `file_refs` table | 29,335,552 | 100,000 logical Files |

The record payloads had no v2 SQLite consumer. Batch context/completion,
idempotency, and domain facts already have dedicated projections; explicit
history reads use authoritative canonical JSONL. The only hot
`operation_outcomes` query is exact `operation_key` existence. Its origin dot is
derivable by joining the retained record/item pointer to `records`.

## Retained changes

- New projections retain compact record headers but write `payload_json` as
  `NULL`; canonical JSONL remains complete and immutable.
- `operation_outcomes` is now a `WITHOUT ROWID` exact-key table containing only
  `operation_key`, `record_id`, and `item_index`. Repeated job/item/outcome text
  and redundant B-trees are not materialized.
- Current File, Object, path, Copy, verification, risk, and status tables and
  their indexes are unchanged. There is no automatic `VACUUM`, pruning, or
  in-place rewrite.

## Measured result

| Projection | Bytes | Change from two-cycle baseline |
| --- | ---: | ---: |
| Original two-cycle projection | 642,764,800 | — |
| Payload deduplication only | 416,886,784 | -225,878,016 (-35.14%) |
| Final compact projection | 359,170,048 | -283,594,752 (-44.12%) |

The final projection uses 87,688 4 KiB pages with zero freelist pages.
`records` is 131,072 bytes. The compact 200,004-row idempotency table is
17,002,496 bytes and exact lookup uses its primary key, versus 74,719,232 bytes
and three B-trees before.

The historical one-cycle frontier was independently rebuilt with the final
layout:

| State | Bytes | Verification rows | Outcome rows |
| --- | ---: | ---: | ---: |
| After first 100,000-File cycle | 288,432,128 | 100,000 | 100,002 |
| After second 100,000-File cycle | 359,170,048 | 200,000 | 200,004 |
| Marginal second cycle | 70,737,920 | +100,000 | +100,002 |

Marginal projection growth is therefore 707.38 bytes per File per additional
successful verification cycle. About 621 bytes per File is the historical
verification row and its audit indexes; about 85 bytes is the compact durable
idempotency key. Older successful verification retention remains intentional
until checkpoint-gated pruning can keep every failure and the newest success
without weakening recovery or audit promises.

## Latency and rebuild checks

All measurements used the already-built debug CLI on the 3.7 GiB test host,
with zero process swaps.

| Check | Result |
| --- | ---: |
| Final two-cycle rebuild | 284.33 s; 23,796 KiB maximum RSS |
| Historical one-cycle rebuild | 139.21 s; 22,936 KiB maximum RSS |
| Full final-layout fsck/rebuild/equivalence | 398.69 s; 124,928 KiB maximum RSS |
| Archive status | 0.17 s; existing policy-finding exit 10 |
| Location status | 0.13 s |
| Indexed 100-row File page | less than 0.01 s |

`EXPLAIN QUERY PLAN` continues to use `file_refs_active_path` for the File page
and the `operation_outcomes` primary key for resume reconciliation. Full fsck
passed Git and signed-history verification, live and rebuilt SQLite
integrity/foreign keys, and deterministic logical equivalence to another
disposable rebuild. Default cleanup left the selected rebuild directory empty.

## Reproduction notes

Use SQLite `dbstat`, `pragma_page_count`, and `pragma_freelist_count` on a
retained disposable scale archive. Rebuild, rather than mutate, each candidate
projection:

```bash
archive --database OLD.db --events canonical \
  db rebuild --target CANDIDATE.db

sqlite3 -readonly CANDIDATE.db \
  "SELECT name,sum(pgsize),sum(payload),count(*)
   FROM dbstat GROUP BY name ORDER BY sum(pgsize) DESC;"
```

Do not install a candidate over a live catalog merely to measure it.
