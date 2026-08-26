# Photo album integration

This guide defines the supported read-only boundary between Archive Ledger and a higher-level
photo album application. It is written for maintainers and coding agents implementing the
consumer. Use the versioned `archive --json app` commands described here; do not open Archive
Ledger's private SQLite database or infer state by listing storage directories.

The current interface supports two jobs:

1. discover active Files first introduced after a saved Archive checkpoint; and
2. resolve an album's File IDs to currently accessible paths or a Device attachment plan.

It is an introduction and access interface, not a general mutation feed. Renames, removals,
copying, retrieval from services, and photo-specific metadata are important explicit limitations
described below.

## Ownership boundary

| Concern | Owner |
| --- | --- |
| Collections and stable File IDs | Archive Ledger |
| Exact byte identity (`object_id`) | Archive Ledger |
| Copy presence, integrity evidence, Locations, Devices, and Sites | Archive Ledger |
| Preservation policy and disaster-risk evaluation | Archive Ledger |
| Albums, canonical capture date/time, ratings, tags, faces, and captions | Photo app |
| Thumbnails and other disposable derivatives | Photo app, unless deliberately cataloged as their own Files |

Use `file_ref_id` as the photo app's durable reference to a logical File. Do not use a path as an
identity: paths may change. Do not automatically collapse two File IDs merely because they have
the same `object_id`; an Object identifies identical bytes, while the Files may have distinct
logical meaning. The photo app may choose its own duplicate policy.

The photo app should persist, at minimum:

- Archive ID and Collection ID;
- the last fully processed canonical Git commit and accepted-frontier hash;
- each Archive Ledger `file_ref_id`, its most recently observed `object_id`, and any cached path;
- photo-owned metadata keyed by `file_ref_id` (or by the app's own record that references it).

Scope checkpoints by Archive ID and Collection ID. Archive and Collection names can be renamed;
their IDs are stable and should be used after initial selection. `archive --json status` returns
both IDs. Note that `status` exits 10 when it has actionable preservation findings even though its
JSON is valid; treat exit 0 and exit 10 as completed status queries.

## Process contract

Invoke the installed CLI directly as a subprocess with an argument array, not through a shell with
interpolated names or paths. Always request `--json` (or set `ARCHIVE_LEDGER_OUTPUT=json`), capture
standard output and standard error separately, and never parse human-readable output. Do not use a
short fixed timeout: a large SQLite query or mount check can take longer on slower storage.

Use `archive list --json` to enumerate Archives, then `archive --archive ID --json status` to list
the selected Archive's Collections. Select the Archive explicitly in a multi-Archive installation:

```bash
archive --archive "$ARCHIVE_ID" --json app changes \
  --collection "$COLLECTION_ID" \
  --since "$LAST_COMMIT" \
  --limit 500
```

The `app` response version is currently `1`. Require the version you implement and fail clearly on
an unknown version. Treat all IDs, hashes, and continuation tokens as opaque strings. Successful
`app` queries exit 0. Errors exit 2 and write a versioned JSON error to standard error:

```json
{
  "version": 1,
  "error": {
    "code": "stale_continuation",
    "message": "application continuation is stale; restart from the first page"
  }
}
```

Use the same `--host` value that Archive Ledger commands use on that installation. The default is
`local-host`; do not invent a different photo-app-specific value. Access decisions use this host's
recorded mount observations, so switching the value can make mounted files appear unavailable.

These commands are read-only. They do not enumerate content directories, scan or verify bytes,
copy Files, mount Devices, retrieve remote content, or update ledger state.

## Discover newly introduced Files

Run:

```bash
archive --archive "$ARCHIVE_ID" --json app changes \
  --collection "$COLLECTION_ID" \
  --since "$LAST_COMMIT" \
  --limit 500
```

`--since` names a reachable commit in this Archive's canonical Git history. It is an external
checkpoint, not an event timestamp or ordering key. Archive Ledger validates that the commit
belongs to the selected Archive and is an ancestor of the current canonical commit, resolves the
accepted causal frontier at both commits, and queries a SQLite snapshot pinned to the returned
`current` frontier.

A response has this shape:

```json
{
  "version": 1,
  "collection_id": "collection_...",
  "since": {
    "git_commit": "012345...",
    "accepted_frontier_hash": "blake3:..."
  },
  "current": {
    "git_commit": "abcdef...",
    "accepted_frontier_hash": "blake3:..."
  },
  "semantics": "currently_active_files_first_introduced_after_cursor",
  "items": [
    {
      "file_ref_id": "file_...",
      "object_id": "blake3:...",
      "external_identity_id": null,
      "identity_state": "resolved",
      "logical_path": {
        "encoding": "utf8",
        "display": "2026/trip/photo.jpg",
        "text": "2026/trip/photo.jpg",
        "base64": null
      },
      "first_seen_record_id": "rec_..."
    }
  ],
  "next": null
}
```

The feed returns currently active Files whose first introduction is causally after the supplied
cursor. Its consequences are deliberate:

- a File introduced before the cursor is not returned just because it was renamed;
- a File renamed after introduction is returned at its current path if it otherwise belongs in
  the result;
- a File that is no longer active is omitted; and
- concurrently written origins are handled through the causal frontier, not wall-clock order.

Therefore, use this endpoint to discover new photos, not as a complete rename/removal or audit
log. Album membership should reference `file_ref_id`, and an access query will return the current
path or an explicit `removed` state when the user opens an album.

### Pagination and checkpoint safety

When `next` is non-null, request the next page using the same Archive, Collection, `--since`, and
limit, plus the opaque token:

```bash
archive --archive "$ARCHIVE_ID" --json app changes \
  --collection "$COLLECTION_ID" \
  --since "$LAST_COMMIT" \
  --limit 500 \
  --continue "$NEXT"
```

Process the feed as an idempotent transaction:

1. keep the previously committed `$LAST_COMMIT` unchanged;
2. upsert page items by `file_ref_id` and retain the first page's `current` checkpoint;
3. follow `next` until it is null; then
4. atomically commit the imported app state and `current.git_commit` as the next checkpoint.

Persist `current.accepted_frontier_hash` alongside the commit for validation and diagnostics, but
pass the Git commit back to `--since`. If the process crashes, replay from the old checkpoint;
File-ID upserts make replay harmless. Never advance the checkpoint after only part of a page set.

Continuation tokens bind the Archive snapshot, Collection, starting commit, and last item. If the
Archive advances between pages, the command returns `stale_continuation`. Discard the token and
restart from the last fully committed `$LAST_COMMIT`; do not skip ahead to the newer checkpoint.
This may repeat items but will not silently omit them.

### First-time bootstrap

If the photo app starts before any photos are added, save `.canonical_git_commit` from `archive
init --json` or establish an empty checkpoint with `--since HEAD`, then use the normal change
feed.

For an already populated Collection, bootstrap without directory enumeration:

1. Run `app changes --since HEAD`. It returns no items and resolves `HEAD` into an anchor commit.
2. Page through `archive --json file find --collection "$COLLECTION_ID"` and upsert the currently
   active File IDs into the photo app.
3. Run `app changes` from the anchor commit and process every page. This catches Files introduced
   during the full listing.
4. Save the last complete change-feed checkpoint.

`file find` currently returns response version 2 and uses its own opaque, snapshot-bound
continuation. Restart that listing if its continuation becomes stale. Because the current app feed
is not a removal feed, bootstrap during a quiet period or reconcile against one completed full
listing if exact active membership matters. A photo app that intentionally retains historical
album entries can instead keep the File ID and handle `removed` from the access query.

## Resolve an album to accessible files

Write the album's File IDs to JSONL, one JSON value per line. Either form is accepted:

```jsonl
"file_01..."
{"file_ref_id":"file_02..."}
```

Blank lines are ignored. IDs must contain 1–512 bytes with no surrounding whitespace, and an
individual line must not exceed 16 KiB. Duplicate IDs are de-duplicated by first occurrence. Keep
the input order deterministic because response `ordinal` values and `request_hash` follow that
order.

Run:

```bash
archive --archive "$ARCHIVE_ID" --json app access \
  --collection "$COLLECTION_ID" \
  --input album-files.jsonl \
  --limit 500
```

Standard input is supported with `--input -`, but a stable file is preferable for a paged request:
every later page rereads and validates the same input. The implementation streams the request into
a temporary SQLite table, so a large album is not placed on the command line or retained as one
in-memory collection.

A response has this shape:

```json
{
  "version": 1,
  "collection_id": "collection_...",
  "current": {
    "git_commit": "abcdef...",
    "accepted_frontier_hash": "blake3:..."
  },
  "request_hash": "blake3:...",
  "requested_file_count": 2,
  "summary": {
    "accessible": 1,
    "attachment_required": 1,
    "no_known_copy": 0,
    "not_found": 0,
    "wrong_collection": 0,
    "removed": 0
  },
  "items": [
    {
      "ordinal": 1,
      "requested_file_ref_id": "file_01...",
      "state": "accessible",
      "object_id": "blake3:...",
      "logical_path": {
        "encoding": "utf8",
        "display": "2026/trip/photo.jpg",
        "text": "2026/trip/photo.jpg",
        "base64": null
      },
      "local_candidate": {
        "copy_claim_id": "copy_...",
        "location_id": "location_...",
        "location_name": "Photos on Main computer",
        "device_id": "device_...",
        "device_name": "Main computer",
        "site_id": "site_...",
        "site_name": "Home",
        "path": {
          "encoding": "utf8",
          "display": "/srv/photos/2026/trip/photo.jpg",
          "text": "/srv/photos/2026/trip/photo.jpg",
          "base64": null
        },
        "mount_identity_status": "match",
        "last_seen_time_utc_ms": 1780000000000,
        "last_verified_time_utc_ms": 1780000000000,
        "last_verification_result": "ok",
        "evidence": "present_claim_on_revalidated_mount_not_freshly_verified"
      }
    }
  ],
  "attachment_plan": {
    "algorithm": "deterministic_greedy_device_cover",
    "optimality": "not_guaranteed",
    "steps": [],
    "no_attachable_copy_count": 0
  },
  "next": null
}
```

Interpret `state` as follows:

| State | Meaning | Photo-app action |
| --- | --- | --- |
| `accessible` | A present Copy claim has a usable path beneath a mount revalidated on this host. | Try to open `local_candidate.path`; handle a normal I/O race if it has since disappeared. |
| `attachment_required` | No local candidate is usable, but an active present Copy is known on an active Device. | Show the Device/Site attachment guidance, let Archive Ledger recognize the mount, then rerun the request. |
| `no_known_copy` | The active File has no known present Copy on an attachable Device. | Warn that content is unavailable and needs preservation/recovery attention. Never suggest deleting a source. |
| `not_found` | The File ID is unknown. | Treat it as a stale or invalid foreign reference and offer reconciliation. |
| `wrong_collection` | The File exists but belongs to another Collection. | Correct the app's Collection association; do not silently cross Collection boundaries. |
| `removed` | The File exists in history but is not currently active. | Preserve album metadata/history, but do not expect a current path. |

`summary` describes the entire unique request and is repeated on every page. `attachment_plan` is
computed only for the first page; it is `null` on continuation pages. Plan steps greedily choose
Devices that cover the most still-uncovered requested Files, with deterministic tie-breaking.
`optimality: "not_guaranteed"` means it is actionable guidance, not a proof of the mathematically
smallest Device set. Each step includes its Device, Site, Locations, and coverage counts.

An accessible candidate is selected deterministically, and the same Object may satisfy multiple
requested File IDs. The candidate is evidence of a `present` claim under a currently revalidated
Archive Root, not a new per-file integrity verification. Display `last_verified_time_utc_ms` and
`last_verification_result` when trust matters. `mount_identity_status: "match"` means confirmed
filesystem identity matched; `"unavailable"` means the mount is usable under Archive Ledger's
weaker unidentified-root rules. Neither value proves that two Locations are independent backups.
Use preservation policy/risk reports for that question.

After a user attaches a Device, rerun the access request rather than continuing an old plan. If it
was mounted at a new path, Archive Ledger must first recognize that mount through its normal
Location workflow (for example, a scan of that Location); the photo app must not invent or update
private mount rows.

### Access pagination

When `next` is non-null, rerun with the exact same logical JSONL request, Archive, Collection,
host, and limit, adding `--continue "$NEXT"`. Reordering, adding, or removing IDs changes the
request hash. An advanced Archive frontier or any bound-input change produces
`stale_continuation`; discard partial path results and rerun the whole album request. Access paths
are transient lookup results, not durable photo-app state.

## Lossless paths

Every logical or filesystem path has four fields:

- `encoding`: `utf8`, `unix_bytes`, or `windows_utf16le`;
- `display`: a lossy human-readable rendering only;
- `text`: the exact path when `encoding` is `utf8`, otherwise `null`; and
- `base64`: URL-safe base64 without padding for non-UTF-8/native-width bytes, otherwise `null`.

Never use `display` for filesystem I/O. Use `text` for UTF-8 paths. For `unix_bytes`, decode
`base64` to native path bytes; for `windows_utf16le`, decode it to little-endian 16-bit path units.
If the photo app cannot represent the returned native encoding, report that limitation instead of
substituting the display string.

The returned candidate path is already constructed beneath a revalidated registered mount. Open
it read-only and expect that removable storage can disappear after the query. Do not concatenate
untrusted path fragments or infer sibling files by listing its parent directory.

## Error handling

Branch on `error.code`, not message text:

| Code | Recovery |
| --- | --- |
| `stale_continuation` | Discard the partial page set and restart from the last committed change checkpoint or the original access request. |
| `invalid_continuation` | Treat the token as corrupt/incompatible and restart without it. |
| `projection_behind` | Run `archive --archive "$ARCHIVE_ID" db apply`, then restart the query. |
| `cursor_not_found` | The saved commit is unavailable; stop and require checkpoint/bootstrap recovery. |
| `cursor_not_reachable` | The saved commit is not an ancestor of current canonical history; stop and reconcile rather than skipping data. |
| `cursor_archive_mismatch` | The checkpoint belongs to another Archive; correct the app's Archive association. |
| `invalid_app_request` | Correct the JSONL line identified by the message; an empty request is also invalid. |
| `invalid_limit` | Use a page size from 1 through 1000. |
| `unsafe_registered_path` | Do not open the path; report damaged or platform-incompatible registered path data. |
| `app_projection_invalid` | Stop and report inconsistent projected data; do not guess. |
| `v2_event_tree_invalid` | Stop normal integration and direct the user to Archive Ledger health/recovery tooling. |

`invalid_input` also covers CLI selection failures such as an unknown Collection. Other I/O,
SQLite, or Git errors should fail the current operation without advancing a checkpoint.

## Photo album workflow

A practical consumer can use the interface as follows:

1. During setup, let the user select an Archive and Photos Collection, then store their stable IDs.
2. Bootstrap once, then poll `app changes` from the last complete checkpoint.
3. Upsert every returned File ID and enqueue photo-owned metadata extraction or thumbnail work.
4. Store albums by File ID, not Collection-relative path.
5. When rendering an album, write its File IDs to JSONL and run `app access`.
6. Open accessible candidates read-only. Present the attachment plan for offline Files and rerun
   after the requested Devices are available.
7. Keep `no_known_copy`, identity status, and integrity age distinct from photo metadata. An
   accessible path alone is never evidence that it is safe to delete another copy.

The photo app does not need to list directories to find additions or search every mounted Device
to locate an album. Archive Ledger answers both queries from its materialized view and performs
only bounded mount revalidation for access candidates.

## Disposable contract smoke test

This workflow uses isolated XDG directories and two tiny fake image files. It does not touch a real
Archive. It assumes `archive` and `jq` are on `PATH`; keep the printed temporary directory for
diagnostics or remove it after inspection.

```bash
AL_TEST_ROOT=$(mktemp -d /tmp/archive-ledger-photo-app.XXXXXX)
mkdir -p "$AL_TEST_ROOT/xdg-data" "$AL_TEST_ROOT/xdg-config" \
  "$AL_TEST_ROOT/photos/2026/trip"
export XDG_DATA_HOME="$AL_TEST_ROOT/xdg-data"
export XDG_CONFIG_HOME="$AL_TEST_ROOT/xdg-config"

printf 'photo-one\n' > "$AL_TEST_ROOT/photos/2026/trip/one.jpg"
printf 'photo-two\n' > "$AL_TEST_ROOT/photos/2026/trip/two.jpg"

archive --json init "Photo integration test" > "$AL_TEST_ROOT/init.json"
archive --json collection init "$AL_TEST_ROOT/photos" \
  --name Photos --device "Test device" --site "Test site" \
  --allow-unidentified-root --non-interactive \
  > "$AL_TEST_ROOT/collection.json"

# Anchor before inventory so the change feed can find both additions.
archive --json app changes --collection Photos --since HEAD \
  > "$AL_TEST_ROOT/anchor.json"
AL_TEST_BASE=$(jq -r '.current.git_commit' "$AL_TEST_ROOT/anchor.json")

(
  cd "$AL_TEST_ROOT/photos"
  archive --json collection add . > "$AL_TEST_ROOT/add.json"
)

archive --json app changes --collection Photos --since "$AL_TEST_BASE" \
  > "$AL_TEST_ROOT/changes.json"
jq -c '.items[].file_ref_id' "$AL_TEST_ROOT/changes.json" \
  > "$AL_TEST_ROOT/album-files.jsonl"
archive --json app access --collection Photos \
  --input "$AL_TEST_ROOT/album-files.jsonl" \
  > "$AL_TEST_ROOT/access.json"

jq '{count: (.items | length), current}' "$AL_TEST_ROOT/changes.json"
jq '{requested_file_count, summary, attachment_plan}' "$AL_TEST_ROOT/access.json"
printf 'Disposable Archive retained at %s\n' "$AL_TEST_ROOT"
```

Assert that the change count is 2, `requested_file_count` is 2, both access states are
`accessible`, and the first-page attachment plan has no steps. Add `--limit 1` and follow `next`
to exercise pagination. Reorder the JSONL between access pages or add another File between change
pages to verify fail-closed `stale_continuation` handling.

## Current limitations

- The change feed reports introductions, not arbitrary mutations, renames, or removals.
- Access returns local filesystem candidates only; it does not retrieve from cloud/service
  Locations or assign retrieval cost.
- Attachment planning is deterministic greedy coverage, not exact minimum-set optimization.
- Archive Ledger does not yet provide a long-running subscription; the photo app polls checkpoints.
- The interface is read-only. Higher-level write/mutation APIs require a separate reviewed design.

These limitations should remain explicit in the photo app's implementation and user messaging.
Do not work around them by reading private SQLite tables or canonical event files.
