# Seven git-annex workflows in Docker

These steps retire git-annex as a dependency while retaining its legacy data as input. They use
one Archive, a Collection named `Media`, legacy Locations named `Media source` and `Media replica`,
and a new ordinary filesystem Location named `Media backup`. No command requires a git-annex
binary for importing, checking, or copying content. Commands operate on the selected default
Archive. Use
`archive-docker use "Personal archive"` to select it again, or pass the global
`--archive "Personal archive"` before a command. Native installations can substitute `archive`
for `archive-docker` and use their actual mounted paths.

## Docker setup

Complete the [Compose setup](../../README.md#run-with-docker-compose), including a private state
directory and stable host ID. From the project directory, define:

```bash
archive-docker() { docker compose run --rm -T archive "$@"; }
```

Use explicit bind mounts in `compose.override.yaml` for repositories outside the configured
Location parent. Replace these host paths with existing directories:

```yaml
services:
  archive:
    working_dir: /locations/source
    volumes:
      - type: bind
        source: /media/source-disk/media
        target: /locations/source
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: /media/replica-disk/media
        target: /locations/replica
        read_only: true
        bind:
          create_host_path: false
```

Use existing legacy repositories for the source and replica mounts. Add the replica mount when
ready for step 5. Both remain read-only to Archive Ledger; new source files are supplied on the
host. Only the deliberate copy destination needs write access. Compose retains disabled
networking, zero Linux capabilities,
no-new-privileges, a read-only image, and `/tmp` mounted with `noexec,nosuid,nodev`.
The working directory is the source Location root so copy path selection resolves there.

Inspect each mounted repository with `location discover` before registering it. If Docker cannot
expose a stable filesystem or partition UUID, setup fails closed; after inspecting that result,
add `--allow-unidentified-root` to the relevant setup command to accept weaker identity. Keep
mount paths and `ARCHIVE_LEDGER_HOST_ID` stable. Do not claim a fingerprint match merely to get a
successful command. Device hardware identity and independent backup protection require their own
checked evidence; two directories on one disk are not independent Devices.

## 1. Create an Archive

```bash
archive-docker init "Personal archive"
archive-docker list
```

This creates the catalog without changing or scanning content. The first Archive becomes the
default.

## 2. Create a Collection by importing git-annex

```bash
archive-docker location discover /locations/source
archive-docker collection init /locations/source \
  --name Media --location-name "Media source" \
  --device "Source disk" --site Home --import-annex --non-interactive
archive-docker collection status Media
```

This creates the Collection, associated Location and necessary topology, then imports the annex
inventory without changing the repository. Readable supported annex content is hashed and records
verified presence. Dropped content remains visible through its annex identity and logical path;
it is not counted as a verified copy. SHA256/SHA256E and SHA512/SHA512E keys supply their original
expected checksum for direct verification; the catalog retains the annex key and uses BLAKE3 as
its canonical Object identity. Ordinary organizational symlinks are ignored.

If an earlier Archive Ledger version imported SHA512 entries as unresolved or without their
expected checksum metadata, rerun import on the same registered path, then verify:

```bash
archive-docker location import-annex /locations/source \
  --collection Media --location-name "Media source" \
  --device "Source disk" --site Home --non-interactive
archive-docker verify "Media source" --path /locations/source
```

Use the existing Collection and Location settings, including `--allow-unidentified-root` if that
was required after discovery. Re-import reuses the Location and Files while learning the original
SHA512 checksum metadata. Rebuilding the catalog database alone cannot discover missing hashes.

## 3. Verify presence and integrity throughout a Location

```bash
archive-docker verify "Media source" --path /locations/source
archive-docker location status "Media source"
```

In the current v2 implementation, `verify` runs a complete Location scan and reads content for
integrity checking. It also discovers additions and reconciles absence; only complete traversal
can publish missing facts. Partial traversal does not mark unvisited files absent. Review the
reported integrity failures and coverage status: exit `10` signals findings, while exit `2`
means a command error. The mounted path must correspond to the entire registered Location.

## 4. Add new files from a path within the Location

After placing new files under the source repository's `incoming/` directory on the host:

```bash
archive-docker collection add /locations/source/incoming \
  --collection Media --location "Media source"
```

This hashes new or changed readable files, adds their logical paths to the Collection, and records
presence and successful integrity reads at the source Location. The operation is positive-only:
it does not mark files elsewhere in the Location missing. Unchanged entries can reuse existing
identity evidence; use step 3 for a full integrity check.

After the initial annex import, ordinary new files require no annex commands or further annex
import. Archive Ledger hashes and catalogs them directly; it does not commit or otherwise manage
the legacy Git repository.

## 5. Register an existing legacy clone as another Location

Use an existing git-annex clone as it stands. There is no need to initialize it again, lock its
files, or run git-annex. Git history and annex representations alone do not prove that a clone
contains file bytes: dangling annex links and recognized pointer placeholders remain absent
content in the catalog. A clone with readable content can also serve as a copy source.

Add the replica bind mount above, then register it under the existing Collection:

```bash
archive-docker location discover /locations/replica
archive-docker location import-annex /locations/replica \
  --collection Media --location-name "Media replica" \
  --device "Replica disk" --site Home --non-interactive
archive-docker collection status Media
```

Discovery reuses known filesystem topology when possible. Supply the actual Device and Site;
do not invent a second Device if both repositories share one disk. This import creates another
Location, not another Collection, and records only bytes actually readable there as present.

## 6. Copy files and record verified destination presence

For the retirement workflow, copy out to a new ordinary directory while preserving both legacy
repositories. Create an empty destination on the host:

```bash
mkdir -p /media/backup-disk/media
```

Add this writable bind mount beneath the override's existing `volumes` entries, using your actual
host path. Match the container UID to the destination owner:

```yaml
      - type: bind
        source: /media/backup-disk/media
        target: /locations/backup
        read_only: false
        bind:
          create_host_path: false
```

Register the directory as another Location of the same Collection:

```bash
archive-docker location discover /locations/backup
archive-docker location init /locations/backup --collection Media \
  --location-name "Media backup" --device "Backup disk" --site Home --non-interactive
```

As with the earlier setup steps, inspect discovery and accept `--allow-unidentified-root` only if
necessary. This Location is an ordinary filesystem destination; no annex metadata, initialization,
permission conversion, or git-annex binary is required.

Select logical paths that are present and resolved at the source, for example:

```bash
archive-docker copy --collection Media --from "Media source" --to "Media backup" \
  photos/example.jpg videos/example.mp4 --dry-run
archive-docker copy --collection Media --from "Media source" --to "Media backup" \
  photos/example.jpg videos/example.mp4 --yes --non-interactive
archive-docker verify "Media backup" --path /locations/backup
```

Run copy from within the source Location even when supplying `--from`; the override's
`working_dir: /locations/source` does this for these examples. Paths are relative to the working
directory, so at the source root they are Collection-relative paths. Directory prefixes also
select files. Omitting paths selects the current directory's Collection subtree, which is the
whole Collection only when run from its root. Selection can fail preflight when the source lacks
selected content. A dropped or unresolved source cannot be copied.

The dry run plans and checks without creating content. The confirmed copy hashes source bytes
against their recorded BLAKE3 identity, publishes destination files without replacement, reads
them back, and records verification and presence. The ordinary destination receives regular
files. Neither the original annex key nor the source representation changes. Copy never replaces
existing content or modifies the source. Planning deduplicates Objects: two logical Files with
identical bytes can need only one transferred Object, and already-present Objects are skipped.

Copying into an existing legacy clone is more constrained: a regular unlocked pointer placeholder
is an existing file and cannot be replaced by the no-overwrite operation. Import that clone as
is, and use the new ordinary Location for copied bytes; do not convert the original to satisfy
the copy command.

## 7. Set a copy requirement and find Files below a chosen count

For a preservation requirement such as “keep at least three trustworthy copies,” use the
Collection's Policy. Setup creates a starter Policy; inspect the Collection and available
Policies, then update the relevant Policy by its name or ID:

```bash
archive-docker collection show Media
archive-docker policy list
archive-docker policy show "Two copies at two sites"
archive-docker policy update "Two copies at two sites" --copies 3
archive-docker report risk --collection Media
```

Replace the example Policy name with the one assigned to your Collection. A shared Policy update
affects every Collection using it. `--copies` sets the minimum **qualifying** copies; existing
Device, Site, freshness, and other requirements remain in force. A physically present copy can
fail qualification because its integrity, freshness, or Device identity is uncertain. This is
the normal workflow for preservation adequacy.

The current v2 risk report limits its detailed findings and has no continuation support, so it
cannot guarantee an exhaustive per-File listing. For the narrower question “which Files have
fewer than X recorded-present copies?”, `file find` exposes `present_copy_count` and supports
pagination. The following alternative is exhaustive for that raw count, not for Policy failures.
It requires `jq` on the host, emits one JSON object per matching File, and follows every page in
the current Archive:

```bash
(
  set -euo pipefail
  minimum=2
  filters=()                         # All Collections in the selected Archive.
  # filters=(--collection Media)      # Optional restriction.
  continuation=()
  while :; do
    page=$(archive-docker --json file find "${filters[@]}" --limit 100 \
      "${continuation[@]}")
    jq -c --argjson minimum "$minimum" \
      '.items[] | select(.present_copy_count < $minimum) |
       {file_ref_id, collection_name, logical_path, identity_state, present_copy_count}' \
      <<<"$page"
    next=$(jq -r '.next // empty' <<<"$page")
    [[ -n "$next" ]] || break
    continuation=(--continue "$next")
  done
)
```

Keep the Archive unchanged during pagination. A continuation becomes stale if the projection
advances; restart the query if that happens. Keeping the complete `logical_path` object preserves
lossless path information rather than relying on a display string. Unresolved Files with no
present copies remain in the results.

These are recorded-present copy counts, not qualifying Policy copies, distinct Devices, or
distinct Sites. Refresh relevant Locations first when current physical presence matters. Use the
Policy workflow above when freshness and independent failure domains should affect the result.

## Repeat the Docker end-to-end test

With Docker Compose running and Python 3 available, run from the repository root. Image builds
require network access; fixture setup and workflow containers remain offline:

```bash
python3 scripts/test-docker-annex-workflows.py \
  --fixture ~/tmp/archive-ledger-annex-media-fixture
```

The [test script](../../scripts/test-docker-annex-workflows.py) exercises all seven workflows in
Docker using private disposable catalog/content directories, a legacy clone prepared with Git
only, SHA512 test content, and a new ordinary copy destination. It binds the original fixture
read-only, checks that it remains unchanged, tests new-file
subtree inventory, verifies copied bytes and catalog presence, exhausts pagination for copy-count
reporting, and checks the runtime restrictions. It removes its disposable test state on success.
Fixture-only missing content is inventory evidence, not a successful integrity verification.
The script asserts that git-annex is absent from the runtime image and implements the paginated
count query in Python, so host git-annex and jq are not prerequisites for this test. Add
`--skip-build` only when the local image has already been built from the current checkout.
