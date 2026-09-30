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

To inventory a large repository first and defer hashing, append `--inventory-only` to the
`collection init` command above. This records annex paths, keys, expected sizes, and original
checksums, but does not check content availability or read content bytes. The summary reports
these entries as `unchecked`, and reminds you to scan afterwards. Unchecked entries are neither
present nor missing and do not contribute verified copies or protection. Git index enumeration
and worktree metadata consistency checks still run, so this is not an instantaneous operation.

Establish presence and integrity afterwards with:

```bash
archive-docker location scan "Media source" --path /locations/source
```

The scan reads available content, validates its original annex checksum, and establishes its
BLAKE3 identity and verified presence. The positional argument is a Location name or ID, not a
filesystem path; supply the mounted directory with `--path`. An incomplete scan cannot mark
unvisited files missing. The scan prints its job ID and resume command on stderr before it starts;
keep it for `archive job resume` if the scan is interrupted. Live scan progress needs a terminal,
so omit Compose's `-T` to see it.

Import progress goes to stderr through metadata inspection, import, source rechecking,
publication, and projection. It includes processed entries, skipped links and other entries,
verified, absent and unchecked counts, errors, and bytes read this run. A terminal gets updates
about once a second; redirected output gets updates every 30 seconds, plus start and finish
updates. The helper above uses Compose's `-T`, so it uses the redirected cadence. Omit `-T` for
terminal progress. JSON results stay on stdout. Saving events shows bytes read from the spool
against its size; SQLite replay shows committed records processed this pass against the frontier
gap. Verification and finalization are named separately, so a full spool counter does not claim
that the Git publication is already complete. There is no percentage or ETA.

If an earlier Archive Ledger version imported SHA512 entries as unresolved or without their
expected checksum metadata, explicitly re-import the same registered path, then scan it:

```bash
archive-docker location import-annex /locations/source --reimport \
  --collection Media --location-name "Media source" \
  --device "Source disk" --site Home --non-interactive
archive-docker location scan "Media source" --path /locations/source
```

Use the existing Collection and Location settings, including `--allow-unidentified-root` if that
was required after discovery. Re-import reuses the Location and Files while learning the original
SHA512 checksum metadata. Rebuilding the catalog database alone cannot discover missing hashes.

Ordinary updates use `location scan`. Repeating a completed import requires `--reimport` to
avoid an accidental full rescan and duplicate import evidence. If an import is unfinished,
setup names its job and refuses to start another; use the printed `archive job resume <job-id>`
command. `--reimport` does not bypass an unfinished job.

### If an import or scan is interrupted

A long import or scan that stops (Ctrl-C, a crash, a stopped container, or a reboot) is
recoverable. Both save local progress every 1,000 entries (`--batch-entries`), so an interruption
costs at most the entries since the last checkpoint. Nothing reaches the catalog history until a
run finishes, so there is no half-written import to repair. The saved progress lives in the
Archive's `local/jobs/<job-id>/` directory on this installation. It is not synchronized to other
installations.

Find the unfinished job and resume it:

```bash
archive-docker job list
archive-docker job show <job-id>
archive-docker job resume <job-id>
```

`job list` shows unfinished jobs by default, including jobs whose progress survives only on disk
(for example after `db rebuild`), and `archive-docker status` mentions them. `job resume` needs no
other options: it takes the original repository, Collection, Location, and settings from the job.
A resumed import repeats the repository metadata checks, which can take a while on a large
repository, then continues from its last checkpoint.

If an import stops during catalog projection, its events are already saved. Keep
the Archive directory, SQLite sidecars, and local job files intact. Resume replays
the saved events, recognizes committed records, and retries the interrupted
transaction group. This also works for imports interrupted on an earlier version.
Projection progress advances in groups of up to 64 canonical records, each of
which can contain many files; the counter is not a file count. `job resume` uses
incremental replay, not `db rebuild`.

Do not re-run `collection init --import-annex` or `location import-annex` to continue. While the
import is unfinished they refuse and name the job, and `--reimport` does not bypass it. A
`location scan` prints its job ID when it starts. A new scan of the same Location is refused
while that job is unfinished, and `archive-docker job cancel <job-id>` abandons an unfinished scan
(preview with `--dry-run`).

An interrupted import resumes only while the repository is unchanged: the same Git commit and the
same worktree metadata. After a commit, `git annex get` or `drop`, or other changes, resume refuses
and says so. Abandon that import and start again from the repository's current state:

```bash
archive-docker job cancel <job-id> --dry-run
archive-docker job cancel <job-id>
archive-docker location import-annex /locations/source --collection Media \
  --location-name "Media source" --device "Source disk" --site Home \
  --inventory-only --non-interactive
```

Cancel removes only that import's local progress; the Collection and Location it set up remain,
which is why the restart uses `location import-annex` with the existing Collection. If the
abandoned import was a `--reimport`, add `--reimport` again.
For a large repository, prefer `--inventory-only` followed by `location scan`, both for the first
import and after a restart. The inventory reads no file content, so it is short and cheap to
redo. The long, content-reading part then happens in the scan, which resumes across repository
changes and skips files it has already verified.

## 3. Verify presence and integrity throughout a Location

```bash
archive-docker verify "Media source" --path /locations/source --all
archive-docker location scan "Media source" --path /locations/source
archive-docker location status "Media source"
```

`verify --all` re-reads every current copy at the Location and checks it against its content
identity; plain `verify` reads only copies that are due. Verification does not discover additions
or reconcile absence: `location scan` does, and only a complete traversal can publish missing
facts. Partial traversal does not mark unvisited files absent. Review the
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
This command also accepts `--inventory-only`; follow it with
`archive-docker location scan "Media replica" --path /locations/replica` when ready to check bytes.

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

## SQLite temporary-directory failure and recovery

A large annex import can save canonical events before updating the SQLite projection fails:

```text
error [v2_projection_sqlite]: SQLite operation failed for .../archive.db: disk I/O error
```

Current projection errors append SQLite's numeric primary and extended result codes to the
original message, in both human and JSON output, while retaining `v2_projection_sqlite`.
For example, extended code `6410` (`SQLITE_IOERR_GETTEMPPATH`) identifies failure to find
a usable temporary directory and adds a permissions/storage hint. Other I/O codes do not
receive that hint. The older failure quoted above did not capture its extended code.

The database path identifies the affected catalog; it does not establish which underlying file
operation failed. SQLite can need temporary files as operations outgrow their temporary page
caches, and an unavailable temporary directory can produce an I/O error. Other I/O errors have
different causes, so do not assume every occurrence has this explanation. See SQLite's
[temporary-file documentation](https://www.sqlite.org/tempfiles.html#temporary_file_storage_locations)
and [extended error codes](https://www.sqlite.org/rescode.html#ioerr_gettemppath).

### What the observed failure established

During a real large-repository import, the catalog was on a read/write ext4 bind mount. It had
42 GB available despite `df` rounding usage to 100%, and only 5% of its inodes were used. The
supplied kernel-log excerpt contained normal startup messages without a reported storage error;
this did not rule out all storage faults. In the diagnostic container, `/tmp` resolved to the
overlay filesystem rather than the writable tmpfs configured in this repository's Compose file.

Routine `fsck` passed Git, signed-event, SQLite `quick_check`, and foreign-key checks, but found
SQLite behind canonical history. Ordinary `db apply` reproduced the I/O error. Running the same
command with `SQLITE_TMPDIR=/state` succeeded, and a subsequent `fsck` reported a current,
healthy catalog with matching record counts and origin cursors.

The operator subsequently reported an earlier out-of-space failure and changing the Compose
`tmpfs` destination from `/tmp` to a host-looking disk directory. A `tmpfs` entry names a
destination inside the container; it does not bind that host directory or use its disk space or
permissions. That change explains why `/tmp` was on overlay and strongly supports unusable
default temporary storage as the cause of the later I/O error. The exact failing syscall and
SQLite extended error code were not captured. There was no evidence requiring a database
rebuild, and this recovery did not rehash annex content.

### Diagnose and recover

Stop the failed import before recovery and preserve the Archive directory, including database
sidecars and local job files. Do not delete the database or repeat `collection init` to clear
this error. From the directory containing your Compose configuration, inspect the mounts:

```bash
docker compose run --rm --no-deps --entrypoint /bin/sh archive -c '
  df -h /state /tmp
  df -i /state /tmp
  findmnt -T /state -o TARGET,SOURCE,FSTYPE,OPTIONS
  findmnt -T /tmp -o TARGET,SOURCE,FSTYPE,OPTIONS
'
```

This starts a new container: it shows the current configuration, not the failed container's
previous temporary-file usage. Also check host kernel logs around the failure for filesystem or
device errors. Check the catalog without attempting repairs (replace `Main` with your Archive):

```bash
docker compose run --rm archive --archive Main fsck
```

If history and SQLite checks pass but the projection is behind, test the temporary-directory
workaround with `/state` writable by the configured container UID/GID:

```bash
docker compose run --rm -e SQLITE_TMPDIR=/state archive --archive Main db apply
# Run this after db apply succeeds:
docker compose run --rm archive --archive Main fsck
```

`db apply` updates SQLite from saved canonical events. It does not scan or hash Location content.
If the workaround also fails, preserve the error and investigate further instead of repeatedly
retrying or assuming disk exhaustion. A successful routine `fsck` establishes the checks it
reports; it does not verify annex payload integrity, prove the entire intended import completed,
or perform the optional full projection-rebuild comparison.

### Disk-backed temporary storage in Compose

The repository's Compose configuration now sets `SQLITE_TMPDIR=/state` by default. Large SQLite
operations can spill to disk without competing with the application for the RAM backing `/tmp`.
Older or custom Compose files can adopt the same setting by adding this entry to the existing
service environment, preserving its other entries:

```yaml
services:
  archive:
    environment:
      SQLITE_TMPDIR: /state
```

It takes effect on subsequent `docker compose run` invocations without rebuilding the image.
SQLite then prefers `/state` for temporary-file selection; temporary spill uses the state disk
and needs free space there. This does not relocate the catalog or disable SQLite journaling.
Temporary-space requirements depend on the operation and catalog; 4 GiB is not a universal
threshold or a sizing guarantee. Increasing the tmpfs limit alone does not add RAM. Disk-backed
SQLite temporary storage addresses the capacity limitation without enlarging tmpfs.

Restore the original `/tmp` tmpfs entry if it was changed to a host-looking path: other tools
also use `/tmp`. The container's tmpfs is separate from the host's `/tmp` mount. Docker normally
limits a tmpfs to half the host's RAM unless a size is specified; a 4 GiB limit on an 8 GiB
machine does not mean Docker mounted the host's `/tmp`. See
[Docker tmpfs mounts](https://docs.docker.com/engine/storage/tmpfs/).

### Use a dedicated disk directory for large temporary files

`SQLITE_TMPDIR=/state` is sufficient when the state disk has adequate free space. To put SQLite
spill files on a different disk, create a dedicated host directory on that mounted disk and make
it writable by the configured container UID/GID. Use a bind mount, keeping the original `/tmp`
tmpfs for other tools. Merge these settings into the service, preserving its existing environment
and `/state` and Location volume entries:

```yaml
services:
  archive:
    environment:
      SQLITE_TMPDIR: /sqlite-tmp
    tmpfs:
      - /tmp:mode=1777,noexec,nosuid,nodev
    volumes:
      - type: bind
        source: /var/data/disk7/tmp/archive-ledger
        target: /sqlite-tmp
        read_only: false
        bind:
          create_host_path: false
```

Here `source` is the host directory and `target` is its container path. SQLite temporary files
use the host directory's filesystem capacity rather than the `/tmp` tmpfs limit. Mount the disk
before starting the container. For the reported UID 1000 setup, host directory ownership by UID
1000 works with a container configured to run as that UID. Confirm the effective mounts with:

```bash
docker compose run --rm --entrypoint /bin/sh archive -c '
  id
  df -h /tmp /sqlite-tmp
  findmnt -T /sqlite-tmp -o TARGET,SOURCE,FSTYPE,OPTIONS
  test -w /sqlite-tmp
'
```

See [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/) for the distinction
between a host source and a container destination.

The reported I/O failure followed a deployment configuration mistake; the earlier temporary-space
exhaustion also exposed a limitation of using tmpfs for large imports. The Compose default now
addresses that limitation using the already-required writable state mount. Custom Compose files,
overrides, and plain `docker run` deployments need to provide usable temporary storage too;
plain `docker run` does not inherit Compose's environment settings. There is no demonstrated
event-replay defect from this incident. Archive Ledger's error reporting still needs improvement:
the current projection error message omits SQLite's extended error code, making different I/O
failures hard to distinguish.

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
