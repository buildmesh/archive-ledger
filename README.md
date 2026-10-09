# Archive Ledger

Archive Ledger is a local-first command-line catalog for answering three practical questions:

- Where are my files and copies?
- Are those copies still readable and recent enough to trust?
- Which files could be permanently lost if a disk, site, account, or shared dependency fails?

It inventories ordinary directories and git-annex repositories, verifies bytes, evaluates backup
policy and disaster risks, protects its own catalog history, and can make verified copies between
registered Locations. It does not move, delete, repair, or drop archive content.

> Development status: new Archives use the signed version 2 event tree and a
> rebuildable compact schema-7 SQLite projection. Setup, inventory, git-annex import,
> Location scanning and verification, staging, verified copy, resumable jobs,
> opt-in targeted background verification, status, risk reporting, enrollment,
> verified Git synchronization, and portable
> snapshot clone and layered catalog `fsck` use the v2 path. Topology-aware
> metadata protection reporting and destructive content operations remain under
> development. Keep
> an independent backup of each Archive's canonical event tree and do not rely on
> this pre-production build as the only catalog for irreplaceable data.

New to Archive Ledger? [From first Archive to routine maintenance](docs/guides/archive-lifecycle.md)
walks through setup, protecting the catalog itself, adding copies, Policy, keeping the catalog
current, and maintenance in order. A test script runs every command in it against a disposable
Archive.

See [Example workflows](docs/workflows.md) for task-oriented walkthroughs based on realistic
Archive Ledger use.

For the initial git-annex workflow, follow [Seven git-annex workflows in Docker](docs/guides/annex-workflows.md):
create an Archive and Collection, verify a Location, add new files from a subtree, register a
clone, make verified copies, and list every File below a chosen copy count. The guide includes a
repeatable Docker end-to-end test using a disposable copy of an existing annex repository.

## Concepts and relationships

An **Archive** is one complete catalog. It is not a directory or storage device: one Archive can
describe many Collections spread across computers, removable disks, NAS devices, offline media,
and services.

```text
Archive
├── Collection ──uses──> Policy
│   └── File (logical path) ──refers to──> Object (exact bytes)
│                                             │
│                                             └── Copy claim at a Location
├── Filesystem Location ──under──> Archive Root ──on──> Device ──at──> Site
├── Service Location ────────────────────────────────────────────────at──> Site
├── Risk domains ──attach to──> Locations, roots, Devices, or Sites
└── Canonical events ──materialize into──> SQLite database
```

### Content

- A **Collection** is a logical set of files, such as “Photos,” “Documents,” or “Emails.” It has
  its own logical path namespace, home Site, and preservation Policy.
- A **File** is a logical path within a Collection, such as `2026/trip/photo.jpg`. It is not the
  bytes themselves.
- An **Object** is one exact byte sequence identified by BLAKE3. Identical Files can refer to one
  deduplicated Object.
- An **external identity** is a source identifier known before bytes are readable, such as a
  git-annex key. It keeps a dropped annex File reviewable but is not verified protection.
- A **path observation** records where a File representation was seen.
- A **copy claim** records current evidence that Object bytes exist at a Location. Its state may be
  present, missing, corrupt, unknown, or superseded.

The distinctions matter: a File answers “what does the user call this?”, an Object answers “which
bytes are these?”, and a copy claim answers “where does the catalog currently believe those bytes
exist?” A source reporting an annex key is a recovery lead, not automatically a verified copy.

### Storage

- A **Site** is a place whose loss matters, such as a home, office, storage unit, or cloud region.
- A **Device** is a physical or virtual storage-bearing unit, such as an SSD, removable disk, or NAS
  volume. Archive Ledger prefers filesystem or partition UUIDs over temporary mount paths.
- An **Archive Root** identifies the mounted filesystem root on a Device.
- A **Location** is a storage area containing copy claims. A filesystem Location belongs to an
  Archive Root and Device; a device-less service Location belongs directly to a Site.

A Location may hold all or only part of a Collection. Several Locations on several Devices may
together form one complete backup set. Two paths on one disk do not provide two-Device protection.

### Protection

- A **Policy** defines required qualifying copies, Devices and Sites, freshness limits, and optional
  offsite, offline, or encrypted-offsite requirements.
- A **qualifying copy** has resolved byte identity, successful recent verification, current
  observation and Device evidence, and sufficiently classified active topology.
- A **risk domain** represents a shared failure not visible from basic topology, such as one NAS
  chassis, safe, cloud account, credential store, power circuit, or flood zone.
- A positive **add** inventories files it sees without drawing conclusions about absent files.
- A complete **scan** reconciles an entire Location and may mark prior paths missing.
- A **verification** re-reads one copy and compares it with the expected Object identity.

Device, Site, and device-less service loss are simulated automatically. Custom risk domains add
shared dependencies. A copy can remain visible while being too stale, unresolved, corrupt, or
uncertain to count as adequate protection.

### Catalog data

Canonical events are the durable append-only history. SQLite is their indexed materialized view
and serves normal `status`, `file`, `copy`, and `report` commands. SQLite can be rebuilt; canonical
history must be checkpointed and independently protected.

## Install

Archive Ledger currently targets Linux and builds from source. It requires Rust/Cargo, Git,
`findmnt` from util-linux, and the POSIX `install` utility. Legacy git-annex repositories are input
data; no git-annex binary is required for import, integrity checks, or copying. Initial import
reads Git metadata without invoking configured content filters. Subsequent inventory and copy
operations use direct filesystem access.

```bash
cd /path/to/archive-ledger
make install
export PATH="$HOME/.local/bin:$PATH"
archive --version
```

`make install` checks dependencies, performs a locked release build, and installs
`$HOME/.local/bin/archive`. Use `make install PREFIX=/usr/local` or `DESTDIR` when packaging.

Catalog replay (initial import, job resume, and rebuild) uses a 128 MiB SQLite page-cache
target and commits groups of up to 256 canonical records. SQLite uses its default 64 KiB
statement-journal spill threshold, with disk fallback and existing durability settings.
These settings are not a total-process memory limit.

Version 0.1.8 removes the custom 1 MiB statement-journal threshold, which could cause
large replay updates to fail with `database or disk is full` despite available space.
If you previously set `LIBSQLITE3_FLAGS=-DSQLITE_STMTJRNL_SPILL=1048576` outside this
repository, remove that definition before rebuilding (preserving any unrelated flags).
After installing the fixed build, retry `archive db rebuild`; a failed replacement build
leaves the original catalog in place.

### Run with Docker Compose

The repository includes a multi-stage `Dockerfile` and a Compose configuration. Compose is used as
a reusable definition for this one-shot CLI, not as a long-running service: run a fresh container
for each command so external devices mounted on the host before the command are visible.

Create a private state directory and one host directory beneath which external devices are
mounted. The device directories may remain empty while their devices are disconnected:

```bash
cp .env.example .env
# Edit the absolute paths, UID/GID, and stable host ID in .env.
mkdir -p "$HOME/.local/share/archive-ledger-container" /mnt/archive-ledger
docker compose build
docker compose run --rm archive --version
```

For example, arrange host mountpoints as `/mnt/archive-ledger/photos-disk`,
`/mnt/archive-ledger/backup-disk`, and so on. The single parent bind mount makes them appear as
`/locations/photos-disk` and `/locations/backup-disk` in the container, so twelve devices do not
require twelve command-line mount arguments. Mount a device before starting a command; an empty
mountpoint is not the device and must never be used to initialize a Collection or Location.

Archive Ledger's catalog and local configuration persist beneath `ARCHIVE_LEDGER_STATE_DIR`.
Location content is read-only by default, while the image filesystem is also read-only. Initialize
and use an Archive with:

```bash
docker compose run --rm archive init "Personal archive"
docker compose run --rm archive location discover /locations/photos-disk
docker compose run --rm archive collection init /locations/photos-disk/documents \
  --name "Documents" --device "Photos disk" --site "Home"
docker compose run --rm archive collection add /locations/photos-disk/documents
```

A shell function can shorten repeated commands without hiding the Compose definition:

```bash
archive-docker() { docker compose run --rm archive "$@"; }
archive-docker status
```

If Archive Roots are scattered under unrelated host parents, copy
`compose.locations.example.yaml` to the ignored `compose.override.yaml` and list those exceptional
bind mounts there. Compose loads that override automatically:

```bash
cp compose.locations.example.yaml compose.override.yaml
docker compose run --rm archive status
```

The override example also shows how to make one deliberate copy destination writable. Keep source
Locations read-only. Do not run native and containerized writers against the same catalog at the
same time.

Compose drops all Linux capabilities, prevents privilege escalation, and mounts `/tmp` with
`noexec,nosuid,nodev`. Runtime networking defaults to `none`: this CLI has no container peers to
contact, so it needs no Compose network. These controls accompany the read-only image and source
mounts; `/state` and explicit copy destinations remain writable. See the
[Docker Compose service reference](https://docs.docker.com/reference/compose-file/services/) for
the capability and network controls.

Compose sets `SQLITE_TMPDIR=/state` so large SQLite operations use the state disk for temporary
files instead of consuming the RAM-backed `/tmp` capacity. Keep enough free space on the state
disk for both the catalog and temporary files. Other tools retain writable `/tmp` on tmpfs.
For a dedicated temporary-file disk, or if an older/custom setup fails during import or
`db apply` with `v2_projection_sqlite: disk I/O error`, see
[SQLite temporary-directory failure and recovery](docs/guides/annex-workflows.md#sqlite-temporary-directory-failure-and-recovery)
for configuration, diagnostics, and recovery from saved events.

Remote HTTP(S)/SSH synchronization and cloning require an explicit network opt-in for that command:

```bash
ARCHIVE_LEDGER_NETWORK_MODE=bridge docker compose run --rm archive sync
```

This enables Docker's default bridge with outbound network access, including reachable host/LAN
services; it is not a destination allowlist. Keep the variable unset for ordinary local commands.
Local Git remotes work offline when their paths are explicitly mounted with the required access.
Image builds still need network access to download dependencies. The runtime restrictions apply
through Compose; plain `docker run` does not inherit them.

The container runs as `ARCHIVE_LEDGER_UID:ARCHIVE_LEDGER_GID`; the state directory must be writable
and Location files readable by that identity. `findmnt` runs inside the container, and Docker may
not expose the underlying filesystem UUID for every bind mount. Always inspect a representative
root with `location discover`. If stable identity is unavailable, `--allow-unidentified-root` is an
explicit weaker fallback whose safety depends on keeping both the container mount path and
`ARCHIVE_LEDGER_HOST_ID` stable. Mounting a host root at the same absolute container path is also
possible by setting `ARCHIVE_LEDGER_CONTAINER_LOCATIONS_DIR` to the host parent path.

The writable state directory is trusted Archive Ledger state. Do not mount it into PhotoDB or other
application containers; those applications should use the Archive Ledger CLI or a service boundary.
Any Git, SSH, or credential configuration deliberately mounted into the Archive Ledger container is
also operator-trusted and may select executable credential helpers or filters.

The parent-directory approach recursively includes devices already mounted beneath it when the
container starts. On older Linux kernels, Docker may be unable to make nested submounts read-only
even though the parent bind is read-only. Use explicit per-root entries like those in
`compose.locations.example.yaml` when read-only enforcement by the container boundary is required.

## Create an Archive and first Collection

Create one named catalog. This does not inspect the current directory or tie the Archive to any
particular files:

```bash
archive init "Personal archive"
```

The first Archive becomes the default. Additional Archives can be selected explicitly:

```bash
archive init "Work archive"
archive list                 # `archive ls` is equivalent
archive use "Personal archive"
archive --archive "Work archive" status
```

`archive list` reads only the per-user Archive registry, marks the default, and remains usable if
one registered catalog is unavailable or needs repair. `archive list --json` also returns each
Archive's stable ID and catalog root for scripts.

Catalogs live under the XDG data directory, normally
`~/.local/share/archive-ledger/archives/<archive-id>/`. Normal output confirms the Archive and
suggests the next setup step; `archive init --json` includes its identity, accepted frontier,
canonical Git commit, and Archive root. Pre-v2 development catalogs are intentionally unsupported
and should be recreated. `--name` remains available as an alternative for scripts.

For an ordinary directory, create a Collection from its logical root:

```bash
cd /srv/archive/documents
archive collection init --name "Documents"
```

Archive Ledger discovers the mount root, directory-relative path, and filesystem or partition UUID
when available. It asks for a Device name and Site only when those facts cannot be inferred. A
typical first run might use “Main computer” and “Home.” Setup creates a starter Policy and a
Location named `Documents on Main computer` unless overridden.

For scripts, provide every fact that might otherwise prompt:

```bash
archive collection init /srv/archive/documents \
  --name "Documents" \
  --device "Main computer" \
  --site "Home" \
  --non-interactive
```

If stable filesystem identity is unavailable, non-interactive setup fails closed. Inspect it and
explicitly accept weaker identity only when necessary:

```bash
archive location discover /srv/archive/documents
archive collection init /srv/archive/documents \
  --name "Documents" --device "Main computer" --site "Home" \
  --allow-unidentified-root --non-interactive
```

An unidentified removable filesystem can only be reused from matching prior mount evidence. A
mount path alone is never silently promoted to durable Device identity.

Filesystem/partition UUID evidence identifies the Archive Root, not the physical Device. Confirm
Device independence separately with stable hardware evidence that you have checked on the current
machine or drive:

```bash
archive device status "Main computer"
archive device identity "Main computer" \
  --kind hardware_uuid --fingerprint '<hardware UUID>'
# Typical external-drive evidence kinds include serial, wwn, and nvme_eui64.
```

Do not use a filesystem UUID, partition UUID, label, or mount path as the Device fingerprint. If
the platform exposes no trustworthy hardware identity, keep that uncertainty explicit with
`archive device identity <device> --unavailable`. If recorded evidence is cloned or no longer
matches, use `--conflict`; the Device then stops qualifying as independent protection until a
stronger identity is confirmed. Confirmation records a current manual identity check-in, while
Archive Root identity remains unchanged.

## Add files and reconcile a Location

Setup registers topology but does not enumerate ordinary content. Add present files from the
Collection root:

```bash
cd /srv/archive/documents
archive collection add . --collection "Documents"
```

`collection add` infers the current Location and is positive-only. It streams traversal, computes
BLAKE3 for new and changed regular files, records matching reads as verification and presence at
that Location, and never marks an unvisited file missing. A known file whose size and modification
time are unchanged at this Location, with a good last check, is not read again: adding a few new
files to a large tree reads only those files. A file that appears at a Location for the first time
is always read, even if the Collection already has it elsewhere. Git metadata named `.git` is always
excluded. It can safely target a subtree:

```bash
cd /srv/archive/documents/2026
archive collection add .
```

After the first inventory, Location and Collection can usually be inferred from the current path.
Use `--location` or `--collection` when a path is ambiguous.

A complete reconciliation is explicit:

```bash
cd /srv/archive/documents
archive location scan --dry-run
archive location scan
```

`--dry-run` on `location scan` or `collection add` previews the run from metadata alone. It
lists new files, files known elsewhere but not recorded at this Location, size or time changes,
corrupt or unverified copies that would be read, files that would be marked missing (complete
scan only), and copies whose presence or verification is due. It reads no file content, writes
nothing, and exits with code 10 when a real run would record something. It cannot predict
integrity results. Unlocked annex pointer files are recognized from their size; a small
annex-tracked file that is neither unchanged, its recorded content size, nor a pointer's size is
listed as uncertain, because telling requires reading it. Like a scan, the preview refuses while
the Location has an unfinished scan job.

To list **all** files new to a Collection or Location, without the 20-path preview
sample limit or verification-due calculations:

```bash
archive collection add /path/to/subdirectory --collection Files --location "Files on disk9" --dry-run --list-new
archive --json collection add /path/to/subdirectory --collection Files --location "Files on disk9" --dry-run --list-new
```

The listing streams paths in filesystem discovery order, labeled `new-to-collection`
or `new-to-location` (a known File not currently recorded present here). Paths are
Collection-relative, including when selecting a subtree. Existing recorded files that
need verification are not listed as new. Ordinary symlinks are ignored; imported annex
links are checked for local content availability using metadata, without hashing or fetching
content. `--exclude` works as in the ordinary preview. `--list-new` requires `--dry-run`
and cannot be combined with `--accept-changes`.

JSON output is one object with a streamed `items` array; each item has `kind`, lossless
`path`, and `size_bytes`. The final `summary` and `complete` fields describe coverage within
the requested scope, with exclusions, filesystem boundaries, ignored entries and errors
reported explicitly. Check the exit code and final `complete` field before treating results
as exhaustive: code 0 means a complete listing with no new files, 10 means new files or
incomplete coverage, and 2 means a fatal error. A traversal/classification failure may leave
partial items followed by `complete: false` and an `error`; an interrupted command or failed
output write may leave unfinished JSON. No catalog updates or file-content reads are made.
Memory use does not grow with the result count; walking a large HDD directory tree can
still take time. Version 0.1.5 adds this option without requiring a database rebuild.

On a terminal, `location scan` and `collection add` show live progress on stderr. Each first
prints its job ID; if the run is interrupted, continue it with `archive job resume <job-id>`.
While a Location has an unfinished scan, a new `location scan` of it is refused rather than
silently starting over; the error names the job to resume or cancel.

During catalog replay, complete-scan finalization reports its current phase and rows
processed as **uncommitted** work. A single completion record may update presence across
the Location; the canonical-record counter advances only after the transaction commits.
If interrupted, resume the existing job to replay its published observations without
reading those file contents again. Version 0.1.3 uses temporary indexed path/annex lookups
to avoid repeatedly searching the whole Location for each copy during this step.

A complete `location scan` also skips unchanged files, and when it finishes it refreshes presence
for every file it saw. It re-reads new, changed, corrupt, and never-verified files. Byte integrity
of unchanged files is the job of `archive verify` and the background runner, which re-read copies
as their verification comes due. Content replaced with the same size and modification time (for
example by `rsync -a`, coarse FAT timestamps, or some network filesystems) is therefore detected
when that copy is next verified, not by the scan. Scan output reports how many copies at the
Location are due and suggests `archive verify`.

Only a successfully completed scan can mark prior paths missing. Traversal errors, permission
failures, Device removal, cancellation, or concurrent namespace changes make coverage partial.
Partial runs retain positives but cannot publish missing facts or fresh complete-coverage evidence.

Cataloged content is immutable by default. If a known file's bytes differ, add and scan report
“content differs from catalog,” mark that copy corrupt, and return exit code 10. The File keeps
its expected content identity. Restoring the original bytes and rescanning makes the copy good
again. Merely changing modification time without changing bytes is not an integrity failure.

To accept an intentional edit, name the exact ordinary file relative to the inventory directory:

```bash
archive collection add . --accept-changes notes.txt --dry-run
archive collection add . --accept-changes notes.txt --yes
```

Repeat `--accept-changes FILE` for multiple files. Only those files are processed; directories,
unknown paths, and annex-managed files cannot be accepted this way. Preview hashes current bytes
without recording changes. Acceptance hashes them again, updates the catalog, and leaves file
contents untouched. Without `--yes`, an interactive confirmation is required; scripts can use
`--non-interactive --yes`. Paused acceptance jobs retain their exact selection for `job resume`.

The v2 JSON summary reports `new_paths`, `confirmed_good`, `missing_paths`, and
`integrity_mismatches`. `changed_paths` counts explicitly accepted changes to known content;
ordinary add and scan never increment it for unexpected edits. `integrity_findings` provides up
to 20 example paths; the mismatch count includes all findings.

## Check an unfamiliar directory before deleting its original

Use staging when files arrive from another computer or removable disk and you do not know which
contents are already cataloged:

```bash
archive stage /media/incoming --collection "Photos"
```

Staging computes BLAKE3 for stable regular files and compares content identity across every
Collection. It reports content already in the selected Collection, content found only in other
Collections, and content entirely new to the Archive. Names do not determine a match. Ordinary
symlinks and special files are ignored and reported. For cataloged content it also reports
policy-satisfied, at-risk, and unknown counts. Policy evidence is read from the current SQLite
cache; staging never refreshes that cache itself.

`archive stage` changes no ledger data. It appends no events and creates no File, Object, Location,
Copy, presence, verification, or Policy facts. Reusable checksums normally go in
`.archive-ledger-stage/manifest.sqlite3` beneath the staged directory; that reserved directory is
excluded from its own audit. If the source is unwritable, the command creates a private temporary
manifest and prints its path for use with `--manifest PATH`.

Review an import without writing anything:

```bash
cd /srv/archive/photos
archive stage import /media/incoming --dry-run
```

Then explicitly import only content that is still unknown across the whole Archive:

```bash
archive stage import /media/incoming --yes
```

Location and Collection are inferred from `cwd` when unambiguous. The command creates one new
subtree named after the staged source; use `--into NEW-DIRECTORY` to select another single new
directory name. Existing destinations are never overwritten.

Import does not repeat a preliminary checksum scan. It hashes bytes while copying them into a
private destination-side tree, compares them with the saved checksum, and reads every completed
destination back for verification. The whole tree becomes visible only after every candidate
succeeds, then the normal positive-only add engine records verified presence. Source files are
never modified or deleted. Rerunning `archive stage` reuses unchanged checksums and refreshes the
comparison against current ledger state. Import prints a durable job ID. If it is interrupted
while preparing files or after the tree becomes visible but before ledger recording completes,
resume it with `archive job resume JOB_ID`; existing destination bytes are re-read and must match
the reviewed checksums.

“Already cataloged” is not by itself a deletion-safety claim. A known Object may still have too
few qualifying copies or all copies at one Site. After importing new content and making the needed
verified Location-to-Location copies, review `archive report risk`; retain the staged source until
every relevant Collection satisfies its Policy. Then rerun `archive stage` and retain the source
unless it says `Source removal readiness: READY`. Readiness requires a complete audit, no
archive-unknown content, and a satisfied current Policy for every active Collection that owns each
staged Object; the staged source itself never counts as protection.

## Make a verified copy at another Location

Run copy from within the registered source Location. A path selects a logical File or directory
prefix from the SQLite catalog; it does not enumerate the source directory. Omitting paths selects
the Collection subtree corresponding to `cwd`:

```bash
cd /srv/archive/photos/2026/trip
archive copy --to "Photos on SD01" . --dry-run
archive copy --to "Photos on SD01" . --yes
```

`archive location copy` is an equivalent, more explicit entry point. Use `--from` and
`--collection` when they cannot be inferred, and use `--non-interactive --yes` for unattended
execution.

Copy planning deduplicates identical Objects and skips Objects already recorded present at the
destination. Before writing, Archive Ledger checks both mounted Device identities, every selected
source, destination collisions and containment, and available space. Each source stream is checked
against the reviewed BLAKE3 while it is copied through a same-directory temporary file; the final
destination is published without replacement and read back for verification. Existing files are
never overwritten, and source files are never changed or deleted. If post-publication verification
fails, the unrecorded suspect destination is left in place for inspection rather than deleted.

When the destination was imported from git-annex, Archive Ledger can safely fill a registered
dangling annex symlink by writing its missing content beneath that Location's `.git/annex/objects`
directory. It preserves the symlink and does not run git-annex. Any ordinary or unregistered
symlink is refused rather than followed.

Long copies have a durable job ID. If a run is interrupted, mount the same registered Devices and
resume it; completed Objects are reconciled from canonical facts and are not recopied:

```bash
archive job resume <job-id>
```

Copy creates additional verified presence, not proof that preservation Policy is satisfied. Review
`archive report risk` after copying, especially for distinct-Device, distinct-Site, freshness, and
shared-risk requirements.

## Add another Device or partial Location

Suppose an external disk is mounted at `/media/sd01` and contains another ordinary copy or subset:

```bash
cd /media/sd01/documents
archive location init --collection "Documents" \
  --device "SD01" --site "Home" --non-interactive
archive collection add . --collection "Documents"
```

One Device may have several Locations, and several Devices together may contain every Object. If a
removable filesystem is later mounted elsewhere, its UUID identifies the same Archive Root, which
remains associated with its registered Device; that UUID is never treated as Device hardware
identity.

Record a physical Site move without changing stable IDs:

```bash
archive site add \
  --id site_offsite_storage --name "Offsite storage" --kind storage
archive device move "SD01" --to "Offsite storage"
```

Correct display names without changing identity or history:

```bash
archive rename "Family archive"
archive collection rename "Documents" "Family documents"
archive location rename "Documents on SD01" "Documents backup on SD01"
archive device rename "SD01" "Blue backup disk"
archive site rename "Home" "House"
```

## Import git-annex repositories

One git-annex repository maps to one Collection Location, even when it contains only part of the
Collection's bytes. Create and import the main repository in one step:

```bash
cd /var/lib/annex/photos
archive collection init --name "Photos" \
  --device "Main computer" --site "Home" \
  --import-annex --non-interactive
```

Import each additional annex repository or remote as another partial Location:

```bash
cd /media/sd01/annex/photos
archive location import-annex --collection "Photos" \
  --device "SD01" --site "Home" --non-interactive
```

Use `location import-annex`, not `location init`, for an annex repository.
`location init` is topology-only setup for ordinary directories and intentionally
does not enumerate files; it refuses an unimported annex worktree before creating
an empty Location. If an older Archive Ledger version already registered that
exact path, `location import-annex` reuses the Location and fills in its annex
inventory rather than creating a duplicate.

The importer is a one-time migration/bootstrap step. It reads the Git index, annex keys, and local
object bytes without invoking git-annex or configured Git content filters, and checks source
consistency. SHA256/SHA256E and SHA512/SHA512E keys retain their original expected checksum for
direct integrity verification; BLAKE3 remains the canonical Object identity. Every annex-managed
path becomes a File reference. A dangling annex link remains an unresolved external identity and is absent from that
Location; readable content becomes a BLAKE3 Object and verified present copy. Other symlinks,
including Git-tracked organizational links, are counted and explicitly reported as ignored. They
create no File, Object, path-observation, or Copy facts.

For a large repository, add `--inventory-only` to either `collection init --import-annex` or
`location import-annex` to defer content reads. This records annex paths, keys, expected sizes,
and checksums without checking local content availability or integrity. The summary counts these
entries as `unchecked`; they create no verified copies or BLAKE3 Objects and provide no verified
protection. Git enumeration and worktree metadata consistency checks still take time.

After inventory-only import, establish presence and integrity with a normal scan. The positional
argument identifies the Location; `--path` supplies its mounted directory:

```bash
archive location scan "Photos on Main computer" --path /var/lib/annex/photos
```

Annex import reports its current phase, processed and skipped entries, verified, absent and
unchecked content, errors, and bytes read this run on stderr. Updates appear about once a second
on a terminal and every 30 seconds when redirected, with start and finish updates. Progress covers
metadata inspection, import, source rechecking, publication, and projection; it does not estimate
completion time. JSON results remain on stdout.

For SHA512 entries imported by an earlier version without their expected checksum metadata,
rerun `location import-annex --reimport` on the same registered path with its existing
Collection and Location settings, then run `location scan`. Re-import preserves the Location and File
identities while learning the original checksum; a database rebuild alone does not discover missing
hashes. See
the [legacy annex guide](docs/guides/annex-workflows.md#2-create-a-collection-by-importing-git-annex)
for commands.

After a successful import, use the normal inventory commands:

```bash
archive collection add .
archive location scan
```

These commands recognize the imported annex paths from SQLite and inspect the filesystem directly;
they do not run Git or git-annex. Locked content is read only through a validated symlink target
inside that Location's `.git/annex/objects` directory. Dangling links and annex pointer files remain
known but absent, and `.git` itself is never traversed as ordinary Collection content. A complete
`location scan` can therefore detect content that has appeared or disappeared after migration,
while `collection add` remains positive-only. New regular files created after migration are added
directly as ordinary Archive Ledger Files; they do not need `git annex add` or another annex import.
An annex repository that has not been imported still fails closed and directs the user to
`--import-annex`.

For example, photos, documents, and emails repositories normally become three Collections. The
main photos repository and every partial photos remote are Locations of Photos. Multiple disks that
together contain all Photos Objects are multiple Locations on multiple Devices, not separate
Collections.

Review annex UUID evidence and optionally map a reported remote to known storage:

```bash
archive annex-remote list --all
archive annex-remote map <source-annex-uuid> <remote-annex-uuid> <location-id> \
  --name "Photos on offsite annex"
archive annex-remote unmap <source-annex-uuid> <remote-annex-uuid>
```

Remote availability is a recovery lead, not a verified copy. Import or scan actual bytes before
treating the Location as proven protection.

## Review status, integrity, and disaster risk

Fast summaries come from indexed SQLite and do not enumerate storage:

```bash
archive status
archive c status "Documents"
archive l status "Documents on Main computer"
archive d status "Main computer"
archive s status "Home"
archive c ls
archive l ls
archive d ls
archive s ls
archive file find --collection "Documents" --limit 100
archive file show <file-id>
archive file history <file-id> --limit 100
archive object show <object-id> --limit 100
archive object history <object-id> --limit 100
```

`c`, `l`, `d`, and `s` are shortcuts for `collection`, `location`, `device`, and `site`;
`ls` is a shortcut for `list`. The human list commands print one active display name per line.
Use `show` or `--json` when IDs and registry details are needed.

`archive status` gives an Archive-wide action view: every Collection's File count and current
Policy at-risk and uncertain counts. Collection status expands that view into the Locations known
to contain its inventory. Location status shows its Device, Site, path relative to the Device
root, File count, present-byte space, and stale-presence count and age threshold. Device status
rolls those figures up across its Locations and, when the Device is currently mounted and its
filesystem identity still matches, reports live free space. Site status rolls them up by Device.
Unavailable or unconfirmed facts are shown explicitly rather than guessed.

File and copy lists use stable continuations, so directories with thousands of entries and
Collections with hundreds of thousands of Files remain reviewable without running the equivalent
of `ls` or loading the full result in memory. `file find` accepts a Collection name or stable ID
and supports `--exact` and `--prefix` logical-path filters. `file show` reports the exact total
Copy count and returns at most 1,000 detailed Copy rows; JSON sets `copies_truncated` when more
rows exist. `object show` similarly returns a bounded, continuable page of the logical Files that
refer to one content Object, so heavily deduplicated content cannot produce an unbounded response.

`file history` and `object history` are explicit audit operations. They authenticate and stream
canonical event records in bounded memory because full event payloads are deliberately not
duplicated in SQLite. Use the printed `--continue` token for another page; the command rejects a
token if canonical history has advanced, so a page sequence cannot silently mix snapshots.

Risk reports automatically refresh missing or stale derived assessments from SQLite; they never
scan storage or replay canonical history. Review the starter Policy and simulated loss results:

```bash
archive policy list
archive policy show "Two copies at two sites"
archive report risk
archive report integrity
archive report policy
```

Status and detailed risk reports evaluate copies of content referenced by the selected
Collection, including protecting copies in other Collections and Locations. Version 0.1.4
scopes these queries to that content instead of aggregating unrelated archive contents.
Reports still evaluate current policy freshness on each invocation; limiting displayed
findings does not limit the Collection totals. No database rebuild is required for this update.

`report integrity` lists copies whose content differs from the catalog (corrupt copies). For each
one it shows where verified copies of the same content are: Location, Device, path, when each was
last verified, and whether it is connected now. It says plainly when no verified copy remains in
the Archive. It reads only the catalog and exits with code 10 while corrupt copies exist. To
repair one by hand, copy a good file back over the corrupt one, keeping the corrupt bytes aside
if you are unsure, then run `archive verify` on that Location: corrupt copies are always
re-read, and a matching read marks the copy good again.

`archive repair` does that for you when a verified copy is connected:

```bash
archive repair "Photos on Blue disk" --dry-run
archive repair "Photos on Blue disk" --yes
```

For each corrupt copy it re-reads the most recently verified connected copy of the same content
while copying it, moves the corrupt file into `.archive-ledger/quarantine/<job-id>/` in the same
Location, places the verified replacement with its original modification time and permissions,
reads it back, and records it as verified. Scans ignore the quarantine; delete it when you are
satisfied. A copy whose size or modification time changed may be an intentional edit, so it is
skipped unless you pass `--include-changed` (accept a real edit with
`collection add --accept-changes` instead). Without a connected verified copy it says so and
changes nothing. Omit the Location to repair every connected Location with matching identity.
It is resumable with `archive job resume`, and requires `--yes` when not interactive.

The starter Policy requires two qualifying copies on two Devices at two Sites, including one
offsite copy, with verification, presence, and Device check-in evidence no more than 365 days old.
Update only the settings that should change, for example:

```bash
archive policy update "Two copies at two sites" \
  --copies 3 --verification-days 180
```

`archive policy evaluate` remains available to precompute the same SQLite cache explicitly.

Early reports commonly have findings until independent Devices and Sites are inventoried and
verified. Use risk domains for shared failures that topology cannot reveal, such as several disks
in one safe, one NAS chassis, one cloud account, or one credential store.

The stale-presence report answers which Device should be mounted and refreshed next. Its first line
states the applicable Policy age or mixed-Policy range:

```bash
archive report stale-presence
archive report stale-presence --locations
archive report stale-presence --collection "Photos" --older-than 180
```

The default deduplicates stale Objects per Device. `--locations` adds Location counts, last complete
inventory, oldest stale observation, Site and availability context, and a suggested `scan` or
`import-annex` action. Missing, corrupt, unknown, and unresolved annex states remain separate from
stale resolved presence.

To refresh only stale Copy claims on recognized connected Devices, enable the bounded one-shot
runner and invoke it manually or from your operating system's scheduler:

```bash
archive background enable --max-items 100
archive background status
archive background run
```

The runner queries stale targets from SQLite; it does not list or rescan entire directories. It
revalidates Device and Archive Root identity before reading, ignores symlinks, never changes archive
content, and records each successful or failed integrity check. A run processes at most the
configured number of Copy claims and prints a job ID when more work remains:

```bash
archive job resume <job-id>
archive background pause       # preserve settings but refuse scheduled runs
archive background disable     # opt out
```

There is no Archive Ledger daemon or installed scheduler service. Configure cron, systemd, or
launchd to call `archive background run` only after explicitly enabling it. Configuration is local
to this installation, so another synchronized computer must be enabled separately. An unidentified,
conflicting, disconnected, or ambiguously mounted Device is skipped and its evidence remains stale.

## Verify bytes and resume work

Adding or scanning content records the hashing read as baseline verification. Routine verification
re-reads only the copies that are due: never verified, failed their last check, past their
Policy's presence or verification age, or expiring within 30 days (`--verify-within DAYS`), but
never more often than every half of the Policy's verification age. It reads the least recently
verified first and does not walk directories. Omit the Location to verify every connected
Location whose identity currently matches; add `--all` to re-read every copy:

```bash
archive verify
archive verify <main-location-id> \
  --path /srv/archive/documents \
  --fingerprint-status match
archive verify <main-location-id> --all
```

Verification does not discover new files or mark files missing; use `location scan` for that. If
a copy cannot be read because it was moved or removed, verify records a read error and suggests a
scan. Copies whose content identity is not yet known, for example after an inventory-only annex
import, are reported and need `location scan`.

Use `match` only after confirming the mounted filesystem is the registered Device. A mismatch
blocks reads. A hash mismatch marks that copy corrupt without redefining the expected Object; a
read error makes the claim non-qualifying until later successful verification.

Long operations print durable job IDs:

```bash
archive job list
archive job show <job-id>
archive job resume <job-id>
archive job cancel <job-id> --dry-run
```

`job list` shows unfinished jobs with their type, age and last recorded progress; add `--all` to
include finished, partial, failed and cancelled jobs. `archive status` mentions unfinished jobs.
It also lists local job directories that have no row in the catalog database, for example after
`db rebuild`. These are marked resumable, in use by another running process, or unrecognized.
An unrecognized directory has no readable configuration and is kept for inspection. `job show`
explains where an unfinished job stopped. After `db rebuild`, `job resume <job-id>` can recover
annex and inventory work from this installation’s local checkpoint. Existing terminal job status
still takes precedence; local checkpoints are not transferred by sync or portable snapshots.

To abandon an unfinished location scan, collection add, or annex import, run
`archive job cancel <job-id>`.
Preview it first with `--dry-run`. Cancel removes only that job's local checkpoint files,
including jobs left only on disk after `db rebuild`. Its unpublished progress is lost; the job had
published nothing to catalog history. A job that is still running elsewhere is refused.

Resume first finishes a verified local publication interrupted between frontier advancement and
its Git commit, then applies canonical events and reconciles deterministic outcomes. It does not
duplicate durable facts. Recovery refuses unrelated canonical edits, unfinished Git operations, or
ambiguous history; preserve the files and inspect the reported problem before retrying. Operations
are batched and do not require all paths in memory.

## Protect and recover the catalog

SQLite is the normal interactive materialized view, but it is replaceable. Canonical events are the
durable rebuild source, so protecting only `archive.db` is insufficient. `archive init --json`
prints the Archive root; its SQLite view is `archive.db`, its Git-backed event tree is `canonical/`,
and its private client key stays under `local/`.

Configure a Git remote for the Archive's canonical history, then synchronize. Supported transports
are local paths and `file://`, `http://`, `https://`, SSH, and scp-style SSH locators. Option-shaped
locators and arbitrary Git remote helpers are refused. HTTP(S) locators containing user
information, a query, or a fragment are also refused; use normal Git/SSH credential configuration.

Archive Ledger treats its writable state directory—including repository-local Git
configuration—and deliberately supplied system, user, SSH, and credential configuration as trusted
operator input. Credential helpers and filters configured there may execute programs. Managed Git
commands remove inherited Git/SSH command selectors, force the standard `ssh` executable, override
hooks and filesystem monitors, disable automatic signing and paging, and permit only the transports
above. Use SSH configuration rather than `core.sshCommand` for ports, identities, and proxying. A
URL rewrite cannot enable a disallowed helper or protocol.

This boundary is deliberate: distrusting writable Git configuration while preserving arbitrary
credential helpers, filters, and URL rewrites would require a separate Git-configuration
virtualization subsystem. Archive Ledger instead keeps `/state` private to its own container and
treats canonical content and supplied remote locators—not operator configuration—as untrusted.

```bash
archive sync remote add central ssh://backup.example/personal-archive.git
archive sync
archive sync status
```

Until catalog history is on a sync remote, `archive status` and commands that change the catalog
(`init`, `collection init`, annex import, `collection add`, `location scan`) print one warning with
the next step, for example `WARNING: 3 catalog commits are not yet on a sync remote; … Next:
archive sync`. The warning stops once `archive sync` has sent the history to a configured
remote. Put that remote on another device and site: Archive Ledger does not yet check whether it is
independent.

`archive sync [remote]` fetches and verifies both histories before changing accepted state. A
fast-forward remains a fast-forward; compatible offline additions from different enrolled
installations become one Git merge commit whose tree is the verified union of immutable origin
journals. Event JSONL is never text-merged, neither side is dropped by arrival order, and SQLite is
updated only by applying the newly accepted origin ranges. Remote publication uses compare-and-swap
and retries a race instead of force-pushing over it.

The coordination remote is transport and a rendezvous for short signed leases; it is not by itself
proof of independent disaster protection. Multi-client topology, Policy, registry, revocation,
Archive rename, and complete-scan negative publication use a conservative Archive-wide lease.
Positive observations can still be recorded offline. Keep an independently protected copy of the
canonical event tree, and keep each installation's private key under `local/` private.

On an Archive copied to a new installation, create a public signed request:

```bash
archive sync enroll --name "Laptop" --output laptop.enrollment.json
```

Transfer only that request to an already enrolled installation and approve it:

```bash
archive sync approve laptop.enrollment.json
archive sync
archive sync status
```

Create a portable SQLite snapshot when a full event replay would be slow. The new directory is an
out-of-band cache artifact; it is deliberately not committed to canonical Git history. Transfer it
through any suitable file-transfer mechanism alongside access to the Git remote.

```bash
archive snapshot create /media/transfer/personal-snapshot
archive snapshot inspect /media/transfer/personal-snapshot
```

On the new installation, clone canonical history and optionally seed SQLite from that snapshot:

```bash
archive sync clone ssh://backup.example/personal-archive.git \
  --snapshot /media/transfer/personal-snapshot
```

Clone verifies the snapshot signature, database checksum, Archive and genesis IDs, historical Git
commit, frontier, schema, and projector version before use. It applies only the newer event ranges
in the cloned Git history. If the snapshot is absent or rejected, clone safely rebuilds SQLite from
canonical events instead. It never stores the SQLite database in the canonical Git repository.
Schema-6 snapshots are rejected by the current reader and use this canonical-replay fallback.

After cloning, run `archive sync enroll --name <this-computer>`, approve that public request on an
already enrolled installation, and synchronize both installations before the new one writes. The
request never contains the private key. To stop a lost installation from making future writes, use
`archive sync revoke <client-id> --yes`; previously accepted history remains intact.

### Upgrade an existing schema-6 or schema-7 catalog

After installing the new binary, stop commands writing the selected Archive and allow enough
space for a replacement database alongside the existing one. Rebuild its local SQLite catalog:

```bash
archive events verify
archive db rebuild
archive fsck --full
```

This creates schema 8 from the existing signed history, omitting Location/check rows for
annex content that was never present while retaining observations of copies that went missing. The canonical genesis schema remains 6;
the event tree is unchanged. Rebuild does not re-import an annex repository or rehash archive
contents. It retains the previous schema database beside `archive.db` as
`.archive-ledger-previous-<id>.db` and reports its exact path (`previous_database` in JSON).
Keep that backup and any accompanying SQLite sidecars until you have checked the rebuilt catalog
and recovered any unfinished work. Rebuilding an already-current schema does not retain this
additional backup.

Local job checkpoints remain under `local/jobs/`. Resume unfinished work with
`archive job resume <job-id>` after the rebuild; unpublished database job rows can be recreated
from those local files. Ordinary `db apply` does not upgrade an older schema.

### Check and rebuild the current catalog

Verify history, update SQLite, rebuild a disposable projection, and rehearse recovery:

```bash
archive events verify
archive fsck
archive fsck --full
archive db apply
archive db rebuild --target /tmp/archive-rebuilt.db

archive restore check restored-events \
  --rebuild-database restored-archive.db
```

Routine `archive fsck` is read-only. It runs strict Git object verification,
verifies every signed origin journal and accepted frontier, runs SQLite
`quick_check` and `foreign_key_check`, and checks Archive identity, record count,
and origin cursors. It does not bring a stale projection current; a finding tells
you to run `archive db apply` explicitly. `--full` additionally creates a unique
disposable clone and database at the live projection's captured frontier, checks
the rebuild's SQLite integrity and foreign keys, compares classified control tables and logical
domain views without database-local integer IDs, then removes only that tool-owned rebuild. A behind
projection can therefore pass logical comparison through its applied frontier
while separately telling you to run `archive db apply`. Use `--keep-rebuild` to
retain the diagnostic database or `--rebuild-dir <directory>` to select a volume
with enough free space. Each external Git step has a 30-minute wall-clock deadline. A timeout stops
the command's Unix process group, reports `fsck_git_timeout`, and makes the requested integrity
check incomplete rather than successful.

Exit status 0 means all performed checks passed, 10 means health or currency
findings were found, and 2 means a requested check could not be completed.

`restore check` verifies the chain and builds a new database; it does not overwrite the current
catalog.

## Use Archive Ledger from another app

Higher-level applications can use a versioned, read-only CLI contract without opening the private
SQLite schema or listing storage directories. Maintainers implementing a photo or album
application should use the complete
[photo album integration guide](docs/integrations/photo-album.md). It documents ownership
boundaries, first-time bootstrap, checkpoint safety, pagination, exact response fields, lossless
paths, availability evidence, stable errors, and a disposable contract test.

For example, a photo application can remember the Archive's canonical Git commit after a
successful import, then ask which active Files were first introduced afterward:

```bash
archive --json app changes \
  --collection "Photos" \
  --since <previous-canonical-commit> \
  --limit 100
```

Each page returns stable File/Object IDs, current lossless Collection-relative paths, the resolved
starting cursor, the current commit/frontier checkpoint, and an opaque continuation. This is an
introduction feed: it does not treat a rename as a newly introduced File, and it omits Files that
are no longer active.

To locate a requested set of Files, write one File ID JSON string (or a
`{"file_ref_id":"..."}` object) per JSONL line and run:

```bash
archive --json app access \
  --collection "Photos" \
  --input album-files.jsonl \
  --limit 100
```

The response gives at most one deterministic local candidate per File with the underlying presence
and verification evidence. “Accessible” means the Copy is claimed present and its registered
Archive Root is currently revalidated on this host; it is not a new integrity scan. Files that are
offline receive a deterministic greedy Device/Location attachment plan whose optimality is
explicitly not guaranteed. Files with no known attachable Copy and unknown IDs remain distinct.
The whole-request summary appears on every page, while the more expensive attachment plan is
returned on the first page only. Later pages must use the same input file and continuation; a
changed request or advanced Archive frontier fails closed. These commands never copy, retrieve,
scan, or otherwise mutate content or ledger state.

## Automation and exit status

- `0`: command completed and the selected check has no findings.
- `2`: invalid input, damaged state, I/O failure, or another command error.
- `10`: command completed but found preservation, integrity, stale-presence, metadata-protection,
  or partial-coverage concerns.

Exit `10` is an actionable finding, not a crash. Global `--json` provides versioned structured
results. An agent environment can set `ARCHIVE_LEDGER_OUTPUT=json` once instead; human-readable
output remains the default. Setup commands have explicit non-interactive flags:

```bash
archive --json status
archive --json report stale-presence --locations
archive --json file find --collection "Documents" --limit 100

archive collection init /srv/archive/documents \
  --name "Documents" --device "Main computer" --site "Home" \
  --non-interactive
```

Errors include stable codes. Review lists use deterministic ordering and continuation tokens that
fail closed if SQLite advances between pages.

## Safety and current scope

- `stage`, `collection add`, `location scan`, and git-annex import do not modify existing archive
  content. `stage import` is an explicit mutation that creates only new verified destination files
  and refuses overwrite.
- `copy` is an explicit mutation that creates only verified files at a registered destination
  Location. It refuses overwrite and never changes or deletes its source.
- Generic traversal excludes every `.git` path and every `.archive-ledger` path (repair's
  quarantine) at any depth, does not follow symlinks as ordinary files, and does not cross
  filesystems. Do not keep archive content in directories with either name.
- A git-annex repository requires one successful import. Later add and scan operations use the
  imported catalog facts and direct filesystem reads without depending on Git or git-annex.
- Imported annex symlinks are read only when both lexical and canonical checks keep the target
  inside the registered Location's `.git/annex/objects`; escape attempts fail closed.
- Every other symlink is ignored and reported. Archive Ledger does not follow it, count it as a
  File, treat its target as another Copy, or manage the organization it represents.
- Device identity mismatch blocks scanning; unidentified roots remain visibly uncertain.
- Positive-only add and every partial scan are incapable of publishing missing facts.
- Complete missing activation is atomic and follows only confirmed complete coverage.
- Registry changes and renames append canonical events; history is not rewritten.
- `repair` is the one explicit command that replaces existing archive content: only a copy whose
  bytes no longer match the catalog, only from a verified copy re-read during the repair, never
  by overwriting (the corrupt file is moved into the Location's `.archive-ledger/quarantine`
  first), and never automatically. No command deletes, drops, or otherwise rewrites existing
  archive content.

Background scanning of connected Devices and destructive Location-to-Location operations remain
future work. Verified copy is available as both `archive copy` and the equivalent
`archive location copy`; it copies unique Objects rather than materializing ignored organizational
symlinks. Archive Ledger no longer needs git-annex for an imported Location's scanning or copying.
It does not yet drop content, so use an established external workflow for any removal and scan the
resulting state afterward.

The current v2 acceptance gate inventories 100,000 real files in one resumable logical operation,
publishes 111 bounded physical records in one Git commit, rebuilds the projection, and checks
interactive status latency. Earlier streaming-foundation tests cover 500,000 paths. Discovery,
hashing, projection, and large result lists are bounded or paged. SQLite intentionally trades some
storage for low-latency indexed review; canonical history remains the recovery source. Reproducible
measurements live under `docs/benchmarks/`. The 100,000-file gate is ignored by routine
`make test`; run it deliberately with `make test-scale` only when changing traversal, batching,
projection-scale, or memory behavior.

### Diagnose a failed catalog rebuild

SQLite replay and rebuild errors include failure context while retaining
stable error codes such as `v2_projection_sqlite`. Reports include the source callsite,
replay origin/sequence/batch and item index when available, and a statement BLAKE3
identifier for compact projection operations. The identifier hashes the SQL template;
bound file paths and contents are not included in this added context.

Best-effort SQLite diagnostics report the library version, autocommit state, and
`page_size`, `page_count`, and `max_page_count` for the main and temporary databases.
`null` means a diagnostic query failed. These are observations **after the error** and
may reflect automatic rollback; they do not prove that disk space was exhausted.
Keep the complete error when reporting a failure. This change adds diagnostics, not a
fix for every `SQLITE_FULL` cause, and does not change the catalog schema or require
an additional rebuild for catalogs already on schema 8.


## License

Archive Ledger is licensed under the GNU Affero General Public License, version 3 only
(`AGPL-3.0-only`). See [LICENSE](LICENSE) for the complete license terms.
