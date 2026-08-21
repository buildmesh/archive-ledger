# Archive Ledger

Archive Ledger is a local-first command-line catalog for answering three practical questions:

- Where are my files and copies?
- Are those copies still readable and recent enough to trust?
- Which files could be permanently lost if a disk, site, account, or shared dependency fails?

It inventories ordinary directories and git-annex repositories, verifies bytes, evaluates backup
policy and disaster risks, and protects its own catalog history. It does not copy, move, delete,
repair, or drop archive content.

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
`findmnt` from util-linux, and the POSIX `install` utility. Git-annex is useful for managing annex
repositories but is not required by the read-only importer.

```bash
cd /path/to/archive-ledger
make install
export PATH="$HOME/.local/bin:$PATH"
archive --version
```

`make install` checks dependencies, performs a locked release build, and installs
`$HOME/.local/bin/archive`. Use `make install PREFIX=/usr/local` or `DESTDIR` when packaging.

## Create an Archive and first Collection

Create one named catalog. This does not inspect the current directory or tie the Archive to any
particular files:

```bash
archive init --name "Personal archive"
```

The first Archive becomes the default. Additional Archives can be selected explicitly:

```bash
archive init --name "Work archive"
archive use "Personal archive"
archive --archive "Work archive" status
```

Catalogs live under the XDG data directory, normally
`~/.local/share/archive-ledger/archives/<archive-id>/`. Init prints the exact SQLite and canonical
event paths. Existing custom catalogs remain accessible with global `--database` and `--events`
options, but central named Archives are the normal workflow.

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

## Add files and reconcile a Location

Setup registers topology but does not enumerate ordinary content. Add present files from the
Collection root:

```bash
cd /srv/archive/documents
archive location add . --collection "Documents"
```

`location add` is positive-only. It streams traversal, computes BLAKE3 for new or changed regular
files, records successful reads as verification, and never marks an unvisited file missing. It can
safely target a subtree:

```bash
cd /srv/archive/documents/2026
archive location add .
```

After the first inventory, Location and Collection can usually be inferred from the current path.
Use `--location` or `--collection` when a path is ambiguous.

A complete reconciliation is explicit:

```bash
cd /srv/archive/documents
archive location scan
```

Only a successfully completed scan can mark prior paths missing. Traversal errors, permission
failures, Device removal, cancellation, or concurrent namespace changes make coverage partial.
Partial runs retain positives but cannot publish missing facts or fresh complete-coverage evidence.

## Add another Device or partial Location

Suppose an external disk is mounted at `/media/sd01` and contains another ordinary copy or subset:

```bash
cd /media/sd01/documents
archive location init --collection "Documents" \
  --device "SD01" --site "Home" --non-interactive
archive location add . --collection "Documents"
```

One Device may have several Locations, and several Devices together may contain every Object. If a
removable filesystem is later mounted elsewhere, its UUID identifies the same Archive Root and
Device.

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

The importer reads the Git index, annex keys, object bytes, location logs, and `git-annex` branch.
It does not invoke mutating git-annex commands and verifies that HEAD and worktree status stay
unchanged. Every tracked annex path becomes a File reference. A dangling link remains an unresolved
external identity and is absent from that Location; readable content becomes a BLAKE3 Object and
verified present copy.

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
archive collection status "Documents"
archive location status "Documents on Main computer"
archive collection list
archive location list
archive file find --collection <documents-collection-id> --limit 100
archive file show <file-id>
archive copy list --location <main-location-id> --limit 100
```

File and copy lists use stable continuations, so directories with thousands of entries and
Collections with hundreds of thousands of Files remain reviewable without running the equivalent
of `ls` or loading the full result in memory.

Evaluate and review Policy and simulated loss results:

```bash
archive policy evaluate
archive report risk
archive report integrity
archive report policy
```

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

## Verify bytes and resume work

Adding or scanning content records the hashing read as baseline verification. Routine verification
re-reads current copy claims:

```bash
archive verify <main-location-id> \
  --path /srv/archive/documents \
  --fingerprint-status match

archive verify <main-location-id> \
  --path /srv/archive/documents \
  --copy <copy-claim-id> \
  --fingerprint-status match
```

Use `match` only after confirming the mounted filesystem is the registered Device. A mismatch
blocks reads. A hash mismatch marks that copy corrupt without redefining the expected Object; a
read error makes the claim non-qualifying until later successful verification.

Long operations print durable job IDs:

```bash
archive job list
archive job show <job-id>
archive job resume <job-id>
```

Resume applies canonical events first and uses deterministic outcomes, so interruption does not
duplicate durable facts. Operations are batched and do not require all paths in memory.

## Protect and recover the catalog

SQLite is the normal interactive materialized view, but it is replaceable. Canonical events are the
durable rebuild source, so protecting only `archive.db` is insufficient. Exact paths are printed by
`archive init --json`.

Record the registered Location physically containing the catalog, then configure a Git remote whose
registered storage and Site are independent:

```bash
archive catalog-location <catalog-location-id>

archive metadata-destination add \
  --name "Offsite catalog history" \
  --location <offsite-metadata-location-id> \
  --remote backup \
  --locator ssh://backup.example/archive-ledger.git

git -C <canonical-event-path> remote add \
  backup ssh://backup.example/archive-ledger.git

archive checkpoint --replicate
archive report metadata
```

“Protected through N” appears only after Archive Ledger observes the checkpoint at independent
topology. A Git repository on the same disk may receive events but is not counted as proven
independent protection. Keep credentials in Git, SSH, or credential-manager configuration—not in
locators or canonical events.

Verify history, update SQLite, rebuild a disposable projection, and rehearse recovery:

```bash
archive events verify
archive db apply
archive db rebuild --target /tmp/archive-rebuilt.db

git clone --branch archive-ledger \
  ssh://backup.example/archive-ledger.git restored-events
archive restore check restored-events \
  --rebuild-database restored-archive.db
```

`restore check` verifies the chain and builds a new database; it does not overwrite the current
catalog.

## Automation and exit status

- `0`: command completed and the selected check has no findings.
- `2`: invalid input, damaged state, I/O failure, or another command error.
- `10`: command completed but found preservation, integrity, stale-presence, metadata-protection,
  or partial-coverage concerns.

Exit `10` is an actionable finding, not a crash. Global `--json` provides versioned structured
results. Setup commands have explicit non-interactive flags:

```bash
archive --json status
archive --json report stale-presence --locations
archive --json file find --collection <documents-collection-id> --limit 100

archive collection init /srv/archive/documents \
  --name "Documents" --device "Main computer" --site "Home" \
  --non-interactive
```

Errors include stable codes. Review lists use deterministic ordering and continuation tokens that
fail closed if SQLite advances between pages.

## Safety and current scope

- `location add`, `location scan`, and git-annex import do not modify archive content.
- Generic traversal does not follow symlinks as ordinary files or cross filesystems.
- Device identity mismatch blocks scanning; unidentified roots remain visibly uncertain.
- Positive-only add and every partial scan are incapable of publishing missing facts.
- Complete missing activation is atomic and follows only confirmed complete coverage.
- Registry changes and renames append canonical events; history is not rewritten.
- Current commands do not copy, move, delete, drop, repair, or quarantine content.

Background scanning of connected Devices and content mutation such as `archive copy` are planned,
not current behavior. Continue using established tools such as git-annex for copy/drop operations,
then import or scan the resulting state.

The implementation has explicit 500,000-File and 500,000-Object scale gates. Discovery, hashing,
projection, and large result lists are bounded or paged. SQLite intentionally trades some storage
for low-latency indexed review; canonical history remains the recovery source.
