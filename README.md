# Archive Ledger

Archive Ledger is a local-first command-line catalog for answering three practical questions:

- Where are my files and copies?
- Are those copies still readable and recent enough to trust?
- Which files could be permanently lost if a disk, site, account, or other shared dependency fails?

It inventories ordinary directories and git-annex repositories, verifies file content, evaluates
backup policy and disaster risks, and protects its own catalog history. It does **not** copy, move,
delete, repair, or drop archive content.

## Concepts and relationships

An **archive** is the complete catalog managed by one Archive Ledger installation. It is not one
directory or storage device: one archive can describe many collections spread across computers,
removable disks, NAS devices, offline media, and storage services. The archive has one stable ID,
one canonical event history, and a replaceable SQLite view used for interactive commands.

The main relationships are:

```text
Archive
├── Collection ──uses──> Policy
│   ├── has a home Site
│   └── contains File references ──refer to──> Objects or External identities
│                            │                          │
│                            └── Path observations      ├── External identity resolves to Object
│                                      │               └── Copy claims
│                                      └──────────────────at a Location
├── Filesystem Location ──under──> Archive root ──on──> Device ──at──> Site
├── Service Location ────────────────────────────────────────────────at──> Site
├── Risk domains ──attach to──> Locations, roots, devices, or sites
└── Canonical events ──materialize into──> SQLite database
```

### Content and file concepts

- A **collection** is a logical group of files, such as “Family photos” or “Scanned documents.”
  Each collection has its own logical path namespace, one home site, and one preservation policy.
  The same storage location may contain files from more than one collection.
- A **file** in CLI output means a **file reference**: a logical path within a collection, such as
  `2025/trip/photo.jpg` in the “Family photos” collection. Renaming a file changes its logical
  reference; it does not change the bytes themselves.
- An **object** is one exact byte sequence identified by its BLAKE3 hash. Two logical files with
  identical bytes can refer to the same object. Archive Ledger creates an object identity only
  after it has successfully read the bytes.
- An **external identity** is a source-system identifier known before bytes are readable, such as a
  git-annex key. It lets a dropped annex file remain in the inventory, but it is not verified
  protection until readable bytes resolve it to an object.
- A **path observation** records that a logical file was seen at a particular path and location.
  It describes names and representations, including supported git-annex representations.
- A **copy claim** records the catalog's current evidence that content bytes exist at a path in a
  location. It refers to an object, or initially to an external identity, and can be present,
  missing, corrupt, unknown, or superseded. A source saying that a remote has an annex key is a
  recovery lead, not automatically a verified copy claim.

This separation is intentional: a filename answers “what does the user call this?”, an object hash
answers “which bytes are these?”, and a copy claim answers “where does the catalog currently
believe those bytes exist?”

### Storage topology

- A **site** is a place whose loss matters, such as a home, office, storage unit, or cloud region.
- A **device** is a physical or virtual storage-bearing unit, such as an SSD, removable disk, or
  NAS volume. Its identity should come from a filesystem UUID or another stable fingerprint, not
  from a temporary mount path.
- An **archive root** is a stable path on a device's filesystem beneath which Archive Ledger
  locations are registered.
- A **location** is the storage area where copy claims live. A filesystem location belongs to an
  archive root and device; a device-less service location belongs directly to a site.

For example, `/media/backup/photos` and `/media/backup/photos-copy` are two paths and may produce
two copy claims, but if both are on the same disk they do not provide two-device protection. A copy
on a second disk at another site can provide independent protection once its identity, observation,
verification, and other policy requirements are current.

### Protection and risk concepts

- A **policy** defines what counts as adequate protection for a collection: required qualifying
  copies, devices and sites, freshness limits, and optional offsite, offline, or encrypted-offsite
  requirements. Trust and topology classification are also considered when a copy is evaluated.
- A **qualifying copy** is a present copy claim with resolved byte identity, a successful recent
  verification, current observation and device evidence, and active, sufficiently classified
  topology. Visible but stale, unresolved, corrupt, or uncertain claims do not count as proven
  protection.
- A **risk domain** represents a shared failure that topology alone may not reveal, such as one
  cloud account, chassis, power circuit, credential store, flood zone, or safe. Device, service,
  and site loss are evaluated automatically; custom domains add shared dependencies.
- A **scan** inventories one filesystem location for one collection. It discovers paths, hashes new
  or changed files, and records coverage without modifying archive content. A git-annex **import**
  performs the equivalent source-aware inventory from Git and annex metadata.
- A **verification** re-reads a specific copy's bytes and compares them with the expected identity.
  A mismatch affects that copy claim; it does not silently redefine the object.

As a concrete example, the logical path `2025/trip/photo.jpg` in the “Family photos” collection may
resolve to one BLAKE3 object and have two copy claims: one in a home SSD location and one in an
offsite NAS location. The collection's policy determines whether those claims are sufficiently
fresh and independent. Losing either device or site is then simulated against the remaining
qualifying copy.

### Catalog storage

**Canonical events** are the durable, append-only history of observations and configuration
changes. The **SQLite database** is their indexed materialized view and serves normal `status`,
`file`, `copy`, and `report` commands without rescanning disks or replaying event files. SQLite can
be rebuilt; the canonical event repository must be checkpointed and independently protected.

## Install

Archive Ledger currently builds from source and requires Rust and Git. Git-annex is useful for
creating and managing annex repositories, but the importer itself uses read-only Git metadata.

```bash
cd /path/to/archive-ledger
cargo build --release
mkdir -p "$HOME/.local/bin"
install -m 0755 target/release/archive "$HOME/.local/bin/archive"
archive --version
```

Run commands from the directory where you want the catalog, or pass explicit global paths:

```bash
archive --database /path/to/archive.db \
        --events /path/to/canonical-events \
        status
```

The defaults are `.archive-ledger/archive.db` and `.archive-ledger/canonical` in the current
directory.

## Quick start

On a terminal, `archive init` prompts for a mounted archive path and creates a starter home site,
device, root, location, collection, and two-site backup policy. For scripts, use the equivalent
non-interactive form:

```bash
archive init --non-interactive \
  --root-path /mnt/archive \
  --fingerprint 0123-4567 \
  --fingerprint-kind filesystem_uuid
```

If the storage has no stable identifier you can omit the fingerprint. Archive Ledger keeps that
uncertainty visible instead of treating the mount path as device identity. `archive device discover
/mnt/archive` shows safe discovery information, but its host-local device number is not presented as
a durable fingerprint.

The starter IDs are printed by `init`. With their defaults, inventory the files without modifying
them:

```bash
archive scan location_primary \
  --collection collection_primary \
  --path /mnt/archive \
  --device device_primary \
  --root root_primary
```

Scan and verification commands default device fingerprint status to `unavailable`. After checking
that the mounted storage's real identifier matches the registered fingerprint, add
`--fingerprint-status match`; pass `mismatch` when it does not. Archive Ledger will record the
check and refuse a mismatched scan instead of trusting the path.

Review the result from SQLite; these commands do not need the event directory to be online:

```bash
archive status
archive file find --collection collection_primary --limit 100
archive file show <file-id>
archive copy list --location location_primary --limit 100
archive report risk
archive report integrity
archive report policy
```

Lists are read from the indexed database rather than by enumerating large directories. Use the
printed `--continue` token to page through hundreds of thousands of records without rescanning
storage.

## Add another copy location

The starter policy deliberately reports risk until it sees two current, verified copies on two
devices at two sites. Register the actual topology of another copy before scanning it:

```bash
archive site add \
  --id site_offsite --name "Offsite" --kind office

archive device add \
  --id device_offsite --name "Offsite disk" --kind disk \
  --site site_offsite \
  --fingerprint A1B2-C3D4 --fingerprint-kind filesystem_uuid \
  --availability offline

archive root add \
  --id root_offsite --name "Offsite archive root" --kind filesystem \
  --device device_offsite --path /

archive location add \
  --id location_offsite --name "Offsite files" --kind filesystem \
  --root root_offsite --device device_offsite --path ""

archive scan location_offsite \
  --collection collection_primary \
  --path /media/offsite/archive \
  --device device_offsite \
  --root root_offsite

archive policy evaluate
archive report risk
```

Use `archive risk-domain add` and `archive risk-domain assign` for dependencies the structural
topology cannot infer—for example, two services in one account or disks stored in the same safe.
Loss reports simulate each registered device, site, service account, and custom shared domain.

## Verify content

A scan hashes new or changed regular files and records that read as baseline verification. Routine
verification re-reads current copy claims in bounded batches:

```bash
archive verify location_primary --path /mnt/archive
archive verify location_primary --path /mnt/archive --copy <copy-claim-id>
```

Every attempt is durable. A mismatch marks only that copy corrupt; a read error or device identity
failure makes it non-qualifying until a later successful verification. Archive Ledger never repairs
or replaces the bytes automatically.

Long-running scans, imports, and verification jobs print a durable job ID:

```bash
archive job list
archive job show <job-id>
archive job resume <job-id>
```

Resume applies the canonical event tail first and skips already-recorded per-file outcomes, so an
interruption cannot duplicate durable facts.

## Import a git-annex repository

Register two locations on the annex device: one for the worktree representation and one for the
annex object store. Then run this from inside the repository:

```bash
archive import annex . \
  --collection collection_primary \
  --worktree-location location_annex_worktree \
  --cas-location location_annex_cas \
  --device device_primary \
  --root root_primary
```

The importer reads the Git index, annex keys, object bytes, and the `git-annex` branch. It does not
run mutating git-annex commands or change the source repository. Present, dropped, unsupported,
mismatched, unreadable, and duplicate entries are reported separately. Dropped files remain
reviewable even when no local bytes exist.

See remote UUIDs observed in annex location logs and map a remote to a registered location:

```bash
archive annex-remote list --all
archive annex-remote map <source-annex-uuid> <remote-annex-uuid> <location-id> \
  --name "Offsite annex"
archive annex-remote unmap <source-annex-uuid> <remote-annex-uuid>
```

A remote availability claim is useful evidence but does not become a verified copy merely because
it is mapped.

## Protect the catalog

The SQLite database is a replaceable materialized view. The canonical event repository is the
durable history needed to rebuild it, so protecting only `archive.db` is not sufficient.

First register the location that physically contains the catalog if guided setup did not do so:

```bash
archive catalog-location <location-id>
```

Register a Git destination whose location has honest device/site/risk topology, add the Git remote,
then checkpoint and replicate:

```bash
archive metadata-destination add \
  --id metadata_offsite \
  --name "Offsite catalog history" \
  --location <registered-location-id> \
  --remote backup \
  --locator ssh://backup.example/archive-ledger.git

git -C .archive-ledger/canonical remote add \
  backup ssh://backup.example/archive-ledger.git

archive checkpoint --replicate
archive report metadata
```

“Protected through N” appears only after Archive Ledger observes the checkpoint at a destination
whose storage and site are independent of the catalog. A second directory or bare Git repository
on the catalog disk may be replicated successfully, but it is intentionally reported as
independence `unknown`.

Credentials belong in Git/SSH credential configuration, never in destination locators or canonical
events.

## Integrity and recovery

Verify the canonical chain and bring SQLite up to date:

```bash
archive events verify
archive db apply
```

Rebuild a replacement database from canonical history:

```bash
archive db rebuild --target /tmp/archive-rebuilt.db
```

To rehearse clean-machine recovery, clone an independently protected event repository and rebuild a
new database from it:

```bash
git clone --branch archive-ledger \
  ssh://backup.example/archive-ledger.git restored-events

archive restore check restored-events \
  --rebuild-database restored-archive.db
```

`restore check` verifies the event chain, streams a fresh SQLite projection, and confirms that the
rebuilt cursor matches the verified event tail. It does not overwrite the current database.

## Exit status and automation

- `0`: command completed and the selected check has no findings.
- `2`: invalid input, damaged state, I/O failure, or another command error.
- `10`: the command completed but found preservation, integrity, metadata-protection, or partial
  coverage concerns.

Exit `10` is expected while an archive is under-protected; it is not the same as a command failure.
Use global `--json` for versioned structured output and stable error codes:

```bash
archive --json report risk --limit 100
archive --json status
```

## Safety model

- Scans and git-annex imports are read-only and do not follow symlinks as ordinary content.
- Scans stay on the selected filesystem and record exclusions and traversal uncertainty.
- A known device fingerprint mismatch blocks a scan and causes verification to avoid reading bytes.
- Partial scans never infer that unseen files are missing.
- Registry corrections append new facts; canonical history is not rewritten.
- No current command deletes, drops, copies, repairs, or quarantines archive content.

For large archives, discovery and hashing stream in bounded batches, projection applies only the
unapplied event tail, and normal file/copy/risk review is served from indexed SQLite state. The
project includes explicit 500,000-file scale gates; routine test runs leave those expensive tests
ignored unless requested.
