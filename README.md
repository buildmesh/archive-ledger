# Archive Ledger

Archive Ledger is a local-first command-line catalog for answering three practical questions:

- Where are my files and copies?
- Are those copies still readable and recent enough to trust?
- Which files could be permanently lost if a disk, site, account, or other shared dependency fails?

It inventories ordinary directories and git-annex repositories, verifies file content, evaluates
backup policy and disaster risks, and protects its own catalog history. It does **not** copy, move,
delete, repair, or drop archive content.

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
