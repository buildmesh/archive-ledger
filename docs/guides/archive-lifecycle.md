# From first Archive to routine maintenance

An Archive is a local SQLite catalog of expected file contents, Locations, and check history.
It does not contain your files. This guide creates a Collection, checks its files, makes a backup,
and backs up the catalog itself.

The examples use documents in `~/Documents`, a backup disk at `/media/backup-disk`, and separate
storage for catalog backups at `/media/offsite-disk`. Replace these paths and names with your own.
Every `bash` block runs in order against disposable fixtures in `scripts/test-lifecycle-guide.py`.
The `text` examples are not run by that script.

## 1. Create an Archive

Creating an Archive does not scan files or require Git. The first Archive becomes the default.

```bash
archive init "Personal archive" --non-interactive
```

## 2. Register and check your primary files

A Collection identifies files by their relative paths. The first successful checksum establishes
each path's expected contents. A Location identifies where those paths are stored.

```bash
cd ~/Documents
archive collection init --name "Documents" --location-name "Primary documents" \
  --device "Main computer" --site "Home" --non-interactive
archive collection add . --collection "Documents"
```

Setup records filesystem identity where available. If it cannot identify the filesystem, review
that limitation before explicitly allowing `--allow-unidentified-root`. The disposable test runner
uses that option because its temporary directories have no stable disk identity.

For annex repositories, `collection init --import-annex` imports logical worktree paths.
`--inventory-only` defers checksumming: unknown contents do not qualify as verified backups.
A later `location scan` checks local bytes against annex keys before establishing expected contents.

## 3. Register a backup Location and copy files

The backup Location uses the same Collection-relative paths as the primary Location. Equal bytes
under a different path do not count as a backup of the original path.

```bash
mkdir -p /media/backup-disk/Documents
archive location init /media/backup-disk/Documents --collection "Documents" \
  --location-name "Backup documents" --device "Backup disk" --site "Office" --non-interactive
cd ~/Documents
archive copy --from "Primary documents" --to "Backup documents" --collection "Documents" --dry-run
archive copy --from "Primary documents" --to "Backup documents" --collection "Documents" --yes
```

Copy verifies bytes and preserves existing destination files. A conflicting destination produces an
error; it is not overwritten. If files were copied with another program, scan their Location to
record and verify them:

```bash
archive location scan "Backup documents" --collection "Documents"
```

For Locations mounted read-only into a container, use the listing commands below and perform
copies outside the container. Scan afterward to record the resulting evidence.

## 4. Find files missing from the backup set

Human output lists every matching path, one per line. `--json` returns a bounded page with Object
IDs and a continuation token; `--print0` emits lossless NUL-separated paths for scripts.

```bash
archive file find --collection "Documents" --in "Primary documents" \
  --and --not --in "Backup documents" --verified-within 30d
```

Repeated `--in` values within a group mean “any of these Locations.” `--and` starts another group,
and `--not` excludes its matches. For several backup disks:

```text
archive file find --collection Files --in "Files on disk10" \
  --and --not --in "Files on sd" --in "Files on sd02" --in "Files on sd03" \
  --verified-within 30d
```

The age condition applies to its group. This example accepts a successful backup checksum within
30 days; it does not reread the backup drives. Damaged, missing, or unresolved copies do not qualify.
Use `file show <object-id>` for current Location evidence and `file history <object-id>` for checks
and changes. Obtain IDs with `file find --json`.

## 5. Keep current state and verification evidence up to date

`collection add` checks files under the selected directory without declaring other paths missing.
`location scan` checks an entire Location; only a completed scan with adequate coverage can mark
unseen paths missing. Both preserve the expected checksum when bytes differ, recording damage.

```bash
cd ~/Documents
printf '%s\n' "New notes" > notes-2026.txt
archive collection add . --collection "Documents"
archive location scan "Primary documents" --collection "Documents"
archive verify "Backup documents" --all
archive job list
```

Without `--all`, verification selects copies due for another check. `job resume <job-id>` continues
interrupted work; mounting a different disk at the old path is not permission to resume against it.

To accept an intentional edit, explicitly name the changed path:

```text
archive collection add . --collection Documents --accept-changes notes-2026.txt --dry-run
archive collection add . --collection Documents --accept-changes notes-2026.txt --yes
```

Acceptance changes that Object's expected checksum and invalidates previous backup verification.
It does not change any backup bytes. A checksum mismatch is otherwise reported as damage and exits
with code 10.

## 6. Preview catalog removal without deleting files

`file removed` records that a copy has been removed. It never deletes filesystem contents.
Preview the exact affected paths first:

```bash
archive file removed --collection "Documents" --location "Primary documents" \
  --path letter.txt --dry-run
```

After deliberately removing a real copy outside Archive Ledger, use the same command without
`--dry-run` to update the catalog. A later successful checksum is required before a rediscovered
copy qualifies as verified again.

For a temporary USB backup, select paths that also have a recent verified copy in the backup set:

```text
archive file find --collection Files --in "Files on usb" --and \
  --in "Files on sd" --in "Files on sd02" --in "Files on sd03" --verified-within 30d
```

Listing these paths does not delete them. Filesystem deletion and any subsequent catalog update
remain explicit operations.

## 7. Back up and rehearse restoring the catalog

The catalog is user data too. Use `backup` to create a consistent standalone SQLite backup on
independent storage. Choose a new destination filename for each backup; existing files are preserved.

```bash
archive backup --to /media/offsite-disk/personal-catalog.db
archive restore catalog /media/offsite-disk/personal-catalog.db --to ~/restored-personal-catalog.db
archive status
```

Restore validates the backup and creates a new database file. It does not replace or activate your
current catalog. Keep a recent catalog backup after recording new files, checks, or removals.
Catalog backup protects the index and history; file contents still need their own verified copies.
