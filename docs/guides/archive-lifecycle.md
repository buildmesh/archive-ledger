# From first Archive to routine maintenance

This guide walks through the normal life of an Archive in order: create it, add files, protect the
catalog itself, add a second copy somewhere else, review Policy, keep the catalog current, and
maintain it over time. Each step links to the [README](../../README.md) section with the details
instead of repeating them.

The examples use one Collection of documents in `~/Documents` on the main computer, a backup disk
mounted at `/media/backup-disk`, and a second disk kept at another site and mounted at
`/media/offsite-disk`. Replace names and paths with your own.

Every `bash` block in this guide is run in order against a disposable Archive by
`scripts/test-lifecycle-guide.py`. `text` blocks are illustrations that the script does not run.

## 1. Create the Archive

An Archive is the catalog. Creating it does not look at any files.

```bash
archive init "Personal archive"
```

The first Archive becomes the default. For several Archives, see
[Create an Archive and first Collection](../../README.md#create-an-archive-and-first-collection).
The command also warns that the new catalog history is not yet on a sync remote. Step 3 deals
with that.

## 2. Create a Collection and inventory its files

A Collection is the logical set of files you care about. Create it from its root directory, then
add the files. Adding reads and hashes every file, which records a verified first copy.

```bash
cd ~/Documents
archive collection init --name "Documents" \
  --device "Main computer" --site "Home" --non-interactive
archive collection add . --collection "Documents"
```

Without `--non-interactive`, setup asks for the Device and Site only when it cannot infer them.
If the filesystem has no stable identity, setup stops. Read
[Create an Archive and first Collection](../../README.md#create-an-archive-and-first-collection)
before using `--allow-unidentified-root`.

For a git-annex repository, use `archive collection init --import-annex` instead. For a very large
repository, use `--inventory-only` followed by a `location scan`. See
[Import git-annex repositories](../../README.md#import-git-annex-repositories) and the
[annex workflows guide](annex-workflows.md).

## 3. Protect the catalog itself

The catalog history lives in a Git repository inside the Archive directory, on the main computer's
disk. Every change is committed there, but a local Git commit is not a backup. If that disk fails,
the catalog is gone together with the knowledge of where every copy is. Make independent protection
of the catalog part of setup, not an afterthought.

Give the Archive a sync remote on storage that fails independently of the main computer, then
synchronize. Here the remote is a bare Git repository on the offsite disk:

```bash
git init --bare /media/offsite-disk/personal-archive.git
archive sync remote add offsite /media/offsite-disk/personal-archive.git
archive sync
archive status
```

An SSH remote works the same way:

```text
archive sync remote add offsite ssh://backup.example/personal-archive.git
```

Until the history has reached a sync remote, `archive status` and every command that changes the
catalog print one warning line with the next step:

```text
WARNING: 3 catalog commits are not yet on a sync remote; a local Git commit is not a backup. Next: archive sync
```

The warning stops once the history is on a configured remote. Archive Ledger does not yet check
whether that remote is on a different device and site; that is your responsibility. See
[Protect and recover the catalog](../../README.md#protect-and-recover-the-catalog) for supported
remotes, other installations, and recovery.

## 4. Add a second Location on another Device

A Location is one place where a Collection's files are stored. Register an empty directory on the
backup disk as another Location, then copy verified files to it from the main Location:

```bash
mkdir -p /media/backup-disk/Documents
cd /media/backup-disk/Documents
archive location init --collection "Documents" \
  --device "Backup disk" --site "Office" --non-interactive
cd ~/Documents
archive copy --to "Documents on Backup disk" --yes --non-interactive
```

Copy checks each file against its recorded hash while writing and reads the result back. It never
overwrites or deletes files. To register a disk that already holds copies, run
`archive collection add .` from that Location instead of copying. See
[Make a verified copy at another Location](../../README.md#make-a-verified-copy-at-another-location)
and [Add another Device or partial Location](../../README.md#add-another-device-or-partial-location).

## 5. Review Policy and risk

Each Collection has a Policy: how many qualifying copies it needs, on how many Devices and Sites,
and how old verification, presence, and Device check-in evidence may be. The starter Policy asks
for two copies on two Devices at two Sites, including one offsite, with evidence no older than 365
days. Review it and change only what should differ:

```bash
archive policy list
archive policy show "Two copies at two sites"
archive policy update "Two copies at two sites" --verification-days 180
archive report policy
archive report risk
```

Expect findings at first. A copy counts toward Policy only when its Device has confirmed identity.
Setup records the filesystem's identity, which is not the physical Device. Until you record
hardware evidence for each Device, reports list its copies as not qualifying:

```text
archive device identity "Backup disk" --kind serial --fingerprint '<disk serial number>'
```

See [Create an Archive and first Collection](../../README.md#create-an-archive-and-first-collection)
for which evidence to use. A Device's Site is where it is normally kept. Once both Devices are
confirmed, a backup disk kept at the Office provides the second Site. Record shared failure causes
that topology cannot show, such as two disks in one safe, as risk domains. See
[Review status, integrity, and disaster risk](../../README.md#review-status-integrity-and-disaster-risk).

## 6. Keep the catalog current

Use the two scan commands for different jobs:

- `archive collection add .` records new and changed files under the current directory. It only
  adds; it never marks anything missing. Use it after putting new files in place.
- `archive location scan` reconciles a whole Location, so a complete run can also mark files that
  are gone as missing, and it refreshes presence for everything it saw.

Both read only new and changed files. Files whose size and modification time are unchanged are
not read again. Re-reading their bytes is the job of `verify` (step 7), so routine scans stay fast.

```bash
cd ~/Documents
echo "New notes" > notes-2026.txt
archive collection add . --collection "Documents"
archive location scan
```

Cataloged content is immutable by default. If a known file's bytes change, add and scan report
"content differs from catalog", mark that copy corrupt, and exit with code 10. They do not accept
the edit silently. To accept an intentional edit, use `--accept-changes` as described in
[Add files and reconcile a Location](../../README.md#add-files-and-reconcile-a-location).

Long scans show progress on a terminal and print a job ID first. If a scan is interrupted, list
the unfinished jobs and resume or cancel:

```bash
archive job list
```

```text
archive job resume <job-id>
archive job cancel <job-id> --dry-run
archive job cancel <job-id>
```

While a Location has an unfinished scan, a new `location scan` of it is refused and names that job,
so progress is never discarded silently. See
[Verify bytes and resume work](../../README.md#verify-bytes-and-resume-work).

Currently no command lists files in a directory that the Collection does not track. Scan and add
have no dry run yet. Do not use a command that changes the catalog just to find out.

## 7. Routine maintenance

Start with the summary views. They read the local SQLite catalog and do not touch storage:

```bash
archive status
archive report risk
archive report integrity
archive report stale-presence --locations
```

`status` also points at unfinished jobs. `report stale-presence` says which Device to mount and
refresh next.

Re-read bytes to catch silent corruption. `verify` reads only the copies that are due: never
verified, failed their last check, or past their Policy's age or within 30 days of it. It starts
with the least recently verified. Without a Location it covers every connected Location whose
identity is confirmed as matching, and `--all` re-reads everything. Use `--fingerprint-status match` only after confirming that the
mounted disk is the registered Device:

```bash
archive verify "Documents on Backup disk" --path /media/backup-disk/Documents \
  --fingerprint-status match
```

For bounded, unattended checking of stale copies on connected Devices, enable the one-shot
background runner and call it from your scheduler:

```bash
archive background enable --max-items 100
archive background run
```

```text
# crontab: every night at 02:30, at low CPU and I/O priority
30 2 * * * nice -n 19 ionice -c3 archive background run
```

When a Policy report shows under-replicated Files, make another verified copy (step 4).
`report integrity` lists corrupt copies. Archive Ledger does not repair them yet, and `copy`
never overwrites an existing file, so it cannot replace one. Check the catalog's own consistency
occasionally:

```bash
archive fsck
```

## 8. Keep catalog protection current

Every catalog change creates new local history. Synchronize after a session of changes, or
routinely from your scheduler, and confirm that the warning is gone:

```bash
archive sync
archive status
```

`archive status --json` reports the same information as `catalog_protection`, with the number of
local commits not yet on a sync remote.
