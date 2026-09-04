# Example workflows

These examples start with a user goal and show one safe path through the CLI. They supplement the
command-oriented [README](../README.md); the README remains the detailed reference for setup,
verification, synchronization, and recovery.

Available workflows:

- [Check files on another laptop without copying them first](#check-files-on-another-laptop-without-copying-them-first)

## Check files on another laptop without copying them first

Suppose a laptop contains many files that probably already exist in a Collection whose archived
Location is a git-annex repository on the main computer. Copying every file to the main computer
merely to check would be slow. Instead, copy or clone the much smaller Archive metadata to the
laptop and run a read-only Stage audit there.

### 1. Prepare current metadata on the main computer

If the result might be used to decide whether the laptop copies can be removed, first verify the
registered annex Location and review risk. Use `match` only after confirming that the mounted
filesystem is the registered Device.

```bash
archive verify <annex-location-id> \
  --path /srv/archive/photos \
  --fingerprint-status match
archive report risk
```

Synchronize canonical metadata, then create a portable SQLite snapshot on transfer storage:

```bash
archive sync
archive snapshot create /media/transfer/personal-snapshot
```

The snapshot is an acceleration cache, not the durable Archive. Do not substitute a raw copy of
`archive.db`: it may be stale or copied during a transaction, and it has no canonical history from
which to verify or rebuild itself. Do not copy the entire Archive directory either, because its
`local/` directory contains the main installation's private client identity.

### 2. Clone the metadata on the laptop

Clone the canonical Git history and use the transferred snapshot to avoid a full replay:

```bash
archive sync clone ssh://backup.example/personal-archive.git \
  --snapshot /media/transfer/personal-snapshot
```

The remote carries catalog metadata, not the annex content bytes. It may be an SSH Git remote, a
local bare repository on the transfer drive, or another Git locator. Clone validates the snapshot
against the Archive identity, signature, database checksum, canonical commit, frontier, schema,
and projector version before installing it. If validation fails, it rebuilds SQLite from the
cloned canonical history instead.

The laptop does not need to enroll as a writing client for this audit. Enrollment is required
before it appends Archive events, not for read-only Stage.

### 3. Stage the laptop files

Run Stage against the cloned Archive:

```bash
archive --archive "Personal archive" stage "$HOME/Pictures" \
  --collection "Photos"
```

Stage reads each stable regular file, computes its BLAKE3 identity, and compares it with active
Files in every Collection. It does not read annex content across the network and does not append
catalog events. It normally writes reusable checksums to
`$HOME/Pictures/.archive-ledger-stage/manifest.sqlite3` so a later run can avoid rehashing unchanged
files.

Interpret the result as follows:

- **Already cataloged** means the exact bytes have an active BLAKE3 Object match in the Archive.
- **New to this Archive** means no such match existed at the cloned metadata frontier.
- **Source removal readiness: READY** additionally requires a complete audit and sufficient
  current qualifying copies for every owning Collection Policy.

An annex entry imported while its bytes were dropped or otherwise unreadable may exist only as an
unresolved external identity. Because it has no BLAKE3 Object yet, Stage cannot prove that a
laptop file is the same content and may report it as new. Make those annex bytes readable, scan or
verify the annex Location, synchronize again, and rerun Stage before treating that result as a
true absence.

Finally, “already cataloged” alone does not prove that an annex copy is currently readable. Keep
the laptop source unless the annex Location has recent successful verification, the relevant
Policies are satisfied, and the final complete Stage run reports source-removal readiness.
