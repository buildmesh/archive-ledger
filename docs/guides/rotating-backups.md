# Rotate backup sets and maintain a carried USB backup

This workflow keeps primary files on the computer, rotates two sets of backup drives between
Home and Offsite, and uses a carried USB drive for new files that have not reached the offsite
set yet. It follows the `altest` walkthrough, including host-side copies and removals when
Archive Ledger sees the drives through read-only Docker mounts.

The routine is: **register primary files → update and register the home backup set → rotate
sets → clean and scan USB → copy and register unprotected files on USB → check status**.

## Names and starting arrangement

A backup set can be a partial mirror spread across several drives: each file needs to be on
at least one drive in that set. Paths are relative to the Collection root and must have the
same contents everywhere that path is present.

| Role | Devices | Starting Site | Site after this rotation |
| --- | --- | --- | --- |
| Primary | `disk10` | Home | Home |
| Set A, being updated | `sd`, `sd02`, `sd03` | Home | Offsite |
| Set B, previous offsite set | `sd2`, `sd22`, `sd23` | Offsite | Home |
| Carried temporary backup | `usb` | Sam | Sam |

Location names follow `<Collection> on <device>`, such as `altest on disk10` or `Files on usb`.
The commands below assume these Locations and Sites already exist and the right Archive is
selected. See [initial setup](archive-lifecycle.md) if needed. Each real drive should have
its own Device record; the walkthrough's separate virtual Devices simulate that arrangement
on one filesystem.

`device move` changes the recorded Site; it does not move, mount, unmount, or copy files.
Record the move when the physical move occurs. A Site called `Sam` represents the carried
USB drive, so update that Site assignment if its actual storage arrangement changes. Site
counts reflect the catalog assignments; they cannot establish physical separation themselves.

## Choose how to run the commands

Run these examples in Bash. Choose **one** setup block for your current session.

For the native `altest` walkthrough:

```bash
archive_cmd=(archive)
locations_root="$HOME/tmp/locations"
collection=altest
collection_dir=altest
```

For Collection `Files` in Docker, run from the Compose project directory:

```bash
archive_cmd=(docker compose run --rm -T archive)
locations_root=/locations
collection=Files
collection_dir=files
```

`"${archive_cmd[@]}"` below runs the selected CLI. Paths passed to that CLI use
`locations_root`. Run generated Bash scripts on the **host**, not in the container.

For the desktop layout, `.env` contains `ARCHIVE_LEDGER_LOCATIONS_DIR=/var/data`. The current
Compose configuration maps `/var/data` on the host to `/locations` in the container and passes
that mapping to the script generator. Native use needs no mapping. Explicit overrides are
`--host-root /var/data --locations-root /locations`. The host needs Bash, rsync, and b3sum
(for removals). See the [copy](../../README.md#generate-a-copy-script-for-the-host) and
[removal](../../README.md#generate-a-removal-script-for-a-temporary-backup) references for details.

## 1. Register new primary files

```bash
"${archive_cmd[@]}" collection add "$locations_root/disk10/annex/$collection_dir" \
  --collection "$collection"
```

This checks and records new files. It does not declare previously tracked files missing.
For multiple primary drives, repeat for each primary Location with new files, such as disk7
or disk9. Files are immutable by default: an unexpected checksum change is damage, not an
implicitly accepted edit.

## 2. Fill gaps in the home backup set

Copy files from disk10 that are not already on `sd` or `sd02` onto `sd03`:

```bash
"${archive_cmd[@]}" copy --host-script --collection "$collection" \
  --from "$collection on disk10" \
  --to "$collection on sd03" \
  --not --in "$collection on sd" --in "$collection on sd02" \
  > /tmp/copy-to-sd03.sh
```

Only proceed if generation succeeds. Review the full list, preview, then copy:

```bash
less /tmp/copy-to-sd03.sh
bash /tmp/copy-to-sd03.sh --dry-run
bash /tmp/copy-to-sd03.sh
```

The generator automatically excludes files recorded present at the destination Location.
The script also preserves existing destination files, including files not yet in the catalog.
It copies source symlink contents as regular files and preserves Collection-relative paths.
It does not overwrite an existing damaged file; repair is a separate operation.

After a successful copy, checksum and register the new destination files **before taking
this set offsite**:

```bash
"${archive_cmd[@]}" collection add "$locations_root/sd03/annex/$collection_dir" \
  --collection "$collection"
```

Repeat the generate/copy/register sequence for other primary Locations if needed. Copying
alone does not create backup evidence in the catalog.

## 3. Rotate the sets and record their Sites

Once Set A has been taken offsite and Set B brought home, record the moves:

```bash
"${archive_cmd[@]}" device move sd --to Offsite
"${archive_cmd[@]}" device move sd02 --to Offsite
"${archive_cmd[@]}" device move sd03 --to Offsite

"${archive_cmd[@]}" device move sd2 --to Home
"${archive_cmd[@]}" device move sd22 --to Home
"${archive_cmd[@]}" device move sd23 --to Home

"${archive_cmd[@]}" collection status "$collection"
```

The remainder of this cycle uses **sd, sd02, and sd03** as the offsite set. The queries name
Locations explicitly; they do not automatically discover Devices at the Site named Offsite.
Always change the named set when you rotate it.

## 4. Register files created since the rotation

Whenever you add more files to disk10, run:

```bash
"${archive_cmd[@]}" collection add "$locations_root/disk10/annex/$collection_dir" \
  --collection "$collection"
"${archive_cmd[@]}" collection status "$collection"
```

A new file may now have only one copy at one Site. The next steps clear space on USB and give
that file its temporary backup while the full backup set is away.

## 5. Remove USB files now protected by the offsite set

Select verified USB files with a matching verified copy on at least one current offsite drive,
checked within 30 days:

```bash
"${archive_cmd[@]}" file remove --host-script --collection "$collection" \
  --from "$collection on usb" \
  --in "$collection on sd" \
  --in "$collection on sd02" \
  --in "$collection on sd03" \
  --verified-within 30d \
  > /tmp/remove-from-usb.sh
```

Generation reads the catalog only. Each named backup must belong to a different Device from
USB. Offsite drives do not need to be mounted: recent recorded checksum evidence is accepted.
Stale, missing, damaged, or unresolved backups do not justify cleanup. If needed, refresh
backup verification while those drives are available; do not treat stale evidence as a new check.

Review and preview the script, then explicitly request deletion:

```bash
less /tmp/remove-from-usb.sh
bash /tmp/remove-from-usb.sh --dry-run
bash /tmp/remove-from-usb.sh --delete
```

With no argument, a removal script only previews. With `--delete`, it checks each selected
USB file's current BLAKE3 before removal and refuses changed contents. A saved script expires
when its backup evidence becomes too old. It rejects directories and directory symlinks;
a final symlink to a regular file is unlinked without deleting its target. Run while no other
program is changing the target tree. Errors stop execution, so some earlier files may already
have been removed.

**After any deletion run, including a partial or failed run, reconcile USB:**

```bash
"${archive_cmd[@]}" location scan "$collection on usb" --collection "$collection"
```

The scan records what is actually missing. Missing rows are expected after cleanup; they are
not present copies. This step prevents the next copy query from relying on old USB presence.
`collection add` alone does not record deletions. `file removed` is a separate catalog-only
declaration, not the command that deletes files.

## 6. Copy files without offsite backups onto USB

```bash
"${archive_cmd[@]}" copy --host-script --collection "$collection" \
  --from "$collection on disk10" \
  --to "$collection on usb" \
  --not --in "$collection on sd" \
        --in "$collection on sd02" \
        --in "$collection on sd03" \
  > /tmp/copy-to-usb.sh
```

After successful generation, review and run it on the host:

```bash
less /tmp/copy-to-usb.sh
bash /tmp/copy-to-usb.sh --dry-run
bash /tmp/copy-to-usb.sh
```

Repeated `--in` values form one OR group. `--not` means the file must be absent from **all**
qualifying Locations in that group. The source is required implicitly by `--from`, and files
already recorded present on USB are excluded automatically.

As in the tested workflow, this copy query accepts matching verified offsite evidence of any
age. To also put files with stale offsite evidence onto USB, add `--verified-within 30d` after
the offsite `--in` group. The cleanup query above always uses its explicit 30-day window.

Register and verify the new USB copies, then inspect protection:

```bash
"${archive_cmd[@]}" collection add "$locations_root/usb/annex/$collection_dir" \
  --collection "$collection"
"${archive_cmd[@]}" collection status "$collection"
"${archive_cmd[@]}" location show "$collection on usb"
```

If USB is at Site Sam and every remaining file has either an offsite copy or a USB copy, the
Collection should again show all files at two known Sites. Inspect the recently verified counts
as well as present-copy counts. A copy count counts Locations, not necessarily independent
Devices; accurate Device and Site assignments matter. The status summary is cached evidence,
not a fresh read of every drive or a full backup-policy evaluation.

## Repeat with the other set next time

On the next rotation, Set B is the home set. Fill `sd23` from each primary Location while
excluding `sd2` and `sd22`; register the copies. Then move `sd2`, `sd22`, and `sd23` to Offsite,
and move `sd`, `sd02`, and `sd03` to Home. Use **sd2, sd22, and sd23** in both USB queries for
that cycle. USB stays at its actual Site; it is not part of the rotating sets.

Keep a separate current backup of the SQLite catalog as well; the procedure is in
[catalog backup and restore](archive-lifecycle.md#7-back-up-and-rehearse-restoring-the-catalog).
Backing up the catalog does not back up file contents, and generating or running a host script
does not update the catalog by itself.
