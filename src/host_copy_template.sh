#!/usr/bin/env bash
# Archive Ledger host copy script. Requires Bash and rsync.
# Review the roots and file list below, then run:
#   bash copy.sh --dry-run   # Preview without copying.
#   bash copy.sh             # Copy the selected files.
# Source symlinks are followed to copy their contents. Existing destination
# files are skipped, not verified or overwritten. Nothing is deleted.
# Selection uses cached catalog evidence; after copying, checksum and register
# the destination with: archive collection add /path/to/destination
set -euo pipefail

# 1. Accept only the optional preview flag.
rsync_options=()
if (( $# > 1 )); then
  printf 'Usage: bash copy.sh [--dry-run]\n' >&2
  exit 2
fi
case "${1-}" in
  '') ;;
  --dry-run) rsync_options+=(--dry-run) ;;
  *) printf 'Usage: bash copy.sh [--dry-run]\n' >&2; exit 2 ;;
esac

# 2. Source and destination directories (safely quoted by the generator).
# ARCHIVE_LEDGER_ROOTS
for root in "$source_root" "$destination_root"; do
  if [[ ! -d "$root" ]]; then
    printf 'Directory is unavailable: %s\n' "$root" >&2
    exit 1
  fi
done
if [[ "$source_root" -ef "$destination_root" ]]; then
  printf 'Source and destination are the same directory.\n' >&2
  exit 1
fi

# 3. The complete file list, relative to the source and destination roots.
# Each data line below names one file. Spaces, quotes, $, and backticks are literal.
# Escapes: \\ = backslash, \n = newline, \r = carriage return, \t = tab.
# Other non-ASCII/control bytes use \0ooo (three octal digits).
# A filename matching the end marker has its first letter escaped as \0101.
# The quoted heredoc prevents shell expansion. printf decodes only these escapes;
# filenames are never evaluated as commands. The temporary list is NUL-separated
# for rsync, so filenames containing newlines remain a single entry.
manifest=$(mktemp)
trap 'rm -f -- "$manifest"' EXIT
while IFS= read -r encoded_path; do
  printf '%b\0' "$encoded_path"
done > "$manifest" <<'ARCHIVE_LEDGER_PATHS'
# ARCHIVE_LEDGER_MANIFEST
ARCHIVE_LEDGER_PATHS

# 4. rsync can follow pre-existing destination directory symlinks. Refuse them
# before copying any files; preserve the symlinks and anything outside the root.
while IFS= read -r -d '' relative; do
  while [[ "$relative" == */* ]]; do
    relative=${relative%/*}
    if [[ -L "$destination_root/$relative" ]]; then
      printf 'Refusing destination directory symlink: %s\n' "$destination_root/$relative" >&2
      exit 1
    fi
  done
done < "$manifest"

# 5. Copy only the listed paths, preserving metadata and following source links.
# --ignore-existing preserves destination files; --from0 reads exact path bytes.
rsync -aL --from0 --files-from="$manifest" \
  --ignore-existing --itemize-changes "${rsync_options[@]}" \
  -- "$source_root/" "$destination_root/"
