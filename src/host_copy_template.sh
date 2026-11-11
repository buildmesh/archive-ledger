#!/usr/bin/env bash
# Generated from catalog evidence. Requires Bash, rsync and GNU base64.
# Run with --dry-run to preview. Existing destinations are skipped, not verified.
# After copying, run archive collection add for the destination Location.
set -euo pipefail

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

manifest=$(mktemp)
trap 'rm -f -- "$manifest"' EXIT
base64 --decode > "$manifest" <<'ARCHIVE_LEDGER_PATHS'
# ARCHIVE_LEDGER_MANIFEST
ARCHIVE_LEDGER_PATHS

# rsync can follow pre-existing destination directory symlinks. Refuse them
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

rsync -aL --from0 --files-from="$manifest" \
  --ignore-existing --itemize-changes "${rsync_options[@]}" \
  -- "$source_root/" "$destination_root/"
