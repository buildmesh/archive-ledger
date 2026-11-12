#!/usr/bin/env bash
# Archive Ledger host removal script. Requires Bash; --delete also needs b3sum.
# Review the target root and complete file list below, then run:
#   bash remove.sh --dry-run   # List planned removals; this is also the default.
#   bash remove.sh --delete    # Check BLAKE3, then remove matching files only.
# Selection uses cached backup evidence; it does not reread backup drives.
# Run while other programs are not modifying the target files or directories.
# No directories are removed. A final file symlink is unlinked, not its target.
# This script never updates the catalog. After any deletion run (even if stopped
# partway), reconcile actual presence with: archive location scan "TARGET LOCATION"

# The function is invoked only at the very end, so incomplete generation cannot
# execute a partial removal plan.
main() {
  set -euo pipefail

  # 1. Deletion must be explicitly requested.
  mode=preview
  if (( $# > 1 )); then
    printf 'Usage: bash remove.sh [--dry-run|--delete]\n' >&2
    exit 2
  fi
  case "${1-}" in
    ''|--dry-run) ;;
    --delete) mode=delete ;;
    *) printf 'Usage: bash remove.sh [--dry-run|--delete]\n' >&2; exit 2 ;;
  esac

  # 2. Target directory, safely quoted by the generator.
# ARCHIVE_LEDGER_ROOTS

  # 3. Complete file list: expected BLAKE3, a tab, then Collection-relative path.
  # Paths are data, never commands. Spaces, quotes, $, and backticks are literal.
  # Escapes: \\ = backslash, \n = newline, \r = carriage return, \t = tab;
  # other non-ASCII/control bytes use \0ooo (three octal digits).
  # The quoted heredoc disables expansion. A fixed printf format decodes the
  # list into alternating NUL-separated checksums and paths, without eval.
  manifest=$(mktemp)
  trap 'rm -f -- "$manifest"' EXIT
  while IFS=$'\t' read -r expected encoded_path; do
    if [[ ! "$expected" =~ ^[0-9a-f]{64}$ || -z "$encoded_path" || "$encoded_path" == *$'\t'* ]]; then
      printf 'Invalid file-list entry.\n' >&2
      exit 1
    fi
    printf '%s\0%b\0' "$expected" "$encoded_path"
  done > "$manifest" <<'ARCHIVE_LEDGER_PATHS'
# ARCHIVE_LEDGER_MANIFEST
ARCHIVE_LEDGER_PATHS

  # 4. The earliest expiry of the selected files' newest matching backup checks.
  # This keeps a saved script from using evidence beyond the requested age.
# ARCHIVE_LEDGER_EXPIRY

  check_evidence_age() {
    local current_time
    # An arithmetic if condition does not stop on command failure under set -e.
    # Check the command and its output explicitly before doing any arithmetic.
    if ! current_time=$(date +%s) || [[ ! "$current_time" =~ ^[0-9]{1,16}$ ]]; then
      printf 'Cannot read a valid host time; refusing deletion.\n' >&2
      exit 1
    fi
    if (( 10#$current_time >= evidence_expires_at )); then
      printf 'Backup evidence has expired; regenerate this script.\n' >&2
      exit 1
    fi
  }

  # Reject unsafe paths and any symlink in a directory component. Also check
  # ancestors of the configured root; only a final file symlink is permitted.
  check_path() {
    case "$relative" in
      ''|/*|.|..|./*|../*|*/./*|*/../*|*/.|*/..|*//*|*/)
        printf 'Refusing non-normalized path: %q\n' "$relative" >&2; exit 1 ;;
    esac
    full_path="$target_root/$relative"
    parent=${full_path%/*}
    while [[ -n "$parent" && "$parent" != / ]]; do
      if [[ -L "$parent" ]]; then
        printf 'Refusing directory symlink: %q\n' "$parent" >&2
        exit 1
      fi
      parent=${parent%/*}
    done
    if [[ -e "$full_path" || -L "$full_path" ]]; then
      if [[ ! -f "$full_path" ]]; then
        printf 'Refusing non-regular or dangling file: %q\n' "$full_path" >&2
        exit 1
      fi
    fi
  }

  # 5. Validate every path before the first deletion. Preview lists all planned
  # paths from the catalog; current contents are checked only with --delete.
  if [[ "$mode" == preview ]]; then
    printf 'Would remove these files (contents will be checked before deletion):\n'
  else
    if [[ ! -d "$target_root" ]]; then
      printf 'Target directory is unavailable: %q\n' "$target_root" >&2
      exit 1
    fi
    check_evidence_age
    command -v b3sum >/dev/null || { printf 'Install b3sum before deleting files.\n' >&2; exit 1; }
  fi
  while IFS= read -r -d '' expected; do
    IFS= read -r -d '' relative || { printf 'Incomplete file list.\n' >&2; exit 1; }
    check_path
    if [[ "$mode" == preview ]]; then
      printf '%q\n' "$relative"
    fi
  done < "$manifest"
  if [[ "$mode" == preview ]]; then
    return
  fi

  # 6. Recheck each path immediately before use. Refuse changed bytes; deletion
  # can stop partway on an error, so reconcile the catalog even after a failure.
  while IFS= read -r -d '' expected; do
    IFS= read -r -d '' relative || { printf 'Incomplete file list.\n' >&2; exit 1; }
    check_path
    if [[ ! -e "$full_path" && ! -L "$full_path" ]]; then
      printf 'Already absent: %q\n' "$relative"
      continue
    fi
    actual=$(b3sum --no-names --num-threads 1 -- "$full_path")
    if [[ "$actual" != "$expected" ]]; then
      printf 'Checksum changed; refusing to remove: %q\n' "$relative" >&2
      exit 1
    fi
    check_path
    check_evidence_age
    rm -- "$full_path"
    printf 'Removed: %q\n' "$relative"
  done < "$manifest"
  printf 'Finished. Reconcile this Location with archive location scan.\n'
}
main "$@"
