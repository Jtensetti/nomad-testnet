#!/usr/bin/env bash
# Compares two independently produced build trees for reproducibility.
#
# It reports byte-identical artifacts as such, and where an artifact differs
# it reports WHERE, so that a difference is explained rather than waved away.
# An artifact that merely "runs on both builders" is not reproducible and
# this script will not call it so.
set -euo pipefail

left="${1:?usage: compare-builds.sh <dir-a> <dir-b>}"
right="${2:?usage: compare-builds.sh <dir-a> <dir-b>}"

status=0
identical=0
differing=0

while IFS= read -r relative; do
  a="$left/$relative"
  b="$right/$relative"
  if [ ! -f "$b" ]; then
    printf 'MISSING  %s (absent from %s)\n' "$relative" "$right"
    status=1
    continue
  fi
  if cmp -s "$a" "$b"; then
    printf 'IDENTICAL %s\n' "$relative"
    identical=$((identical + 1))
  else
    differing=$((differing + 1))
    status=1
    printf 'DIFFERS   %s\n' "$relative"
    printf '          %s  %s\n' "$(sha256sum "$a" | cut -d" " -f1)" "$left"
    printf '          %s  %s\n' "$(sha256sum "$b" | cut -d" " -f1)" "$right"
    first="$(cmp "$a" "$b" 2>/dev/null | head -1 || true)"
    printf '          first difference: %s\n' "${first:-unknown}"
  fi
done < <(cd "$left" && find . -type f -printf '%P\n' | sort)

printf '\n%d identical, %d differing\n' "$identical" "$differing"
if [ "$status" -ne 0 ]; then
  printf 'NOT REPRODUCIBLE: every difference above must be explained and normalized before a reproducibility claim.\n'
fi
exit "$status"
