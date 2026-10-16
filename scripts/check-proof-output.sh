#!/usr/bin/env bash
# Fails when a GNATprove run did not look at every unit it was asked to.
#
# GNATprove exits 0 and prints "Success" when it skips a unit ("skipped for
# this unit", "error during checking of SPARK_Mode"), so the exit status
# alone is not evidence that every check was proved. This reads the run's
# summary (gnatprove.out) and fails on a skipped unit, a checking error,
# any unproved or justified check, or a summary with no total.
#
# Usage: check-proof-output.sh [path/to/gnatprove.out]
#        check-proof-output.sh --self-test
set -euo pipefail

judge () { # file
  local f=$1 bad=0
  [ -s "$f" ] || { echo "proof output: $f is missing or empty"; return 1; }
  if grep -n -e "skipped for this unit" -e "error during checking" "$f"; then
    echo "proof output: a unit was skipped or not checked"; bad=1
  fi
  local total
  total=$(grep -E '^Total ' "$f" | head -n 1) \
    || { echo "proof output: no Total line in $f"; return 1; }
  # Columns: Total, Flow, Provers, Justified, Unproved ("." means none).
  if ! echo "$total" | grep -Eq '[[:space:]]\.[[:space:]]+\.[[:space:]]*$'; then
    echo "proof output: justified or unproved checks in: $total"; bad=1
  fi
  [ "$bad" -eq 0 ] || return 1
  echo "proof output: every unit checked, nothing unproved or justified ($total)" | tr -s ' '
}

if [ "${1:-}" = "--self-test" ]; then
  d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
  good='Total                          2805    251 (9%)                                        2554 (91%)           .          .'
  printf '%s\n' "$good" > "$d/good"
  printf '%s\n' "$good" "info: blake2b-hashing.adb skipped for this unit" > "$d/skip"
  printf '%s\n' "$good" "error during checking of SPARK_Mode" > "$d/err"
  printf '%s\n' 'Total   10   2 (20%)   7 (70%)   .   1' > "$d/unproved"
  printf '%s\n' 'Total   10   2 (20%)   7 (70%)   1   .' > "$d/justified"
  printf '%s\n' 'Summary of SPARK analysis' > "$d/nototal"
  : > "$d/empty"
  judge "$d/good" > /dev/null || { echo "self-test: good output rejected"; exit 1; }
  for bad in skip err unproved justified nototal empty missing; do
    if judge "$d/$bad" > /dev/null 2>&1; then echo "self-test: $bad accepted"; exit 1; fi
  done
  echo "check-proof-output self-test: ok"; exit 0
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
f=${1:-$(ls "$root"/obj/*/gnatprove/gnatprove.out 2>/dev/null | head -n 1)}
judge "${f:-/nonexistent}"
