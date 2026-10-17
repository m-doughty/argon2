#!/usr/bin/env bash
# Fails when a GNATprove run did not look at every unit it was asked to.
#
# GNATprove exits 0 and prints "Success" when it skips a unit ("skipped for
# this unit", "error during checking of SPARK_Mode"), so the exit status
# alone is not evidence that every check was proved. This reads the run's
# summary (gnatprove.out) and fails on:
#   * a skipped unit or a checking error;
#   * a summary with no Total line, a total that is not a positive number
#     of checks, or any unproved or justified check;
#   * no "Analyzed N units" line with N at least 1, or a count of
#     "in unit" lines that differs from N;
#   * a unit not every subprogram and package of which was analyzed
#     ("in unit U, X subprograms and packages out of Y analyzed" with X
#     less than Y). For this crate's own units (src/) X must equal Y. A
#     unit of a dependency may fall short only by subprograms GNATprove
#     lists as "skipped; body is SPARK_Mode => Off" that are run-time
#     library generics (declared in a GNAT run-time file, a-*.ads,
#     s-*.ads, ...) instantiated in that unit; those entries are printed.
# With --whole-crate it also fails unless every unit in src/ (a spec and
# body pair is one unit) is in the summary: the check for a run of the whole
# crate (CI's). Without it, a run restricted to some units (gnatprove -u,
# as the mutation suite runs it) passes with only those.
#
# With no path it looks under obj/*/gnatprove/; if that finds more than one
# summary (an old profile's report beside the new one) it fails and asks for
# the path, rather than judge a report that may not be the run's.
#
# Usage: check-proof-output.sh [--whole-crate] [path/to/gnatprove.out]
#        check-proof-output.sh --self-test
set -euo pipefail

discover () { # root: the one summary under root/obj/*/gnatprove/
  local found n
  found=$(ls "$1"/obj/*/gnatprove/gnatprove.out 2>/dev/null) || true
  n=$(grep -c . <<< "$found") || true
  if [ "$n" -gt 1 ]; then
    echo "proof output: $n summaries found, give the path of this run's:" >&2
    echo "$found" >&2
    return 1
  fi
  printf '%s\n' "$found"
}

units () { # root: the unit names (file stems) of root/src, one per line
  local f
  for f in "$1"/src/*.ads "$1"/src/*.adb; do
    [ -f "$f" ] || continue
    f=${f##*/}
    printf '%s\n' "${f%.ad[sb]}"
  done | LC_ALL=C sort -u
}

judge () { # file root whole-crate(0|1)
  local f=$1 root=$2 whole=$3 bad=0 own
  [ -s "$f" ] || { echo "proof output: $f is missing or empty"; return 1; }
  own=$(units "$root")
  [ -n "$own" ] || { echo "proof output: no units in $root/src"; return 1; }
  if grep -n -e "skipped for this unit" -e "error during checking" "$f"; then
    echo "proof output: a unit was skipped or not checked"; bad=1
  fi
  local total
  total=$(grep -E '^Total ' "$f" | head -n 1) \
    || { echo "proof output: no Total line in $f"; return 1; }
  # Columns: Total, Flow, Provers, Justified, Unproved ("." means none).
  if ! awk '{ exit !($2 ~ /^[0-9]+$/ && $2 + 0 > 0) }' <<< "$total"; then
    echo "proof output: the total is not a positive number of checks: $total"
    bad=1
  fi
  if ! echo "$total" | grep -Eq '[[:space:]]\.[[:space:]]+\.[[:space:]]*$'; then
    echo "proof output: justified or unproved checks in: $total"; bad=1
  fi
  # The unit list: its count, each unit's analysed subprograms and, in
  # whole-crate mode, every unit of src/.
  awk -v own="$(tr '\n' ' ' <<< "$own")" -v whole="$whole" '
    function close_unit() {
      if (unit == "") return
      if (x != y) {
        if (unit in mine) {
          printf "proof output: unit %s: %d of %d subprograms and packages analyzed\n", unit, x, y
          bad = 1
        } else if (y - x != rtl) {
          printf "proof output: unit %s: %d of %d subprograms and packages analyzed, and %d of the rest are run-time library generics with SPARK_Mode => Off bodies\n", unit, x, y, rtl
          bad = 1
        } else {
          printf "proof output: unit %s: %d of %d analyzed; the rest are run-time library generics, bodies SPARK_Mode => Off:%s\n", unit, x, y, rtl_names
        }
      }
      unit = ""
    }
    BEGIN {
      n = split(own, a, " ")
      for (i = 1; i <= n; i++) mine[a[i]] = 1
      analyzed = -1; listed = 0; bad = 0; unit = ""
    }
    { sub(/\r$/, "") }                         # a summary written on Windows
    /^Analyzed / {
      if ($0 !~ /^Analyzed [0-9]+ units?$/ || analyzed >= 0) {
        print "proof output: unexpected line: " $0; bad = 1
      } else analyzed = $2 + 0
      next
    }
    /^in unit / {
      close_unit()
      listed++
      if ($0 !~ /^in unit [^ ,]+, [0-9]+ subprograms and packages out of [0-9]+ analyzed$/) {
        print "proof output: unexpected line: " $0; bad = 1; next
      }
      unit = $3; sub(/,$/, "", unit)
      x = $4 + 0; y = $(NF - 1) + 0
      rtl = 0; rtl_names = ""
      seen[unit] = 1
      next
    }
    unit != "" && /^  / {
      if ($0 ~ / at [agis]-[a-z0-9_]+\.ads:[0-9]+, instantiated at [^ ]+ skipped; body is SPARK_Mode => Off$/) {
        rtl++
        e = $0; sub(/^ +/, "", e); sub(/ .*$/, "", e)
        rtl_names = rtl_names " " e
      }
      next
    }
    { close_unit() }
    END {
      close_unit()
      if (analyzed < 1) {
        print "proof output: no \"Analyzed N units\" line with N at least 1"
        bad = 1
      } else if (listed != analyzed) {
        printf "proof output: %d units analyzed but %d listed\n", analyzed, listed
        bad = 1
      }
      if (whole == 1)
        for (i = 1; i <= n; i++)
          if (!(a[i] in seen)) {
            print "proof output: unit " a[i] " (src/) is not in the summary"
            bad = 1
          }
      exit bad
    }' "$f" || bad=1
  [ "$bad" -eq 0 ] || return 1
  if [ "$whole" -eq 1 ]; then
    echo "proof output: every unit of src/ checked, every subprogram" \
         "analyzed, nothing unproved or justified ($total)" | tr -s ' '
  else
    echo "proof output: every unit checked, every subprogram analyzed," \
         "nothing unproved or justified ($total)" | tr -s ' '
  fi
}

if [ "${1:-}" = "--self-test" ]; then
  d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
  # A crate with the units of this one.
  mkdir -p "$d/c/src"
  for u in argon2.ads argon2-blocks.ads argon2-compression.ads \
           argon2-compression.adb argon2-compression_model.ads \
           argon2-h0.ads argon2-h0.adb argon2-h0_model.ads \
           argon2-h0_model.adb argon2-h_prime.ads argon2-h_prime.adb \
           argon2-h_prime_model.ads argon2-wipe.ads argon2-wipe.adb; do
    : > "$d/c/src/$u"
  done
  total='Total                          3398    304 (9%)                                        3094 (91%)           .          .'
  ok='flow analyzed (0 errors, 0 checks, 0 warnings and 0 pragma Assume statements) and proved (1 checks)'
  rtl_skip () { # unit name, line
    echo "  Blake2b.Hashing.Big.$1 at a-nbnbin.ads:$2, instantiated at blake2b-hashing.ads:96 skipped; body is SPARK_Mode => Off"
  }
  unit () { # name, analyzed, of
    echo "in unit $1, $2 subprograms and packages out of $3 analyzed"
    echo "  X at $1.ads:1 $ok"
  }
  # Modelled on a whole-crate run's summary.
  {
    echo 'Summary of SPARK analysis'
    echo "$total"
    echo
    echo 'Analyzed 12 units'
    for u in argon2 argon2-blocks argon2-compression \
             argon2-compression_model argon2-h0 argon2-h0_model \
             argon2-h_prime argon2-h_prime_model argon2-wipe argon2_config; do
      unit "$u" 1 1
    done
    unit blake2b-hashing 3 5
    rtl_skip Lengths.From_Big_Integer 85
    rtl_skip Lengths.To_Big_Integer 82
    unit blake2b-core 15 15
  } > "$d/good"
  # Modelled on a run restricted to one unit (gnatprove -u).
  {
    echo "$total"
    echo 'Analyzed 2 units'
    unit argon2-compression 20 20
    unit blake2b-core 15 15
  } > "$d/restricted"
  printf '%s\n' "$total" > "$d/totalonly"
  cp "$d/good" "$d/skip"; echo "info: blake2b-hashing.adb skipped for this unit" >> "$d/skip"
  cp "$d/good" "$d/err"; echo "error during checking of SPARK_Mode" >> "$d/err"
  sed 's/^Total .*/Total   10   2 (20%)   7 (70%)   .   1/' "$d/good" > "$d/unproved"
  sed 's/^Total .*/Total   10   2 (20%)   7 (70%)   1   ./' "$d/good" > "$d/justified"
  sed 's/^Total .*/Total   0   .   .   .   ./' "$d/good" > "$d/zero"
  sed 's/^Total .*/Total   .   .   .   .   ./' "$d/good" > "$d/dot"
  sed '/^Total /d' "$d/good" > "$d/nototal"
  sed '/^Analyzed /d' "$d/good" > "$d/noanalyzed"
  sed 's/^Analyzed 12 units/Analyzed 0 units/' "$d/good" > "$d/zerounits"
  sed 's/^Analyzed 12 units/Analyzed 13 units/' "$d/good" > "$d/count"
  sed 's/^in unit argon2-h0, 1 subprograms and packages out of 1/in unit argon2-h0, 19 subprograms and packages out of 20/' \
    "$d/good" > "$d/own_short"
  sed 's/^in unit blake2b-core, 15 /in unit blake2b-core, 14 /' "$d/good" > "$d/dep_short"
  sed 's/^in unit blake2b-hashing, 3 /in unit blake2b-hashing, 2 /' "$d/good" > "$d/dep_shorter"
  sed 's/at a-nbnbin.ads:82/at blake2b-hashing.ads:82/' "$d/good" > "$d/dep_own_off"
  sed 's/^in unit argon2-blocks, .*/in unit argon2-blocks, all subprograms analyzed/' "$d/good" > "$d/malformed"
  : > "$d/empty"
  judge "$d/good" "$d/c" 1 > /dev/null || { echo "self-test: good output rejected"; exit 1; }
  judge "$d/good" "$d/c" 0 > /dev/null || { echo "self-test: good output rejected (restricted)"; exit 1; }
  judge "$d/restricted" "$d/c" 0 > /dev/null || { echo "self-test: restricted run rejected"; exit 1; }
  if judge "$d/restricted" "$d/c" 1 > /dev/null 2>&1; then
    echo "self-test: restricted run accepted as the whole crate"; exit 1
  fi
  for bad in skip err unproved justified zero dot nototal noanalyzed \
             zerounits count own_short dep_short dep_shorter dep_own_off \
             malformed totalonly empty missing; do
    for mode in 0 1; do
      if judge "$d/$bad" "$d/c" "$mode" > /dev/null 2>&1; then
        echo "self-test: $bad accepted (whole-crate $mode)"; exit 1
      fi
    done
  done
  # A unit of src/ missing from a whole-crate run.
  : > "$d/c/src/argon2-extra.ads"
  judge "$d/good" "$d/c" 0 > /dev/null || { echo "self-test: good output rejected"; exit 1; }
  if judge "$d/good" "$d/c" 1 > /dev/null 2>&1; then
    echo "self-test: missing unit accepted in whole-crate mode"; exit 1
  fi
  rm "$d/c/src/argon2-extra.ads"
  # No src/ at all.
  if judge "$d/good" "$d" 0 > /dev/null 2>&1; then
    echo "self-test: a crate with no src/ accepted"; exit 1
  fi
  mkdir -p "$d/r/obj/validation/gnatprove" "$d/r/obj/development/gnatprove"
  cp "$d/good" "$d/r/obj/validation/gnatprove/gnatprove.out"
  [ "$(discover "$d/r")" = "$d/r/obj/validation/gnatprove/gnatprove.out" ] \
    || { echo "self-test: single summary not found"; exit 1; }
  cp "$d/good" "$d/r/obj/development/gnatprove/gnatprove.out"
  if discover "$d/r" > /dev/null 2>&1; then
    echo "self-test: two summaries accepted"; exit 1
  fi
  echo "check-proof-output self-test: ok"; exit 0
fi

whole=0
if [ "${1:-}" = "--whole-crate" ]; then
  whole=1
  shift
fi
case ${1:-} in
  -*) echo "usage: check-proof-output.sh [--whole-crate] [path/to/gnatprove.out]" >&2
      echo "       check-proof-output.sh --self-test" >&2
      exit 2 ;;
esac
root="$(cd "$(dirname "$0")/.." && pwd)"
f=${1:-$(discover "$root")} || exit 1
judge "${f:-/nonexistent}" "$root" "$whole"
