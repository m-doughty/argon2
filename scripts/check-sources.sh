#!/usr/bin/env bash
# Source gate: the library may not contain any of the ways to make
# GNATprove accept something it has not proved. (Adapted from blake2b's
# gate of the same name.)
#
#   pragma Assume                         an unproved fact
#   Annotate (GNATprove, False_Positive)  a check waved through
#   Annotate (GNATprove, Intentional)     a check waved through
#   Skip_Proof / Skip_Flow_And_Proof      a subprogram not analysed
#   SPARK_Mode => Off / (Off)             code outside SPARK
#   Import (aspect or pragma), anywhere   a declaration GNATprove trusts
#                                         without analysing a body
#   pragma Interface                      the same, by its older name
#
# TRUST.md must list exactly the warning suppressions found (one W-n row
# each).
#
# Two checks are specific to this crate:
#   * the only compiler annotation that silences a warning outside a
#     `pragma Warnings` region is the single `pragma Unreferenced` that
#     TRUST.md records as N-4, in src/argon2-h0_model.adb; any other one,
#     or a second there, fails;
#   * the project file keeps the proof's warnings fatal (--warnings=error,
#     -gnatwe) and does not switch warnings off (-gnatws, --warnings=off,
#     --warnings=continue).
#
# Warnings (GNATprove's, or unqualified ones, which GNATprove also obeys)
# may be suppressed only with a recorded Reason. The script lists every
# suppression so that a reviewer sees them all.
#
# The checks run on the source as the compiler reads it, not on its
# spelling:
#   * string literals, character literals and comments are removed first,
#     in one left-to-right pass, so a comment or a string that mentions a
#     forbidden pragma doesn't trip the gate, and "--" inside a string
#     can't hide the code after it;
#   * the rest is lowercased (Ada is case-insensitive), and line breaks
#     and runs of spaces become one space, so a pragma split across lines
#     is caught.
#
# Usage: scripts/check-sources.sh               check src/
#        scripts/check-sources.sh --self-test   check the gate itself
#                                               against known bypasses

set -euo pipefail
cd "$(dirname "$0")/.."

# Prints "file<TAB>normalised text", one line per Ada source given.
normalise () {
  perl -e '
    for my $file (@ARGV) {
      open my $fh, "<", $file or die "$file: $!";
      local $/; my $t = <$fh>; close $fh;
      # One pass, leftmost match first: a string, a character literal (a
      # quote not preceded by an identifier or a closing bracket, which
      # would make it an attribute tick) or a comment. A comment (and a
      # string, which cannot span lines) ends at any end of line Ada
      # knows: LF, CR, VT, FF, and NEL, LS and PS in UTF-8.
      my $eol = q{(?:[\r\n\x0b\x0c]|\xC2\x85|\xE2\x80[\xA8\xA9])};
      $t =~ s{("(?:(?!$eol)[^"]|"")*")|((?<![A-Za-z0-9_)\]])\x27.\x27)|(--(?:(?!$eol).)*)}
             {defined $1 ? q{""} : " "}gse;
      $t = lc $t;
      $t =~ s/\s+/ /g;
      print "$file\t$t\n";
    }' "$@"
}

# Runs every check over the given files. Prints findings; returns non-zero
# if there are any.
scan () {
  local normal found=0 hits
  normal=$(normalise "$@")
  forbid () {
    local what=$1 pattern=$2
    # Match the text after the tab only, never the file name before it.
    # grep exits 1 for "no match" and 2 or more for an error: only the
    # first means nothing was found.
    local rc=0 matches
    matches=$(grep -E $'\t'".*($pattern)" <<< "$normal") || rc=$?
    if [ "$rc" -gt 1 ]; then
      echo "ERROR: grep failed (status $rc) while checking for $what"
      found=1
      return
    fi
    hits=$(cut -f1 <<< "$matches")
    if [ -n "$hits" ]; then
      echo "FORBIDDEN ($what) in:"
      printf '  %s\n' $hits
      found=1
    fi
  }
  forbid "pragma Assume"             'pragma ?assume\b'
  forbid "False_Positive annotation" '\bfalse_positive\b'
  forbid "Intentional annotation"    '\bintentional\b'
  forbid "Skip_Proof"                '\bskip_(flow_and_)?proof\b'
  forbid "SPARK_Mode Off"            'spark_mode ?(=> ?off\b|\( ?off ?\))'
  forbid "Import"                    '\bimport\b'
  forbid "pragma Interface"          'pragma ?interface\b'
  # Outside comments and strings Ada source is ASCII here. A non-ASCII
  # byte in code (NEL, LS or PS, say, standing where a space would) would
  # let a forbidden word hide from the patterns above, so it fails too.
  local rc_ascii=0 nonascii
  nonascii=$(perl -ne '
    my ($f, $t) = split /\t/, $_, 2;
    print "$f\n" if $t =~ /[^\x00-\x7f]/;' <<< "$normal") || rc_ascii=$?
  if [ "$rc_ascii" -ne 0 ]; then
    echo "ERROR: could not check for non-ASCII code"
    found=1
  elif [ -n "$nonascii" ]; then
    echo "FORBIDDEN (non-ASCII character outside a comment or string) in:"
    printf '  %s\n' $nonascii
    found=1
  fi
  # Every suppression pragma: pragma Warnings ([tool,] Off ...); each must
  # carry "Reason =>" before its closing semicolon.
  local sup without
  sup=$(perl -ne '
    my ($f, $t) = split /\t/, $_, 2;
    while ($t =~ /(pragma warnings ?\( ?(?:(?:gnatprove|gnat) ?, ?)?off\b[^;]*;)/g) {
      print "$f\t$1\n";
    }' <<< "$normal")
  local rc=0
  without=$(grep -vE 'reason ?=>' <<< "$sup") || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "ERROR: grep failed (status $rc) while checking warning suppressions"
    found=1
  fi
  without=$(cut -f1 <<< "$without")
  if [ -n "$without" ]; then
    echo "FORBIDDEN (warning suppression without a Reason) in:"
    printf '  %s\n' $without
    found=1
  fi
  rc=0
  SUPPRESSIONS=$(grep -c . <<< "$sup") || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "ERROR: grep failed (status $rc) while counting warning suppressions"
    found=1
  fi
  return "$found"
}

# The register (TRUST.md) lists one W-n row per warning suppression. Prints
# the number of rows in the register's table; fails the check if it differs
# from the number of suppressions the scan found.
register_matches () {
  local register=$1 found=$2 listed
  listed=$(grep -cE '^\| W-[0-9]+ \|' "$register" || true)
  if [ "$listed" -ne "$found" ]; then
    echo "REGISTER MISMATCH: $register lists $listed warning suppressions," \
         "the sources have $found"
    return 1
  fi
}

# `pragma Unreferenced` may appear once, in the file TRUST.md's N-4 names.
unreferenced () {
  local normal rc=0 hits total in_model
  normal=$(normalise "$@")
  hits=$(perl -ne '
    my ($f, $t) = split /\t/, $_, 2;
    my $n = () = $t =~ /pragma ?unreferenced\b/g;
    print "$f\t$n\n" if $n;' <<< "$normal") || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "ERROR: could not count pragma Unreferenced"
    return 1
  fi
  total=$(awk -F'\t' '{ n += $2 } END { print n + 0 }' <<< "$hits")
  in_model=$(awk -F'\t' '$1 ~ /(^|\/)argon2-h0_model\.adb$/ { n += $2 } END { print n + 0 }' <<< "$hits")
  if [ "$total" -ne 1 ] || [ "$in_model" -ne 1 ]; then
    echo "FORBIDDEN (pragma Unreferenced other than the one registered as N-4):"
    printf '  %s\n' "${hits:-(none found; N-4 expects exactly one in argon2-h0_model.adb)}"
    return 1
  fi
}

# The project file keeps warnings fatal and never switches them off.
project_flags () {
  local gpr=$1 bad=0 flag
  for flag in '"--warnings=error"' '"-gnatwe"'; do
    if ! grep -qF -- "$flag" "$gpr"; then
      echo "MISSING in $gpr: $flag"
      bad=1
    fi
  done
  if grep -qE -- '-gnatw[sS]|-gnatwA|--warnings=(off|continue)' "$gpr"; then
    echo "FORBIDDEN in $gpr: a switch that turns warnings off"
    bad=1
  fi
  return "$bad"
}

self_test () {
  local dir pass=0 bad=0
  dir=$(mktemp -d)
  # name | must the gate flag it? | source (\n for line breaks)
  local cases=(
    'lower-assume|yes|pragma assume (True);'
    'split-assume|yes|PRAGMA ASSUME\n   (True);'
    'split-false-positive|yes|pragma Annotate\n  (GNATprove,\n   False_Positive, "x", "y");'
    'aspect-skip|yes|procedure P with Annotate => (gnatprove, skip_proof);'
    'split-spark-off|yes|package P with SPARK_Mode\n   => Off is end P;'
    'pragma-spark-off|yes|pragma spark_mode (off);'
    'string-hides-code|yes|S : constant String := "--"; pragma Assume (False);'
    'char-quote-hides-code|yes|C : constant Character := '"'"'"'"'"'; pragma Assume (X); S : String := "a";'
    'unexplained-warning|yes|pragma Warnings (GNATprove, Off, "msg");'
    'unexplained-plain-warning|yes|pragma Warnings\n  (Off, "msg");'
    'spec-import|yes|package P with Import, Convention => C;'
    'import-outside-spec|yes|function F (X : U64) return Boolean\n  with Ghost, Import, Global => null;'
    'split-pragma-import|yes|PRAGMA\n  IMPORT (C, F, "f");'
    'pragma-interface|yes|pragma Interface (Ada, F);'
    'interface-type|no|type T is interface;'
    'nel-in-code|yes|pragma\xc2\x85Assume (True);'
    'ls-in-code|yes|pragma\xe2\x80\xa8Assume (True);'
    'ps-in-code|yes|pragma\xe2\x80\xa9Assume (True);'
    'unicode-in-comment|no|-- caf\xc3\xa9\npragma Pure;'
    'unicode-in-string|no|S : constant String := "caf\xc3\xa9";'
    'cr-ends-comment|yes|-- c\rpragma Assume (True);'
    'vt-ends-comment|yes|-- c\vpragma Assume (True);'
    'ff-ends-comment|yes|-- c\fpragma Assume (True);'
    'cr-hides-import|yes|-- c\rfunction F return Boolean with Ghost, Import;'
    'crlf-comment|no|-- pragma Assume (True)\r\npragma Pure;'
    'comment-mentions|no|--  pragma Assume (True) would be forbidden'
    'string-mentions|no|S : constant String := "pragma Assume (True)";'
    'explained-warning|no|pragma Warnings (GNATprove, Off, "m",\n   Reason => "why");'
    'warning-on|no|pragma Warnings (GNATprove, On, "msg");'
    'attribute-tick|no|N : constant := X'"'"'Length; pragma Assert (N > 0);'
    'import-in-name|no|Imported : Natural := Import_Count;'
    'intentional-file-name|no|X : constant Natural := 0;'
  )
  local entry name expect src got
  for entry in "${cases[@]}"; do
    IFS='|' read -r name expect src <<< "$entry"
    printf '%b\n' "$src" > "$dir/$name.adb"
    if scan "$dir/$name.adb" > /dev/null; then got=no; else got=yes; fi
    if [ "$got" = "$expect" ]; then
      pass=$((pass + 1))
    else
      echo "self-test FAILED: $name (flagged: $got, expected: $expect)"
      bad=$((bad + 1))
    fi
  done
  # The register comparison: equal counts pass, unequal counts fail.
  printf '| W-1 | x |\n| W-2 | y |\n| N-1 | z |\n' > "$dir/register.md"
  if register_matches "$dir/register.md" 2 > /dev/null; then
    pass=$((pass + 1))
  else
    echo "self-test FAILED: register-equal (flagged)"; bad=$((bad + 1))
  fi
  if register_matches "$dir/register.md" 3 > /dev/null; then
    echo "self-test FAILED: register-unequal (not flagged)"; bad=$((bad + 1))
  else
    pass=$((pass + 1))
  fi
  # pragma Unreferenced: exactly one, in the model body.
  mkdir -p "$dir/u"
  printf 'procedure P is\n  pragma Unreferenced (X);\nbegin null; end P;\n' > "$dir/u/argon2-h0_model.adb"
  printf 'procedure Q is begin null; end Q;\n' > "$dir/u/other.adb"
  printf 'procedure R is\n  PRAGMA\n  UNREFERENCED (X);\nbegin null; end R;\n' > "$dir/u/third.adb"
  printf -- '-- pragma Unreferenced (X);\nprocedure S is begin null; end S;\n' > "$dir/u/comment.adb"
  if unreferenced "$dir/u/argon2-h0_model.adb" "$dir/u/other.adb" "$dir/u/comment.adb" > /dev/null; then
    pass=$((pass + 1))
  else
    echo "self-test FAILED: unreferenced-registered (flagged)"; bad=$((bad + 1))
  fi
  if unreferenced "$dir/u/argon2-h0_model.adb" "$dir/u/third.adb" > /dev/null; then
    echo "self-test FAILED: unreferenced-extra-file (not flagged)"; bad=$((bad + 1))
  else
    pass=$((pass + 1))
  fi
  if unreferenced "$dir/u/third.adb" > /dev/null; then
    echo "self-test FAILED: unreferenced-wrong-file (not flagged)"; bad=$((bad + 1))
  else
    pass=$((pass + 1))
  fi
  if unreferenced "$dir/u/other.adb" > /dev/null; then
    echo "self-test FAILED: unreferenced-missing (not flagged)"; bad=$((bad + 1))
  else
    pass=$((pass + 1))
  fi
  # Project switches.
  printf 'x ("--warnings=error", "-gnatwe");\n' > "$dir/ok.gpr"
  printf 'x ("--warnings=error");\n' > "$dir/no-gnatwe.gpr"
  printf 'x ("-gnatwe");\n' > "$dir/no-warn-error.gpr"
  printf 'x ("--warnings=error", "-gnatwe", "-gnatws");\n' > "$dir/gnatws.gpr"
  printf 'x ("--warnings=error", "-gnatwe", "--warnings=off");\n' > "$dir/off.gpr"
  if project_flags "$dir/ok.gpr" > /dev/null; then
    pass=$((pass + 1))
  else
    echo "self-test FAILED: gpr-ok (flagged)"; bad=$((bad + 1))
  fi
  local g
  for g in no-gnatwe no-warn-error gnatws off; do
    if project_flags "$dir/$g.gpr" > /dev/null; then
      echo "self-test FAILED: gpr-$g (not flagged)"; bad=$((bad + 1))
    else
      pass=$((pass + 1))
    fi
  done
  rm -rf "$dir"
  echo "self-test: $pass passed, $bad failed"
  [ "$bad" -eq 0 ]
}

if [ "${1:-}" = --self-test ]; then
  self_test
  exit $?
fi

SUPPRESSIONS=0
fail=0
scan src/*.ads src/*.adb || fail=1
unreferenced src/*.ads src/*.adb || fail=1
project_flags argon2.gpr || fail=1

echo "warning suppressions ($SUPPRESSIONS, each with a Reason):"
grep -rn -i -A2 'pragma warnings' src/ | grep -i -E '\boff\b' \
  || echo "  (none)"

register_matches TRUST.md "$SUPPRESSIONS" || fail=1

if [ "$fail" -eq 0 ]; then
  echo "sources: clean"
else
  exit 1
fi
