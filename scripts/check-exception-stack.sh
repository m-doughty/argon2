#!/usr/bin/env bash
# What the hardened subprograms leave on the stack, after a normal return
# and after an exception escapes them (TRUST.md, H-1 and H-2). The
# hardened subprograms carry GCC's strub ("internal") (the stack their
# body used is zeroed on return) and zero_call_used_regs ("all"); what GCC
# does on an exceptional exit is not documented as a guarantee, so it is
# measured here, and the normal return is gated.
#
# What is measured. The script copies the library's sources and those of
# its BLAKE2b dependency (the version Alire deployed for tests/, never
# written to) into a scratch directory (obj/exception-stack/, which git
# ignores) and builds copies of them with a driver
# (scripts/exception-stack/) through Alire, the library in its release or
# validation profile (each profile named on the command line; default
# both), BLAKE2b in its release profile, as the tests build them. Nothing
# is added to src/. Three kinds of build:
#   shipped   the sources unmodified; the driver calls the function and
#             it returns normally (the measurement of a normal return);
#   injected  ONE statement inserted, `if <trigger> then raise
#             Program_Error; end if;`, at an anchor that must match
#             exactly once (or the script stops); the trigger is data, so
#             one build serves a run that raises and a run that returns
#             normally (the latter is reported too, as "normal, injected
#             build": the inserted line can change the code around it);
#   spill     (case A' only) a block inserted at case A's anchor that
#             copies 32 words of the permuted block (256 bytes) into a
#             local array of volatile components, which the compiler must
#             store in the frame of Compress's body and cannot discard; no
#             raise. A positive control for compression's normal return:
#             without the hardening the words stay on the stack, with it
#             strub must scrub them.
# The cases:
#   A  Argon2.Compression.Compress (the injected line is in Store_G,
#      after the permutation of R = M (X) xor M (Y), which the first loop
#      of Combine put in the working block, and before the last loop that
#      writes M (Z); it fires when Z = 2);
#   A' the spill above, at the same place; the normal run of case A;
#   B  Argon2.H_Prime.Hash, through its hardened helper Initial_Hash (the
#      injected line follows the absorption of the input into the BLAKE2b
#      state, Blake2b.Hashing.Update (S, Input); it fires when
#      Input'First = 1); its shipped-sources run hashes a 1,023-byte
#      message (1,019 bytes of input);
#   C  Argon2.H_Prime.Hash, with the raise inside BLAKE2b's compression
#      (Blake2b.Core.Compress, after round 6 of 12; it fires when the
#      byte counter T_Lo = 1024, the last block of a 1024-byte message,
#      so during Blake2b.Hashing.Final, into whose scrubbed body
#      blake2b inlines Compress); its shipped-sources run hashes that
#      1,024-byte message, which nothing interrupts there.
#
# The driver (scripts/exception-stack/src/exception_stack.adb) keeps every
# input and output on the heap, so no frame of its own holds a canary. The
# canaries are 64-bit SplitMix64 values: for A and A', the words of M (X),
# of M (Y), of M (X) xor M (Y) and of its permutation (computed by an
# independent transcription of RFC 9106, checked against the library's
# output); for B and C, BLAKE2b's message words 1 to 126 (M: the input as
# BLAKE2b loads it, after the 4-byte length prefix) and the input's own
# 8-byte words (I: these straddle two message words, so an I hit at an
# unaligned offset between two adjacent M hits is the same bytes again,
# so the report also gives the number of distinct words of each class).
# From one helper frame the driver zeroes the region of stack below that
# frame, calls the
# hardened subprogram, then copies the same region with volatile reads and
# counts every occurrence of every canary, at 8-byte-aligned offsets and
# at the others (byte-wise); depths are counted in bytes below the helper
# frame. The frame that catches the injected Program_Error calls a frame
# holding an unused spacer of SPACER_KIB (8) KiB, which makes the call:
# the handler's own calls into the run-time run just below the catching
# frame, inside the spacer, and so do not overwrite what the call and the
# exception's propagation left. The region is the spacer plus PROBE_KIB
# KiB (default 16). Each run of the injected builds is one of: baseline
# (no call; must find nothing), raise (the injected exception escapes; it
# must be raised) and normal (the same call returns normally; it must not
# raise); the shipped and spill builds have baseline and normal only. The
# deepest byte written must lie inside the region with 256 bytes to
# spare; if not, the runs are repeated with the region doubled, up to
# 256 KiB (an exception's propagation writes much more stack than the
# call itself). The hits of a discarded batch are kept, tagged
# repeat=d<batch>-<n>, and counted like any repeat; "stack written up to"
# and the bookkeeping check are of the final batch only. The driver runs
# REPEATS (5) times per build, as separate processes: the counts can differ
# from one process to the next, and the report gives each; a "hits" figure
# below is the most of any repeat.
#
# Positive controls, one per mode. The control is the same copy with the
# strub and zero_call_used_regs pragmas removed from the library and from
# BLAKE2b (flatten kept, so the code is laid out as the hardened build's).
# Each mode of each case and profile is judged against its own control:
#   exception        (the raise run): if the control leaves no canary,
#                    the exception results of that case are UNMEASURED
#                    (a notice is printed; the exit status is unchanged);
#   normal, A        the control's normal return of compression has left
#                    no canary wherever it was measured (its own code
#                    leaves none to find), so it cannot show that the scan
#                    would see a canary there; A' does: its control must
#                    leave canaries, or compression's normal-return results
#                    (A and A') are BLIND and the script fails (exit 1);
#   normal, B and C  the control's normal return in the same kind of
#                    build is reported beside the hardened build's; where
#                    both leave none, the result is reported as "the
#                    control is not discriminating here": such a control
#                    does not show that the scan would see a canary there
#                    (a hardened hit fails whatever the control left).
# For A a second control also removes flatten; it is reported, not judged.
#
# What is gated (normal returns only; H-2 claims nothing for an
# exception, so hits after an exception are reported and never change the
# exit status): a hardened build must leave no canary after a normal
# return, in every case (A, A', B and C; shipped and injected builds, and
# the spill). The rule is "fail on any hit" (Matt, 2026-10-17). From
# blake2b 0.1.2, BLAKE2b's compression is inlined into its scrubbed entry
# points (Init, Update and Final), so in B and C it runs inside a
# scrubbed body too.
#
# Task abort (scripts/exception-stack/src/abort_stack.adb, on the shipped
# sources): the environment task calls Compress over and over in the
# abortable part of an asynchronous select, with the same canaries and
# probe, ABORT_TRIALS (3) times in each of two runs: abort (`delay 0.02`
# expires during the loop, which aborts it) and quiet (the delay never
# expires). The loop ends by itself after 0.3 s, so a run-time that aborts
# only at abort completion points (the loop has none) lets it run to that
# bound: the report says how many trials were interrupted before the loop
# ended. Reported for the control and the hardened build; it never changes
# the exit status.
#
# Output: per case and profile, each build's counts per run, then one
# "summary:" line per case and mode (profile, case, mode, the control's
# and the hardened build's hits, the verdict).
#
# Exit status:
#   0  every gated result passed, and A' saw its control's canaries;
#   1  a harness error, or a normal-return control that is blind (A');
#   3  a hardened build left a canary after a normal return (any case).
# A notice "exception results unmeasured" names each case whose control
# left no canary after the exception; it does not change the status.
#
# Usage: bash scripts/check-exception-stack.sh [profile ...]
#        ALR=/path/to/alr PROBE_KIB=16 REPEATS=5 ABORT_TRIALS=3 \
#          CASES='A B C T' bash scripts/check-exception-stack.sh release
# (CASES: the cases to run, A including A', T the task abort; default
# all.) It runs alr itself (not inside `alr exec`), after tests/ has been
# built once (it reads the BLAKE2b version Alire deployed for tests/, which
# must be the one alire.toml asks for, at the commit it pins, if it pins one).

set -euo pipefail

ALR=${ALR:-alr}
PROBE_KIB=${PROBE_KIB:-16}
SPACER_KIB=8
ABORT_TRIALS=${ABORT_TRIALS:-3}
REPEATS=${REPEATS:-5}
CASES=${CASES:-A B C T}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK="$ROOT/obj/exception-stack"
DRIVER="$ROOT/scripts/exception-stack"
if [ "$#" -eq 0 ]; then
  set -- release validation
fi

say () { echo "check-exception-stack: $*"; }
# To standard error: it may run inside a command substitution.
harness_error () {
  say "HARNESS ERROR: $*" >&2
  exit 1
}

case $PROBE_KIB in
  ''|*[!0-9]*|0) harness_error "PROBE_KIB must be a positive number of KiB" ;;
esac
case $REPEATS in
  ''|*[!0-9]*|0) harness_error "REPEATS must be a positive number" ;;
esac
case $ABORT_TRIALS in
  ''|*[!0-9]*|0) harness_error "ABORT_TRIALS must be a positive number" ;;
esac
# STRICT_NORMAL was a switch of an earlier version of this script; any
# canary after a normal return now fails. Set to 1 (what it asked for) it
# changes nothing; set to anything else it asks for a rule that is gone.
if [ -n "${STRICT_NORMAL+set}" ] && [ "$STRICT_NORMAL" != 1 ]; then
  harness_error "STRICT_NORMAL='$STRICT_NORMAL': the switch is gone; any" \
    "canary a hardened build leaves after a normal return fails (exit 3)." \
    "Unset it (or set it to 1, which changes nothing)"
fi
for profile in "$@"; do
  case $profile in
    release|validation) ;;
    *) harness_error "unknown profile $profile (release or validation)" ;;
  esac
done
for which in $CASES; do
  case $which in
    A|B|C|T) ;;
    *) harness_error "unknown case $which in CASES (A, B, C or T)" ;;
  esac
done

# The anchors, and what is inserted after each. In each, \n stands for a
# line break; the sources are copied with LF line endings.
ANCHOR_A='      Lemma_Same_Block (R, Model.Xor_Blocks (X0, Y0));\n      Permute (R);\n'
INSERT_A='      Lemma_Same_Block (R, Model.Xor_Blocks (X0, Y0));\n      Permute (R);\n      if Z = 2 then\n         raise Program_Error;\n      end if;\n'
# A': the first 32 words of the permuted block, into a local array whose
# components are volatile (every store is made, in the body's frame).
INSERT_S='      Lemma_Same_Block (R, Model.Xor_Blocks (X0, Y0));\n      Permute (R);\n      declare\n         type Spill_Words is array (Word_Index range 0 .. 31) of Unsigned_64\n         with Volatile_Components;\n         Spill : Spill_Words;\n      begin\n         for K in Spill'"'"'Range loop\n            Spill (K) := R (K);\n         end loop;\n      end;\n'
FILE_A=argon2/src/argon2-compression.adb
ANCHOR_B='      Blake2b.Hashing.Update (S, Input);\n'
INSERT_B='      Blake2b.Hashing.Update (S, Input);\n      if Input'"'"'First = 1 then\n         raise Program_Error;\n      end if;\n'
FILE_B=argon2/src/argon2-h_prime.adb
ANCHOR_C='      Round (V, M, 5);\n      Lemma_Same (V, Spec.Rounds (Init, M, 6));\n'
INSERT_C='      Round (V, M, 5);\n      Lemma_Same (V, Spec.Rounds (Init, M, 6));\n      if T_Lo = 1024 then\n         raise Program_Error;\n      end if;\n'
FILE_C=blake2b/src/blake2b-core.adb

# Replaces the one occurrence of $2 in file $1 with $3, literally (awk's
# index, no pattern; the file is read as one record, as it holds no \001);
# stops the script if $2 does not occur exactly once. (Bash's own string
# operations would do it, but bash 3.2 takes minutes over a source file.)
patch_once () {
  local file=$1 count
  count=$(SEARCH=$2 REPLACE=$3 OUT="$file.patched" awk '
    BEGIN { RS = "\001"; s = ENVIRON["SEARCH"]; r = ENVIRON["REPLACE"] }
    { text = text $0; records++ }
    END {
      if (records > 1 || s == "") { print -1; exit }
      rest = text; out = ""; n = 0
      while ((i = index(rest, s)) > 0) {
        n++
        out = out substr(rest, 1, i - 1) r
        rest = substr(rest, i + length(s))
      }
      printf "%s%s", out, rest > ENVIRON["OUT"]
      print n
    }' "$file") || harness_error "could not read ${file#"$WORK"/}"
  if [ "$count" -ne 1 ]; then
    rm -f "$file.patched"
    harness_error "anchor found $count times (want exactly 1) in" \
      "${file#"$WORK"/}: $2"
  fi
  mv "$file.patched" "$file"
}

# Copies the Ada sources of directory $1 to $2 with LF line endings (a
# Windows checkout may have CRLF; the compiler reads both alike).
copy_sources () {
  local from=$1 to=$2 file
  mkdir -p "$to"
  for file in "$from"/*.ads "$from"/*.adb; do
    [ -f "$file" ] || continue
    tr -d '\r' < "$file" > "$to/${file##*/}"
  done
}

# Removes, from the sources in directory $1, every Machine_Attribute
# pragma naming one of the attributes in the regular expression $2, and
# checks that some were removed and none is left.
strip_attributes () {
  local dir=$1 names=$2 file before after removed=0
  for file in "$dir"/*.ads "$dir"/*.adb; do
    before=$(grep -cE "^ *pragma Machine_Attribute \\(.*\"($names)\"" "$file" || true)
    [ "$before" -gt 0 ] || continue
    grep -vE "^ *pragma Machine_Attribute \\(.*\"($names)\"" "$file" \
      > "$file.tmp"
    mv "$file.tmp" "$file"
    after=$(grep -cE "\"($names)\"" "$file" || true)
    [ "$after" -eq 0 ] \
      || harness_error "could not remove every $names pragma from ${file#"$WORK"/}"
    removed=$((removed + before))
  done
  [ "$removed" -gt 0 ] \
    || harness_error "no $names pragma found in ${dir#"$WORK"/}"
  echo "$removed"
}

# The BLAKE2b release the tests build against, as Alire deployed it: the
# BLAKE2B_ALIRE_PREFIX that Alire sets for tests/ (on Windows a Windows
# path, which cygpath converts).
environment=$("$ALR" -n -C "$ROOT/tests" printenv --unix) \
  || harness_error "alr printenv in tests/ failed (build tests/ first)"
blake2b_dir=$(printf '%s\n' "$environment" | tr -d '\r' \
  | sed -n 's/^export BLAKE2B_ALIRE_PREFIX="\(.*\)"$/\1/p')
[ -n "$blake2b_dir" ] \
  || harness_error "Alire sets no BLAKE2B_ALIRE_PREFIX for tests/"
if command -v cygpath > /dev/null 2>&1; then
  blake2b_dir=$(cygpath -u "$blake2b_dir")
fi
[ -f "$blake2b_dir/alire.toml" ] && [ -d "$blake2b_dir/src" ] \
  || harness_error "BLAKE2b sources not found (BLAKE2B_ALIRE_PREFIX=$blake2b_dir)"
# The deployed BLAKE2b must be the version alire.toml asks for (exactly,
# "=X"). If alire.toml pins blake2b to a commit (in [[pins]]: url and a
# 40-hex commit), the deployed directory must be a git checkout of that
# commit with no modified tracked file, and its version is X or X-dev (what
# a commit of X carries before the release); without a pin it is X.
blake2b_version=$(tr -d '\r' < "$ROOT/alire.toml" \
  | sed -n 's/^blake2b = "=\([0-9][0-9.]*\)"$/\1/p')
case $blake2b_version in
  ''|*[!0-9.]*) harness_error "alire.toml asks for no exact BLAKE2b version" \
                  "(want one line blake2b = \"=X\")" ;;
esac
blake2b_pin=$(tr -d '\r' < "$ROOT/alire.toml" \
  | awk '/^\[/ { pins = ($0 == "[[pins]]") } pins && /^blake2b *=/')
pinned_commit=""
if [ -n "$blake2b_pin" ]; then
  pinned_commit=$(printf '%s\n' "$blake2b_pin" | sed -n \
    's/^blake2b = { url = "[^"]*", commit = "\([0-9a-f]\{40\}\)" }$/\1/p')
  [ -n "$pinned_commit" ] \
    || harness_error "alire.toml pins blake2b in a form this script does not" \
         "read (want blake2b = { url = \"...\", commit = \"<40 hex>\" })"
fi
deployed_version=$(tr -d '\r' < "$blake2b_dir/alire.toml" \
  | sed -n 's/^version = "\(.*\)"$/\1/p')
deployed_commit=""
if [ -n "$pinned_commit" ]; then
  command -v git > /dev/null 2>&1 \
    || harness_error "git not found (alire.toml pins blake2b to a commit)"
  [ -e "$blake2b_dir/.git" ] \
    || harness_error "the deployed BLAKE2b is not a git checkout" \
         "(alire.toml pins it to commit $pinned_commit)"
  deployed_commit=$(git -C "$blake2b_dir" rev-parse HEAD 2> /dev/null \
                      | tr -d '\r') \
    || harness_error "git rev-parse failed in the deployed BLAKE2b" \
         "($blake2b_dir)"
  [ "$deployed_commit" = "$pinned_commit" ] \
    || harness_error "the deployed BLAKE2b is at commit '$deployed_commit';" \
         "alire.toml pins it to commit $pinned_commit"
  modified=$(git -C "$blake2b_dir" status --porcelain --untracked-files=no \
               2> /dev/null | tr -d '\r') \
    || harness_error "git status failed in the deployed BLAKE2b" \
         "($blake2b_dir)"
  [ -z "$modified" ] \
    || harness_error "the deployed BLAKE2b sources are modified (commit" \
         "$deployed_commit; git status: $modified)"
  case $deployed_version in
    "$blake2b_version"|"$blake2b_version-dev") ;;
    *) harness_error "the deployed BLAKE2b is version '$deployed_version';" \
         "alire.toml asks for $blake2b_version" ;;
  esac
else
  [ "$deployed_version" = "$blake2b_version" ] \
    || harness_error "the deployed BLAKE2b is version '$deployed_version';" \
         "alire.toml asks for exactly $blake2b_version (no pin)"
fi

compiler=$("$ALR" -n -C "$ROOT/tests" exec -- gcc --version | head -n 1 | tr -d '\r')
platform="$(uname -s) $(uname -m)"
say "platform: $platform; compiler: $compiler"
say "measured: the shipped sources (normal returns), copies with one" \
    "injected raise per case, and compression with an injected spill (A');" \
    "see the script's header. Stack region scanned:" \
    "$((PROBE_KIB + SPACER_KIB)) KiB below the helper frame ($SPACER_KIB" \
    "KiB of spacer, then $PROBE_KIB KiB below the hardened call; doubled" \
    "when the call needs more); depths are counted from the helper frame"
say "hits are given per class as aligned/unaligned/distinct words, then" \
    "class@depth#word for the first ones"
say "BLAKE2b $deployed_version${deployed_commit:+ at commit $deployed_commit}" \
    "(alire.toml asks for =$blake2b_version)"

# The sources as shipped, then one build tree per variant: the injected
# and spill copies are rebuilt for each case, the shipped ones once per
# profile.
rm -rf "$WORK"
mkdir -p "$WORK/sources/argon2" "$WORK/sources/blake2b"
copy_sources "$ROOT/src" "$WORK/sources/argon2/src"
# The library's own pins go: the driver pins BLAKE2b to the copy beside it.
tr -d '\r' < "$ROOT/alire.toml" \
  | awk '/^\[/ { skip = ($0 == "[[pins]]") } !skip' \
  > "$WORK/sources/argon2/alire.toml"
tr -d '\r' < "$ROOT/argon2.gpr" > "$WORK/sources/argon2/argon2.gpr"
copy_sources "$blake2b_dir/src" "$WORK/sources/blake2b/src"
# A pinned crate's manifest may not carry the index's [origin] table.
tr -d '\r' < "$blake2b_dir/alire.toml" \
  | awk '/^\[/ { skip = ($0 == "[origin]") } !skip' \
  > "$WORK/sources/blake2b/alire.toml"
tr -d '\r' < "$blake2b_dir/blake2b.gpr" > "$WORK/sources/blake2b/blake2b.gpr"

TREES="hardened control control-noflatten hardened-shipped control-shipped"
NOTED=""
for tree_name in $TREES; do
  tree="$WORK/$tree_name"
  mkdir -p "$tree/driver"
  cp -R "$WORK/sources/argon2" "$WORK/sources/blake2b" "$tree/"
  copy_sources "$DRIVER/src" "$tree/driver/src"
  tr -d '\r' < "$DRIVER/exception_stack.gpr" > "$tree/driver/exception_stack.gpr"
  cat > "$tree/driver/alire.toml" <<TOML
name = "exception_stack"
description = "Stack left by hardened subprograms on return and on an exception"
version = "0.0.0"
licenses = "BSD-3-Clause"
executables = ["exception_stack", "abort_stack"]

[[depends-on]]
argon2 = "*"
blake2b = "=$blake2b_version"

[[pins]]
argon2 = { path = "../argon2" }
blake2b = { path = "../blake2b" }
TOML
done

# Restores tree $1's library sources, removes the attributes of variant
# $2 (hardened, control or control-noflatten), and inserts case $3's line
# (A, B or C: the raise; S: A's spill; none: the shipped sources).
prepare () {
  local tree=$1 variant=$2 which=$3 names n1 n2
  rm -rf "$tree/argon2/src" "$tree/blake2b/src"
  cp -R "$WORK/sources/argon2/src" "$tree/argon2/src"
  cp -R "$WORK/sources/blake2b/src" "$tree/blake2b/src"
  case $variant in
    hardened) ;;
    control|control-noflatten)
      names='strub|zero_call_used_regs'
      [ "$variant" = control ] || names="$names|flatten"
      n1=$(strip_attributes "$tree/argon2/src" "$names")
      n2=$(strip_attributes "$tree/blake2b/src" 'strub|zero_call_used_regs')
      case " $NOTED " in
        *" $variant "*) ;;
        *)
          NOTED="$NOTED $variant"
          say "$variant: $n1 Machine_Attribute pragmas ($names) removed" \
              "from the library, $n2 (strub|zero_call_used_regs) from BLAKE2b"
          ;;
      esac
      ;;
    *) harness_error "unknown variant $variant" ;;
  esac
  case $which in
    A) patch_once "$tree/$FILE_A" "$(printf '%b' "$ANCHOR_A")" "$(printf '%b' "$INSERT_A")" ;;
    S) patch_once "$tree/$FILE_A" "$(printf '%b' "$ANCHOR_A")" "$(printf '%b' "$INSERT_S")" ;;
    B) patch_once "$tree/$FILE_B" "$(printf '%b' "$ANCHOR_B")" "$(printf '%b' "$INSERT_B")" ;;
    C) patch_once "$tree/$FILE_C" "$(printf '%b' "$ANCHOR_C")" "$(printf '%b' "$INSERT_C")" ;;
    none) ;;
    *) harness_error "unknown insertion $which" ;;
  esac
}

# Builds tree $1 with the library in profile $2; the log is $3.
build () {
  (cd "$1/driver" \
     && "$ALR" -n build "--$2" "--profiles=argon2=$2,blake2b=release") \
    > "$3" 2>&1 || {
      tail -n 40 "$3"
      harness_error "build failed (${3#"$ROOT"/})"
    }
}

# Summarises run $2 of results file $1 (every repeat, those of a discarded
# batch too: repeat=d<batch>-<n>, listed only if they hit): prints
# "<least> <most> <totals per repeat>|<detail>", where the detail is, for
# the repeat with the most hits, each class's hits at aligned and at other
# offsets and the number of distinct words found, and where the first
# hits lie (depth in bytes below the helper frame # index of the word).
summarise () {
  awk -v run="$2" '
    $1 == "hits" {
      delete f
      for (i = 2; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
      if (f["run"] != run) next
      r = f["repeat"]
      if (!(r in total)) keys[++count] = r
      n = f["aligned"] + f["unaligned"]
      total[r] += n
      text[r] = text[r] sprintf(" %s=%d/%d/%d", f["class"], f["aligned"],
                                f["unaligned"], f["distinct"])
      if (n > 0) depths[r] = depths[r] sprintf(" %s@%s", f["class"], f["depths"])
    }
    END {
      lo = -1; hi = -1; best = keys[1]; list = ""; shown = 0
      for (k = 1; k <= count; k++) {
        r = keys[k]
        if (lo < 0 || total[r] < lo) lo = total[r]
        if (total[r] > hi) { hi = total[r]; best = r }
        if (r ~ /^d/) {
          if (total[r] > 0) list = list "," r "=" total[r]
        } else {
          list = list (shown++ > 0 ? "," : "") total[r] + 0
        }
      }
      printf "%d %d %s|%s%s\n", lo, hi, list, substr(text[best], 2),
             (depths[best] == "" ? "" : ";" depths[best])
    }' "$1"
}

# The most stack any repeat of run $2 in file $1 wrote (the touched=
# field: bytes of the region from its top down to the deepest nonzero
# byte). The repeats of a discarded batch (repeat=d...) are left out: they
# wrote more than their region held, and the figure is of the final batch.
touched () {
  awk -v run="$2" '
    $1 == "hits" {
      delete f
      for (i = 2; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
      if (f["repeat"] ~ /^d/) next
      if (f["run"] == run && f["touched"] + 0 > m) m = f["touched"] + 0
    }
    END { print m + 0 }' "$1"
}

# Checks the bookkeeping of results file $1 (label $2), from a build of
# kind $3 (raise: the injected raise; normal: none): the baseline finds
# nothing, the raise run raised (and exists only in a raise build), the
# normal run did not raise, and every call wrote some stack. The repeats
# of a discarded batch (repeat=d...) are evidence only, and not checked.
check_runs () {
  local file=$1 label=$2 mode=$3
  awk -v label="$label" -v mode="$mode" '
    $1 == "hits" {
      delete f
      for (i = 2; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
      if (f["repeat"] ~ /^d/) next
      seen[f["run"]] = 1
      if (f["run"] == "baseline" && f["aligned"] + f["unaligned"] > 0) {
        print label ": the baseline (no call) found canaries"; bad = 1 }
      if (f["run"] == "raise" && f["raised"] != "yes") {
        print label ": the injected exception was not raised"; bad = 1 }
      if (f["run"] == "normal" && f["raised"] != "no") {
        print label ": the normal run raised"; bad = 1 }
      if (f["run"] != "baseline" && f["touched"] + 0 == 0) {
        print label ": the call wrote nothing in the region"; bad = 1 }
    }
    END {
      if (!seen["baseline"] || !seen["normal"] \
          || (mode == "raise") != ("raise" in seen)) {
        print label ": runs missing from the output, or unexpected"; bad = 1 }
      exit bad
    }' "$file" | sort -u
  return "${PIPESTATUS[0]}"
}

# Runs program $1 REPEATS times, with the region size (KiB, initially $3)
# as its first argument and the rest of the arguments after it; its
# output goes to file $2, each "hits" line tagged repeat=<n>. The region
# must hold all the stack the program wrote, with 256 bytes to spare; if
# it does not, every repeat is run again with the region doubled, up to
# 256 KiB. The "hits" lines of a batch run again are not lost: they are
# tagged repeat=d<batch>-<n> and appended after the last batch. Sets
# KIB_USED.
run_probe () {
  local program=$1 out=$2 kib=$3 deepest repeat discarded=0
  shift 3
  : > "$out.discarded"
  while :; do
    : > "$out"
    for repeat in $(seq 1 "$REPEATS"); do
      "$program" "$kib" "$@" > "$out.one" 2>&1 \
        || { cat "$out.one"; harness_error "${program##*/} failed (${out#"$ROOT"/})"; }
      tr -d '\r' < "$out.one" \
        | sed "s/^hits /hits repeat=$repeat /" >> "$out"
    done
    rm -f "$out.one"
    deepest=$(awk '$1 == "hits" { for (i = 2; i <= NF; i++) {
                     split($i, kv, "=")
                     if (kv[1] == "touched" && kv[2] + 0 > m) m = kv[2] + 0 } }
                   END { print m + 0 }' "$out")
    if [ $((deepest + 256)) -le $((kib * 1024)) ]; then
      break
    fi
    if [ "$kib" -ge 256 ]; then
      harness_error "the call wrote $deepest bytes of stack, more than a" \
        "$kib KiB region can scan (${out#"$ROOT"/})"
    fi
    say "  (${program##*/} wrote $deepest bytes of a $kib KiB region;" \
        "repeating with $((kib * 2)) KiB)"
    discarded=$((discarded + 1))
    sed -n "s/^hits repeat=\([0-9][0-9]*\) /hits repeat=d$discarded-\1 /p" \
      "$out" >> "$out.discarded"
    kib=$((kib * 2))
  done
  cat "$out.discarded" >> "$out"
  rm -f "$out.discarded"
  KIB_USED=$kib
}

# Runs the driver of tree $1 on case $2 in mode $3 (raise or normal),
# into file $4, and checks the bookkeeping (label $5). Appends the region
# used to REGIONS.
probe_case () {
  local tree=$1 which=$2 mode=$3 out=$4 label=$5
  run_probe "$tree/driver/bin/exception_stack" "$out" \
    $((PROBE_KIB + SPACER_KIB)) "$SPACER_KIB" "$which" "$mode"
  # The variant and the kind of build: the first two words of the label.
  REGIONS="$REGIONS $(printf '%s' "$label" | awk '{ print $1 "/" $2 }')=$KIB_USED"
  check_runs "$out" "$label" "$mode" \
    || harness_error "bad run ($label; see ${out#"$ROOT"/})"
}

case_name () {
  case $1 in
    A) echo "A (Argon2.Compression.Compress; raise in Store_G after the permutation; A': spill there)" ;;
    B) echo "B (Argon2.H_Prime.Hash; raise in Initial_Hash after Update (S, Input))" ;;
    C) echo "C (Argon2.H_Prime.Hash; raise in Blake2b.Core.Compress after round 6, in Final)" ;;
  esac
}

# Prints one build's counts for run $4 of file $3 (label $2), and records
# the most hits of any repeat as result $1 (see most).
show () {
  local key=$1 label=$2 file=$3 run=$4 result hits per_repeat
  result=$(summarise "$file" "$run")
  read -r _ hits per_repeat <<< "${result%%|*}"
  echo "  $label: hits per repeat $per_repeat (most: ${result#*|});" \
       "stack written up to $(touched "$file" "$run") bytes"
  printf -v "MOST_${key//[^A-Za-z0-9]/_}" '%s' "$hits"
}

# The result recorded as $1 by show (bash 3 has no associative arrays).
most () {
  local name="MOST_${1//[^A-Za-z0-9]/_}"
  [ -n "${!name:-}" ] || harness_error "no result recorded for $1"
  echo "${!name}"
}

# The verdicts, collected over the whole scan.
blind_normal=""   # normal-return controls that saw nothing (exit 1)
failed=""         # gated normal-return results that failed (exit 3)
unmeasured=""     # exception results whose control saw nothing (notice)
exception_hits="" # hardened hits after an exception (reported only)

summary () { echo "  summary: $1 $2 $3: control $4, hardened $5: $6"; }

# Judges and prints the normal-return result of case $2 (B or C) in
# profile $1, build kind $3, with control hits $4 and hardened hits $5.
judge_hash_normal () {
  local profile=$1 which=$2 kind=$3 c=$4 h=$5 verdict
  if [ "$h" -gt 0 ]; then
    failed="$failed $profile/$which/normal-$kind"
    verdict="FAIL: the hardened build left canaries after a normal return"
  elif [ "$c" -gt 0 ]; then
    verdict="pass: none left (the control left some)"
  else
    verdict="pass: none left in either build (the control is not discriminating here)"
  fi
  summary "$profile" "$which" "normal-$kind" "$c" "$h" "$verdict"
}

# Judges and prints the exception result of case $2 in profile $1, with
# control hits $3 and hardened hits $4. Never gated.
judge_exception () {
  local profile=$1 which=$2 c=$3 h=$4
  if [ "$c" -eq 0 ]; then
    unmeasured="$unmeasured $profile/$which"
    summary "$profile" "$which" exception "$c" "$h" \
      "UNMEASURED: the control left no canary after the exception, so the hardened count is not a measurement (reported only)"
  else
    [ "$h" -eq 0 ] || exception_hits="$exception_hits $profile/$which=$h"
    summary "$profile" "$which" exception "$c" "$h" \
      "measured; reported only (H-2 claims nothing for an exception)"
  fi
}

start=$(date +%s)
for profile in "$@"; do
  # The shipped sources: normal returns, and the task abort.
  for variant in control hardened; do
    tree="$WORK/$variant-shipped"
    prepare "$tree" "$variant" none
    build "$tree" "$profile" "$WORK/$variant-shipped-$profile.build.log"
  done

  for which in $CASES; do
    [ "$which" != T ] || continue
    REGIONS=""
    for variant in control hardened; do
      probe_case "$WORK/$variant-shipped" "$which" normal \
        "$WORK/$variant-shipped-$profile-$which.out" \
        "$variant shipped $profile $which"
    done
    for variant in control control-noflatten hardened; do
      [ "$variant" != control-noflatten ] || [ "$which" = A ] || continue
      tree="$WORK/$variant"
      prepare "$tree" "$variant" "$which"
      build "$tree" "$profile" "$WORK/$variant-$profile-$which.build.log"
      probe_case "$tree" "$which" raise "$WORK/$variant-$profile-$which.out" \
        "$variant injected $profile $which"
    done
    if [ "$which" = A ]; then
      for variant in control hardened; do
        tree="$WORK/$variant"
        prepare "$tree" "$variant" S
        build "$tree" "$profile" "$WORK/$variant-$profile-S.build.log"
        probe_case "$tree" A normal "$WORK/$variant-$profile-S.out" \
          "$variant spill $profile A'"
      done
    fi

    say "case $(case_name "$which"), $profile profile (region KiB:$REGIONS):"
    for variant in control control-noflatten hardened; do
      out="$WORK/$variant-$profile-$which.out"
      [ -f "$out" ] || continue
      show "$profile/$which/$variant/exception" \
        "$variant: exception (injected build)" "$out" raise
      show "$profile/$which/$variant/normal-injected" \
        "$variant: normal (injected build)" "$out" normal
    done
    for variant in control hardened; do
      show "$profile/$which/$variant/normal-shipped" \
        "$variant: normal (shipped sources)" \
        "$WORK/$variant-shipped-$profile-$which.out" normal
    done
    if [ "$which" = A ]; then
      for variant in control hardened; do
        show "$profile/A/$variant/spill" "$variant: normal (A' spill build)" \
          "$WORK/$variant-$profile-S.out" normal
      done
    fi

    c=$(most "$profile/$which/control/exception")
    h=$(most "$profile/$which/hardened/exception")
    judge_exception "$profile" "$which" "$c" "$h"
    case $which in
      A)
        c=$(most "$profile/A/control/spill")
        h=$(most "$profile/A/hardened/spill")
        if [ "$c" -eq 0 ]; then
          blind_normal="$blind_normal $profile/A'"
          spill_seen=no
          verdict="BLIND: the control's spilled words were not found, so the scan is not shown to see what a normal return leaves here"
        else
          spill_seen=yes
          verdict="the control's spilled words were found"
        fi
        if [ "$h" -gt 0 ]; then
          failed="$failed $profile/A'/normal-spill"
          verdict="$verdict; FAIL: the hardened build left spilled words (strub did not scrub them)"
        elif [ "$spill_seen" = yes ]; then
          verdict="pass: $verdict, and the hardened build scrubbed them"
        else
          verdict="$verdict; the hardened build left none (not a measurement)"
        fi
        summary "$profile" "A'" normal-spill "$c" "$h" "$verdict"
        for kind in shipped injected; do
          c=$(most "$profile/A/control/normal-$kind")
          h=$(most "$profile/A/hardened/normal-$kind")
          if [ "$h" -gt 0 ]; then
            failed="$failed $profile/A/normal-$kind"
            verdict="FAIL: the hardened build left canaries after a normal return, where the crate claims none"
          elif [ "$spill_seen" = yes ]; then
            verdict="pass: none left (the scan's sensitivity at a normal return is shown by A')"
          else
            verdict="none left, but A' is blind in this profile, so this is not a measurement"
          fi
          summary "$profile" A "normal-$kind" "$c" "$h" "$verdict"
        done
        ;;
      B|C)
        for kind in shipped injected; do
          c=$(most "$profile/$which/control/normal-$kind")
          h=$(most "$profile/$which/hardened/normal-$kind")
          judge_hash_normal "$profile" "$which" "$kind" "$c" "$h"
        done
        ;;
    esac
  done

  # Task abort, on the shipped sources.
  case " $CASES " in
    *" T "*) ;;
    *) continue ;;
  esac
  say "task abort (ATC around a loop of Compress, shipped sources)," \
      "$profile profile:"
  for variant in control hardened; do
    tree="$WORK/$variant-shipped"
    out="$WORK/$variant-shipped-$profile-abort.out"
    REPEATS=1 run_probe "$tree/driver/bin/abort_stack" "$out" "$PROBE_KIB" \
      "$ABORT_TRIALS"
    awk -v variant="$variant" '
      $1 == "hits" {
        delete f
        for (i = 2; i <= NF; i++) { split($i, kv, "="); f[kv[1]] = kv[2] }
        key = f["run"] SUBSEP f["trial"]
        if (!(key in seen)) {
          seen[key] = 1; trials[f["run"]]++
          if (f["aborted"] == "yes") aborted[f["run"]]++
        }
        # the most of any batch (a discarded batch has repeat=d...)
        n = f["aligned"] + f["unaligned"]
        batch[key, f["repeat"]] += n
        if (batch[key, f["repeat"]] > hits[key]) hits[key] = batch[key, f["repeat"]]
        if (f["trial"] + 0 > last) last = f["trial"] + 0
      }
      END {
        for (r = 1; r <= 2; r++) {
          run = (r == 1 ? "abort" : "quiet")
          list = ""
          for (t = 1; t <= last; t++) list = list sprintf(" %d", hits[run, t])
          printf "  %s: %s: %d trials, %d interrupted before the loop" \
                 " ended; hits per trial:%s\n", variant, run, trials[run],
                 aborted[run] + 0, list
        }
      }' "$out"
  done
done
say "time: $(( $(date +%s) - start )) s"

if [ -n "$exception_hits" ]; then
  say "after an exception (reported only), hardened hits in:$exception_hits"
fi
if [ -n "$unmeasured" ]; then
  say "NOTICE: exception results unmeasured on this platform (the control" \
      "left no canary after the exception) in:$unmeasured"
fi
if [ -n "$blind_normal" ]; then
  say "BLIND: a normal-return control left no canary in:$blind_normal;" \
      "compression's normal-return results there are not a" \
      "measurement${failed:+ (failed besides:$failed)}"
  exit 1
fi
if [ -n "$failed" ]; then
  say "FAILED: a hardened build left canaries after a normal return in:$failed"
  exit 3
fi
say "passed: no hardened build left a canary after a normal return"
exit 0
