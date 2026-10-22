#!/usr/bin/env bash
# Object-code check for H0, H', block compression and indexing: the
# compiled code must hold no trace of the proof, and must carry its
# hardening. Run it after a build, through `alr exec` (see Usage); it reads
# the objects of each profile named on the command line (default: release
# and validation, the two the README's commands build).
#
# For obj/<profile>/argon2-h0.o (Compute carries GCC's strub ("internal"),
# zero_call_used_regs ("all") and flatten attributes, and every helper in
# the body is Inline_Always):
#   * the hardening checks below, as for compression, with Compute the one
#     entry point. One function besides is allowed outside the scrubbed
#     frame: argon2__h0__parametersIP, the initialisation procedure GNAT
#     generates for the body's record type Parameters (Compute builds its
#     Parameters with an aggregate and does not call it), and only while
#     its whole code is one return instruction (with at most a landing pad
#     before it and padding after it): it reads and writes nothing. Any
#     other instruction in it fails the check by name;
#   * it fails on any symbol, defined or referenced, that names:
#       - System.Soft_Links, or abort deferral (Abort_Defer,
#         Abort_Undefer): the cleanup a static ghost loop invariant once
#         left behind;
#       - the secondary stack;
#       - big integers (Ada.Numerics.Big_Numbers), BLAKE2b's ghost counter;
#       - the proof model: Argon2.H0_Model, Blake2b.Streaming (and its
#         Theory), Blake2b.Spec, Blake2b.Hashing.Model, Absorbed,
#         Max_Input.
# It also checks that the object defines (a text symbol, not a reference to)
# Argon2.H0.Compute, so that an empty or unreadable object cannot pass.
#
# For obj/<profile>/argon2-h_prime.o (Hash carries GCC's strub
# ("internal"), zero_call_used_regs ("all") and flatten attributes, and
# every helper in the body is Inline_Always):
#   * the hardening checks below, as for compression, with Hash the one
#     entry point;
#   * the same proof and abort-deferral residue as argon2-h0.o but not the
#     secondary stack, which its LE32 function uses for the 4-byte output
#     length (not secret), nor Argon2.H0_Model: no soft_links,
#     abort_defer, abort_undefer, big integer, streaming-theory, Spec or
#     absorbed-counter symbol.
#
# For obj/<profile>/argon2-compression.o (Compress and Compress_Xor carry
# the same three attributes, and every helper in the body is
# Inline_Always), the hardening checks, which are:
#   * each entry point is a defined text symbol (the wrapper strub
#     "internal" makes), and has its strub clone, a defined text symbol
#     <name>.strub.<n> (the wrapped body);
#   * register clearing: at every return of each wrapper (the entry point
#     its callers return through), at least the registers that
#     zero_call_used_regs ("all") zeroes for this target hold zero: zeroed
#     after the last call, branch or branch target before the return, and
#     not written again (zeroed-at-return.awk; a function with an indirect
#     jump has none). The set is measured, not hard-coded: a probe
#     function with the attribute is compiled by the same toolchain's gcc
#     for the same target, so the check holds for each ABI CI runs (x86-64
#     SysV and Windows, AArch64 Linux and macOS). The clone is not checked
#     on its own: it returns into the wrapper, which clears the registers;
#   * the whole computation is inside the scrubbed frame: the object
#     defines no function but the wrappers and their clones (an empty
#     procedure the unit names, as for H0's Parameters, aside; and the
#     cold part GCC may split off a function, <name>.cold, which runs in
#     that function's frame; a cold part with a return must pass the
#     register check at it, like a wrapper, and the cold parts with no
#     return are listed). Any other defined function, a helper left
#     out of line, fails the check by name, unless it is itself hardened
#     the same way: it has its own strub clone and passes the register
#     check. Section symbols (COFF) and assembler temporaries (Mach-O
#     ltmp<n>) are not functions and are ignored;
#   * no data copied outside the scrubbed frame: the object must not
#     reference memcpy or memmove (nor their fortified forms), the calls
#     GCC makes for a whole-array assignment (a block, or an H' chain
#     value), which would copy the data in a libc frame that is not
#     scrubbed. The failure names them. The other functions the object
#     calls in other units (BLAKE2b, the wipe, memset for a zeroing
#     aggregate, the secondary stack; with checks on, the run-time's
#     check-failure and exception-propagation routines) are listed, not
#     checked: they run outside the scrubbed frame;
#   * not checked: how much of the stack the wrapper scrubs (GCC scrubs
#     the clone's frame), nor what the listed external calls leave behind.
# For compression, also the proof-residue list of argon2-h0.o, with
# Argon2.Compression_Model and Argon2.H_Prime_Model added: no soft_links or
# abort-deferral calls (compression is the hot loop), no secondary stack, no
# big integer, model, streaming-theory or Spec symbol.
# The register check reads the code (objdump -d), so it needs the
# toolchain's gcc and an objdump for the target; the rest reads symbol
# names (nm).
#
# For obj/<profile>/argon2-h0_model.o, argon2-h_prime_model.o and
# argon2-indexing_model.o (static ghost code only), the only external
# symbol must be the package's elaboration flag, no function may be
# defined, local or global, and nothing may be referenced. For
# argon2-compression_model.o, the elaboration flag and the initialisation
# procedure of its type Positions (see below), no other function, and
# nothing referenced. (No symbol but these means no big-integer or ghost
# symbol either.)
#
# For obj/<profile>/argon2-indexing.o (Locate and Next_Address_Block are
# Inline_Always, and the rest of the body is static ghost code or
# Inline_Always helpers, so that the code runs in its caller's scrubbed
# frame):
#   * in the release profile, the object defines no function (a text
#     symbol, global or local, other than a section symbol or a Mach-O
#     assembler temporary): any one fails the check by name. In the
#     validation profile the functions it defines are listed (measured),
#     not checked. Whether the caller's scrubbed frame holds the inlined
#     code is the caller's check, not this one;
#   * in every profile, it fails on any symbol, defined or referenced,
#     that names the proof residue listed for compression, the indexing
#     model (Argon2.Indexing_Model), BLAKE2b's ghost big-integer
#     conversions (Blake2b.Hashing.Big), or one of the unit's own ghost
#     subprograms (its lemmas and Same_Block); the references it makes to
#     other units are listed;
#   * it checks that the object defines the package's elaboration flag, so
#     that an empty or unreadable object cannot pass.
#
# Before reading the crate's objects, the script checks its own symbol
# reading against control objects compiled by the same gcc for the same
# target (so in each object format CI meets: Mach-O, ELF, COFF): one that
# holds only an elaboration flag must pass the indexing check and the
# elaboration-flag-only check; one with a planted global function, one with
# a planted local function and one that references a big-integer symbol
# must each fail the indexing check (naming the planted symbol); and one
# with a planted function besides the flag must fail the
# elaboration-flag-only check. A control that does not behave so stops the
# run (exit 2): the checks would be blind.
#
# Usage: alr -C tests -n exec -- bash ../scripts/check-h0-object.sh [profile ...]
#        NM=/path/to/nm OBJDUMP=/path/to/objdump PROBE_CC=/path/to/gcc \
#          bash scripts/check-h0-object.sh release
# (Inside `alr exec`, gcc is the toolchain's. On macOS objdump is the
# system's LLVM objdump, which reads the Mach-O objects; elsewhere it is
# the toolchain's GNU objdump.)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NM=${NM:-nm}
OBJDUMP=${OBJDUMP:-objdump}
PROBE_CC=${PROBE_CC:-gcc}
if [ "$#" -eq 0 ]; then
  set -- release validation
fi

FORBIDDEN='soft_links|abort_defer|abort_undefer|secondary_stack'
FORBIDDEN="$FORBIDDEN|big_numbers|big_integer|h0_model|blake2b__streaming"
FORBIDDEN="$FORBIDDEN|blake2b__spec|blake2b__hashing__model"
FORBIDDEN="$FORBIDDEN|blake2b__hashing__absorbed|blake2b__hashing__max_input"
COMPRESSION_FORBIDDEN="$FORBIDDEN|compression_model|h_prime_model"
INDEXING_FORBIDDEN="$COMPRESSION_FORBIDDEN|indexing_model|blake2b__hashing__big"
INDEXING_FORBIDDEN="$INDEXING_FORBIDDEN|argon2__indexing__lemma_"
INDEXING_FORBIDDEN="$INDEXING_FORBIDDEN|argon2__indexing__same_block"

# Disassembly. LLVM hides Mach-O function symbols behind section-start
# aliases unless all symbols are requested. GNU AArch64 objdump also
# supports the option, but it exposes ELF mapping symbols ($d/$x) within
# functions, interrupting the function boundaries the register parser
# tracks; GNU's default output already labels the functions correctly.
# (As in blake2b's scripts/check-hardening.sh.)
objdump_help=$("$OBJDUMP" --help)
objdump_version=$("$OBJDUMP" --version)
disassembly_args=(-d --no-show-raw-insn)
if grep -qi 'LLVM' <<< "$objdump_version" &&
   grep -q -- '--show-all-symbols' <<< "$objdump_help"; then
  disassembly_args+=(--show-all-symbols)
fi
disassemble () {
  "$OBJDUMP" "${disassembly_args[@]}" "$1"
}

# The registers zero_call_used_regs ("all") zeroes on this target, measured
# once with a probe compiled by the toolchain's gcc. Another compiler (the
# system's clang answers to gcc on macOS) could zero a different set, so
# the probe compiler must be GCC.
if ! "$PROBE_CC" -v 2>&1 | grep -q '^gcc version'; then
  echo "check-h0-object: $PROBE_CC is not GCC; run the script through" \
       "\`alr exec\` (see its Usage) or set PROBE_CC"
  exit 2
fi
probe_dir="$ROOT/obj/hardening-probe"
mkdir -p "$probe_dir"
printf '%s\n' \
  '__attribute__ ((zero_call_used_regs ("all")))' \
  'void argon2_hardening_probe (void) { }' > "$probe_dir/probe.c"
"$PROBE_CC" -O2 -c "$probe_dir/probe.c" -o "$probe_dir/probe.o"
probe_dis=$(disassemble "$probe_dir/probe.o")
printf '%s\n' "$probe_dis" > "$probe_dir/probe.dis"
want=$(awk -v fn=argon2_hardening_probe \
           -f "$ROOT/scripts/zeroed-at-return.awk" <<< "$probe_dis")
want=${want#ret:}
if [ "$want" = none ] || [ -z "${want// /}" ]; then
  echo "check-h0-object: could not measure the registers" \
       "zero_call_used_regs zeroes (probe disassembly in" \
       "${probe_dir#"$ROOT"/}/probe.dis)"
  "$PROBE_CC" --version >&2
  printf '%s\n' "$objdump_version" >&2
  exit 2
fi
echo "check-h0-object: call-used registers on this target:$want"

# Prints the registers of $want that do not hold zero at some return of
# function $2 in disassembly $1 (see zeroed-at-return.awk; "none" if the
# function has no return); prints nothing if every return zeroes all.
not_cleared () {
  local dis=$1 fn=$2 rets ret reg missing=""
  rets=$(awk -v fn="$fn" -f "$ROOT/scripts/zeroed-at-return.awk" <<< "$dis")
  if [ "$rets" = none ]; then
    echo none
    return
  fi
  while IFS= read -r ret; do
    for reg in $want; do
      case " ${ret#ret:} |$missing " in
        *" $reg "*) ;;
        *) missing="$missing $reg" ;;
      esac
    done
  done <<< "$rets"
  printf '%s' "$missing"
}

# Prints the instructions of function $2 in disassembly $1 that are not
# one return instruction, alone, with at most a landing pad (endbr64, bti)
# before it and padding (nop, int3) before or after it (the Windows build
# of the validation profile emits "nop; ret"); prints "none" if the
# function is not in the disassembly or has no return. Prints nothing for a
# lone return.
not_lone_return () {
  awk -v fn="$2" '
    { sub(/\r$/, "") }
    /^[0-9a-fA-F]+ <[^>]+>:[ \t]*$/ {
      name = $0
      sub(/^[0-9a-fA-F]+ </, "", name); sub(/>:[ \t]*$/, "", name)
      name = tolower(name)
      if (name == fn || name == "_" fn) { inside = 1; seen = 1; next }
      # Another label at the same address (a Mach-O section-start alias)
      # before any instruction does not end the function.
      if (inside && n > 0) inside = 0
      next
    }
    inside && /^[ \t]+[0-9a-fA-F]+:/ {
      line = $0
      sub(/^[ \t]+[0-9a-fA-F]+:[ \t]*/, "", line)
      sub(/[ \t]*(\/\/|;).*$/, "", line)
      sub(/[ \t][ \t]+#.*$/, "", line)
      if (line == "") next
      insn[++n] = line
    }
    END {
      if (!seen) { print "none"; exit }
      ret = 0; bad = ""
      for (i = 1; i <= n; i++) {
        m = tolower(insn[i])
        gsub(/[ \t]+/, " ", m)
        sub(/^(data16 |cs |rep |repz )+/, "", m)
        if (!ret && m ~ /^(endbr64|endbr32|bti( [cj]+)?)$/) continue
        if (!ret && m ~ /^ret[lqw]?$/) { ret = 1; continue }
        if (m ~ /^nop[wlq]?( |$)/ || m == "int3" || m ~ /^xchg %ax, ?%ax$/) continue
        bad = bad "; " insn[i]
      }
      if (!ret) { print "none"; exit }
      if (bad != "") print substr(bad, 3)
    }' <<< "$1"
}

# The hardening checks of a unit whose whole computation runs in scrubbed
# frames (compression, H', H0): check_scrubbed PROFILE OBJECT SYMBOLS EMPTY
# ENTRY..., where SYMBOLS is nm's output for OBJECT, EMPTY is the
# space-separated list of the encoded (lower-case) names of compiler-
# generated procedures that may stand outside the scrubbed frame while
# their code is a lone return (or empty), and each ENTRY is the encoded
# name of an entry point that carries strub ("internal"),
# zero_call_used_regs ("all") and flatten. Sets status to 1 on a failure;
# exits 2 if an entry point is not defined (an unreadable object). See the
# header for what each step checks.
check_scrubbed () {
  local profile=$1 object=$2 symbols=$3 empty=$4
  shift 4
  local obj_name dis name entry clones missing prefix functions fn base
  local stray hardened cold_parts cold_noret cold_cleared cold_missing
  local external copies wrapper is_entry empty_found extra
  obj_name=${object##*/}
  dis=$(disassemble "$object")
  for name in "$@"; do
    entry=${name##*__}
    # The wrapper keeps the entry point's own name; strub ("internal")
    # moves the body into a local clone, <name>.strub.<n>.
    if ! printf '%s\n' "$symbols" \
         | awk -v n="$name" 'tolower($NF) ~ ("^_?" n "$") && $(NF - 1) ~ /^[Tt]$/ { ok = 1 } END { exit !ok }'; then
      echo "check-h0-object: $profile: $obj_name does not" \
           "define $name (unreadable object?)"
      exit 2
    fi
    clones=$(printf '%s\n' "$symbols" \
      | awk -v n="$name" '$(NF - 1) ~ /^[Tt]$/ && tolower($NF) ~ ("^_?" n "\\.strub\\.") { s = $NF; sub(/^_/, "", s); print s }')
    if [ -z "$clones" ]; then
      echo "check-h0-object: $profile: $obj_name: MISSING" \
           "strub clone of $entry"
      status=1
    else
      echo "check-h0-object: $profile: $obj_name: strub clone" \
           "present: $entry"
    fi
    missing=$(not_cleared "$dis" "$name")
    if [ "$missing" = none ]; then
      echo "check-h0-object: $profile: $obj_name: MISSING:" \
           "no return found in $entry"
      status=1
    elif [ -n "$missing" ]; then
      echo "check-h0-object: $profile: $obj_name: NOT" \
           "cleared on return from $entry:$missing"
      status=1
    else
      echo "check-h0-object: $profile: $obj_name: registers" \
           "cleared on return: $entry"
    fi
  done
  # The whole computation inside the scrubbed frame: no function defined
  # here but the wrappers, their clones and the cold parts of either. Names
  # are compared without the leading underscore of Mach-O, and sorted
  # bytewise, so that a function comes before its clone and cold part.
  prefix=$(printf '%s\n' "$symbols" \
    | awk -v n="_$1" '$(NF - 1) ~ /^[Tt]$/ && tolower($NF) == n { print "_"; exit }')
  functions=$(printf '%s\n' "$symbols" | awk -v p="$prefix" '
    NF >= 3 && $(NF - 1) ~ /^[Tt]$/ {
      s = $NF
      # A COFF section symbol (.text, .text$name) or a Mach-O assembler
      # temporary (ltmp<n>) labels a section, not a function.
      if (s ~ /^\./ || s ~ /^ltmp[0-9]+$/) next
      if (p != "" && substr(s, 1, 1) == p) s = substr(s, 2)
      print tolower(s)
    }' | LC_ALL=C sort -u)
  stray=""
  hardened=""
  empty_found=""
  cold_parts=""
  cold_noret=""
  cold_cleared=""
  for fn in $functions; do
    # A cold part runs in its function's frame, but a return from it
    # leaves that frame like any other: it must clear the registers too.
    # Most cold parts cannot return (they end in a call that raises or
    # unwinds); those are listed as such.
    if [[ $fn =~ \.cold(\.[0-9]+)?$ ]]; then
      cold_parts="$cold_parts $fn"
      if ! grep -qE "^[0-9a-fA-F]+ <_?${fn//./\\.}>:" <<< "$dis"; then
        echo "check-h0-object: $profile: $obj_name: cold part" \
             "$fn is not in the disassembly"
        status=1
      elif [[ $fn =~ \.strub\.[0-9]+\.cold(\.[0-9]+)?$ ]]; then
        # Like the clone itself, its cold part returns into the wrapper,
        # which zeroes the registers afterwards: not checked on its own.
        cold_noret="$cold_noret $fn"
      else
        cold_missing=$(not_cleared "$dis" "$fn")
        if [ "$cold_missing" = none ]; then
          cold_noret="$cold_noret $fn"
        elif [ -n "$cold_missing" ]; then
          echo "check-h0-object: $profile: $obj_name: NOT" \
               "cleared on return from cold part $fn:$cold_missing"
          status=1
        else
          cold_cleared="$cold_cleared $fn"
        fi
      fi
    fi
    base=$(sed -E 's/\.cold(\.[0-9]+)?$//; s/\.strub\.[0-9]+$//' <<< "$fn")
    is_entry=""
    for wrapper in "$@"; do
      if [ "$base" = "$wrapper" ]; then
        is_entry=yes
      fi
    done
    if [ -n "$is_entry" ]; then
      continue
    fi
    case " $hardened $stray $empty_found " in
      *" $base "*) continue ;;
    esac
    # A compiler-generated procedure the caller names, outside the
    # scrubbed frame: allowed only while its code is a lone return.
    case " $empty " in
      *" $fn "*)
        extra=$(not_lone_return "$dis" "$fn")
        if [ -z "$extra" ]; then
          empty_found="$empty_found $fn"
        else
          echo "check-h0-object: $profile: $obj_name: $fn is not" \
               "a lone return (instructions: $extra)"
          stray="$stray $fn"
        fi
        continue ;;
    esac
    # A helper left out of line passes only if it is hardened itself: its
    # own strub clone, and the registers cleared at its every return.
    if [ "$base" = "$fn" ] \
       && awk -v b="$base." 'index($0, b "strub.") == 1 && substr($0, length(b) + 7) ~ /^[0-9]+$/ { ok = 1 } END { exit !ok }' <<< "$functions" \
       && [ -z "$(not_cleared "$dis" "$base")" ]; then
      hardened="$hardened $base"
    else
      stray="$stray $base"
    fi
  done
  if [ -n "$stray" ]; then
    echo "check-h0-object: $profile: $obj_name: NOT inlined" \
         "into the scrubbed body (a function of its own, not hardened):$stray"
    status=1
  else
    echo "check-h0-object: $profile: $obj_name: no function" \
         "outside the scrubbed bodies${hardened:+ but hardened helpers:$hardened}"
  fi
  if [ -n "$empty_found" ]; then
    echo "check-h0-object: $profile: $obj_name: outside the scrubbed" \
         "bodies, a lone return (no data):$empty_found"
  fi
  if [ -z "$cold_parts" ]; then
    echo "check-h0-object: $profile: $obj_name: no cold parts"
  elif [ -n "$cold_noret$cold_cleared" ]; then
    echo "check-h0-object: $profile: $obj_name: cold parts" \
         "with no return:${cold_noret:- none}; cold parts whose returns" \
         "clear the registers:${cold_cleared:- none}"
  fi
  external=$(printf '%s\n' "$symbols" \
    | awk -v p="$prefix" '$(NF - 1) == "U" { s = $NF; if (p != "" && substr(s, 1, 1) == p) s = substr(s, 2); printf " %s", s }')
  echo "check-h0-object: $profile: $obj_name: references to" \
       "other units (code outside the scrubbed frame; listed, not" \
       "checked):${external:- none}"
  # Data copied by libc, outside the scrubbed frame: memcpy or memmove (a
  # whole-array assignment), with any leading underscores and the
  # fortified _chk form.
  copies=$(printf '%s\n' "$symbols" \
    | awk '$(NF - 1) == "U" && tolower($NF) ~ /^_*(memcpy|memmove)(_chk)?$/ { printf " %s", $NF }')
  if [ -n "$copies" ]; then
    echo "check-h0-object: $profile: $obj_name: COPIES" \
         "data outside the scrubbed frame: references$copies"
    status=1
  else
    echo "check-h0-object: $profile: $obj_name: no memcpy or" \
         "memmove (no data copied outside the scrubbed frame)"
  fi
}

# The functions that nm's output $1 defines, each after a space: text
# symbols, global (T) or local (t), less the section symbols of COFF
# (.text, .text$name) and Mach-O's assembler temporaries (ltmp<n>), which
# label a section, not a function. Names as nm prints them.
defined_functions () {
  printf '%s\n' "$1" | awk '
    NF >= 3 && $(NF - 1) ~ /^[Tt]$/ {
      s = $NF
      if (s ~ /^\./ || s ~ /^ltmp[0-9]+$/) next
      printf " %s", s
    }'
}

# The indexing checks (see the header) of object $2, read as profile $1:
# the function check is gated only in the release profile. Prints what it
# finds; returns 1 on a failure, 2 if the object does not define
# Argon2.Indexing's elaboration flag (an unreadable object).
check_indexing () {
  local profile=$1 object=$2 obj_name symbols functions external found
  local failed=0
  obj_name=${object##*/}
  symbols=$("$NM" "$object")
  if ! printf '%s\n' "$symbols" \
       | awk 'NF >= 3 && $(NF - 1) != "U" && tolower($NF) ~ /^_?argon2__indexing_e$/ { ok = 1 } END { exit !ok }'; then
    echo "check-h0-object: $profile: $obj_name does not define" \
         "Argon2.Indexing's elaboration flag (unreadable object?)"
    return 2
  fi
  functions=$(defined_functions "$symbols")
  if [ "$profile" = release ]; then
    if [ -n "$functions" ]; then
      echo "check-h0-object: $profile: $obj_name DEFINES a function" \
           "(code outside its caller's frame):$functions"
      failed=1
    else
      echo "check-h0-object: $profile: $obj_name defines no function"
    fi
  else
    echo "check-h0-object: $profile: $obj_name defines (measured, not" \
         "checked):${functions:- no function}"
  fi
  external=$(printf '%s\n' "$symbols" \
    | awk '$(NF - 1) == "U" { printf " %s", $NF }')
  echo "check-h0-object: $profile: $obj_name: references to other units" \
       "(listed, not checked):${external:- none}"
  found=$(printf '%s\n' "$symbols" | grep -iE "$INDEXING_FORBIDDEN" || true)
  if [ -n "$found" ]; then
    echo "check-h0-object: $profile: $obj_name names proof or" \
         "runtime-cleanup symbols:"
    printf '%s\n' "$found" | sed 's/^/  /'
    failed=1
  else
    echo "check-h0-object: $profile: $obj_name clean"
  fi
  return "$failed"
}

# Whether object $2, read as profile $1, holds only what static ghost code
# leaves (see the header): exactly $4 external symbols, all of them
# matching the extended regular expression $3 (on the lower-cased name),
# no function but those, and no reference; $5 says what that is. Prints
# the verdict; returns 1 if the object holds more.
check_flag_only () {
  local profile=$1 object=$2 allowed=$3 expected=$4 what=$5
  local obj_name external defined referenced fn extra=""
  obj_name=${object##*/}
  external=$("$NM" -g "$object" | awk 'NF > 0')
  defined=$(printf '%s\n' "$external" | awk '$(NF - 1) != "U" && NF >= 2')
  referenced=$(printf '%s\n' "$external" | awk '$(NF - 1) == "U"')
  # A local function is not external: read every symbol for those.
  for fn in $(defined_functions "$("$NM" "$object")"); do
    if ! awk '{ print tolower($0) }' <<< "$fn" | grep -qE "$allowed"; then
      extra="$extra $fn"
    fi
  done
  if [ -n "$referenced" ] || [ -n "$extra" ] \
     || [ "$(printf '%s\n' "$defined" | grep -c .)" -ne "$expected" ] \
     || [ "$(printf '%s\n' "$defined" \
             | awk '{ print tolower($NF) }' \
             | grep -cE "$allowed")" -ne "$expected" ]; then
    echo "check-h0-object: $profile: $obj_name holds more than $what:"
    printf '%s\n' "$external" | sed 's/^/  /'
    [ -z "$extra" ] || echo "  functions:$extra"
    return 1
  fi
  echo "check-h0-object: $profile: $obj_name holds only $what"
}

# The controls (see the header): objects compiled from C by the probe's
# gcc, each checked as a release object, must pass or fail as listed.
control_dir="$ROOT/obj/object-check-controls"
rm -rf "$control_dir"
mkdir -p "$control_dir"
flag='char argon2__indexing_E = 1;'
model_flag='char argon2__indexing_model_E = 1;'
planted='int argon2__indexing__planted (int x) { return 3 * x + 1; }'
# name | check (indexing or flag) | outcome (pass or fail) | the symbol a
#   failure must name | the C source (\n stands for a line break)
controls=(
  "flag-only|indexing|pass||$flag"
  "global-function|indexing|fail|argon2__indexing__planted|$flag\n$planted"
  "local-function|indexing|fail|argon2__indexing__planted_local|$flag\n__attribute__ ((used, noinline)) static int argon2__indexing__planted_local (int x) { return 3 * x + 1; }"
  "big-integer|indexing|fail|ada__numerics__big_numbers__big_integers__planted|$flag\nextern char ada__numerics__big_numbers__big_integers__planted;\nchar *argon2__indexing__planted_ref = &ada__numerics__big_numbers__big_integers__planted;"
  "model-flag-only|flag|pass||$model_flag"
  "model-global-function|flag|fail|argon2__indexing_model__planted|$model_flag\nint argon2__indexing_model__planted (int x) { return 3 * x + 1; }"
  "model-local-function|flag|fail|argon2__indexing_model__planted_local|$model_flag\n__attribute__ ((used, noinline)) static int argon2__indexing_model__planted_local (int x) { return 3 * x + 1; }"
)
for c_entry in "${controls[@]}"; do
  IFS='|' read -r c_name c_check c_want c_symbol c_source <<< "$c_entry"
  printf '%b\n' "$c_source" > "$control_dir/$c_name.c"
  "$PROBE_CC" -O2 -c "$control_dir/$c_name.c" -o "$control_dir/$c_name.o"
  c_rc=0
  case $c_check in
    indexing)
      c_out=$(check_indexing release "$control_dir/$c_name.o") || c_rc=$? ;;
    *)
      c_out=$(check_flag_only release "$control_dir/$c_name.o" \
              '^_?argon2__indexing_model_e$' 1 "its elaboration flag") \
        || c_rc=$? ;;
  esac
  printf '%s\n' "$c_out" > "$control_dir/$c_name.log"
  if [ "$c_want" = pass ] && [ "$c_rc" -eq 0 ]; then
    echo "check-h0-object: control $c_name: the $c_check check passes, as it must"
  elif [ "$c_want" = fail ] && [ "$c_rc" -eq 1 ] \
       && grep -q -- "$c_symbol" <<< "$c_out"; then
    echo "check-h0-object: control $c_name: the $c_check check fails, as it" \
         "must, naming $c_symbol"
  else
    echo "check-h0-object: control $c_name: the $c_check check does not" \
         "behave as it must (want $c_want, status $c_rc); its output:"
    printf '%s\n' "$c_out" | sed 's/^/  /'
    "$NM" "$control_dir/$c_name.o" | sed 's/^/  nm: /' || true
    exit 2
  fi
done

status=0
for profile in "$@"; do
  client="$ROOT/obj/$profile/argon2-h0.o"
  model="$ROOT/obj/$profile/argon2-h0_model.o"
  for object in "$client" "$model"; do
    if [ ! -f "$object" ]; then
      echo "check-h0-object: $profile: missing ${object#"$ROOT"/} (build first)"
      exit 2
    fi
  done

  symbols=$("$NM" "$client")
  if ! printf '%s\n' "$symbols" \
       | awk 'tolower($NF) ~ /argon2__h0__compute/ && $(NF - 1) ~ /^[Tt]$/ { ok = 1 } END { exit !ok }'; then
    echo "check-h0-object: $profile: argon2-h0.o does not define" \
         "Argon2.H0.Compute (unreadable object?)"
    exit 2
  fi
  found=$(printf '%s\n' "$symbols" | grep -iE "$FORBIDDEN" || true)
  if [ -n "$found" ]; then
    echo "check-h0-object: $profile: argon2-h0.o names proof or" \
         "runtime-cleanup symbols:"
    printf '%s\n' "$found" | sed 's/^/  /'
    status=1
  else
    echo "check-h0-object: $profile: argon2-h0.o clean"
  fi
  # H0: hardening present (the whole computation in Compute's scrubbed
  # frame; Parameters' initialisation procedure aside, while it is a lone
  # return).
  check_scrubbed "$profile" "$client" "$symbols" \
    argon2__h0__parametersip argon2__h0__compute

  hprime="$ROOT/obj/$profile/argon2-h_prime.o"
  if [ ! -f "$hprime" ]; then
    echo "check-h0-object: $profile: missing ${hprime#"$ROOT"/} (build first)"
    exit 2
  fi
  hp_symbols=$("$NM" "$hprime")
  # H': hardening present (the whole computation in Hash's scrubbed frame),
  # and no proof residue.
  check_scrubbed "$profile" "$hprime" "$hp_symbols" "" argon2__h_prime__hash
  hp_found=$(printf '%s\n' "$hp_symbols" \
    | grep -iE 'soft_links|abort_defer|abort_undefer|big_numbers|big_integer|blake2b__streaming|blake2b__spec|blake2b__hashing__model|blake2b__hashing__absorbed|blake2b__hashing__max_input' || true)
  if [ -n "$hp_found" ]; then
    echo "check-h0-object: $profile: argon2-h_prime.o names proof or" \
         "abort-deferral symbols:"
    printf '%s\n' "$hp_found" | sed 's/^/  /'
    status=1
  else
    echo "check-h0-object: $profile: argon2-h_prime.o clean (secondary" \
         "stack not checked)"
  fi

  # Block compression: hardening present, and no proof residue.
  compression="$ROOT/obj/$profile/argon2-compression.o"
  if [ ! -f "$compression" ]; then
    echo "check-h0-object: $profile: missing" \
         "${compression#"$ROOT"/} (build first)"
    exit 2
  fi
  c_symbols=$("$NM" "$compression")
  check_scrubbed "$profile" "$compression" "$c_symbols" "" \
    argon2__compression__compress argon2__compression__compress_xor
  c_found=$(printf '%s\n' "$c_symbols" \
    | grep -iE "$COMPRESSION_FORBIDDEN" || true)
  if [ -n "$c_found" ]; then
    echo "check-h0-object: $profile: argon2-compression.o names proof or" \
         "runtime-cleanup symbols:"
    printf '%s\n' "$c_found" | sed 's/^/  /'
    status=1
  else
    echo "check-h0-object: $profile: argon2-compression.o clean"
  fi

  # Indexing: no function of its own in the release profile (measured in
  # the others), and no proof residue in any.
  indexing="$ROOT/obj/$profile/argon2-indexing.o"
  if [ ! -f "$indexing" ]; then
    echo "check-h0-object: $profile: missing" \
         "${indexing#"$ROOT"/} (build first)"
    exit 2
  fi
  rc=0
  check_indexing "$profile" "$indexing" || rc=$?
  [ "$rc" -ne 2 ] || exit 2
  [ "$rc" -eq 0 ] || status=1

  # Static ghost code only: the object holds one external symbol, the
  # package's elaboration flag, no function, and references nothing.
  # Argon2.Compression_Model also holds the initialisation procedure GNAT
  # generates for its array type Positions (TpositionsBIP): the type is
  # deliberately not ghost, because the implementation uses it, and the
  # procedure has no data and calls nothing.
  for unit in h0_model h_prime_model compression_model indexing_model; do
    object="$ROOT/obj/$profile/argon2-$unit.o"
    if [ ! -f "$object" ]; then
      echo "check-h0-object: $profile: missing ${object#"$ROOT"/} (build first)"
      exit 2
    fi
    case $unit in
      compression_model)
        allowed="^_?argon2__${unit}_e\$|^_?argon2__${unit}__tpositionsbip\$"
        expected=2
        what="its elaboration flag and Positions' initialisation" ;;
      *)
        allowed="^_?argon2__${unit}_e\$"
        expected=1
        what="its elaboration flag" ;;
    esac
    check_flag_only "$profile" "$object" "$allowed" "$expected" "$what" \
      || status=1
  done
done
exit "$status"
