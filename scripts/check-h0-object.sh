#!/usr/bin/env bash
# Object-code check for H0, H' and block compression: the compiled code
# must hold no trace of the proof, and must carry its hardening. Run it after a build, through `alr exec` (see Usage); it reads
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
# For obj/<profile>/argon2-h0_model.o and argon2-h_prime_model.o (static
# ghost code only), the only external symbol must be the package's
# elaboration flag, and nothing may be referenced. For
# argon2-compression_model.o, the elaboration flag and the initialisation
# procedure of its type Positions (see below), and nothing referenced.
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
# before it and padding (nop, int3) after it; prints "none" if the function
# is not in the disassembly or has no return. Prints nothing for a lone
# return.
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
        if (ret && (m ~ /^nop[wlq]?( |$)/ || m == "int3" || m ~ /^xchg %ax, ?%ax$/)) continue
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

  # Static ghost code only: the object holds one external symbol, the
  # package's elaboration flag, and references nothing.
  # Argon2.Compression_Model also holds the initialisation procedure GNAT
  # generates for its array type Positions (TpositionsBIP): the type is
  # deliberately not ghost, because the implementation uses it, and the
  # procedure has no data and calls nothing.
  for unit in h0_model h_prime_model compression_model; do
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
    external=$("$NM" -g "$object" | awk 'NF > 0')
    defined=$(printf '%s\n' "$external" | awk '$(NF - 1) != "U" && NF >= 2')
    referenced=$(printf '%s\n' "$external" | awk '$(NF - 1) == "U"')
    if [ -n "$referenced" ] \
       || [ "$(printf '%s\n' "$defined" | grep -c .)" -ne "$expected" ] \
       || [ "$(printf '%s\n' "$defined" \
               | awk '{ print tolower($NF) }' \
               | grep -cE "$allowed")" -ne "$expected" ]; then
      echo "check-h0-object: $profile: argon2-$unit.o holds more than" \
           "$what:"
      printf '%s\n' "$external" | sed 's/^/  /'
      status=1
    else
      echo "check-h0-object: $profile: argon2-$unit.o holds only $what"
    fi
  done
done
exit "$status"
