#!/usr/bin/env bash
# Object-code check for H0, H' and block compression: the compiled code
# must hold no trace of the proof, and compression must carry its
# hardening. Run it after a build, through `alr exec` (see Usage); it reads
# the objects of each profile named on the command line (default: release
# and validation, the two the README's commands build).
#
# For obj/<profile>/argon2-h0.o, it fails on any symbol, defined or
# referenced, that names:
#   * System.Soft_Links, or abort deferral (Abort_Defer, Abort_Undefer):
#     the cleanup a static ghost loop invariant once left behind;
#   * the secondary stack;
#   * big integers (Ada.Numerics.Big_Numbers), BLAKE2b's ghost counter;
#   * the proof model: Argon2.H0_Model, Blake2b.Streaming (and its
#     Theory), Blake2b.Spec, Blake2b.Hashing.Model, Absorbed, Max_Input.
# It also checks that the object defines (a text symbol, not a reference to)
# Argon2.H0.Compute, so that an empty or unreadable object cannot pass.
#
# For obj/<profile>/argon2-h_prime.o (H', checked for the same proof and
# abort-deferral residue but not for the secondary stack, which its
# LE32 function uses, nor for Argon2.H0_Model): no soft_links,
# abort_defer, abort_undefer, big integer, streaming-theory, Spec or
# absorbed-counter symbol; and Argon2.H_Prime.Hash must be defined.
#
# For obj/<profile>/argon2-compression.o (Compress and Compress_Xor carry
# GCC's strub ("internal") and zero_call_used_regs ("all") attributes):
#   * each of Compress and Compress_Xor is a defined text symbol (the
#     wrapper strub "internal" makes), and has its strub clone, a defined
#     text symbol <name>.strub.<n> (the wrapped body);
#   * register clearing: at every return of each wrapper (the entry point
#     its callers return through), the instructions after its last call or
#     branch zero at least the registers that zero_call_used_regs ("all")
#     zeroes for this target. The set is measured, not hard-coded: a probe
#     function with the attribute is compiled by the same toolchain's gcc
#     for the same target, so the check holds for each ABI CI runs (x86-64
#     SysV and Windows, AArch64 Linux and macOS). The clone is not checked
#     on its own: it returns into the wrapper, and it may end in a tail
#     call to a helper that is not hardened instead of a return (it does
#     in the validation profile on macOS arm64);
#   * not checked: how much of the stack the wrapper scrubs. It scrubs the
#     clone's frame; helpers the clone calls that are not inlined are not
#     strub functions, and GCC does not scrub their frames;
#   * the proof-residue list of argon2-h0.o, with Argon2.Compression_Model
#     and Argon2.H_Prime_Model added: no soft_links or abort-deferral calls
#     (compression is the hot loop), no secondary stack, no big integer,
#     model, streaming-theory or Spec symbol.
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

# Prints the registers of $want that some return of function $2 in
# disassembly $1 does not zero after its last call or branch ("none" if
# the function has no return); prints nothing if every return zeroes all.
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

  hprime="$ROOT/obj/$profile/argon2-h_prime.o"
  if [ ! -f "$hprime" ]; then
    echo "check-h0-object: $profile: missing ${hprime#"$ROOT"/} (build first)"
    exit 2
  fi
  hp_symbols=$("$NM" "$hprime")
  if ! printf '%s\n' "$hp_symbols" \
       | awk 'tolower($NF) ~ /argon2__h_prime__hash/ && $(NF - 1) ~ /^[Tt]$/ { ok = 1 } END { exit !ok }'; then
    echo "check-h0-object: $profile: argon2-h_prime.o does not define" \
         "Argon2.H_Prime.Hash (unreadable object?)"
    exit 2
  fi
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
  c_dis=$(disassemble "$compression")
  for entry in compress compress_xor; do
    name="argon2__compression__$entry"
    # The wrapper keeps the entry point's own name; strub ("internal")
    # moves the body into a local clone, <name>.strub.<n>.
    if ! printf '%s\n' "$c_symbols" \
         | awk -v n="$name" 'tolower($NF) ~ ("^_?" n "$") && $(NF - 1) ~ /^[Tt]$/ { ok = 1 } END { exit !ok }'; then
      echo "check-h0-object: $profile: argon2-compression.o does not" \
           "define $name (unreadable object?)"
      exit 2
    fi
    clones=$(printf '%s\n' "$c_symbols" \
      | awk -v n="$name" '$(NF - 1) ~ /^[Tt]$/ && tolower($NF) ~ ("^_?" n "\\.strub\\.[0-9]+$") { s = $NF; sub(/^_/, "", s); print s }')
    if [ -z "$clones" ]; then
      echo "check-h0-object: $profile: argon2-compression.o: MISSING" \
           "strub clone of $entry"
      status=1
    else
      echo "check-h0-object: $profile: argon2-compression.o: strub clone" \
           "present: $entry"
    fi
    missing=$(not_cleared "$c_dis" "$name")
    if [ "$missing" = none ]; then
      echo "check-h0-object: $profile: argon2-compression.o: MISSING:" \
           "no return found in $entry"
      status=1
    elif [ -n "$missing" ]; then
      echo "check-h0-object: $profile: argon2-compression.o: NOT" \
           "cleared on return from $entry:$missing"
      status=1
    else
      echo "check-h0-object: $profile: argon2-compression.o: registers" \
           "cleared on return: $entry"
    fi
  done
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
