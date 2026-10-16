#!/usr/bin/env bash
# Object-code check for H0: the compiled Argon2.H0 must hold no trace of
# the proof. Run it after a build; it reads the objects of each profile
# named on the command line (default: release and validation, the two the
# README's commands build).
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
# For obj/<profile>/argon2-h0_model.o and argon2-h_prime_model.o (static
# ghost code only), the only external symbol must be the package's
# elaboration flag, and nothing may be referenced.
#
# Usage: bash scripts/check-h0-object.sh [profile ...]
#        NM=/path/to/nm bash scripts/check-h0-object.sh release
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NM=${NM:-nm}
if [ "$#" -eq 0 ]; then
  set -- release validation
fi

FORBIDDEN='soft_links|abort_defer|abort_undefer|secondary_stack'
FORBIDDEN="$FORBIDDEN|big_numbers|big_integer|h0_model|blake2b__streaming"
FORBIDDEN="$FORBIDDEN|blake2b__spec|blake2b__hashing__model"
FORBIDDEN="$FORBIDDEN|blake2b__hashing__absorbed|blake2b__hashing__max_input"

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

  # Static ghost code only: the object holds one external symbol, the
  # package's elaboration flag, and references nothing.
  for unit in h0_model h_prime_model; do
    object="$ROOT/obj/$profile/argon2-$unit.o"
    if [ ! -f "$object" ]; then
      echo "check-h0-object: $profile: missing ${object#"$ROOT"/} (build first)"
      exit 2
    fi
    external=$("$NM" -g "$object" | awk 'NF > 0')
    defined=$(printf '%s\n' "$external" | awk '$(NF - 1) != "U" && NF >= 2')
    referenced=$(printf '%s\n' "$external" | awk '$(NF - 1) == "U"')
    if [ -n "$referenced" ] \
       || [ "$(printf '%s\n' "$defined" | grep -c .)" -ne 1 ] \
       || ! printf '%s\n' "$defined" | grep -qiE "argon2__${unit}_e\$"; then
      echo "check-h0-object: $profile: argon2-$unit.o holds more than" \
           "its elaboration flag:"
      printf '%s\n' "$external" | sed 's/^/  /'
      status=1
    else
      echo "check-h0-object: $profile: argon2-$unit.o holds only its" \
           "elaboration flag"
    fi
  done
done
exit "$status"
