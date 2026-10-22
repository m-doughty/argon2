#!/usr/bin/env bash
# Mutation suite for H0 (Argon2.H0 and Argon2.H0_Model), for block
# compression (Argon2.Compression and Argon2.Compression_Model) and for
# indexing (Argon2.Indexing, Argon2.Indexing_Model and Argon2.Geometry):
# shows that the proof and the tests each catch the mistakes they are
# supposed to catch, and that the tests catch the mistakes the proof
# cannot see.
# Adapted from the blake2b crate's scripts/mutants.sh. (The file keeps its
# first name.)
#
# First the unmutated crate (the baseline) must build, prove and pass its
# tests under the same settings, or the run stops: otherwise a broken
# toolchain or a missing prover would look like a caught mutant. The
# baseline proves every proved unit (UNITS: H0, compression and H', each
# model and client, the indexing model with the geometry, and indexing)
# from cold, once with every prover and once with each prover alone, and
# every check must cost at most STEP_MARGIN steps (5000,
# half the units' 10000-step budget in argon2.gpr; not configurable) with
# its cheapest prover (scripts/spark-proof.py margin), so a check a mutant
# fails proved in the baseline with at least half its budget to spare; and
# every check must be proved by at least two of the provers each on its
# own (scripts/spark-proof.py coverage), so that none rests on one prover.
# Both gates fail, rather than pass, a unit with no checks, a check with
# no VC tree to cost, and a check missing from a single-prover proof.
#
# Then each mutant changes one or more places in a TEMPORARY COPY of the
# crate (under .mutants/, never the sources). Its entry names the layers
# that must catch it:
#   * P: GNATprove re-runs on the unit named in the entry, under the guard
#     below, and must catch it;
#   * T: the tests are rebuilt and re-run and must catch it (mutants of
#     executable code). Mutants of static ghost code only (a model, the
#     client's lemma calls) change nothing any build compiles, so for them
#     tests are n/a;
#   * S: a shared mutant, the same mistake made in the code and in its
#     static model. Proof shows that the code agrees with the model, not
#     that the model agrees with the RFC, so the proof is expected NOT to
#     catch it: every unit the entry names is re-proved from cold, under
#     the guard, and must still prove (GNATprove exits 0, every check is
#     proved by a prover, scripts/spark-proof.py proved, and no unit was
#     skipped, scripts/check-proof-output.sh). The tests (T) must catch
#     it. A shared mutant whose proof fails (FAILED) is not the same
#     mistake in both, or broke something else: an error in the suite;
#   * T alone: a mutant of executable code that no model states, so that
#     no proof can see it (Data_Independent): no proof is run (n/a), and
#     the tests must catch it.
# The proof is judged strictly, from GNATprove's results file
# (scripts/spark-proof.py judge): caught only when an unproved check lies
# at one of the places the mutant's entry expects (file, line and rule, in
# the mutated copy) and one of its VCs was attempted by every prover in
# PROVERS and failed within the step budget for each. A clean unproved
# check elsewhere is not a catch (a mutant can make a true goal dearer
# without the proof seeing the mistake): MISSED. A proof the guard
# killed, or whose unproved checks failed only through a timeout, memory
# exhaustion, a prover crash or a prover that never ran, is TAINTED: not a
# catch, and it fails the run. The tests catch a mutant only with evidence
# from the mutated unit's own tests: the harness reports failed tests
# (" N passed, M failed" with M > 0) and at least one of them is a test of
# that unit ("FAIL: H0: ..." for an H0 mutant, "FAIL: compression: ..."
# for a compression mutant, "FAIL: indexing: ..." for a mutant of
# indexing, its model or the geometry, whose tests are one group) that
# did not fail through Storage_Error. An exception that escapes the
# harness, or failures only outside the unit's tests, are an ERROR, not a
# catch. The classifier has its own check:
# scripts/h0-mutants.sh --selftest.
#
# The H0 mutants:
#   * field-order: T and m swapped among the hashed fields (code);
#   * field-byte-order: the fields stored big-endian, the local contract
#     changed to match (code). The top byte is written
#     (Value / 2**24) mod 2**8, the same value for a 32-bit Value: written
#     Value / 2**24, Z3 runs on the false assertion into the timeout or
#     the memory guard instead of failing on its step budget (TAINTED);
#   * len-p-omitted: the length field of P never absorbed: Absorb_Field
#     returns at once for it (code). Omitting its call in Compute instead
#     makes Z3 run on the false precondition of Absorb_Input into the
#     timeout or the memory guard (TAINTED);
#   * dropped-final-chunk: each input's last chunk never absorbed (code);
#   * rounded-m: m replaced by the rounded m' = 4p floor (m / 4p) (code);
#   * copy-input-swap: Copy_Input copies S where P belongs and P where S
#     belongs (code);
#   * client-no-bridge: the input-chunk lemma applied to an empty slice
#     instead of the chunk, so the chunk's place is never established
#     (ghost; removing the call outright leaves the lemma unreferenced,
#     which the warning-free build refuses);
#   * model-m-prime: the model hashing m' instead of m, its field lemma
#     changed to match (ghost; the client's proof must fail);
#   * model-le-byte-order: the model's LE_Byte big-endian (ghost; the
#     client's proof must fail);
#   * model-schedule-swap: P's and S's pieces exchanged in the schedule
#     (ghost; the byte-position lemma must fail);
#   * model-formula-field: the formula reading length (S) where length (P)
#     belongs (ghost; the byte-position lemma must fail);
#   * model-length: the message one byte longer than its pieces (ghost).
#
# The compression mutants. Implementation-only (the code wrong, the model
# right; P and T):
#   * c-rot-const: GB's second rotation by 25 instead of 24;
#   * c-rot-dir: GB's third rotation (by 16) to the left instead of the
#     right (not the rotation by 32, which is the same either way);
#   * c-fblamka-factor: fBlaMka without its factor 2;
#   * c-diagonal-call: the fifth GB call, on the diagonal (0, 5, 10, 15),
#     made on (0, 5, 10, 14), its lemma call left as it was;
#   * c-diagonal: the same with the code's lemmas changed to match (the
#     code consistent with itself, not with the model);
#   * c-pass-swap: the row pass applying P to the column groups and the
#     column pass to the row groups (the passes' word mappings swapped at
#     their calls of P);
#   * c-register-transpose: the word lists of rows and columns of the
#     register matrix exchanged (the bodies of Consecutive and Strided).
#     It computes what c-pass-swap computes, through other code, and the
#     proof catches it elsewhere;
#   * c-fused-xor-word: the first loop of Combine, which fills the working
#     block with X xor Y word by word (no block copy), reading word 127 - K
#     of M (Y) instead of word K (linear index arithmetic, no mod);
#   * c-final-xor: the final xor with X xor Y omitted (G = P's output);
#   * c-xor-old-z: Compress_Xor not xoring the old block (it writes G).
# Shared (the same mistake in Argon2.Compression and in
# Argon2.Compression_Model, including the code's lemmas; S and T):
#   * s-rot-const: the rotation by 25 instead of 24;
#   * s-diagonal: the diagonal (0, 5, 10, 14) instead of (0, 5, 10, 15);
#   * s-fblamka-factor: fBlaMka without its factor 2;
#   * s-final-xor: G without its final xor with R = X xor Y.
#
# The indexing mutants. Implementation-only, in Locate (the code wrong,
# the model right; P and T). Locate's proof states each step's agreement
# with the model in a static assertion, so the proof fails at the
# assertion after the wrong step (J2, the reference lane, the area, zz or
# the start), not at the postcondition (an assertion that fails is assumed
# after it):
#   * i-swap-j1-j2: J1 taken from the high half of W and J2 from the low;
#   * i-j2-shift-31: J2 taken as (W / 2**31) mod 2**32, a shift by 31;
#   * i-own-lane-minus-one: in later passes, the own lane's area keeps the
#     previous block (Q - s + Index for Q - s + Index - 1);
#   * i-other-lane-index-0: in pass 0, another lane's area keeps its last
#     block at index 0 (the -1 at index 0 dropped);
#   * i-slice3-start: in later passes, slice 3's area starting at 3 s
#     instead of 0 (written as 4 s it would be 0 mod q: equivalent, not a
#     mutant);
#   * i-mod-lanes-minus-one: the reference lane J2 mod (p - 1);
#   * i-lane-not-forced: the own lane forced in pass 0, slice 0 only when
#     p = 1, where J2 mod p is the own lane anyway: on every position
#     Locate accepts, the same as never forcing it;
# in Next_Address_Block (P and T; the proof fails Input_Word's
# postcondition, that word K of Z_N is the model's, or, for i-one-g, the
# assertion that Scratch (2) is the model's A_N):
#   * i-counter-n-minus-1: word 6 of Z_N is N - 1 instead of N;
#   * i-one-g: one compression instead of two: A_N = G (ZERO, Z_N), the
#     loop of two Compress calls replaced by one call;
#   * i-pass-word-zero: word 0 of Z_N (the pass) left 0 (written
#     Pass * 0, so that the formal stays referenced in the warning-free
#     build);
#   * i-lane-slice-swap: words 1 and 2 of Z_N (lane and slice) swapped;
# in Argon2.Geometry:
#   * i-shape-round-up: Shape_Of's segment rounded up,
#     (m + 4 p - 1) / (4 p) (P and T; the proof fails the assertions in
#     Shape_Of that give its postcondition: s <= 2**30 - 1 and
#     p * 4 s <= m);
#   * i-data-independent-slice-2: Argon2id data-independent in pass 0
#     slice 2 too (T alone: no model states Data_Independent, and no
#     proof uses what it computes; with it, the geometry and indexing
#     still prove).
# Model-only (the model wrong, the code right; P, the check named is the
# one the proof fails):
#   * m-a-minus-yy: zz = |W| - y instead of |W| - 1 - y (the assertion in
#     Relative_Position's body that gives its range postcondition,
#     zz <= |W| - 1);
#   * m-own-lane-minus-one: in later passes, the own lane's area keeps the
#     previous block (the window lemma);
#   * m-other-lane-index-0: in later passes, another lane's area keeps the
#     last block of the slice before at index 0 (the window lemma);
#   * m-pass0-area-plus-i: in pass 0, the own lane's area Slice * s +
#     Index instead of Slice * s + Index - 1 (the window lemma);
#   * m-lane-not-forced: the lane forced in pass 0, slice 0 only when
#     p = 1, as i-lane-not-forced (Lemma_Area's forced-lane clause);
#   * m-j2-shift-31: J2 as (W / 2**31) mod 2**32 (Locate's proof, at its
#     assertion that its J2 is the model's, the step toward its
#     postcondition: the model's own lemmas cannot see it, since every
#     32-bit J2 stays in the range and the window). Written unmasked,
#     U32 (W / 2**31), it fails a range check in the model instead;
#   * m-mod-lanes-minus-one: the reference lane J2 mod (p - 1) (a division
#     check in Reference_Lane, for p = 1, and Lemma_Lane's assertion).
# Shared (the same mistake in Argon2.Indexing and Argon2.Indexing_Model,
# including the code's lemmas; S and T):
#   * s-swap-j1-j2: J1 and J2 swapped;
#   * s-counter-n-minus-1: word 6 of Z_N is N - 1;
#   * s-one-g: A_N = G (ZERO, Z_N), one G: one Compress call, as in
#     i-one-g, the model's Address_Block and the code's lemma for it
#     changed to match;
#   * s-pass-word-zero: word 0 of Z_N left 0.
#
# The guard. Every mutant proof runs under a guard that polls the proof's
# process tree every MUTANT_POLL seconds and kills the whole tree when one
# process, or the tree in total, exceeds MUTANT_RSS_KB of resident memory,
# or the proof exceeds MUTANT_WALL seconds. MUTANT_TIMEOUT bounds each
# prover attempt (mutant proofs and the baseline's): on a false goal a
# prover can run on without ever exhausting its step budget. The crate's
# own proof stays steps-only.
#
# Usage: scripts/h0-mutants.sh            (from anywhere in the crate)
#        scripts/h0-mutants.sh --selftest (the test classifier only)
#        ALR=/path/to/alr PROVE_JOBS=2 scripts/h0-mutants.sh
#        ONLY=field-order,rounded-m scripts/h0-mutants.sh
#        ONLY=c-rot-const,s-rot-const scripts/h0-mutants.sh
#        MUTANT_TIMEOUT=300 MUTANT_RSS_KB=4194304 MUTANT_WALL=3600 \
#          MUTANT_POLL=2 scripts/h0-mutants.sh
# Logs are kept in .mutants/logs/. The crate's CI does not run this
# script.

set -euo pipefail

ALR=${ALR:-alr}
PROVE_JOBS=${PROVE_JOBS:-4}
MUTANT_TIMEOUT=${MUTANT_TIMEOUT:-300}
MUTANT_RSS_KB=${MUTANT_RSS_KB:-4194304}
MUTANT_WALL=${MUTANT_WALL:-3600}
MUTANT_POLL=${MUTANT_POLL:-2}
STEP_MARGIN=5000
ONLY=${ONLY:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK="$ROOT/.mutants"
LOGS="$WORK/logs"
SPARK_PROOF="$ROOT/scripts/spark-proof.py"
PYTHON=${PYTHON:-python3}
PROVERS="z3 cvc5 altergo"
UNITS="argon2-h0_model.adb argon2-h0.adb"
UNITS="$UNITS argon2-compression_model.ads argon2-compression.adb"
UNITS="$UNITS argon2-h_prime_model.ads argon2-h_prime.adb"
UNITS="$UNITS argon2-geometry.adb argon2-indexing_model.adb"
UNITS="$UNITS argon2-indexing.adb"

# name | file | exact text | replacement | unit to prove | must catch |
#   expected unproved checks (FILE:LINE:RULE, comma-separated, as the
#   mutated copy numbers its lines; a change to the sources can move them:
#   rerun with DISCOVER=1 and read each mutant's judge log to update them)
# Entries with the same name are one mutant changing several places; the
# unit, the layers and the expected checks are those of its first entry,
# and the tests that give evidence are those of its first entry's file.
# "Must catch" is P, PT, ST or T (see the header). A P or PT mutant
# proves one unit; an ST mutant names every unit that must still prove,
# separated by spaces, and no expected checks; a T mutant names no unit
# and no expected checks.
# In the text and its replacement, \n stands for a line break.
MUTANTS=(
  "field-order|src/argon2-h0.adb|        when 1 => Pr.Tag_Length,\n        when 2 => Pr.Memory,|        when 1 => Pr.Memory,\n        when 2 => Pr.Tag_Length,|argon2-h0.adb|PT|argon2-h0.adb:427:VC_ASSERT"
  "field-byte-order|src/argon2-h0.adb|        Post   => Bytes (0) = Byte (Value mod 2**8)\n                  and then Bytes (1) = Byte ((Value / 2**8) mod 2**8)\n                  and then Bytes (2) = Byte ((Value / 2**16) mod 2**8)\n                  and then Bytes (3) = Byte (Value / 2**24);|        Post   => Bytes (0) = Byte ((Value / 2**24) mod 2**8)\n                  and then Bytes (1) = Byte ((Value / 2**16) mod 2**8)\n                  and then Bytes (2) = Byte ((Value / 2**8) mod 2**8)\n                  and then Bytes (3) = Byte (Value mod 2**8);|argon2-h0.adb|PT|argon2-h0.adb:432:VC_ASSERT"
  "field-byte-order|src/argon2-h0.adb|        [Byte (Value mod 2**8), Byte ((Value / 2**8) mod 2**8),\n         Byte ((Value / 2**16) mod 2**8), Byte (Value / 2**24)];|        [Byte ((Value / 2**24) mod 2**8), Byte ((Value / 2**16) mod 2**8),\n         Byte ((Value / 2**8) mod 2**8), Byte (Value mod 2**8)];|||"
  "len-p-omitted|src/argon2-h0.adb|      Store_LE32 (Field_Value (Pr, P, S, K, X, Id), Bytes);\n      Lemma_Fields_Of|      if Id = 6 then\n         return;\n      end if;\n      Store_LE32 (Field_Value (Pr, P, S, K, X, Id), Bytes);\n      Lemma_Fields_Of|argon2-h0.adb|PT|argon2-h0.adb:262:VC_POSTCONDITION"
  "dropped-final-chunk|src/argon2-h0.adb|      while Offset < Total loop|      while Total - Offset > Chunk_Bytes loop|argon2-h0.adb|PT|argon2-h0.adb:503:VC_ASSERT"
  "rounded-m|src/argon2-h0.adb|        when 2 => Pr.Memory,|        when 2 =>\n          (if 4 * Pr.Parallelism = 0 then Pr.Memory\n           else 4 * Pr.Parallelism * (Pr.Memory / (4 * Pr.Parallelism))),|argon2-h0.adb|PT|argon2-h0.adb:429:VC_ASSERT"
  "copy-input-swap|src/argon2-h0.adb|         when 10 => Copy_Chunk (P, Offset, Chunk (0 .. Last));\n         when 11 => Copy_Chunk (S, Offset, Chunk (0 .. Last));|         when 10 => Copy_Chunk (S, Offset, Chunk (0 .. Last));\n         when 11 => Copy_Chunk (P, Offset, Chunk (0 .. Last));|argon2-h0.adb|PT|argon2-h0.adb:244:VC_POSTCONDITION"
  "client-no-bridge|src/argon2-h0.adb|         Pr.Kind, P, S, K, X, Id, I64 (Offset), Chunk (0 .. Last));|         Pr.Kind, P, S, K, X, Id, I64 (Offset), Chunk (1 .. 0));|argon2-h0.adb|P|argon2-h0.adb:464:VC_PRECONDITION"
  "model-m-prime|src/argon2-h0_model.ads|     ([0 => Parallelism, 1 => Tag_Length, 2 => Memory, 3 => Passes,|     ([0 => Parallelism, 1 => Tag_Length,\n       2 => (if 4 * Parallelism = 0 then Memory\n             else 4 * Parallelism * (Memory / (4 * Parallelism))),\n       3 => Passes,|argon2-h0.adb|P|argon2-h0.adb:427:VC_ASSERT"
  "model-m-prime|src/argon2-h0_model.ads|                              Kind, P, S, K, X) (2) = Memory|                              Kind, P, S, K, X) (2)\n                   = (if 4 * Parallelism = 0 then Memory\n                      else 4 * Parallelism\n                           * (Memory / (4 * Parallelism)))|||"
  "model-le-byte-order|src/argon2-h0_model.ads|        when 0      => Byte (Field mod 2**8),\n        when 1      => Byte ((Field / 2**8) mod 2**8),\n        when 2      => Byte ((Field / 2**16) mod 2**8),\n        when others => Byte (Field / 2**24))|        when 0      => Byte (Field / 2**24),\n        when 1      => Byte ((Field / 2**16) mod 2**8),\n        when 2      => Byte ((Field / 2**8) mod 2**8),\n        when others => Byte (Field mod 2**8))|argon2-h0.adb|P|argon2-h0.adb:432:VC_ASSERT"
  "model-schedule-swap|src/argon2-h0_model.ads|       8  => (Source => 10, Start => 0, Count => L (10), First => 28),|       8  => (Source => 11, Start => 0, Count => L (10), First => 28),|argon2-h0_model.adb|P|argon2-h0_model.ads:163:VC_POSTCONDITION"
  "model-schedule-swap|src/argon2-h0_model.ads|       10 => (Source => 11, Start => 0, Count => L (11),|       10 => (Source => 10, Start => 0, Count => L (11),|||"
  "model-formula-field|src/argon2-h0_model.ads|      elsif Pos < 28 then LE_Byte (F (6), Pos - 24)|      elsif Pos < 28 then LE_Byte (F (7), Pos - 24)|argon2-h0_model.adb|P|argon2-h0_model.adb:112:VC_ASSERT"
  "model-length|src/argon2-h0_model.ads|     (40 + L (10) + L (11) + L (12) + L (13))|     (41 + L (10) + L (11) + L (12) + L (13))|argon2-h0_model.adb|P|argon2-h0_model.ads:117:VC_POSTCONDITION"
  # Compression: implementation-only mutants (the code wrong, the model
  # right; proof and tests must each catch them).
  "c-rot-const|src/argon2-compression.adb|      VB := Rotate_Right (VB xor VC, 24);|      VB := Rotate_Right (VB xor VC, 25);|argon2-compression.adb|PT|argon2-compression.adb:72:VC_POSTCONDITION"
  "c-rot-dir|src/argon2-compression.adb|      VD := Rotate_Right (VD xor VA, 16);|      VD := Rotate_Left (VD xor VA, 16);|argon2-compression.adb|PT|argon2-compression.adb:72:VC_POSTCONDITION"
  "c-fblamka-factor|src/argon2-compression.adb|      return X + Y + 2 * ((X and 16#FFFF_FFFF#) * (Y and 16#FFFF_FFFF#));|      return X + Y + ((X and 16#FFFF_FFFF#) * (Y and 16#FFFF_FFFF#));|argon2-compression.adb|PT|argon2-compression.adb:57:VC_POSTCONDITION"
  "c-diagonal-call|src/argon2-compression.adb|      GB (R, V (0), V (5), V (10), V (15));|      GB (R, V (0), V (5), V (10), V (14));|argon2-compression.adb|PT|argon2-compression.adb:184:VC_PRECONDITION,argon2-compression.adb:185:VC_PRECONDITION"
  "c-diagonal|src/argon2-compression.adb|          and then Model.Distinct (V (0), V (5), V (10), V (15))|          and then Model.Distinct (V (0), V (5), V (10), V (14))|argon2-compression.adb|PT|argon2-compression.adb:165:VC_POSTCONDITION"
  "c-diagonal|src/argon2-compression.adb|      GB (R, V (0), V (5), V (10), V (15));\n      Lemma_Same_Block (R, Model.GB (Prev, V (0), V (5), V (10), V (15)));|      GB (R, V (0), V (5), V (10), V (14));\n      Lemma_Same_Block (R, Model.GB (Prev, V (0), V (5), V (10), V (14)));|||"
  "c-pass-swap|src/argon2-compression.adb|         P (R, Consecutive (I));\n         pragma Loop_Invariant (Static => R = Model.Rows (Entry_R, I + 1));|         P (R, Strided (I));\n         pragma Loop_Invariant (Static => R = Model.Rows (Entry_R, I + 1));|argon2-compression.adb|PT|argon2-compression.adb:207:VC_PRECONDITION,argon2-compression.adb:208:VC_LOOP_INVARIANT_INIT,argon2-compression.adb:208:VC_LOOP_INVARIANT_PRESERV,argon2-compression.adb:222:VC_PRECONDITION,argon2-compression.adb:223:VC_LOOP_INVARIANT_INIT,argon2-compression.adb:223:VC_LOOP_INVARIANT_PRESERV"
  "c-pass-swap|src/argon2-compression.adb|         P (R, Strided (I));\n         pragma Loop_Invariant (Static => R = Model.Columns (Entry_R, I + 1));|         P (R, Consecutive (I));\n         pragma Loop_Invariant (Static => R = Model.Columns (Entry_R, I + 1));|||"
  "c-register-transpose|src/argon2-compression.adb|   function Consecutive (I : Integer) return Model.Positions\n   is ([16 * I,      16 * I + 1,  16 * I + 2,  16 * I + 3,\n        16 * I + 4,  16 * I + 5,  16 * I + 6,  16 * I + 7,\n        16 * I + 8,  16 * I + 9,  16 * I + 10, 16 * I + 11,\n        16 * I + 12, 16 * I + 13, 16 * I + 14, 16 * I + 15])|   function Consecutive (I : Integer) return Model.Positions\n   is ([2 * I,       2 * I + 1,   2 * I + 16,  2 * I + 17,\n        2 * I + 32,  2 * I + 33,  2 * I + 48,  2 * I + 49,\n        2 * I + 64,  2 * I + 65,  2 * I + 80,  2 * I + 81,\n        2 * I + 96,  2 * I + 97,  2 * I + 112, 2 * I + 113])|argon2-compression.adb|PT|argon2-compression.adb:118:VC_POSTCONDITION,argon2-compression.adb:130:VC_POSTCONDITION"
  "c-register-transpose|src/argon2-compression.adb|   function Strided (I : Integer) return Model.Positions\n   is ([2 * I,       2 * I + 1,   2 * I + 16,  2 * I + 17,\n        2 * I + 32,  2 * I + 33,  2 * I + 48,  2 * I + 49,\n        2 * I + 64,  2 * I + 65,  2 * I + 80,  2 * I + 81,\n        2 * I + 96,  2 * I + 97,  2 * I + 112, 2 * I + 113])|   function Strided (I : Integer) return Model.Positions\n   is ([16 * I,      16 * I + 1,  16 * I + 2,  16 * I + 3,\n        16 * I + 4,  16 * I + 5,  16 * I + 6,  16 * I + 7,\n        16 * I + 8,  16 * I + 9,  16 * I + 10, 16 * I + 11,\n        16 * I + 12, 16 * I + 13, 16 * I + 14, 16 * I + 15])|||"
  "c-fused-xor-word|src/argon2-compression.adb|         R (K) := M (X) (K) xor M (Y) (K);|         R (K) := M (X) (K) xor M (Y) (Word_Index'Last - K);|argon2-compression.adb|PT|argon2-compression.adb:356:VC_LOOP_INVARIANT_INIT,argon2-compression.adb:356:VC_LOOP_INVARIANT_PRESERV"
  "c-final-xor|src/argon2-compression.adb|           xor R (K) xor M (X) (K) xor M (Y) (K);|           xor R (K);|argon2-compression.adb|PT|argon2-compression.adb:294:VC_LOOP_INVARIANT_INIT,argon2-compression.adb:294:VC_LOOP_INVARIANT_PRESERV,argon2-compression.adb:295:VC_LOOP_INVARIANT_INIT,argon2-compression.adb:295:VC_LOOP_INVARIANT_PRESERV,argon2-compression.adb:296:VC_LOOP_INVARIANT_INIT,argon2-compression.adb:296:VC_LOOP_INVARIANT_PRESERV"
  "c-xor-old-z|src/argon2-compression.adb|      Combine (M, X, Y, Z, Accumulate => True, R => Work);|      Combine (M, X, Y, Z, Accumulate => False, R => Work);|argon2-compression.adb|PT|argon2-compression.ads:70:VC_POSTCONDITION,argon2-compression.ads:71:VC_POSTCONDITION"
  # Compression: shared mutants (the same mistake in the code and the
  # static model; the proof must still succeed, the tests must catch them).
  "s-rot-const|src/argon2-compression.adb|      VB := Rotate_Right (VB xor VC, 24);|      VB := Rotate_Right (VB xor VC, 25);|argon2-compression_model.ads argon2-compression.adb|ST|"
  "s-rot-const|src/argon2-compression_model.ads|         B1 : constant Word := Rotate_Right (V (B) xor C1, 24);|         B1 : constant Word := Rotate_Right (V (B) xor C1, 25);|||"
  "s-diagonal|src/argon2-compression.adb|          and then Model.Distinct (V (0), V (5), V (10), V (15))|          and then Model.Distinct (V (0), V (5), V (10), V (14))|argon2-compression_model.ads argon2-compression.adb|ST|"
  "s-diagonal|src/argon2-compression.adb|      GB (R, V (0), V (5), V (10), V (15));\n      Lemma_Same_Block (R, Model.GB (Prev, V (0), V (5), V (10), V (15)));|      GB (R, V (0), V (5), V (10), V (14));\n      Lemma_Same_Block (R, Model.GB (Prev, V (0), V (5), V (10), V (14)));|||"
  "s-diagonal|src/argon2-compression_model.ads|         V5 : constant Block := GB (V4, Pos (0), Pos (5), Pos (10), Pos (15));|         V5 : constant Block := GB (V4, Pos (0), Pos (5), Pos (10), Pos (14));|||"
  "s-fblamka-factor|src/argon2-compression.adb|      return X + Y + 2 * ((X and 16#FFFF_FFFF#) * (Y and 16#FFFF_FFFF#));|      return X + Y + ((X and 16#FFFF_FFFF#) * (Y and 16#FFFF_FFFF#));|argon2-compression_model.ads argon2-compression.adb|ST|"
  "s-fblamka-factor|src/argon2-compression_model.ads|   is (X + Y + 2 * ((X mod 2**32) * (Y mod 2**32)))|   is (X + Y + ((X mod 2**32) * (Y mod 2**32)))|||"
  "s-final-xor|src/argon2-compression.adb|           xor R (K) xor M (X) (K) xor M (Y) (K);|           xor R (K);|argon2-compression_model.ads argon2-compression.adb|ST|"
  "s-final-xor|src/argon2-compression_model.ads|         Xor_Blocks (Z, R))|         Z)|||"
  # Indexing: implementation-only mutants of Locate (the code wrong, the
  # model right; proof and tests must each catch them).
  "i-swap-j1-j2|src/argon2-indexing.adb|      J1    : constant U32 := U32 (W mod 2**32);\n      J2    : constant U32 := U32 (W / 2**32);|      J1    : constant U32 := U32 (W / 2**32);\n      J2    : constant U32 := U32 (W mod 2**32);|argon2-indexing.adb|PT|argon2-indexing.adb:155:VC_ASSERT,argon2-indexing.adb:189:VC_ASSERT"
  "i-j2-shift-31|src/argon2-indexing.adb|      J2    : constant U32 := U32 (W / 2**32);|      J2    : constant U32 := U32 ((W / 2**31) mod 2**32);|argon2-indexing.adb|PT|argon2-indexing.adb:155:VC_ASSERT"
  "i-own-lane-minus-one|src/argon2-indexing.adb|         Area := Q - S.Segment + Index - 1;|         Area := Q - S.Segment + Index;|argon2-indexing.adb|PT|argon2-indexing.adb:183:VC_ASSERT"
  "i-other-lane-index-0|src/argon2-indexing.adb|            Area := Slice * S.Segment + (if Index = 0 then -1 else 0);|            Area := Slice * S.Segment;|argon2-indexing.adb|PT|argon2-indexing.adb:183:VC_ASSERT"
  "i-slice3-start|src/argon2-indexing.adb|      if Pass = 0 or else Slice = 3 then\n         Start := 0;|      if Pass = 0 or else Slice = 3 then\n         Start := (if Pass = 0 then 0 else 3 * S.Segment);|argon2-indexing.adb|PT|argon2-indexing.adb:197:VC_ASSERT"
  "i-mod-lanes-minus-one|src/argon2-indexing.adb|         Ref_Lane := Long_Long_Integer (J2) mod S.Lanes;|         Ref_Lane := Long_Long_Integer (J2) mod (S.Lanes - 1);|argon2-indexing.adb|PT|argon2-indexing.adb:156:VC_DIVISION_CHECK,argon2-indexing.adb:158:VC_ASSERT"
  "i-lane-not-forced|src/argon2-indexing.adb|      if Pass = 0 and then Slice = 0 then\n         Ref_Lane := Lane;|      if Pass = 0 and then Slice = 0 and then S.Lanes = 1 then\n         Ref_Lane := Lane;|argon2-indexing.adb|PT|argon2-indexing.adb:161:VC_ASSERT"
  # Indexing: implementation-only mutants of Next_Address_Block.
  "i-counter-n-minus-1|src/argon2-indexing.adb|         when 6      => Interfaces.Unsigned_64 (N),|         when 6      => Interfaces.Unsigned_64 (N - 1),|argon2-indexing.adb|PT|argon2-indexing.adb:280:VC_POSTCONDITION"
  "i-one-g|src/argon2-indexing.adb|      for Y in Block_Index range 1 .. 2 loop\n         Compression.Compress (Scratch, 0, Y, 2, Work);\n         Lemma_Same_Block (Scratch (0), Model.Zero_Block);\n         if Y = 1 then\n            Lemma_Same_Block (Scratch (2), A1);\n         end if;\n         pragma Loop_Invariant\n           (Scratch (0)'Initialized and then Scratch (1)'Initialized\n            and then Scratch (2)'Initialized);\n         pragma Loop_Invariant\n           (Static =>\n              Zero_Block_Ok (Scratch (0))\n              and then Same_Block (Scratch (0), Model.Zero_Block)\n              and then\n              (if Y = 1 then Same_Block (Scratch (2), A1)\n               else Scratch (2) = Compression_Model.G (Model.Zero_Block, A1)));\n      end loop;|      Compression.Compress (Scratch, 0, 1, 2, Work);\n      Lemma_Same_Block (Scratch (0), Model.Zero_Block);\n      Lemma_Same_Block (Scratch (2), A1);|argon2-indexing.adb|PT|argon2-indexing.adb:371:VC_ASSERT"
  "i-pass-word-zero|src/argon2-indexing.adb|         when 0      => Interfaces.Unsigned_64 (Pass),|         when 0      => Interfaces.Unsigned_64 (Pass) * 0,|argon2-indexing.adb|PT|argon2-indexing.adb:280:VC_POSTCONDITION"
  "i-lane-slice-swap|src/argon2-indexing.adb|         when 1      => Interfaces.Unsigned_64 (Lane),\n         when 2      => Interfaces.Unsigned_64 (Slice),|         when 1      => Interfaces.Unsigned_64 (Slice),\n         when 2      => Interfaces.Unsigned_64 (Lane),|argon2-indexing.adb|PT|argon2-indexing.adb:280:VC_POSTCONDITION"
  # Indexing: implementation-only mutants of the geometry.
  "i-shape-round-up|src/argon2-geometry.adb|      Segment : constant Long_Long_Integer := M / (4 * P);|      Segment : constant Long_Long_Integer := (M + 4 * P - 1) / (4 * P);|argon2-geometry.adb|PT|argon2-geometry.adb:16:VC_ASSERT,argon2-geometry.adb:17:VC_ASSERT"
  "i-data-independent-slice-2|src/argon2-geometry.ads|       or else (V = Argon2id and then Pass = 0 and then Slice < 2));|       or else (V = Argon2id and then Pass = 0 and then Slice <= 2));||T|"
  # Indexing: model-only mutants (the model wrong, the code right; the
  # proof must fail the check each names).
  "m-a-minus-yy|src/argon2-indexing_model.ads|         A - Big_LLI (1) - YY)|         A - YY)|argon2-indexing_model.adb|P|argon2-indexing_model.adb:91:VC_ASSERT"
  "m-own-lane-minus-one|src/argon2-indexing_model.ads|         (if Same_Lane then 3 * S.Segment + Index - 1|         (if Same_Lane then 3 * S.Segment + Index|argon2-indexing_model.adb|P|argon2-indexing_model.ads:371:VC_POSTCONDITION"
  "m-other-lane-index-0|src/argon2-indexing_model.ads|          else 3 * S.Segment + (if Index = 0 then -1 else 0)))|          else 3 * S.Segment))|argon2-indexing_model.adb|P|argon2-indexing_model.ads:371:VC_POSTCONDITION"
  "m-pass0-area-plus-i|src/argon2-indexing_model.ads|          elsif Same_Lane then Slice * S.Segment + Index - 1|          elsif Same_Lane then Slice * S.Segment + Index|argon2-indexing_model.adb|P|argon2-indexing_model.ads:371:VC_POSTCONDITION"
  "m-lane-not-forced|src/argon2-indexing_model.ads|   is (if Pass = 0 and then Slice = 0 then Lane|   is (if Pass = 0 and then Slice = 0 and then S.Lanes = 1 then Lane|argon2-indexing_model.adb|P|argon2-indexing_model.ads:328:VC_POSTCONDITION"
  "m-j2-shift-31|src/argon2-indexing_model.ads|   is (U32 (W / 2**32))|   is (U32 ((W / 2**31) mod 2**32))|argon2-indexing.adb|P|argon2-indexing.adb:155:VC_ASSERT"
  "m-mod-lanes-minus-one|src/argon2-indexing_model.ads|       else Long_Long_Integer (J2 (W)) mod S.Lanes)|       else Long_Long_Integer (J2 (W)) mod (S.Lanes - 1))|argon2-indexing_model.adb|P|argon2-indexing_model.ads:172:VC_DIVISION_CHECK,argon2-indexing_model.adb:117:VC_ASSERT"
  # Indexing: shared mutants (the same mistake in the code and the static
  # model; the proof must still succeed, the tests must catch them).
  "s-swap-j1-j2|src/argon2-indexing.adb|      J1    : constant U32 := U32 (W mod 2**32);\n      J2    : constant U32 := U32 (W / 2**32);|      J1    : constant U32 := U32 (W / 2**32);\n      J2    : constant U32 := U32 (W mod 2**32);|argon2-indexing_model.adb argon2-indexing.adb|ST|"
  "s-swap-j1-j2|src/argon2-indexing_model.ads|   is (U32 (W mod 2**32))|   is (U32 (W / 2**32))|||"
  "s-swap-j1-j2|src/argon2-indexing_model.ads|   function J2 (W : U64) return U32\n   is (U32 (W / 2**32))|   function J2 (W : U64) return U32\n   is (U32 (W mod 2**32))|||"
  "s-counter-n-minus-1|src/argon2-indexing.adb|         when 6      => Interfaces.Unsigned_64 (N),|         when 6      => Interfaces.Unsigned_64 (N - 1),|argon2-indexing_model.adb argon2-indexing.adb|ST|"
  "s-counter-n-minus-1|src/argon2-indexing_model.ads|         when 6      => U64 (N),|         when 6      => U64 (N - 1),|||"
  "s-one-g|src/argon2-indexing.adb|      for Y in Block_Index range 1 .. 2 loop\n         Compression.Compress (Scratch, 0, Y, 2, Work);\n         Lemma_Same_Block (Scratch (0), Model.Zero_Block);\n         if Y = 1 then\n            Lemma_Same_Block (Scratch (2), A1);\n         end if;\n         pragma Loop_Invariant\n           (Scratch (0)'Initialized and then Scratch (1)'Initialized\n            and then Scratch (2)'Initialized);\n         pragma Loop_Invariant\n           (Static =>\n              Zero_Block_Ok (Scratch (0))\n              and then Same_Block (Scratch (0), Model.Zero_Block)\n              and then\n              (if Y = 1 then Same_Block (Scratch (2), A1)\n               else Scratch (2) = Compression_Model.G (Model.Zero_Block, A1)));\n      end loop;|      Compression.Compress (Scratch, 0, 1, 2, Work);\n      Lemma_Same_Block (Scratch (0), Model.Zero_Block);\n      Lemma_Same_Block (Scratch (2), A1);|argon2-indexing_model.adb argon2-indexing.adb|ST|"
  "s-one-g|src/argon2-indexing.adb|             Compression_Model.G\n               (Model.Zero_Block,\n                Compression_Model.G\n                  (Model.Zero_Block,\n                   Model.Address_Input (S, V, Pass, Lane, Slice, N))));|             Compression_Model.G\n               (Model.Zero_Block,\n                Model.Address_Input (S, V, Pass, Lane, Slice, N)));|||"
  "s-one-g|src/argon2-indexing_model.ads|   is (Compression_Model.G\n         (Zero_Block,\n          Compression_Model.G\n            (Zero_Block, Address_Input (S, V, Pass, Lane, Slice, N))))|   is (Compression_Model.G\n         (Zero_Block, Address_Input (S, V, Pass, Lane, Slice, N)))|||"
  "s-pass-word-zero|src/argon2-indexing.adb|         when 0      => Interfaces.Unsigned_64 (Pass),|         when 0      => Interfaces.Unsigned_64 (Pass) * 0,|argon2-indexing_model.adb argon2-indexing.adb|ST|"
  "s-pass-word-zero|src/argon2-indexing_model.ads|         when 0      => U64 (Pass),|         when 0      => U64 (Pass) * 0,|||"
)

copy_crate () {
  local dest=$1
  rm -rf "$dest"
  mkdir -p "$dest/tests"
  cp -R "$ROOT/src" "$ROOT/scripts" "$ROOT/alire.toml" "$ROOT/argon2.gpr" \
        "$dest/"
  # Alire's state, with the pinned dependency already deployed, so that a
  # copy builds without the network.
  [ ! -d "$ROOT/alire" ] || cp -R "$ROOT/alire" "$dest/"
  cp -R "$ROOT/tests/src" "$ROOT/tests/ref" "$ROOT/tests/alire.toml" \
        "$ROOT/tests/argon2_tests.gpr" "$dest/tests/"
  [ ! -d "$ROOT/tests/alire" ] || cp -R "$ROOT/tests/alire" "$dest/tests/"
}

# How many times $2 occurs in file $1, literally (across lines).
occurrences () {
  local content stripped
  content=$(cat "$1"; printf x); content=${content%x}
  stripped=${content//"$2"/}
  echo $(( (${#content} - ${#stripped}) / ${#2} ))
}

# Replaces the one occurrence of $2 in file $1 with $3, literally.
mutate () {
  local file=$1 search=$2 replace=$3
  local content count
  content=$(cat "$file"; printf x); content=${content%x}
  count=$(occurrences "$file" "$search")
  if [ "$count" -ne 1 ]; then
    echo "  mutation site found $count times (want exactly 1): $search"
    return 1
  fi
  printf '%s' "${content/"$search"/"$replace"}" > "$file"
}

build () {        # $1 = crate copy, $2 = log
  (cd "$1/tests" \
     && "$ALR" -n build --validation --profiles=argon2=validation) \
    > "$2" 2>&1
}

prove () {        # $1 = crate copy, $2 = unit, $3 = log
  (cd "$1/tests" && "$ALR" -n exec -- gnatprove \
     -P ../argon2.gpr -j"$PROVE_JOBS" -u "$2" \
     --timeout="$MUTANT_TIMEOUT") > "$3" 2>&1
}

# Proves unit $2 of crate copy $1 with prover $3 alone, from cold, into
# log $4. Some checks need another prover, so the exit status means
# nothing; the results file is what is read.
prove_alone () {
  rm -rf "$1"/obj/*/gnatprove
  (cd "$1/tests" && "$ALR" -n exec -- gnatprove \
     -P ../argon2.gpr -j"$PROVE_JOBS" -u "$2" --prover="$3" \
     --timeout="$MUTANT_TIMEOUT") > "$4" 2>&1 || true
}

run_tests () {    # $1 = crate copy, $2 = log
  (cd "$1/tests" && ./bin/test_main) > "$2" 2>&1
}

# A unit's file name without its extension (argon2-h0.adb -> argon2-h0,
# argon2-compression_model.ads -> argon2-compression_model): the name of
# its results file.
unit_stem () {
  local stem=${1%.adb}
  echo "${stem%.ads}"
}

# The results file GNATprove wrote for unit $2 in crate copy $1 (empty if
# there is none).
spark_file () {
  local stem
  stem=$(unit_stem "$2")
  { find "$1/obj" -path "*/gnatprove/$stem.spark" 2>/dev/null || true; } \
    | head -n 1
}

# The process tree under pid $1 (itself included), from one ps snapshot.
tree_snapshot () {
  ps -A -o pid=,ppid=,rss= 2>/dev/null | awk -v root="$1" '
    { parent[$1] = $2; rss[$1] = $3 }
    END {
      keep[root] = 1
      do {
        grown = 0
        for (p in parent)
          if (!(p in keep) && (parent[p] in keep)) { keep[p] = 1; grown = 1 }
      } while (grown)
      for (p in keep) if (p in rss) print p, rss[p]
    }'
}

# Stops the whole tree under pid $1, then kills every process in it.
kill_tree () {
  local all="" pids round
  for round in 1 2 3 4 5 6 7 8; do
    pids=$(tree_snapshot "$1" | awk '{ print $1 }')
    [ -n "$pids" ] || break
    all="$all $pids"
    # shellcheck disable=SC2086
    kill -STOP $pids 2>/dev/null || true
  done
  if [ -n "$all" ]; then
    # shellcheck disable=SC2086
    kill -KILL $all 2>/dev/null || true
  fi
}

# Proves unit $2 of crate copy $1 into log $3 under the guard, and writes
# the guard's record to $4. Sets PROVE_STATUS, GUARD_FIRED, GUARD_WALL_S
# and GUARD_PEAK_TREE_KB.
guarded_prove () {
  local crate=$1 unit=$2 log=$3 record=$4
  local pid start now one tree
  GUARD_FIRED=""
  GUARD_PEAK_TREE_KB=0
  start=$(date +%s)
  prove "$crate" "$unit" "$log" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    read -r one tree < <(tree_snapshot "$pid" \
      | awk '{ t += $2; if ($2 > m) m = $2 } END { print m + 0, t + 0 }') \
      || { one=0; tree=0; }
    [ "$tree" -le "$GUARD_PEAK_TREE_KB" ] || GUARD_PEAK_TREE_KB=$tree
    now=$(date +%s)
    if [ "$one" -gt "$MUTANT_RSS_KB" ]; then
      GUARD_FIRED="memory: one process at $one KB (limit $MUTANT_RSS_KB)"
    elif [ "$tree" -gt "$MUTANT_RSS_KB" ]; then
      GUARD_FIRED="memory: process tree at $tree KB (limit $MUTANT_RSS_KB)"
    elif [ "$MUTANT_WALL" -gt 0 ] && [ $((now - start)) -gt "$MUTANT_WALL" ]
    then
      GUARD_FIRED="wall: $((now - start)) s (limit $MUTANT_WALL)"
    fi
    if [ -n "$GUARD_FIRED" ]; then
      echo "guard fired: $GUARD_FIRED" >> "$record"
      kill_tree "$pid"
      break
    fi
    sleep "$MUTANT_POLL"
  done
  PROVE_STATUS=0
  wait "$pid" 2>/dev/null || PROVE_STATUS=$?
  GUARD_WALL_S=$(( $(date +%s) - start ))
  echo "exit=$PROVE_STATUS wall=${GUARD_WALL_S}s" \
       "guard=${GUARD_FIRED:-none}" \
       "peak_rss_tree_kb=$GUARD_PEAK_TREE_KB" >> "$record"
}

# A mutant's proof, judged strictly from its results file. $1 = exit
# status, $2 = log, $3 = unit, $4 = results file (may be empty), $5 = the
# judgement's log.
proof_outcome () {   # ... $6 = expected checks (comma-separated)
  local reference=() expects=() status=0 place
  if [ "$1" -eq 0 ]; then
    echo no
    return
  fi
  if [ -z "$4" ]; then
    echo "no results file" > "$5"
    echo ERROR
    return
  fi
  if [ -f "$LOGS/baseline.costs.json" ]; then
    reference=(--costs "$LOGS/baseline.costs.json")
  fi
  IFS=',' read -r -a places <<< "$6"
  for place in "${places[@]}"; do
    [ -z "$place" ] || expects+=(--expect "$place")
  done
  "$PYTHON" -I "$SPARK_PROOF" judge "$3" "$4" "${PROVERS// /,}" \
    ${reference[@]+"${reference[@]}"} ${expects[@]+"${expects[@]}"} \
    > "$5" 2>&1 || status=$?
  case "$status" in
    0) echo yes ;;
    3) echo TAINTED ;;
    5) echo no ;;
    4)
      # Unproved checks only outside the unit: not a catch.
      if grep -qE '^ *(low|medium|high): ' "$2"; then echo no; else echo ERROR; fi
      ;;
    *) echo ERROR ;;
  esac
}

# The tests whose failure is evidence against a mutant of source file $1
# (as the harness labels their failures), or nothing for a file the suite
# has no tests for.
evidence_for () {
  case "$1" in
    src/argon2-h0.adb|src/argon2-h0_model.ads|src/argon2-h0_model.adb)
      echo H0 ;;
    src/argon2-compression.adb|src/argon2-compression_model.ads)
      echo compression ;;
    src/argon2-indexing.adb|src/argon2-indexing.ads|\
    src/argon2-indexing_model.ads|src/argon2-indexing_model.adb|\
    src/argon2-geometry.adb|src/argon2-geometry.ads)
      echo indexing ;;
    *) echo "" ;;
  esac
}

# A test run's outcome: yes only with evidence from the mutated unit's
# tests (see the header).
test_outcome () {    # $1 = exit status, $2 = log, $3 = evidence (H0, ...)
  if [ -z "$3" ]; then
    echo ERROR
  elif [ "$1" -eq 0 ]; then
    echo no
  elif grep -qE '^ *[0-9]+ passed, *[1-9][0-9]* failed' "$2" \
       && awk -v marker="FAIL: $3: " '
            index($0, marker) == 1 && tolower($0) !~ /storage_error/ {
              found = 1
            }
            END { exit !found }' "$2"; then
    echo yes
  else
    echo ERROR
  fi
}

# The classifier's own check, on synthetic logs.
classifier_selftest () {
  local dir failures=0 got
  dir=$(mktemp -d)
  # name | evidence | exit status | log | expected outcome
  local cases=(
    "pass|H0|0| 1444 passed, 0 failed|no"
    "h0-mismatch|H0|1|FAIL: H0: RFC 9106 pre-hashing digest, y = 2: got 00\n 1443 passed, 1 failed|yes"
    "h0-contract|H0|1|FAIL: H0: random case 3: unexpected exception: raised ADA.ASSERTIONS.ASSERTION_ERROR\n 1443 passed, 1 failed|yes"
    "storage-error-escapes|H0|1|raised STORAGE_ERROR : synthetic allocation failure|ERROR"
    "storage-error-in-h0|H0|1|FAIL: H0: random case 3: unexpected exception: raised STORAGE_ERROR\n 1443 passed, 1 failed|ERROR"
    "h-prime-only|H0|1|FAIL: input 1 output 4 input first 0 output first 0\n 1443 passed, 1 failed|ERROR"
    "h-prime-tests-only|H0|1|FAIL: H': RFC 9106 tag 32\n 1443 passed, 1 failed|ERROR"
    "marker-without-count|H0|1|FAIL: H0: every input empty|ERROR"
    "crash-no-log|H0|139||ERROR"
    "many-h0-failures|H0|1|@MANY@|yes"
    "compression-for-h0|H0|1|FAIL: compression: Ada argon2d: published block\n 1443 passed, 1 failed|ERROR"
    "compression-pass|compression|0| 1444 passed, 0 failed|no"
    "compression-mismatch|compression|1|FAIL: compression: Ada argon2d: published block\n 1443 passed, 1 failed|yes"
    "compression-many|compression|1|FAIL: compression: word 3 in X plain: equals the oracle\nFAIL: compression: random 7: equals the oracle\nFAIL: H0: random case 3: against the C serialisation\n 1440 passed, 3 failed|yes"
    "h0-for-compression|compression|1|FAIL: H0: random case 3: against the C serialisation\n 1443 passed, 1 failed|ERROR"
    "h-prime-for-compression|compression|1|FAIL: H': RFC 9106 tag 32\n 1443 passed, 1 failed|ERROR"
    "harness-for-compression|compression|1|FAIL: input 1 output 4 input first 0 output first 0\n 1443 passed, 1 failed|ERROR"
    "compression-case|compression|1|FAIL: Compression: Ada argon2d: published block\n 1443 passed, 1 failed|ERROR"
    "compression-indented|compression|1|  FAIL: compression: Ada argon2d: published block\n 1443 passed, 1 failed|ERROR"
    "compression-storage-error|compression|1|FAIL: compression: random 3: raised STORAGE_ERROR\n 1443 passed, 1 failed|ERROR"
    "compression-escapes|compression|1|raised CONSTRAINT_ERROR : compression_tests.adb:113 index check failed|ERROR"
    "compression-no-count|compression|1|FAIL: compression: Ada argon2d: published block|ERROR"
    "compression-crash|compression|139||ERROR"
    "compression-many-failures|compression|1|@MANY@|yes"
    "indexing-pass|indexing|0| 1444 passed, 0 failed|no"
    "indexing-mismatch|indexing|1|FAIL: indexing: reference index 5, oracle 6: y 1 p 2 s 8 t 3 pass 1 slice 2 lane 0 index 0 J1 0 J2 1\n 1443 passed, 1 failed|yes"
    "indexing-many|indexing|1|FAIL: indexing: address block: y 1 pass 0 lane 0 slice 0 p 1 s 2 t 3 N 1\nFAIL: indexing: Shape_Of ( 1, 9, 1): segment 3\nFAIL: compression: random 7: equals the oracle\n 1440 passed, 3 failed|yes"
    "indexing-exception|indexing|1|FAIL: indexing: Locate grid: unexpected exception: raised CONSTRAINT_ERROR : argon2-indexing.adb:156 divide by zero\n 1443 passed, 1 failed|yes"
    "indexing-storage-error|indexing|1|FAIL: indexing: Locate grid: unexpected exception: raised STORAGE_ERROR : stack overflow\n 1443 passed, 1 failed|ERROR"
    "compression-for-indexing|indexing|1|FAIL: compression: Ada argon2d: published block\n 1443 passed, 1 failed|ERROR"
    "h0-for-indexing|indexing|1|FAIL: H0: random case 3: against the C serialisation\n 1443 passed, 1 failed|ERROR"
    "harness-for-indexing|indexing|1|FAIL: input 1 output 4 input first 0 output first 0\n 1443 passed, 1 failed|ERROR"
    "indexing-for-compression|compression|1|FAIL: indexing: address block: y 1 pass 0 lane 0 slice 0 p 1 s 2 t 3 N 1\n 1443 passed, 1 failed|ERROR"
    "indexing-for-h0|H0|1|FAIL: indexing: Data_Independent: Argon2id pass 0 slice 2 is not data-independent\n 1443 passed, 1 failed|ERROR"
    "indexing-case|indexing|1|FAIL: Indexing: Shape_Of ( 1, 9, 1): segment 3\n 1443 passed, 1 failed|ERROR"
    "indexing-indented|indexing|1|  FAIL: indexing: Shape_Of ( 1, 9, 1): segment 3\n 1443 passed, 1 failed|ERROR"
    "indexing-escapes|indexing|1|raised CONSTRAINT_ERROR : indexing_tests.adb:131 divide by zero|ERROR"
    "indexing-no-count|indexing|1|FAIL: indexing: Shape_Of ( 1, 9, 1): segment 3|ERROR"
    "indexing-crash|indexing|139||ERROR"
    "indexing-many-failures|indexing|1|@MANY@|yes"
    "no-evidence||1|FAIL: compression: Ada argon2d: published block\n 1443 passed, 1 failed|ERROR"
  )
  local entry name evidence status text want
  for entry in "${cases[@]}"; do
    IFS='|' read -r name evidence status text want <<< "$entry"
    if [ "$text" = "@MANY@" ]; then
      # More than a pipe's buffer of failures (a pipeline with grep -q
      # once misread this under pipefail).
      for got in $(seq 1 3000); do
        echo "FAIL: $evidence: random case $got: against the oracle"
      done > "$dir/$name.log"
      echo " 1 passed, 3000 failed" >> "$dir/$name.log"
    else
      printf '%b\n' "$text" > "$dir/$name.log"
    fi
    got=$(test_outcome "$status" "$dir/$name.log" "$evidence")
    if [ "$got" != "$want" ]; then
      echo "classifier selftest FAILED: $name: got $got, want $want"
      failures=$((failures + 1))
    fi
  done
  rm -rf "$dir"
  echo "classifier selftest: $failures failed"
  [ "$failures" -eq 0 ]
}

if [ "${1-}" = "--selftest" ]; then
  classifier_selftest
  exit $?
fi

# The selected mutants, in order, without repeats.
names=()
for entry in "${MUTANTS[@]}"; do
  IFS='|' read -r name _ <<< "$entry"
  if [ -n "$ONLY" ]; then
    case ",$ONLY," in
      *",$name,"*) ;;
      *) continue ;;
    esac
  fi
  case " ${names[*]-} " in
    *" $name "*) ;;
    *) names+=("$name") ;;
  esac
done
if [ "${#names[@]}" -eq 0 ]; then
  echo "h0-mutants: no mutant matched ONLY=$ONLY"
  exit 1
fi

# The test classifier must pass its own check first.
classifier_selftest > /dev/null || { classifier_selftest; exit 2; }

# Every selected mutation site must occur exactly once in the sources,
# every proof mutant must name the checks it expects to fail (DISCOVER=1
# lifts that, to find them: the judge then accepts any clean check), a
# shared mutant must name none and be tested, and a tested mutant's file
# must have tests to give evidence, before any time goes into the
# baseline.
sites_ok=1
for entry in "${MUTANTS[@]}"; do
  IFS='|' read -r name file search replace unit expect checks <<< "$entry"
  case " ${names[*]} " in *" $name "*) ;; *) continue ;; esac
  if [ -z "$expect" ] && [ -n "$unit$checks" ]; then
    echo "mutant $name: a further entry names a unit or checks"
    sites_ok=0
  fi
  if [ -n "$expect" ]; then
    case "$expect" in
      P|PT) multiple=0 ;;
      ST) multiple=1 ;;
      T)
        multiple=0
        if [ -n "$unit" ]; then
          echo "mutant $name: a tests-only mutant proves no unit, not '$unit'"
          sites_ok=0
        fi
        ;;
      *) echo "mutant $name: layers '$expect' (want P, PT, ST or T)"
         sites_ok=0
         multiple=1 ;;
    esac
    if [ "$expect" != T ] && [ -z "$unit" ]; then
      echo "mutant $name: no unit to prove"
      sites_ok=0
    fi
    if [ "$multiple" -eq 0 ] && [ "$unit" != "${unit%% *}" ]; then
      echo "mutant $name: a proof mutant proves one unit, not '$unit'"
      sites_ok=0
    fi
    case "$expect" in
      *S*|T)
        if [ -n "$checks" ]; then
          echo "mutant $name: a shared or tests-only mutant expects no" \
               "unproved check"
          sites_ok=0
        fi
        ;;
      *)
        if [ -z "$checks" ] && [ "${DISCOVER:-0}" != 1 ]; then
          echo "mutant $name: no expected checks"
          sites_ok=0
        fi
        ;;
    esac
    case "$expect" in
      *T*)
        if [ -z "$(evidence_for "$file")" ]; then
          echo "mutant $name: no tests give evidence for $file"
          sites_ok=0
        fi
        ;;
    esac
  fi
  search=${search//\\n/$'\n'}
  count=$(occurrences "$ROOT/$file" "$search")
  if [ "$count" -ne 1 ]; then
    echo "mutant $name: site found $count times in $file (want exactly 1)"
    sites_ok=0
  fi
done
[ "$sites_ok" -eq 1 ] || exit 2

rm -rf "$WORK"
mkdir -p "$LOGS"

echo "=================================================================="
echo "baseline: unmutated crate (units: $UNITS)"
base="$WORK/baseline"
copy_crate "$base"
if ! build "$base" "$LOGS/baseline.build.log"; then
  echo "  baseline does not build: see $LOGS/baseline.build.log"
  exit 2
fi
if grep -qiE 'warning|\(style\)' "$LOGS/baseline.build.log"; then
  echo "  baseline build prints warnings: see $LOGS/baseline.build.log"
  exit 2
fi
for unit in $UNITS; do
  rm -rf "$base"/obj/*/gnatprove
  if ! prove "$base" "$unit" "$LOGS/baseline.prove.$unit.log"; then
    echo "  baseline proof of $unit failed: see $LOGS/baseline.prove.$unit.log"
    exit 2
  fi
  spark=$(spark_file "$base" "$unit")
  if [ -z "$spark" ]; then
    echo "  baseline proof of $unit left no results file"
    exit 2
  fi
  stem=$(unit_stem "$unit")
  cp "$spark" "$LOGS/baseline.$stem.spark"
  for prover in $PROVERS; do
    prove_alone "$base" "$unit" "$prover" \
      "$LOGS/baseline.prove.$unit.$prover.log"
    spark=$(spark_file "$base" "$unit")
    if [ -n "$spark" ]; then
      cp "$spark" "$LOGS/baseline.$stem.$prover.spark"
    fi
  done
done
# shellcheck disable=SC2086
if ! "$PYTHON" -I "$SPARK_PROOF" margin "$STEP_MARGIN" \
     "$LOGS/baseline.costs.json" "$LOGS" "${PROVERS// /,}" \
     $UNITS > "$LOGS/baseline.margin.log" 2>&1; then
  sed 's/^/  /' "$LOGS/baseline.margin.log"
  echo "  baseline fails the step margin: see $LOGS/baseline.margin.log"
  exit 2
fi
sed 's/^/  /' "$LOGS/baseline.margin.log"
# shellcheck disable=SC2086
if ! "$PYTHON" -I "$SPARK_PROOF" coverage 2 "$LOGS" "${PROVERS// /,}" \
     $UNITS > "$LOGS/baseline.coverage.log" 2>&1; then
  sed 's/^/  /' "$LOGS/baseline.coverage.log"
  echo "  baseline fails the prover coverage: a check is proved by fewer"
  echo "  than two provers on their own"
  exit 2
fi
sed 's/^/  /' "$LOGS/baseline.coverage.log"
if ! run_tests "$base" "$LOGS/baseline.tests.log"; then
  echo "  baseline tests failed: see $LOGS/baseline.tests.log"
  exit 2
fi
rm -rf "$base"
echo "  baseline: builds without warnings, proves and passes"

results=()
broken=0
errors=0
tainted=0
for name in "${names[@]}"; do
  echo "=================================================================="
  echo "mutant: $name"
  dir="$WORK/$name"
  copy_crate "$dir"
  unit=""
  expect=""
  checks=""
  evidence=""
  first=1
  for entry in "${MUTANTS[@]}"; do
    IFS='|' read -r ename file search replace eunit eexpect echecks \
      <<< "$entry"
    [ "$ename" = "$name" ] || continue
    if [ "$first" -eq 1 ]; then
      first=0
      unit=$eunit
      expect=$eexpect
      checks=$echecks
      evidence=$(evidence_for "$file")
    fi
    search=${search//\\n/$'\n'}
    replace=${replace//\\n/$'\n'}
    mutate "$dir/$file" "$search" "$replace"
  done

  caught_p=-
  caught_t=n/a
  GUARD_WALL_S=0
  GUARD_PEAK_TREE_KB=0
  if ! build "$dir" "$LOGS/$name.build.log"; then
    # A mutant that doesn't compile tests nothing: an error in the suite,
    # not a catch.
    echo "  does not build: see $LOGS/$name.build.log"
    caught_p=ERROR
    caught_t=ERROR
  else
    case "$expect" in
      *S*)
        # A shared mutant: every unit it names must still prove, cold,
        # under the guard, with every check proved by a prover and every
        # unit checked. The proof catching nothing is the expected "no".
        caught_p=no
        wall=0
        peak=0
        for one in $unit; do
          stem=$(unit_stem "$one")
          rm -rf "$dir"/obj/*/gnatprove
          guarded_prove "$dir" "$one" "$LOGS/$name.prove.$stem.log" \
            "$LOGS/$name.guard"
          wall=$((wall + GUARD_WALL_S))
          [ "$GUARD_PEAK_TREE_KB" -le "$peak" ] || peak=$GUARD_PEAK_TREE_KB
          spark=$(spark_file "$dir" "$one")
          [ -z "$spark" ] || cp "$spark" "$LOGS/$name.$stem.spark"
          if [ -n "$GUARD_FIRED" ]; then
            caught_p=TAINTED
            echo "  guard fired on $one: $GUARD_FIRED"
            break
          fi
          if [ "$PROVE_STATUS" -ne 0 ]; then
            caught_p=FAILED
            echo "  proof of $one failed: see $LOGS/$name.prove.$stem.log"
            break
          fi
          if ! "$PYTHON" -I "$SPARK_PROOF" proved "$one" \
                 "$LOGS/$name.$stem.spark" > "$LOGS/$name.proved.$stem.log" 2>&1 \
             || ! bash "$dir/scripts/check-proof-output.sh" \
                 >> "$LOGS/$name.proved.$stem.log" 2>&1; then
            caught_p=ERROR
            echo "  proof of $one exited 0 without proving every check:" \
                 "see $LOGS/$name.proved.$stem.log"
            break
          fi
          sed 's/^/  /' "$LOGS/$name.proved.$stem.log"
        done
        GUARD_WALL_S=$wall
        GUARD_PEAK_TREE_KB=$peak
        ;;
      T)
        # A tests-only mutant: no proof is run.
        caught_p=n/a
        ;;
      *)
        guarded_prove "$dir" "$unit" "$LOGS/$name.prove.log" \
          "$LOGS/$name.guard"
        spark=$(spark_file "$dir" "$unit")
        if [ -n "$spark" ]; then
          cp "$spark" "$LOGS/$name.spark"
          spark="$LOGS/$name.spark"
        fi
        if [ -n "$GUARD_FIRED" ]; then
          caught_p=TAINTED
          echo "  guard fired: $GUARD_FIRED"
        else
          caught_p=$(proof_outcome "$PROVE_STATUS" "$LOGS/$name.prove.log" \
                       "$unit" "$spark" "$LOGS/$name.judge.log" "$checks")
          [ ! -f "$LOGS/$name.judge.log" ] \
            || sed 's/^/  /' "$LOGS/$name.judge.log"
        fi
        ;;
    esac
    case "$expect" in
      *T*)
        status=0
        run_tests "$dir" "$LOGS/$name.tests.log" || status=$?
        caught_t=$(test_outcome "$status" "$LOGS/$name.tests.log" \
                     "$evidence")
        ;;
    esac
  fi

  verdict=ok
  if [ "$caught_p" = ERROR ] || [ "$caught_t" = ERROR ] \
     || [ "$caught_p" = FAILED ]; then
    verdict=ERROR
    errors=$((errors + 1))
  elif [ "$caught_p" = TAINTED ]; then
    verdict=TAINTED
    tainted=$((tainted + 1))
  else
    case "$expect" in
      *P*) [ "$caught_p" = yes ] || verdict=MISSED ;;
      *S*) [ "$caught_p" = no ] || verdict=MISSED ;;
    esac
    case "$expect" in
      *T*) [ "$caught_t" = yes ] || verdict=MISSED ;;
    esac
    [ "$verdict" = ok ] || broken=$((broken + 1))
  fi
  line=$(printf '%-26s proof:%-7s tests:%-5s must:%-3s %-7s wall:%5ss rss:%8sKB' \
         "$name" "$caught_p" "$caught_t" "$expect" "$verdict" \
         "$GUARD_WALL_S" "$GUARD_PEAK_TREE_KB")
  echo "  $line"
  results+=("$line")
  rm -rf "$dir"
done

echo
echo "mutation summary (logs in $LOGS; wall and rss: the guarded proof)"
printf '  %s\n' "${results[@]}"
status=0
if [ "$errors" -gt 0 ]; then
  echo "h0-mutants: $errors mutant(s) could not be judged (ERROR)"
  status=1
fi
if [ "$tainted" -gt 0 ]; then
  echo "h0-mutants: $tainted mutant(s) TAINTED: not catches"
  status=1
fi
if [ "$broken" -gt 0 ]; then
  echo "h0-mutants: $broken mutant(s) MISSED"
  status=1
fi
if [ "$status" -eq 0 ]; then
  echo "h0-mutants: every mutant caught by every layer it must be"
fi
exit "$status"
