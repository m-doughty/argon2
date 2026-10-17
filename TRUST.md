# argon2 trust register

Everything the crate's claims rest on that its own proof does not
establish. **No entry is signed.** The sign-off is a signature by the
maintainer's key, produced by a tool that does not exist yet; until it does,
every sign-off reads `unsigned`. Entries here are proposals, and an agent
cannot sign them. The README says what is proven, what is tested and what is
trusted; this file is the detail behind its "trusted" list.

The crate is an early milestone: H′ (RFC 9106 §3.3), H₀ (RFC 9106 §3.2) and
block compression (RFC 9106 §§3.5, 3.6). Memory filling and the public
password-hashing interface do not exist yet, and nothing here covers them.
Block compression is covered as S-4, N-1 and N-5 say; H-1 says what its
hardening attributes give and what they do not.

## Summary

| Class | Entries | Needs a signature |
|---|---|---|
| Assumptions (`pragma Assume`, `False_Positive`, `Intentional`, `Skip_Proof`, an `Import` GNATprove trusts) | none in `src/` | would need one each |
| Unproved code (`SPARK_Mode => Off`, C or Rust behind it) | none in `src/` | would need one each |
| Third-party SPARK | blake2b 0.1.1, same maintainer, its own register (D-1) | listed |
| Trusted definitions | none | would need one each |
| Warning suppressions | W-1, W-2, W-4 to W-7 (`pragma Warnings`; W-3 retired); see also N-4 | no, each has a recorded `Reason` |
| Toolchain and proof model | T-1 to T-3 | a bump is a signed change |
| The specification | S-1 to S-4 | listed |
| Not proved | H-1 (wiping), H-2 (abnormal exits), H-3 (secrets held outside a future cleanup guard) | listed |
| Test-only trust (C oracles, `Import`ed C in `tests/`, CPython-generated vectors, published block vectors) | T-4 | listed; the separate tests register this crate's rules ask for does not exist yet |

`scripts/check-sources.sh` enforces the first two rows, the warning
suppressions and the `Unreferenced` pragma, on the source as the compiler reads it (comments and strings
removed, case and line breaks normalised). It fails on any `Assume`, `Import`,
`pragma Interface`, `SPARK_Mode => Off`, `False_Positive`, `Intentional` or
`Skip_Proof` in `src/`; on a `pragma Warnings` suppression without a `Reason`;
when the number of suppressions differs from the number of `W-n` rows of this
register; on any `pragma Unreferenced` other than the single one in
`src/argon2-h0_model.adb` (N-4); and when `argon2.gpr` no longer carries
`--warnings=error` and `-gnatwe` or adds a switch that turns warnings off.
It checks the count of the `W-n` rows, not that each row names the right
place, and `--self-test` runs it against known bypasses. The project's
`--warnings=error` also makes any unexplained proof warning fail the proof.

**What CI runs** (the first run, on 17 October 2026, passed; the
release-profile test step below, the compression part of the object check and
the register-parser test were added after it and have not run on CI yet): on
each of the four platforms the `validation` build (checks and
contracts on), the H′, H₀ and compression tests including `--long`, the same
tests on the `release` build (checks and contracts off; the tests of
precondition rejection skip themselves there), and `scripts/check-h0-object.sh`; the
full GNATprove run followed by `scripts/check-proof-output.sh` (and its
self-test), which fails if a unit was skipped or a check is unproved or
justified; and, once, `scripts/check-sources.sh` (and its self-test),
`scripts/check-dependency.sh`, `scripts/h0-vectors.py --check`,
`scripts/h-prime-vectors.py --check`, `scripts/compression-vectors.py --check`,
the proof-judge self-test and `scripts/test-zeroed-at-return.sh` (the object
check's disassembly parser, on GNU and LLVM output for x86-64 and AArch64). It does not run the mutation and coverage suite
(`scripts/h0-mutants.sh`). Nothing below depends on a CI result as yet.

## Entries

| ID | Kind | Location | Sign-off |
|---|---|---|---|
| T-1 | Toolchain | GNAT, GNATprove, gprbuild, Alire | unsigned |
| T-2 | Toolchain | the provers and Why3 | unsigned |
| T-3 | Proof model | GNAT runtime big-integer library | unsigned |
| T-4 | Test-only trust | the C oracles and `Import`ed C in `tests/` | unsigned |
| D-1 | Third-party SPARK | `blake2b` 0.1.1 from the Alire index | unsigned |
| S-1 | Specification | `Argon2.H0_Model` is the RFC 9106 §3.2 message | unsigned |
| S-2 | Specification | `Blake2b.Spec` is RFC 7693, and `Logical_Hash` is BLAKE2b beyond 2³¹ bytes | unsigned |
| S-3 | Specification | `Argon2.H_Prime_Model` is RFC 9106 §3.3 | unsigned |
| S-4 | Specification | `Argon2.Compression_Model` is RFC 9106 §§3.5, 3.6 | unsigned |
| H-1 | Not proved | wipes, register and stack clearing | unsigned |
| H-2 | Not proved | exceptional and asynchronous exits | unsigned |
| H-3 | Not proved | the cleanup guard does not exist yet; BLAKE2b's own compression frame will stay outside it | unsigned |
| W-1 | Warning suppression | `src/argon2-h0.ads` (`Compute`), `Machine_Attribute` | no signature needed |
| W-2 | Warning suppression | `src/argon2-h0.adb`, `Machine_Attribute` on seven helpers | no signature needed |
| W-4 | Warning suppression | `src/argon2-h_prime.ads` (`Hash`), `Machine_Attribute` | no signature needed |
| W-5 | Warning suppression | `src/argon2-h_prime.adb` (`Initial_Hash`), `Machine_Attribute` | no signature needed |
| W-6 | Warning suppression | `src/argon2-wipe.ads` (`Bytes`), `Machine_Attribute` | no signature needed |
| W-7 | Warning suppression | `src/argon2-compression.ads` (`Compress`, `Compress_Xor`), `Machine_Attribute` | no signature needed |

### T-1 Compiler and build tools
- **Proposition:** GNAT 16.1.0 compiles the SPARK source to code that behaves
  as the language defines it, and GNATprove 16.1.0 implements SPARK's
  semantics, so a proof of the source is a proof about the compiled program.
  gprbuild 26.0.1 and Alire 2.1.1 build what the sources say. (`alire.toml`
  asks only for `gnat >= 16`; CI installs the exact GNAT and gprbuild
  versions and the Alire version, the nested `tests/alire.toml` pins
  GNATprove, and the README states them.)
- **Why believed:** on 14 October 2026, on macOS arm64, the pinned versions
  pass the test suite built with run-time checks and contracts on (the
  `validation` profile). The `release` profile builds with optimisation,
  run-time checks off (`-gnatp`) and contracts off, on the grounds that the
  proof covers every check `-gnatp` removes (true only for the proved units;
  the BLAKE2b dependency keeps its own release profile). With contracts off
  the `Executable` postconditions (the cleanup guarantees) are not run in
  `release`; their proof is unaffected. No optimisation-level matrix or
  build-matrix script exists yet, unlike blake2b; Alire's default
  `development` profile also exists and is not used for any claim. The same
  proof, tests and checks then ran on Linux arm64 and Linux x86_64 in
  containers, on 14 and 15 October 2026, with the same result (GNAT,
  GNATprove and the provers at the pinned versions; the images carry the
  gprbuild 26.0.1 crate, whose binary reports itself as 26.0.0 there as on
  macOS), plus the long-input tests (21 passed on each) on the first run's
  sources. The first two Linux runs predate the crate's present name (it was
  `argon2id` then). A third run on 15 October, on the renamed crate, passed
  on both architectures: every gate (dependency, sources and its self-test,
  test vectors, the judge's self-test), the validation and release builds,
  1444 tests, the object check, and the cold whole-crate proof (2750 checks,
  none unproved; 1036 s on arm64, 1888 s on amd64), with the margin and
  coverage reports as before (costliest condition 2807 of 5000 steps). The
  long-input tests were not repeated on it. That tree had no compression and
  the older H′ (chunked input). On 17 October 2026, on macOS arm64, the
  current tree (H′ taking a BLAKE2b array of at most 1,024 bytes and proved
  equal to its model, `Argon2.Blocks`, compression and its model) passes 4240
  tests, the source gate, and a cold whole-crate proof of 3358 checks with none
  unproved, none
  justified and no unit skipped (`scripts/check-proof-output.sh`); the first
  CI run (17 October 2026) passed the tests and the cold proof on macOS
  arm64, Linux x86_64 and aarch64, and Windows x86_64, with blake2b 0.1.1
  from the index. The local runs used a copy beside the crate.
- **If false:** a proof could hold for a program the compiler does not
  produce. The tests would be the only remaining evidence.
- **Scope:** all code. A version bump is a signed change.

### T-2 Provers
- **Proposition:** Z3 4.15.4, cvc5 1.3.2 and Alt-Ergo 2.6.1, driven by Why3 as
  shipped with GNATprove 16.1.0, never report a false statement proved.
- **Why believed:** widely used. The crate's proof (`argon2.gpr`, and CI)
  races all three and is limited in steps, not time (`--timeout=0`). On top of
  that, a local script, `scripts/h0-mutants.sh` (the name is old; it covers
  all six proved units), shows at its baseline that every check of the H₀,
  H′ and compression units and their models is proved by at least two
  provers each on its own, and that, for each of its conditions, the cheapest
  proof found among the single-prover runs costs no more than half the step
  budget (different conditions of one check may use different provers). Run on
  macOS arm64 on 17 October 2026: no check is proved by fewer than two
  provers; the costliest check is H′'s at 3,613 steps against the limit of
  5,000 (the budget is 10,000). It also shows that twenty-five mutated
  programs behave as designed: twelve of H₀, and thirteen of compression
  (nine whose code is wrong and which the proof and the tests both catch, and
  four where code and model are wrong in the same way, which still prove, the
  blind spot of S-4, and which the tests catch). Earlier runs: 14 and 15
  October 2026 for H₀, and a baseline on Linux arm64 and x86_64 on 15 October.
  Two H₀ mutants are written in a particular form because Z3 runs on in the
  other (see the script's header). The mutants were run on macOS arm64 only. That script is **not** run by CI;
  all its proof runs (the baseline, the single-prover runs and every mutant)
  also carry a wall-clock timeout (default 300 s) besides the steps, unlike
  the crate's own proof, which has none; and its logs are kept outside the repository (they are gitignored),
  so the repository itself retains no record of the result. The H′ and wipe
  checks are held to both gates now. blake2b's units, on which the H₀ proof
  depends, are not held to the two-prover rule here. The H′ units are set to
  10,000 steps per check; their costliest check needs 3,613 steps with the cheapest
  prover, a margin of 2.7 (a check is proved when any one prover proves it
  within the budget).
- **If false:** a lemma or postcondition could be false while shown proved.
- **Scope:** every proved check.

### T-3 The big-integer proof model
- **Proposition:** GNATprove's model of `Ada.Numerics.Big_Numbers.Big_Integers`
  agrees with mathematical integers. The H₀ statement counts absorbed bytes
  (up to 2³⁴ + 36) with blake2b's ghost big-integer counter.
- **Why believed:** it is the standard library's own SPARK model. The H₀
  mutation suite includes a mutant (`len-p-omitted`) that fails the
  precondition of the call to `Absorb_Input`, whose conjuncts include the
  counter (`Absorbed (St) = Big.Length (Off)`) and the context equality; no mutant targets the
  counter's arithmetic itself (blake2b's carry mutants do, in blake2b).
- **If false:** the length claims in ghost code could be about the wrong
  numbers.
- **Scope:** ghost code only. `scripts/check-h0-object.sh` scans the symbols of
  `argon2-h0.o` and `argon2-h_prime.o` (release and validation) for
  big-integer symbols and finds none; for `argon2-h0_model.o` it checks only
  that the object's one external symbol is its elaboration flag and that it
  references nothing.

### T-4 Test-only trust
- **Proposition:** the C code in `tests/` is a valid reference. It decides
  whether the specification claims (S-1, S-3, S-4) are believed, not whether the
  proofs hold; production proof takes no result or contract from it.
- **What there is:**
  - five `Import`ed C functions in the tests (`compress_oracle` in
    `tests/src/compression_tests.adb`; `h0_oracle`, `h0_oracle_generated` and
    `blake2b_512` in `tests/src/h0_tests.adb`; `blake2b_long` in
    `tests/src/test_main.adb`), compiled at `-O3` by `tests/argon2_tests.gpr`;
  - the vendored official Argon2 reference files (`ref.c`, `core.c`, `core.h`,
    `thread.h`, `blake2/blamka-round-ref.h`, the BLAKE2b files), unmodified and
    pinned to an upstream commit (`tests/ref/README.md`); `core.c` is compiled
    with `-DARGON2_NO_THREADS`; the earlier `clear_internal_memory` shim is
    gone;
  - for compression, `tests/ref/compress_oracle.c`, a test-only file that
    `#include`s `ref.c` (which is never compiled alone) and exports one wrapper
    around the reference's static `fill_block`: the oracle for both forms of G;
  - for compression, 15 blocks taken from the reference's own known-answer
    files (`tests/ref/kat-blocks.json`, `tests/src/compression_vectors.ads`,
    produced and re-checked by `scripts/compression-vectors.py`, which the CI
    `gates` job will run). The known-answer files themselves are not kept in the
    repository; the script says how the blocks are found. Each stored block is
    the compression of two other blocks of the same file, as the script
    checks;
  - for H₀, three C functions written for the tests in `tests/src/h0_oracle.c`
    (an incremental serialisation, a one-shot hash of the serialisation the Ada
    test builds, and the generated-bytes oracle of the `--long` run). The first
    two sit on the **one** vendored BLAKE2b implementation. The reference's own
    `initial_hash` is vendored (in `core.c`) but no test calls it, so H₀ is
    checked against test-written serialisations, not against the Argon2
    reference's own H₀ code; H′ is checked against the reference's own
    `blake2b_long`, and against CPython (below); compression against the
    reference's own `fill_block`;
  - for H′, 55 expected outputs computed with CPython's `hashlib.blake2b`
    straight from RFC 9106 §3.3 (`tests/src/h_prime_vectors.ads`, produced and
    re-checked by `scripts/h-prime-vectors.py`, which the CI `gates` job will
    run). Each is recorded as the 32-byte BLAKE2b digest of the whole output,
    because outputs reach 2²⁴ + 8 bytes; the test hashes its own output the same
    way. The input bytes are one formula written twice (the script and
    `tests/src/h_prime_tests.adb`), so the hashing is independent, not the
    inputs. The test-only files are `tests/src/h_prime_tests.ads` and `.adb`
    and the generated `tests/src/h_prime_vectors.ads`;
  - input bytes from one formula written twice, in the `--long` run (Ada and C)
    and in the nineteen CPython cases (`scripts/h0-vectors.py` and
    `tests/src/h0_tests.adb`), so there the hashing is independent, not the
    inputs; the CPython digests are fixed constants, so a divergence between
    the two copies fails a test;
  - CPython's `hashlib` BLAKE2b and the generator's serialisation
    (`struct.pack ("<6I", …)` and the field order), which produce the
    nineteen expected digests in `tests/src/h0_vectors.ads` (the CI `gates`
    job checks they are current), and the three RFC 9106 §5 digests, typed
    in by hand in `tests/src/h0_tests.adb`;
- **If false:** a wrong expectation could hide a defect, or hide that the
  model is not the RFC's.
- **Scope:** all tests. This crate's own rules ask for signed test-only entries
  in a separate `tests/TRUST.md`, linked from this register with
  machine-checked coverage; neither exists yet (see Notes).

### D-1 blake2b 0.1.1
- **Proposition:** the contracts and lemmas the proofs here use are true of
  blake2b's code: `Blake2b.Hashing` (`Init`, `Update` and `Final`),
  `Blake2b.Streaming` and `.Theory` (including `Logical_Equal` on
  `Same_Context`), `.Consistency`, `.Example` (`Lemma_Room`) and
  `Blake2b.Spec` with `Blake2b.Spec.Incremental`.
- **Why believed:** blake2b's own proof and register (its T-1, T-2, T-3, S-1,
  H-1, W-1 to W-8, N-1 and N-2), which this register does not repeat. On
  14 October 2026, on macOS arm64, this crate's cold proof also analyzed those
  units (the GNATprove run on this project covers the dependency's sources)
  and proved them. `alire.toml` asks the Alire index for exactly blake2b
  0.1.1 and carries no pin; `scripts/check-dependency.sh` checks that (no pin
  of any kind, exactly that version); the CI `gates` job will run it.
- **If false:** every H₀ and H′ claim that names `Blake2b` is about a function
  that is not BLAKE2b.
- **Scope:** H₀ and H′. Proof visibility (blake2b's N-2) matters to both,
  differently. H′ calls `Blake2b.Hashing.Update` directly, so its proof reads
  the private completion of `Max_Input` itself; H₀'s proof gets the same facts
  from `Blake2b.Streaming.Example.Lemma_Room`, so it is that lemma's proof
  (blake2b's, analyzed here too) that reads it. If a toolchain stops doing
  that, the proofs fail; they cannot succeed on a wrong statement.

### S-1 The H₀ message
- **Proposition:** `Argon2.H0_Model` (`H0_Original`, `H0_Contents`,
  `H0_Hash`) describes exactly the message RFC 9106 §3.2 hashes: the ten
  little-endian 32-bit fields p, T, m, t, v, y and the four lengths, in the
  RFC's order, interleaved with P, S, K, X, using the original m, not the
  rounded m′.
- **What is proved:** `Compute`'s `Digest` equals `H0_Model.H0_Hash`, which is
  `Blake2b.Streaming.Theory.Logical_Hash` of that message, not `Blake2b.Spec.Hash`
  of it: the proof ties `Logical_Hash` to `Blake2b.Spec.Hash` only where one
  array holds the message (at most 2³¹ bytes, `Lemma_H0_Spec_Hash`). That the
  long-stream function is BLAKE2b beyond 2³¹ bytes is S-2. The model's two
  views of the message agree (`Lemma_All_Positions`); a transcription mistake
  made in both views would still prove.
- **Why believed (tested, not proved):** the three H₀ values published in RFC
  9106 §5; nineteen CPython `hashlib` cases that build the RFC's byte string
  independently, each also against both C oracles; the empty, one-byte,
  chunk-boundary (4,095 to 4,097, 8,192) and 3 MiB cases; and a `--long` run
  with all four inputs at 2³²−1 bytes and with each of P, S, K, X at 2³¹−1,
  2³¹, 2³¹+1 and 2³²−1 bytes. See T-4 for what the oracles share.
- **If false:** the code would be proved equal to the wrong function.
- **Scope:** `Argon2.H0.Compute`. Parameters are hashed as given; the
  RFC's ranges are not checked here.

### S-2 BLAKE2b
- **Proposition:** `Blake2b.Spec` computes BLAKE2b as RFC 7693 defines it, and
  for messages longer than 2³¹ bytes (which no `Blake2b.Byte_Array` holds)
  `Logical_Hash` is the same function.
- **Why believed:** `Logical_Hash` is written as RFC 7693's padded block fold of
  the whole stream, which blake2b can name for messages of up to 2³⁴ + 36
  bytes, every H₀ message among them. It is proved equal to
  `Blake2b.Spec.Hash` only where one `Blake2b.Byte_Array` holds the message
  (blake2b's `Consistency`, at most 2³¹ bytes); above that the equality is
  tested, not proved: blake2b's long-stream tests run its code, not the ghost
  `Logical_Hash`, and are evidence for it through the proof that the code
  equals `Logical_Hash`; this crate's `--long` run against the C oracle does
  the same for H₀. `Blake2b.Spec` itself is tested, not
  proved (its S-1). The proof here establishes nothing about `Logical_Hash`
  for such messages beyond equality with the digest `Compute` returns.
- **If false:** for H₀ inputs whose total exceeds 2³¹ bytes, the digest could
  differ from RFC BLAKE2b while the proof still holds.
- **Scope:** H₀ with total message above 2³¹ bytes (S-2, second half); all
  functional claims for the first half, as blake2b's S-1.

### S-3 H′
- **Proposition:** `Argon2.H_Prime_Model` (`Message`, `V`, `Tail`, `Out_Byte`) is
  the variable-length hash H′ of RFC 9106 §3.3: for an output of T bytes and an
  input A, the T-byte BLAKE2b of LE32 (T) ‖ A when T ≤ 64; otherwise, with
  r = ⌈T/32⌉ − 2, the first 32 bytes of each of V₁ … Vᵣ (V₁ the 64-byte BLAKE2b
  of LE32 (T) ‖ A, Vᵢ that of Vᵢ₋₁) followed by V(r+1), the BLAKE2b with a digest
  length of T − 32r (33 to 64 bytes) of Vᵣ, not a truncation.
- **What is proved:** after `Argon2.H_Prime.Hash (Input, Digest, …)`, byte P of
  `Digest` equals `H_Prime_Model.Out_Byte (Input, Digest'Length, P)` for every P,
  every output length from 1 to 2³²−1 bytes and every input of at most 1,024
  bytes (the precondition), through blake2b's contracts for `Init`, `Update`
  and `Final` and `Blake2b.Spec`. No run-time error, the exact little-endian
  encoding of the output length, and zeroed chain values after their wipe
  (`docs/proof-scope.md`). The proof of the calls to `Blake2b.Hashing.Update`
  depends on blake2b's proof-visibility note N-2 (D-1), as before; that was not
  re-examined for the new proof. The code was proved equal to the model, not to
  the RFC: the model is a hand transcription, and a mistake in it would still
  prove. The postcondition is `Static`: proved, never compiled or run (N-5).
- **Why believed (tested, not proved):** 55 CPython `hashlib` outputs written
  from the RFC text (T-4: inputs of 72 and 1,024 bytes, output lengths 1 to
  2²⁴ + 8 including the 64/65 boundary and tails that are not multiples of 32,
  and seven short and empty inputs), and the same lengths against the vendored
  official Argon2 C reference's `blake2b_long`, with input lengths 0, 1, 72,
  127, 128, 129, 1,023 and 1,024, output lengths from 1 to 1,025, arbitrary
  bounds, deterministic random inputs, and a test that an input over 1,024
  bytes is rejected. No test reaches output lengths above 2²⁴ + 8; for those
  the proof is the only evidence, and it is a proof about the model. No mutation
  suite covers H′ yet. Rests on `Blake2b.Spec` being BLAKE2b (S-2, D-1).
- **If false:** H′ would be proved equal to the wrong function, or differ from
  RFC 9106 on an output length above 2²⁴ + 8 where only the model's reading of
  the RFC stands behind it.
- **Scope:** `Argon2.H_Prime`, `Argon2.H_Prime_Model`. Not initialisation, the
  fill or the final tag.

### S-4 Block compression
- **Proposition:** `Argon2.Compression_Model` (`G`, `G_Xor`, and the functions
  they use: `FBlaMka`, `GB`, `P`, `Rows`, `Columns`) is the compression
  function of RFC 9106 §§3.5 and 3.6, including version 1.3's later-pass form
  (the old block xor `G`).
- **What is proved:** after `Argon2.Compression.Compress (M, X, Y, Z)`, `M (Z)`
  equals `G (M'Old (X), M'Old (Y))` and every other initialised block is
  unchanged; after `Compress_Xor`, `M (Z)` equals
  `G_Xor (M'Old (X), M'Old (Y), M'Old (Z))`. This holds for every index in
  range, `Z` equal to `X` or `Y` included. The literal index lists the code
  uses equal the model's row and column positions. `M (X)` and `M (Y)`
  initialised on entry, `M (Z)` initialised on exit, nothing initialised
  becomes uninitialised. No run-time error. The code was proved equal to the
  model, not to the RFC: the model is a hand transcription, and a mistake in it
  would still prove (its `FBlaMka` writes the truncating product with
  `mod 2**32` where the code uses `and`: a second transcription).
- **Why believed (tested, not proved):** the unmodified reference's
  `fill_block` as oracle (T-4), on the 15 published blocks, every single-word
  position in either input, extreme words, `X` equal to `Y`, pseudo-random
  pairs, and `Z` equal to `X` or `Y`, in both forms; and thirteen compression
  mutants (see T-2): the tests catch every one, including the four the proof
  cannot see because code and model share the mistake. These runs are local
  and not in CI.
- **If false:** compression would be proved equal to the wrong function, and
  the tests would be the only evidence against it.
- **Scope:** `Argon2.Compression`, `Argon2.Compression_Model`. Not the memory
  fill, indexing or the final tag.

### H-1 Wiping, registers and stack
- **Proposition:** on normal return, `Argon2.H0.Compute` and
  `Argon2.H_Prime.Hash` leave no copy of an input or intermediate digest
  that the library holds in a buffer of its own, in a call-used register
  (callee-saved registers are not zeroed; the ABI restores them), or on the
  stack. The caller's own arrays are not erased by these calls. For
  `Argon2.Compression.Compress` and `Compress_Xor` it is narrower: on normal
  return no word derived from the blocks is left in a call-used register or
  in the stack frame of their own body. `Work` is the caller's to wipe, and
  the frames of the helpers the body calls are outside it (below).
- **What is proved:** after `Argon2.Wipe.Bytes`, every byte of the buffer it
  is given is zero. That is about the value of an object only.
- **What is requested, not proved:** `Wipe.Bytes` is never inlined and is
  `noipa`, with an `Inspection_Point`; the entry points and the helpers that
  handle input carry `strub` and `zero_call_used_regs ("all")`, and so do
  `Compress` and `Compress_Xor`. For H₀ and H′ nothing checks that wipes or
  scrubbing exist in the object code (blake2b has
  `scripts/check-hardening.sh`). For compression the attributes are checked in
  the object code (below), not proved.
- **Compression's hardening.** `Argon2.Compression` works on blocks of
  workspace data (derived from the password, salt and key) and takes one
  block of working space from its caller (`Work`); it does not wipe `Work`
  (it is the hot loop; the caller does). `strub ("internal")` makes each of
  `Compress` and `Compress_Xor` a wrapper that calls the body (a clone) and
  then scrubs the stack the body's own frame used; `zero_call_used_regs
  ("all")` zeroes every call-used register before the wrapper returns. The
  helpers the body calls and that are not inlined are not `strub` functions,
  and GCC does not scrub their frames: on macOS arm64 the release body calls
  `memcpy`, `Row_Pass` and `Column_Pass` (whose frames hold saved registers
  and the return address; they call `GB`, which uses no stack), and the
  validation body ends in a tail call to `Combine`, so there the whole
  computation runs outside the scrubbed frame. What those frames hold has not
  been examined further, nor on other targets. No claim is made about them.
- **What is checked in the objects, and what is not:** `scripts/check-h0-object.sh`
  looks for proof residue and runtime cleanup: it requires `Compute` and
  `Hash` to be defined text symbols (not merely named), scans `argon2-h0.o`
  for soft-links, abort-deferral, secondary-stack, big-integer, model and
  theory symbols by name (any symbol, defined or referenced, whose name
  contains one), scans `argon2-h_prime.o` for soft-links, abort-deferral,
  big-integer, streaming-theory, `Spec` and absorbed-counter names but not for
  the secondary stack (which H′'s length-encoding function uses; it holds the
  output length, not a secret) nor for `Argon2.H0_Model`, and checks that
  the external symbols (`nm -g`) of `argon2-h0_model.o` and
  `argon2-h_prime_model.o` are only their elaboration flag. That is a check on static ghost code having left nothing
  behind (see N-2), not on wiping, and it looks at symbol names, not at the
  code. For `argon2-compression.o`, in both the `release` and the
  `validation` objects, it also reads the code: `Compress` and `Compress_Xor`
  must be defined text symbols with a `strub` clone each
  (`<name>.strub.<n>`), and at every return of each of the two, the
  instructions after the last call or branch must zero at least the registers
  that `zero_call_used_regs ("all")` zeroes on the target. That set is
  measured, not written down: the script compiles a probe function with the
  attribute with the toolchain's `gcc` and disassembles it (on macOS arm64,
  `x0`–`x17` and `v0`–`v7`, `v16`–`v31`). It scans the object's symbols for
  the same names as `argon2-h0.o` (soft-links, abort deferral, the secondary
  stack, big integers, models, theory), and checks that `argon2-compression_model.o`
  holds only its elaboration flag and the initialisation procedure of the type
  `Positions` (N-5). It does not check how much stack is scrubbed, nor the
  helpers' frames, nor `Work`.
- **If false:** key- or password-derived bytes could remain in memory the
  library no longer controls.
- **Scope:** macOS arm64, Linux arm64 and Linux x86_64 so far (the object check
  ran in the containers on 14 and 15 October 2026, the last time on the renamed crate); Windows x86_64 and the
  compilers and targets of CI, whose first run passed it on all four platforms (T-1). The
  compression part of the object check has run on macOS arm64 only (17 October
  2026: GCC 16.1.0, Apple's LLVM objdump); CI runs it on the other three
  platforms and has not run it yet. See also H-2.

### H-2 Exceptional and asynchronous exits
- **Proposition:** none is made. The wipes run on normal completion with the
  preconditions met. An exception, a task abort or a stack overflow in the
  middle of `Compute` or `Hash` leaves whatever the buffers held; no handler
  wipes them (the sources contain no exception handler). Nothing has examined
  the behaviour on such exits.
- **If false (if cleanup were expected):** secrets remain after an abnormal
  exit. The cleanup mechanism is a separate design, not part of this crate yet.
- **Scope:** every call.

### H-3 The cleanup guard, and what stays outside it
- **Proposition:** none beyond H-1 and H-2. The cleanup guard and release
  tokens do not exist yet. The units that handle secrets already take the
  scratch the future guard will wipe as parameters, so it can reach them:
  `Argon2.H_Prime.Hash` takes its BLAKE2b state and its two chain values
  (`S`, `V`, `Next_V`); `Argon2.H0.Compute` takes its BLAKE2b state
  (`Hash_State`); `Argon2.Compression.Compress` and `Compress_Xor` take their
  working block (`Work`). On normal return H′ wipes its chain values
  (`Argon2.Wipe.Bytes`) and BLAKE2b's `Final` wipes its state; compression
  does not wipe `Work`, the caller does.
- **What stays outside any guard:** the working vector and message words that
  `Blake2b.Core.Compress` keeps in its own locals (`M`, `V`). Only `blake2b`
  itself could change that. They rest on `blake2b`'s own `strub` and
  `zero_call_used_regs` attributes and its hardening check (its H-1), not on
  this crate.
- **What is requested, not proved:** stack scrubbing and register clearing
  by compiler attributes (`strub`, `zero_call_used_regs`), which are not
  proved. For compression they are checked in the object code; for H₀ and H′
  they are not yet gated here (H-1). The frames of compression's helpers are
  not scrubbed (H-1).
- **If false:** after an abnormal exit (H-2), or if a scrub is not emitted,
  bytes derived from the password or key can remain in stack memory the library
  no longer controls.
- **Scope:** the future public calls; today, `Argon2.H_Prime.Hash`,
  `Argon2.H0.Compute` and `Argon2.Compression`.

### W-1, W-2, W-4 to W-7 `Machine_Attribute` ignored
- **W-1, W-2, W-4, W-5, W-6, W-7** (`Machine_Attribute` ignored by GNATprove):
  `src/argon2-h0.ads` (`Compute`); `src/argon2-h0.adb` (`Store_LE32`,
  `Copy_Chunk`, `Copy_Input`, `Absorb_Field`, `Absorb_Chunk`, `Absorb_Input`,
  `Finish`); `src/argon2-h_prime.ads` (`Hash`); `src/argon2-h_prime.adb`
  (`Initial_Hash`); `src/argon2-wipe.ads` (`Bytes`);
  `src/argon2-compression.ads` (`Compress`, `Compress_Xor`).
  **Reason recorded:** "code-generation attribute: no effect on proof".
  GNATprove ignores the attribute, which is correct: it affects code
  generation only.
- **W-3** was retired when `Argon2.H0.Compute`'s BLAKE2b state became a
  formal (`Hash_State`): the unused-state warning no longer arises and the
  suppression is gone from `src/argon2-h0.adb`.

## Notes
- **N-1 Annotations that are not trusted:** `Hide_Info` on `H0_Original`,
  `Fields_Of`, `H0_Contents` and `Chunk_At` (`src/argon2-h0_model.ads`) hide
  an expression function's body from the provers. Each is reopened by
  `Unhide_Info` in a lemma that GNATprove proves, so they are proof
  engineering, not assumptions. `Logical_Equal` is blake2b's, checked there.
  The same holds for compression: `Hide_Info` on `FBlaMka`, `GB` and `P`
  (`src/argon2-compression_model.ads`) hide a function's body from the provers,
  and each is reopened by `Unhide_Info` in the compression body where GNATprove
  proves it; `Logical_Equal` on `Same_Block` and `Same_Positions`
  (`src/argon2-compression.adb`) makes the provers substitute array equality,
  and lemmas convert it to ordinary equality. Proof engineering, not
  assumptions. In `Argon2.H_Prime`, `Hide_Info` on `Prefix_Done` (in `Hash`) and
  on `Blake2b.Spec.Incremental.Update` (in `Initial_Hash`) are local: they only
  stop the provers unfolding a definition, and two null-body ghost lemmas
  reopen `Prefix_Done` where a proof needs it. The existing `Hide_Info` on
  `Message`, `V` and `Tail` in `Argon2.H_Prime_Model` is the same kind. The
  H′ and compression units were restructured on 17 October 2026 so that every
  check is proved by two provers each on its own (T-2).
- **N-2 Static ghost code:** every declaration in `Argon2.H0_Model` is
  `Ghost => Static`, so nothing of it is compiled in any profile. In
  `Argon2.H0`, the static loop invariants of `Absorb_Input` and `Compute` are
  a single call to a static ghost function (`In_Progress`); written inline they
  left abort-deferral calls in the release object. `Copy_Chunk`'s static
  invariant is an inline quantified expression over the arrays and leaves no
  such calls (checked by `scripts/check-h0-object.sh`). H′'s and
  compression's objects are checked by the same script.
- **N-4 A warning annotation outside the W rows:** `pragma Unreferenced (Off,
  Src, From)` in `Argon2.H0_Model` (`src/argon2-h0_model.adb`, the body of
  a ghost procedure) silences unused-parameter diagnostics, because those
  parameters appear only in the contract. It is not a `pragma Warnings` region
  and affects no proof.
- **N-5 A `Static` postcondition and assertion levels:** `Compress` and
  `Compress_Xor` state their result in a `Static` postcondition
  (`src/argon2-compression.ads`, with `pragma Assertion_Level (Executable)`
  naming the other level), and `Hash` does the same for H′
  (`src/argon2-h_prime.ads`). GNATprove proves them; no build compiles or runs
  them, and `Compression_Model` and `H_Prime_Model` are static ghost code, so
  nothing of either model is in any object, except, from `Compression_Model`,
  the type `Positions` (not ghost, because the implementation uses it): its
  object holds the elaboration flag and the initialisation procedure GNAT
  generates for that type, which returns at once, and nothing else (checked by
  `scripts/check-h0-object.sh`). The result of compression and of H′
  is therefore checked at run time only by the tests against the reference
  oracle (and, for H′, CPython). This uses GNAT 16.1.0's assertion
  levels (T-1).
- **N-3 Follow-ups before signature:**
  - the separate test-only register this crate's rules ask for, and the
    machine-checked link from this one;
  - an object-code hardening gate for `Compute` and `Hash` (compression's
    is in `scripts/check-h0-object.sh`);
  - the frames of compression's helpers, which `strub` does not scrub (H-1):
    whether to harden them, and what they hold;
  - keeping the mutation and coverage logs where the repository, not a
    gitignored directory, holds them, or running the suite in CI;
  - `Lemma_Room` comes from a blake2b example unit,
    `Blake2b.Streaming.Example`, and should move to its theory unit in a
    blake2b release.
