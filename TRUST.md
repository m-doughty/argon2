# argon2 trust register

Everything the crate's claims rest on that its own proof does not
establish. **No entry is signed.** The sign-off is a signature by the
maintainer's key, produced by a tool that does not exist yet; until it does,
every sign-off reads `unsigned`. Entries here are proposals, and an agent
cannot sign them. The README says what is proven, what is tested and what is
trusted; this file is the detail behind its "trusted" list.

The crate is an early milestone: H′ (RFC 9106 §3.3), H₀ (RFC 9106 §3.2),
block compression (RFC 9106 §§3.5, 3.6) and indexing (RFC 9106 §3.4, which
nothing calls yet). Memory filling and the public
password-hashing interface do not exist yet, and nothing here covers them.
Block compression is covered as S-4, N-1 and N-5 say; H-1 says what its
hardening attributes give and what they do not.

## Summary

| Class | Entries | Needs a signature |
|---|---|---|
| Assumptions (`pragma Assume`, `False_Positive`, `Intentional`, `Skip_Proof`, an `Import` GNATprove trusts) | none in `src/` | would need one each |
| Unproved code (`SPARK_Mode => Off`, C or Rust behind it) | none in `src/` | would need one each |
| Third-party SPARK | blake2b 0.1.2, same maintainer, its own register (D-1) | listed |
| Trusted definitions | none | would need one each |
| Warning suppressions | W-1, W-4, W-6, W-7 (`pragma Warnings`; W-2, W-3 and W-5 retired); see also N-4 | no, each has a recorded `Reason` |
| Toolchain and proof model | T-1 to T-3 | a bump is a signed change |
| The specification | S-1 to S-5 | listed |
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
release-profile test step below, the compression part of the object check,
the register-parser test and the exception-stack scan were added after it,
and the proof-output judge and the register parser have been tightened since,
none of which has run on CI yet): on
each of the four platforms the `validation` build (this crate's checks and
contracts on), the H′, H₀ and compression tests including `--long`, the same
tests on the `release` build (checks and contracts off; the four tests of
a precondition check skip themselves there, each printing
`note: skipped (contracts off): <name>`, and the job requires exactly four
such lines), `scripts/check-h0-object.sh`, and
`scripts/check-exception-stack.sh` (H-2), a gate on normal returns and a
measurement of exceptions: exit 1 (a harness error, or a blind
normal-return control: A′) and exit 3 (a hardened build left a canary
after a normal return, in any case) fail the job; exception results are
reported only, and where an exception's control leaves no canary they are
marked unmeasured and CI prints a warning. BLAKE2b is built in its own
`release` profile (checks and contracts off) in every one of these builds.
Also on each platform: the full GNATprove run followed by
`scripts/check-proof-output.sh --whole-crate` (and its self-test; the README
says what it rejects). And, once, `scripts/check-sources.sh` (and its self-test),
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
| D-1 | Third-party SPARK | `blake2b` 0.1.2, exactly that version, from the Alire index | unsigned |
| S-1 | Specification | `Argon2.H0_Model` is the RFC 9106 §3.2 message | unsigned |
| S-2 | Specification | `Blake2b.Spec` is RFC 7693, and `Logical_Hash` is BLAKE2b beyond 2³¹ bytes | unsigned |
| S-3 | Specification | `Argon2.H_Prime_Model` is RFC 9106 §3.3 | unsigned |
| S-4 | Specification | `Argon2.Compression_Model` is RFC 9106 §§3.5, 3.6 | unsigned |
| S-5 | Specification | `Argon2.Indexing_Model` and `Argon2.Geometry` are RFC 9106 §§3.4.1, 3.4.2 and §3.2's m′ | unsigned |
| H-1 | Not proved | wipes, register and stack clearing | unsigned |
| H-2 | Not proved | exceptional and asynchronous exits | unsigned |
| H-3 | Not proved | the cleanup guard does not exist yet; BLAKE2b's own compression locals will stay outside it | unsigned |
| W-1 | Warning suppression | `src/argon2-h0.ads` (`Compute`: `strub`, `zero_call_used_regs`, `flatten`), `Machine_Attribute` | no signature needed |
| W-4 | Warning suppression | `src/argon2-h_prime.ads` (`Hash`: `strub`, `zero_call_used_regs`, `flatten`), `Machine_Attribute` | no signature needed |
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
  proof covers the run-time checks, and the preconditions as obligations on
  the caller, which SPARK callers are proved to meet. A caller that is not
  proved and breaks a precondition (an empty H′ output, an H′ input over
  1,024 bytes, an H₀ digest that is not 64 bytes, compression indices
  outside the block array, an indexing position, counter or scratch block
  outside its procedure's precondition, uninitialised or aliased arguments)
  gets no diagnostic in `release`, and undefined behaviour (for example,
  writes outside an array). The four tests of a precondition check run only
  with contracts on and skip themselves in `release`. With contracts off the
  `Executable` postconditions (the cleanup guarantees) are not run in
  `release` either; their proof is unaffected. In both profiles BLAKE2b is
  compiled in its own `release` profile (Alire's default for a dependency;
  `scripts/check-exception-stack.sh` names it), with its checks and
  contracts off, so `validation` turns on this crate's checks only. No optimisation-level matrix or
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
  coverage reports as before (costliest condition 2807 of 5000 steps on that
  tree; the 17 October figures are in T-2). The
  long-input tests were not repeated on it. That tree had no compression and
  the older H′ (chunked input). On 17 October 2026, on macOS arm64, the
  current tree (H′ taking a BLAKE2b array of at most 1,024 bytes and proved
  equal to its model, `Argon2.Blocks`, compression and its model) passes 4240
  tests, the source gate, and a cold whole-crate proof of 3398 checks with none
  unproved, none
  justified and no unit skipped (`scripts/check-proof-output.sh`); the first
  CI run (17 October 2026) passed the tests and the cold proof on macOS
  arm64, Linux x86_64 and aarch64, and Windows x86_64, with blake2b 0.1.1
  from the index. The local runs used a copy beside the crate. On
  22 October 2026, on macOS arm64, the tree with `Argon2.Indexing` passes
  719,000 tests in `validation` (718,995 in `release`, the four tests of a
  precondition check skipped) and a cold whole-crate proof of 3,827 checks
  with none unproved, none justified and no unit skipped; CI has not run
  that tree yet.
- **If false:** a proof could hold for a program the compiler does not
  produce. The tests would be the only remaining evidence.
- **Scope:** all code. A version bump is a signed change.

### T-2 Provers
- **Proposition:** Z3 4.15.4, cvc5 1.3.2 and Alt-Ergo 2.6.1, driven by Why3 as
  shipped with GNATprove 16.1.0, never report a false statement proved.
- **Why believed:** widely used. The crate's proof (`argon2.gpr`, and CI)
  races all three and is limited in steps, not time (`--timeout=0`). On top of
  that, a local script, `scripts/h0-mutants.sh` (the name is old; it covers
  the six units of H₀, H′ and compression, models included, and the three of
  indexing: the code, its model and the geometry), shows at its baseline
  that every check of those units is proved by at least two
  provers each on its own, and that, for each of its conditions, the cheapest
  proof found among the single-prover runs costs no more than half the step
  budget (different conditions of one check may use different provers). Run on
  macOS arm64 on 17 October 2026: no check is proved by fewer than two
  provers; the costliest check is H′'s at 3,613 steps against the limit of
  5,000 (the budget is 10,000), H₀'s costliest is at 2,763 and compression's
  at 1,637. On 20 October 2026 (macOS arm64) the baseline passed again with
  `Argon2.Geometry` and `Argon2.Indexing_Model` added: their costliest
  checks need 1 and 2 steps, and no check of theirs is proved by fewer than
  two provers. On 22 October 2026 (macOS arm64) it passed again with
  `Argon2.Indexing` added, the other units' figures unchanged: its 134
  checks are each proved by at least two provers, and the costliest needs
  682 steps. It also shows that fifty mutated
  programs behave as designed: twelve of H₀, fourteen of compression
  (ten whose code is wrong and which the proof and the tests both catch, and
  four where code and model are wrong in the same way, which still prove, the
  blind spot of S-4, and which the tests catch), and twenty-four of indexing
  (twelve whose code is wrong, caught by the proof and the tests; one in
  `Data_Independent`, which no model states, so no proof runs and the tests
  catch it; seven whose model is wrong, caught by the proof; and four where
  code and model are wrong in the same way, the blind spot of S-5, which
  still prove and which the tests catch). One indexing code mutant (the
  own lane not forced in pass 0, slice 0) is caught on the test side only
  by the test-written lane check (T-4), not by the reference. The full suite of fifty ran on 22 October 2026.
  Earlier runs: 14 and 15
  October 2026 for H₀, and a baseline on Linux arm64 and x86_64 on 15 October.
  Two H₀ mutants are written in a particular form because Z3 runs on in the
  other (see the script's header). The mutants were run on macOS arm64 only. That script is **not** run by CI;
  all its proof runs (the baseline, the single-prover runs and every mutant)
  also carry a wall-clock timeout (default 300 s) besides the steps, unlike
  the crate's own proof, which has none; and its logs are kept outside the repository (they are gitignored),
  so the repository itself retains no record of the result. Both gates
  cover the nine units the script lists (`UNITS`): `Argon2.H0`,
  `Argon2.H_Prime` and `Argon2.Compression`, their three models,
  `Argon2.Geometry`, `Argon2.Indexing_Model` and `Argon2.Indexing`.
  `Argon2.Wipe` (the wipe procedure's body), `Argon2` and `Argon2.Blocks`
  are proved in the whole-crate run but held to neither gate; the checks at
  the wipe's calls from H₀ and H′ belong to those units, and those are
  gated. blake2b's units, on which the H₀ and H′ proofs
  depend, are not held to either gate here. The H′ units are set to
  10,000 steps per check; their costliest check needs 3,613 steps with the cheapest
  prover, a margin of 2.7 (a check is proved when any one prover proves it
  within the budget).
- **If false:** a lemma or postcondition could be false while shown proved.
- **Scope:** every proved check.

### T-3 The big-integer proof model
- **Proposition:** GNATprove's model of `Ada.Numerics.Big_Numbers.Big_Integers`
  agrees with mathematical integers. The H₀ statement counts absorbed bytes
  (up to 2³⁴ + 36) with blake2b's ghost big-integer counter. The indexing model (S-5) also
  multiplies and divides big integers: J₁², area·x and the divisions by
  2³², through blake2b's ghost conversions; `Argon2.Indexing`'s ghost code
  states each step of `Locate`'s arithmetic in those terms, so its proof of
  equality with the model rests on this too.
- **Why believed:** it is the standard library's own SPARK model. The H₀
  mutation suite includes a mutant (`len-p-omitted`) that fails the
  precondition of the call to `Absorb_Input`, whose conjuncts include the
  counter (`Absorbed (St) = Big.Length (Off)`) and the context equality; no mutant targets the
  counter's arithmetic itself (blake2b's carry mutants do, in blake2b).
- **If false:** the length claims in ghost code could be about the wrong
  numbers.
- **Scope:** ghost code only. `scripts/check-h0-object.sh` scans the symbols of
  `argon2-h0.o` and `argon2-h_prime.o` (release and validation) for
  big-integer symbols and finds none, and does the same for
  `argon2-indexing.o` (including blake2b's ghost conversions,
  `Blake2b.Hashing.Big`); for `argon2-h0_model.o` and
  `argon2-indexing_model.o` it checks only that the object's one external
  symbol is its elaboration flag, that it defines no function, and that it
  references nothing.

### T-4 Test-only trust
- **Proposition:** the C code in `tests/` is a valid reference. It decides
  whether the specification claims (S-1, S-3, S-4, S-5) are believed, not whether the
  proofs hold; production proof takes no result or contract from it.
- **What there is:**
  - seven `Import`ed C functions in the tests (`compress_oracle` in
    `tests/src/compression_tests.adb`; `h0_oracle`, `h0_oracle_generated` and
    `blake2b_512` in `tests/src/h0_tests.adb`; `blake2b_long` in
    `tests/src/test_main.adb`; `index_alpha_oracle` and
    `next_addresses_oracle` in `tests/src/indexing_tests.adb`), compiled at
    `-O3` by `tests/argon2_tests.gpr`;
  - the vendored official Argon2 reference files (`ref.c`, `core.c`, `core.h`,
    `thread.h`, `blake2/blamka-round-ref.h`, the BLAKE2b files), unmodified and
    pinned to an upstream commit (`tests/ref/README.md`); `core.c` is compiled
    with `-DARGON2_NO_THREADS`; the earlier `clear_internal_memory` shim is
    gone;
  - for compression, `tests/ref/compress_oracle.c`, a test-only file that
    `#include`s `ref.c` (which is never compiled alone) and exports one wrapper
    around the reference's static `fill_block`: the oracle for both forms of G.
    For indexing it exports two more: one that builds the reference's
    instance and position on the stack (the fields `index_alpha` reads, the
    rest as the reference sets them) and calls the reference's own
    `index_alpha`, and one that calls the reference's static
    `next_addresses` on an input block whose first seven words the test
    passes and whose other words, like the zero block, are zero, as
    `fill_segment` initialises them;
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
  - for indexing (S-5), `tests/src/indexing_tests.adb`: `Locate` against
    the reference's own `index_alpha` and `Next_Address_Block` against its
    own `next_addresses`, through the two wrappers above. The seven input
    words of each address block (m′ and y among them) are typed in by hand
    in the test, not computed by `Shape_Of`. The reference lane is checked
    against a value the test computes itself (the own lane in pass 0,
    slice 0, else J₂ mod p), a test-written oracle: the reference chooses
    the lane inside `fill_segment`, which no test calls, so until the fill
    exists the lane rests on that check and the proof. The test also tells
    `index_alpha` whether that lane is the own one. The replay that S-5
    first rested on ran outside this repository, against the vendored
    `core.c` and `ref.c` (compiled with `-DARGON2_NO_THREADS`), and against
    the reference's published memory dumps;
- **If false:** a wrong expectation could hide a defect, or hide that the
  model is not the RFC's.
- **Scope:** all tests. This crate's own rules ask for signed test-only entries
  in a separate `tests/TRUST.md`, linked from this register with
  machine-checked coverage; neither exists yet (see Notes).

### D-1 blake2b 0.1.2
- **Proposition:** the contracts and lemmas the proofs here use are true of
  blake2b's code: `Blake2b.Hashing` (`Init`, `Update` and `Final`),
  `Blake2b.Streaming` and `.Theory` (including `Logical_Equal` on
  `Same_Context`), `.Consistency`, `.Example` (`Lemma_Room`) and
  `Blake2b.Spec` with `Blake2b.Spec.Incremental`.
- **Why believed:** blake2b's own proof and register (its T-1, T-2, T-3, S-1,
  H-1, W-1 to W-8, N-1 and N-2), which this register does not repeat. On
  19 October 2026, on macOS arm64, this crate's cold proof also analyzed those
  units of 0.1.2 (the GNATprove run on this project covers the dependency's
  sources) and proved them (3432 checks in all, none unproved; on 14 October
  it did the same for 0.1.1). `alire.toml` asks for exactly blake2b 0.1.2,
  from the Alire index, whose release is the commit
  `fec91ab72758a7c5d1d06450f78615c793352440` (tag `0.1.2`) of
  `https://github.com/m-doughty/blake2b`; the proof above ran on the commit
  before it, whose sources are the same. `scripts/check-dependency.sh`
  checks that (exactly that version, and no pin of any crate); the CI
  `gates` job runs it.
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
  bounds, deterministic random inputs, and a test, run with contracts on
  only, that the precondition check raises on an input over 1,024 bytes. No
  test reaches output lengths above 2²⁴ + 8; for those
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
  pairs, and `Z` equal to `X` or `Y`, in both forms; and fourteen compression
  mutants (see T-2): the tests catch every one, including the four the proof
  cannot see because code and model share the mistake. These runs are local
  and not in CI.
- **If false:** compression would be proved equal to the wrong function, and
  the tests would be the only evidence against it.
- **Scope:** `Argon2.Compression`, `Argon2.Compression_Model`. Not the memory
  fill, indexing or the final tag.

### S-5 Indexing
- **Proposition:** `Argon2.Indexing_Model`, with `Argon2.Geometry`'s
  `M_Prime`, `Shape_Of`, `Computed` and `Data_Independent`, is RFC 9106's
  reference selection and address-block construction (§§3.4.1 and 3.4.2):
  W from the previous block or from the address block
  `G (ZERO, G (ZERO, Z))`, J₁ and J₂, the reference lane, the area, the
  start and the index; and §3.2's rounding of m to m′ blocks. Where the RFC
  leaves a point open, the model follows the official reference: the number
  of address blocks a segment needs (⌈s / 128⌉), the area listed from its
  first block cyclically, and in pass 0 every finished segment rather than
  "the last 3". Not the pass, slice and lane loops, nor the compression of
  each block.
- **What is proved:** `Shape_Of` returns p lanes, t passes, a segment of at
  least 2 and m′ = 4p·⌊m / 4p⌋ blocks. For every computed position and every
  64-bit W, the model's reference is a block of the memory and lies in the
  window of blocks already written, never the block being made or the one
  before it (the README states the window). `Argon2.Indexing` is proved
  equal to the model: for every computed position and every W, `Locate`
  returns the model's reference lane and index (the code takes J₁² and
  |W|·x in 128-bit signed subtypes bounded so that neither overflows; the
  model, in big integers); and `Next_Address_Block` leaves the model's
  address block in `Scratch (2)` and the zero block in `Scratch (0)`, with
  all three scratch blocks initialised. These postconditions are `Static`:
  proved, never compiled or run. The code was proved equal to the model,
  not to the RFC: a mistake in the model would still prove.
- **Why believed (tested, not proved):** the reference's own functions, as
  oracles (T-4): `Locate` against `index_alpha` on 338,310 cases of
  position and W, and 18,375 more at the two extreme shapes, and
  `Next_Address_Block` against `next_addresses` on 618 address blocks,
  N = 2²³ included; and twenty-four indexing mutants (T-2), including the
  four the proof cannot see because code and model share the mistake,
  which the tests catch. The choice of lane is not checked against the
  reference: the reference makes it inside `fill_segment`, so the tests
  check it against a test-written oracle (J₂ mod p, or the own lane in
  pass 0, slice 0); the reference checks it only through a whole-memory
  comparison and its published memory dumps, once the fill exists. Before
  the code, a transcription of the same rules was replayed over the
  official reference's published memory dumps (all blocks of every pass,
  the three variants) and against the reference's own memory fill at
  segment lengths it cannot reach (up to 1,024, one to five lanes); this
  replay is not in this repository. These runs are local and not yet in
  CI.
- **If false:** the indexing code would be proved equal to the wrong rule,
  and only the tests would show it; the window would still be proved, so
  the fill would still read only written blocks.
- **Scope:** `Argon2.Indexing`, `Argon2.Indexing_Model`, `Argon2.Geometry`.
  Not the memory fill, the order of the loops or the final tag.

### H-1 Wiping, registers and stack
- **Proposition:** on normal return, `Argon2.H0.Compute` and
  `Argon2.H_Prime.Hash` leave no copy of an input or intermediate digest
  that the library holds in a buffer of its own, in a call-used register
  (callee-saved registers are not zeroed; the ABI restores them), or on the
  stack. From blake2b 0.1.2, BLAKE2b's compression is inlined into its own
  scrubbed entry points (`Init`, `Update` and `Final`), so after a normal
  return its frame is inside blake2b's scrubbed body. For `Hash` this is
  measured and gated (H-2): the scan fails on any canary a hardened build
  leaves after a normal return, and on macOS arm64 (19 October 2026, both
  profiles) it found none. `Compute` has not been measured: what its calls of
  BLAKE2b leave is not known. The caller's own arrays are not erased by
  these calls. For
  `Argon2.Compression.Compress` and `Compress_Xor` it is narrower: on normal
  return no word derived from the blocks is left in a call-used register or
  in the stack frame of their body, into which every helper of the unit is
  inlined. `Work` is the caller's to wipe, and the code the body calls in
  other units (with checks on only, the run-time's check-failure and
  exception-propagation routines) is outside it (below).
- **What is proved:** after `Argon2.Wipe.Bytes`, every byte of the buffer it
  is given is zero. That is about the value of an object only.
- **What is requested, not proved:** `Wipe.Bytes` is never inlined and is
  `noipa`, with an `Inspection_Point`; the entry points `Compute`, `Hash`,
  `Compress` and `Compress_Xor` carry `strub`, `zero_call_used_regs ("all")`
  and `flatten`, and the helpers that handle input, chain values or blocks
  are `Inline_Always`, so each runs in its entry point's scrubbed frame (as
  described for compression below). The attributes and the inlining are
  checked in the object code (below), not proved. That the object code
  calls `Wipe.Bytes` where the source does is not checked (blake2b's
  `scripts/check-hardening.sh` does that for its own).
- **Compression's hardening.** `Argon2.Compression` works on blocks of
  workspace data (derived from the password, salt and key) and takes one
  block of working space from its caller (`Work`); it does not wipe `Work`
  (it is the hot loop; the caller does). `strub ("internal")` makes each of
  `Compress` and `Compress_Xor` a wrapper that calls the body (a clone) and
  then scrubs the stack the body's own frame used; `zero_call_used_regs
  ("all")` zeroes every call-used register before the wrapper returns. GCC
  scrubs only the frame of the `strub` body itself, not the frames of
  functions it calls, so every helper of `src/argon2-compression.adb` that
  handles block words (`FBlaMka`, `GB`, `Consecutive`, `Strided`, `P`,
  `Row_Pass`, `Column_Pass`, `Permute`, `Store_G`, `Combine`) is
  `Inline_Always` (GCC's `always_inline`: a call it cannot inline is a
  compilation error). With contracts on, GNAT checks the postconditions of
  `Store_G` and `Combine` by moving their statements into procedures it
  generates, which no pragma can name; `flatten` on `Compress` and
  `Compress_Xor` inlines them, and every other call that can be inlined.
  Unlike `Inline_Always`, `flatten` raises no error when it cannot inline a
  call, and GCC does not apply it at `-O0` (both profiles build at `-O3`; a
  `validation` build at `-O0` leaves those procedures, and others GNAT
  generates for the checks, out of line, and the object check fails on
  them). The whole computation then runs in the scrubbed
  frame: on macOS arm64 (17 October 2026) the `release` and `validation`
  objects define no function but the two wrappers and their clones. The body
  copies no block through libc: the first loop of `Combine` writes each word
  of `Work` straight from the two inputs (`R (K) := M (X) (K) xor M (Y) (K)`),
  where a block assignment (`R := M (X)`, as the body once had) is a call of
  libc's `memcpy`, outside the scrubbed frame (an iterated aggregate, tried
  instead of the loop, is one too: GCC builds it in a temporary and copies
  it). On macOS arm64 (17 October 2026) neither object references `memcpy`
  or `memmove`, and the `release` object references no other unit at all. With checks on, the `validation`
  object calls the run-time routines that raise an exception when a check
  fails (`__gnat_rcheck_CE_Invalid_Data`, `__gnat_rcheck_CE_Range_Check`,
  `system__assertions__raise_assert_failure`) and the unwinder's
  (`_Unwind_Resume`, `__gnat_personality_v0`), outside the scrubbed frame,
  only when a check fails, which the proof says never happens; their
  arguments are a source location, a message or the exception, not block
  data, and an exit through them is H-2's.
- **What is checked in the objects, and what is not:** `scripts/check-h0-object.sh`
  looks for proof residue and runtime cleanup: it requires `Compute`,
  `Hash`, `Compress` and `Compress_Xor` to be defined text symbols (not
  merely named), scans `argon2-h0.o`
  for soft-links, abort-deferral, secondary-stack, big-integer, model and
  theory symbols by name (any symbol, defined or referenced, whose name
  contains one), scans `argon2-h_prime.o` for soft-links, abort-deferral,
  big-integer, streaming-theory, `Spec` and absorbed-counter names but not for
  the secondary stack (which H′'s length-encoding function uses; it holds the
  output length, not a secret) nor for `Argon2.H0_Model`, and checks that
  the external symbols (`nm -g`) of `argon2-h0_model.o` and
  `argon2-h_prime_model.o` are only their elaboration flag, and that they
  define no function. That is a check on static ghost code having left nothing
  behind (see N-2), not on wiping, and it looks at symbol names, not at the
  code. For `argon2-h0.o`, `argon2-h_prime.o` and `argon2-compression.o`, in
  both the `release` and the `validation` objects, it also reads the code,
  the same check for each: the entry points (`Compute`; `Hash`; `Compress`
  and `Compress_Xor`) must be defined text symbols with a `strub` clone each
  (`<name>.strub.<n>`), and at each return of the wrapper, at least the
  registers a probe shows `zero_call_used_regs ("all")` zeroes must hold
  zero, within the parser's limits below. That set is
  measured, not written down: the script compiles a probe function with the
  attribute with the toolchain's `gcc` and disassembles it (on macOS arm64,
  `x0`–`x17` and `v0`–`v7`, `v16`–`v31`). The parser
  (`scripts/zeroed-at-return.awk`, 30 tests in
  `scripts/test-zeroed-at-return.sh`) counts a register as zeroed at a
  return only if it is zeroed after the last call, branch or branch target
  before that return and not written again (in any view of it); an 8- or
  16-bit x86 clear does not count, since it leaves the upper bits. A cold part
  of a wrapper (`<name>.cold`) that returns is checked at its returns like
  the wrapper; the clone, and its cold part, are not checked on their own
  (they return into the wrapper). Its limits: it reads symbol names and
  instructions only; a jump from a cold part back into its hot function is
  invisible in a `.o` file (the target is a relocation), so such a path is
  not seen; and it is a linear scan, not a proof about control flow. It
  also requires that the object
  define no function but the entry-point wrappers, their clones and GCC's
  cold parts of either (`<name>.cold`, code of the same function): a helper
  left out of line fails the check by name, unless it is hardened itself (its own
  `strub` clone, and the registers zeroed at each of its returns). It fails
  if the object references `memcpy` or `memmove` (or their `_chk` forms),
  naming them; a copy of the crate with `R := M (X)` restored fails it in
  both profiles, naming `memcpy` (macOS arm64, 17 October 2026). For H₀ the
  one function allowed outside the scrubbed bodies is GNAT's initialisation
  procedure for the body's `Parameters` record, `argon2__h0__parametersIP`,
  and only while its code is a single return. H₀ copies each input into a
  local chunk by a byte loop; at `-O3` GCC turns that loop into a `memcpy`
  call, so `argon2.gpr` compiles `argon2-h0.adb` with
  `-fno-tree-loop-distribute-patterns` (without it the `release` object
  references `memcpy` and the check fails). It lists, without checking them,
  the other symbols the object references in other units.
  It scans the object's symbols for
  the same names as `argon2-h0.o` (soft-links, abort deferral, the secondary
  stack, big integers, models, theory), and checks that `argon2-compression_model.o`
  holds only its elaboration flag and the initialisation procedure of the type
  `Positions` (N-5). For indexing, whose `Locate` and `Next_Address_Block`
  are `Inline_Always` so that they run in the scrubbed frame of the
  hardened subprogram that calls them, it requires that the `release`
  object `argon2-indexing.o` define no function (in `validation` it lists
  the functions, without checking them), that neither profile's object name
  the same residue as compression's, the indexing model, blake2b's ghost
  conversions or the unit's own ghost subprograms, and that
  `argon2-indexing_model.o` hold only its elaboration flag; before reading
  the crate's objects it checks its own symbol reading against control
  objects compiled by the same `gcc`, with a planted function or
  big-integer reference that must fail. On macOS arm64 (22 October 2026)
  neither profile's `argon2-indexing.o` defines a function. Nothing calls
  the two procedures yet, so whether they are inlined into a scrubbed frame
  is not checked; that check comes with their caller, the fill. It does
  not check how much stack is scrubbed, nor what the run-time leaves, nor
  `Work`.
- **If false:** key- or password-derived bytes could remain in memory the
  library no longer controls.
- **Scope:** macOS arm64, Linux arm64 and Linux x86_64 so far (the object check
  ran in the containers on 14 and 15 October 2026, the last time on the renamed crate); Windows x86_64 and the
  compilers and targets of CI, whose first run passed it on all four platforms (T-1). The
  part of the object check that reads the code (H₀, H′ and compression) has
  run on macOS arm64 only (17 October 2026: GCC 16.1.0, Apple's LLVM
  objdump); CI runs it on the other three platforms and has not run it yet.
  See also H-2.

### H-2 Exceptional and asynchronous exits
- **Proposition:** none is made. The wipes run on normal completion with the
  preconditions met. An exception, a task abort or a stack overflow in the
  middle of `Compute` or `Hash` leaves whatever the buffers held; no handler
  wipes them (the sources contain no exception handler). What an exception
  leaves on the stack has been measured, below; nothing is claimed beyond
  that measurement. The same scan gates what a normal return leaves (below).
- **What is scanned, and on what code:** `scripts/check-exception-stack.sh`
  (see its header), on copies of the sources and of the BLAKE2b version
  Alire deployed, built in both profiles (BLAKE2b in its `release` profile,
  as the tests build it), never `src/` itself. Three kinds of build: the
  shipped sources (normal returns); copies with ONE statement inserted per
  case, `if <trigger> then raise Program_Error; end if;` (the raise, and the
  normal return of the same build, since the line can change the code
  around it); and, for compression, a copy that spills 32 permuted words
  (256 bytes) into a local array of volatile components in `Store_G` (case
  A′, no raise). Case A: in
  `Argon2.Compression.Store_G`, after the permutation of `M (X) xor M (Y)`,
  firing when `Z = 2`. Case B: in `Argon2.H_Prime.Initial_Hash` (inlined into
  `Hash`'s scrubbed body), after `Blake2b.Hashing.Update (S, Input)`, firing when
  `Input'First = 1`. Case C: in `Blake2b.Core.Compress` after round 6 of 12,
  firing on the last block of a 1,024-byte message, that is during `Final`,
  called from `Hash`. The inputs hold known 64-bit canaries (for A, the words
  of `M (X)`, `M (Y)`, their xor and its permutation, the last computed by an
  independent transcription checked against the library's output; for B and
  C, the words of the message BLAKE2b compresses), all on the heap. A driver
  zeroes the stack below one frame, makes the call there through a frame
  holding an unused 8 KiB spacer (so that the handler's own run-time calls do
  not overwrite what the call left), catches any exception, and counts the
  canaries in the stack it zeroed (24 KiB, doubled when needed), five
  processes per build. Each build has a **control**, the same copy with
  `strub` and `zero_call_used_regs` removed from both crates. Hits are
  counted per 8-byte position (aligned or not); the distinct words found are
  given in brackets (for B and C, message words only: a hit on an input word
  that straddles two adjacent message words repeats their bytes). The probe
  recognises selected complete 64-bit words only: a partial word, a word in
  another form, or any other value is not seen.
- **What is gated, and what is reported:** exit 1 (a harness error, or a
  blind normal-return control: A′'s control must leave its spilled words,
  32 of 32 on macOS arm64, and the hardened build none, `strub` scrubbing
  them) and exit 3 (a hardened build left a canary after a normal return,
  in any case: A, A′, B or C) fail the script and CI's job. For B and C,
  where control and hardened build both leave none, the result passes as
  "not discriminating". Exception results are reported only; where an
  exception's control leaves no canary they are marked unmeasured and CI
  prints a warning.
- **What GCC emits for an exceptional exit** (the injected copies' objects,
  macOS arm64): once the body can raise, the `strub` wrapper gets a cleanup
  that zeroes the body's frame (from the watermark to the wrapper's stack
  pointer, as on a normal return) and then resumes the propagation
  (`_Unwind_Resume`). The frames below the body's, those of the run-time's
  raise routines and of the unwinder, are not zeroed, and the registers are
  not cleared on that path (`zero_call_used_regs` acts at returns).
- **Results, macOS arm64, blake2b 0.1.2** (19 October 2026, GCC 16.1.0,
  natively; one run of the present script, five processes per build, 24 KiB
  region; control / hardened, hits (distinct words); a range is the spread
  over the processes):

  | Case | Profile | Exception | Normal, injected build | Normal, shipped sources |
  |---|---|---|---|---|
  | A | release | 14 (8) / 10–12 (8) | 0 / 0 | 0 / 0 |
  | A | validation | 6 (4) / 6 (4) | 0 / 0 | 0 / 0 |
  | A′ (spill) | both | no raise | 32 (32) / 0 | not applicable |
  | B | release | 1 (1) / 0 | 2 (2) / 0 | 2 (2) / 0 |
  | B | validation | 0–1 (1) / 0 | 2 (2) / 0 | 2 (2) / 0 |
  | C | release | 5 (5) / 0 | 0 / 0 | 2 (2) / 0 |
  | C | validation | 5 (5) / 0 | 0 / 0 | 2 (2) / 0 |

  **Results, macOS arm64, blake2b 0.1.1** (17 October 2026, two runs of an
  earlier version of the script; on 19 October the present script, on a
  copy of the crate set back to 0.1.1, gave the same figures for B and C and
  failed, exit 3, on every normal return of B and C):

  | Case | Profile | Exception | Normal, injected build | Normal, shipped sources |
  |---|---|---|---|---|
  | A | release | 14 (8) / 10–12 (8) | 0 / 0 | 0 / 0 |
  | A | validation | 5–6 (4) / 6 (4) | 0 / 0 | 0 / 0 |
  | A′ (spill) | both | no raise | 32 (32) / 0 | not applicable |
  | B | release | 2 (2) / 3 (2) | 1 (1) / 1 (1) | 1 (1) / 1 (1) |
  | B | validation | 2 (2) / 3 (2) | 1 (1) / 1 (1) | 1 (1) / 1 (1) |
  | C | release | 5 (5) / 5 (5) | 1 (1) / 1 (1) | 1 (1) / 1 (1) |
  | C | validation | 5 (5) / 5 (5) | 1 (1) / 1 (1) | 1 (1) / 1 (1) |

  **Results, Linux, from the earlier version of the script** (17 October
  2026, in containers: aarch64 natively on Apple silicon, x86_64 emulated;
  that version had no shipped-sources build, no A′, and one control for both
  modes; raise / normal return of the injected build, hits (distinct
  words)):

  | Platform | Case | Profile | Control | Hardened |
  |---|---|---|---|---|
  | Linux aarch64 | A | both | 5 (5) / 0 | 0 / 0 |
  | Linux aarch64 | B, C | release | 14 (4) / 4 (4) | 0 / 4 (4) |
  | Linux aarch64 | B, C | validation | 14 (4) / 0 | 0 / 0 |
  | Linux x86_64 | A | release | blind: 0 / 0 | not measured |
  | Linux x86_64 | A | validation | 1 (1) / 0 | 0 / 0 |
  | Linux x86_64 | B, C | release | blind: 0 / 16–17 (10–11) | not measured; 0 / 19 (11) |
  | Linux x86_64 | B, C | validation | blind: 0 / 8 (6) | not measured; 0 / 10 (6) |

  Both with the pinned toolchain; macOS arm64 is the only platform measured
  with the present script. On macOS the hardened builds leave about what the unhardened ones leave after an
  exception: in A, words of the xor (each the low half of a vector register
  at the raise, consistent with the unwinder saving the floating-point
  registers) and permuted words (held in callee-saved registers), in the
  run-time's and the unwinder's frames below the scrubbed one; in B and C,
  with blake2b 0.1.1, message words in the frame of `Blake2b.Core.Compress`,
  which was not hardened itself (its callers' `strub` scrubbed only their
  own frames). With blake2b 0.1.2, which inlines that compression into its
  scrubbed entry points, the hardened builds left none after the raise in B
  and C (the controls 1 and 5); reported only, not a claim. On Linux aarch64 the
  hardened builds left none after the raise in any case; the measurement
  does not tell whether the scrub or the propagation's own frames (resumed
  from the wrapper's frame, so written over the stack below it) removed
  them. On Linux x86_64 the exception's propagation overwrote the stack the
  call had used, in the controls as in the hardened builds (for H′, GNAT
  generates a cleanup in `Initial_Hash`, to release the secondary stack,
  which now sits in `Hash`'s clone and resumes the propagation from that
  frame), so B, C and A in
  `release` were blind there; the present script would mark those exception
  results unmeasured (a warning, not a failure), and whether A′ sees its
  spill there is not known yet. On macOS the first process after a build
  sometimes left fewer hits in B's `validation` build (1 instead of 2 or 3).
- **Normal returns (gated):** for compression, no selected canary words were
  detected after a normal return of the hardened `Compress` (macOS arm64,
  both profiles, shipped and injected builds), and A′ shows that the scan
  sees words an unhardened build leaves in the body's frame (32 of 32) and
  that `strub` removes them in the hardened one. That is not complete
  erasure: the probe recognises selected complete 64-bit words only. The
  earlier script also found none on Linux aarch64, and on Linux x86_64 in
  `validation`, but had no A′, so there that is not a measurement. After a
  normal return of the hardened `Hash`, with blake2b 0.1.2, no selected
  canary word was detected (macOS arm64, 19 October 2026, both profiles,
  shipped and injected builds), where the controls left 2 message words in
  every build but C's injected one (0, not discriminating). From 0.1.2
  BLAKE2b's compression runs inside its own scrubbed entry points, and the
  scan fails on any hardened hit after a normal return in B and C as in A.
  With blake2b 0.1.1 one message word remained there in each profile (a
  debugger placed it in the frame of `Blake2b.Core.Compress`, which ran
  outside the scrubbed bodies), and the earlier script found more on Linux
  (in `release` 4 on aarch64 and 11 on x86_64, in `validation` none on
  aarch64 and 6 on x86_64); the present script would fail on such hits.
  Whether 0.1.2 leaves none on Linux and Windows is not known until CI
  runs the scan there.
- **Task abort: not measured.** In each of the three platforms and both
  profiles, an asynchronous select around a loop of `Compress` (the shipped
  sources, no injected line) was never interrupted before the loop ended by
  itself (0 of 3 trials, control and hardened). GNAT's run-time with
  zero-cost exceptions does not abort asynchronously (the abort signal's
  handler, `Abort_Handler` in `System.Task_Primitives.Operations`, returns at
  once), so an abort completes at the next abort completion point, and the
  hardened subprograms contain none. Incidentally, the stack held canaries
  (0 to 8 per trial in the recorded runs, mostly 4 to 6) after the trials
  whose delay expired during the loop, and none after those whose delay
  never expired: consistent with the abort signal's
  frame (the interrupted registers) being pushed below the scrubbed one; not
  examined further, and not a claim.
- **Not covered:** Linux aarch64 and x86_64 with the present script, and
  Windows x86_64 with any version of it, until CI runs it; H₀ (`Compute`) and `Compress_Xor`;
  other raise points, inputs and lengths; values other than the selected
  canary words, and partial words; the registers themselves; signals, stack
  overflow (`Storage_Error`), and the exits the proof rules out (a failed
  check). On x86-64 Linux, a leaf `strub` clone may use the 128-byte red
  zone below its stack pointer; whether GCC's watermark, and so the scrub,
  covers it is shown neither by the arm64 measurement nor by the object
  check, which reads symbols and instructions, not stack extents.
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
  itself could change that. From blake2b 0.1.2 that compression is inlined
  into blake2b's scrubbed entry points (`Init`, `Update` and `Final`), so
  after a normal return those locals are in a scrubbed body's frame, and the
  scan (H-2) fails on any canary a hardened build leaves after a normal
  return of `Hash`.
- **What is requested, not proved:** stack scrubbing and register clearing
  by compiler attributes (`strub`, `zero_call_used_regs`), which are not
  proved. For H₀, H′ and compression they are checked in the object code
  (H-1), on macOS arm64 so far. Their helpers are inlined into the entry
  point's scrubbed frame, and none copies data through libc (H-1).
- **If false:** after an abnormal exit (H-2), or if a scrub is not emitted,
  bytes derived from the password or key can remain in stack memory the library
  no longer controls.
- **Scope:** the future public calls; today, `Argon2.H_Prime.Hash`,
  `Argon2.H0.Compute` and `Argon2.Compression`.

### W-1, W-4, W-6, W-7 `Machine_Attribute` ignored
- **W-1, W-4, W-6, W-7** (`Machine_Attribute` ignored by GNATprove):
  `src/argon2-h0.ads` (`Compute`: `strub`, `zero_call_used_regs` and
  `flatten`); `src/argon2-h_prime.ads` (`Hash`: the same three);
  `src/argon2-wipe.ads` (`Bytes`: `noipa`); `src/argon2-compression.ads`
  (`Compress`, `Compress_Xor`: the same three as `Compute`). `Inline_Always`
  on the helpers of H₀, H′ and compression is a pragma GNATprove accepts
  without a warning; it needs no row.
  **Reason recorded:** "code-generation attribute: no effect on proof".
  GNATprove ignores the attribute, which is correct: it affects code
  generation only.
- **W-2** (`src/argon2-h0.adb`, `strub` and `zero_call_used_regs` on seven
  helpers) and **W-5** (`src/argon2-h_prime.adb`, the same on
  `Initial_Hash`) were retired when those helpers became `Inline_Always`,
  inlined into the hardened entry point: the attributes, and the
  suppressions with them, are gone from the bodies.
- **W-3** was retired when `Argon2.H0.Compute`'s BLAKE2b state became a
  formal (`Hash_State`): the unused-state warning no longer arises and the
  suppression is gone from `src/argon2-h0.adb`.

## Notes
- **N-1 Annotations that are not trusted:** `Hide_Info` on `H0_Original`,
  `Fields_Of`, `H0_Contents` and `Chunk_At` (`src/argon2-h0_model.ads`) hide
  an expression function's body from the provers. Each is reopened by
  `Unhide_Info` in a lemma that GNATprove proves, so they are proof
  engineering, not assumptions. The same holds for compression: `Hide_Info`
  on `FBlaMka`, `GB` and `P` (`src/argon2-compression_model.ads`) hide a
  function's body from the provers, and each is reopened by `Unhide_Info` in
  the compression body where GNATprove proves it. `Logical_Equal` on
  `Same_Block` and `Same_Positions` (`src/argon2-compression.adb`) and on
  `Same` (`src/argon2-h_prime.adb`) lets the provers substitute equal
  arrays into opaque functions, and null-body lemmas convert array equality
  into it. These are expression functions whose bodies GNATprove sees, so it
  emits a check, at each annotation, that the body is the logical equality
  (reported as an inline check), and proves it, as it proves the lemmas'
  postconditions; blake2b's own `Logical_Equal` functions (`Same_Context`,
  which the H₀ proof uses, D-1) are checked the same way in its units, which
  this crate's whole-crate run also analyses. Proof engineering, not
  assumptions. In `Argon2.H_Prime`, `Hide_Info` on `Prefix_Done` (in `Hash`) and
  on `Blake2b.Spec.Incremental.Update` (in `Initial_Hash`) are local: they only
  stop the provers unfolding a definition, and two null-body ghost lemmas
  reopen `Prefix_Done` where a proof needs it. The existing `Hide_Info` on
  `Message`, `V` and `Tail` in `Argon2.H_Prime_Model` is the same kind. The
  H′ and compression units were restructured on 17 October 2026 so that every
  check is proved by two provers each on its own (T-2). In `Argon2.Indexing`
  (`src/argon2-indexing.adb`), `Logical_Equal` on its own `Same_Block` (a
  static ghost function distinct from compression's) is checked and proved
  in the same way, and a null-body lemma converts array equality into it;
  and `Hide_Info` on `Argon2.Compression_Model.G`, local to
  `Next_Address_Block`, only stops the provers unfolding G there (the proof
  composes `Compress`'s postconditions and never needs G's body). Proof
  engineering, not assumptions.
- **N-2 Static ghost code:** every declaration in `Argon2.H0_Model` is
  `Ghost => Static`, so nothing of it is compiled in any profile. In
  `Argon2.H0`, the static loop invariants of `Absorb_Input` and `Compute` are
  a single call to a static ghost function (`In_Progress`); written inline they
  left abort-deferral calls in the release object. `Copy_Chunk`'s static
  invariant is an inline quantified expression over the arrays and leaves no
  such calls (checked by `scripts/check-h0-object.sh`). H′'s,
  compression's and indexing's objects are checked by the same script.
- **N-4 A warning annotation outside the W rows:** `pragma Unreferenced (Off,
  Src, From)` in `Argon2.H0_Model` (`src/argon2-h0_model.adb`, the body of
  a ghost procedure) silences unused-parameter diagnostics, because those
  parameters appear only in the contract. It is not a `pragma Warnings` region
  and affects no proof.
- **N-5 A `Static` postcondition and assertion levels:** `Compress` and
  `Compress_Xor` state their result in a `Static` postcondition
  (`src/argon2-compression.ads`, with `pragma Assertion_Level (Executable)`
  naming the other level), and `Hash` does the same for H′
  (`src/argon2-h_prime.ads`), and `Locate` and `Next_Address_Block` for
  indexing (`src/argon2-indexing.ads`). GNATprove proves them; no build
  compiles or runs them, and `Compression_Model`, `H_Prime_Model` and
  `Indexing_Model` are static ghost code, so nothing of these models is in
  any object, except, from `Compression_Model`,
  the type `Positions` (not ghost, because the implementation uses it): its
  object holds the elaboration flag and the initialisation procedure GNAT
  generates for that type, which returns at once, and nothing else (checked by
  `scripts/check-h0-object.sh`). The result of compression, of H′ and of
  indexing is therefore checked at run time only by the tests against the
  reference oracle (and, for H′, CPython; for indexing's lane, the
  test-written check of T-4). This uses GNAT 16.1.0's assertion
  levels (T-1).
- **N-3 Follow-ups before signature:**
  - the separate test-only register this crate's rules ask for, and the
    machine-checked link from this one;
  - an object-code hardening gate for `Compute` and `Hash` (compression's
    is in `scripts/check-h0-object.sh`);
  - keeping the mutation and coverage logs where the repository, not a
    gitignored directory, holds them, or running the suite in CI;
  - `Lemma_Room` comes from a blake2b example unit,
    `Blake2b.Streaming.Example`, and should move to its theory unit in a
    blake2b release.
