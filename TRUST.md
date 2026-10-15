# argon2id trust register

Everything the crate's claims rest on that its own proof does not
establish. **No entry is signed.** The sign-off is a signature by the
maintainer's key, produced by a tool that does not exist yet; until it does,
every sign-off reads `unsigned`. Entries here are proposals, and an agent
cannot sign them. The README says what is proven, what is tested and what is
trusted; this file is the detail behind its "trusted" list.

The crate is an early milestone: H′ (RFC 9106 §3.3) and H₀ (RFC 9106 §3.2).
Memory filling, block compression and the public password-hashing interface
do not exist yet, and nothing here covers them.

## Summary

| Class | Entries | Needs a signature |
|---|---|---|
| Assumptions (`pragma Assume`, `False_Positive`, `Intentional`, `Skip_Proof`, an `Import` GNATprove trusts) | none in `src/` | would need one each |
| Unproved code (`SPARK_Mode => Off`, C or Rust behind it) | none in `src/` | would need one each |
| Third-party SPARK | blake2b 0.1.1, same maintainer, its own register (D-1) | listed |
| Trusted definitions | none | would need one each |
| Warning suppressions | W-1 to W-6 (`pragma Warnings`); see also N-4 | no, each has a recorded `Reason` |
| Toolchain and proof model | T-1 to T-3 | a bump is a signed change |
| The specification | S-1 to S-3 | listed |
| Not proved | H-1 (wiping), H-2 (abnormal exits) | listed |
| Test-only trust (C oracles, `Import`ed C in `tests/`, CPython-generated vectors) | T-4 | listed; the separate tests register this crate's rules ask for does not exist yet |

`scripts/check-sources.sh` enforces the first two rows, the warning
suppressions and the `Unreferenced` pragma, on the source as the compiler reads it (comments and strings
removed, case and line breaks normalised). It fails on any `Assume`, `Import`,
`pragma Interface`, `SPARK_Mode => Off`, `False_Positive`, `Intentional` or
`Skip_Proof` in `src/`; on a `pragma Warnings` suppression without a `Reason`;
when the number of suppressions differs from the number of `W-n` rows of this
register; on any `pragma Unreferenced` other than the single one in
`src/argon2id-h0_model.adb` (N-4); and when `argon2id.gpr` no longer carries
`--warnings=error` and `-gnatwe` or adds a switch that turns warnings off.
It checks the count of the `W-n` rows, not that each row names the right
place, and `--self-test` runs it against known bypasses. The project's
`--warnings=error` also makes any unexplained proof warning fail the proof.

**What CI is configured to run, once it has run** (it has not): on each of
the four platforms the build with checks and contracts, the H′ and H₀ tests
including `--long`, and `scripts/check-h0-object.sh`; the full GNATprove run;
and, once, `scripts/check-sources.sh` (and its self-test), `scripts/check-dependency.sh`, `scripts/h0-vectors.py --check` and the
proof-judge self-test. It does not run the mutation and coverage suite
(`scripts/h0-mutants.sh`). Nothing below depends on a CI result as yet.

## Entries

| ID | Kind | Location | Sign-off |
|---|---|---|---|
| T-1 | Toolchain | GNAT, GNATprove, gprbuild, Alire | unsigned |
| T-2 | Toolchain | the provers and Why3 | unsigned |
| T-3 | Proof model | GNAT runtime big-integer library | unsigned |
| T-4 | Test-only trust | the C oracles and `Import`ed C in `tests/` | unsigned |
| D-1 | Third-party SPARK | `blake2b` 0.1.1 from the Alire index | unsigned |
| S-1 | Specification | `Argon2id.H0_Model` is the RFC 9106 §3.2 message | unsigned |
| S-2 | Specification | `Blake2b.Spec` is RFC 7693, and `Logical_Hash` is BLAKE2b beyond 2³¹ bytes | unsigned |
| S-3 | Specification | H′ is RFC 9106 §3.3 (no functional proof) | unsigned |
| H-1 | Not proved | wipes, register and stack clearing | unsigned |
| H-2 | Not proved | exceptional and asynchronous exits | unsigned |
| W-1 | Warning suppression | `src/argon2id-h0.ads` (`Compute`), `Machine_Attribute` | no signature needed |
| W-2 | Warning suppression | `src/argon2id-h0.adb`, `Machine_Attribute` on seven helpers | no signature needed |
| W-3 | Warning suppression | `src/argon2id-h0.adb` (`Compute`), `St` is set by `Finish` but not used | no signature needed |
| W-4 | Warning suppression | `src/argon2id-h_prime.ads` (`Hash`), `Machine_Attribute` | no signature needed |
| W-5 | Warning suppression | `src/argon2id-h_prime.adb` (`Copy_Chunk`, `Initial_Hash`), `Machine_Attribute` | no signature needed |
| W-6 | Warning suppression | `src/argon2id-wipe.ads` (`Bytes`), `Machine_Attribute` | no signature needed |

### T-1 Compiler and build tools
- **Proposition:** GNAT 16.1.0 compiles the SPARK source to code that behaves
  as the language defines it, and GNATprove 16.1.0 implements SPARK's
  semantics, so a proof of the source is a proof about the compiled program.
  gprbuild 26.0.1 and Alire 2.1.1 build what the sources say. (`alire.toml`
  asks only for `gnat >= 16`; CI installs the exact GNAT and gprbuild
  versions and the Alire version, the nested `tests/alire.toml` pins
  GNATprove, and the README states them.)
- **Why believed:** on 14 October 2026, on macOS arm64, the pinned versions
  pass the test suite built with run-time checks and contracts on (`release`
  and `validation` both enable them; no checks-off build, optimisation-level
  matrix or build-matrix script exists, unlike blake2b; Alire's default
  `development` profile also exists and is not used for any claim). The same
  proof, tests and checks then ran on Linux arm64 and Linux x86_64 in
  containers (the first run on 14 October 2026, the second, on the final
  sources of this draft, on 15 October 2026; GNAT, GNATprove and the provers
  at the pinned versions, but gprbuild 26.0.0, not 26.0.1, which the images
  carry), with the same result, plus the long-input tests (21 passed on each)
  on the first run's sources. Those runs used a copy of blake2b 0.1.1 beside
  the crate, not the index. Windows x86_64 has no evidence yet, and CI for the
  four platforms is configured and has not run.
- **If false:** a proof could hold for a program the compiler does not
  produce. The tests would be the only remaining evidence.
- **Scope:** all code. A version bump is a signed change.

### T-2 Provers
- **Proposition:** Z3 4.15.4, cvc5 1.3.2 and Alt-Ergo 2.6.1, driven by Why3 as
  shipped with GNATprove 16.1.0, never report a false statement proved.
- **Why believed:** widely used. The crate's proof (`argon2id.gpr`, and CI)
  races all three and is limited in steps, not time (`--timeout=0`). On top of
  that, a local script, `scripts/h0-mutants.sh`, shows at its baseline that
  every H₀ check is proved by at least two provers each on its own (as run
  on 14 and 15 October 2026, on macOS arm64 and, on 15 October, on Linux arm64
  and x86_64: 322 of 360 model checks and 187 or 188 of 207 client checks by
  all three, the rest by exactly two, none by fewer) and that,
  for each of its conditions, the cheapest proof found among the single-prover
  runs costs no more than half the step budget (different conditions of one
  check may use different provers), and that
  twelve mutated programs are not proved (the mutants were run on macOS
  arm64 only; the Linux runs ran the baseline and single-prover runs). That script is **not** run by CI;
  all its proof runs (the baseline, the single-prover runs and every mutant)
  also carry a wall-clock timeout (default 300 s) besides the steps, unlike
  the crate's own proof, which has none; and its logs are kept outside the repository (they are gitignored),
  so the repository itself retains no record of the result. The H′ and wipe
  checks, and blake2b's units on which the H₀ proof depends, are not held to
  the two-prover rule.
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
  `argon2id-h0.o` and `argon2id-h_prime.o` (release and validation) for
  big-integer symbols and finds none; for `argon2id-h0_model.o` it checks only
  that the object's one external symbol is its elaboration flag and that it
  references nothing.

### T-4 Test-only trust
- **Proposition:** the C code in `tests/` is a valid reference. It decides
  whether the specification claims (S-1, S-3) are believed, not whether the
  proofs hold; production proof takes no result or contract from it.
- **What there is:**
  - four `Import`ed C functions in the tests (three in `tests/src/h0_tests.adb`,
    one in `tests/src/test_main.adb`), compiled at `-O3` by
    `tests/argon2id_tests.gpr`;
  - the vendored official Argon2 reference files, pinned to an upstream commit
    (`tests/ref/README.md`), with a test-only shim for `clear_internal_memory`;
  - for H₀, three C functions written for the tests in `tests/src/h0_oracle.c`
    (an incremental serialisation, a one-shot hash of the serialisation the Ada
    test builds, and the generated-bytes oracle of the `--long` run). The first
    two sit on the **one** vendored BLAKE2b implementation, and the reference's own
    `initial_hash` is not vendored, so H₀ is checked against test-written
    serialisations, not against the Argon2 reference's own H₀ code; H′ is
    checked against the reference's own `blake2b_long`;
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
  blake2b's code: `Blake2b.Hashing` (`Init`, `Update`, `Final`, and the one-shot `Hash`, which
  H′ calls),
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
- **Proposition:** `Argon2id.H0_Model` (`H0_Original`, `H0_Contents`,
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
- **Scope:** `Argon2id.H0.Compute`. Parameters are hashed as given; the
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
- **Proposition:** `Argon2id.H_Prime.Hash` computes RFC 9106 §3.3 H′.
- **What is proved:** absence of run-time errors, the exact encoding of the
  output length, byte-for-byte correspondence of each copied chunk with its
  input interval, the absorbed-byte counts and the output intervals
  (`docs/proof-scope.md`). It is **not** proved equal to an independent
  specification of H′. Discharging the size precondition of its calls to
  `Blake2b.Hashing.Update` depends on blake2b's proof-visibility note N-2
  (D-1).
- **Why believed (tested, not proved):** cases against the vendored official
  Argon2 C reference's `blake2b_long`, including boundary lengths, arbitrary
  bounds and deterministic random inputs.
- **If false:** H′ could differ from RFC 9106 on an input no test reaches.
- **Scope:** `Argon2id.H_Prime`. A proof that H′ equals an independent
  specification is not done.

### H-1 Wiping, registers and stack
- **Proposition:** on normal return, `Argon2id.H0.Compute` and
  `Argon2id.H_Prime.Hash` leave no copy of an input or intermediate digest
  that the library holds in a buffer of its own, in a call-used register
  (callee-saved registers are not zeroed; the ABI restores them), or on the
  stack. The caller's own arrays are not erased by these calls.
- **What is proved:** after `Argon2id.Wipe.Bytes`, every byte of the buffer it
  is given is zero. That is about the value of an object only.
- **What is requested, not proved or gated:** `Wipe.Bytes` is never inlined and
  is `noipa`, with an `Inspection_Point`; the entry points and the helpers that
  handle input carry `strub` and `zero_call_used_regs ("all")`. This crate has
  no object-code hardening gate (blake2b has `scripts/check-hardening.sh`);
  nothing checks that wipes or scrubbing exist in the object code.
- **What is checked in the objects, and what is not:** `scripts/check-h0-object.sh`
  looks for proof residue and runtime cleanup: it requires `Compute` and
  `Hash` to be defined text symbols (not merely named), scans `argon2id-h0.o`
  for soft-links, abort-deferral, secondary-stack, big-integer, model and
  theory symbols by name (any symbol, defined or referenced, whose name
  contains one), scans `argon2id-h_prime.o` for soft-links, abort-deferral,
  big-integer, streaming-theory, `Spec` and absorbed-counter names but not for
  the secondary stack (which H′'s length-encoding function uses; it holds the
  output length, not a secret) nor for `Argon2id.H0_Model`, and checks that
  the external symbols (`nm -g`) of `argon2id-h0_model.o` are only its
  elaboration flag. That is a check on static ghost code having left nothing
  behind (see N-2), not on wiping, and it looks at symbol names, not at the
  code.
- **If false:** key- or password-derived bytes could remain in memory the
  library no longer controls.
- **Scope:** macOS arm64, Linux arm64 and Linux x86_64 so far (the object check
  ran in the containers on 14 and 15 October 2026); Windows x86_64 and the
  compilers and targets of CI once it has run (T-1). See also H-2.

### H-2 Exceptional and asynchronous exits
- **Proposition:** none is made. The wipes run on normal completion with the
  preconditions met. An exception, a task abort or a stack overflow in the
  middle of `Compute` or `Hash` leaves whatever the buffers held; no handler
  wipes them (the sources contain no exception handler). Nothing has examined
  the behaviour on such exits.
- **If false (if cleanup were expected):** secrets remain after an abnormal
  exit. The cleanup mechanism is a separate design, not part of this crate yet.
- **Scope:** every call.

### W-1 to W-6 `Machine_Attribute` ignored, and a state not read again
- **W-1, W-2, W-4, W-5, W-6** (`Machine_Attribute` ignored by GNATprove):
  `src/argon2id-h0.ads` (`Compute`); `src/argon2id-h0.adb` (`Store_LE32`,
  `Copy_Chunk`, `Copy_Input`, `Absorb_Field`, `Absorb_Chunk`, `Absorb_Input`,
  `Finish`); `src/argon2id-h_prime.ads` (`Hash`); `src/argon2id-h_prime.adb`
  (`Copy_Chunk`, `Initial_Hash`); `src/argon2id-wipe.ads` (`Bytes`).
  **Reason recorded:** "code-generation attribute: no effect on proof".
  GNATprove ignores the attribute, which is correct: it affects code
  generation only.
- **W-3** (`"St" is set by "Finish" but not used`): `src/argon2id-h0.adb`,
  around the call to `Finish` in `Compute`. **Reason recorded:** "the state is
  finalized and wiped; only Digest is used".

## Notes
- **N-1 Annotations that are not trusted:** `Hide_Info` on `H0_Original`,
  `Fields_Of`, `H0_Contents` and `Chunk_At` (`src/argon2id-h0_model.ads`) hide
  an expression function's body from the provers. Each is reopened by
  `Unhide_Info` in a lemma that GNATprove proves, so they are proof
  engineering, not assumptions. `Logical_Equal` is blake2b's, checked there.
- **N-2 Static ghost code:** every declaration in `Argon2id.H0_Model` is
  `Ghost => Static`, so nothing of it is compiled in any profile. In
  `Argon2id.H0`, the static loop invariants of `Absorb_Input` and `Compute` are
  a single call to a static ghost function (`In_Progress`); written inline they
  left abort-deferral calls in the release object. `Copy_Chunk`'s static
  invariant is an inline quantified expression over the arrays and leaves no
  such calls (checked by `scripts/check-h0-object.sh`). H′ keeps inline
  static invariants, including one over the big-integer counter; its object is
  checked by the same script and is clean.
- **N-4 A warning annotation outside W-1 to W-6:** `pragma Unreferenced (Off,
  Src, From)` in `Argon2id.H0_Model` (`src/argon2id-h0_model.adb`, the body of
  a ghost procedure) silences unused-parameter diagnostics, because those
  parameters appear only in the contract. It is not a `pragma Warnings` region
  and affects no proof.
- **N-3 Follow-ups before signature:**
  - the separate test-only register this crate's rules ask for, and the
    machine-checked link from this one;
  - an object-code hardening gate for `Compute` and `Hash`;
  - the proof and the tests on the other three platforms (CI is configured);
  - keeping the mutation and coverage logs where the repository, not a
    gitignored directory, holds them, or running the suite in CI;
  - `Lemma_Room` comes from a blake2b example unit,
    `Blake2b.Streaming.Example`, and should move to its theory unit in a
    blake2b release.
