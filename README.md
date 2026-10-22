# argon2

An Ada/SPARK implementation of four parts of Argon2
([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)): the variable-length
hash H′ (§3.3), the pre-hashing digest H0 (§3.2), the block compression
function G (§§3.5, 3.6) and the indexing (§3.4: the reference block of each
position, and the address blocks), which nothing calls yet. This is an early
milestone; it does not yet implement password hashing or memory filling, and
the Argon2d, Argon2i and Argon2id variants are not yet offered.

The BLAKE2b dependency is blake2b 0.1.2, exactly that version, from the
Alire index. Builds need no neighbouring checkout.

## API

```ada
with Argon2;
with Argon2.H_Prime;

--  Input is a Blake2b.Byte_Array of at most 1,024 bytes; Digest is an
--  Argon2 byte array. S, V and Next_V are scratch the caller supplies.
Argon2.H_Prime.Hash (Input, Digest, S, V, Next_V);
```

H′ hashes at most `Max_Input_Bytes` = 1,024 bytes of input, which is all
Argon2 ever hashes (a 72-byte seed, or a 1,024-byte block); a longer input
breaks the precondition, which only the `validation` profile checks (see
"Preconditions in the release profile" below). `Digest` may be 1 through 2³²−1 bytes
(`Argon2.Byte_Array`, index 0 through 2³²−2); the future complete Argon2 API
will require at least 4 output bytes. The input is absorbed in one piece and
not copied. The caller supplies the output buffer, and the scratch: `S` is a
`Blake2b.Hashing.State`, `V` and `Next_V` are 64-byte chain values
(`Argon2.H_Prime.Chain`). Their contents on entry do not matter; on normal
return `V` and `Next_V` are zero and `S` has been finalized (which wipes it);
the postcondition says so, and it is proved, so a SPARK caller can rely on it.
`H0.Compute` likewise states that its `Hash_State` is finalized on return.
Input and output must not overlap. Byte P of `Digest` is byte P of H′ as
`Argon2.H_Prime_Model` writes RFC 9106 §3.3, for every P (the postcondition;
see "H′: what is proven, tested and trusted" below).

```ada
with Argon2.H0;

--  Password, Salt, Secret and Associated_Data are Argon2 byte arrays;
--  the six parameters are Interfaces.Unsigned_32; Digest is a 64-byte
--  Blake2b.Byte_Array; Hash_State is scratch the caller supplies.
Argon2.H0.Compute
  (Password, Salt, Secret, Associated_Data,
   Parallelism, Tag_Length, Memory, Passes, Version, Kind, Digest,
   Hash_State);
```

`Compute` returns H0 = BLAKE2b-512 of LE32(p) ‖ LE32(T) ‖ LE32(m) ‖ LE32(t) ‖
LE32(v) ‖ LE32(y) ‖ LE32(length(P)) ‖ P ‖ LE32(length(S)) ‖ S ‖
LE32(length(K)) ‖ K ‖ LE32(length(X)) ‖ X, with p = `Parallelism`,
T = `Tag_Length`, m = `Memory` (the memory size as given, not the rounded
m′), t = `Passes`, v = `Version`, y = `Kind`. Each input may be empty or up
to 2³²−1 bytes long, with any bounds, so the hashed message is up to
2³⁴ + 36 bytes. The parameters are hashed as given: `Compute` does not check
them against RFC 9106's ranges, which is the job of the future complete API.
`Digest` must be 64 bytes long, with any bounds. Inputs are fed into BLAKE2b
in chunks of at most 4,096 bytes; nothing is sized from an input's length.

```ada
with Argon2.Blocks;
with Argon2.Compression;

--  M is an Argon2.Blocks.Block_Array of 1,024-byte blocks (128 words of 64 bits).
--  Work is one scratch block the caller supplies; it holds a mix of the two
--  inputs on return and nothing in Compress wipes it, so the caller does.
Argon2.Compression.Compress     (M, X, Y, Z, Work);  --  M (Z) := G (M (X), M (Y))
Argon2.Compression.Compress_Xor (M, X, Y, Z, Work);  --  M (Z) := M (Z) xor G (M (X), M (Y))
```

`Compress` is the first-pass form of RFC 9106 §3.5, `Compress_Xor` the
later-pass form of version 1.3. `X`, `Y` and `Z` are block indices into `M`;
`Z` may equal `X` or `Y`. `M (X)` and `M (Y)` must be initialised (and, for
`Compress_Xor`, `M (Z)`); `M` may otherwise be partly uninitialised. These
packages are internal building blocks for the future Argon2 interface and are
not a stable public API.

## Build, test and prove

Requires GNAT 16 or newer. Development uses Alire 2.1.1, GNAT 16.1.0,
GPRbuild 26.0.1 and GNATprove 16.1.0.

```sh
bash scripts/check-dependency.sh
bash scripts/check-sources.sh
cd tests
alr -n build --validation --profiles=argon2=validation
./bin/test_main
alr -n exec -- gnatprove -P ../argon2.gpr -j0
cd ..
bash scripts/check-proof-output.sh --whole-crate
```

`check-sources.sh` fails if `src/` contains `Assume`, `Import`,
`pragma Interface`, `SPARK_Mode => Off`, `False_Positive`, `Intentional` or
`Skip_Proof`, a warning suppression without a `Reason` or without a row in
`TRUST.md`, or if the project stops making warnings fatal; `--self-test` runs
it against known bypasses. GNATprove exits 0 and prints `Success` even when
it skips a unit. `check-proof-output.sh` reads the run's summary and fails on
a skipped unit, a checking error, any unproved or justified check, a missing
total or one that is not a positive number, a missing `Analyzed N units`
line (or a unit count that differs from it), a unit with subprograms left
unanalysed (none may be in this crate's units; a dependency's unit may fall
short only by GNAT run-time generics whose bodies are `SPARK_Mode => Off`,
as `blake2b-hashing` does, 33 of 37), and (with `--whole-crate`, as CI runs
it) any unit of `src/` absent from the summary (`--self-test` runs it
against 18 bad summaries).

Build before invoking GNATprove: Alire generates the project configuration
files during the build. GNATprove is a dependency of the nested test crate,
so library consumers do not install it. The `release` profile drops this
crate's run-time checks and contracts; the `validation` profile keeps both
on, and the tests run on it. In both, the BLAKE2b dependency is compiled in
its own `release` profile, with its checks and contracts off (Alire's default
for a dependency, which these commands and CI leave as it is;
`scripts/check-exception-stack.sh` names it, `blake2b=release`), so
`validation` turns on this crate's checks and contracts only.
The default run (719,000 tests, 22 October
2026, macOS arm64) compares H′ against the
[vendored official Argon2 C reference](tests/ref/README.md) and against
CPython-generated vectors, including input lengths 0, 1, 72, 127, 128, 129,
1,023 and 1,024, output lengths from 1 byte to 2²⁴ + 8, arbitrary bounds and
deterministic random inputs, and checks that the precondition check raises
on an input over 1,024 bytes. It compares `Argon2.Compression` word for word
with the reference's own compression function, and `Argon2.Indexing` with
the reference's own `index_alpha` and `next_addresses`. CI also runs the
same tests on the `release` build, where the four tests of a precondition
check (an empty H′ output, an H′ input over 1,024 bytes, a 32-byte H0
digest, an indexing position among the first two blocks of pass 0,
slice 0) skip themselves, each printing
`note: skipped (contracts off): <name>`; CI requires exactly four such
lines, and no failure. Run locally, the `release` build passes 718,995
tests (22 October 2026, macOS arm64).

**Preconditions in the release profile.** The proof covers the run-time
checks, and the preconditions as obligations on the caller: a SPARK caller
is proved to meet them. In `release` neither the checks nor the
preconditions run, so a caller that is not proved and breaks a precondition (an empty H′ output, an H′ input over
1,024 bytes, an H0 digest that is not 64 bytes, compression indices outside
the block array, an indexing position, counter or scratch block outside its
procedure's precondition, uninitialised or aliased arguments) gets no
diagnostic and undefined behaviour, such as writes outside an array. The
`Executable` postconditions (the cleanup guarantees) do not run in
`release` either; their proof is unaffected (see [TRUST.md](TRUST.md) T-1).

Several more commands are not part of the default run:

- `./bin/test_main --long` (from `tests/`) runs only the long H0 tests (see
  below). They allocate up to 4 GiB at once (never 16 GiB) and took about
  4 minutes on Linux aarch64 and 8 minutes on Linux x86_64, in containers.
- `alr -C tests -n exec -- bash ../scripts/check-h0-object.sh` (from the
  crate's root, after building both the `validation` and the `release`
  profile; it needs the toolchain's `gcc` and an `objdump`, hence `alr exec`)
  checks the compiled objects: no trace of the proof (model, big integers,
  streaming theory) and no abort-deferral calls in `argon2-h0.o`,
  `argon2-h_prime.o`, `argon2-compression.o` and `argon2-indexing.o`, no
  secondary stack in `argon2-h0.o`, `argon2-compression.o` and
  `argon2-indexing.o`, nothing but the elaboration flag in
  `argon2-h0_model.o`, `argon2-h_prime_model.o` and
  `argon2-indexing_model.o`, and no function in them (and, in
  `argon2-compression_model.o`, the flag and the empty initialisation of the
  type `Positions`). For indexing, the `release` object
  `argon2-indexing.o` must define no function at all (`Locate` and
  `Next_Address_Block` are `Inline_Always`); in `validation` the functions
  it defines are listed, not checked. Before reading the crate's objects,
  the script checks its own symbol reading against control objects it
  compiles, with a planted function or big-integer reference that must
  fail. For compression it also reads the code: `Compress` and
  `Compress_Xor` must have their stack-scrubbing (`strub`) clone; at each
  return of the two wrappers (and of a wrapper's cold part, `<name>.cold`,
  that returns) it must find zeroed at least the registers that a probe,
  compiled with the same `gcc`, shows `zero_call_used_regs ("all")` zeroes
  on the target (a linear scan of the disassembly, not a proof about control
  flow; its limits are in [TRUST.md](TRUST.md) H-1); the object must define
  no other function (a helper left out of line, outside the scrubbed frame,
  fails it by name); and it must not call `memcpy` or `memmove` (a block
  copy, which would run in libc, outside the scrubbed frame; the failure
  names them). It lists the other symbols the object references in other
  units (with checks on, the run-time's check-failure and
  exception-propagation routines).
  `bash scripts/test-zeroed-at-return.sh` tests the disassembly parser it
  uses (30 cases, GNU and LLVM output for x86-64 and AArch64).
- `bash scripts/check-exception-stack.sh` (from the crate's root, after
  building `tests/` once) scans the stack below the hardened subprograms for
  known 64-bit canaries: a gate on what a normal return leaves, and a
  measurement of what an exception leaves. It builds copies of the sources
  (and of the BLAKE2b version Alire deployed) in `obj/exception-stack/`, in
  the `release` and `validation` profiles, never `src/` itself, of three
  kinds: the shipped sources (normal returns); copies with one injected
  `raise` per case (exceptions, and the normal return of the same build),
  in `Compress` after the permutation, in `H′` after the input is absorbed,
  and inside BLAKE2b's compression during `H′`; and, for compression, a copy
  that spills 32 permuted words (256 bytes) into a volatile local array (A′,
  no raise). A driver fills the inputs with canaries, zeroes the stack below
  one frame, makes the call there and counts the canaries left in that
  stack. Each build has a control, the same copy with `strub` and
  `zero_call_used_regs` removed. Exit 1 (a harness error, or a blind
  normal-return control: A′'s control left none of its spilled words) and
  exit 3 (a hardened build left a canary after a normal return, in any
  case) fail it. Exception results are reported only; where an
  exception's control leaves no canary they are marked unmeasured (CI
  prints a warning). It also tries a task abort
  (an asynchronous select around `Compress`), reported only. The numbers
  and their limits are in [TRUST.md](TRUST.md) H-2.
- `python3 -I scripts/h0-vectors.py --check` checks that
  `tests/src/h0_vectors.ads`, the H0 digests computed with CPython's
  `hashlib`, is what the script generates (run it without `--check` to
  regenerate).
- `python3 -I scripts/h-prime-vectors.py --check` checks that
  `tests/src/h_prime_vectors.ads`, 55 H′ outputs (recorded as the BLAKE2b digest
  of each whole output) computed with CPython's `hashlib` from RFC 9106 §3.3, is
  what the script generates (run it without `--check` to regenerate).
- `python3 -I scripts/compression-vectors.py --check` checks that
  `tests/src/compression_vectors.ads`, 15 blocks taken from the reference's
  own known-answer files (`tests/ref/kat-blocks.json`), is what the script
  generates, and that each block is the compression of two other blocks of the
  same file (run it without `--check` to regenerate).
- `bash scripts/h0-mutants.sh` runs the mutation suite for the H0,
  compression and indexing units (indexing with its model and the
  geometry), after a baseline that checks the step margin and that
  two provers each prove every check alone (for those units and H′'s) (see
  its header; `--selftest`
  checks its test classifier alone). It takes tens of minutes and is not run
  by CI.

For H′, compression and indexing the proofs establish equality with the
crate's own model of the RFC's function (`Argon2.H_Prime_Model`,
`Argon2.Compression_Model`, `Argon2.Indexing_Model`), not with the RFC
itself: that each model is the
RFC's function is tested, not proved. The precise scope is documented in
[docs/proof-scope.md](docs/proof-scope.md).

## H0: what is proven, tested and trusted

**Proven** (GNATprove 16.1.0, from cold, step limits only, run on macOS
arm64, and the H0 and H′ parts on Linux arm64 and Linux x86_64 in containers
(14 and 15 October 2026, on an earlier tree); the two H0 units are held to
10,000 steps per check; in the mutation suite's baseline (macOS arm64,
17 October 2026) every check is proved by at least two of Z3, CVC5 and
Alt-Ergo each on its own, and the costliest needs 2,763 steps with its
cheapest prover (2,807 in the run of 15 October, on the earlier tree); no
`pragma Assume`, no `Import`, no justified check, no `SPARK_Mode => Off`):

- **The digest.** `Compute`'s postcondition: `Digest` equals
  `H0_Model.H0_Hash`, which is `Blake2b.Streaming.Theory.Logical_Hash`
  (unkeyed, 64 bytes) of the logical message `H0_Model` builds from the
  arguments, for every legal input length, empty inputs and the
  2³⁴ + 36-byte maximum included. The proof follows the real `Init`, every
  real `Update` (ten 4-byte fields, each input in 4,096-byte chunks) and the
  real `Final`, with the per-call lemmas of blake2b 0.1.2.
- **Two views of the message agree.** `H0_Model` lays the message out as
  fourteen sources (the ten fields and P, S, K, X) cut into fourteen pieces
  in RFC 9106's order. `Lemma_All_Positions` proves that at every position,
  padding included, that layout gives the byte `H0_Byte` reads off the
  formula by running offsets: the little-endian byte of a field, a byte of
  an input, or zero past the end. Empty inputs are empty pieces;
  `Lemma_Extremes` covers the all-empty and all-maximal cases.
- **Chunks.** Each chunk copied from an input, and each field's four bytes,
  hold exactly their place in the logical message (`Lemma_Slice`,
  `Lemma_Input_Chunk`, `Lemma_Field_Chunk`), however an input is cut.
- **The specification.** Wherever the message fits one array (at most 2³¹
  bytes), `H0_Hash` is `Blake2b.Spec.Hash` of the explicit serialisation
  (`Lemma_H0_Spec_Hash`).
- No run-time error, termination, and zero in every scratch buffer after
  its wipe.

All of `H0_Model`, and every model reference in `Argon2.H0`, is static
ghost code: proved, never compiled (`scripts/check-h0-object.sh` checks the
objects).

What the proof does not show is that `H0_Model` (`H0_Byte`, `H0_Original`,
`Fields_Of`) is RFC 9106 §3.2: it is this crate's transcription of the
formula, and a mistake made the same way in both views would still prove.
That the transcription is the RFC's is **tested**, as blake2b tests its
specification against RFC 7693.

**Tested** (`tests/src/h0_tests.adb`):

- RFC 9106 §5.1–5.3: the three published pre-hashing digests.
- 19 digests computed by CPython's `hashlib.blake2b` from the RFC's formula
  (`scripts/h0-vectors.py`), each also against both C oracles below.
- Every differential case against two C oracles over the vendored
  reference BLAKE2b: its own serialisation of the inputs, written in C, and
  a one-shot hash of the serialisation the test builds. Empty and one-byte
  inputs, each input at the chunk boundaries (4,095, 4,096, 4,097, 8,192
  bytes and more), inputs of up to 3 MiB, arrays at the top of the index
  range, every field 0 and 2³²−1, distinct bytes in every field, m not a
  multiple of 4p, 200 random cases, and digests at arbitrary bounds; with
  contracts on, the precondition check raises on a 32-byte digest (in
  `release` that test skips itself).
- `--long`, through the public `Compute`, against a C oracle that
  regenerates every input from its own seed and position: four inputs of
  2³²−1 bytes (one array passed as all four), a 2³⁴ + 36-byte message; and
  each of P, S, K and X in turn at 2³¹−1, 2³¹, 2³¹+1 and 2³²−1 bytes, the
  other three short, of different lengths and contents, so that swapped
  inputs, swapped length fields or one input hashed in place of another
  change the digest. The byte generator is one formula written twice (in
  the Ada test and in the C oracle), so the test also checks that the bytes
  it generates vary and differ between seeds.
- A mutation suite (`scripts/h0-mutants.sh`): swapped fields, big-endian
  fields, a missing length field, a dropped last chunk, the rounded m′ in
  place of m, P and S copied in each other's place, a missing bridge step,
  and model mutants. Each is caught by the proof at the check its entry
  names, and each mutant of compiled code by an H0 test too. For
  compression, fourteen more: ten with wrong code (a rotation constant or
  direction, the factor 2 of fBlaMka, a diagonal index, the pass order, the
  register view, a wrong word read in the first XOR, the final XOR, the XOR
  with the old block) caught by the proof and the tests, and four where the
  code and the model are wrong the same way, which the proof cannot catch
  and the tests do.

**Trusted.** The proofs rest on blake2b 0.1.2: its streaming theory, its
`TRUST.md` (including note N-2: the whole-stream lemmas read
`Blake2b.Hashing.Max_Input`'s private completion through proof
visibility), and its specification, which its own tests validate against
BLAKE2b; and on the toolchain (GNATprove, its provers, GNAT). The crate's
own [TRUST.md](TRUST.md) lists all of it, unsigned: four GNATprove warning
suppressions, each with its reason (the ignored `Machine_Attribute` pragmas
in `argon2-h0.ads`, `argon2-h_prime.ads`, `argon2-wipe.ads` and
`argon2-compression.ads`), the test-only C code, and what is not proved.

**Scope limits.** H0, H′ and block compression only (internal building
blocks): no Argon2 password hashing, no parameter validation, no memory
filling. Beyond 2³¹ bytes the proved statement is equality with
`Logical_Hash`, blake2b's model of a long stream, which is tied to
`Blake2b.Spec.Hash` wherever one array holds the message and is not itself
proven against RFC 7693. The first CI run (17 October 2026) passed the tests and the cold
proof on macOS arm64, Linux x86_64 and aarch64, and Windows x86_64. The
long tests exercise the maximum length and the 2³¹ boundaries once each.
Buffers are wiped and the stack-scrubbing and register-clearing attributes
are requested as for H′ (see "Zeroization boundary" in
[docs/proof-scope.md](docs/proof-scope.md)), with the same limits; the
object check above does not inspect the wipes, nor whether these attributes
took effect in H0's object.

## H′: what is proven, tested and trusted

**Proven** (GNATprove 16.1.0, from cold, step limits only; whole crate, macOS
arm64, 22 October 2026: 3,827 checks, none unproved, none justified, no unit
skipped; the H′ units are held to 10,000 steps per check and their costliest
check needs 3,613 with the cheapest prover, a margin of 2.7, checked by the
margin gate; no `pragma Assume`, no `Import`, no `SPARK_Mode => Off`):

- **The output.** After `Hash (Input, Digest, …)`, byte P of `Digest` is
  `Argon2.H_Prime_Model.Out_Byte (Input, Digest'Length, P)` for every P, for
  every output length from 1 byte to 2³²−1 and every input of at most 1,024
  bytes. The model writes RFC 9106 §3.3 as it reads: for T ≤ 64 the T-byte
  BLAKE2b of LE32 (T) ‖ A; for T > 64, r = ⌈T/32⌉ − 2, V₁ the 64-byte BLAKE2b
  of LE32 (T) ‖ A, Vᵢ the 64-byte BLAKE2b of Vᵢ₋₁, the first 32 bytes of
  V₁ … Vᵣ and then V(r+1), the BLAKE2b with a digest length of T − 32r of Vᵣ
  (not a truncation). The proof follows the real `Init`, `Update` and `Final`
  of blake2b 0.1.2 and relates the k-th value of the loop to the model's
  V(k + 1); it never unfolds the chain (up to 2²⁷ links).
- **The input bound.** An input over 1,024 bytes breaks the precondition: a
  SPARK caller is proved never to pass one; for any other caller only
  `validation` checks it (see "Preconditions in the release profile").
- No run-time error, termination, and zero in the chain values and a finalized state on return (public
  postconditions of `Hash` and of `H0.Compute`).

The model is static ghost code: proved, never compiled, never run, and so is the
postcondition that states the result. No test runs it.

What the proof does not show is that `H_Prime_Model` is RFC 9106 §3.3: it is
this crate's transcription, and a mistake in it would still prove. That it is
the RFC's is **tested**.

**Tested** (`tests/src/h_prime_tests.adb`, `tests/src/test_main.adb`):

- 55 H′ outputs computed by CPython's `hashlib.blake2b` straight from the RFC
  text (`scripts/h-prime-vectors.py`): inputs of 72 and 1,024 bytes at output
  lengths 1, 4, 31, 32, 33, 63, 64, 65, 66, 95, 96, 97, 127, 128, 129, 1,023,
  1,024, 1,025, 2¹⁶ ± 1, 2²⁰, 2²⁰ + 8 and 2²⁴ + 8 (the last link of the chain has a
  length that is not a multiple of 32, which a truncating variant gets wrong),
  and seven short and empty inputs.
- The same lengths against the vendored official reference's `blake2b_long`,
  byte for byte, and its comparison loop over input lengths 0, 1, 72, 127, 128,
  129, 1,023 and 1,024, output lengths from 1 to 1,025, arbitrary bounds and
  random inputs; with contracts on, the precondition check raises on an
  input over 1,024 bytes and on an empty output (in `release` those two
  tests skip themselves).
- Output lengths beyond 2²⁴ + 8 (up to 2³²−1) are covered by the proof only; no
  test reaches them.

**Trusted.** `H_Prime_Model` as the RFC's function ([TRUST.md](TRUST.md) S-3),
blake2b 0.1.2 and its specification (D-1, S-2), the toolchain, and the test-only
C code and CPython (T-4).

**Scope limits.** H′ only. Buffers are wiped and the stack-scrubbing and
register-clearing attributes are requested on `Hash`, with the same limits as
for H0 (see "Zeroization boundary" in [docs/proof-scope.md](docs/proof-scope.md));
the object check does not inspect the wipes. `S`, `V` and `Next_V` are supplied
by the caller so that a future cleanup guard can reach them; no guard exists yet.
From blake2b 0.1.2, BLAKE2b's compression is inlined into its own scrubbed
entry points, so after a normal return its frame is inside blake2b's
scrubbed body. `scripts/check-exception-stack.sh` fails on any canary a
hardened build leaves after a normal return (macOS arm64, 19 October 2026:
none, in both profiles). After an exception, what remains depends on the
platform; the script measures it, on copies with an injected `raise`, and
nothing prevents it (see [TRUST.md](TRUST.md) H-2).

## Block compression: what is proven, tested and trusted

**Proven** (GNATprove 16.1.0, from cold, step limits only; whole crate, macOS
arm64, 22 October 2026: 3,827 checks, none unproved, none justified, no unit
skipped; the compression units are held to 10,000 steps per check, and their
costliest check needs 1,637 with the cheapest prover, checked by the margin
gate, and every check is proved by two provers each on its own; no
`pragma Assume`, no `Import`, no `SPARK_Mode => Off`):

- **The result.** After `Compress (M, X, Y, Z)`, `M (Z)` is `G` of the original
  `M (X)` and `M (Y)`, and every other initialised block is unchanged;
  `Compress_Xor` does the same with the old `M (Z)` xor `G`. This holds for
  every index in range, `Z` equal to `X` or `Y` included. `G` here is
  `Argon2.Compression_Model.G`, a transcription of RFC 9106 §§3.5 and 3.6 (the
  8×8 register matrix, `P` on each row and then each column, BlaMka's `GB`
  with `fBlaMka` and the rotations 32, 24, 16, 63).
- **Initialisation.** `M (X)` and `M (Y)` must be initialised; `M (Z)` is
  initialised afterwards; no block that was initialised becomes uninitialised,
  so a workspace need not be filled first.
- **The index lists.** The literal row and column index lists the code uses
  (copied from the reference) are proved equal to the model's row and column
  positions.
- No run-time error, termination.

The model is static ghost code: proved, never compiled, never run. The
postcondition that states the result is likewise proved and never executed, so
no test runs it.

What the proof does not show is that `Compression_Model` is RFC 9106 §§3.5 and
3.6: it is this crate's transcription, and a mistake in it would still prove.
That it is the RFC's is **tested**.

**Tested** (`tests/src/compression_tests.adb`):

- 15 blocks from the official reference's own known-answer files for Argon2d,
  Argon2i and Argon2id (`tests/src/compression_vectors.ads`, generated by
  `scripts/compression-vectors.py`), each the compression of two other blocks
  of the same file, in both forms.
- Differential cases against the unmodified reference's compression function:
  every one of the 128 word positions alone in either input, extreme words
  (including the multiplication's wrap), `X` equal to `Y`, pseudo-random pairs
  at varied layouts and index bounds, and `Z` equal to `X` or `Y`, each in both
  forms.

**Trusted.** `Compression_Model` as the RFC's compression function
([TRUST.md](TRUST.md) S-4), the toolchain, and the test-only C code.

**Scope limits.** Compression only: no memory filling, no lane indexing, no
password hashing, no Argon2d, Argon2i or Argon2id. `Compress` and
`Compress_Xor` request GCC's stack scrubbing (`strub`) and clearing of all
call-used registers (`zero_call_used_regs`); that is requested and checked in
the object code, not proved. Every helper of the compression body is
`Inline_Always` and the two entry points also request `flatten`, so the whole
computation runs in the one scrubbed frame. The object check above finds the
scrubbing clone, at each return of the wrappers at least the registers a
probe shows `zero_call_used_regs` zeroes (within the limits in
[TRUST.md](TRUST.md) H-1), and no function left out of line, in the
`release` and `validation` objects; it has run on macOS arm64 only so far
(17 October 2026), and CI runs it on the other three platforms. The body copies no block through libc: it fills `Work` word by
word from `M (X)` and `M (Y)`, neither object calls `memcpy` or `memmove`,
and the object check fails if one does. The `release` object calls nothing
in another unit; with checks on (`validation`), the body calls the
run-time's check-failure and exception-propagation routines, outside the
scrubbed frame, only when a check fails, which the proof says never happens
(see [TRUST.md](TRUST.md) H-1). Compression does not wipe `Work`: its caller
does. The scrubbing and register clearing are for normal returns: after a
normal return of `Compress`, `scripts/check-exception-stack.sh` detected
none of its selected canary words on the stack, and fails if it does
(macOS arm64, 17 October 2026, both profiles; a copy that spills 32 words
into the body's frame shows that the scan sees them when the hardening is
removed). When an exception escapes `Compress` (in a copy with an injected
`raise`), the values held in registers at the raise can reappear in the
stack frames of the exception's propagation, below the scrubbed frame: on
macOS arm64 the hardened build left about as many as an unhardened one, on
Linux aarch64 (an earlier version of the script) none. The script measures
this and does not gate it; nothing prevents it (see [TRUST.md](TRUST.md)
H-2).

## Indexing: what is proven, tested and trusted

`Argon2.Indexing` is the code: `Locate` (the reference block of a position,
for its pseudo-random value W, step by step as the reference's `index_alpha`
computes it) and `Next_Address_Block` (an address block, G (ZERO, G (ZERO,
Z)), as the reference's `next_addresses` makes it). `Argon2.Geometry` gives
the memory's shape and positions, and `Argon2.Indexing_Model` is the model:
which earlier block each position is compressed with, and the address
blocks (RFC 9106 §3.4). Nothing calls `Locate` or `Next_Address_Block` yet;
the memory fill will. Like compression, they are internal building blocks,
not a stable public API.

**Proven** (GNATprove 16.1.0, from cold, step limits only; whole crate, macOS
arm64, 22 October 2026: 3,827 checks, none unproved, none justified, no unit
skipped; the three units are held to 10,000 steps per check; in the mutation
suite's baseline (macOS arm64, 22 October 2026) every check is proved by two
provers each on its own, and `Argon2.Indexing`'s costliest check needs 682
steps with the cheapest prover, checked by the margin gate (T-2); no
`pragma Assume`, no `Import`, no `SPARK_Mode => Off`):

- **`Locate`.** For every computed position and every 64-bit W, the
  reference lane and index `Locate` returns are those of the model's
  `Locate`. The model computes in mathematical integers; the code takes the
  products J₁² and |W|·x in a 128-bit signed type, in subtypes bounded so
  that neither can overflow (an overflow would be a failed check).
- **`Next_Address_Block`.** For a segment whose positions are
  data-independent, and a counter N up to the number of address blocks the
  segment needs, `Scratch (2)` is the model's address block
  G (ZERO, G (ZERO, Z_N)) on return, `Scratch (0)` is still the zero block,
  and all three scratch blocks are initialised (`Scratch (1)` and
  `Scratch (2)` may be uninitialised on entry). G is
  `Argon2.Compression_Model.G`, through `Argon2.Compression.Compress`.
- **The address stream.** `Lemma_Address_Stream`, for the fill's loop:
  block Index of a segment takes address block Index / 128 + 1, which is at
  most the number the segment needs; it takes the same block as Index − 1,
  or the next one when Index is a multiple of 128; indices 0 to 127 take
  block 1.
- **`Shape_Of`.** The shape of p lanes and m KiB has m′ = 4p·⌊m / 4p⌋
  blocks, a segment of at least 2 blocks, and at most 2³² − 1 blocks.
- **The reference is a block of the memory.** For every computed position
  (every position but the first two blocks of each lane in pass 0, which
  come from H₀; in later passes those two are computed too, and the first
  one's previous block is the lane's last) and every 64-bit W: the area is not
  empty, the reference lane is one of the p lanes (the block's own in pass 0,
  slice 0), and the reference index is in the lane. The products J₁² and
  area·x are taken in mathematical integers.
- **The window.** The reference is a block already written and not the
  previous one: in pass 0, a block before the previous one in the own lane,
  or one of another lane's finished segments (less the last block when the
  position is the first of its segment); in later passes, any block but the
  rest of the own segment and the previous block, or, in another lane, any
  but the current slice (and its block before it, for the first position).
  This is the safety property the memory fill will rely on, not the RFC's
  exact choice: an area wrong by a block that stays inside the window would
  still prove.
- No run-time error, termination.

`Indexing_Model`, `Geometry`'s `M_Prime` (with the half of `Shape_Of`'s
postcondition that names it), the postconditions of `Locate` and
`Next_Address_Block` that name the model, and `Lemma_Address_Stream` are
static ghost code: proved, never compiled, never run, so no test runs them.
`Indexing_Model`'s object file holds only the package's elaboration flag.
The rest of `Geometry` (`Shape_Of`, `Computed`, `Data_Independent` and the
shape's sizes) is ordinary code, compiled into the library and used by
`Argon2.Indexing`.

What the proof does not show is that `Indexing_Model` is RFC 9106 §3.4: it
is this crate's transcription, and a mistake in it would still prove. That
it is the RFC's is **tested**.

**Tested** (`tests/src/indexing_tests.adb`, with the oracles in
`tests/ref/compress_oracle.c`):

- `Locate` against the unmodified reference's `index_alpha`: 338,310 cases
  (9,666 positions, 35 values of W at each: J₁ at 0, 2³² − 1 and three
  pseudo-random values; J₂ at 0, 2³² − 1, values that give the own lane and
  lane p − 1, each small and near 2³², and a pseudo-random one), for segments of
  2, 3, 127, 128, 129, 130 and 256 blocks, one, two, three and five lanes,
  three passes, every slice, the first, a middle and the last lane, and the
  segment indices 0, 1, 2, 127, 128, 129 and the last; and 18,375 cases at
  the two extreme shapes (2²⁴ − 1 lanes with a segment of 64 blocks, and one
  lane with a segment of 2³⁰ − 1, each with m′ near 2³²). Each case checks
  the lane and the index. The expected lane (the own lane in pass 0,
  slice 0, else J₂ mod p) is computed by the test itself, not by the
  reference, which chooses the lane inside its `fill_segment`; the test
  tells `index_alpha` whether that lane is the own one.
- `Next_Address_Block` against the reference's `next_addresses`, on 618
  address blocks: every counter of segments of 2, 128, 129 and 300 blocks
  with one, two and five lanes, every pass of three and every slice for
  Argon2i, pass 0, slices 0 and 1 for Argon2id, other pass counts, and the
  extremes of each word (the pass 2³² − 2 of 2³² − 1, the lane 2²⁴ − 2, m′
  near 2³², and the largest counter, N = 2²³). The oracle's input words are
  typed in by hand, not computed by `Shape_Of`; each case also checks that
  `Scratch (0)` is still the zero block.
- With contracts on, the precondition check raises when `Locate` is given
  one of the first two blocks of pass 0, slice 0 (in `release` that test
  skips itself).
- `Shape_Of` on 18 shapes against hand values of the segment and m′ (the
  least memory, m not a multiple of 4p, the largest m, segment and pass
  count), and `Data_Independent` at every slice of five passes for each
  variant, including Argon2id's turn to data-dependent at pass 0, slice 2.
- A mutation suite (`scripts/h0-mutants.sh`, macOS arm64, 22 October 2026),
  24 indexing mutants, all caught: twelve with wrong code (in `Locate`,
  `Next_Address_Block` and `Shape_Of`) caught by the proof and the tests,
  and one in `Data_Independent`, which no model states, caught by the tests
  alone; seven with a wrong model, caught by the proof; and four where the
  code and the model are wrong the same way (J₁ and J₂ swapped, the counter
  word N − 1, one G instead of two, the pass word left 0), which the proof
  cannot catch and the tests do. One code mutant (the own lane not forced
  in pass 0, slice 0, where the index does not depend on the lane) is
  caught only by the test-written lane check, not by the reference.
- Before the code existed, the model was also checked outside this
  repository, by replaying a transcription of it over the official
  reference's published memory dumps and against the reference's own memory
  fill (segment lengths up to 1,024, one to five lanes).

**Trusted.** `Indexing_Model` and `Geometry` as RFC 9106's reference
selection and address blocks ([TRUST.md](TRUST.md) S-5), `Compression_Model`
for the G of the address blocks (S-4), the big-integer proof model (T-3),
the toolchain and the provers (T-1, T-2), and the official reference's C
code and the test-written lane check (T-4).

**Scope limits.** Indexing only: nothing calls `Locate` or
`Next_Address_Block` yet; the memory fill will. The choice of lane is
checked against the reference only once the fill exists, by comparing whole
memories with the reference's and with its published memory dumps; until
then it rests on the proof against the model and the test-written check.
`Locate` and `Next_Address_Block` are `Inline_Always`, so that they run in
the scrubbed frame of the hardened subprogram that calls them (W comes from
secret-derived memory in Argon2d and Argon2id). The object check above
requires that the `release` object `argon2-indexing.o` define no function
(on macOS arm64, 22 October 2026, neither profile's object defines one);
whether the two procedures are inlined into their caller's scrubbed frame
can be checked only once that caller exists, with the fill. CI has not yet
run this code.

Licensed under [BSD-3-Clause](LICENSE).
