# argon2id

An Ada/SPARK implementation of two parts of Argon2
([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)): the variable-length
hash H′ (§3.3) and the pre-hashing digest H0 (§3.2). This is an early Argon2id
milestone; it does not yet implement password hashing, block compression,
memory filling or Argon2id's lane indexing.

The BLAKE2b dependency is blake2b 0.1.1 from the Alire index, exactly that
version and unpinned. Builds need no neighbouring checkout.

## API

```ada
with Argon2id;
with Argon2id.H_Prime;

--  Input and Digest are Argon2id byte arrays.
Argon2id.H_Prime.Hash (Input, Digest);
```

The byte-array length domain is 0 through 2³²−1. H′ accepts output lengths
from 1 through 2³²−1; the future complete Argon2id API will require at least
4 output bytes. The caller supplies the output buffer; input and output
must not overlap. Input is fed into
BLAKE2b in bounded chunks rather than allocating a second complete input.

```ada
with Argon2id.H0;

--  Password, Salt, Secret and Associated_Data are Argon2id byte arrays;
--  the six parameters are Interfaces.Unsigned_32; Digest is a 64-byte
--  Blake2b.Byte_Array.
Argon2id.H0.Compute
  (Password, Salt, Secret, Associated_Data,
   Parallelism, Tag_Length, Memory, Passes, Version, Kind, Digest);
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

## Build, test and prove

Requires GNAT 16 or newer. Development uses Alire 2.1.1, GNAT 16.1.0,
GPRbuild 26.0.1 and GNATprove 16.1.0.

```sh
bash scripts/check-dependency.sh
bash scripts/check-sources.sh
cd tests
alr -n build --validation --profiles=argon2id=validation
./bin/test_main
alr -n exec -- gnatprove -P ../argon2id.gpr -j0
```

Build before invoking GNATprove: Alire generates the project configuration
files during the build. GNATprove is a dependency of the nested test crate,
so library consumers do not install it. Runtime checks and contracts remain
enabled in this initial milestone. The tests compare H′ against the
[vendored official Argon2 C reference](tests/ref/README.md), including
boundary lengths, arbitrary bounds and deterministic random inputs.

Five more commands are not part of the default run:

- `./bin/test_main --long` (from `tests/`) runs only the long H0 tests (see
  below). They allocate up to 4 GiB at once (never 16 GiB) and took about
  four minutes on a recent laptop.
- `bash scripts/check-sources.sh` fails if `src/` contains `Assume`, `Import`,
  `pragma Interface`, `SPARK_Mode => Off`, `False_Positive`, `Intentional` or
  `Skip_Proof`, a warning suppression without a `Reason` or without a row in
  `TRUST.md`, or if the project stops making warnings fatal;
  `--self-test` runs it against known bypasses.
- `bash scripts/check-h0-object.sh`, after the build, checks the compiled
  objects: no trace of the proof (model, big integers, streaming
  theory) and no abort-deferral calls in `argon2id-h0.o` and
  `argon2id-h_prime.o`, no secondary stack in `argon2id-h0.o`, and nothing
  but the elaboration flag in `argon2id-h0_model.o`.
- `python3 -I scripts/h0-vectors.py --check` checks that
  `tests/src/h0_vectors.ads`, the H0 digests computed with CPython's
  `hashlib`, is what the script generates (run it without `--check` to
  regenerate).
- `bash scripts/h0-mutants.sh` runs the H0 mutation suite (see its header;
  `--selftest` checks its test classifier alone).

The proof obligations for H′ cover runtime safety and local invariants. They
do not establish end-to-end equivalence to RFC 9106 H′. The precise scope is
documented in [docs/proof-scope.md](docs/proof-scope.md).

## H0: what is proven, tested and trusted

**Proven** (GNATprove 16.1.0, from cold, step limits only, run on macOS
arm64 only so far; the two H0 units are held to 10,000 steps per check;
every check is proved by at least two of Z3, CVC5 and Alt-Ergo each on its
own, and the costliest needs 2,807 steps with its cheapest prover; no
`pragma Assume`, no `Import`, no justified check, no `SPARK_Mode => Off`):

- **The digest.** `Compute`'s postcondition: `Digest` equals
  `H0_Model.H0_Hash`, which is `Blake2b.Streaming.Theory.Logical_Hash`
  (unkeyed, 64 bytes) of the logical message `H0_Model` builds from the
  arguments, for every legal input length, empty inputs and the
  2³⁴ + 36-byte maximum included. The proof follows the real `Init`, every
  real `Update` (ten 4-byte fields, each input in 4,096-byte chunks) and the
  real `Final`, with the per-call lemmas of blake2b 0.1.1.
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

All of `H0_Model`, and every model reference in `Argon2id.H0`, is static
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
  multiple of 4p, 200 random cases, and digests at arbitrary bounds; a
  digest of the wrong length is refused.
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
  names, and each mutant of compiled code by an H0 test too.

**Trusted.** The proofs rest on blake2b 0.1.1: its streaming theory, its
`TRUST.md` (including note N-2: the whole-stream lemmas read
`Blake2b.Hashing.Max_Input`'s private completion through proof
visibility), and its specification, which its own tests validate against
BLAKE2b; and on the toolchain (GNATprove, its provers, GNAT). The crate's
own [TRUST.md](TRUST.md) lists all of it, unsigned: six GNATprove warning
suppressions, each with its reason (the ignored `Machine_Attribute` pragmas
in `argon2id-h0.ads`, `argon2id-h0.adb`, `argon2id-h_prime.ads`,
`argon2id-h_prime.adb` and `argon2id-wipe.ads`, and the finalized state that
`Compute` does not read after `Finish`), the test-only C code, and what is
not proved.

**Scope limits.** H0 only: no Argon2 password hashing, no parameter
validation. Beyond 2³¹ bytes the proved statement is equality with
`Logical_Hash`, blake2b's model of a long stream, which is tied to
`Blake2b.Spec.Hash` wherever one array holds the message and is not itself
proven against RFC 7693. The proof has been run on macOS arm64 only. The
long tests exercise the maximum length and the 2³¹ boundaries once each.
Buffers are wiped and the stack-scrubbing and register-clearing attributes
are requested as for H′ (see "Zeroization boundary" in
[docs/proof-scope.md](docs/proof-scope.md)), with the same limits; the
object check above does not inspect them.

Licensed under [BSD-3-Clause](LICENSE).
