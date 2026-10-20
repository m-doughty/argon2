# Assurance scope

This milestone implements three parts of RFC 9106: the variable-length hash
H′ (§3.3), the pre-hashing digest H0 (§3.2) and the block compression
function G (§§3.5, 3.6). It does not implement Argon2's memory filling, lane
scheduling, or public password-hashing interface. The README states what is
proven, tested and trusted for H0, H′ and compression; this note gives the
scope of the H′ proof in more detail.

## H′: supported domain

`Argon2.Byte_Array` has a 64-bit signed index base and index subtype
`0 .. 2**32 - 2`, so an output can be up to `2**32 - 1` bytes. The input is a
`Blake2b.Byte_Array` of at most `Max_Input_Bytes` = 1,024 bytes (all that
Argon2 hashes: a 72-byte seed or a 1,024-byte block); arrays can have
arbitrary lower bounds and the input may be empty. Output must contain at
least one byte; this is H′'s domain, distinct from the complete Argon2
algorithm's four-byte minimum tag length. Input and output must not overlap;
SPARK's anti-aliasing rules enforce this for SPARK callers, and ordinary Ada
callers must respect the same requirement. The preconditions are
obligations on the caller, proved for SPARK callers; the `release` profile
checks none of them, so another caller that breaks one gets no diagnostic
and undefined behaviour (see the README).

The input is absorbed into BLAKE2b in one piece and is not copied. The BLAKE2b
state and the two 64-byte chaining values are scratch the caller supplies; the
only local byte buffer is a four-byte prefix, besides compiler-managed call
storage. This bound excludes the caller's input, output and scratch buffers.

## H′: proof obligations

GNATprove 16.1.0 proves the H′ and wipe bodies with the crate's configured
options (whole-crate proof on 17 October 2026: 3398 checks, none unproved or
justified). There are no `pragma Assume` statements. The source contracts and
invariants establish:

- Absence of run-time errors and termination over the supported domain.
- Exact little-endian encoding of the 32-bit output length.
- Safe consecutive 32-byte output intervals and a final interval of 33–64
  bytes for long outputs. The number of 32-byte intervals is exactly
  `ceil(Output_Length / 32) - 2`; shorter outputs use one digest of their
  requested length. All output elements are initialized.
- Zero values in scratch buffers after the explicit wipe procedures.
- Equality of every output byte with the model (below).

## H′: functional equivalence boundary

`Hash`'s postcondition states that byte P of the output is byte P of
`Argon2.H_Prime_Model.Out_Byte`, for every P: this crate's static ghost
transcription of RFC 9106 §3.3 (the T-byte BLAKE2b of LE32 (T) ‖ A for
T ≤ 64; otherwise the 32-byte pieces of the chain V₁ … Vᵣ and the last link,
a BLAKE2b with a digest length of T − 32r). The proof goes through blake2b's
contracts for `Init`, `Update` and `Final`. It is a proof that the code equals
the model, **not** that the model is the RFC's function: a mistake in the
model would still prove. That the model is the RFC's function is tested, against
the official Argon2 C reference's `blake2b_long` and against 55 outputs
computed with CPython, for inputs of 72 and 1,024 bytes and output lengths up
to 2²⁴ + 8. Output lengths above that are covered by the proof only. The model
and the postcondition are static ghost code: proved, never compiled or run.

## Compression

`Argon2.Compression` is proved equal to `Argon2.Compression_Model`, this
crate's static ghost transcription of RFC 9106 §§3.5 and 3.6. That the model
is the RFC's function is tested against the official reference's compression
function, not proved. See the README and `TRUST.md` S-4.

## Indexing

`Argon2.Indexing_Model` is this crate's static ghost transcription of RFC 9106
§3.4.1 and §3.4.2 (the pseudo-random value, the address blocks, the reference
lane and index), with `Argon2.Geometry` (§3.2's rounding to m′ blocks, the
positions that are computed, and which take their value from an address
block). Proved: the reference is a block of the memory and lies in the
window of blocks already written; `Shape_Of` meets its postcondition. Not
proved, and so far not tested in this repository: that the model is the
RFC's indexing. No indexing code exists yet. See the README and `TRUST.md`
S-5.

## Zeroization boundary

On normal return, the BLAKE2b finalization API wipes its state, and the
private `Argon2.Wipe.Bytes` procedure explicitly clears every local byte
buffer. `No_Inline`, GCC's `noipa` attribute, and `Inspection_Point` prevent
the wipe from becoming a dead store. Procedures handling input and
intermediate digests additionally request GCC's internal stack scrubbing
and clearing of all call-used registers. Their presence and generated
instructions require separate compiled-code inspection: a SPARK value
proof cannot establish the absence of register copies or compiler spills.

Compression works in one block of scratch (`Work`) that its caller supplies;
nothing in `Compress` wipes it (the caller does). `Compress` and
`Compress_Xor` request the same stack scrubbing and register clearing; for
them, `scripts/check-h0-object.sh` checks the compiled code for the scrubbing
clone, for at least the registers a probe shows `zero_call_used_regs`
zeroes at each return of the wrapper (within the limits in `TRUST.md` H-1),
for no helper left out of line, and for no call of `memcpy` or `memmove`
(the body copies no block through libc). The scrub covers their own body's
frame, not the frames of helpers the body calls that are not inlined. H′ and
H₀ likewise take their BLAKE2b state, and H′ its two chain values, as
scratch parameters, so a future cleanup guard can reach them. BLAKE2b's own
compression locals stay outside any such guard. From blake2b 0.1.2 its
compression is inlined into its own scrubbed entry points (`Init`, `Update`
and `Final`), so after a normal return its frame is inside blake2b's
scrubbed body. `scripts/check-exception-stack.sh` fails on any canary a
hardened build leaves after a normal return of H′ or compression
(`TRUST.md` H-2).

The guarantee is for normal completion with satisfied preconditions.
This package does not guarantee cleanup after asynchronous interruption,
process termination, compiler defects, hardware faults, or exceptional
exits. It does not erase the caller's input or returned output, and does
not claim a complete constant-time or side-channel analysis.
