# H-prime assurance scope

This milestone implements only RFC 9106 section 3.3, the variable-length
hash H′. It does not implement Argon2id's memory filling, block compression,
lane scheduling, or public password-hashing interface.

## Supported domain

`Argon2id.Byte_Array` has a 64-bit signed index base and index subtype
`0 .. 2**32 - 2`. Consequently an array can contain up to `2**32 - 1`
bytes, including an input of that length. Arrays can have arbitrary lower
bounds, and input may be empty. Output must contain at least one byte;
this is H′'s domain, distinct from the complete Argon2 algorithm's four-byte
minimum tag length. Input and output must not overlap. SPARK's
anti-aliasing rules enforce this for SPARK callers; ordinary Ada callers
must respect the same requirement.

The implementation converts input in chunks of at most 4,096 bytes into
the BLAKE2b library's array type. It never converts or concatenates the
whole input. Fixed local byte buffers comprise a four-byte prefix, a
4,096-byte chunk, and two 64-byte chaining values, in addition to a
BLAKE2b state and compiler-managed call storage. This bound excludes the
caller's input and output buffers. Absorption-count assertions use Static
ghost code: they are proved, but excluded from every compiled profile,
including validation. They do not require runtime ghost symbols from the
BLAKE2b dependency. Validation builds execute the remaining bounded
contracts and wipe assertions.

## Proof obligations

On 8 October 2026, GNATprove 16.1.0 proved all 143 checks for the H′ and
wipe bodies, including flow analysis, using `-u argon2id-h_prime.adb
argon2id-wipe.adb -j2` and the configured `--mode=all --timeout=0
--steps=200000` options with the Z3, CVC5, and Alt-Ergo provers. This count
excludes BLAKE2b dependency results retained in the summary. There are no
unproved or justified checks and no `pragma Assume` statements. The source
contracts and invariants establish:

- Absence of run-time errors and termination over the supported domain.
- Exact little-endian encoding of the 32-bit output length.
- Byte-for-byte correspondence between each copied chunk and its input
  interval, including arrays whose bounds approach the maximum index.
- A streaming state that remains absorbing with the requested BLAKE2b
  output length, and has absorbed exactly `4 + Offset` bytes at each
  chunk boundary. It absorbs exactly `4 + Input'Length` before finalizing.
  This quantity is at most `2**32 + 3`, safely below BLAKE2b's counter limit.
- Safe consecutive 32-byte output intervals and a final interval of
  33–64 bytes for long outputs. The number of 32-byte intervals is exactly
  `ceil(Output_Length / 32) - 2`; shorter outputs use one digest of their
  requested length. All output elements are initialized.
- Zero values in scratch buffers after the explicit wipe procedures.

## Functional equivalence boundary

These obligations do **not** constitute an end-to-end proof that H′
equals an independently specified RFC 9106 function. In particular,
the input-copy contract and exact absorption count do not alone prove
the complete sequence of bytes absorbed by BLAKE2b. The BLAKE2b library
provides proved per-step model contracts; its one-array theorem uses its
own narrower array type, but since blake2b 0.1.1 its streaming theory
(`Blake2b.Streaming`) can name a message of up to 2³⁴ + 36 bytes, this
package's full 32-bit input domain included, and H0 (`Argon2id.H0`) uses
it for an end-to-end proof. H′ has no such proof yet: for H′ the gap
remains. No assumptions or disabled proof checks bridge
it. Tests compare H′ against the official Argon2 C reference at practical
sizes; those comparisons provide independent algorithm checks but do not
replace a functional proof or test multi-gigabyte buffers.

## Zeroization boundary

On normal return, the BLAKE2b finalization API wipes its state, and the
private `Argon2id.Wipe.Bytes` procedure explicitly clears every local byte
buffer. `No_Inline`, GCC's `noipa` attribute, and `Inspection_Point` prevent
the wipe from becoming a dead store. Procedures handling input and
intermediate digests additionally request GCC's internal stack scrubbing
and clearing of all call-used registers. Their presence and generated
instructions require separate compiled-code inspection: a SPARK value
proof cannot establish the absence of register copies or compiler spills.

The guarantee is for normal completion with satisfied preconditions.
This package does not guarantee cleanup after asynchronous interruption,
process termination, compiler defects, hardware faults, or exceptional
exits. It does not erase the caller's input or returned output, and does
not claim a complete constant-time or side-channel analysis.
