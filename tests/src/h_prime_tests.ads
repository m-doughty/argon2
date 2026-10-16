--  Tests of Argon2.H_Prime beyond the default comparisons of Test_Main.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package H_Prime_Tests is

   --  The default run:
   --  * for every vector in H_Prime_Vectors (scripts/h-prime-vectors.py,
   --    RFC 9106 section 3.3 written out with CPython's hashlib.blake2b),
   --    the output of Argon2.H_Prime.Hash must hash to the recorded
   --    digest: the two input lengths Argon2 uses (72 and 1,024 bytes) at
   --    output lengths from 1 byte to 2**20 + 8, covering the single-hash
   --    case, the chain, every tail length class and the 64/65 boundary;
   --  * the same inputs and output lengths against the vendored official
   --    blake2b_long, byte for byte.
   procedure Run;

   function Passed return Natural;
   function Failed return Natural;

end H_Prime_Tests;
