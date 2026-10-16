--  Sanity tests of the vendored reference's block compression
--  (ref/compress_oracle.c) against published vectors.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package Compression_Tests is

   --  The default run: for every vector in Compression_Vectors (blocks of
   --  the reference's own known-answer files, scripts/compression-vectors.py),
   --  the C oracle must reproduce the published block, in both argument
   --  orders, leave its inputs unchanged, and overwrite a polluted output
   --  (or xor into the old value, for the later-pass form). This checks the
   --  oracle's wiring and the vectors on every platform. It then runs
   --  Argon2.Compression (both forms) on the vectors and on further inputs
   --  against the oracle: every word position alone, extreme words, equal
   --  inputs and pseudo-random pairs, at varied layouts and lower bounds.
   procedure Run;

   function Passed return Natural;
   function Failed return Natural;

end Compression_Tests;
