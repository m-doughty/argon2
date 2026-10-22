--  Tests of Argon2.Indexing (Locate, Next_Address_Block) against the
--  vendored official reference, and of the boundaries of Argon2.Geometry.
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package Indexing_Tests is

   --  The default run:
   --  * Locate against the reference's own index_alpha (ref/core.c,
   --    through ref/compress_oracle.c), over a grid of every computed
   --    position class: the three variants, segment lengths 2 to 256 around
   --    the 128-word address-block boundary, one to five lanes, own lane
   --    first, middle and last, passes 0 to 2, all four slices, segment
   --    indices from 0 to the last, and J1 and J2 at their extremes, at
   --    the own lane and at p - 1, and pseudo-random. The reference lane is
   --    computed by the test from J2 mod p (the own lane in pass 0, slice
   --    0), and is the oracle's same_lane argument; two extreme shapes
   --    (p = 2**24 - 1 and p = 1 with the longest segment) are included;
   --  * Next_Address_Block against the reference's next_addresses (ref/ref.c,
   --    through ref/compress_oracle.c), with the input words written out by
   --    hand: Argon2i in every pass and slice and Argon2id in pass 0, slices
   --    0 and 1, over several lanes, shapes and every counter of a segment,
   --    and the extreme counter 2**23;
   --  * Locate's rejection of the first two blocks of pass 0, slice 0 (not
   --    run when contracts are off);
   --  * Shape_Of and Data_Independent at their boundaries, with hand values.
   procedure Run;

   function Passed return Natural;
   function Failed return Natural;

end Indexing_Tests;
