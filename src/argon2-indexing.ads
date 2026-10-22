--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Level (Executable);

with Interfaces;

with Argon2.Blocks;   use Argon2.Blocks;
with Argon2.Geometry; use Argon2.Geometry;
with Argon2.Indexing_Model;

--  RFC 9106 section 3.4: the reference block of a position, and the
--  address blocks that Argon2i (and Argon2id, in pass 0, slices 0 and 1)
--  takes its pseudo-random values from.
--
--  Locate follows the reference implementation's index_alpha, step by
--  step: J1 and J2 are the low and high halves of W, and the products
--  J1**2 and |W| * x are computed exactly, in a 128-bit integer type, in
--  subtypes bounded so that neither can overflow. Next_Address_Block
--  writes Z_N and compresses it twice with the zero block, as the
--  reference's next_addresses does.
--
--  The postconditions that name Argon2.Indexing_Model are static ghost
--  code: GNATprove proves them, and no build compiles them. Locate's
--  states that its result is the model's Locate, which computes in
--  mathematical integers; Next_Address_Block's, that the block it makes
--  is the model's Address_Block. Lemma_Address_Stream states how the
--  address counter follows the index, for the fill's loop. Whether the
--  model is the RFC is shown by the tests, against the reference.
--
--  Locate and Next_Address_Block are Inline_Always, so that they run in
--  the scrubbed frame of the hardened subprogram that calls them: W comes
--  from secret-derived memory in Argon2d and Argon2id.
--  Next_Address_Block calls Argon2.Compression.Compress, which is
--  hardened on its own.

package Argon2.Indexing
  with SPARK_Mode
is
   package Model renames Argon2.Indexing_Model;
   use type Interfaces.Unsigned_64;

   --  The three blocks Next_Address_Block works on: the zero block, Z_N
   --  and the address block A_N.
   subtype Address_Scratch is Block_Array (0 .. 2);

   --  B is the zero block.
   function Zero_Block_Ok (B : Block) return Boolean
   is (for all K in Word_Index => B (K) = 0)
   with Inline_Always;

   --  Section 3.4.1.2: A_N = G (ZERO, G (ZERO, Z_N)) into Scratch (2),
   --  for the segment (Pass, Lane, Slice) of a data-independent position,
   --  with Z_N written into Scratch (1). Scratch (0) is the zero block,
   --  before and after; Scratch (1) and Scratch (2) may be uninitialised
   --  on entry, as a fresh workspace is, and are initialised on return.
   --  Work is scratch: Compress's working block, which the caller supplies
   --  and owns (it may hold anything on entry).
   procedure Next_Address_Block
     (Scratch : in out Address_Scratch;
      Work    : out Block;
      S       : Shape;
      V       : Variant;
      Pass    : Pass_Number;
      Lane    : Lane_Number;
      Slice   : Slice_Index;
      N       : Address_Counter)
   with Inline_Always,
        Relaxed_Initialization => Scratch,
        Global                 => null,
        Pre                    =>
          Scratch (0)'Initialized
          and then Zero_Block_Ok (Scratch (0))
          and then Pass < S.Passes and then Lane < S.Lanes
          and then Data_Independent (V, Pass, Slice)
          and then N <= (S.Segment + 127) / 128,
        Post                   =>
          (Executable =>
             Scratch (0)'Initialized and then Scratch (1)'Initialized
             and then Scratch (2)'Initialized,
           Static     =>
             Zero_Block_Ok (Scratch (0))
             and then (for all K in Word_Index =>
                         Scratch (2) (K)
                         = Model.Address_Block
                             (S, V, Pass, Lane, Slice, N) (K)));

   --  Section 3.4.1.2: the reference block of block Index of the segment
   --  (pass, slice, lane), for the pseudo-random value W. Ref_Index is the
   --  block's index within lane Ref_Lane.
   procedure Locate
     (S         : Shape;
      Pass      : Pass_Number;
      Slice     : Slice_Index;
      Lane      : Lane_Number;
      Index     : Segment_Index;
      W         : Interfaces.Unsigned_64;
      Ref_Lane  : out Lane_Number;
      Ref_Index : out Block_Index)
   with Inline_Always,
        Global => null,
        Pre    => Computed (S, Pass, Slice, Lane, Index),
        Post   =>
          (Static =>
             Ref_Lane = Model.Locate (S, Pass, Slice, Lane, Index, W).Lane
             and then Long_Long_Integer (Ref_Index)
                      = Model.Locate (S, Pass, Slice, Lane, Index, W).Index);

   --  The address stream, for the fill's loop over a segment: block Index
   --  takes word Index mod 128 of address block N = Index / 128 + 1.
   --  (b) N is at most the number of address blocks the segment needs;
   --  (a) Index takes the same address block as Index - 1, or the next one
   --  when Index is a multiple of 128; (c) indices 0 .. 127 take block 1.
   procedure Lemma_Address_Stream (S : Shape; Index : Segment_Index)
   with Ghost  => Static,
        Global => null,
        Pre    => Index < S.Segment,
        Post   =>
          Index / 128 + 1 <= (S.Segment + 127) / 128
          and then (if Index mod 128 /= 0
                    then Index / 128 = (Index - 1) / 128)
          and then (if Index > 0 and then Index mod 128 = 0
                    then Index / 128 = (Index - 1) / 128 + 1)
          and then (if Index <= 127 then Index / 128 + 1 = 1);
end Argon2.Indexing;
