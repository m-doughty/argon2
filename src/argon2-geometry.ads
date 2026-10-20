--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Level (Executable);

--  RFC 9106 sections 3.2 and 3.4: the shape of Argon2's memory and the
--  positions in it.
--
--  The memory is p lanes of q = 4 s blocks: four slices of s blocks (a
--  segment) in each lane. Section 3.2 rounds the memory size m (in KiB,
--  at least 8 p) down to m' = 4 p * floor (m / (4 p)) blocks, so that
--  s = m' / (4 p) is at least 2.
--
--  A position is (pass, slice, lane, index): pass r of t, slice sl of 4,
--  lane l of p, and the index i of the block in its segment. Its block is
--  block sl * s + i of lane l.
--
--  Every count is a Long_Long_Integer subtype: t and m reach 2**32 - 1,
--  and no product of two fields here overflows 64 bits.

package Argon2.Geometry
  with SPARK_Mode, Pure
is
   --  Section 3.1: y = 0, 1, 2 (Variant'Pos).
   type Variant is (Argon2d, Argon2i, Argon2id);

   subtype Lane_Count      is Long_Long_Integer range 1 .. 2**24 - 1;
   subtype Pass_Count      is Long_Long_Integer range 1 .. 2**32 - 1;
   subtype Segment_Length  is Long_Long_Integer range 2 .. 2**30 - 1;
   subtype Memory_KiB      is Long_Long_Integer range 8 .. 2**32 - 1;
   subtype Block_Count     is Long_Long_Integer range 0 .. 2**32 - 1;

   --  The counter of an address block within a segment: it starts at 1
   --  (section 3.4.1.2), and a segment of at most 2**30 - 1 blocks needs at
   --  most 2**23 address blocks of 128 words.
   subtype Address_Counter is Long_Long_Integer range 1 .. 2**23 + 1;

   subtype Pass_Number     is Long_Long_Integer range 0 .. 2**32 - 2;
   subtype Slice_Index     is Long_Long_Integer range 0 .. 3;
   subtype Lane_Number     is Long_Long_Integer range 0 .. 2**24 - 2;
   subtype Segment_Index   is Long_Long_Integer range 0 .. 2**30 - 2;

   --  p lanes of 4 * Segment blocks each, and t passes. m' = p * 4 s is at
   --  most 2**32 - 1, so every block has an index below 2**32 - 1.
   type Shape is record
      Lanes   : Lane_Count;
      Segment : Segment_Length;       --  lane length is 4 * Segment
      Passes  : Pass_Count;
   end record
   with Dynamic_Predicate => Shape.Lanes * (4 * Shape.Segment) <= 2**32 - 1;

   --  q, the blocks of one lane.
   function Lane_Length (S : Shape) return Long_Long_Integer
   is (4 * S.Segment);

   --  m', the blocks of the whole memory.
   function Memory_Blocks (S : Shape) return Block_Count
   is (S.Lanes * (4 * S.Segment));

   --  Section 3.2: m' = 4 p * floor (m / (4 p)).
   function M_Prime (P : Lane_Count; M : Memory_KiB) return Block_Count
   is (4 * P * (M / (4 * P)))
   with Ghost => Static,
        Pre   => M >= 8 * P;

   --  The shape of p lanes, m KiB and t passes: m' blocks, segment length
   --  m' / (4 p) (at least 2, since m >= 8 p).
   function Shape_Of (P : Lane_Count; M : Memory_KiB; T : Pass_Count)
     return Shape
   with Global => null,
        Pre    => M >= 8 * P,
        Post   =>
          (Executable =>
             Shape_Of'Result.Lanes = P
             and then Shape_Of'Result.Passes = T
             and then Shape_Of'Result.Segment >= 2,
           Static     =>
             Memory_Blocks (Shape_Of'Result) = M_Prime (P, M));

   --  Section 3.4.1: the positions whose reference block is computed. In
   --  pass 0, slice 0, the first two blocks of each lane come from H0
   --  (section 3.4), not from a reference.
   function Computed
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      Index : Segment_Index) return Boolean
   is (Pass < S.Passes and then Lane < S.Lanes and then Index < S.Segment
       and then (Pass > 0 or else Slice > 0 or else Index >= 2));

   --  Section 3.4.1.2: whether the position takes its pseudo-random value
   --  from an address block (Argon2i; Argon2id in pass 0, slices 0 and 1)
   --  rather than from the previous block (section 3.4.1.1).
   function Data_Independent
     (V : Variant; Pass : Pass_Number; Slice : Slice_Index) return Boolean
   is (V = Argon2i
       or else (V = Argon2id and then Pass = 0 and then Slice < 2));
end Argon2.Geometry;
