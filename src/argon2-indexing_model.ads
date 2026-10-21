--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Numerics.Big_Numbers.Big_Integers;
with Interfaces;

with Blake2b;
with Blake2b.Hashing;

with Argon2.Blocks;
with Argon2.Compression_Model;
with Argon2.Geometry; use Argon2.Geometry;

--  RFC 9106 section 3.4: which earlier block a position is compressed
--  with, and the address blocks that Argon2i (and Argon2id, in pass 0,
--  slices 0 and 1) takes its pseudo-random values from.
--
--  For block i of the segment in pass r, slice sl and lane l, with s the
--  segment length, q = 4 s the lane length and p the lanes:
--
--  * W, a 64-bit value: word 0 of the previous block (section 3.4.1.1),
--    or word i mod 128 of the address block A_n, n = i / 128 + 1, where
--    A_n = G (ZERO, G (ZERO, Z_n)) and Z_n's words are
--    r, l, sl, m', t, y, n, then zeros (section 3.4.1.2). Which W applies
--    is Geometry.Data_Independent; reading W is the fill's.
--  * J1 is the low 32 bits of W and J2 the high 32 (section 3.4.1.1).
--  * The reference lane is l in pass 0, slice 0, and J2 mod p otherwise
--    (section 3.4.2).
--  * |W|, the area, is the number of blocks the reference may be: in pass
--    0 every block of the lane's finished segments, in later passes those
--    of the last three segments, and in the own lane also the blocks
--    already made in this segment, less the previous one. When i = 0 and
--    the lane is another, the area's last block is left out.
--  * x = J1**2 / 2**32, y = |W| * x / 2**32, zz = |W| - 1 - y, and the
--    reference index is zz counted from the area's first block
--    (Start_Position), cyclically in the lane.
--
--  The RFC leaves three points to the reference implementation, which the
--  model follows: the number of address blocks is what the segment needs
--  (ceil (s / 128)), not q / (128 * 4); the area is listed from its first
--  block, cyclically; and in pass 0 the area is every finished segment,
--  not "the last 3".
--
--  The products J1**2 and |W| * x are written in mathematical integers
--  (Big_Integer), so an implementation that wraps fails its proof against
--  this model rather than agreeing with it.
--
--  In_Window and the lemmas after it state what the fill relies on: the
--  reference lies in the memory, and only among blocks already written in
--  this pass or the last, never the block being made or the one before.
--
--  Static ghost code: GNATprove proves it, and no build ever compiles it.
--  Every declaration is marked static ghost, and deliberately not the
--  package itself, so that its object file still holds one symbol, the
--  package's elaboration flag (a library member with no symbols makes
--  macOS ranlib warn).
--
--  The conversions to mathematical integers are blake2b's (the ghost
--  package Blake2b.Hashing.Big, as Argon2.H0 uses), so this crate holds no
--  instance of the run-time library's conversion generics, whose bodies
--  GNATprove does not analyse. Big_LLI and the body of
--  Relative_Position are the only places that name blake2b's conversions.

package Argon2.Indexing_Model
  with SPARK_Mode
is
   use Ada.Numerics.Big_Numbers.Big_Integers;
   use type Interfaces.Unsigned_64;

   subtype U32 is Interfaces.Unsigned_32 with Ghost => Static;
   subtype U64 is Interfaces.Unsigned_64 with Ghost => Static;

   --  X as a mathematical integer.
   function Big_LLI (X : Long_Long_Integer) return Big_Integer
   is (Blake2b.Hashing.Big.Length (Blake2b.I64 (X)))
   with Ghost => Static;

   --  Section 3.1: the variant's type y.
   function Y (V : Variant) return U64
   is (U64 (Variant'Pos (V)))
   with Ghost => Static;

   ----------------------------------------------------------------------
   --  Address blocks (section 3.4.1.2)
   ----------------------------------------------------------------------

   --  Word K of Z_N: r, l, sl, m', t, y, N, then zeros.
   function Address_Input_Word
     (S     : Shape;
      V     : Variant;
      Pass  : Pass_Number;
      Lane  : Lane_Number;
      Slice : Slice_Index;
      N     : Address_Counter;
      K     : Blocks.Word_Index) return U64
   is (case K is
         when 0      => U64 (Pass),
         when 1      => U64 (Lane),
         when 2      => U64 (Slice),
         when 3      => U64 (Memory_Blocks (S)),
         when 4      => U64 (S.Passes),
         when 5      => Y (V),
         when 6      => U64 (N),
         when others => 0)
   with Ghost => Static;

   --  Z_N as a block.
   function Address_Input
     (S     : Shape;
      V     : Variant;
      Pass  : Pass_Number;
      Lane  : Lane_Number;
      Slice : Slice_Index;
      N     : Address_Counter) return Blocks.Block
   is ([for K in Blocks.Word_Index =>
          Address_Input_Word (S, V, Pass, Lane, Slice, N, K)])
   with Ghost => Static;

   --  ZERO (1024), the block of zero words.
   function Zero_Block return Blocks.Block
   is ([others => 0])
   with Ghost => Static;

   --  A_N = G (ZERO, G (ZERO, Z_N)), the zero block first each time.
   function Address_Block
     (S     : Shape;
      V     : Variant;
      Pass  : Pass_Number;
      Lane  : Lane_Number;
      Slice : Slice_Index;
      N     : Address_Counter) return Blocks.Block
   is (Compression_Model.G
         (Zero_Block,
          Compression_Model.G
            (Zero_Block, Address_Input (S, V, Pass, Lane, Slice, N))))
   with Ghost => Static;

   --  W for block Index of the segment: word Index mod 128 of
   --  A_(Index / 128 + 1).
   function Address_Value
     (S     : Shape;
      V     : Variant;
      Pass  : Pass_Number;
      Lane  : Lane_Number;
      Slice : Slice_Index;
      Index : Segment_Index) return U64
   is (Address_Block (S, V, Pass, Lane, Slice, Index / 128 + 1)
         (Blocks.Word_Index (Index mod 128)))
   with Ghost => Static;

   ----------------------------------------------------------------------
   --  The reference block (sections 3.4.1.1 and 3.4.2)
   ----------------------------------------------------------------------

   --  The low and the high 32 bits of W.
   function J1 (W : U64) return U32
   is (U32 (W mod 2**32))
   with Ghost => Static;

   function J2 (W : U64) return U32
   is (U32 (W / 2**32))
   with Ghost => Static;

   --  The own lane in pass 0, slice 0; J2 mod p otherwise.
   function Reference_Lane
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      W     : U64) return Lane_Number
   is (if Pass = 0 and then Slice = 0 then Lane
       else Long_Long_Integer (J2 (W)) mod S.Lanes)
   with Ghost => Static;

   --  |W|. Same_Lane: the reference lane is the block's own.
   function Area
     (S         : Shape;
      Pass      : Pass_Number;
      Slice     : Slice_Index;
      Index     : Segment_Index;
      Same_Lane : Boolean) return Long_Long_Integer
   is (if Pass = 0 then
         (if Slice = 0 then Index - 1
          elsif Same_Lane then Slice * S.Segment + Index - 1
          else Slice * S.Segment + (if Index = 0 then -1 else 0))
       else
         (if Same_Lane then 3 * S.Segment + Index - 1
          else 3 * S.Segment + (if Index = 0 then -1 else 0)))
   with Ghost => Static;

   --  2**32 as a mathematical integer.
   function Two32 return Big_Integer
   is (Big_LLI (2**32))
   with Ghost => Static;

   --  zz = |W| - 1 - y, where x = J1**2 / 2**32 and y = |W| * x / 2**32,
   --  in mathematical integers.
   function Rel_Big (Area : Long_Long_Integer; J : U32) return Big_Integer
   is (declare
         A  : constant Big_Integer := Big_LLI (Area);
         JB : constant Big_Integer := Big_LLI (Long_Long_Integer (J));
         X  : constant Big_Integer := (JB * JB) / Two32;
         YY : constant Big_Integer := (A * X) / Two32;
       begin
         A - Big_LLI (1) - YY)
   with Ghost => Static,
        Pre   => Area >= 1;

   --  zz as a machine integer: x <= 2**32 - 2, so y <= |W| - 1 and zz is
   --  in 0 .. |W| - 1.
   function Relative_Position
     (Area : Long_Long_Integer; J : U32) return Long_Long_Integer
   with Ghost => Static,
        Pre   => Area >= 1,
        Post  =>
          Relative_Position'Result in 0 .. Area - 1
          and then Big_LLI (Relative_Position'Result)
                   = Rel_Big (Area, J);

   --  The lane position the area starts from: the next segment in passes
   --  after the first (the one after slice 3 is slice 0), 0 in pass 0.
   function Start_Position
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index) return Long_Long_Integer
   is (if Pass = 0 or else Slice = 3 then 0 else (Slice + 1) * S.Segment)
   with Ghost => Static;

   --  The reference's index in its lane: zz counted from the start,
   --  cyclically.
   function Reference_Index
     (S         : Shape;
      Pass      : Pass_Number;
      Slice     : Slice_Index;
      Index     : Segment_Index;
      Same_Lane : Boolean;
      J         : U32) return Long_Long_Integer
   is ((Start_Position (S, Pass, Slice)
        + Relative_Position (Area (S, Pass, Slice, Index, Same_Lane), J))
       mod Lane_Length (S))
   with Ghost => Static,
        Pre   => Area (S, Pass, Slice, Index, Same_Lane) >= 1;

   type Reference is record
      Lane  : Lane_Number;
      Index : Long_Long_Integer;       --  within the lane
   end record
   with Ghost => Static;

   --  The reference block of the position, for the value W.
   function Locate
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      Index : Segment_Index;
      W     : U64) return Reference
   is (declare
         Ref_Lane : constant Lane_Number :=
           Reference_Lane (S, Pass, Slice, Lane, W);
       begin
         (Lane  => Ref_Lane,
          Index =>
            Reference_Index
              (S, Pass, Slice, Index, Ref_Lane = Lane, J1 (W))))
   with Ghost => Static,
        Pre   => Computed (S, Pass, Slice, Lane, Index);

   ----------------------------------------------------------------------
   --  What the fill relies on
   ----------------------------------------------------------------------

   --  The blocks R may be, for block Index of the segment, by pass and
   --  lane, with L = Slice * s + Index the block's own place in its lane:
   --
   --  * pass 0, slice 0: the own lane only;
   --  * pass 0, own lane: 0 .. L - 2;
   --  * pass 0, other lane: 0 .. Slice * s - 1, less the last when
   --    Index = 0;
   --  * later passes, own lane: any but the rest of this segment
   --    (L .. (Slice + 1) * s - 1) and the previous block, L - 1 mod q;
   --  * later passes, other lane: any but this slice, and also
   --    Slice * s - 1 mod q when Index = 0.
   function In_Window
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      Index : Segment_Index;
      R     : Reference) return Boolean
   is (declare
         Q   : constant Long_Long_Integer := Lane_Length (S);
         L   : constant Long_Long_Integer := Slice * S.Segment + Index;
         Own : constant Boolean := R.Lane = Lane;
       begin
         R.Lane < S.Lanes and then R.Index in 0 .. Q - 1
         and then (if Pass = 0 and then Slice = 0 then Own)
         and then
           (if Pass = 0 then
              (if Own then R.Index <= L - 2
               else R.Index
                    <= Slice * S.Segment - (if Index = 0 then 2 else 1))
            elsif Own then
              R.Index /= (L - 1) mod Q
              and then R.Index not in L .. (Slice + 1) * S.Segment - 1
            else
              R.Index not in Slice * S.Segment .. (Slice + 1) * S.Segment - 1
              and then
                (if Index = 0 then R.Index /= (Slice * S.Segment - 1) mod Q)))
   with Ghost => Static;

   --  The area is never empty (in pass 0, slice 0, the reference lane is
   --  the own lane and Index >= 2).
   procedure Lemma_Area
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      Index : Segment_Index;
      W     : U64)
   with Ghost  => Static,
        Global => null,
        Pre    => Computed (S, Pass, Slice, Lane, Index),
        Post   =>
          Area (S, Pass, Slice, Index,
                Reference_Lane (S, Pass, Slice, Lane, W) = Lane) >= 1
          and then (if Pass = 0 and then Slice = 0
                    then Reference_Lane (S, Pass, Slice, Lane, W) = Lane);

   --  The reference lane is a lane of the memory.
   procedure Lemma_Lane
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      W     : U64)
   with Ghost  => Static,
        Global => null,
        Pre    => Lane < S.Lanes,
        Post   => Reference_Lane (S, Pass, Slice, Lane, W) < S.Lanes;

   --  The reference is a block of the memory: lane 0 .. p - 1, index
   --  0 .. q - 1.
   procedure Lemma_Ranges
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      Index : Segment_Index;
      W     : U64)
   with Ghost  => Static,
        Global => null,
        Pre    => Computed (S, Pass, Slice, Lane, Index),
        Post   =>
          Locate (S, Pass, Slice, Lane, Index, W).Lane in 0 .. S.Lanes - 1
          and then Locate (S, Pass, Slice, Lane, Index, W).Index
                   in 0 .. Lane_Length (S) - 1;

   --  The reference is in the window.
   procedure Lemma_Window
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      Index : Segment_Index;
      W     : U64)
   with Ghost  => Static,
        Global => null,
        Pre    => Computed (S, Pass, Slice, Lane, Index),
        Post   =>
          In_Window
            (S, Pass, Slice, Lane, Index,
             Locate (S, Pass, Slice, Lane, Index, W));
end Argon2.Indexing_Model;
