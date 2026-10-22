--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Level (Executable);

--  Locate takes J1 and J2 from W as the model does, then computes in
--  signed integers: the counts in Long_Long_Integer, and the two products
--  J1**2 and |W| * x in Wide, a 128-bit type, in subtypes bounded so that
--  neither can overflow. zz is computed by a helper, so that its
--  arithmetic is proved in a small context; it is Inline_Always, as
--  Locate is.
--
--  Next_Address_Block makes A_N with two calls of Compress, from one call
--  site in a loop, so that Work's value from each call reaches the
--  caller. Compress's postcondition states each result as G of its
--  inputs, by array equality, and G is opaque; Same_Block (logical
--  equality) carries the inputs' identity with the model's blocks into G,
--  as in Argon2.Compression. Scratch has relaxed initialisation, as
--  Compress's M has, so that Compress's contract applies to Scratch as it
--  stands rather than to a converted copy.

with Ada.Numerics.Big_Numbers.Big_Integers;

with Argon2.Compression;
with Argon2.Compression_Model;

package body Argon2.Indexing
  with SPARK_Mode
is
   use Ada.Numerics.Big_Numbers.Big_Integers;
   subtype U32 is Interfaces.Unsigned_32;
   use type U32;

   --  The products, in 128 bits: J1 and |W| are below 2**32, x is at most
   --  2**32 - 2.
   subtype Wide is Long_Long_Long_Integer;
   subtype Half is Wide range 0 .. 2**32 - 1;
   subtype X_Range is Wide range 0 .. 2**32 - 2;
   subtype Product is Wide range 0 .. (2**32 - 1) * (2**32 - 1);

   ----------------------------------------------------------------------
   --  Arithmetic
   ----------------------------------------------------------------------

   --  x = J1**2 / 2**32 <= 2**32 - 2, for J1 <= 2**32 - 1.
   procedure Lemma_X_Below (J : Half)
   with Ghost  => Static,
        Global => null,
        Post   => J * J / 2**32 <= 2**32 - 2;

   procedure Lemma_X_Below (J : Half)
   is
      Max : constant Wide := 2**32 - 1;
   begin
      pragma Assert (J * J <= J * Max);
      pragma Assert (J * Max <= Max * Max);
      pragma Assert (J * J < Max * 2**32);
      pragma Assert (J * J / 2**32 < Max);
   end Lemma_X_Below;

   --  y = |W| x / 2**32 <= |W| - 1, for |W| >= 1 and x <= 2**32 - 2.
   procedure Lemma_Y_Below (A : Half; X : X_Range)
   with Ghost  => Static,
        Global => null,
        Pre    => A >= 1,
        Post   => A * X / 2**32 <= A - 1;

   procedure Lemma_Y_Below (A : Half; X : X_Range)
   is
   begin
      pragma Assert (A * X <= A * (2**32 - 2));
      pragma Assert (A * (2**32 - 2) < A * 2**32);
      pragma Assert (A * X / 2**32 < A);
   end Lemma_Y_Below;

   ----------------------------------------------------------------------
   --  zz
   ----------------------------------------------------------------------

   --  zz = |W| - 1 - y, where x = J1**2 / 2**32 and y = |W| x / 2**32,
   --  in 0 .. |W| - 1.
   function Relative (Area : Long_Long_Integer; J : U32)
     return Long_Long_Integer
   with Global => null,
        Pre    => Area in 1 .. 2**32 - 1,
        Post   =>
          (Static =>
             Relative'Result in 0 .. Area - 1
             and then Model.Big_LLI (Relative'Result)
                      = Model.Rel_Big (Area, J));

   function Relative (Area : Long_Long_Integer; J : U32)
     return Long_Long_Integer
   is
      A  : constant Half := Wide (Area);
      J1 : constant Half := Wide (J);
      X  : X_Range;
      Y  : Half;
   begin
      Lemma_X_Below (J1);
      X := Product'(J1 * J1) / 2**32;
      Lemma_Y_Below (A, X);
      Y := Product'(A * X) / 2**32;

      --  The model's terms, one by one.
      declare
         AB : constant Big_Integer := Model.Big_LLI (Area)
         with Ghost => Static;
         JB : constant Big_Integer := Model.Big_LLI (Long_Long_Integer (J))
         with Ghost => Static;
         XB : constant Big_Integer := (JB * JB) / Model.Two32
         with Ghost => Static;
         YB : constant Big_Integer := (AB * XB) / Model.Two32
         with Ghost => Static;
      begin
         pragma Assert
           (Static => Model.Big_LLI (Long_Long_Integer (X)) = XB);
         pragma Assert
           (Static => Model.Big_LLI (Long_Long_Integer (Y)) = YB);
         pragma Assert
           (Static =>
              Model.Rel_Big (Area, J) = AB - Model.Big_LLI (1) - YB);
      end;
      return Long_Long_Integer (A - 1 - Y);
   end Relative;

   pragma Inline_Always (Relative);

   ----------------------------------------------------------------------
   --  Indexing
   ----------------------------------------------------------------------

   procedure Locate
     (S         : Shape;
      Pass      : Pass_Number;
      Slice     : Slice_Index;
      Lane      : Lane_Number;
      Index     : Segment_Index;
      W         : Interfaces.Unsigned_64;
      Ref_Lane  : out Lane_Number;
      Ref_Index : out Block_Index)
   is
      J1    : constant U32 := U32 (W mod 2**32);
      J2    : constant U32 := U32 (W / 2**32);
      Q     : constant Long_Long_Integer := Lane_Length (S);
      Area  : Long_Long_Integer;
      ZZ    : Long_Long_Integer;
      Start : Long_Long_Integer;
   begin
      --  Section 3.4.2: the reference lane, J2 mod p, except in pass 0,
      --  slice 0.
      if Pass = 0 and then Slice = 0 then
         Ref_Lane := Lane;
      else
         pragma Assert (Static => J2 = Model.J2 (W));
         Ref_Lane := Long_Long_Integer (J2) mod S.Lanes;
         pragma Assert
           (Static => Ref_Lane = Long_Long_Integer (Model.J2 (W)) mod S.Lanes);
         pragma Assert
           (Static =>
              Model.Reference_Lane (S, Pass, Slice, Lane, W)
              = Long_Long_Integer (Model.J2 (W)) mod S.Lanes);
      end if;
      pragma Assert
        (Static => Ref_Lane = Model.Reference_Lane (S, Pass, Slice, Lane, W));
      Model.Lemma_Area (S, Pass, Slice, Lane, Index, W);

      --  The area |W|, as the reference counts it.
      if Pass = 0 then
         if Slice = 0 then
            Area := Index - 1;
         elsif Ref_Lane = Lane then
            Area := Slice * S.Segment + Index - 1;
         else
            Area := Slice * S.Segment + (if Index = 0 then -1 else 0);
         end if;
      elsif Ref_Lane = Lane then
         Area := Q - S.Segment + Index - 1;
      else
         Area := Q - S.Segment + (if Index = 0 then -1 else 0);
      end if;
      pragma Assert
        (Static => Area = Model.Area (S, Pass, Slice, Index, Ref_Lane = Lane));

      --  zz, then the area's first block: the next segment, in passes
      --  after the first (the one after slice 3 is slice 0).
      ZZ := Relative (Area, J1);
      pragma Assert
        (Static => ZZ = Model.Relative_Position (Area, Model.J1 (W)));
      if Pass = 0 or else Slice = 3 then
         Start := 0;
      else
         Start := (Slice + 1) * S.Segment;
      end if;

      pragma Assert
        (Static => Start = Model.Start_Position (S, Pass, Slice));

      --  The reference index: zz counted from the start, cyclically.
      Ref_Index := (Start + ZZ) mod Q;
      pragma Assert
        (Static =>
           Long_Long_Integer (Ref_Index)
           = Model.Reference_Index
               (S, Pass, Slice, Index, Ref_Lane = Lane, Model.J1 (W)));
   end Locate;

   ----------------------------------------------------------------------
   --  Address blocks
   ----------------------------------------------------------------------

   --  Proof machinery (never executed: Static ghost code is not compiled
   --  into any build). The provers will not substitute element-wise equal
   --  arrays into the opaque G; Same_Block is interpreted as logical
   --  equality, which they substitute freely, and the lemma converts one
   --  into the other (array extensionality).
   function Same_Block (L, R : Block) return Boolean is (L = R)
   with Ghost    => Static,
        Global   => null,
        Annotate => (GNATprove, Logical_Equal);

   procedure Lemma_Same_Block (L, R : Block)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same_Block (L, R);

   procedure Lemma_Same_Block (L, R : Block) is null;

   --  The model's A_N, G (ZERO, G (ZERO, Z_N)), as logical equality.
   procedure Lemma_Address_Block
     (S     : Shape;
      V     : Variant;
      Pass  : Pass_Number;
      Lane  : Lane_Number;
      Slice : Slice_Index;
      N     : Address_Counter)
   with Ghost  => Static,
        Global => null,
        Post   =>
          Same_Block
            (Model.Address_Block (S, V, Pass, Lane, Slice, N),
             Compression_Model.G
               (Model.Zero_Block,
                Compression_Model.G
                  (Model.Zero_Block,
                   Model.Address_Input (S, V, Pass, Lane, Slice, N))));

   procedure Lemma_Address_Block
     (S     : Shape;
      V     : Variant;
      Pass  : Pass_Number;
      Lane  : Lane_Number;
      Slice : Slice_Index;
      N     : Address_Counter)
   is null;

   --  Word K of Z_N: r, l, sl, m', t, y, N, then zeros. The model's y is
   --  ghost, so word 5 is computed here.
   function Input_Word
     (S     : Shape;
      V     : Variant;
      Pass  : Pass_Number;
      Lane  : Lane_Number;
      Slice : Slice_Index;
      N     : Address_Counter;
      K     : Word_Index) return Interfaces.Unsigned_64
   is (case K is
         when 0      => Interfaces.Unsigned_64 (Pass),
         when 1      => Interfaces.Unsigned_64 (Lane),
         when 2      => Interfaces.Unsigned_64 (Slice),
         when 3      => Interfaces.Unsigned_64 (Memory_Blocks (S)),
         when 4      => Interfaces.Unsigned_64 (S.Passes),
         when 5      => Interfaces.Unsigned_64 (Variant'Pos (V)),
         when 6      => Interfaces.Unsigned_64 (N),
         when others => 0)
   with Inline_Always,
        Post =>
          (Static =>
             Input_Word'Result
             = Model.Address_Input_Word (S, V, Pass, Lane, Slice, N, K));

   --  Z_N into Scratch (1), one word at a time: a block assignment would
   --  copy a temporary through memcpy, out of the caller's scrubbed frame.
   --  Scratch (0), the zero block, is unchanged.
   procedure Write_Input
     (Scratch : in out Address_Scratch;
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
          Scratch (0)'Initialized and then Zero_Block_Ok (Scratch (0)),
        Post                   =>
          (Executable =>
             Scratch (0)'Initialized and then Scratch (1)'Initialized,
           Static     =>
             Zero_Block_Ok (Scratch (0))
             and then Same_Block (Scratch (0), Model.Zero_Block)
             and then Same_Block
                        (Scratch (1),
                         Model.Address_Input (S, V, Pass, Lane, Slice, N)));

   procedure Write_Input
     (Scratch : in out Address_Scratch;
      S       : Shape;
      V       : Variant;
      Pass    : Pass_Number;
      Lane    : Lane_Number;
      Slice   : Slice_Index;
      N       : Address_Counter)
   is
   begin
      for K in Word_Index loop
         Scratch (1) (K) := Input_Word (S, V, Pass, Lane, Slice, N, K);
         pragma Loop_Invariant (Scratch (0)'Initialized);
         pragma Loop_Invariant
           (for all I in 0 .. K => Scratch (1) (I)'Initialized);
         pragma Loop_Invariant (Static => Zero_Block_Ok (Scratch (0)));
         pragma Loop_Invariant
           (Static =>
              (for all I in 0 .. K =>
                 Scratch (1) (I)
                 = Model.Address_Input_Word (S, V, Pass, Lane, Slice, N, I)));
      end loop;
      pragma Assert
        (Static =>
           Scratch (1) = Model.Address_Input (S, V, Pass, Lane, Slice, N));
      Lemma_Same_Block (Scratch (0), Model.Zero_Block);
      Lemma_Same_Block
        (Scratch (1), Model.Address_Input (S, V, Pass, Lane, Slice, N));
   end Write_Input;

   procedure Next_Address_Block
     (Scratch : in out Address_Scratch;
      Work    : out Block;
      S       : Shape;
      V       : Variant;
      Pass    : Pass_Number;
      Lane    : Lane_Number;
      Slice   : Slice_Index;
      N       : Address_Counter)
   is
      --  G is opaque here: the proof composes Compress's postconditions and
      --  never needs G's body, which would only slow the provers.
      pragma Annotate
        (GNATprove, Hide_Info, "Expression_Function_Body",
         Compression_Model.G);

      --  G (ZERO, Z_N), the first compression's result.
      A1 : constant Block :=
        Compression_Model.G
          (Model.Zero_Block, Model.Address_Input (S, V, Pass, Lane, Slice, N))
      with Ghost => Static;
   begin
      Write_Input (Scratch, S, V, Pass, Lane, Slice, N);
      Lemma_Address_Block (S, V, Pass, Lane, Slice, N);

      --  Y = 1: Scratch (2) := G (ZERO, Z_N); Y = 2: Scratch (2) :=
      --  G (ZERO, Scratch (2)), in place (Compress allows Z = Y).
      for Y in Block_Index range 1 .. 2 loop
         Compression.Compress (Scratch, 0, Y, 2, Work);
         Lemma_Same_Block (Scratch (0), Model.Zero_Block);
         if Y = 1 then
            Lemma_Same_Block (Scratch (2), A1);
         end if;
         pragma Loop_Invariant
           (Scratch (0)'Initialized and then Scratch (1)'Initialized
            and then Scratch (2)'Initialized);
         pragma Loop_Invariant
           (Static =>
              Zero_Block_Ok (Scratch (0))
              and then Same_Block (Scratch (0), Model.Zero_Block)
              and then
              (if Y = 1 then Same_Block (Scratch (2), A1)
               else Scratch (2) = Compression_Model.G (Model.Zero_Block, A1)));
      end loop;
      pragma Assert
        (Static =>
           Scratch (2) = Model.Address_Block (S, V, Pass, Lane, Slice, N));
   end Next_Address_Block;

   ----------------------------------------------------------------------
   --  The address stream
   ----------------------------------------------------------------------

   procedure Lemma_Address_Stream (S : Shape; Index : Segment_Index)
   is null;

end Argon2.Indexing;
