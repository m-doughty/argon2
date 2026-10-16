--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Level (Executable);

with Interfaces; use Interfaces;

package body Argon2.Compression
  with SPARK_Mode
is
   package Model renames Argon2.Compression_Model;
   use type Model.Positions;

   --  Proof machinery (never executed: Static ghost code is not compiled
   --  into any build). The provers will not substitute element-wise equal
   --  arrays into the opaque model functions; Same is interpreted as
   --  logical equality, which they substitute freely, and the lemmas
   --  convert one into the other (array extensionality).
   function Same_Block (L, R : Block) return Boolean is (L = R)
   with Ghost    => Static,
        Global   => null,
        Annotate => (GNATprove, Logical_Equal);

   procedure Lemma_Same_Block (L, R : Block)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same_Block (L, R);

   procedure Lemma_Same_Block (L, R : Block)
   is
   begin
      null;
   end Lemma_Same_Block;

   function Same_Positions (L, R : Model.Positions) return Boolean
   is (L = R)
   with Ghost    => Static,
        Global   => null,
        Annotate => (GNATprove, Logical_Equal);

   procedure Lemma_Same_Positions (L, R : Model.Positions)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same_Positions (L, R);

   procedure Lemma_Same_Positions (L, R : Model.Positions)
   is
   begin
      null;
   end Lemma_Same_Positions;

   --  RFC 9106 section 3.6, fBlaMka: x + y + 2 * lo32 (x) * lo32 (y), all
   --  modulo 2**64. The product of two 32-bit values fits in 64 bits.
   function FBlaMka (X, Y : Word) return Word
   with Post => (Static => FBlaMka'Result = Model.FBlaMka (X, Y));

   function FBlaMka (X, Y : Word) return Word
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Model.FBlaMka);
   begin
      return X + Y + 2 * ((X and 16#FFFF_FFFF#) * (Y and 16#FFFF_FFFF#));
   end FBlaMka;

   --  The mixing function GB on four distinct words of the working block.
   procedure GB (R : in out Block; A, B, C, D : Word_Index)
   with Pre  =>
          A /= B and then A /= C and then A /= D
          and then B /= C and then B /= D and then C /= D,
        Post => (Static => R = Model.GB (R'Old, A, B, C, D))
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Model.GB);
      VA : Word := R (A);
      VB : Word := R (B);
      VC : Word := R (C);
      VD : Word := R (D);
   begin
      VA := FBlaMka (VA, VB);
      VD := Rotate_Right (VD xor VA, 32);
      VC := FBlaMka (VC, VD);
      VB := Rotate_Right (VB xor VC, 24);
      VA := FBlaMka (VA, VB);
      VD := Rotate_Right (VD xor VA, 16);
      VC := FBlaMka (VC, VD);
      VB := Rotate_Right (VB xor VC, 63);
      R (A) := VA;
      R (B) := VB;
      R (C) := VC;
      R (D) := VD;
   end GB;

   --  The reference's first pass: sixteen consecutive words,
   --  16 I .. 16 I + 15.
   function Consecutive (I : Integer) return Model.Positions
   is ([16 * I,      16 * I + 1,  16 * I + 2,  16 * I + 3,
        16 * I + 4,  16 * I + 5,  16 * I + 6,  16 * I + 7,
        16 * I + 8,  16 * I + 9,  16 * I + 10, 16 * I + 11,
        16 * I + 12, 16 * I + 13, 16 * I + 14, 16 * I + 15])
   with Pre => I in 0 .. 7;

   --  The reference's second pass: (2 I, 2 I + 1), (2 I + 16, 2 I + 17), ...
   --  (2 I + 112, 2 I + 113).
   function Strided (I : Integer) return Model.Positions
   is ([2 * I,       2 * I + 1,   2 * I + 16,  2 * I + 17,
        2 * I + 32,  2 * I + 33,  2 * I + 48,  2 * I + 49,
        2 * I + 64,  2 * I + 65,  2 * I + 80,  2 * I + 81,
        2 * I + 96,  2 * I + 97,  2 * I + 112, 2 * I + 113])
   with Pre => I in 0 .. 7;

   --  The two literal lists agree with the model's register-matrix maps.
   procedure Lemma_Row_Positions (I : Integer)
   with Ghost  => Static,
        Global => null,
        Pre    => I in 0 .. 7,
        Post   => Consecutive (I) = Model.Row_Positions (I);

   procedure Lemma_Row_Positions (I : Integer)
   is
   begin
      null;
   end Lemma_Row_Positions;

   procedure Lemma_Column_Positions (I : Integer)
   with Ghost  => Static,
        Global => null,
        Pre    => I in 0 .. 7,
        Post   => Strided (I) = Model.Column_Positions (I);

   procedure Lemma_Column_Positions (I : Integer)
   is
   begin
      null;
   end Lemma_Column_Positions;

   --  The sixteen positions of P are different, so each of its eight calls
   --  of GB is on four different words.
   procedure Lemma_Slots (V : Model.Positions)
   with Ghost  => Static,
        Global => null,
        Pre    => Model.P_Distinct (V),
        Post   =>
          Model.Distinct (V (0), V (4), V (8),  V (12))
          and then Model.Distinct (V (1), V (5), V (9),  V (13))
          and then Model.Distinct (V (2), V (6), V (10), V (14))
          and then Model.Distinct (V (3), V (7), V (11), V (15))
          and then Model.Distinct (V (0), V (5), V (10), V (15))
          and then Model.Distinct (V (1), V (6), V (11), V (12))
          and then Model.Distinct (V (2), V (7), V (8),  V (13))
          and then Model.Distinct (V (3), V (4), V (9),  V (14));

   procedure Lemma_Slots (V : Model.Positions)
   is
   begin
      null;
   end Lemma_Slots;

   --  P: the BLAKE2b round without message words, on the sixteen positions
   --  V (0) .. V (15). Its eight GB calls, in the order of RFC 9106
   --  section 3.6 and of the reference's BLAKE2_ROUND_NOMSG.
   procedure P (R : in out Block; V : Model.Positions)
   with Pre  => (Static => Model.P_Distinct (V)),
        Post => (Static => R = Model.P (R'Old, V))
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Model.P);
      Prev : Block := R with Ghost => Static;
   begin
      Lemma_Slots (V);
      GB (R, V (0), V (4), V (8),  V (12));
      Lemma_Same_Block (R, Model.GB (Prev, V (0), V (4), V (8), V (12)));
      Prev := R;
      GB (R, V (1), V (5), V (9),  V (13));
      Lemma_Same_Block (R, Model.GB (Prev, V (1), V (5), V (9), V (13)));
      Prev := R;
      GB (R, V (2), V (6), V (10), V (14));
      Lemma_Same_Block (R, Model.GB (Prev, V (2), V (6), V (10), V (14)));
      Prev := R;
      GB (R, V (3), V (7), V (11), V (15));
      Lemma_Same_Block (R, Model.GB (Prev, V (3), V (7), V (11), V (15)));
      Prev := R;
      GB (R, V (0), V (5), V (10), V (15));
      Lemma_Same_Block (R, Model.GB (Prev, V (0), V (5), V (10), V (15)));
      Prev := R;
      GB (R, V (1), V (6), V (11), V (12));
      Lemma_Same_Block (R, Model.GB (Prev, V (1), V (6), V (11), V (12)));
      Prev := R;
      GB (R, V (2), V (7), V (8),  V (13));
      Lemma_Same_Block (R, Model.GB (Prev, V (2), V (7), V (8), V (13)));
      Prev := R;
      GB (R, V (3), V (4), V (9),  V (14));
      Lemma_Same_Block (R, Model.GB (Prev, V (3), V (4), V (9), V (14)));
   end P;

   --  The first pass: P on each of the eight groups of consecutive words.
   procedure Row_Pass (R : in out Block)
   with Post => (Static => R = Model.Rows (R'Old, 8))
   is
      Entry_R : constant Block := R with Ghost => Static;
   begin
      for I in 0 .. 7 loop
         Lemma_Same_Block (R, Model.Rows (Entry_R, I));
         Lemma_Row_Positions (I);
         Lemma_Same_Positions (Consecutive (I), Model.Row_Positions (I));
         P (R, Consecutive (I));
         pragma Loop_Invariant (Static => R = Model.Rows (Entry_R, I + 1));
      end loop;
   end Row_Pass;

   --  The second pass: P on each of the eight strided groups.
   procedure Column_Pass (R : in out Block)
   with Post => (Static => R = Model.Columns (R'Old, 8))
   is
      Entry_R : constant Block := R with Ghost => Static;
   begin
      for I in 0 .. 7 loop
         Lemma_Same_Block (R, Model.Columns (Entry_R, I));
         Lemma_Column_Positions (I);
         Lemma_Same_Positions (Strided (I), Model.Column_Positions (I));
         P (R, Strided (I));
         pragma Loop_Invariant (Static => R = Model.Columns (Entry_R, I + 1));
      end loop;
   end Column_Pass;

   --  Both passes in place.
   procedure Permute (R : in out Block)
   with Post =>
          (Static => R = Model.Columns (Model.Rows (R'Old, 8), 8))
   is
      Mid : constant Block := R with Ghost => Static;
   begin
      Row_Pass (R);
      Lemma_Same_Block (R, Model.Rows (Mid, 8));
      Column_Pass (R);
   end Permute;

   --  With Accumulate False: M (Z) := G (M (X), M (Y)); with it True:
   --  M (Z) := M (Z) xor G (M (X), M (Y)). G (X, Y) is Permute (R) xor R,
   --  where R = X xor Y; the first R is kept in the working block, and the
   --  final loop recomputes word K of it from M (X) and M (Y) rather than
   --  keeping a second block. Word K of M (Z) is written after word K of
   --  M (X), M (Y) and M (Z) has been read and before no later step reads
   --  it, so Z may be X or Y.
   procedure Combine
     (M : in out Block_Array; X, Y, Z : Block_Index; Accumulate : Boolean;
      R : out Block)
   with Relaxed_Initialization => M,
        Pre =>
          X in M'Range and then Y in M'Range and then Z in M'Range
          and then M (X)'Initialized and then M (Y)'Initialized
          and then (if Accumulate then M (Z)'Initialized),
        Post =>
          (Executable =>
             (for all I in M'Range =>
                (if (I = Z and then not Accumulate)
                    or else M'Old (I)'Initialized
                 then M (I)'Initialized)),
           Static     =>
             M (Z)
             = (if Accumulate
                then Model.G_Xor (M'Old (X), M'Old (Y), M'Old (Z))
                else Model.G (M'Old (X), M'Old (Y)))
             and then
             (for all I in M'Range =>
                (if I /= Z and then M'Old (I)'Initialized
                 then M (I) = M'Old (I))))
   is
      X0 : constant Block := M (X) with Ghost => Static;
      Y0 : constant Block := M (Y) with Ghost => Static;
      Z0 : constant Block :=
        (if Accumulate then M (Z) else [others => 0]) with Ghost => Static;
      T  : constant Block :=
        (if Accumulate then Model.G_Xor (X0, Y0, Z0) else Model.G (X0, Y0))
      with Ghost => Static;
   begin
      R := M (X);
      for K in Word_Index loop
         R (K) := R (K) xor M (Y) (K);
         pragma Loop_Invariant
           (Static =>
              (for all J in Word_Index range 0 .. K =>
                 R (J) = (X0 (J) xor Y0 (J))));
         pragma Loop_Invariant
           (Static =>
              (for all J in Word_Index range K + 1 .. Word_Index'Last =>
                 R (J) = X0 (J)));
      end loop;

      Lemma_Same_Block (R, Model.Xor_Blocks (X0, Y0));
      Permute (R);

      for K in Word_Index loop
         M (Z) (K) :=
           (if Accumulate then M (Z) (K) else 0)
           xor R (K) xor M (X) (K) xor M (Y) (K);
         pragma Loop_Invariant
           (for all J in Word_Index range 0 .. K => M (Z) (J)'Initialized);
         pragma Loop_Invariant
           (for all I in M'Range =>
              (if I /= Z and then M'Loop_Entry (I)'Initialized
               then M (I)'Initialized));
         pragma Loop_Invariant
           (Static =>
              (for all J in Word_Index range 0 .. K =>
                 M (Z) (J) = T (J)));
         pragma Loop_Invariant
           (Static =>
              (for all J in Word_Index range K + 1 .. Word_Index'Last =>
                 M (X) (J) = X0 (J) and then M (Y) (J) = Y0 (J)
                 and then (if Accumulate then M (Z) (J) = Z0 (J))));
         pragma Loop_Invariant
           (Static =>
              (for all I in M'Range =>
                 (if I /= Z and then M'Loop_Entry (I)'Initialized
                  then M (I) = M'Loop_Entry (I))));
      end loop;
   end Combine;

   procedure Compress
     (M : in out Block_Array; X, Y, Z : Block_Index; Work : out Block)
   is
   begin
      Combine (M, X, Y, Z, Accumulate => False, R => Work);
   end Compress;

   procedure Compress_Xor
     (M : in out Block_Array; X, Y, Z : Block_Index; Work : out Block)
   is
   begin
      Combine (M, X, Y, Z, Accumulate => True, R => Work);
   end Compress_Xor;
end Argon2.Compression;
