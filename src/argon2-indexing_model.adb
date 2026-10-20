--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The proofs of the indexing model. Static ghost code: proved by
--  GNATprove, never compiled.

package body Argon2.Indexing_Model
  with SPARK_Mode
is

   ----------------------------------------------------------------------
   --  Arithmetic
   ----------------------------------------------------------------------

   --  0 <= A and X <= C give A * X <= A * C.
   procedure Lemma_Mul_Mono (A, X, C : Big_Integer)
   with Ghost  => Static,
        Global => null,
        Pre    => A >= Big_LLI (0) and then X <= C,
        Post   => A * X <= A * C
   is
      D : constant Big_Integer := C - X;
   begin
      pragma Assert (D >= Big_LLI (0));
      pragma Assert (A * D >= Big_LLI (0));
      pragma Assert (A * C = A * X + A * D);
   end Lemma_Mul_Mono;

   --  0 <= N < A * D with D > 0 gives 0 <= N / D < A.
   procedure Lemma_Div_Below (N, A, D : Big_Integer)
   with Ghost  => Static,
        Global => null,
        Pre    => N >= Big_LLI (0) and then D > Big_LLI (0)
                  and then N < A * D,
        Post   => N / D >= Big_LLI (0) and then N / D < A
   is
      Q : constant Big_Integer := N / D;
   begin
      pragma Assert (Q >= Big_LLI (0));
      pragma Assert (Q * D <= N);
      pragma Assert (Q < A);
   end Lemma_Div_Below;

   --  X mod Q for X in -Q .. 2 Q - 1: at most one lap either way.
   procedure Lemma_Mod_Near (X, Q : Long_Long_Integer)
   with Ghost  => Static,
        Global => null,
        Pre    => Q in 1 .. 2**40 and then X in -Q .. 2 * Q - 1,
        Post   => X mod Q = (if X < 0 then X + Q
                             elsif X < Q then X
                             else X - Q)
   is
   begin
      null;
   end Lemma_Mod_Near;

   ----------------------------------------------------------------------
   --  The model
   ----------------------------------------------------------------------

   function Relative_Position
     (Area : Long_Long_Integer; J : U32) return Long_Long_Integer
   is
      Zero : constant Big_Integer := Big_LLI (0);
      One  : constant Big_Integer := Big_LLI (1);
      Max  : constant Big_Integer := Big_LLI (2**32 - 1);
      A    : constant Big_Integer := Big_LLI (Area);
      JB   : constant Big_Integer := Big_LLI (Long_Long_Integer (J));
      X    : constant Big_Integer := (JB * JB) / Two32;
      YY   : constant Big_Integer := (A * X) / Two32;
      R    : constant Big_Integer := Rel_Big (Area, J);
   begin
      --  J1 <= 2**32 - 1, so J1**2 <= (2**32 - 1)**2 < (2**32 - 1) 2**32
      --  and x <= 2**32 - 2.
      pragma Assert (JB >= Zero and then JB <= Max);
      Lemma_Mul_Mono (JB, JB, Max);
      Lemma_Mul_Mono (Max, JB, Max);
      pragma Assert (JB * JB <= Max * Max);
      pragma Assert (Max * Max < Max * Two32);
      Lemma_Mul_Mono (JB, Zero, JB);
      Lemma_Div_Below (JB * JB, Max, Two32);
      pragma Assert (X >= Zero and then X <= Max - One);

      --  Then |W| x <= |W| (2**32 - 2) < |W| 2**32, so 0 <= y <= |W| - 1.
      Lemma_Mul_Mono (A, X, Max - One);
      Lemma_Mul_Mono (A, Zero, X);
      pragma Assert (A * (Max - One) < A * Two32);
      Lemma_Div_Below (A * X, A, Two32);
      pragma Assert (YY >= Zero and then YY <= A - One);

      pragma Assert (R >= Zero and then R <= A - One);
      return
        Long_Long_Integer (Blake2b.Hashing.Big.Lengths.From_Big_Integer (R));
   end Relative_Position;

   ----------------------------------------------------------------------
   --  What the fill relies on
   ----------------------------------------------------------------------

   procedure Lemma_Area
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      Index : Segment_Index;
      W     : U64)
   is null;

   procedure Lemma_Lane
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      W     : U64)
   is
   begin
      pragma Assert (Reference_Lane (S, Pass, Slice, Lane, W) < S.Lanes);
   end Lemma_Lane;

   procedure Lemma_Ranges
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      Index : Segment_Index;
      W     : U64)
   is
   begin
      Lemma_Area (S, Pass, Slice, Lane, Index, W);
      Lemma_Lane (S, Pass, Slice, Lane, W);
   end Lemma_Ranges;

   procedure Lemma_Window
     (S     : Shape;
      Pass  : Pass_Number;
      Slice : Slice_Index;
      Lane  : Lane_Number;
      Index : Segment_Index;
      W     : U64)
   is
      Q        : constant Long_Long_Integer := Lane_Length (S);
      First    : constant Long_Long_Integer := Slice * S.Segment;
      L        : constant Long_Long_Integer := First + Index;
      Ref_Lane : constant Lane_Number :=
        Reference_Lane (S, Pass, Slice, Lane, W);
      Same     : constant Boolean := Ref_Lane = Lane;
   begin
      Lemma_Area (S, Pass, Slice, Lane, Index, W);
      Lemma_Lane (S, Pass, Slice, Lane, W);
      pragma Assert (First <= 3 * S.Segment);
      pragma Assert (L <= Q - 1);
      Lemma_Mod_Near (L - 1, Q);
      Lemma_Mod_Near (First - 1, Q);
      declare
         A     : constant Long_Long_Integer :=
           Area (S, Pass, Slice, Index, Same);
         Rel   : constant Long_Long_Integer := Relative_Position (A, J1 (W));
         Start : constant Long_Long_Integer :=
           Start_Position (S, Pass, Slice);
         Sum   : constant Long_Long_Integer := Start + Rel;
         R     : constant Reference :=
           Locate (S, Pass, Slice, Lane, Index, W);
      begin
         pragma Assert (R.Lane = Ref_Lane);
         pragma Assert (R.Index = Sum mod Q);
         pragma Assert (A <= 3 * S.Segment + Index);
         pragma Assert (Sum in 0 .. 2 * Q - 1);
         Lemma_Mod_Near (Sum, Q);
         pragma Assert (if Sum < Q then R.Index = Sum else R.Index = Sum - Q);
      end;
   end Lemma_Window;

end Argon2.Indexing_Model;
