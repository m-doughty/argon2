--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;
with Interfaces.C;
with System;

with Argon2.Blocks;
with Argon2.Compression;
with Compression_Vectors; use Compression_Vectors;

package body Compression_Tests is

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   function Passed return Natural is (Pass_Count);
   function Failed return Natural is (Fail_Count);

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if Condition then
         Pass_Count := Pass_Count + 1;
      else
         Fail_Count := Fail_Count + 1;
         Put_Line ("FAIL: compression: " & Label_Text);
      end if;
   end Check;

   --  The unmodified reference's fill_block, through ref/compress_oracle.c:
   --  Z = G (X, Y), or Z = Z xor G (X, Y) when With_Xor is not zero.
   procedure Compress_Oracle
     (X, Y, Z  : System.Address;
      With_Xor : Interfaces.C.int)
   with Import, Convention => C, External_Name => "compress_oracle";

   package AB renames Argon2.Blocks;
   package AC renames Argon2.Compression;

   --  Compress's scratch block, supplied here as a caller would. It holds
   --  anything on entry, so one block serves every call of these tests.
   Work : AB.Block := [others => 0];
   use type AB.Block;
   use type Interfaces.Unsigned_64;

   --  Test-only xorshift64* generator: the C oracle is the reference, so
   --  one generator written once is enough to make the inputs.
   Rng_State : Word := 16#9E37_79B9_7F4A_7C15#;

   function Next_Word return Word is
      X : Word := Rng_State;
   begin
      X := X xor Interfaces.Shift_Right (X, 12);
      X := X xor Interfaces.Shift_Left (X, 25);
      X := X xor Interfaces.Shift_Right (X, 27);
      Rng_State := X;
      return X * 16#2545_F491_4F6C_DD1D#;
   end Next_Word;

   function Random_Block return AB.Block is
      R : AB.Block;
   begin
      for K in R'Range loop
         R (K) := Next_Word;
      end loop;
      return R;
   end Random_Block;

   function Filled (W : Word) return AB.Block is ([others => W]);

   --  One comparison: the Ada Compress (or Compress_Xor) on a Block_Array
   --  of eight blocks with lower bound Lo, X, Y and Z at Lo + A, Lo + B and
   --  Lo + C (A /= C, B /= C; A = B is allowed), the other blocks holding
   --  sentinels, against the oracle on copies. The oracle's result must
   --  equal the block at Z, and no other block may change.
   procedure Check_Case
     (Label_Text : String;
      X, Y, Z_In : AB.Block;
      With_Xor   : Boolean;
      Lo         : AB.Block_Index;
      A, B, C    : Natural)
   is
      Xi : constant AB.Block_Index := Lo + AB.Block_Index (A);
      Yi : constant AB.Block_Index := Lo + AB.Block_Index (B);
      Zi : constant AB.Block_Index := Lo + AB.Block_Index (C);
      M, Before : AB.Block_Array (Lo .. Lo + 7);
      Ox, Oy : AB.Block;
      Oz : AB.Block := Z_In;
      Unchanged : Boolean := True;
   begin
      for K in M'Range loop
         M (K) := Filled (16#5A5A_0000_0000_0000# + Word (K - Lo));
      end loop;
      M (Xi) := X;
      M (Yi) := Y;
      M (Zi) := Z_In;
      Before := M;
      --  With A = B the block is shared, so the later store wins.
      Ox := M (Xi);
      Oy := M (Yi);

      if With_Xor then
         AC.Compress_Xor (M, Xi, Yi, Zi, Work);
      else
         AC.Compress (M, Xi, Yi, Zi, Work);
      end if;

      Compress_Oracle
        (Ox'Address, Oy'Address, Oz'Address,
         (if With_Xor then 1 else 0));

      for K in M'Range loop
         if K /= Zi and then M (K) /= Before (K) then
            Unchanged := False;
         end if;
      end loop;
      Check (M (Zi) = Oz, Label_Text & ": equals the oracle");
      Check (Unchanged, Label_Text & ": other blocks unchanged");
   end Check_Case;

   --  Both forms of one pair of inputs, at the given layout.
   procedure Both_Forms
     (Label_Text : String;
      X, Y       : AB.Block;
      Lo         : AB.Block_Index;
      A, B, C    : Natural)
   is
   begin
      Check_Case
        (Label_Text & " plain", X, Y, Random_Block, False, Lo, A, B, C);
      Check_Case (Label_Text & " xor", X, Y, Random_Block, True, Lo, A, B, C);
   end Both_Forms;

   --  Z the same block as X, as Y, or X = Y = Z: Which is 0, 1 or 2. The
   --  expected block comes from the oracle on separate copies of the inputs
   --  (and of the old Z, which is X or Y here); the oracle called in place
   --  must agree with that, as the reference's own address generation
   --  relies on.
   procedure Check_Alias
     (Label_Text : String;
      X, Y       : AB.Block;
      With_Xor   : Boolean;
      Which      : Natural)
   is
      Xi : constant AB.Block_Index := 1;
      Yi : constant AB.Block_Index := (if Which = 2 then 1 else 2);
      Zi : constant AB.Block_Index := (if Which = 1 then Yi else Xi);
      M, Before : AB.Block_Array (0 .. 5);
      Ox, Oy, Oz, Inplace : AB.Block;
      Unchanged : Boolean := True;
   begin
      for K in M'Range loop
         M (K) := Filled (16#A5A5_0000_0000_0000# + Word (K));
      end loop;
      M (Xi) := X;
      M (Yi) := (if Which = 2 then X else Y);
      Before := M;
      Ox := M (Xi);
      Oy := M (Yi);
      Oz := M (Zi);
      Inplace := M (Zi);

      if With_Xor then
         AC.Compress_Xor (M, Xi, Yi, Zi, Work);
      else
         AC.Compress (M, Xi, Yi, Zi, Work);
      end if;

      Compress_Oracle
        (Ox'Address, Oy'Address, Oz'Address, (if With_Xor then 1 else 0));

      for K in M'Range loop
         if K /= Zi and then M (K) /= Before (K) then
            Unchanged := False;
         end if;
      end loop;
      Check (M (Zi) = Oz, Label_Text & ": in place equals the oracle");
      Check (Unchanged, Label_Text & ": other blocks unchanged");

      --  The reference itself, with its output block also an input.
      declare
         Rx : AB.Block := X;
         Ry : AB.Block := (if Which = 2 then X else Y);
      begin
         if Which = 1 then
            Compress_Oracle
              (Rx'Address, Ry'Address, Ry'Address,
               (if With_Xor then 1 else 0));
            Inplace := Ry;
         else
            Compress_Oracle
              (Rx'Address, Ry'Address, Rx'Address,
               (if With_Xor then 1 else 0));
            Inplace := Rx;
         end if;
         Check (Inplace = Oz, Label_Text & ": reference in place agrees");
      end;
   end Check_Alias;

   procedure Run_Ada is
      Zero_Block : constant AB.Block := [others => 0];
      Top        : constant AB.Block_Index := AB.Block_Index'Last - 7;
   begin
      --  The published vectors, through the Ada code.
      for V of Vectors loop
         declare
            Label_Text : constant String := "Ada " & V.Name;
            X          : constant AB.Block := AB.Block (V.X);
            Y          : constant AB.Block := AB.Block (V.Y);
            Old        : constant AB.Block := AB.Block (V.Old);
            Expected   : constant AB.Block := AB.Block (V.Expected);
            M          : AB.Block_Array (5 .. 9);
         begin
            M := [others => Filled (16#1111_1111_1111_1111#)];
            M (6) := X;
            M (8) := Y;
            M (9) := (if V.With_Xor then Old else Filled (16#DEAD_BEEF#));
            if V.With_Xor then
               AC.Compress_Xor (M, 6, 8, 9, Work);
            else
               AC.Compress (M, 6, 8, 9, Work);
            end if;
            Check (M (9) = Expected, Label_Text & ": published block");
            Check (M (6) = X and then M (8) = Y
                   and then M (5) = Filled (16#1111_1111_1111_1111#)
                   and then M (7) = Filled (16#1111_1111_1111_1111#),
                   Label_Text & ": other blocks unchanged");
            Check_Case (Label_Text, X, Y, Old, V.With_Xor, 100, 1, 3, 4);
         end;
      end loop;

      --  X = Y (the result is then constant in the inputs).
      declare
         B : constant AB.Block := Random_Block;
      begin
         Both_Forms ("X = Y", B, B, 0, 2, 2, 5);
         Both_Forms ("X = Y zero", Zero_Block, Zero_Block, 0, 0, 0, 1);
      end;

      --  Every word position, alone, in either input.
      for Pos in AB.Word_Index loop
         declare
            One : AB.Block := Zero_Block;
         begin
            One (Pos) := 16#0123_4567_89AB_CDEF# xor Word (Pos);
            Both_Forms
              ("word" & Pos'Image & " in X", One, Zero_Block, 0, 1, 2, 3);
            Both_Forms
              ("word" & Pos'Image & " in Y", Zero_Block, One, 0, 4, 5, 6);
         end;
      end loop;

      --  Extreme words, including the multiplication's wrap.
      Both_Forms ("all ones", Filled (Word'Last), Zero_Block, 0, 0, 1, 7);
      Both_Forms ("all ones both", Filled (Word'Last), Filled (Word'Last),
                  0, 0, 1, 7);
      Both_Forms ("low halves FFFFFFFF", Filled (16#FFFF_FFFF#),
                  Filled (16#FFFF_FFFF#), 0, 3, 6, 0);
      Both_Forms ("high halves FFFFFFFF", Filled (16#FFFF_FFFF_0000_0000#),
                  Filled (16#FFFF_FFFF_0000_0001#), 0, 3, 6, 0);
      Both_Forms ("msb", Filled (16#8000_0000_0000_0000#),
                  Filled (16#8000_0000_8000_0000#), 0, 7, 6, 0);

      --  Pseudo-random pairs, at varied layouts and lower bounds, including
      --  the top of the index range.
      for I in 1 .. 200 loop
         declare
            Lo : constant AB.Block_Index :=
              (case I mod 4 is
                 when 0 => 0,
                 when 1 => 1,
                 when 2 => 3_000_000_000,
                 when others => Top);
            C  : constant Natural := Natural (Next_Word mod 8);
            A  : constant Natural := (C + 1 + Natural (Next_Word mod 7)) mod 8;
            B  : constant Natural :=
              (if I mod 5 = 0 then A
               else (C + 1 + Natural (Next_Word mod 7)) mod 8);
         begin
            Check_Case ("random" & I'Image, Random_Block, Random_Block,
                        Random_Block, I mod 2 = 0, Lo, A, B, C);
         end;
      end loop;

      --  Z aliasing X or Y: published vectors and random pairs.
      for V of Vectors loop
         declare
            X : constant AB.Block := AB.Block (V.X);
            Y : constant AB.Block := AB.Block (V.Y);
         begin
            for Which in 0 .. 2 loop
               Check_Alias (V.Name & " alias" & Which'Image, X, Y,
                            V.With_Xor, Which);
               Check_Alias (V.Name & " alias xor" & Which'Image, X, Y,
                            True, Which);
            end loop;
         end;
      end loop;
      for I in 1 .. 100 loop
         for Which in 0 .. 2 loop
            Check_Alias ("random alias" & I'Image & Which'Image,
                         Random_Block, Random_Block, I mod 2 = 0, Which);
         end loop;
      end loop;
      Check_Alias ("zero alias", Zero_Block, Zero_Block, False, 2);
   end Run_Ada;

   procedure Run is
      Zeros : constant Block := [others => 0];
   begin
      --  A missing or truncated table would otherwise pass silently.
      Check (Vectors'Length = 15, "fifteen published vectors");

      for V of Vectors loop
         declare
            Label_Text : constant String := V.Name;
            X, Y       : Block := [others => 0];
            Z          : Block := [others => 16#DEAD_BEEF_DEAD_BEEF#];
            Flip       : Block := [others => 0];
            Xor_Flag   : constant Interfaces.C.int :=
              (if V.With_Xor then 1 else 0);
         begin
            Check (V.With_Xor or else V.Old = Zeros,
                   Label_Text & ": Old unused");

            X := V.X;
            Y := V.Y;
            Z := (if V.With_Xor then V.Old else Z);
            Compress_Oracle (X'Address, Y'Address, Z'Address, Xor_Flag);
            Check (Z = V.Expected, Label_Text & ": published block");
            Check (X = V.X and then Y = V.Y,
                   Label_Text & ": inputs unchanged");

            --  G is symmetric in its two arguments.
            Flip := (if V.With_Xor then V.Old else [others => 1]);
            Compress_Oracle (Y'Address, X'Address, Flip'Address, Xor_Flag);
            Check (Flip = V.Expected, Label_Text & ": arguments swapped");
         end;
      end loop;

      Run_Ada;
   end Run;

end Compression_Tests;
