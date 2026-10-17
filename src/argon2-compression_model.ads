--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces; use Interfaces;

with Argon2.Blocks; use Argon2.Blocks;

--  RFC 9106 sections 3.5 and 3.6: the compression function G, written for
--  reading against the RFC.
--
--     G (X, Y):  R = X xor Y.
--                Q: P on each row of R viewed as an 8 x 8 matrix of
--                   16-byte registers R_0 .. R_63 (row I is registers
--                   8 I .. 8 I + 7).
--                Z: P on each column of Q (column I is registers I, I + 8,
--                   ..., I + 56).
--                G = Z xor R.
--
--  A register is two words of the block, R_K = (word 2 K, word 2 K + 1),
--  and P works on the sixteen words of the eight registers it is given, in
--  the order v_0 .. v_15 of the RFC. fBlaMka replaces BLAKE2b's addition.
--
--  * Row_Word and Column_Word give the word of the block that slot J of
--    row or column I holds, off the register matrix.
--  * GB and P are the RFC's, on positions of the block; P_Distinct says
--    the sixteen positions are different (the RFC's v_0 .. v_15 are).
--  * Rows (B, N) is the first N rows applied in order; Columns likewise.
--  * G and G_Xor are the two forms: the first pass writes G (X, Y), the
--    later passes (version 1.3) write the old block xor G (X, Y).
--
--  Static ghost code: GNATprove proves it, and no build ever compiles it.
--  Every subprogram is marked static ghost, and deliberately not the
--  package itself. The type Positions is an ordinary type because the
--  implementation uses it. So the object file holds two symbols: the
--  package's elaboration flag and the initialisation procedure GNAT
--  generates for Positions, which does nothing (it returns at once).

package Argon2.Compression_Model
  with SPARK_Mode, Pure
is
   --  Proof machinery: GNATprove hides the bodies of GB and P by default
   --  (the provers compose them by substitution) and the implementation
   --  reveals each one only where it proves it.

   subtype Group_Index is Integer range 0 .. 7;    --  a row or a column
   subtype Slot_Index is Integer range 0 .. 15;    --  v_0 .. v_15
   subtype Register_Index is Integer range 0 .. 63;
   subtype Half_Index is Integer range 0 .. 1;     --  low word, high word

   --  The sixteen block positions P works on, v_0 .. v_15.
   type Positions is array (Slot_Index) of Word_Index;

   --  Word H of register R of the block.
   function Register_Word
     (R : Register_Index; H : Half_Index) return Word_Index
   is (2 * R + H)
   with Ghost => Static;

   --  Slot J of row I: register 8 I + J / 2, word J mod 2.
   function Row_Word (I : Group_Index; J : Slot_Index) return Word_Index
   is (Register_Word (8 * I + J / 2, J mod 2))
   with Ghost => Static;

   --  Slot J of column I: register I + 8 (J / 2), word J mod 2.
   function Column_Word (I : Group_Index; J : Slot_Index) return Word_Index
   is (Register_Word (I + 8 * (J / 2), J mod 2))
   with Ghost => Static;

   --  Section 3.6: x + y + 2 * lo32 (x) * lo32 (y), modulo 2**64.
   function FBlaMka (X, Y : Word) return Word
   is (X + Y + 2 * ((X mod 2**32) * (Y mod 2**32)))
   with Ghost => Static;

   pragma Annotate
     (GNATprove, Hide_Info, "Expression_Function_Body", FBlaMka);

   function Distinct (A, B, C, D : Word_Index) return Boolean
   is (A /= B and then A /= C and then A /= D
       and then B /= C and then B /= D and then C /= D)
   with Ghost => Static;

   --  Section 3.6: GB on four different positions of the block, with
   --  fBlaMka for addition and the rotations (32, 24, 16, 63).
   function GB (V : Block; A, B, C, D : Word_Index) return Block
   is
     (declare
         A1 : constant Word := FBlaMka (V (A), V (B));
         D1 : constant Word := Rotate_Right (V (D) xor A1, 32);
         C1 : constant Word := FBlaMka (V (C), D1);
         B1 : constant Word := Rotate_Right (V (B) xor C1, 24);
         A2 : constant Word := FBlaMka (A1, B1);
         D2 : constant Word := Rotate_Right (D1 xor A2, 16);
         C2 : constant Word := FBlaMka (C1, D2);
         B2 : constant Word := Rotate_Right (B1 xor C2, 63);
      begin
         [V with delta A => A2, B => B2, C => C2, D => D2])
   with Ghost => Static,
        Pre   => Distinct (A, B, C, D);
   pragma Annotate (GNATprove, Hide_Info, "Expression_Function_Body", GB);

   function P_Distinct (Pos : Positions) return Boolean
   is (for all J in Slot_Index =>
         (for all K in Slot_Index => (if J /= K then Pos (J) /= Pos (K))))
   with Ghost => Static;

   --  Section 3.6: P, the BLAKE2b round without message words, on the
   --  positions Pos = v_0 .. v_15: the eight calls of GB on the columns
   --  and then the diagonals of the 4 x 4 matrix of v.
   function P (V : Block; Pos : Positions) return Block
   is
     (declare
         V1 : constant Block := GB (V,  Pos (0), Pos (4), Pos (8),  Pos (12));
         V2 : constant Block := GB (V1, Pos (1), Pos (5), Pos (9),  Pos (13));
         V3 : constant Block := GB (V2, Pos (2), Pos (6), Pos (10), Pos (14));
         V4 : constant Block := GB (V3, Pos (3), Pos (7), Pos (11), Pos (15));
         V5 : constant Block := GB (V4, Pos (0), Pos (5), Pos (10), Pos (15));
         V6 : constant Block := GB (V5, Pos (1), Pos (6), Pos (11), Pos (12));
         V7 : constant Block := GB (V6, Pos (2), Pos (7), Pos (8),  Pos (13));
         V8 : constant Block := GB (V7, Pos (3), Pos (4), Pos (9),  Pos (14));
      begin
         V8)
   with Ghost => Static,
        Pre   => P_Distinct (Pos);
   pragma Annotate (GNATprove, Hide_Info, "Expression_Function_Body", P);

   --  The positions of row I and of column I.
   function Row_Positions (I : Group_Index) return Positions
   is ([for J in Slot_Index => Row_Word (I, J)])
   with Ghost => Static,
        Post  => P_Distinct (Row_Positions'Result);

   function Column_Positions (I : Group_Index) return Positions
   is ([for J in Slot_Index => Column_Word (I, J)])
   with Ghost => Static,
        Post  => P_Distinct (Column_Positions'Result);

   --  P on the first N rows, in order, and on the first N columns.
   function Rows (B : Block; N : Natural) return Block
   is (if N = 0 then B else P (Rows (B, N - 1), Row_Positions (N - 1)))
   with Ghost              => Static,
        Pre                => N <= 8,
        Subprogram_Variant => (Decreases => N);

   function Columns (B : Block; N : Natural) return Block
   is (if N = 0 then B else P (Columns (B, N - 1), Column_Positions (N - 1)))
   with Ghost              => Static,
        Pre                => N <= 8,
        Subprogram_Variant => (Decreases => N);

   function Xor_Blocks (X, Y : Block) return Block
   is ([for K in Word_Index => X (K) xor Y (K)])
   with Ghost => Static;

   --  Section 3.5: G (X, Y).
   function G (X, Y : Block) return Block
   is
     (declare
         R : constant Block := Xor_Blocks (X, Y);
         Q : constant Block := Rows (R, 8);
         Z : constant Block := Columns (Q, 8);
      begin
         Xor_Blocks (Z, R))
   with Ghost => Static;

   --  The form of every pass after the first: the old block xor G (X, Y).
   function G_Xor (X, Y, Old_Z : Block) return Block
   is (Xor_Blocks (Old_Z, G (X, Y)))
   with Ghost => Static;
end Argon2.Compression_Model;
