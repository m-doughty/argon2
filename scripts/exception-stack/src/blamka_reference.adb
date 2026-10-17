--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces; use Interfaces;

package body Blamka_Reference is

   function F (X, Y : Unsigned_64) return Unsigned_64 is
     (X + Y + 2 * ((X and 16#FFFF_FFFF#) * (Y and 16#FFFF_FFFF#)));

   procedure GB (V : in out Word_Array; A, B, C, D : Natural) is
   begin
      V (A) := F (V (A), V (B));
      V (D) := Rotate_Right (V (D) xor V (A), 32);
      V (C) := F (V (C), V (D));
      V (B) := Rotate_Right (V (B) xor V (C), 24);
      V (A) := F (V (A), V (B));
      V (D) := Rotate_Right (V (D) xor V (A), 16);
      V (C) := F (V (C), V (D));
      V (B) := Rotate_Right (V (B) xor V (C), 63);
   end GB;

   type Positions is array (0 .. 15) of Natural;

   --  The BLAKE2b round without message words on the sixteen words of R
   --  at positions S.
   procedure P (R : in out Word_Array; S : Positions) is
   begin
      GB (R, S (0), S (4), S (8),  S (12));
      GB (R, S (1), S (5), S (9),  S (13));
      GB (R, S (2), S (6), S (10), S (14));
      GB (R, S (3), S (7), S (11), S (15));
      GB (R, S (0), S (5), S (10), S (15));
      GB (R, S (1), S (6), S (11), S (12));
      GB (R, S (2), S (7), S (8),  S (13));
      GB (R, S (3), S (4), S (9),  S (14));
   end P;

   function Permute (R : Word_Array) return Word_Array is
      Q : Word_Array := R;
      S : Positions;
   begin
      for I in 0 .. 7 loop
         for J in 0 .. 15 loop
            S (J) := 16 * I + J;
         end loop;
         P (Q, S);
      end loop;
      for I in 0 .. 7 loop
         for J in 0 .. 7 loop
            S (2 * J) := 2 * I + 16 * J;
            S (2 * J + 1) := 2 * I + 16 * J + 1;
         end loop;
         P (Q, S);
      end loop;
      return Q;
   end Permute;

end Blamka_Reference;
