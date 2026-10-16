--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with Interfaces;
with Interfaces.C;
with System;

with Argon2; use Argon2;
with Argon2.H_Prime;
with Blake2b;
with Blake2b.Hashing;
with H_Prime_Vectors;

package body H_Prime_Tests is

   use type Interfaces.C.int;
   use type Blake2b.I64;
   use type Blake2b.Byte;

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
         Put_Line ("FAIL: H': " & Label_Text);
      end if;
   end Check;

   --  Outputs reach 2**20 + 8 bytes: they live on the heap (a Windows
   --  main thread has a 1 MiB stack).
   type Argon2_Bytes is access Byte_Array;
   type Blake2b_Bytes is access Blake2b.Byte_Array;
   procedure Free is new Ada.Unchecked_Deallocation (Byte_Array, Argon2_Bytes);
   procedure Free is new Ada.Unchecked_Deallocation
     (Blake2b.Byte_Array, Blake2b_Bytes);

   function Reference
     (Output  : System.Address;
      Out_Len : Interfaces.C.size_t;
      Input   : System.Address;
      In_Len  : Interfaces.C.size_t) return Interfaces.C.int
   with Import, Convention => C, External_Name => "blake2b_long";

   --  Input byte J: (Seed * 37 + J * 13 + (J / 256) * 7) mod 256, as in
   --  scripts/h-prime-vectors.py.
   function Make_Input (Length, Seed : Natural) return Blake2b.Byte_Array is
      Result : Blake2b.Byte_Array (0 .. Blake2b.I64 (Length) - 1);
   begin
      for J in Result'Range loop
         Result (J) :=
           Blake2b.Byte ((Seed * 37 + Natural (J) * 13
                          + (Natural (J) / 256) * 7) mod 256);
      end loop;
      return Result;
   end Make_Input;

   --  H' with its scratch (hash state and two chain values) supplied here.
   procedure Run_H_Prime
     (Input : Blake2b.Byte_Array; Digest : out Byte_Array)
   is
      S : Blake2b.Hashing.State;
      V, Next_V : Argon2.H_Prime.Chain := [others => 0];
   begin
      Argon2.H_Prime.Hash (Input, Digest, S, V, Next_V);
   end Run_H_Prime;

   function Hex (Data : Blake2b.Byte_Array) return String is
      Digits_Of : constant String := "0123456789abcdef";
      Result : String (1 .. 2 * Natural (Data'Length));
      K : Natural := 0;
   begin
      for B of Data loop
         Result (2 * K + 1) := Digits_Of (Natural (B / 16) + 1);
         Result (2 * K + 2) := Digits_Of (Natural (B mod 16) + 1);
         K := K + 1;
      end loop;
      return Result;
   end Hex;

   --  The 32-byte BLAKE2b of an H' output, in hexadecimal.
   function Digest_Of (Output : Byte_Array) return String is
      Copy : Blake2b_Bytes :=
        new Blake2b.Byte_Array (0 .. Blake2b.I64 (Output'Length) - 1);
      Digest : Blake2b.Byte_Array (0 .. 31);
   begin
      for I in Copy'Range loop
         Copy (I) := Output (Output'First + Byte_Index (I));
      end loop;
      Blake2b.Hashing.Hash (Copy.all, Blake2b.No_Bytes, Digest);
      Free (Copy);
      return Hex (Digest);
   end Digest_Of;

   procedure Check_Vector (V : H_Prime_Vectors.Vector) is
      Input : constant Blake2b.Byte_Array :=
        Make_Input (V.Input_Length, V.Seed);
      Output : Argon2_Bytes :=
        new Byte_Array (0 .. Byte_Index (V.Output_Length) - 1);
   begin
      Run_H_Prime (Input, Output.all);
      Check (Digest_Of (Output.all) = V.Digest,
             "CPython vector, input" & V.Input_Length'Image
             & " output" & V.Output_Length'Image);
      Free (Output);
   exception
      when E : others =>
         Check (False, "unexpected exception: "
                & Ada.Exceptions.Exception_Information (E));
   end Check_Vector;

   procedure Check_Reference (Input_Length, Output_Length : Natural) is
      Input : constant Blake2b.Byte_Array :=
        Make_Input (Input_Length, Input_Length + Output_Length);
      Actual : Argon2_Bytes :=
        new Byte_Array (0 .. Byte_Index (Output_Length) - 1);
      Expected : Argon2_Bytes :=
        new Byte_Array (0 .. Byte_Index (Output_Length) - 1);
      Status : Interfaces.C.int;
   begin
      Expected.all := [others => 0];
      Status := Reference
        (Output  => Expected (0)'Address,
         Out_Len => Interfaces.C.size_t (Output_Length),
         Input   => (if Input'Length = 0 then System.Null_Address
                     else Input (Input'First)'Address),
         In_Len  => Interfaces.C.size_t (Input'Length));
      Run_H_Prime (Input, Actual.all);
      Check (Status = 0 and then Actual.all = Expected.all,
             "reference, input" & Input_Length'Image
             & " output" & Output_Length'Image);
      Free (Actual);
      Free (Expected);
   exception
      when E : others =>
         Check (False, "unexpected exception: "
                & Ada.Exceptions.Exception_Information (E));
   end Check_Reference;

   type Length_List is array (Positive range <>) of Natural;
   Input_Lengths : constant Length_List := [72, 1_024];
   Output_Lengths : constant Length_List :=
     [1, 4, 31, 32, 33, 63, 64, 65, 66, 95, 96, 97, 127, 128, 129,
      1_023, 1_024, 1_025, 65_535, 65_536, 65_537, 1_048_576, 1_048_584];

   procedure Run is
   begin
      for V of H_Prime_Vectors.Vectors loop
         Check_Vector (V);
      end loop;
      --  The two real inputs against the official C, at the output
      --  lengths of the vectors (the C is the second oracle for them).
      for Input_Length of Input_Lengths loop
         for Output_Length of Output_Lengths loop
            Check_Reference (Input_Length, Output_Length);
         end loop;
      end loop;
   end Run;

end H_Prime_Tests;
