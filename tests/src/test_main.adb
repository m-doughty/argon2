--  H-prime comparisons against the official Argon2 C reference, and the
--  H0 tests (H0_Tests).
--
--  Usage: test_main          the default run
--         test_main --long   only the long H0 test (2**34 + 36 bytes,
--                            4 GiB of memory; not in the default run)
--
--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Assertions;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;
with Interfaces.C;
with System;

with Argon2id; use Argon2id;
with Argon2id.H_Prime;
with H0_Tests;

procedure Test_Main is
   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_32;
   use type Interfaces.C.int;

   pragma Compile_Time_Error
     (Byte_Index'Last - Byte_Index'First + 1 /= 2 ** 32 - 1,
      "byte arrays must support the full uint32 length domain");

   function Reference
     (Output  : System.Address;
      Out_Len : Interfaces.C.size_t;
      Input   : System.Address;
      In_Len  : Interfaces.C.size_t) return Interfaces.C.int
   with Import, Convention => C, External_Name => "blake2b_long";

   type Length_List is array (Positive range <>) of Natural;
   Input_Lengths : constant Length_List :=
     [0, 1, 127, 128, 129, 4_095, 4_096, 4_097, 8_193];
   Output_Lengths : constant Length_List :=
     [1, 4, 31, 32, 33, 63, 64, 65, 66, 95, 96, 97,
      127, 128, 129, 1_023, 1_024, 1_025];

   Passed : Natural := 0;
   Failed : Natural := 0;
   Seed   : Interfaces.Unsigned_32 := 16#C0FFEE#;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if Condition then
         Passed := Passed + 1;
      else
         Failed := Failed + 1;
         Put_Line ("FAIL: " & Label_Text);
      end if;
   end Check;

   function Next_Random return Interfaces.Unsigned_32 is
   begin
      Seed := Seed * 1_664_525 + 1_013_904_223;
      return Seed;
   end Next_Random;

   procedure Reference_Hash (Input : Byte_Array; Digest : out Byte_Array) is
      Status : Interfaces.C.int;
   begin
      Digest := [others => 0];
      Status := Reference
        (Output  => Digest (Digest'First)'Address,
         Out_Len => Interfaces.C.size_t (Digest'Length),
         Input   => (if Input'Length = 0 then System.Null_Address
                     else Input (Input'First)'Address),
         In_Len  => Interfaces.C.size_t (Input'Length));
      if Status /= 0 then
         raise Program_Error with "reference returned" & Status'Image;
      end if;
   end Reference_Hash;

   procedure Compare
     (Input_Length  : Natural;
      Output_Length : Positive;
      Input_First   : Byte_Index;
      Output_First  : Byte_Index)
   is
      Input : Byte_Array
        (Input_First .. Input_First + Byte_Index (Input_Length) - 1);
      Actual : Byte_Array
        (Output_First .. Output_First + Byte_Index (Output_Length) - 1) :=
          [others => 16#A5#];
      Expected : Byte_Array (0 .. Byte_Index (Output_Length) - 1);
   begin
      for I in Input'Range loop
         Input (I) := Byte (Next_Random / 2 ** 24);
      end loop;
      Reference_Hash (Input, Expected);
      Argon2id.H_Prime.Hash (Input, Actual);
      Check
        (Actual = Expected,
         "input" & Input_Length'Image & " output" & Output_Length'Image &
         " input first" & Input_First'Image &
         " output first" & Output_First'Image);
   exception
      when E : others =>
         Check (False, "unexpected exception: " &
                Ada.Exceptions.Exception_Information (E));
   end Compare;

   procedure Chunk_Order is
      Input : Byte_Array (0 .. 8_192);
      Actual : Byte_Array (0 .. 1_023);
      Expected : Byte_Array (0 .. 1_023);
   begin
      for I in Input'Range loop
         Input (I) := (if I < 4_096 then 16#11#
                       elsif I < 8_192 then 16#A3# else 16#5B#);
      end loop;
      Reference_Hash (Input, Expected);
      Argon2id.H_Prime.Hash (Input, Actual);
      Check (Actual = Expected, "distinct chunks preserve order and tail");
   end Chunk_Order;

   procedure Empty_Output_Rejected is
      Input : constant Byte_Array := [1, 2, 3];
      Empty : Byte_Array (Byte_Index'Last .. Byte_Index'Last - 1);
   begin
      Argon2id.H_Prime.Hash (Input, Empty);
      Check (False, "empty output must reject the precondition");
   exception
      when Ada.Assertions.Assertion_Error =>
         Check (True, "empty output rejected");
      when E : others =>
         Check (False, "wrong empty-output exception: " &
                Ada.Exceptions.Exception_Information (E));
   end Empty_Output_Rejected;

   procedure Output_Guards is
      Input : constant Byte_Array (17 .. 19) := [1, 2, 3];
      Buffer : Byte_Array (0 .. 1_025) := [others => 16#A5#];
      Expected : Byte_Array (0 .. 1_023);
   begin
      Reference_Hash (Input, Expected);
      Argon2id.H_Prime.Hash (Input, Buffer (1 .. 1_024));
      Check (Buffer (1 .. 1_024) = Expected, "output slice matches reference");
      Check (Buffer (0) = 16#A5# and then Buffer (1_025) = 16#A5#,
             "output slice preserves both guard bytes");
   end Output_Guards;

begin
   if Ada.Command_Line.Argument_Count > 0 then
      if Ada.Command_Line.Argument_Count = 1
        and then Ada.Command_Line.Argument (1) = "--long"
      then
         H0_Tests.Run_Long;
         Put_Line (H0_Tests.Passed'Image & " passed,"
                   & H0_Tests.Failed'Image & " failed");
         Ada.Command_Line.Set_Exit_Status
           (if H0_Tests.Failed = 0 then Ada.Command_Line.Success
            else Ada.Command_Line.Failure);
      else
         Put_Line ("usage: test_main [--long]");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      end if;
      return;
   end if;

   for Input_Length of Input_Lengths loop
      for Output_Length of Output_Lengths loop
         Compare (Input_Length, Output_Length, 0, 0);
         Compare (Input_Length, Output_Length, 17, 23);
         Compare
           (Input_Length, Output_Length,
            (if Input_Length = 0 then Byte_Index'Last
             else Byte_Index'Last - Byte_Index (Input_Length) + 1),
            Byte_Index'Last - Byte_Index (Output_Length) + 1);
      end loop;
   end loop;

   --  Null input at the highest legal lower bound.
   Compare (0, 65, Byte_Index'Last, Byte_Index'Last - 64);
   for I in 1 .. 200 loop
      declare
         Input_Length : constant Natural :=
           Natural (Next_Random mod 9_001);
         Output_Length : constant Positive :=
           Positive (Next_Random mod 1_100 + 1);
      begin
         Compare (Input_Length, Output_Length, 37, 41);
      end;
   end loop;

   Chunk_Order;
   Empty_Output_Rejected;
   Output_Guards;
   H0_Tests.Run;
   Passed := Passed + H0_Tests.Passed;
   Failed := Failed + H0_Tests.Failed;
   Put_Line (Passed'Image & " passed," & Failed'Image & " failed");
   Ada.Command_Line.Set_Exit_Status
     (if Failed = 0 then Ada.Command_Line.Success
      else Ada.Command_Line.Failure);
end Test_Main;
