--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The task-abort experiment of scripts/check-exception-stack.sh, on the
--  shipped library (no injected line): the environment task calls
--  Argon2.Compression.Compress over and over in the abortable part of an
--  asynchronous select (the same canaries and probe as exception_stack.adb,
--  case A). Two runs per trial:
--    abort: the delay alternative (0.02 s) expires during the loop, which
--           aborts the abortable part;
--    quiet: the delay alternative (60 s) never expires: the loop ends by
--           itself and the select completes normally.
--  The loop holds no abort completion point, and ends by itself after
--  0.3 s; so if the runtime aborts only at completion points, the abort
--  run's loop runs to that bound and reports aborted=no.
--
--  Usage: abort_stack <KiB> <trials>
--  Output, per trial, run and class of canary:
--    hits case=T run=<abort|quiet> trial=<n> aborted=<yes|no> calls=<n>
--      touched=<bytes> class=<k> aligned=<n> unaligned=<n> distinct=<n>
--      depths=<list>
--  aborted=yes: the abortable part was abandoned before the loop ended;
--  calls: the calls of Compress that returned.

with Ada.Calendar;
with Ada.Command_Line;
with Ada.Text_IO;
with Interfaces; use Interfaces;
with System;

with Argon2.Blocks;
with Argon2.Compression;

with Stack_Probe; use Stack_Probe;

procedure Abort_Stack is

   use type System.Bit_Order;

   X_Seed : constant Unsigned_64 := 16#A000#;
   Y_Seed : constant Unsigned_64 := 16#B000#;

   type Blocks_Access is access Argon2.Blocks.Block_Array;
   type Block_Access is access Argon2.Blocks.Block;
   Comp_M    : Blocks_Access;
   Comp_Work : Block_Access;

   use type Ada.Calendar.Time;

   type Run_Kind is (Abort_Run, Quiet);
   type Name_Access is access constant String;
   Abort_Name : aliased constant String := "abort";
   Quiet_Name : aliased constant String := "quiet";
   Run_Names : constant array (Run_Kind) of Name_Access :=
     [Abort_Run => Abort_Name'Access, Quiet => Quiet_Name'Access];
   Triggers : constant array (Run_Kind) of Duration :=
     [Abort_Run => 0.02, Quiet => 60.0];

   Calls     : Natural := 0 with Volatile;
   Completed : Boolean := False with Volatile;
   Deadline  : Ada.Calendar.Time;
   Snap      : Word_Array_Access;

   procedure Fill
   with No_Inline;
   pragma Machine_Attribute (Fill, "noipa");

   procedure Fill is
   begin
      for K in Argon2.Blocks.Word_Index loop
         Comp_M (0) (K) := Mix (X_Seed + Unsigned_64 (K));
         Comp_M (1) (K) := Mix (Y_Seed + Unsigned_64 (K));
         Comp_M (2) (K) := 0;
         Comp_Work (K) := 0;
      end loop;
      Calls := 0;
      Completed := False;
      Deadline := Ada.Calendar.Clock + 0.3;
   end Fill;

   procedure Spin
   with No_Inline;
   pragma Machine_Attribute (Spin, "noipa");

   procedure Spin is
   begin
      loop
         Argon2.Compression.Compress (Comp_M.all, 0, 1, 2, Comp_Work.all);
         Calls := Calls + 1;
         exit when Calls mod 1024 = 0 and then Ada.Calendar.Clock > Deadline;
      end loop;
   end Spin;

   procedure Call (Trigger : Duration)
   with No_Inline;
   pragma Machine_Attribute (Call, "noipa");

   procedure Call (Trigger : Duration) is
   begin
      select
         delay Trigger;
      then abort
         Spin;
         Completed := True;
      end select;
   end Call;

   procedure Helper (Trigger : Duration)
   with No_Inline;
   pragma Machine_Attribute (Helper, "noipa");

   procedure Helper (Trigger : Duration) is
   begin
      Fill;
      Region (False, Snap);
      Call (Trigger);
      Region (True, Snap);
   end Helper;

   function Img (N : Natural) return String is
      S : constant String := Natural'Image (N);
   begin
      return S (S'First + 1 .. S'Last);
   end Img;

   KiB    : Positive;
   Trials : Positive;
begin
   if System.Default_Bit_Order /= System.Low_Order_First then
      Ada.Text_IO.Put_Line ("error: big-endian target: not supported");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;
   if Ada.Command_Line.Argument_Count /= 2 then
      Ada.Text_IO.Put_Line ("usage: abort_stack <KiB> <trials>");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;
   KiB := Positive'Value (Ada.Command_Line.Argument (1));
   Trials := Positive'Value (Ada.Command_Line.Argument (2));
   Snap := new Word_Array (0 .. 128 * KiB - 1);
   Comp_M := new Argon2.Blocks.Block_Array (0 .. 2);
   Comp_Work := new Argon2.Blocks.Block;

   for Trial in 1 .. Trials loop
      for Run in Run_Kind loop
         Helper (Triggers (Run));
         declare
            X, Y, XY : Word_Array (0 .. 127);
            Prefix : constant String :=
              "hits case=T run=" & Run_Names (Run).all
              & " trial=" & Img (Trial)
              & " aborted=" & (if Completed then "no" else "yes")
              & " calls=" & Img (Calls);
         begin
            for K in X'Range loop
               X (K) := Mix (X_Seed + Unsigned_64 (K));
               Y (K) := Mix (Y_Seed + Unsigned_64 (K));
               XY (K) := X (K) xor Y (K);
            end loop;
            Put_Hits (Prefix, Snap.all, "X", X);
            Put_Hits (Prefix, Snap.all, "Y", Y);
            Put_Hits (Prefix, Snap.all, "XY", XY);
         end;
      end loop;
   end loop;
end Abort_Stack;
