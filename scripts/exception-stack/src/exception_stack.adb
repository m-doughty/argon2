--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The measurement driver of scripts/check-exception-stack.sh, built
--  against a copy of the library: with one injected raise, with an
--  injected spill (case A'), or unmodified (see the script).
--
--  Usage: exception_stack <KiB> <spacer KiB> <case> <raise|normal>
--    case A: Argon2.Compression.Compress; raises when Z = 2;
--    case B: Argon2.H_Prime.Hash; raises when Input'First = 1;
--    case C: Argon2.H_Prime.Hash; BLAKE2b's compression raises when its
--            byte counter T_Lo = 1024.
--  Mode raise (a build with the injected raise): three runs, baseline (no
--  call), raise (the injected raise fires) and normal (the same call
--  returns normally; for C, on a 1023-byte message, whose last block does
--  not fire it). Mode normal (a build without an injected raise): two
--  runs, baseline and normal, where C's normal run hashes the 1024-byte
--  message of its raise run (in this build nothing fires). For each run,
--  it clears KiB KiB of stack below one helper frame, calls the hardened
--  function from that frame, copies the same region and counts the canary
--  words in it. The
--  call goes through Call, which holds the handler for the injected
--  Program_Error, and Inner, whose frame holds an unused spacer of
--  <spacer KiB> KiB: the handler's own calls (the run-time's handler entry
--  and exit) run just below Call's frame, inside the spacer, and so do
--  not overwrite what the hardened call and the exception's propagation
--  left below it. All the inputs and outputs of the call are on the
--  heap, so the driver's own frames never hold a canary.
--  Output, one line per run and class of canary (see Stack_Probe.Put_Hits):
--    hits case=<c> run=<r> raised=<yes|no> touched=<bytes> class=<k>
--      aligned=<n> unaligned=<n> distinct=<n> depths=<list>
--  The classes: for A, X, Y and XY (word K of M (X), of M (Y) and of their
--  xor) and P (word K of the permutation of X xor Y, which the injected
--  raise follows and the first 32 words of which case A' spills; computed
--  by Blamka_Reference, checked against the library's output after the
--  normal run); for B and C, M (message word
--  J, 1 .. 126, as BLAKE2b loads it) and I (input word J, 0 .. 125: input
--  bytes 8 J .. 8 J + 7).

with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with System;

with Argon2;
with Argon2.Blocks;
with Argon2.Compression;
with Argon2.H_Prime;
with Blake2b;
with Blake2b.Hashing;

with Blamka_Reference;
with Stack_Probe; use Stack_Probe;

procedure Exception_Stack is

   use type System.Bit_Order;
   use type Blake2b.I64;

   type Case_Kind is (A, B, C);
   type Run_Kind is (Baseline, Raise_Run, Normal);
   type Name_Access is access constant String;
   Baseline_Name : aliased constant String := "baseline";
   Raise_Name    : aliased constant String := "raise";
   Normal_Name   : aliased constant String := "normal";
   Run_Names : constant array (Run_Kind) of Name_Access :=
     [Baseline  => Baseline_Name'Access,
      Raise_Run => Raise_Name'Access,
      Normal    => Normal_Name'Access];
   Case_Names : constant array (Case_Kind) of Character :=
     [A => 'A', B => 'B', C => 'C'];

   --  Canary seeds: one block of seeds per class, far apart.
   X_Seed : constant Unsigned_64 := 16#A000#;
   Y_Seed : constant Unsigned_64 := 16#B000#;
   M_Seed : constant Unsigned_64 := 16#C000#;

   --  Compression: M (0) = X, M (1) = Y; Z = 2 raises, Z = 3 does not.
   type Blocks_Access is access Argon2.Blocks.Block_Array;
   type Block_Access is access Argon2.Blocks.Block;
   Comp_M    : Blocks_Access;
   Comp_Work : Block_Access;

   --  H': the message BLAKE2b absorbs is LE32 (T) || Input; T = 100, so
   --  the chained form runs. Message word J (bytes 8 J .. 8 J + 7) is
   --  Mix (M_Seed + J) for J >= 1. The raise run of case B has Input'First
   --  = 1 and 1020 bytes; of case C, Input'First = 0 and 1020 bytes (the
   --  message is 1024 bytes, so BLAKE2b's last compression has T_Lo = 1024);
   --  the normal run has Input'First = 0 and 1019 bytes, except C's in mode
   --  normal, which has the 1020 bytes of C's raise run. Message words 1 ..
   --  126 are the same in all of them.
   Digest_Bytes : constant := 100;
   Words_Counted : constant := 126;
   type Input_Access is access Blake2b.Byte_Array;
   type Digest_Access is access Argon2.Byte_Array;
   type State_Access is access Blake2b.Hashing.State;
   type Chain_Access is access Argon2.H_Prime.Chain;
   HP_Input  : Input_Access;
   HP_Digest : Digest_Access;
   HP_State  : State_Access;
   HP_V      : Chain_Access;
   HP_Next_V : Chain_Access;

   procedure Free is new Ada.Unchecked_Deallocation
     (Blake2b.Byte_Array, Input_Access);

   Snap : Word_Array_Access;

   --  Mode normal: no raise run.
   Normal_Only : Boolean := False;

   --  Byte P of the H' message (P >= 4: the bytes after LE32 (T)).
   function Message_Byte (P : Natural) return Unsigned_8 is
     (Unsigned_8
        (Shift_Right (Mix (M_Seed + Unsigned_64 (P / 8)), 8 * (P mod 8))
         and 16#FF#));

   procedure Fill (Which : Case_Kind; Run : Run_Kind)
   with No_Inline;
   pragma Machine_Attribute (Fill, "noipa");

   procedure Fill (Which : Case_Kind; Run : Run_Kind) is
      First : Blake2b.I64 := 0;
      Bytes : Blake2b.I64 := 1019;
   begin
      case Which is
         when A =>
            for K in Argon2.Blocks.Word_Index loop
               Comp_M (0) (K) := Mix (X_Seed + Unsigned_64 (K));
               Comp_M (1) (K) := Mix (Y_Seed + Unsigned_64 (K));
               Comp_M (2) (K) := 0;
               Comp_M (3) (K) := 0;
               Comp_Work (K) := 0;
            end loop;
         when B | C =>
            if Run = Raise_Run then
               Bytes := 1020;
               if Which = B then
                  First := 1;
               end if;
            elsif Which = C and then Normal_Only then
               Bytes := 1020;
            end if;
            if HP_Input /= null then
               Free (HP_Input);
            end if;
            HP_Input := new Blake2b.Byte_Array (First .. First + Bytes - 1);
            for I in HP_Input'Range loop
               HP_Input (I) := Message_Byte (4 + Natural (I - First));
            end loop;
            HP_Digest.all := [others => 0];
            HP_V.all := [others => 0];
            HP_Next_V.all := [others => 0];
      end case;
   end Fill;

   type Volatile_Words is array (Natural range <>) of Unsigned_64
   with Volatile_Components;

   Spacer_Words : Natural := 0;

   --  The hardened call, below a spacer of Spacer_Words words.
   procedure Inner (Which : Case_Kind; Run : Run_Kind)
   with No_Inline;
   pragma Machine_Attribute (Inner, "noipa");

   procedure Inner (Which : Case_Kind; Run : Run_Kind) is
      Spacer : Volatile_Words (0 .. Spacer_Words);
      pragma Warnings
        (Off, Spacer, Reason => "written only so that it is allocated");
   begin
      --  One volatile store, so that the spacer is allocated; it writes
      --  the zero the scrub left there.
      Spacer (Spacer'First) := 0;
      case Which is
         when A =>
            Argon2.Compression.Compress
              (Comp_M.all, 0, 1, (if Run = Raise_Run then 2 else 3),
               Comp_Work.all);
         when B | C =>
            Argon2.H_Prime.Hash
              (HP_Input.all, HP_Digest.all, HP_State.all, HP_V.all,
               HP_Next_V.all);
      end case;
   end Inner;

   --  The handler for the injected exception.
   procedure Call (Which : Case_Kind; Run : Run_Kind; Raised : out Boolean)
   with No_Inline;
   pragma Machine_Attribute (Call, "noipa");

   procedure Call (Which : Case_Kind; Run : Run_Kind; Raised : out Boolean)
   is
   begin
      Raised := False;
      Inner (Which, Run);
   exception
      when Program_Error =>
         Raised := True;
   end Call;

   --  The helper frame: the scrub, the call and the snapshot are all made
   --  from it, so they reach the same stack addresses.
   procedure Helper (Which : Case_Kind; Run : Run_Kind; Raised : out Boolean)
   with No_Inline;
   pragma Machine_Attribute (Helper, "noipa");

   procedure Helper (Which : Case_Kind; Run : Run_Kind; Raised : out Boolean)
   is
   begin
      Raised := False;
      Fill (Which, Run);
      Region (False, Snap);
      if Run /= Baseline then
         Call (Which, Run, Raised);
      end if;
      Region (True, Snap);
   end Helper;

   procedure Report
     (Which : Case_Kind; Run : Run_Kind; Raised : Boolean;
      Name : String; Class : Word_Array) is
   begin
      Put_Hits
        ("hits case=" & Case_Names (Which) & " run=" & Run_Names (Run).all
         & " raised=" & (if Raised then "yes" else "no"),
         Snap.all, Name, Class);
   end Report;

   Which  : Case_Kind;
   KiB    : Positive;
   Raised : Boolean;
begin
   if System.Default_Bit_Order /= System.Low_Order_First then
      Ada.Text_IO.Put_Line ("error: big-endian target: not supported");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;
   if Ada.Command_Line.Argument_Count /= 4
     or else (Ada.Command_Line.Argument (4) /= "raise"
              and then Ada.Command_Line.Argument (4) /= "normal")
   then
      Ada.Text_IO.Put_Line
        ("usage: exception_stack <KiB> <spacer KiB> <A|B|C> <raise|normal>");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;
   KiB := Positive'Value (Ada.Command_Line.Argument (1));
   Spacer_Words := 128 * Natural'Value (Ada.Command_Line.Argument (2));
   Which := Case_Kind'Value (Ada.Command_Line.Argument (3));
   Normal_Only := Ada.Command_Line.Argument (4) = "normal";
   Snap := new Word_Array (0 .. 128 * KiB - 1);

   Comp_M := new Argon2.Blocks.Block_Array (0 .. 3);
   Comp_Work := new Argon2.Blocks.Block;
   HP_Digest := new Argon2.Byte_Array (0 .. Digest_Bytes - 1);
   HP_State := new Blake2b.Hashing.State;
   HP_V := new Argon2.H_Prime.Chain;
   HP_Next_V := new Argon2.H_Prime.Chain;

   for Run in Run_Kind loop
      if Run = Raise_Run and then Normal_Only then
         goto Next_Run;
      end if;
      Helper (Which, Run, Raised);
      case Which is
         when A =>
            declare
               X, Y, XY : Word_Array (0 .. 127);
            begin
               for K in X'Range loop
                  X (K) := Mix (X_Seed + Unsigned_64 (K));
                  Y (K) := Mix (Y_Seed + Unsigned_64 (K));
                  XY (K) := X (K) xor Y (K);
               end loop;
               declare
                  P : constant Word_Array := Blamka_Reference.Permute (XY);
               begin
                  --  The reference must agree with the library: after the
                  --  normal run M (3) = G (X, Y) = P xor X xor Y.
                  if Run = Normal then
                     for K in P'Range loop
                        if Comp_M (3) (K) /= (P (K) xor XY (K)) then
                           Ada.Text_IO.Put_Line
                             ("error: the reference permutation disagrees"
                              & " with Argon2.Compression");
                           Ada.Command_Line.Set_Exit_Status
                             (Ada.Command_Line.Failure);
                           return;
                        end if;
                     end loop;
                  end if;
                  Report (Which, Run, Raised, "X", X);
                  Report (Which, Run, Raised, "Y", Y);
                  Report (Which, Run, Raised, "XY", XY);
                  Report (Which, Run, Raised, "P", P);
               end;
            end;
         when B | C =>
            declare
               --  M (J): message word J (message bytes 8 J .. 8 J + 7), as
               --  BLAKE2b loads it; I (J): input word J (input bytes 8 J ..
               --  8 J + 7, message bytes 8 J + 4 .. 8 J + 11).
               M : Word_Array (1 .. Words_Counted);
               I : Word_Array (0 .. Words_Counted - 1);
            begin
               for J in M'Range loop
                  M (J) := Mix (M_Seed + Unsigned_64 (J));
               end loop;
               for J in I'Range loop
                  I (J) := 0;
                  for Bt in 0 .. 7 loop
                     I (J) := I (J)
                       or Shift_Left
                            (Unsigned_64 (Message_Byte (8 * J + 4 + Bt)),
                             8 * Bt);
                  end loop;
               end loop;
               Report (Which, Run, Raised, "M", M);
               Report (Which, Run, Raised, "I", I);
            end;
      end case;
      <<Next_Run>>
   end loop;
end Exception_Stack;
