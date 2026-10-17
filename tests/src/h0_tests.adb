--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Assertions;
with Ada.Exceptions;
with Ada.Real_Time;
with Ada.Text_IO; use Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with Interfaces.C;
with System;

with Blake2b;
with Blake2b.Hashing;
with Argon2; use Argon2;
with Argon2_Config;
with Argon2.H0;
with H0_Vectors;

package body H0_Tests is

   use type Interfaces.C.int;
   use type Blake2b.Byte_Array;

   subtype U32 is Unsigned_32;
   subtype Digest_64 is Blake2b.Byte_Array (0 .. 63);

   --  p, T, m, t, v, y, in the order RFC 9106 hashes them.
   type Parameters is array (0 .. 5) of U32 with Convention => C;

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;
   Seed       : U32 := 16#5EED_0042#;

   function Passed return Natural is (Pass_Count);
   function Failed return Natural is (Fail_Count);

   --  Preconditions are checked only when contracts are on (not in the
   --  release profile); tests of their rejection need that.
   Contracts_On : constant Boolean :=
     Argon2_Config.Build_Profile not in Argon2_Config.release;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if Condition then
         Pass_Count := Pass_Count + 1;
      else
         Fail_Count := Fail_Count + 1;
         Put_Line ("FAIL: H0: " & Label_Text);
      end if;
   end Check;

   function Next_Random return U32 is
   begin
      Seed := Seed * 1_664_525 + 1_013_904_223;
      return Seed;
   end Next_Random;

   ----------------------------------------------------------------------
   --  Oracles
   ----------------------------------------------------------------------

   function C_H0
     (Params : Parameters;
      P      : System.Address; P_Length : Unsigned_64;
      S      : System.Address; S_Length : Unsigned_64;
      K      : System.Address; K_Length : Unsigned_64;
      X      : System.Address; X_Length : Unsigned_64;
      Digest : System.Address) return Interfaces.C.int
   with Import, Convention => C, External_Name => "h0_oracle";

   --  Per input (P, S, K, X): its generator seed, and its length.
   type Quad is array (0 .. 3) of Unsigned_64 with Convention => C;

   function C_H0_Generated
     (Params  : Parameters;
      Seeds   : Quad;
      Lengths : Quad;
      Digest  : System.Address) return Interfaces.C.int
   with Import, Convention => C, External_Name => "h0_oracle_generated";

   function C_Blake2b_512
     (Message : System.Address;
      Length  : Unsigned_64;
      Digest  : System.Address) return Interfaces.C.int
   with Import, Convention => C, External_Name => "blake2b_512";

   function Address_Of (A : Byte_Array) return System.Address is
     (if A'Length = 0 then System.Null_Address
      else A (A'First)'Address);

   --  The C oracle's H0, serialised in C.
   function Oracle_H0 (Params : Parameters; P, S, K, X : Byte_Array)
      return Digest_64
   is
      Digest : Digest_64 := [others => 0];
   begin
      if C_H0 (Params,
               Address_Of (P), Unsigned_64 (P'Length),
               Address_Of (S), Unsigned_64 (S'Length),
               Address_Of (K), Unsigned_64 (K'Length),
               Address_Of (X), Unsigned_64 (X'Length),
               Digest (0)'Address) /= 0
      then
         raise Program_Error with "h0_oracle failed";
      end if;
      return Digest;
   end Oracle_H0;

   function LE32 (Value : U32) return Byte_Array is
     ([Byte (Value and 16#FF#), Byte (Shift_Right (Value, 8) and 16#FF#),
       Byte (Shift_Right (Value, 16) and 16#FF#),
       Byte (Shift_Right (Value, 24))]);

   --  RFC 9106's H0 input, written out here as one array.
   function Serialise (Params : Parameters; P, S, K, X : Byte_Array)
      return Byte_Array
   is
     (LE32 (Params (0)) & LE32 (Params (1)) & LE32 (Params (2))
      & LE32 (Params (3)) & LE32 (Params (4)) & LE32 (Params (5))
      & LE32 (U32 (P'Length)) & P & LE32 (U32 (S'Length)) & S
      & LE32 (U32 (K'Length)) & K & LE32 (U32 (X'Length)) & X);

   --  The C reference BLAKE2b-512 of the serialisation built here.
   function Oracle_Serialised
     (Params : Parameters; P, S, K, X : Byte_Array) return Digest_64
   is
      Message : constant Byte_Array := Serialise (Params, P, S, K, X);
      Digest  : Digest_64 := [others => 0];
   begin
      if C_Blake2b_512
           (Address_Of (Message), Unsigned_64 (Message'Length),
            Digest (0)'Address) /= 0
      then
         raise Program_Error with "blake2b failed";
      end if;
      return Digest;
   end Oracle_Serialised;

   --  H0 with its scratch (the hash state) supplied here, as a caller of
   --  the library would.
   procedure Compute_With_Scratch
     (Password, Salt, Secret, Associated_Data : Byte_Array;
      Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      Digest : out Blake2b.Byte_Array)
   is
      Hash_State : Blake2b.Hashing.State;
   begin
      Argon2.H0.Compute
        (Password => Password, Salt => Salt, Secret => Secret,
         Associated_Data => Associated_Data, Parallelism => Parallelism,
         Tag_Length => Tag_Length, Memory => Memory, Passes => Passes,
         Version => Version, Kind => Kind, Digest => Digest,
         Hash_State => Hash_State);
   end Compute_With_Scratch;

   function Implementation (Params : Parameters; P, S, K, X : Byte_Array)
      return Digest_64
   is
      Digest : Digest_64 := [others => 16#A5#];
   begin
      Compute_With_Scratch
        (Password        => P,
         Salt            => S,
         Secret          => K,
         Associated_Data => X,
         Parallelism     => Params (0),
         Tag_Length      => Params (1),
         Memory          => Params (2),
         Passes          => Params (3),
         Version         => Params (4),
         Kind            => Params (5),
         Digest          => Digest);
      return Digest;
   end Implementation;

   Hex_Digits : constant String := "0123456789abcdef";

   function To_Hex (Data : Blake2b.Byte_Array) return String is
      Result : String (1 .. 2 * Data'Length);
      Next   : Positive := 1;
   begin
      for B of Data loop
         Result (Next) := Hex_Digits (Natural (B / 16) + 1);
         Result (Next + 1) := Hex_Digits (Natural (B mod 16) + 1);
         Next := Next + 2;
      end loop;
      return Result;
   end To_Hex;

   function Image (Params : Parameters) return String is
     (" p=" & Params (0)'Image & " T=" & Params (1)'Image
      & " m=" & Params (2)'Image & " t=" & Params (3)'Image
      & " v=" & Params (4)'Image & " y=" & Params (5)'Image);

   --  Compute against both C oracles.
   procedure Compare
     (Params : Parameters; P, S, K, X : Byte_Array; Label_Text : String)
   is
      Got : constant Digest_64 := Implementation (Params, P, S, K, X);
   begin
      Check (Got = Oracle_H0 (Params, P, S, K, X),
             Label_Text & ": against the C serialisation");
      Check (Got = Oracle_Serialised (Params, P, S, K, X),
             Label_Text & ": against BLAKE2b of the explicit bytes");
   exception
      when E : others =>
         Check (False, Label_Text & ": unexpected exception: "
                & Ada.Exceptions.Exception_Information (E));
   end Compare;

   --  An array of Length bytes from First (or from Byte_Index'Last when
   --  First_At_End), filled from the generator.
   function Random_Input (Length : Natural; First_At_End : Boolean)
      return Byte_Array
   is
      First : constant Byte_Index :=
        (if not First_At_End then 0
         elsif Length = 0 then Byte_Index'Last
         else Byte_Index'Last - Byte_Index (Length) + 1);
   begin
      return Result : Byte_Array
        (First .. First + Byte_Index (Length) - 1)
      do
         for I in Result'Range loop
            Result (I) := Byte (Next_Random / 2**24);
         end loop;
      end return;
   end Random_Input;

   ----------------------------------------------------------------------
   --  RFC 9106 section 5's pre-hashing digests
   ----------------------------------------------------------------------

   procedure RFC_Vectors is
      Password : constant Byte_Array (0 .. 31) := [others => 16#01#];
      Salt     : constant Byte_Array (0 .. 15) := [others => 16#02#];
      Secret   : constant Byte_Array (0 .. 7) := [others => 16#03#];
      Data     : constant Byte_Array (0 .. 11) := [others => 16#04#];
      --  y = 0 (Argon2d, section 5.1), 1 (Argon2i, 5.2), 2 (Argon2id,
      --  5.3); m = 32 KiB, t = 3, p = 4, T = 32, v = 0x13.
      Expected : constant array (U32 range 0 .. 2) of String (1 .. 128) :=
        ["b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757"
         & "082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109",
         "c46065815276a0b3e731731c902f1fd80cf776907fbb7b6a5ca72e7b56011fee"
         & "ca446c86dd75b9469a5e6879dec4b72d0863fb939b982e5f397cc7d164fddaa9",
         "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8"
         & "546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997"];
   begin
      for Kind in Expected'Range loop
         declare
            Params : constant Parameters := [4, 32, 32, 3, 16#13#, Kind];
            Got    : constant Digest_64 :=
              Implementation (Params, Password, Salt, Secret, Data);
         begin
            Check (To_Hex (Got) = Expected (Kind),
                   "RFC 9106 pre-hashing digest, y =" & Kind'Image
                   & ": got " & To_Hex (Got));
         end;
      end loop;
   end RFC_Vectors;

   ----------------------------------------------------------------------
   --  CPython's digests (scripts/h0-vectors.py)
   ----------------------------------------------------------------------

   function Vector_Input (Seed, Index, Length : Natural) return Byte_Array
   is
   begin
      return Result : Byte_Array (0 .. Byte_Index (Length) - 1) do
         for J in Result'Range loop
            Result (J) := Byte
              ((Byte_Index (Seed) * 37 + Byte_Index (Index) * 101 + J * 13
                + (J / 512) * 7) mod 256);
         end loop;
      end return;
   end Vector_Input;

   procedure CPython_Vectors is
   begin
      for N in H0_Vectors.Vectors'Range loop
         declare
            V      : H0_Vectors.Vector renames H0_Vectors.Vectors (N);
            Params : constant Parameters :=
              [V.Parallelism, V.Tag_Length, V.Memory, V.Passes, V.Version,
               V.Kind];
            P : constant Byte_Array :=
              Vector_Input (V.Seed, 0, V.Password_Length);
            S : constant Byte_Array :=
              Vector_Input (V.Seed, 1, V.Salt_Length);
            K : constant Byte_Array :=
              Vector_Input (V.Seed, 2, V.Secret_Length);
            X : constant Byte_Array :=
              Vector_Input (V.Seed, 3, V.Data_Length);
            Got : constant Digest_64 := Implementation (Params, P, S, K, X);
         begin
            Check (To_Hex (Got) = V.Digest,
                   "CPython vector" & N'Image & ": got " & To_Hex (Got));
            Check (Got = Oracle_H0 (Params, P, S, K, X),
                   "CPython vector" & N'Image
                   & ": against the C serialisation");
            Check (Got = Oracle_Serialised (Params, P, S, K, X),
                   "CPython vector" & N'Image
                   & ": against BLAKE2b of the explicit bytes");
         end;
      end loop;
   end CPython_Vectors;

   ----------------------------------------------------------------------
   --  Differential tests
   ----------------------------------------------------------------------

   type Length_List is array (Positive range <>) of Natural;
   Boundary_Lengths : constant Length_List :=
     [0, 1, 3, 4, 5, 63, 64, 127, 128, 129, 4_095, 4_096, 4_097, 8_191,
      8_192, 8_193, 12_289];

   function Random_Parameters return Parameters is
     [Next_Random, Next_Random, Next_Random, Next_Random, Next_Random,
      Next_Random];

   --  Each input in turn at each boundary length, the others short, with
   --  the arrays at index 0 and at the top of the index range.
   procedure Boundaries is
   begin
      for Which in 0 .. 3 loop
         for Length of Boundary_Lengths loop
            for At_End in Boolean loop
               declare
                  function Len (I : Natural) return Natural is
                    (if I = Which then Length
                     else Natural (Next_Random mod 41));
                  Params : constant Parameters := Random_Parameters;
                  P : constant Byte_Array := Random_Input (Len (0), At_End);
                  S : constant Byte_Array := Random_Input (Len (1), At_End);
                  K : constant Byte_Array := Random_Input (Len (2), At_End);
                  X : constant Byte_Array := Random_Input (Len (3), At_End);
               begin
                  Compare (Params, P, S, K, X,
                           "input" & Which'Image & " of" & Length'Image
                           & " bytes, at end " & At_End'Image
                           & Image (Params));
               end;
            end loop;
         end loop;
      end loop;
   end Boundaries;

   --  Random lengths, parameters and bounds.
   procedure Random_Cases is
   begin
      for N in 1 .. 200 loop
         declare
            function Len return Natural is
              (Natural (Next_Random mod 9_001));
            Params : constant Parameters := Random_Parameters;
            P : constant Byte_Array := Random_Input (Len, N mod 2 = 0);
            S : constant Byte_Array := Random_Input (Len, N mod 3 = 0);
            K : constant Byte_Array := Random_Input (Len, N mod 5 = 0);
            X : constant Byte_Array := Random_Input (Len, N mod 7 = 0);
         begin
            Compare (Params, P, S, K, X,
                     "random case" & N'Image & Image (Params));
         end;
      end loop;
   end Random_Cases;

   procedure Edge_Cases is
      Empty_Low  : constant Byte_Array (0 .. -1) := [others => 0];
      Empty_High : constant Byte_Array
        (Byte_Index'Last .. Byte_Index'Last - 1) := [others => 0];
      One        : constant Byte_Array (17 .. 17) := [16#5A#];
      Top        : constant Byte_Array (Byte_Index'Last .. Byte_Index'Last) :=
        [16#C3#];
      Typical    : constant Parameters := [1, 32, 64, 3, 16#13#, 2];
   begin
      Compare (Typical, Empty_Low, Empty_Low, Empty_Low, Empty_Low,
               "every input empty");
      Compare (Typical, Empty_High, Empty_High, Empty_High, Empty_High,
               "every input empty, bounds at the top of the range");
      Compare (Typical, One, One, One, One, "every input one byte");
      Compare (Typical, Top, Empty_Low, Top, Empty_High,
               "one-byte inputs at the last index, empty ones between");
      Compare ([0, 0, 0, 0, 0, 0], Empty_Low, Empty_Low, Empty_Low,
               Empty_Low, "every field zero, every input empty");
      Compare ([U32'Last, U32'Last, U32'Last, U32'Last, U32'Last, U32'Last],
               One, Empty_Low, One, Empty_Low, "every field 2**32 - 1");
      --  m = 37, p = 3: the rounded m' (36) must not be hashed.
      Compare ([3, 32, 37, 3, 16#13#, 2], One, One, One, One,
               "m not a multiple of 4p");
      --  Each field's bytes distinct, so a swapped field or byte shows.
      Compare ([16#0302_0100#, 16#0706_0504#, 16#0B0A_0908#, 16#0F0E_0D0C#,
                16#1312_1110#, 16#1716_1514#],
               One, Top, Empty_Low, One, "distinct field bytes");
   end Edge_Cases;

   --  Inputs of 1 MiB and more: hundreds of chunks each.
   procedure Many_Chunks is
      type Bytes_Access is access Byte_Array;
      procedure Free is
        new Ada.Unchecked_Deallocation (Byte_Array, Bytes_Access);
      P : Bytes_Access := new Byte_Array (0 .. 2**20 + 2);
      S : Bytes_Access := new Byte_Array (5 .. 2**20 + 4_100);
      K : Bytes_Access := new Byte_Array (0 .. 2**18 - 1);
      X : Bytes_Access := new Byte_Array (0 .. 2**20 * 3 - 1);
      procedure Fill (A : out Byte_Array) is
      begin
         for I in A'Range loop
            A (I) := Byte (Next_Random / 2**24);
         end loop;
      end Fill;
   begin
      Fill (P.all);
      Fill (S.all);
      Fill (K.all);
      Fill (X.all);
      Compare ([4, 64, 65_536, 2, 16#13#, 2], P.all, S.all, K.all, X.all,
               "inputs of 1, 1, 0.25 and 3 MiB");
      Free (P);
      Free (S);
      Free (K);
      Free (X);
   end Many_Chunks;

   --  The digest goes to Digest whatever its bounds, touching nothing
   --  else; any other length is refused.
   procedure Digest_Bounds is
      One    : constant Byte_Array (0 .. 0) := [7];
      Params : constant Parameters := [1, 32, 64, 3, 16#13#, 2];
      Buffer : Blake2b.Byte_Array (99 .. 164) := [others => 16#A5#];
      Short  : Blake2b.Byte_Array (0 .. 31);
   begin
      Compute_With_Scratch
        (One, One, One, One, Params (0), Params (1), Params (2), Params (3),
         Params (4), Params (5), Buffer (100 .. 163));
      Check (Buffer (100 .. 163) = Oracle_H0 (Params, One, One, One, One),
             "digest written at bounds 100 .. 163");
      Check (Buffer (99) = 16#A5# and then Buffer (164) = 16#A5#,
             "digest leaves both guard bytes");
      begin
         if Contracts_On then
            Compute_With_Scratch
              (One, One, One, One, Params (0), Params (1), Params (2),
               Params (3), Params (4), Params (5), Short);
            Check (False, "a 32-byte digest must fail the precondition");
         end if;
      exception
         when Ada.Assertions.Assertion_Error =>
            Check (True, "a 32-byte digest is refused");
      end;
   end Digest_Bounds;

   --  Runs one group of tests; an exception out of it is a failed H0 test,
   --  and the remaining groups still run.
   procedure Guarded (Name : String; Test : not null access procedure) is
   begin
      Test.all;
   exception
      when E : others =>
         Check (False, Name & ": unexpected exception: "
                & Ada.Exceptions.Exception_Information (E));
   end Guarded;

   procedure Run is
   begin
      Guarded ("RFC 9106 vectors", RFC_Vectors'Access);
      Guarded ("CPython vectors", CPython_Vectors'Access);
      Guarded ("edge cases", Edge_Cases'Access);
      Guarded ("chunk boundaries", Boundaries'Access);
      Guarded ("random cases", Random_Cases'Access);
      Guarded ("many chunks", Many_Chunks'Access);
      Guarded ("digest bounds", Digest_Bounds'Access);
   end Run;

   ----------------------------------------------------------------------
   --  The long test
   ----------------------------------------------------------------------

   --  Byte J of the long test's inputs, as h0_oracle.c generates it: byte
   --  J mod 8 (little-endian) of the splitmix64 output for word J / 8
   --  under Seed. The same formula is written a second time in
   --  h0_oracle.c, so the two are not independent; Run_Long checks that
   --  what it generates is not degenerate (Varied).
   function Word (Seed, W : Unsigned_64) return Unsigned_64 is
      Z : Unsigned_64 := Seed + (W + 1) * 16#9E37_79B9_7F4A_7C15#;
   begin
      Z := (Z xor Shift_Right (Z, 30)) * 16#BF58_476D_1CE4_E5B9#;
      Z := (Z xor Shift_Right (Z, 27)) * 16#94D0_49BB_1331_11EB#;
      return Z xor Shift_Right (Z, 31);
   end Word;

   --  Buf := the first Buf'Length bytes generated from Seed.
   procedure Generate (Buf : out Byte_Array; Seed : Unsigned_64) is
      W : Unsigned_64 := 0;
   begin
      for J in Buf'Range loop
         if (J - Buf'First) mod 8 = 0 then
            W := Word (Seed, Unsigned_64 ((J - Buf'First) / 8));
         end if;
         Buf (J) := Byte (W and 16#FF#);
         W := Shift_Right (W, 8);
      end loop;
   end Generate;

   --  The first 64 bytes of A take at least 32 distinct values.
   function Varied (A : Byte_Array) return Boolean is
      Seen  : array (Byte) of Boolean := [others => False];
      Count : Natural := 0;
   begin
      for J in A'First .. A'First + 63 loop
         if not Seen (A (J)) then
            Seen (A (J)) := True;
            Count := Count + 1;
         end if;
      end loop;
      return Count >= 32;
   end Varied;

   function Seconds (Since : Ada.Real_Time.Time) return String is
     (Duration'Image
        (Ada.Real_Time.To_Duration (Ada.Real_Time."-" (Ada.Real_Time.Clock,
                                                        Since)))
      & " s");

   type Bytes_Access is access Byte_Array;
   procedure Free is
     new Ada.Unchecked_Deallocation (Byte_Array, Bytes_Access);

   Long_Params : constant Parameters := [7, 64, 2_097_149, 3, 16#13#, 2];

   --  The C oracle's digest of inputs generated from Seeds, of Lengths.
   function Oracle_Generated (Seeds, Lengths : Quad) return Digest_64 is
      Digest : Digest_64 := [others => 0];
   begin
      if C_H0_Generated (Long_Params, Seeds, Lengths, Digest (0)'Address)
         /= 0
      then
         raise Program_Error with "h0_oracle_generated failed";
      end if;
      return Digest;
   end Oracle_Generated;

   Input_Names : constant array (0 .. 3) of String (1 .. 1) :=
     ["P", "S", "K", "X"];

   --  One input (Which: 0 for P .. 3 for X) is Big, the first Length bytes
   --  generated from Seeds (Which); the other three are short, of distinct
   --  lengths, each generated from its own seed. So a swap of two inputs
   --  or of two length fields, or one input hashed in place of another,
   --  changes the digest.
   procedure Long_Case
     (Big : Byte_Array; Which : Natural; Seeds : Quad; Label : String)
   is
      Short_Lengths : constant array (0 .. 2) of Byte_Index := [3, 11, 29];
      Lengths : Quad;
      Shorts  : array (0 .. 3) of Bytes_Access := [others => null];
      Next    : Natural := 0;
      Got     : Digest_64 := [others => 0];
      Start   : Ada.Real_Time.Time := Ada.Real_Time.Clock;
   begin
      for I in 0 .. 3 loop
         if I = Which then
            Lengths (I) := Unsigned_64 (Big'Length);
         else
            Shorts (I) := new Byte_Array (0 .. Short_Lengths (Next) - 1);
            Generate (Shorts (I).all, Seeds (I));
            Lengths (I) := Unsigned_64 (Short_Lengths (Next));
            Next := Next + 1;
         end if;
      end loop;
      case Which is
         when 0 =>
            Compute_With_Scratch
              (Big, Shorts (1).all, Shorts (2).all, Shorts (3).all,
               Long_Params (0), Long_Params (1), Long_Params (2),
               Long_Params (3), Long_Params (4), Long_Params (5), Got);
         when 1 =>
            Compute_With_Scratch
              (Shorts (0).all, Big, Shorts (2).all, Shorts (3).all,
               Long_Params (0), Long_Params (1), Long_Params (2),
               Long_Params (3), Long_Params (4), Long_Params (5), Got);
         when 2 =>
            Compute_With_Scratch
              (Shorts (0).all, Shorts (1).all, Big, Shorts (3).all,
               Long_Params (0), Long_Params (1), Long_Params (2),
               Long_Params (3), Long_Params (4), Long_Params (5), Got);
         when others =>
            Compute_With_Scratch
              (Shorts (0).all, Shorts (1).all, Shorts (2).all, Big,
               Long_Params (0), Long_Params (1), Long_Params (2),
               Long_Params (3), Long_Params (4), Long_Params (5), Got);
      end case;
      for I in Shorts'Range loop
         if Shorts (I) /= null then
            Free (Shorts (I));
         end if;
      end loop;
      Put ("   " & Label & ": Compute" & Seconds (Start));
      Start := Ada.Real_Time.Clock;
      declare
         Expected : constant Digest_64 := Oracle_Generated (Seeds, Lengths);
      begin
         Put_Line (", C oracle" & Seconds (Start));
         Put_Line ("      digest " & To_Hex (Got));
         Check (Got = Expected,
                "long H0, " & Label & ": got " & To_Hex (Got)
                & ", C oracle " & To_Hex (Expected));
      end;
   end Long_Case;

   procedure Run_Long_Cases;

   procedure Run_Long is
   begin
      Guarded ("long H0", Run_Long_Cases'Access);
   end Run_Long;

   procedure Run_Long_Cases is
      use Ada.Real_Time;
      Overall : constant Time := Clock;
      Seeds   : constant Quad :=
        [16#4_0000_0024#, 16#5_1111_0035#, 16#6_2222_0046#,
         16#7_3333_0057#];
      Boundary_Lengths : constant array (1 .. 4) of Long_Long_Integer :=
        [2**31 - 1, 2**31, 2**31 + 1, 2**32 - 1];
      --  One array of the greatest length, 2**32 - 1 bytes (4 GiB), the
      --  most this test allocates at once; shorter long inputs are its
      --  prefixes.
      Input   : Bytes_Access := new Byte_Array (0 .. Byte_Index'Last);
      Head    : Byte_Array (0 .. 63) := [others => 0];
      Start   : Time := Clock;
   begin
      Put_Line ("long H0," & Image (Long_Params));

      --  Four inputs of 2**32 - 1 bytes, one array passed as all four:
      --  the greatest message, 2**34 + 36 bytes.
      Generate (Input.all, Seeds (0));
      Put_Line ("   generated 4 GiB in" & Seconds (Start));
      Check (Varied (Input.all), "long H0: generated bytes vary");
      Head := Input (0 .. 63);
      declare
         Got : Digest_64 := [others => 0];
      begin
         Start := Clock;
         Compute_With_Scratch
           (Input.all, Input.all, Input.all, Input.all,
            Long_Params (0), Long_Params (1), Long_Params (2),
            Long_Params (3), Long_Params (4), Long_Params (5), Got);
         Put ("   all four inputs of 2**32 - 1 bytes: Compute"
              & Seconds (Start));
         Start := Clock;
         declare
            Same     : constant Quad := [others => Seeds (0)];
            Lengths  : constant Quad := [others => 2**32 - 1];
            Expected : constant Digest_64 :=
              Oracle_Generated (Same, Lengths);
         begin
            Put_Line (", C oracle" & Seconds (Start));
            Put_Line ("      digest " & To_Hex (Got));
            Check (Got = Expected,
                   "long H0 of 2**34 + 36 bytes: got " & To_Hex (Got)
                   & ", C oracle " & To_Hex (Expected));
         end;
      end;

      --  Each input in turn at 2**31 - 1, 2**31, 2**31 + 1 and 2**32 - 1
      --  bytes, the others short and distinct.
      for Which in 0 .. 3 loop
         if Which > 0 then
            Start := Clock;
            Generate (Input.all, Seeds (Which));
            Put_Line ("   generated 4 GiB in" & Seconds (Start));
            Check (Varied (Input.all) and then Input (0 .. 63) /= Head,
                   "long H0: seed" & Which'Image & " gives other bytes");
         end if;
         for Length of Boundary_Lengths loop
            Long_Case
              (Input (0 .. Length - 1), Which, Seeds,
               Input_Names (Which) & " of" & Length'Image & " bytes");
         end loop;
      end loop;
      Free (Input);
      Put_Line ("   long H0 total" & Seconds (Overall));
   end Run_Long_Cases;

end H0_Tests;
