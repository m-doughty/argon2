--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Assertions;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;
with Interfaces.C;
with System;

with Argon2_Config;
with Argon2.Blocks;
with Argon2.Geometry; use Argon2.Geometry;
with Argon2.Indexing;

package body Indexing_Tests is

   use type Interfaces.Unsigned_64;
   use type Interfaces.Unsigned_32;
   use type Argon2.Blocks.Block;

   subtype LLI is Long_Long_Integer;
   subtype U32 is Interfaces.Unsigned_32;
   subtype Word is Argon2.Blocks.Word;

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;
   Seed       : U32 := 16#1DE7_0042#;

   --  A failure of the grid would print a line per case; only the first
   --  ones are shown (all are counted).
   Shown_Failures : constant := 40;

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
         if Fail_Count <= Shown_Failures then
            Put_Line ("FAIL: indexing: " & Label_Text);
         elsif Fail_Count = Shown_Failures + 1 then
            Put_Line ("FAIL: indexing: further failures not shown");
         end if;
      end if;
   end Check;

   function Next_Random return U32 is
   begin
      Seed := Seed * 1_664_525 + 1_013_904_223;
      return Seed;
   end Next_Random;

   ----------------------------------------------------------------------
   --  Oracles (ref/compress_oracle.c)
   ----------------------------------------------------------------------

   --  The unmodified reference's index_alpha (core.c): the index within
   --  the reference lane of the reference block of block Index of the
   --  segment (Pass, Slice, Lane), for J1 (Pseudo_Rand) and whether the
   --  reference lane is the block's own lane.
   function Index_Alpha_Oracle
     (Lanes          : Interfaces.C.unsigned;
      Segment_Length : Interfaces.C.unsigned;
      Passes         : Interfaces.C.unsigned;
      Variant_Type   : Interfaces.C.unsigned;
      Pass           : Interfaces.C.unsigned;
      Lane           : Interfaces.C.unsigned;
      Slice          : Interfaces.C.unsigned;
      Index          : Interfaces.C.unsigned;
      Pseudo_Rand    : Interfaces.C.unsigned;
      Same_Lane      : Interfaces.C.int) return Interfaces.C.unsigned
   with Import, Convention => C, External_Name => "index_alpha_oracle";

   --  The unmodified reference's next_addresses (ref.c): the 128 words of
   --  an address block from the first seven words of the input block, as
   --  fill_segment holds them before the call (word 6 is N - 1).
   procedure Next_Addresses_Oracle
     (Input_Words   : System.Address;
      Address_Words : System.Address)
   with Import, Convention => C, External_Name => "next_addresses_oracle";

   ----------------------------------------------------------------------
   --  Locate against index_alpha
   ----------------------------------------------------------------------

   type U32_List is array (Positive range <>) of U32;

   function Image (V : LLI) return String is
     (Long_Long_Integer'Image (V));

   --  One position and one W, against the oracle. J1 and J2 are W's low
   --  and high halves. The expected lane is the own lane in pass 0,
   --  slice 0, else J2 mod p; the oracle's same_lane comes from it, never
   --  from Locate's output.
   procedure Check_Position
     (S     : Shape;
      Y     : Interfaces.C.unsigned;
      Pass  : LLI;
      Slice : LLI;
      Lane  : LLI;
      Index : LLI;
      J1    : U32;
      J2    : U32)
   is
      W : constant Interfaces.Unsigned_64 :=
        Interfaces.Shift_Left (Interfaces.Unsigned_64 (J2), 32)
        or Interfaces.Unsigned_64 (J1);
      Expected_Lane : constant LLI :=
        (if Pass = 0 and then Slice = 0 then Lane else LLI (J2) mod S.Lanes);
      Ref_Lane  : Lane_Number;
      Ref_Index : Argon2.Blocks.Block_Index;
      Expected_Index : Interfaces.C.unsigned;

      function Describe return String is
        ("y" & Interfaces.C.unsigned'Image (Y) & " p" & Image (S.Lanes)
         & " s" & Image (S.Segment) & " t" & Image (S.Passes)
         & " pass" & Image (Pass) & " slice" & Image (Slice)
         & " lane" & Image (Lane) & " index" & Image (Index)
         & " J1 " & U32'Image (J1) & " J2 " & U32'Image (J2));
   begin
      Argon2.Indexing.Locate
        (S, Pass, Slice, Lane, Index, W, Ref_Lane, Ref_Index);
      Expected_Index := Index_Alpha_Oracle
        (Lanes          => Interfaces.C.unsigned (S.Lanes),
         Segment_Length => Interfaces.C.unsigned (S.Segment),
         Passes         => Interfaces.C.unsigned (S.Passes),
         Variant_Type   => Y,
         Pass           => Interfaces.C.unsigned (Pass),
         Lane           => Interfaces.C.unsigned (Lane),
         Slice          => Interfaces.C.unsigned (Slice),
         Index          => Interfaces.C.unsigned (Index),
         Pseudo_Rand    => Interfaces.C.unsigned (J1),
         Same_Lane      => (if Expected_Lane = Lane then 1 else 0));
      if Ref_Lane = Expected_Lane then
         Pass_Count := Pass_Count + 1;
      else
         Check (False, "reference lane " & Image (Ref_Lane)
                & ", expected " & Image (Expected_Lane) & ": " & Describe);
      end if;
      if Ref_Index = LLI (Expected_Index) then
         Pass_Count := Pass_Count + 1;
      else
         Check (False, "reference index " & Image (Ref_Index)
                & ", oracle" & Interfaces.C.unsigned'Image (Expected_Index)
                & ": " & Describe);
      end if;
   end Check_Position;

   --  Every J1 and J2 of the grid at one position: J1 at 0, 2**32 - 1 and
   --  three pseudo-random values; J2 at 0, 2**32 - 1, the own lane (small
   --  and near 2**32), p - 1 (small and near 2**32) and a pseudo-random
   --  value.
   procedure Check_Values
     (S     : Shape;
      Y     : Interfaces.C.unsigned;
      Pass  : LLI;
      Slice : LLI;
      Lane  : LLI;
      Index : LLI)
   is
      Top : constant LLI := 2 ** 32 - 1;
      P   : constant LLI := S.Lanes;
      J1s : U32_List (1 .. 5);
      J2s : U32_List (1 .. 7);
   begin
      J1s (1) := 0;
      J1s (2) := U32'Last;
      J1s (3) := Next_Random;
      J1s (4) := Next_Random;
      J1s (5) := Next_Random;
      J2s (1) := 0;
      J2s (2) := U32'Last;
      J2s (3) := U32 (Lane);
      J2s (4) := U32 (Lane + P * ((Top - Lane) / P));
      J2s (5) := U32 (P - 1);
      J2s (6) := U32 (P - 1 + P * ((Top - (P - 1)) / P));
      J2s (7) := Next_Random;
      for J1 of J1s loop
         for J2 of J2s loop
            Check_Position (S, Y, Pass, Slice, Lane, Index, J1, J2);
         end loop;
      end loop;
   end Check_Values;

   --  The segment indices of the grid: 0, 1, 2, 127, 128, 129 and the
   --  last, those below the segment length, once each. -1 if K does not
   --  name one.
   function Grid_Index (Segment : LLI; K : Positive) return LLI is
   begin
      case K is
         when 1 => return 0;
         when 2 => return 1;
         when 3 => return (if 2 < Segment then 2 else -1);
         when 4 => return (if 127 < Segment then 127 else -1);
         when 5 => return (if 128 < Segment then 128 else -1);
         when 6 => return (if 129 < Segment then 129 else -1);
         when others =>
            return (if Segment - 1 in 0 | 1 | 2 | 127 | 128 | 129 then -1
                    else Segment - 1);
      end case;
   end Grid_Index;

   --  The own lanes of the grid: the first, the middle and the last, once
   --  each. -1 if K does not name one.
   function Grid_Lane (Lanes : LLI; K : Positive) return LLI is
   begin
      case K is
         when 1 => return 0;
         when 2 => return (if (Lanes - 1) / 2 in 1 .. Lanes - 2
                           then (Lanes - 1) / 2 else -1);
         when others => return (if Lanes > 1 then Lanes - 1 else -1);
      end case;
   end Grid_Lane;

   procedure Locate_Grid is
      Segments : constant array (1 .. 7) of LLI :=
        [2, 3, 127, 128, 129, 130, 256];
      Lane_Counts : constant array (1 .. 4) of LLI := [1, 2, 3, 5];
   begin
      for Y in Interfaces.C.unsigned range 0 .. 2 loop
         for Segment of Segments loop
            for Lanes of Lane_Counts loop
               declare
                  S : constant Shape :=
                    (Lanes => Lanes, Segment => Segment, Passes => 3);
               begin
                  for KL in 1 .. 3 loop
                     declare
                        Lane : constant LLI := Grid_Lane (Lanes, KL);
                     begin
                        if Lane >= 0 then
                           for Pass in 0 .. 2 loop
                              for Slice in 0 .. 3 loop
                                 for KI in 1 .. 7 loop
                                    declare
                                       Index : constant LLI :=
                                         Grid_Index (Segment, KI);
                                    begin
                                       if Index >= 0
                                         and then (Pass > 0 or else Slice > 0
                                                   or else Index >= 2)
                                       then
                                          Check_Values
                                            (S, Y, LLI (Pass), LLI (Slice),
                                             Lane, Index);
                                       end if;
                                    end;
                                 end loop;
                              end loop;
                           end loop;
                        end if;
                     end;
                  end loop;
               end;
            end loop;
         end loop;
      end loop;
   end Locate_Grid;

   --  The two extreme shapes. p = 2**24 - 1 with segment 64 has
   --  m' = 2**32 - 256 (lane numbers up to 2**24 - 2); p = 1 with segment
   --  2**30 - 1 has m' = 2**32 - 4 (every lane-length product reaching
   --  the top of uint32).
   procedure Locate_Extremes is
      Many : constant Shape :=
        (Lanes => 2 ** 24 - 1, Segment => 64, Passes => 3);
      Long : constant Shape :=
        (Lanes => 1, Segment => 2 ** 30 - 1, Passes => 3);
      Many_Lanes : constant array (1 .. 3) of LLI :=
        [0, 2 ** 23, 2 ** 24 - 2];
      Many_Indexes : constant array (1 .. 3) of LLI := [0, 2, 63];
      Long_Indexes : constant array (1 .. 6) of LLI :=
        [0, 1, 2, 128, 2 ** 30 - 3, 2 ** 30 - 2];
   begin
      for Y in Interfaces.C.unsigned range 0 .. 2 loop
         for Lane of Many_Lanes loop
            for Pass in 0 .. 2 loop
               for Slice in 0 .. 3 loop
                  for Index of Many_Indexes loop
                     if Pass > 0 or else Slice > 0 or else Index >= 2 then
                        Check_Values
                          (Many, Y, LLI (Pass), LLI (Slice), Lane, Index);
                     end if;
                  end loop;
               end loop;
            end loop;
         end loop;
         for Pass in 0 .. 2 loop
            for Slice in 0 .. 3 loop
               for Index of Long_Indexes loop
                  if Pass > 0 or else Slice > 0 or else Index >= 2 then
                     Check_Values
                       (Long, Y, LLI (Pass), LLI (Slice), 0, Index);
                  end if;
               end loop;
            end loop;
         end loop;
      end loop;
   end Locate_Extremes;

   --  The first two blocks of pass 0, slice 0 come from H0, not from a
   --  reference: Locate's precondition refuses them.
   procedure Locate_Rejects_First_Blocks is
      S : constant Shape := (Lanes => 2, Segment => 8, Passes => 2);
      Ref_Lane  : Lane_Number;
      Ref_Index : Argon2.Blocks.Block_Index;
   begin
      if not Contracts_On then
         Put_Line ("note: skipped (contracts off): "
                   & "Locate_Rejects_First_Blocks");
         return;
      end if;
      for Index in LLI range 0 .. 1 loop
         begin
            Argon2.Indexing.Locate
              (S, 0, 0, 1, Index, 16#0000_0001_0000_0001#,
               Ref_Lane, Ref_Index);
            Check (False, "pass 0, slice 0, index" & Image (Index)
                   & " must reject the precondition");
         exception
            when Ada.Assertions.Assertion_Error =>
               Check (True, "pass 0, slice 0, index" & Image (Index)
                      & " rejected");
            when E : others =>
               Check (False, "wrong exception for index" & Image (Index)
                      & ": " & Ada.Exceptions.Exception_Information (E));
         end;
      end loop;
   end Locate_Rejects_First_Blocks;

   ----------------------------------------------------------------------
   --  Next_Address_Block against next_addresses
   ----------------------------------------------------------------------

   type Seven_Words is array (0 .. 6) of Word with Convention => C;

   --  One address block, N of the segment (Pass, Lane, Slice). The oracle's
   --  input words are the caller's literals: m' (M_Prime) and y (Y_Word)
   --  are written out by hand at each call, and N - 1 is word 6.
   procedure Check_Address
     (V       : Variant;
      Pass    : LLI;
      Lane    : LLI;
      Slice   : LLI;
      P       : LLI;
      Segment : LLI;
      T       : LLI;
      M_Prime : Word;
      Y_Word  : Word;
      N       : Address_Counter)
   is
      S : constant Shape := (Lanes => P, Segment => Segment, Passes => T);
      Input : constant Seven_Words :=
        [Word (Pass), Word (Lane), Word (Slice), M_Prime, Word (T), Y_Word,
         Word (N - 1)];
      Expected : Argon2.Blocks.Block := [others => 16#C3C3_C3C3_C3C3_C3C3#];
      Scratch : Argon2.Indexing.Address_Scratch :=
        [0 => [others => 0],
         1 => [others => 16#A5A5_A5A5_A5A5_A5A5#],
         2 => [others => 16#5A5A_5A5A_5A5A_5A5A#]];
      Work : Argon2.Blocks.Block := [others => 16#DEAD_BEEF_DEAD_BEEF#];
      Zero : constant Argon2.Blocks.Block := [others => 0];
      Label_Text : constant String :=
        "y" & Word'Image (Y_Word) & " pass" & Image (Pass)
        & " lane" & Image (Lane) & " slice" & Image (Slice)
        & " p" & Image (P) & " s" & Image (Segment) & " t" & Image (T)
        & " N" & Image (N);
   begin
      Next_Addresses_Oracle (Input'Address, Expected'Address);
      Argon2.Indexing.Next_Address_Block
        (Scratch, Work, S, V, Pass, Lane, Slice, N);
      Check (Scratch (2) = Expected, "address block: " & Label_Text);
      Check (Scratch (0) = Zero, "zero block kept: " & Label_Text);
   end Check_Address;

   --  Every counter 1 .. Max_N of one segment.
   procedure Check_Counters
     (V       : Variant;
      Pass    : LLI;
      Lane    : LLI;
      Slice   : LLI;
      P       : LLI;
      Segment : LLI;
      T       : LLI;
      M_Prime : Word;
      Y_Word  : Word;
      Max_N   : Address_Counter)
   is
   begin
      for N in 1 .. Max_N loop
         Check_Address
           (V, Pass, Lane, Slice, P, Segment, T, M_Prime, Y_Word, N);
      end loop;
   end Check_Counters;

   --  The lanes 0 and p - 1 (once, for p = 1) and a middle one.
   procedure Check_Lanes
     (V       : Variant;
      Pass    : LLI;
      Slice   : LLI;
      P       : LLI;
      Segment : LLI;
      T       : LLI;
      M_Prime : Word;
      Y_Word  : Word;
      Max_N   : Address_Counter)
   is
   begin
      for K in 1 .. 3 loop
         declare
            Lane : constant LLI := Grid_Lane (P, K);
         begin
            if Lane >= 0 then
               Check_Counters
                 (V, Pass, Lane, Slice, P, Segment, T, M_Prime, Y_Word,
                  Max_N);
            end if;
         end;
      end loop;
   end Check_Lanes;

   --  Shapes with p lanes and the given segment length: m' = 4 p s and the
   --  number of address blocks of a segment, written out by hand.
   type Address_Shape is record
      P       : LLI;
      Segment : LLI;
      M_Prime : Word;
      Max_N   : Address_Counter;
   end record;

   Address_Shapes : constant array (1 .. 12) of Address_Shape :=
     [(1, 2, 8, 1), (1, 128, 512, 1), (1, 129, 516, 2), (1, 300, 1_200, 3),
      (2, 2, 16, 1), (2, 128, 1_024, 1), (2, 129, 1_032, 2),
      (2, 300, 2_400, 3),
      (5, 2, 40, 1), (5, 128, 2_560, 1), (5, 129, 2_580, 2),
      (5, 300, 6_000, 3)];

   procedure Address_Grid is
   begin
      for A of Address_Shapes loop
         --  Argon2i (y = 1): every pass of three, every slice.
         for Pass in 0 .. 2 loop
            for Slice in 0 .. 3 loop
               Check_Lanes
                 (Argon2i, LLI (Pass), LLI (Slice), A.P, A.Segment, 3,
                  A.M_Prime, 1, A.Max_N);
            end loop;
         end loop;
         --  Argon2id (y = 2): pass 0, slices 0 and 1.
         for Slice in 0 .. 1 loop
            Check_Lanes
              (Argon2id, 0, LLI (Slice), A.P, A.Segment, 3, A.M_Prime, 2,
               A.Max_N);
         end loop;
      end loop;
   end Address_Grid;

   --  Other pass counts, and a case in which the seven words differ: pass 2
   --  of 7, lane 4 of 5, slice 3, m' = 6,000, y = 1, N - 1 = 0.
   procedure Address_Words_Distinct is
   begin
      Check_Counters (Argon2i, 2, 4, 3, 5, 300, 7, 6_000, 1, 3);
      Check_Counters (Argon2id, 0, 3, 1, 5, 300, 7, 6_000, 2, 3);
      Check_Counters (Argon2i, 0, 0, 0, 1, 128, 1, 512, 1, 1);
      Check_Counters (Argon2i, 6, 1, 2, 2, 129, 7, 1_032, 1, 2);
      Check_Counters (Argon2id, 0, 1, 0, 2, 129, 7, 1_032, 2, 2);
   end Address_Words_Distinct;

   --  The extremes of every field: the largest pass number and pass count,
   --  the largest lane and lane count, m' near 2**32, and the largest
   --  counter (segment 2**30 - 1 needs 2**23 address blocks).
   procedure Address_Extremes is
      Long_M : constant Word := 4_294_967_292;  --  4 (2**30 - 1)
      Many_M : constant Word := 4_294_967_040;  --  4 * 64 * (2**24 - 1)
   begin
      Check_Address
        (Argon2i, 1, 0, 2, 1, 2 ** 30 - 1, 3, Long_M, 1, 2 ** 23);
      Check_Address
        (Argon2i, 2, 0, 3, 1, 2 ** 30 - 1, 3, Long_M, 1, 2 ** 23);
      Check_Address
        (Argon2id, 0, 0, 1, 1, 2 ** 30 - 1, 3, Long_M, 2, 2 ** 23);
      Check_Address
        (Argon2id, 0, 0, 0, 1, 2 ** 30 - 1, 3, Long_M, 2, 2 ** 23);
      Check_Address
        (Argon2i, 1, 0, 1, 1, 2 ** 30 - 1, 3, Long_M, 1, 2 ** 23 - 1);
      Check_Address
        (Argon2i, 1, 0, 1, 1, 2 ** 30 - 1, 3, Long_M, 1, 2 ** 22 + 1);
      Check_Address
        (Argon2i, 1, 0, 1, 1, 2 ** 30 - 1, 3, Long_M, 1, 1);
      Check_Address
        (Argon2i, 2 ** 32 - 2, 0, 3, 1, 2 ** 30 - 1, 2 ** 32 - 1, Long_M, 1,
         2 ** 23);
      Check_Address
        (Argon2i, 2 ** 32 - 2, 0, 0, 1, 2 ** 30 - 1, 2 ** 32 - 1, Long_M, 1,
         1);
      for Slice in 0 .. 3 loop
         Check_Address
           (Argon2i, 2, 2 ** 24 - 2, LLI (Slice), 2 ** 24 - 1, 64, 3,
            Many_M, 1, 1);
         Check_Address
           (Argon2i, 0, 2 ** 23, LLI (Slice), 2 ** 24 - 1, 64, 3,
            Many_M, 1, 1);
      end loop;
      for Slice in 0 .. 1 loop
         Check_Address
           (Argon2id, 0, 2 ** 24 - 2, LLI (Slice), 2 ** 24 - 1, 64, 3,
            Many_M, 2, 1);
      end loop;
   end Address_Extremes;

   ----------------------------------------------------------------------
   --  Geometry
   ----------------------------------------------------------------------

   --  Shape_Of (P, M, T), against the hand values of segment length
   --  floor (m / 4p) and memory blocks 4 p * floor (m / 4p).
   procedure Check_Shape
     (P, M, T : LLI; Segment : LLI; Memory : LLI)
   is
      S : constant Shape := Shape_Of (P, M, T);
      Label_Text : constant String :=
        "Shape_Of (" & Image (P) & "," & Image (M) & "," & Image (T) & ")";
   begin
      Check (S.Lanes = P, Label_Text & ": lanes");
      Check (S.Passes = T, Label_Text & ": passes");
      Check (S.Segment = Segment,
             Label_Text & ": segment" & Image (S.Segment));
      Check (Memory_Blocks (S) = Memory,
             Label_Text & ": memory blocks" & Image (Memory_Blocks (S)));
      Check (Lane_Length (S) = 4 * Segment, Label_Text & ": lane length");
   end Check_Shape;

   procedure Shape_Boundaries is
   begin
      --  m = 8 p: the least memory, segment 2.
      Check_Shape (1, 8, 1, 2, 8);
      Check_Shape (2, 16, 3, 2, 16);
      Check_Shape (5, 40, 3, 2, 40);
      Check_Shape (2 ** 24 - 1, 134_217_720, 1, 2, 134_217_720);
      --  m not a multiple of 4 p: rounded down to a multiple.
      Check_Shape (1, 9, 1, 2, 8);
      Check_Shape (1, 11, 2, 2, 8);
      Check_Shape (1, 12, 2, 3, 12);
      Check_Shape (2, 23, 3, 2, 16);
      Check_Shape (2, 24, 3, 3, 24);
      Check_Shape (3, 35, 3, 2, 24);
      Check_Shape (3, 36, 3, 3, 36);
      --  The largest m (2**32 - 1 KiB).
      Check_Shape (1, 2 ** 32 - 1, 1, 2 ** 30 - 1, 4_294_967_292);
      Check_Shape (2, 2 ** 32 - 1, 3, 536_870_911, 4_294_967_288);
      Check_Shape (2 ** 24 - 1, 2 ** 32 - 1, 3, 64, 4_294_967_040);
      --  Around the largest segment length.
      Check_Shape (1, 2 ** 32 - 4, 1, 2 ** 30 - 1, 4_294_967_292);
      Check_Shape (1, 2 ** 32 - 5, 1, 2 ** 30 - 2, 4_294_967_288);
      --  The largest pass count.
      Check_Shape (1, 8, 2 ** 32 - 1, 2, 8);
      Check_Shape (2 ** 24 - 1, 2 ** 32 - 1, 2 ** 32 - 1, 64, 4_294_967_040);
   end Shape_Boundaries;

   --  Data_Independent, by hand: Argon2d never; Argon2i always; Argon2id
   --  only in pass 0, slices 0 and 1.
   procedure Data_Independent_Table is
      type Row is array (Slice_Index) of Boolean;
      Argon2id_Pass_0 : constant Row := [True, True, False, False];
      Never           : constant Row := [others => False];
      Always          : constant Row := [others => True];
      Passes : constant array (1 .. 5) of Pass_Number :=
        [0, 1, 2, 7, 2 ** 32 - 2];
   begin
      for Pass of Passes loop
         for Slice in Slice_Index loop
            declare
               Label_Text : constant String :=
                 " pass" & Image (Pass) & " slice" & Image (Slice);
            begin
               Check (not Data_Independent (Argon2d, Pass, Slice),
                      "Argon2d" & Label_Text);
               Check (Data_Independent (Argon2i, Pass, Slice) = Always (Slice),
                      "Argon2i" & Label_Text);
               Check (Data_Independent (Argon2id, Pass, Slice)
                      = (if Pass = 0 then Argon2id_Pass_0 (Slice)
                         else Never (Slice)),
                      "Argon2id" & Label_Text);
            end;
         end loop;
      end loop;
      --  Slice 2 of pass 0 is where Argon2id turns data-dependent.
      Check (Data_Independent (Argon2id, 0, 1), "Argon2id pass 0 slice 1");
      Check (not Data_Independent (Argon2id, 0, 2),
             "Argon2id pass 0 slice 2 is not data-independent");
   end Data_Independent_Table;

   ----------------------------------------------------------------------

   --  Runs one group of tests; an exception out of it is a failed test,
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
      Guarded ("Locate grid", Locate_Grid'Access);
      Guarded ("Locate extreme shapes", Locate_Extremes'Access);
      Guarded ("Locate precondition", Locate_Rejects_First_Blocks'Access);
      Guarded ("address grid", Address_Grid'Access);
      Guarded ("address words", Address_Words_Distinct'Access);
      Guarded ("address extremes", Address_Extremes'Access);
      Guarded ("Shape_Of", Shape_Boundaries'Access);
      Guarded ("Data_Independent", Data_Independent_Table'Access);
   end Run;

end Indexing_Tests;
