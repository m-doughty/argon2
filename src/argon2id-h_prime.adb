--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Ada.Numerics.Big_Numbers.Big_Integers;
with Blake2b.Hashing;
with Argon2id.Wipe;

package body Argon2id.H_Prime
  with SPARK_Mode
is
   use Ada.Numerics.Big_Numbers.Big_Integers;
   use type Blake2b.I64;
   use type Blake2b.Byte;

   Chunk_Bytes : constant := 4_096;
   subtype Chunk_Offset is Blake2b.I64 range 0 .. Chunk_Bytes - 1;
   subtype Length is Long_Long_Integer range 0 .. 2**32 - 1;

   function LE32 (N : Length) return Blake2b.Byte_Array
   with Global => null,
        Post => LE32'Result'First = 0 and then LE32'Result'Last = 3
          and then LE32'Result (0) = Byte (N mod 256)
          and then LE32'Result (1) = Byte ((N / 256) mod 256)
          and then LE32'Result (2) = Byte ((N / 65_536) mod 256)
          and then LE32'Result (3) = Byte ((N / 16_777_216) mod 256)
   is
   begin
      return [Byte (N mod 256), Byte ((N / 256) mod 256),
              Byte ((N / 65_536) mod 256),
              Byte ((N / 16_777_216) mod 256)];
   end LE32;

   --  A bounded, content-preserving bridge between the two array types.
   procedure Copy_Chunk
     (Input : Byte_Array; Offset : Length; Chunk : out Blake2b.Byte_Array)
   with Global => null,
        Pre => Input'Length >= 1
          and then Chunk'First = 0 and then Chunk'Length in 1 .. Chunk_Bytes
          and then Offset <= Input'Length
          and then Long_Long_Integer (Chunk'Length) <= Input'Length - Offset,
        Post => (for all J in Chunk'Range =>
          Chunk (J) =
            Input (Input'First + Offset + Long_Long_Integer (J)));

   procedure Initial_Hash
     (Input : Byte_Array; Output_Length : Length;
      Digest : out Blake2b.Byte_Array)
   with Global => null,
        Pre => Output_Length >= 1 and then Digest'Length in 1 .. 64;

   --  Copies and streaming absorption also process caller input. Stack
   --  scrubbing covers their frames, including compiler-created spills.
   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   pragma Machine_Attribute (Copy_Chunk, "strub", "internal");
   pragma Machine_Attribute (Copy_Chunk, "zero_call_used_regs", "all");
   pragma Machine_Attribute (Initial_Hash, "strub", "internal");
   pragma Machine_Attribute (Initial_Hash, "zero_call_used_regs", "all");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");

   procedure Copy_Chunk
     (Input : Byte_Array; Offset : Length; Chunk : out Blake2b.Byte_Array)
   is
      Start : constant Byte_Index := Input'First + Offset;
   begin
      pragma Assert (Start in Input'Range);
      pragma Assert (Long_Long_Integer (Chunk'Last) <= Input'Last - Start);
      Chunk := [others => 0];
      for J in Chunk_Offset range 0 .. Chunk'Length - 1 loop
         Chunk (J) := Input (Start + Long_Long_Integer (J));
         pragma Loop_Invariant (Chunk'First = 0);
         pragma Loop_Invariant (Chunk'Length in 1 .. Chunk_Bytes);
         pragma Loop_Invariant
           (Long_Long_Integer (Chunk'Last) <= Input'Last - Start);
         pragma Loop_Invariant
           (for all K in Chunk_Offset range 0 .. J =>
              Chunk (K) = Input (Start + Long_Long_Integer (K)));
      end loop;
   end Copy_Chunk;

   procedure Initial_Hash
     (Input : Byte_Array; Output_Length : Length;
      Digest : out Blake2b.Byte_Array)
   is
      S : Blake2b.Hashing.State;
      Prefix : Blake2b.Byte_Array (0 .. 3) := LE32 (Output_Length);
      Chunk : Blake2b.Byte_Array (0 .. Chunk_Bytes - 1) := [others => 0];
      Offset : Length := 0;
   begin
      Blake2b.Hashing.Init (S, Digest'Length, Blake2b.No_Bytes);
      Blake2b.Hashing.Update (S, Prefix);
      while Offset < Input'Length loop
         pragma Loop_Invariant (Offset <= Input'Length);
         pragma Loop_Invariant (Blake2b.Hashing.Is_Absorbing (S));
         pragma Loop_Invariant
           (Blake2b.Hashing.Output_Length (S) = Digest'Length);
         pragma Loop_Invariant
           (Static => Blake2b.Hashing.Absorbed (S) =
              Blake2b.Hashing.Big.Length (Blake2b.I64 (4 + Offset)));
         pragma Loop_Variant (Decreases => Input'Length - Offset);
         declare
            Count : constant Length :=
              Length'Min (Chunk_Bytes, Input'Length - Offset);
         begin
            Copy_Chunk (Input, Offset, Chunk (0 .. Blake2b.I64 (Count) - 1));
            Blake2b.Hashing.Update (S, Chunk (0 .. Blake2b.I64 (Count) - 1));
            Offset := Offset + Count;
         end;
      end loop;
      pragma Assert (Offset = Input'Length);
      pragma Assert
        (Static => Blake2b.Hashing.Absorbed (S) =
           Blake2b.Hashing.Big.Length (Blake2b.I64 (4 + Input'Length)));
      Blake2b.Hashing.Final (S, Digest);
      pragma Assert (Blake2b.Hashing.Is_Finalized (S));
      Argon2id.Wipe.Bytes (Prefix);
      pragma Assert (for all I in Prefix'Range => Prefix (I) = 0);
      Argon2id.Wipe.Bytes (Chunk);
      pragma Assert (for all I in Chunk'Range => Chunk (I) = 0);
   end Initial_Hash;

   procedure Hash (Input : Byte_Array; Digest : out Byte_Array) is
      T : constant Length := Digest'Length;
      V : Blake2b.Byte_Array (0 .. 63) := [others => 0];
      Next_V : Blake2b.Byte_Array (0 .. 63) := [others => 0];
      Written : Length := 0;
   begin
      --  Every output element is initialized before any partial write.
      --  No dynamic object is sized from an input or output length.
      Digest := [others => 0];
      if T <= 64 then
         Initial_Hash (Input, T, V (0 .. Blake2b.I64 (T) - 1));
         for J in 0 .. T - 1 loop
            Digest (Digest'First + J) := V (Blake2b.I64 (J));
         end loop;
      else
         Initial_Hash (Input, T, V);
         --  r = ceil(T / 32) - 2; the last digest has 33 .. 64 bytes.
         --  Emit a 32-byte prefix while more than 64 bytes remain.
         while T - Written > 64 loop
            pragma Loop_Invariant (Written <= T - 33);
            pragma Loop_Invariant (Written mod 32 = 0);
            pragma Loop_Variant (Decreases => T - Written);
            for J in Long_Long_Integer range 0 .. 31 loop
               Digest (Digest'First + Written + J) := V (Blake2b.I64 (J));
            end loop;
            Written := Written + 32;
            if T - Written > 64 then
               Blake2b.Hashing.Hash (V, Blake2b.No_Bytes, Next_V);
               V := Next_V;
            end if;
         end loop;
         pragma Assert (T - Written in 33 .. 64);
         pragma Assert (Written = 32 * ((T + 31) / 32 - 2));
         Blake2b.Hashing.Hash
           (V, Blake2b.No_Bytes, Next_V (0 .. Blake2b.I64 (T - Written) - 1));
         for J in 0 .. T - Written - 1 loop
            Digest (Digest'First + Written + J) := Next_V (Blake2b.I64 (J));
         end loop;
      end if;
      Argon2id.Wipe.Bytes (V);
      pragma Assert (for all I in V'Range => V (I) = 0);
      Argon2id.Wipe.Bytes (Next_V);
      pragma Assert (for all I in Next_V'Range => Next_V (I) = 0);
   end Hash;
end Argon2id.H_Prime;
