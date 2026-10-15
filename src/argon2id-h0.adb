--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The helpers' contracts have two parts: Executable, checked at run time
--  in builds with assertions enabled (-gnata) and proved; Static, proved
--  and never compiled (it describes the hash in progress through
--  Blake2b.Hashing.Model, which exists only for the proof).
pragma Assertion_Level (Executable);

with Ada.Numerics.Big_Numbers.Big_Integers;

with Blake2b.Hashing;
with Blake2b.Spec.Incremental;
with Blake2b.Streaming;
with Blake2b.Streaming.Example;
with Blake2b.Streaming.Theory;
with Argon2id.Wipe;

package body Argon2id.H0
  with SPARK_Mode
is
   use Ada.Numerics.Big_Numbers.Big_Integers;
   use Blake2b.Hashing;
   use Blake2b.Streaming;
   use Blake2b.Streaming.Theory;
   use Argon2id.H0_Model;
   use type Blake2b.I64;
   use type Blake2b.Byte;
   use type Interfaces.Unsigned_32;

   package Inc renames Blake2b.Spec.Incremental;
   use type Inc.Context;

   subtype U32 is Interfaces.Unsigned_32;
   subtype I64 is Blake2b.I64;

   --  Inputs reach BLAKE2b in chunks of at most this many bytes, copied
   --  into a fixed buffer: Blake2b.Byte_Array holds at most 2**31 bytes,
   --  an input up to 2**32 - 1.
   Chunk_Bytes : constant := 4_096;
   subtype Chunk_Offset is I64 range 0 .. Chunk_Bytes - 1;
   subtype Chunk_Buffer is Blake2b.Byte_Array (Chunk_Offset);
   subtype Length is Long_Long_Integer range 0 .. 2**32 - 1;

   --  Fields 0 .. 9 (p, T, m, t, v, y, then the four input lengths) and
   --  inputs 10 .. 13 (P, S, K, X), numbered as H0_Model's sources.
   subtype Field_Number is Natural range 0 .. 9;
   subtype Input_Number is Natural range 10 .. 13;

   type Parameters is record
      Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
   end record;

   function Field_Value
     (Pr : Parameters; P, S, K, X : Byte_Array; Id : Field_Number)
      return U32
   is
     (case Id is
        when 0 => Pr.Parallelism,
        when 1 => Pr.Tag_Length,
        when 2 => Pr.Memory,
        when 3 => Pr.Passes,
        when 4 => Pr.Version,
        when 5 => Pr.Kind,
        when 6 => U32 (P'Length),
        when 7 => U32 (S'Length),
        when 8 => U32 (K'Length),
        when 9 => U32 (X'Length));

   function Input_Length
     (P, S, K, X : Byte_Array; Id : Input_Number) return Length
   is
     (case Id is
        when 10 => P'Length,
        when 11 => S'Length,
        when 12 => K'Length,
        when 13 => X'Length);

   --  The proof's view of a call (static ghost): its logical message, the
   --  context of its first Off bytes, and where each piece starts. The
   --  contracts below state the hash in progress as Same_Context
   --  (Model (St), Prefix (...)), a logical equality, which the provers
   --  substitute freely.
   function Call_C (Pr : Parameters; P, S, K, X : Byte_Array)
      return Contents
   is
     (Call_Contents (Pr.Parallelism, Pr.Tag_Length, Pr.Memory, Pr.Passes,
                     Pr.Version, Pr.Kind, P, S, K, X))
   with Ghost => Static;

   function Prefix
     (Pr : Parameters; P, S, K, X : Byte_Array; Off : Offset)
      return Inc.Context
   is
     (Logical_After
        (Blake2b.No_Bytes, Call_C (Pr, P, S, K, X), Call_Pieces (P, S, K, X),
         Call_Length (P, S, K, X), Off, 64))
   with Ghost => Static,
        Pre   => Off <= Call_Length (P, S, K, X);

   function Field_First (P, S, K, X : Byte_Array; Id : Field_Number)
      return Offset
   is
     (Field_Start (Lengths_Of (P, S, K, X), Id))
   with Ghost => Static;

   function Input_First (P, S, K, X : Byte_Array; Id : Input_Number)
      return Offset
   is
     (Input_Start (Lengths_Of (P, S, K, X), Id))
   with Ghost => Static;

   --  Each piece starts where the one before it ends, in the order
   --  Compute absorbs them.
   procedure Lemma_Next (P, S, K, X : Byte_Array; Id : Field_Number)
   with Ghost  => Static,
        Global => null,
        Post   =>
          (if Id < 6
           then Field_First (P, S, K, X, Id) + 4
                = Field_First (P, S, K, X, Id + 1))
          and then
          (if Id >= 6
           then Field_First (P, S, K, X, Id) + 4
                = Input_First (P, S, K, X, Id + 4))
          and then
          (if Id in 6 .. 8
           then Input_First (P, S, K, X, Id + 4)
                + Lengths_Of (P, S, K, X) (Id + 4)
                = Field_First (P, S, K, X, Id + 1))
          and then
          (if Id = 9
           then Input_First (P, S, K, X, 13) + Lengths_Of (P, S, K, X) (13)
                = Call_Length (P, S, K, X))
   is
   begin
      null;
   end Lemma_Next;

   --  St has absorbed the first Off bytes of the message, and nothing
   --  else. One function, so that the loop invariants below are a single
   --  static ghost call: as a conjunction written out in the pragma, GNAT
   --  wraps them in a transient scope whose (empty) cleanup still calls
   --  System.Soft_Links.Abort_Defer and Abort_Undefer in the compiled
   --  code, although the invariant itself is never compiled.
   function In_Progress
     (St : State; Pr : Parameters; P, S, K, X : Byte_Array; Off : Offset)
      return Boolean
   is
     (Absorbed (St) = Big.Length (Off)
      and then Same_Context (Model (St), Prefix (Pr, P, S, K, X, Off)))
   with Ghost => Static,
        Pre   => Is_Absorbing (St) and then Off <= Call_Length (P, S, K, X);

   --  Data holds the message's bytes from Pos on (H0_Model.Chunk_At, kept
   --  hidden: the proofs below pass it along whole).
   function Holds
     (Pr : Parameters; P, S, K, X : Byte_Array; Pos : Offset;
      Data : Blake2b.Byte_Array) return Boolean
   is
     (Chunk_At (Pr.Parallelism, Pr.Tag_Length, Pr.Memory, Pr.Passes,
                Pr.Version, Pr.Kind, P, S, K, X, Pos, Data))
   with Ghost => Static,
        Pre   => Pos <= Call_Length (P, S, K, X);

   --  One Update in the proof's terms: absorbing Data, which holds the
   --  message's bytes from Pos on, takes the context of the first Pos
   --  bytes to the context of the first Pos + Data'Length (the step of
   --  Blake2b.Streaming.Example.Run_Loop, in a small proof context).
   procedure Lemma_Step
     (Before     : Inc.Context;
      Pr         : Parameters;
      P, S, K, X : Byte_Array;
      Pos        : Offset;
      Data       : Blake2b.Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Pos <= Call_Length (P, S, K, X)
                  and then Pos + Data'Length <= Call_Length (P, S, K, X)
                  and then Holds (Pr, P, S, K, X, Pos, Data)
                  and then Same_Context
                             (Before, Prefix (Pr, P, S, K, X, Pos)),
        Post   => Same_Context
                    (Inc.Update (Before, Data),
                     Prefix (Pr, P, S, K, X, Pos + Data'Length))
   is
   begin
      Lemma_Chunk_At
        (Pr.Parallelism, Pr.Tag_Length, Pr.Memory, Pr.Passes, Pr.Version,
         Pr.Kind, P, S, K, X, Pos, Data);
      pragma Assert (Before.NN = 64);
      Lemma_Update_Of
        (Before, Blake2b.No_Bytes,
         Call_Contents (Pr.Parallelism, Pr.Tag_Length, Pr.Memory, Pr.Passes,
                        Pr.Version, Pr.Kind, P, S, K, X),
         Call_Pieces (P, S, K, X), Call_Length (P, S, K, X), Pos, Data);
      Lemma_Same_Context
        (Inc.Update (Before, Data),
         Logical_After
           (Blake2b.No_Bytes,
            Call_Contents (Pr.Parallelism, Pr.Tag_Length, Pr.Memory,
                           Pr.Passes, Pr.Version, Pr.Kind, P, S, K, X),
            Call_Pieces (P, S, K, X), Call_Length (P, S, K, X),
            Pos + Data'Length, Before.NN));
   end Lemma_Step;

   --  Bytes holds Value little-endian.
   procedure Store_LE32 (Value : U32; Bytes : out Blake2b.Byte_Array)
   with Global => null,
        Pre    => Bytes'First = 0 and then Bytes'Last = 3,
        Post   => Bytes (0) = Byte (Value mod 2**8)
                  and then Bytes (1) = Byte ((Value / 2**8) mod 2**8)
                  and then Bytes (2) = Byte ((Value / 2**16) mod 2**8)
                  and then Bytes (3) = Byte (Value / 2**24);

   --  A bounded, content-preserving bridge between the two array types.
   procedure Copy_Chunk
     (Input : Byte_Array; Offset : Length; Chunk : out Blake2b.Byte_Array)
   with Global => null,
        Pre    => Input'Length >= 1
                  and then Chunk'First = 0
                  and then Chunk'Length in 1 .. Chunk_Bytes
                  and then Offset <= Input'Length
                  and then Long_Long_Integer (Chunk'Length)
                           <= Input'Length - Offset,
        Post   => (for all J in Chunk'Range =>
                     Chunk (J)
                     = Input (Input'First + Offset + Long_Long_Integer (J)));

   --  Chunk (0 .. Count - 1) := bytes Offset .. Offset + Count - 1 of
   --  input Id.
   procedure Copy_Input
     (P, S, K, X : Byte_Array;
      Id         : Input_Number;
      Offset     : Length;
      Count      : Length;
      Chunk      : in out Chunk_Buffer)
   with Global => null,
        Pre    => Count in 1 .. Chunk_Bytes
                  and then Offset <= Input_Length (P, S, K, X, Id)
                  and then Count <= Input_Length (P, S, K, X, Id) - Offset,
        Post   =>
          (Static =>
             (for all J in I64 range 0 .. I64 (Count) - 1 =>
                Chunk (J)
                = Selected_Byte (Id, P, S, K, X, I64 (Offset) + J)));

   --  Absorbs field Id, the next piece of the message.
   procedure Absorb_Field
     (St         : in out State;
      Pr         : Parameters;
      P, S, K, X : Byte_Array;
      Id         : Field_Number)
   with Global => null,
        Pre    =>
          (Executable => Is_Absorbing (St) and then Output_Length (St) = 64,
           Static     =>
             In_Progress
               (St, Pr, P, S, K, X, Field_First (P, S, K, X, Id))),
        Post   =>
          (Executable => Is_Absorbing (St) and then Output_Length (St) = 64,
           Static     =>
             In_Progress
               (St, Pr, P, S, K, X, Field_First (P, S, K, X, Id) + 4));

   --  Absorbs Chunk (0 .. Count - 1), the bytes Offset .. Offset + Count
   --  - 1 of input Id, the next bytes of the message.
   procedure Absorb_Chunk
     (St            : in out State;
      Pr            : Parameters;
      P, S, K, X    : Byte_Array;
      Id            : Input_Number;
      Offset, Count : Length;
      Chunk         : Chunk_Buffer)
   with Global => null,
        Pre    =>
          (Executable =>
             Is_Absorbing (St)
             and then Output_Length (St) = 64
             and then Count in 1 .. Chunk_Bytes
             and then Offset <= Input_Length (P, S, K, X, Id)
             and then Count <= Input_Length (P, S, K, X, Id) - Offset,
           Static     =>
             (for all J in I64 range 0 .. I64 (Count) - 1 =>
                Chunk (J)
                = Selected_Byte (Id, P, S, K, X, I64 (Offset) + J))
             and then In_Progress
                        (St, Pr, P, S, K, X,
                         Input_First (P, S, K, X, Id) + I64 (Offset))),
        Post   =>
          (Executable => Is_Absorbing (St) and then Output_Length (St) = 64,
           Static     =>
             In_Progress
               (St, Pr, P, S, K, X,
                Input_First (P, S, K, X, Id) + I64 (Offset + Count)));

   --  Absorbs input Id, the next piece of the message, in chunks.
   procedure Absorb_Input
     (St         : in out State;
      Pr         : Parameters;
      P, S, K, X : Byte_Array;
      Id         : Input_Number)
   with Global => null,
        Pre    =>
          (Executable => Is_Absorbing (St) and then Output_Length (St) = 64,
           Static     =>
             In_Progress
               (St, Pr, P, S, K, X, Input_First (P, S, K, X, Id))),
        Post   =>
          (Executable => Is_Absorbing (St) and then Output_Length (St) = 64,
           Static     =>
             In_Progress
               (St, Pr, P, S, K, X,
                Input_First (P, S, K, X, Id)
                + Lengths_Of (P, S, K, X) (Id)));

   --  Final, once the whole message is absorbed.
   procedure Finish
     (St         : in out State;
      Pr         : Parameters;
      P, S, K, X : Byte_Array;
      Digest     : out Blake2b.Byte_Array)
   with Global => null,
        Pre    =>
          (Executable =>
             Is_Absorbing (St)
             and then Output_Length (St) = 64
             and then Digest'Length = 64,
           Static     =>
             Same_Context
               (Model (St),
                Prefix (Pr, P, S, K, X, Call_Length (P, S, K, X)))),
        Post   =>
          (Executable => Is_Finalized (St),
           Static     =>
             Digest
             = Logical_Hash
                 (Blake2b.No_Bytes, Call_C (Pr, P, S, K, X),
                  Call_Pieces (P, S, K, X), Call_Length (P, S, K, X), 64));

   --  Copies and streaming absorption process caller input. Stack
   --  scrubbing covers their frames, including compiler-created spills.
   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   pragma Machine_Attribute (Store_LE32, "strub", "internal");
   pragma Machine_Attribute (Store_LE32, "zero_call_used_regs", "all");
   pragma Machine_Attribute (Copy_Chunk, "strub", "internal");
   pragma Machine_Attribute (Copy_Chunk, "zero_call_used_regs", "all");
   pragma Machine_Attribute (Copy_Input, "strub", "internal");
   pragma Machine_Attribute (Copy_Input, "zero_call_used_regs", "all");
   pragma Machine_Attribute (Absorb_Field, "strub", "internal");
   pragma Machine_Attribute (Absorb_Field, "zero_call_used_regs", "all");
   pragma Machine_Attribute (Absorb_Chunk, "strub", "internal");
   pragma Machine_Attribute (Absorb_Chunk, "zero_call_used_regs", "all");
   pragma Machine_Attribute (Absorb_Input, "strub", "internal");
   pragma Machine_Attribute (Absorb_Input, "zero_call_used_regs", "all");
   pragma Machine_Attribute (Finish, "strub", "internal");
   pragma Machine_Attribute (Finish, "zero_call_used_regs", "all");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");

   procedure Store_LE32 (Value : U32; Bytes : out Blake2b.Byte_Array) is
   begin
      Bytes :=
        [Byte (Value mod 2**8), Byte ((Value / 2**8) mod 2**8),
         Byte ((Value / 2**16) mod 2**8), Byte (Value / 2**24)];
   end Store_LE32;

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
         --  Static: proved, not executed (it would make each chunk's
         --  copy quadratic in builds with assertions enabled).
         pragma Loop_Invariant
           (Static =>
              (for all K in Chunk_Offset range 0 .. J =>
                 Chunk (K) = Input (Start + Long_Long_Integer (K))));
      end loop;
   end Copy_Chunk;

   procedure Copy_Input
     (P, S, K, X : Byte_Array;
      Id         : Input_Number;
      Offset     : Length;
      Count      : Length;
      Chunk      : in out Chunk_Buffer)
   is
      Last : constant I64 := I64 (Count) - 1;
   begin
      case Id is
         when 10 => Copy_Chunk (P, Offset, Chunk (0 .. Last));
         when 11 => Copy_Chunk (S, Offset, Chunk (0 .. Last));
         when 12 => Copy_Chunk (K, Offset, Chunk (0 .. Last));
         when 13 => Copy_Chunk (X, Offset, Chunk (0 .. Last));
      end case;
   end Copy_Input;

   procedure Absorb_Field
     (St         : in out State;
      Pr         : Parameters;
      P, S, K, X : Byte_Array;
      Id         : Field_Number)
   is
      Bytes  : Blake2b.Byte_Array (0 .. 3);
      Before : constant Inc.Context := Model (St) with Ghost => Static;
   begin
      Store_LE32 (Field_Value (Pr, P, S, K, X, Id), Bytes);
      Lemma_Fields_Of
        (Pr.Parallelism, Pr.Tag_Length, Pr.Memory, Pr.Passes, Pr.Version,
         Pr.Kind, P, S, K, X);
      --  The value is the model's field, and its bytes are little-endian:
      --  two ground facts, so that a wrong field or a wrong byte order
      --  fails here, quickly, rather than inside a quantified goal.
      pragma Assert
        (Static =>
           Field_Value (Pr, P, S, K, X, Id)
           = Fields_Of (Pr.Parallelism, Pr.Tag_Length, Pr.Memory, Pr.Passes,
                        Pr.Version, Pr.Kind, P, S, K, X) (Id));
      pragma Assert
        (Static =>
           Bytes (0) = LE_Byte (Field_Value (Pr, P, S, K, X, Id), 0)
           and then Bytes (1) = LE_Byte (Field_Value (Pr, P, S, K, X, Id), 1)
           and then Bytes (2) = LE_Byte (Field_Value (Pr, P, S, K, X, Id), 2)
           and then Bytes (3)
                    = LE_Byte (Field_Value (Pr, P, S, K, X, Id), 3));
      Lemma_Field_Chunk
        (Pr.Parallelism, Pr.Tag_Length, Pr.Memory, Pr.Passes, Pr.Version,
         Pr.Kind, P, S, K, X, Id, Bytes);
      Lemma_Step
        (Before, Pr, P, S, K, X, Field_First (P, S, K, X, Id), Bytes);
      Blake2b.Streaming.Example.Lemma_Room
        (St, Blake2b.No_Bytes, Field_First (P, S, K, X, Id), 4);
      Update (St, Bytes);
      Lemma_Same_Context (Model (St), Inc.Update (Before, Bytes));
      Argon2id.Wipe.Bytes (Bytes);
      pragma Assert (for all I in Bytes'Range => Bytes (I) = 0);
   end Absorb_Field;

   procedure Absorb_Chunk
     (St            : in out State;
      Pr            : Parameters;
      P, S, K, X    : Byte_Array;
      Id            : Input_Number;
      Offset, Count : Length;
      Chunk         : Chunk_Buffer)
   is
      Last   : constant I64 := I64 (Count) - 1;
      Before : constant Inc.Context := Model (St) with Ghost => Static;
   begin
      Lemma_Input_Chunk
        (Pr.Parallelism, Pr.Tag_Length, Pr.Memory, Pr.Passes, Pr.Version,
         Pr.Kind, P, S, K, X, Id, I64 (Offset), Chunk (0 .. Last));
      Lemma_Step
        (Before, Pr, P, S, K, X, Input_First (P, S, K, X, Id) + I64 (Offset),
         Chunk (0 .. Last));
      Blake2b.Streaming.Example.Lemma_Room
        (St, Blake2b.No_Bytes, Input_First (P, S, K, X, Id) + I64 (Offset),
         I64 (Count));
      Update (St, Chunk (0 .. Last));
      Lemma_Same_Context (Model (St), Inc.Update (Before, Chunk (0 .. Last)));
   end Absorb_Chunk;

   procedure Absorb_Input
     (St         : in out State;
      Pr         : Parameters;
      P, S, K, X : Byte_Array;
      Id         : Input_Number)
   is
      Total  : constant Length := Input_Length (P, S, K, X, Id);
      Chunk  : Chunk_Buffer := [others => 0];
      Offset : Length := 0;
   begin
      while Offset < Total loop
         pragma Loop_Invariant (Offset <= Total);
         pragma Loop_Invariant
           (Is_Absorbing (St) and then Output_Length (St) = 64);
         pragma Loop_Invariant
           (Static =>
              In_Progress
                (St, Pr, P, S, K, X,
                 Input_First (P, S, K, X, Id) + I64 (Offset)));
         pragma Loop_Variant (Decreases => Total - Offset);
         declare
            Count : constant Length :=
              Length'Min (Chunk_Bytes, Total - Offset);
         begin
            Copy_Input (P, S, K, X, Id, Offset, Count, Chunk);
            Absorb_Chunk (St, Pr, P, S, K, X, Id, Offset, Count, Chunk);
            Offset := Offset + Count;
         end;
      end loop;
      pragma Assert (Static => I64 (Offset) = Lengths_Of (P, S, K, X) (Id));
      Argon2id.Wipe.Bytes (Chunk);
      pragma Assert (for all I in Chunk'Range => Chunk (I) = 0);
   end Absorb_Input;

   --  Transitivity of array equality, in a small proof context.
   procedure Lemma_Eq_Trans (A, B, C : Blake2b.Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => A = B and then B = C,
        Post   => A = C
   is
   begin
      null;
   end Lemma_Eq_Trans;

   procedure Finish
     (St         : in out State;
      Pr         : Parameters;
      P, S, K, X : Byte_Array;
      Digest     : out Blake2b.Byte_Array)
   is
      Last : constant Inc.Context := Model (St) with Ghost => Static;
   begin
      pragma Assert (Static => Last.NN = 64);
      Lemma_Final_Of
        (Last, Blake2b.No_Bytes, Call_C (Pr, P, S, K, X),
         Call_Pieces (P, S, K, X), Call_Length (P, S, K, X));
      Final (St, Digest);
      Lemma_Eq_Trans
        (Digest, Inc.Final (Last),
         Logical_Hash
           (Blake2b.No_Bytes, Call_C (Pr, P, S, K, X),
            Call_Pieces (P, S, K, X), Call_Length (P, S, K, X), Last.NN));
   end Finish;

   procedure Compute
     (Password, Salt, Secret, Associated_Data : Byte_Array;
      Parallelism, Tag_Length, Memory, Passes, Version, Kind :
        Interfaces.Unsigned_32;
      Digest : out Blake2b.Byte_Array)
   is
      Pr : constant Parameters :=
        (Parallelism => Parallelism, Tag_Length => Tag_Length,
         Memory => Memory, Passes => Passes, Version => Version,
         Kind => Kind);
      St : State;
   begin
      Init (St, 64, Blake2b.No_Bytes);
      Lemma_Init
        (Blake2b.No_Bytes,
         Call_C (Pr, Password, Salt, Secret, Associated_Data),
         Call_Pieces (Password, Salt, Secret, Associated_Data),
         Call_Length (Password, Salt, Secret, Associated_Data), 64);
      Lemma_Same_Context (Model (St), Inc.Init (Blake2b.No_Bytes, 64));
      Lemma_Same_Context
        (Prefix (Pr, Password, Salt, Secret, Associated_Data, 0),
         Inc.Init (Blake2b.No_Bytes, 64));
      --  The pieces in RFC 9106's order: the ten fields, each length
      --  field (6 .. 9) followed by its input (10 .. 13).
      for Id in Field_Number loop
         pragma Loop_Invariant
           (Is_Absorbing (St) and then Output_Length (St) = 64);
         pragma Loop_Invariant
           (Static =>
              In_Progress
                (St, Pr, Password, Salt, Secret, Associated_Data,
                 Field_First (Password, Salt, Secret, Associated_Data, Id)));
         Lemma_Next (Password, Salt, Secret, Associated_Data, Id);
         Absorb_Field (St, Pr, Password, Salt, Secret, Associated_Data, Id);
         if Id >= 6 then
            Absorb_Input
              (St, Pr, Password, Salt, Secret, Associated_Data, Id + 4);
         end if;
      end loop;
      pragma Warnings
        (GNATprove, Off, """St"" is set by ""Finish"" but not used*",
         Reason => "the state is finalized and wiped; only Digest is used");
      Finish (St, Pr, Password, Salt, Secret, Associated_Data, Digest);
      pragma Warnings
        (GNATprove, On, """St"" is set by ""Finish"" but not used*");
   end Compute;

end Argon2id.H0;
