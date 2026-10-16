--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  The helpers' contracts have two parts: Executable, checked at run time
--  in builds with assertions enabled (-gnata) and proved; Static, proved
--  and never compiled (it names the model of RFC 9106 section 3.3, which
--  exists only for the proof).
pragma Assertion_Level (Executable);

with Argon2.Wipe;
with Blake2b.Spec;
with Blake2b.Spec.Incremental;

package body Argon2.H_Prime
  with SPARK_Mode
is
   use type Blake2b.I64;
   use type Blake2b.Byte_Array;

   use Blake2b.Hashing;
   package Model renames Argon2.H_Prime_Model;

   subtype Length is Long_Long_Integer range 0 .. 2**32 - 1;

   --  The two unfoldings of the model's chain that the loop uses.
   procedure Lemma_V_First
     (Input : Blake2b.Byte_Array; T : Model.Output_Length)
   with Ghost => Static,
        Global => null,
        Pre => Input'Length <= Max_Input_Bytes and then T > 64,
        Post => Model.V (Input, T, 1)
                = Blake2b.Spec.Hash
                    (Model.Message (Input, T), Blake2b.No_Bytes, 64)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Model.V);
   begin
      null;
   end Lemma_V_First;

   procedure Lemma_V_Next
     (Input : Blake2b.Byte_Array; T : Model.Output_Length;
      I : Model.Chain_Index)
   with Ghost => Static,
        Global => null,
        Pre => Input'Length <= Max_Input_Bytes and then T > 64
               and then I in 2 .. Model.R (T),
        Post => Model.V (Input, T, I)
                = Blake2b.Spec.Hash
                    (Model.V (Input, T, I - 1), Blake2b.No_Bytes, 64)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Model.V);
   begin
      null;
   end Lemma_V_Next;

   procedure Lemma_Tail
     (Input : Blake2b.Byte_Array; T : Model.Output_Length)
   with Ghost => Static,
        Global => null,
        Pre => Input'Length <= Max_Input_Bytes and then T > 64,
        Post => Model.Tail (Input, T)
                = Blake2b.Spec.Hash
                    (Model.V (Input, T, Model.R (T)), Blake2b.No_Bytes,
                     Blake2b.I64 (T - 32 * Model.R (T)))
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Model.Tail);
   begin
      null;
   end Lemma_Tail;

   --  Array equality reaches the provers element by element, and they will
   --  not substitute equal arrays into an opaque function such as
   --  Spec.Hash. Same is logical equality, which they do substitute;
   --  Lemma_Same converts (as in Blake2b.Core).
   function Same (L, R : Chain) return Boolean is (L = R)
   with Ghost    => Static,
        Global   => null,
        Annotate => (GNATprove, Logical_Equal);

   procedure Lemma_Same (L, R : Chain)
   with Ghost  => Static,
        Global => null,
        Pre    => L = R,
        Post   => Same (L, R)
   is
   begin
      null;
   end Lemma_Same;

   --  Byte P of the model's output, in the three places it lives.
   procedure Lemma_Out_Short
     (Input : Blake2b.Byte_Array; T : Model.Output_Length; P : Length)
   with Ghost => Static,
        Global => null,
        Pre => Input'Length <= Max_Input_Bytes and then T <= 64
               and then P in 0 .. T - 1,
        Post => Model.Out_Byte (Input, T, P)
                = Blake2b.Spec.Hash
                    (Model.Message (Input, T), Blake2b.No_Bytes,
                     Blake2b.I64 (T)) (Blake2b.I64 (P))
   is
   begin
      null;
   end Lemma_Out_Short;

   procedure Lemma_Out_Chain
     (Input : Blake2b.Byte_Array; T : Model.Output_Length; P : Length)
   with Ghost => Static,
        Global => null,
        Pre => Input'Length <= Max_Input_Bytes and then T > 64
               and then P in 0 .. 32 * Model.R (T) - 1,
        Post => Model.Out_Byte (Input, T, P)
                = Model.V (Input, T, P / 32 + 1) (Blake2b.I64 (P mod 32))
   is
   begin
      null;
   end Lemma_Out_Chain;

   procedure Lemma_Out_Tail
     (Input : Blake2b.Byte_Array; T : Model.Output_Length; P : Length)
   with Ghost => Static,
        Global => null,
        Pre => Input'Length <= Max_Input_Bytes and then T > 64
               and then P in 32 * Model.R (T) .. T - 1,
        Post => Model.Out_Byte (Input, T, P)
                = Model.Tail (Input, T)
                    (Blake2b.I64 (P - 32 * Model.R (T)))
   is
   begin
      null;
   end Lemma_Out_Tail;

   --  The first P bytes of Digest are the model's.
   function Prefix_Done
     (Input : Blake2b.Byte_Array; Digest : Byte_Array;
      T : Model.Output_Length; P : Length) return Boolean
   is (for all Q in Long_Long_Integer range 0 .. P - 1 =>
         Digest (Digest'First + Q) = Model.Out_Byte (Input, T, Q))
   with Ghost => Static,
        Pre => Digest'Length = T and then P <= T
               and then Input'Length <= Max_Input_Bytes;

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

   procedure Initial_Hash
     (S : out Blake2b.Hashing.State;
      Input : Blake2b.Byte_Array; Output_Length : Length;
      Digest : out Blake2b.Byte_Array)
   with Global => null,
        Pre => Output_Length >= 1 and then Digest'Length in 1 .. 64
          and then Input'Length <= Max_Input_Bytes,
        Post =>
          (Executable => Blake2b.Hashing.Is_Finalized (S),
           Static     =>
             Digest
             = Blake2b.Spec.Hash
                 (Model.Message (Input, Output_Length), Blake2b.No_Bytes,
                  Digest'Length));

   --  BLAKE2b of the 64-byte chain value V, as long as Digest.
   procedure Rehash
     (S : out Blake2b.Hashing.State;
      V : Chain; Digest : out Blake2b.Byte_Array)
   with Global => null,
        Pre => Digest'Length in 1 .. 64,
        Post =>
          (Executable => Blake2b.Hashing.Is_Finalized (S),
           Static     =>
             Digest = Blake2b.Spec.Hash (V, Blake2b.No_Bytes, Digest'Length));

   --  Streaming absorption processes caller input. Stack scrubbing covers
   --  its frame, including compiler-created spills.
   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   pragma Machine_Attribute (Initial_Hash, "strub", "internal");
   pragma Machine_Attribute (Initial_Hash, "zero_call_used_regs", "all");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");

   procedure Initial_Hash
     (S : out Blake2b.Hashing.State;
      Input : Blake2b.Byte_Array; Output_Length : Length;
      Digest : out Blake2b.Byte_Array)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Model.Message);
      Prefix : Blake2b.Byte_Array (0 .. 3) := LE32 (Output_Length);
      Joined : constant Blake2b.Byte_Array :=
        Model.Message (Input, Output_Length) with Ghost => Static;
   begin
      pragma Assert (Static => Prefix = Model.LE32 (Output_Length));
      Blake2b.Hashing.Init (S, Digest'Length, Blake2b.No_Bytes);
      pragma Assert
        (Static => Has_Absorbed (S, Blake2b.No_Bytes, Blake2b.No_Bytes));
      Lemma_Update (S, Blake2b.No_Bytes, Blake2b.No_Bytes, Prefix, Prefix);
      Blake2b.Hashing.Update (S, Prefix);
      pragma Assert (Static => Has_Absorbed (S, Blake2b.No_Bytes, Prefix));
      pragma Assert
        (Static =>
           Blake2b.Spec.Incremental.Is_Concatenation (Joined, Prefix, Input));
      Lemma_Update (S, Blake2b.No_Bytes, Prefix, Input, Joined);
      Blake2b.Hashing.Update (S, Input);
      pragma Assert (Static => Has_Absorbed (S, Blake2b.No_Bytes, Joined));
      Lemma_Final (S, Blake2b.No_Bytes, Joined);
      Blake2b.Hashing.Final (S, Digest);
      pragma Assert (Blake2b.Hashing.Is_Finalized (S));
      Argon2.Wipe.Bytes (Prefix);
      pragma Assert (for all I in Prefix'Range => Prefix (I) = 0);
   end Initial_Hash;

   procedure Rehash
     (S : out Blake2b.Hashing.State;
      V : Chain; Digest : out Blake2b.Byte_Array)
   is
   begin
      Blake2b.Hashing.Init (S, Digest'Length, Blake2b.No_Bytes);
      pragma Assert
        (Static => Has_Absorbed (S, Blake2b.No_Bytes, Blake2b.No_Bytes));
      Lemma_Update (S, Blake2b.No_Bytes, Blake2b.No_Bytes, V, V);
      Blake2b.Hashing.Update (S, V);
      pragma Assert (Static => Has_Absorbed (S, Blake2b.No_Bytes, V));
      Lemma_Final (S, Blake2b.No_Bytes, V);
      Blake2b.Hashing.Final (S, Digest);
   end Rehash;

   --  The three ways bytes are copied from a link into Digest. Each is a
   --  small proof of its own: the loop facts stay out of Hash.

   --  T <= 64: V (0 .. T - 1) is the whole output.
   procedure Copy_Short
     (Input : Blake2b.Byte_Array; T : Model.Output_Length;
      V : Chain; Digest : in out Byte_Array)
   with Global => null,
        Pre =>
          (Executable =>
             Digest'Length = T and then T <= 64
             and then Input'Length <= Max_Input_Bytes,
           Static     =>
             V (0 .. Blake2b.I64 (T) - 1)
             = Blake2b.Spec.Hash
                 (Model.Message (Input, T), Blake2b.No_Bytes,
                  Blake2b.I64 (T))),
        Post => (Static => Prefix_Done (Input, Digest, T, T))
   is
   begin
      for J in 0 .. T - 1 loop
         Lemma_Out_Short (Input, T, J);
         Digest (Digest'First + J) := V (Blake2b.I64 (J));
         pragma Loop_Invariant
           (Static => Prefix_Done (Input, Digest, T, J + 1));
      end loop;
   end Copy_Short;

   --  Written < T - 64: the 32 bytes of the link V_(Written / 32 + 1).
   procedure Copy_Piece
     (Input : Blake2b.Byte_Array; T : Model.Output_Length;
      Written : Length; V : Chain; Digest : in out Byte_Array)
   with Global => null,
        Pre =>
          (Executable =>
             Digest'Length = T and then T > 64 and then Written mod 32 = 0
             and then Written + 64 < T
             and then Input'Length <= Max_Input_Bytes,
           Static     =>
             Written / 32 + 1 <= Model.R (T)
             and then V = Model.V (Input, T, Written / 32 + 1)
             and then Prefix_Done (Input, Digest, T, Written)),
        Post => (Static => Prefix_Done (Input, Digest, T, Written + 32))
   is
   begin
      for J in Long_Long_Integer range 0 .. 31 loop
         pragma Assert (Static => (Written + J) / 32 = Written / 32);
         pragma Assert (Static => (Written + J) mod 32 = J);
         Lemma_Out_Chain (Input, T, Written + J);
         Digest (Digest'First + Written + J) := V (Blake2b.I64 (J));
         pragma Loop_Invariant
           (Static =>
              (for all Q in Long_Long_Integer range 0 .. Written + J =>
                 Digest (Digest'First + Q)
                 = Model.Out_Byte (Input, T, Q)));
      end loop;
   end Copy_Piece;

   --  The last link: T - Written bytes of Tail.
   procedure Copy_Tail
     (Input : Blake2b.Byte_Array; T : Model.Output_Length;
      Written : Length; Next_V : Chain; Digest : in out Byte_Array)
   with Global => null,
        Pre =>
          (Executable =>
             Digest'Length = T and then T > 64
             and then T - Written in 33 .. 64
             and then Input'Length <= Max_Input_Bytes,
           Static     =>
             Written = 32 * Model.R (T)
             and then Next_V (0 .. Blake2b.I64 (T - Written) - 1)
                      = Model.Tail (Input, T)
             and then Prefix_Done (Input, Digest, T, Written)),
        Post => (Static => Prefix_Done (Input, Digest, T, T))
   is
   begin
      for J in 0 .. T - Written - 1 loop
         Lemma_Out_Tail (Input, T, Written + J);
         Digest (Digest'First + Written + J) := Next_V (Blake2b.I64 (J));
         pragma Loop_Invariant
           (Static =>
              (for all Q in Long_Long_Integer range 0 .. Written + J =>
                 Digest (Digest'First + Q)
                 = Model.Out_Byte (Input, T, Q)));
      end loop;
   end Copy_Tail;

   procedure Hash
     (Input  : Blake2b.Byte_Array;
      Digest : out Byte_Array;
      S      : out Blake2b.Hashing.State;
      V      : out Chain;
      Next_V : out Chain)
   is
      T : constant Length := Digest'Length;
      Written : Length := 0;
   begin
      --  Every output element is initialized before any partial write.
      --  No dynamic object is sized from an input or output length.
      Digest := [others => 0];
      V := [others => 0];
      Next_V := [others => 0];
      if T <= 64 then
         Initial_Hash (S, Input, T, V (0 .. Blake2b.I64 (T) - 1));
         pragma Assert (Blake2b.Hashing.Is_Finalized (S));
         Copy_Short (Input, T, V, Digest);
      else
         Lemma_V_First (Input, T);
         Initial_Hash (S, Input, T, V);
         pragma Assert (Blake2b.Hashing.Is_Finalized (S));
         pragma Assert (Static => V = Model.V (Input, T, 1));
         --  r = ceil(T / 32) - 2; the last digest has 33 .. 64 bytes.
         --  Emit a 32-byte prefix while more than 64 bytes remain.
         while T - Written > 64 loop
            pragma Loop_Invariant (Written <= T - 33);
            pragma Loop_Invariant (Written mod 32 = 0);
            pragma Loop_Invariant (Digest'Length = T);
            pragma Loop_Invariant
              (Static =>
                 Written / 32 + 1 <= Model.R (T)
                 and then V = Model.V (Input, T, Written / 32 + 1)
                 and then Prefix_Done (Input, Digest, T, Written));
            pragma Loop_Variant (Decreases => T - Written);
            Copy_Piece (Input, T, Written, V, Digest);
            Written := Written + 32;
            if T - Written > 64 then
               Lemma_V_Next (Input, T, Written / 32 + 1);
               Lemma_Same (V, Model.V (Input, T, Written / 32));
               Rehash (S, V, Next_V);
               pragma Assert (Blake2b.Hashing.Is_Finalized (S));
               pragma Assert
                 (Static => Next_V = Model.V (Input, T, Written / 32 + 1));
               V := Next_V;
            end if;
         end loop;
         pragma Assert (Static => Written = 32 * Model.R (T));
         pragma Assert (Static => V = Model.V (Input, T, Model.R (T)));
         Lemma_Same (V, Model.V (Input, T, Model.R (T)));
         Lemma_Tail (Input, T);
         Rehash (S, V, Next_V (0 .. Blake2b.I64 (T - Written) - 1));
         pragma Assert (Blake2b.Hashing.Is_Finalized (S));
         Copy_Tail (Input, T, Written, Next_V, Digest);
      end if;
      pragma Assert (Blake2b.Hashing.Is_Finalized (S));
      pragma Assert (Static => Prefix_Done (Input, Digest, T, T));
      Argon2.Wipe.Bytes (V);
      pragma Assert (for all I in V'Range => V (I) = 0);
      Argon2.Wipe.Bytes (Next_V);
      pragma Assert (for all I in Next_V'Range => Next_V (I) = 0);
   end Hash;
end Argon2.H_Prime;
