--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Level (Executable);

with Interfaces;

with Argon2.H_Prime_Model;
with Blake2b;
with Blake2b.Hashing;

package Argon2.H_Prime
  with SPARK_Mode
is
   use type Interfaces.Unsigned_8;

   --  The longest input H' is given anywhere in Argon2: H0 || LE32 (block
   --  number) || LE32 (lane) is 72 bytes, and the final block of each lane
   --  is hashed as a whole 1024-byte block (RFC 9106 sections 3.2 and 3.3).
   Max_Input_Bytes : constant := 1_024;

   --  RFC 9106 section 3.3. The output length is encoded as LE32 before
   --  hashing the input. H' accepts 1-byte outputs; the complete Argon2
   --  algorithm has a separate minimum tag length of 4 bytes.
   --
   --  The input is a BLAKE2b byte array of at most Max_Input_Bytes bytes,
   --  which is all Argon2 ever hashes, so it is absorbed in one piece and
   --  no copy of it is made. Arrays may have arbitrary bounds. Input and
   --  Digest must not overlap: SPARK's anti-aliasing rules enforce this
   --  for SPARK callers.
   --
   --  Scratch: the hash state S and the two 64-byte chain values V and
   --  Next_V hold bytes derived from the input, so the caller supplies
   --  them (they may hold anything on entry) and owns their cleanup after
   --  an abnormal exit. On a normal return Hash has already wiped V and
   --  Next_V and the hash state is finalized (wiped); the postcondition
   --  says so. Their size does not depend on either length.
   --
   --  Byte P of the output is byte P of H' as Argon2.H_Prime_Model writes
   --  RFC 9106 section 3.3, for every P. That statement is proved and never
   --  compiled (Static); whether the model is the RFC is shown by the
   --  tests, against the reference and CPython.
   subtype Chain is Blake2b.Byte_Array (0 .. 63);

   procedure Hash
     (Input  : Blake2b.Byte_Array;
      Digest : out Byte_Array;
      S      : out Blake2b.Hashing.State;
      V      : out Chain;
      Next_V : out Chain)
   with Global => null,
        Pre => Digest'Length >= 1 and then Input'Length <= Max_Input_Bytes,
        Post =>
          (Executable =>
             Blake2b.Hashing.Is_Finalized (S)
             and then (for all I in V'Range => V (I) = 0)
             and then (for all I in Next_V'Range => Next_V (I) = 0),
           Static =>
             (for all P in Long_Long_Integer range 0 .. Digest'Length - 1 =>
                Digest (Digest'First + P)
                = H_Prime_Model.Out_Byte (Input, Digest'Length, P)));

private
   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   pragma Machine_Attribute (Hash, "strub", "internal");
   pragma Machine_Attribute (Hash, "zero_call_used_regs", "all");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");
end Argon2.H_Prime;
