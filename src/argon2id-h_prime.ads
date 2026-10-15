--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package Argon2id.H_Prime
  with SPARK_Mode
is
   --  RFC 9106 section 3.3. The output length is encoded as LE32 before
   --  hashing the input. H' accepts 1-byte outputs; the complete Argon2
   --  algorithm has a separate minimum tag length of 4 bytes.
   --
   --  Arrays may have arbitrary bounds. Input and Digest must not
   --  overlap: SPARK's anti-aliasing rules enforce this for SPARK callers.
   --  Scratch storage is bounded independently of either array's length.
   procedure Hash (Input : Byte_Array; Digest : out Byte_Array)
   with Global => null,
        Pre => Digest'Length >= 1;

private
   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   pragma Machine_Attribute (Hash, "strub", "internal");
   pragma Machine_Attribute (Hash, "zero_call_used_regs", "all");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");
end Argon2id.H_Prime;
