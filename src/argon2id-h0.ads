--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces;

with Blake2b;
with Argon2id.H0_Model;

package Argon2id.H0
  with SPARK_Mode
is
   use type Blake2b.Byte_Array;

   --  RFC 9106 section 3.2: the 64-byte pre-hashing digest H0, BLAKE2b-512
   --  (unkeyed) of
   --
   --     LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y) ||
   --     LE32(length(P)) || P || LE32(length(S)) || S ||
   --     LE32(length(K)) || K || LE32(length(X)) || X
   --
   --  with p = Parallelism, T = Tag_Length, m = Memory (the memory size as
   --  given, in KiB, not rounded to m'), t = Passes, v = Version,
   --  y = Kind, P = Password, S = Salt, K = Secret and
   --  X = Associated_Data. Each input may be empty or up to 2**32 - 1
   --  bytes long, with any bounds; the message is then up to
   --  2**34 + 36 bytes. The parameters are hashed as given: checking them
   --  against RFC 9106's ranges is the caller's business.
   --
   --  Proved (Static, never compiled): Digest is H0_Model.H0_Hash, the
   --  digest of the logical message H0_Model defines from the arguments;
   --  H0_Model proves that message is the formula's, byte by byte, and
   --  that its hash is Blake2b.Spec.Hash of the explicit bytes wherever
   --  they fit one array (Lemma_H0_Spec_Hash).
   procedure Compute
     (Password, Salt, Secret, Associated_Data : Byte_Array;
      Parallelism, Tag_Length, Memory, Passes, Version, Kind :
        Interfaces.Unsigned_32;
      Digest : out Blake2b.Byte_Array)
   with Global => null,
        Pre    => Digest'Length = 64,
        Post   =>
          (Static =>
             Digest
             = H0_Model.H0_Hash
                 (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
                  Password, Salt, Secret, Associated_Data));

private
   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   pragma Machine_Attribute (Compute, "strub", "internal");
   pragma Machine_Attribute (Compute, "zero_call_used_regs", "all");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");
end Argon2id.H0;
