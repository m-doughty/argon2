--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

pragma Assertion_Level (Executable);

with Argon2.Blocks; use Argon2.Blocks;
with Argon2.Compression_Model;

package Argon2.Compression
  with SPARK_Mode
is
   --  RFC 9106 sections 3.5 and 3.6: Argon2's block compression G, with
   --  BlaMka's multiplication-hardened round. A block is 128 words of 64
   --  bits (1024 bytes); this package works on words. The conversion from
   --  and to the RFC's little-endian bytes belongs to initialisation and
   --  finalisation, not here. The block types are in Argon2.Blocks.

   --  Initialisation: M may be partly uninitialised, as an uninitialised
   --  workspace is; X and Y must be initialised, Z is initialised
   --  afterwards, and no block that was initialised before becomes
   --  uninitialised.
   --
   --  M (Z) := G (M (X), M (Y)); every other block of M is unchanged.
   --  X, Y and Z may be any blocks, equal or not: the working block is
   --  filled from M (X) and M (Y) before anything is written, and the last
   --  loop reads and writes only word K at step K, so M (Z) may be M (X)
   --  or M (Y).
   --
   --  Work is scratch: one block of working space (as in the reference
   --  implementation, which keeps two), holding the mixed block while G is
   --  computed, that is, data derived from M (X) and M (Y). The caller
   --  supplies it, owns its cleanup and wipes it after the last call
   --  (Compress itself does not: it is the hot loop). It may hold anything
   --  on entry and is a separate object from M.
   procedure Compress
     (M : in out Block_Array; X, Y, Z : Block_Index; Work : out Block)
   with Relaxed_Initialization => M,
        Global                 => null,
        Pre                    =>
          X in M'Range and then Y in M'Range and then Z in M'Range
          and then M (X)'Initialized and then M (Y)'Initialized,
        Post                   =>
          (Executable =>
             (for all I in M'Range =>
                (if I = Z or else M'Old (I)'Initialized
                 then M (I)'Initialized)),
           Static     =>
             M (Z) = Argon2.Compression_Model.G (M'Old (X), M'Old (Y))
             and then
             (for all I in M'Range =>
                (if I /= Z and then M'Old (I)'Initialized
                 then M (I) = M'Old (I))));

   --  M (Z) := M (Z) xor G (M (X), M (Y)); every other block unchanged.
   --  This is the form of every pass after the first (version 1.3).
   --  The same freedom for X, Y and Z. Z must already be initialised.
   procedure Compress_Xor
     (M : in out Block_Array; X, Y, Z : Block_Index; Work : out Block)
   with Relaxed_Initialization => M,
        Global                 => null,
        Pre                    =>
          X in M'Range and then Y in M'Range and then Z in M'Range
          and then M (X)'Initialized and then M (Y)'Initialized
          and then M (Z)'Initialized,
        Post                   =>
          (Executable =>
             (for all I in M'Range =>
                (if M'Old (I)'Initialized then M (I)'Initialized)),
           Static     =>
             M (Z)
             = Argon2.Compression_Model.G_Xor
                 (M'Old (X), M'Old (Y), M'Old (Z))
             and then
             (for all I in M'Range =>
                (if I /= Z and then M'Old (I)'Initialized
                 then M (I) = M'Old (I))));
end Argon2.Compression;
