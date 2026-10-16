--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces;

package Argon2.Blocks
  with SPARK_Mode, Pure
is
   --  RFC 9106 section 3.4: a block is 128 words of 64 bits (1024 bytes).
   --  The conversion from and to the RFC's little-endian bytes belongs to
   --  initialisation and finalisation, not to the types.
   subtype Word is Interfaces.Unsigned_64;

   subtype Word_Index is Integer range 0 .. 127;
   type Block is array (Word_Index) of Word;

   --  At most 2**32 - 1 blocks (m' <= 2**32 - 1), as Byte_Index bounds a
   --  byte array.
   subtype Block_Index is Long_Long_Integer range 0 .. 2**32 - 2;
   type Block_Array is array (Block_Index range <>) of Block;
end Argon2.Blocks;
