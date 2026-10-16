--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces;

package Argon2
  with SPARK_Mode, Pure
is
   subtype Byte is Interfaces.Unsigned_8;

   --  The greatest array length is 2**32 - 1. The base integer also
   --  represents lengths and one-past-end offsets without overflow.
   subtype Byte_Index is Long_Long_Integer range 0 .. 2**32 - 2;
   type Byte_Array is array (Byte_Index range <>) of Byte;
end Argon2;
