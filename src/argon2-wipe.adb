--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package body Argon2.Wipe
  with SPARK_Mode
is
   procedure Bytes (Data : out Blake2b.Byte_Array) is
   begin
      Data := [others => 0];
      pragma Inspection_Point (Data);
   end Bytes;
end Argon2.Wipe;
