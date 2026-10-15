--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b;

private package Argon2id.Wipe
  with SPARK_Mode, Pure
is
   use type Blake2b.Byte;

   --  These stores are retained independently of a caller's later use.
   procedure Bytes (Data : out Blake2b.Byte_Array)
   with Global => null,
        No_Inline,
        Post => (for all I in Data'Range => Data (I) = 0);

   pragma Warnings
     (GNATprove, Off, "pragma ""Machine_Attribute"" ignored*",
      Reason => "code-generation attribute: no effect on proof");
   pragma Machine_Attribute (Bytes, "noipa");
   pragma Warnings
     (GNATprove, On, "pragma ""Machine_Attribute"" ignored*");
end Argon2id.Wipe;
