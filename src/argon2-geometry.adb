--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

package body Argon2.Geometry
  with SPARK_Mode
is

   function Shape_Of (P : Lane_Count; M : Memory_KiB; T : Pass_Count)
     return Shape
   is
      Segment : constant Long_Long_Integer := M / (4 * P);
   begin
      --  m >= 8 p gives s >= 2; m <= 2**32 - 1 and p >= 1 give
      --  s <= 2**30 - 1; and m' = 4 p s <= m, the predicate's bound.
      pragma Assert (Segment >= 2);
      pragma Assert (Segment <= 2**30 - 1);
      pragma Assert (P * (4 * Segment) <= M);
      return (Lanes => P, Segment => Segment, Passes => T);
   end Shape_Of;

end Argon2.Geometry;
