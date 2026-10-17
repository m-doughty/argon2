--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

--  A plain transcription of RFC 9106 section 3.6, independent of the
--  library, for the driver of scripts/check-exception-stack.sh: it gives
--  the values the compression computes after its permutation, so that
--  they can be looked for on the stack. The driver checks it against the
--  library's own output (G (X, Y) = Permute (X xor Y) xor X xor Y) before
--  using it.

with Stack_Probe; use Stack_Probe;

package Blamka_Reference is

   --  P applied to the eight rows of R (words 16 I .. 16 I + 15), then to
   --  the eight columns (words 2 I, 2 I + 1, 2 I + 16, 2 I + 17, ...,
   --  2 I + 112, 2 I + 113). R'Length must be 128.
   function Permute (R : Word_Array) return Word_Array
   with Pre => R'First = 0 and then R'Length = 128;

end Blamka_Reference;
