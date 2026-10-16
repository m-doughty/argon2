--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b;
with Blake2b.Spec;

--  RFC 9106 section 3.3: the variable-length hash H', for an output of T
--  bytes and an input A of at most 1024 bytes (all Argon2 ever hashes).
--
--     T <= 64:  H'(A) = H^T (LE32 (T) || A)
--     T  > 64:  r = ceil (T / 32) - 2
--               V_1 = H^64 (LE32 (T) || A),  V_i = H^64 (V_(i-1))  (i <= r)
--               H'(A) = first 32 bytes of V_1 || ... || first 32 bytes of V_r
--                       || V_(r+1),   V_(r+1) = H^(T - 32 r) (V_r)
--
--  where H^N is BLAKE2b with an N-byte digest and no key. The last link
--  has a digest length of T - 32 r (33 .. 64) bytes; it is not a
--  truncation of a 64-byte digest.
--
--  * Message is LE32 (T) || A as one array, exactly as the RFC writes it.
--  * V is the chain, by recursion on the index (the proof relates a loop's
--    k-th value to V (A, T, k + 1), it never unfolds 2**27 steps), and
--    Tail is V_(r+1).
--  * Out_Byte gives byte P of H' directly, so that no array of up to
--    2**32 - 1 bytes is ever built: callers (initialisation and the tag)
--    ask for the bytes they need.
--
--  Message, V and Tail hide their bodies from GNATprove by default (the
--  provers compose them as opaque functions); the implementation reveals
--  each one only where it proves a step about it.
--
--  Static ghost code: GNATprove proves it, and no build ever compiles it.
--  Every declaration is marked static ghost, and deliberately not the
--  package itself, so that its object file still holds one symbol, the
--  package's elaboration flag.

package Argon2.H_Prime_Model
  with SPARK_Mode, Pure
is
   use type Blake2b.I64;

   --  The longest input Argon2 gives H'.
   Max_Input : constant := 1_024;

   subtype Output_Length is Long_Long_Integer range 1 .. 2**32 - 1
     with Ghost => Static;

   --  r is at most 2**27 - 2, so V_1 .. V_(r+1) have indices up to 2**27.
   subtype Chain_Index is Long_Long_Integer range 1 .. 2**27
     with Ghost => Static;

   --  One link of the chain: a 64-byte digest.
   subtype Link is Blake2b.Byte_Array (0 .. 63)
     with Ghost => Static;

   --  Section 3.3: the 4-byte little-endian output length.
   function LE32 (T : Output_Length) return Blake2b.Byte_Array
   is ([Byte (T mod 256), Byte ((T / 256) mod 256),
        Byte ((T / 65_536) mod 256), Byte ((T / 16_777_216) mod 256)])
   with Ghost => Static,
        Post  => LE32'Result'First = 0 and then LE32'Result'Last = 3;

   --  LE32 (T) || A, indexed from 0.
   function Message
     (Input : Blake2b.Byte_Array; T : Output_Length)
      return Blake2b.Byte_Array
   is ([for I in 0 .. Input'Length + 3 =>
          (if I < 4 then LE32 (T) (I) else Input (Input'First + (I - 4)))])
   with Ghost => Static,
        Pre   => Input'Length <= Max_Input,
        Post  => Message'Result'First = 0
                 and then Message'Result'Length = Input'Length + 4;
   pragma Annotate
     (GNATprove, Hide_Info, "Expression_Function_Body", Message);

   --  r = ceil (T / 32) - 2: the number of full 32-byte pieces.
   function R (T : Output_Length) return Long_Long_Integer
   is ((T + 31) / 32 - 2)
   with Ghost => Static,
        Pre   => T > 64,
        Post  => R'Result in 1 .. 2**27 - 2;

   --  V_I of the chain.
   function V
     (Input : Blake2b.Byte_Array; T : Output_Length; I : Chain_Index)
      return Link
   is (if I = 1
       then Blake2b.Spec.Hash (Message (Input, T), Blake2b.No_Bytes, 64)
       else Blake2b.Spec.Hash (V (Input, T, I - 1), Blake2b.No_Bytes, 64))
   with Ghost              => Static,
        Pre                => Input'Length <= Max_Input and then T > 64
                              and then I <= R (T),
        Subprogram_Variant => (Decreases => I);
   pragma Annotate (GNATprove, Hide_Info, "Expression_Function_Body", V);

   --  V_(r+1): BLAKE2b with a digest length of T - 32 r (not truncated).
   function Tail
     (Input : Blake2b.Byte_Array; T : Output_Length)
      return Blake2b.Byte_Array
   is (Blake2b.Spec.Hash
         (V (Input, T, R (T)), Blake2b.No_Bytes,
          Blake2b.I64 (T - 32 * R (T))))
   with Ghost => Static,
        Pre   => Input'Length <= Max_Input and then T > 64,
        Post  => Tail'Result'First = 0
                 and then Tail'Result'Length = T - 32 * R (T);
   pragma Annotate (GNATprove, Hide_Info, "Expression_Function_Body", Tail);

   --  Byte P of H' (0 <= P < T).
   function Out_Byte
     (Input : Blake2b.Byte_Array; T : Output_Length; P : Long_Long_Integer)
      return Byte
   is (if T <= 64
       then Blake2b.Spec.Hash
              (Message (Input, T), Blake2b.No_Bytes, Blake2b.I64 (T))
              (Blake2b.I64 (P))
       elsif P < 32 * R (T)
       then V (Input, T, P / 32 + 1) (Blake2b.I64 (P mod 32))
       else Tail (Input, T) (Blake2b.I64 (P - 32 * R (T))))
   with Ghost => Static,
        Pre   => Input'Length <= Max_Input and then P in 0 .. T - 1;
end Argon2.H_Prime_Model;
