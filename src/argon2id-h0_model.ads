--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Interfaces;

with Blake2b;
with Blake2b.Spec;
with Blake2b.Streaming;
with Blake2b.Streaming.Theory;

--  RFC 9106 section 3.2's H0 input as a logical message of
--  Blake2b.Streaming:
--
--     H0 = H^(64)(LE32(p) || LE32(T) || LE32(m) || LE32(t) ||
--                 LE32(v) || LE32(y) || LE32(length(P)) || P ||
--                 LE32(length(S)) || S || LE32(length(K)) || K ||
--                 LE32(length(X)) || X)
--
--  * Sources 0 .. 9 hold the ten 32-bit fields, little-endian, in this
--    order: p, T, m, t, v, y, length (P), length (S), length (K),
--    length (X). Sources 10 .. 13 hold P, S, K and X. m is the memory
--    parameter as given, not the rounded m'.
--  * H0_Original lists the fourteen pieces in the RFC's order, and
--    H0_Length is 40 plus the four input lengths: at most 2**34 + 36
--    bytes, Blake2b.Streaming.Max_Length.
--  * H0_Byte reads byte Pos of the message straight off the formula, by
--    running offsets, without the schedule. Lemma_Byte_Position and
--    Lemma_All_Positions prove the schedule gives the same byte at every
--    position (the model is the RFC's message); Lemma_Extremes covers
--    every input empty and every input 2**32 - 1 bytes long.
--  * Lemma_Slice is the bridge from arrays to the model: any array whose
--    bytes are a run of one piece's source realizes its place in the
--    message, wherever the run is cut. Lemma_Field_Chunk and
--    Lemma_Input_Chunk apply it to a call's fields and input chunks.
--  * H0_Contents builds the sources from the caller's arguments, and
--    H0_Hash is the digest Argon2id.H0.Compute is proved to return.
--  * Serialised is the message as one array, byte by byte off the
--    formula; Lemma_Spec_Hash and Lemma_H0_Spec_Hash tie the logical hash
--    to Blake2b.Spec.Hash of it whenever it fits one array (2**31 bytes).
--
--  Static ghost code: GNATprove proves it, and no build ever compiles it.
--  Every declaration is marked static ghost, and deliberately not the
--  package itself, so that its object file still holds one symbol, the
--  package's elaboration flag (a library member with no symbols makes
--  macOS ranlib warn).

package Argon2id.H0_Model
  with SPARK_Mode, Pure
is
   use Blake2b.Streaming;
   use Blake2b.Streaming.Theory;
   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_32;
   use type Blake2b.I64;
   use type Blake2b.Byte_Array;

   subtype U32 is Interfaces.Unsigned_32 with Ghost => Static;
   subtype I64 is Blake2b.I64 with Ghost => Static;

   --  The ten 32-bit fields and the four inputs, as sources.
   subtype Field_Id is Source_Id range 0 .. 9 with Ghost => Static;
   subtype Input_Id is Source_Id range 10 .. 13 with Ghost => Static;

   type Fields32 is array (Field_Id) of U32 with Ghost => Static;
   type Input_Lengths is array (Input_Id) of Source_Position
   with Ghost => Static;

   --  Fields 6 .. 9 are the lengths of inputs 10 .. 13.
   function Consistent (L : Input_Lengths; F : Fields32) return Boolean is
     (for all Id in Input_Id => F (Id - 4) = U32 (L (Id)))
   with Ghost => Static;

   function H0_Length (L : Input_Lengths) return Offset is
     (40 + L (10) + L (11) + L (12) + L (13))
   with Ghost => Static;

   --  Byte J of Field, little-endian.
   function LE_Byte (Field : U32; J : Source_Position) return Byte is
     (case J is
        when 0      => Byte (Field mod 2**8),
        when 1      => Byte ((Field / 2**8) mod 2**8),
        when 2      => Byte ((Field / 2**16) mod 2**8),
        when others => Byte (Field / 2**24))
   with Ghost => Static,
        Pre   => J <= 3;

   ----------------------------------------------------------------------
   --  The schedule
   ----------------------------------------------------------------------

   subtype H0_Index is Positive range 1 .. 14 with Ghost => Static;
   subtype H0_Pieces is Pieces (H0_Index) with Ghost => Static;

   --  The pieces in the RFC's order: fields 0 .. 6, P, field 7, S,
   --  field 8, K, field 9, X. Each starts at position 0 of its source.
   function H0_Original (L : Input_Lengths) return H0_Pieces is
     ([1  => (Source => 0, Start => 0, Count => 4, First => 0),
       2  => (Source => 1, Start => 0, Count => 4, First => 4),
       3  => (Source => 2, Start => 0, Count => 4, First => 8),
       4  => (Source => 3, Start => 0, Count => 4, First => 12),
       5  => (Source => 4, Start => 0, Count => 4, First => 16),
       6  => (Source => 5, Start => 0, Count => 4, First => 20),
       7  => (Source => 6, Start => 0, Count => 4, First => 24),
       8  => (Source => 10, Start => 0, Count => L (10), First => 28),
       9  => (Source => 7, Start => 0, Count => 4, First => 28 + L (10)),
       10 => (Source => 11, Start => 0, Count => L (11),
              First => 32 + L (10)),
       11 => (Source => 8, Start => 0, Count => 4,
              First => 32 + L (10) + L (11)),
       12 => (Source => 12, Start => 0, Count => L (12),
              First => 36 + L (10) + L (11)),
       13 => (Source => 9, Start => 0, Count => 4,
              First => 36 + L (10) + L (11) + L (12)),
       14 => (Source => 13, Start => 0, Count => L (13),
              First => 40 + L (10) + L (11) + L (12))])
   with Ghost => Static,
        Post  => Valid (H0_Original'Result, H0_Length (L));

   pragma Annotate
     (GNATprove, Hide_Info, "Expression_Function_Body", H0_Original);
   --  Hidden from the provers, which otherwise unfold all fourteen pieces
   --  into every proof that names the schedule; opened by
   --  Lemma_Field_Piece, Lemma_Input_Piece and Lemma_Extremes.

   --  Where field Id and input Id start in the message, by running
   --  offsets.
   function Field_Start (L : Input_Lengths; Id : Field_Id) return Offset is
     (if Id <= 6 then 4 * I64 (Id)
      elsif Id = 7 then 28 + L (10)
      elsif Id = 8 then 32 + L (10) + L (11)
      else 36 + L (10) + L (11) + L (12))
   with Ghost => Static;

   function Input_Start (L : Input_Lengths; Id : Input_Id) return Offset is
     (case Id is
        when 10 => 28,
        when 11 => 32 + L (10),
        when 12 => 36 + L (10) + L (11),
        when 13 => 40 + L (10) + L (11) + L (12))
   with Ghost => Static;

   --  The piece of field Id, and of input Id.
   function Field_Piece (Id : Field_Id) return H0_Index is
     (if Id <= 6 then Id + 1 else 2 * Id - 5)
   with Ghost => Static;

   function Input_Piece (Id : Input_Id) return H0_Index is
     (2 * Id - 12)
   with Ghost => Static;

   procedure Lemma_Field_Piece (L : Input_Lengths; Id : Field_Id)
   with Ghost  => Static,
        Global => null,
        Post   => H0_Original (L) (Field_Piece (Id)).Source = Id
                  and then H0_Original (L) (Field_Piece (Id)).Start = 0
                  and then H0_Original (L) (Field_Piece (Id)).Count = 4
                  and then H0_Original (L) (Field_Piece (Id)).First
                           = Field_Start (L, Id);

   procedure Lemma_Input_Piece (L : Input_Lengths; Id : Input_Id)
   with Ghost  => Static,
        Global => null,
        Post   => H0_Original (L) (Input_Piece (Id)).Source = Id
                  and then H0_Original (L) (Input_Piece (Id)).Start = 0
                  and then H0_Original (L) (Input_Piece (Id)).Count
                           = L (Id)
                  and then H0_Original (L) (Input_Piece (Id)).First
                           = Input_Start (L, Id);

   --  The sources hold the fields: field Id is source Id's first four
   --  bytes, little-endian. (Nothing constrains a source past the bytes
   --  the schedule reads.)
   function H0_Realizes
     (C : Contents;
      L : Input_Lengths;
      F : Fields32) return Boolean
   is
     (Has_Contents (C)
      and then Consistent (L, F)
      and then (for all Id in Field_Id =>
                  (for all J in Source_Position range 0 .. 3 =>
                     C (Id, J) = LE_Byte (F (Id), J))))
   with Ghost => Static;

   ----------------------------------------------------------------------
   --  The byte-position lemma
   ----------------------------------------------------------------------

   --  Byte Pos of the H0 input, read off RFC 9106's formula by running
   --  offsets, independently of the schedule; zero from H0_Length on
   --  (BLAKE2b's padding).
   function H0_Byte
     (C   : Contents;
      L   : Input_Lengths;
      F   : Fields32;
      Pos : I64) return Byte
   is
     (if Pos < 4 then LE_Byte (F (0), Pos)
      elsif Pos < 8 then LE_Byte (F (1), Pos - 4)
      elsif Pos < 12 then LE_Byte (F (2), Pos - 8)
      elsif Pos < 16 then LE_Byte (F (3), Pos - 12)
      elsif Pos < 20 then LE_Byte (F (4), Pos - 16)
      elsif Pos < 24 then LE_Byte (F (5), Pos - 20)
      elsif Pos < 28 then LE_Byte (F (6), Pos - 24)
      elsif Pos < 28 + L (10) then C (10, Pos - 28)
      elsif Pos < 32 + L (10) then LE_Byte (F (7), Pos - 28 - L (10))
      elsif Pos < 32 + L (10) + L (11) then C (11, Pos - 32 - L (10))
      elsif Pos < 36 + L (10) + L (11)
      then LE_Byte (F (8), Pos - 32 - L (10) - L (11))
      elsif Pos < 36 + L (10) + L (11) + L (12)
      then C (12, Pos - 36 - L (10) - L (11))
      elsif Pos < 40 + L (10) + L (11) + L (12)
      then LE_Byte (F (9), Pos - 36 - L (10) - L (11) - L (12))
      elsif Pos < 40 + L (10) + L (11) + L (12) + L (13)
      then C (13, Pos - 40 - L (10) - L (11) - L (12))
      else 0)
   with Ghost => Static,
        Pre   => Has_Contents (C) and then Pos in 0 .. Max_Length + 127;

   --  At position Pos, the schedule's byte is the formula's.
   procedure Lemma_Byte_Position
     (C   : Contents;
      L   : Input_Lengths;
      F   : Fields32;
      Pos : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => H0_Realizes (C, L, F) and then Pos in 0 .. Max_Length + 127,
        Post   => Byte_At (C, H0_Original (L), H0_Length (L), Pos)
                  = H0_Byte (C, L, F, Pos);

   --  The same at every position, padding included.
   procedure Lemma_All_Positions
     (C : Contents;
      L : Input_Lengths;
      F : Fields32)
   with Ghost  => Static,
        Global => null,
        Pre    => H0_Realizes (C, L, F),
        Post   => (for all Pos in I64 range 0 .. Max_Length + 127 =>
                     Byte_At (C, H0_Original (L), H0_Length (L), Pos)
                     = H0_Byte (C, L, F, Pos));

   --  The extremes: with every input empty the message is the 40 bytes of
   --  fields (four empty pieces); with every input 2**32 - 1 bytes long
   --  it is Max_Length = 2**34 + 36 bytes. Both schedules are valid.
   Empty_Lengths : constant Input_Lengths := [others => 0]
   with Ghost => Static;
   Full_Lengths : constant Input_Lengths := [others => 2**32 - 1]
   with Ghost => Static;

   procedure Lemma_Extremes
   with Ghost  => Static,
        Global => null,
        Post   => H0_Length (Empty_Lengths) = 40
                  and then Valid (H0_Original (Empty_Lengths), 40)
                  and then (for all I in H0_Index =>
                              (if H0_Original (Empty_Lengths) (I).Source
                                  in Input_Id
                               then H0_Original (Empty_Lengths) (I).Count
                                    = 0))
                  and then H0_Length (Full_Lengths) = Max_Length
                  and then Valid (H0_Original (Full_Lengths), Max_Length);

   ----------------------------------------------------------------------
   --  The bridge from arrays
   ----------------------------------------------------------------------

   --  Data holds bytes Off .. Off + Data'Length - 1 of piece I's run of
   --  its source, whatever Data's bounds: then it holds the logical bytes
   --  from At_Pos = M (I).First + Off on. Any array cut from a piece
   --  qualifies, however the piece is cut. (Src and From name the source
   --  and its first position, so that the premise on Data does not
   --  mention M.)
   procedure Lemma_Slice
     (C      : Contents;
      M      : Pieces;
      Length : Offset;
      I      : Positive;
      Off    : Offset;
      At_Pos : Offset;
      Src    : Source_Id;
      From   : Source_Position;
      Data   : Blake2b.Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Has_Contents (C)
                  and then Valid (M, Length)
                  and then I in M'Range
                  and then Off <= M (I).Count
                  and then Data'Length <= M (I).Count - Off
                  and then At_Pos = M (I).First + Off
                  and then Src = M (I).Source
                  and then From = M (I).Start + Off
                  and then (for all J in I64 range 0 .. Data'Length - 1 =>
                              Data (Data'First + J) = C (Src, From + J)),
        Post   => Realizes (C, M, Length, At_Pos, Data);

   ----------------------------------------------------------------------
   --  The sources of a call's arguments
   ----------------------------------------------------------------------

   --  Byte J of A, zero past its end.
   function Input_Byte (A : Byte_Array; J : Source_Position) return Byte is
     (if J < A'Length then A (A'First + Long_Long_Integer (J)) else 0)
   with Ghost => Static;

   --  Byte J of input Id.
   function Selected_Byte
     (Id         : Input_Id;
      P, S, K, X : Byte_Array;
      J          : Source_Position) return Byte
   is
     (case Id is
        when 10 => Input_Byte (P, J),
        when 11 => Input_Byte (S, J),
        when 12 => Input_Byte (K, J),
        when 13 => Input_Byte (X, J))
   with Ghost => Static;

   function Lengths_Of (P, S, K, X : Byte_Array) return Input_Lengths is
     ([10 => P'Length, 11 => S'Length, 12 => K'Length, 13 => X'Length])
   with Ghost => Static;

   function Fields_Of
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array) return Fields32
   is
     ([0 => Parallelism, 1 => Tag_Length, 2 => Memory, 3 => Passes,
       4 => Version, 5 => Kind,
       6 => U32 (P'Length), 7 => U32 (S'Length),
       8 => U32 (K'Length), 9 => U32 (X'Length)])
   with Ghost => Static;
   --  Hidden from the provers, which otherwise unfold the aggregate into
   --  every proof about a call's contents; opened by Lemma_Fields_Of.
   pragma Annotate
     (GNATprove, Hide_Info, "Expression_Function_Body", Fields_Of);

   procedure Lemma_Fields_Of
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Post   =>
          Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                     Kind, P, S, K, X) (0) = Parallelism
          and then Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                              Kind, P, S, K, X) (1) = Tag_Length
          and then Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                              Kind, P, S, K, X) (2) = Memory
          and then Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                              Kind, P, S, K, X) (3) = Passes
          and then Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                              Kind, P, S, K, X) (4) = Version
          and then Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                              Kind, P, S, K, X) (5) = Kind
          and then Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                              Kind, P, S, K, X) (6) = U32 (P'Length)
          and then Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                              Kind, P, S, K, X) (7) = U32 (S'Length)
          and then Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                              Kind, P, S, K, X) (8) = U32 (K'Length)
          and then Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                              Kind, P, S, K, X) (9) = U32 (X'Length);

   --  The fourteen sources of a call: the fields F, then P, S, K and X.
   --  Hidden from the provers; opened one byte at a time by
   --  Lemma_Field_Byte and Lemma_Input_Byte.
   function H0_Contents (F : Fields32; P, S, K, X : Byte_Array)
      return Contents
   is
     ([for Id in Source_Id =>
         [for J in Source_Position =>
            (if Id in Field_Id
             then (if J <= 3 then LE_Byte (F (Id), J) else 0)
             else Selected_Byte (Id, P, S, K, X, J))]])
   with Ghost => Static,
        Post  => Has_Contents (H0_Contents'Result);
   pragma Annotate
     (GNATprove, Hide_Info, "Expression_Function_Body", H0_Contents);

   --  Field Id's source is the field, little-endian.
   procedure Lemma_Field_Byte
     (F          : Fields32;
      P, S, K, X : Byte_Array;
      Id         : Field_Id)
   with Ghost  => Static,
        Global => null,
        Post   => (for all J in Source_Position range 0 .. 3 =>
                     H0_Contents (F, P, S, K, X) (Id, J)
                     = LE_Byte (F (Id), J));

   --  Input Id's source is that input, zero past its end.
   procedure Lemma_Input_Byte
     (F          : Fields32;
      P, S, K, X : Byte_Array;
      Id         : Input_Id)
   with Ghost  => Static,
        Global => null,
        Post   => (for all J in Source_Position =>
                     H0_Contents (F, P, S, K, X) (Id, J)
                     = Selected_Byte (Id, P, S, K, X, J));

   --  A call's sources realize its fields.
   procedure Lemma_Contents
     (F          : Fields32;
      P, S, K, X : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Consistent (Lengths_Of (P, S, K, X), F),
        Post   => H0_Realizes
                    (H0_Contents (F, P, S, K, X), Lengths_Of (P, S, K, X), F);

   --  The logical message of a call.
   function Call_Contents
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array) return Contents
   is
     (H0_Contents
        (Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
                    P, S, K, X),
         P, S, K, X))
   with Ghost => Static;

   function Call_Pieces (P, S, K, X : Byte_Array) return H0_Pieces is
     (H0_Original (Lengths_Of (P, S, K, X)))
   with Ghost => Static;

   function Call_Length (P, S, K, X : Byte_Array) return Offset is
     (H0_Length (Lengths_Of (P, S, K, X)))
   with Ghost => Static;

   --  Data holds the bytes of a call's message from position Pos on:
   --  Realizes for the call's message. Hidden from the provers, so that
   --  the client's proofs pass it along by matching it whole rather than
   --  by instantiating its quantifier; opened by Lemma_Chunk_At.
   function Chunk_At
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Pos        : Offset;
      Data       : Blake2b.Byte_Array) return Boolean
   is
     (Realizes
        (Call_Contents (Parallelism, Tag_Length, Memory, Passes, Version,
                        Kind, P, S, K, X),
         Call_Pieces (P, S, K, X),
         Call_Length (P, S, K, X),
         Pos, Data))
   with Ghost => Static,
        Pre   => Pos <= Call_Length (P, S, K, X);
   pragma Annotate
     (GNATprove, Hide_Info, "Expression_Function_Body", Chunk_At);

   procedure Lemma_Chunk_At
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Pos        : Offset;
      Data       : Blake2b.Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Pos <= Call_Length (P, S, K, X)
                  and then Chunk_At (Parallelism, Tag_Length, Memory, Passes,
                                     Version, Kind, P, S, K, X, Pos, Data),
        Post   => Realizes
                    (Call_Contents (Parallelism, Tag_Length, Memory, Passes,
                                    Version, Kind, P, S, K, X),
                     Call_Pieces (P, S, K, X),
                     Call_Length (P, S, K, X),
                     Pos, Data);

   --  The bridge for a call: four bytes holding field Id little-endian
   --  are that field's place in the message ...
   procedure Lemma_Field_Chunk
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Id         : Field_Id;
      Data       : Blake2b.Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Data'Length = 4
                  and then (for all J in I64 range 0 .. 3 =>
                              Data (Data'First + J)
                              = LE_Byte
                                  (Fields_Of (Parallelism, Tag_Length, Memory,
                                              Passes, Version, Kind,
                                              P, S, K, X) (Id), J)),
        Post   => Field_Start (Lengths_Of (P, S, K, X), Id) + 4
                  <= Call_Length (P, S, K, X)
                  and then Chunk_At
                             (Parallelism, Tag_Length, Memory, Passes,
                              Version, Kind, P, S, K, X,
                              Field_Start (Lengths_Of (P, S, K, X), Id),
                              Data);

   --  ... and any run of input Id's bytes, from Off, is its place: each
   --  chunk of an input, however the input is cut.
   procedure Lemma_Input_Chunk
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Id         : Input_Id;
      Off        : Offset;
      Data       : Blake2b.Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Off <= Lengths_Of (P, S, K, X) (Id)
                  and then Data'Length <= Lengths_Of (P, S, K, X) (Id) - Off
                  and then (for all J in I64 range 0 .. Data'Length - 1 =>
                              Data (Data'First + J)
                              = Selected_Byte (Id, P, S, K, X, Off + J)),
        Post   => Input_Start (Lengths_Of (P, S, K, X), Id) + Off
                  + Data'Length <= Call_Length (P, S, K, X)
                  and then Chunk_At
                             (Parallelism, Tag_Length, Memory, Passes,
                              Version, Kind, P, S, K, X,
                              Input_Start (Lengths_Of (P, S, K, X), Id) + Off,
                              Data);

   ----------------------------------------------------------------------
   --  The digest, and the explicit bytes when they fit one array
   ----------------------------------------------------------------------

   subtype Digest_64 is Blake2b.Byte_Array (0 .. 63) with Ghost => Static;

   --  RFC 9106's H0 of a call's arguments: BLAKE2b-512, unkeyed, of the
   --  logical message. A total function, with no precondition: the
   --  postconditions of H0_Contents (Has_Contents) and H0_Original (Valid)
   --  discharge Logical_Hash's (OK) for every argument, and GNATprove
   --  checks that they do.
   function H0_Hash
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array) return Digest_64
   is
     (Logical_Hash
        (Blake2b.No_Bytes,
         Call_Contents (Parallelism, Tag_Length, Memory, Passes, Version,
                        Kind, P, S, K, X),
         Call_Pieces (P, S, K, X),
         Call_Length (P, S, K, X),
         64))
   with Ghost => Static;

   --  The message's bytes as one array, read off the formula.
   function Serialised
     (C : Contents;
      L : Input_Lengths;
      F : Fields32) return Blake2b.Byte_Array
   is
     ([for Pos in 0 .. H0_Length (L) - 1 => H0_Byte (C, L, F, Pos)])
   with Ghost => Static,
        Pre   => Has_Contents (C) and then H0_Length (L) <= 2**31;

   --  Wherever one array holds the message, the logical hash is
   --  Blake2b.Spec.Hash of the explicit bytes.
   procedure Lemma_Spec_Hash
     (C : Contents;
      L : Input_Lengths;
      F : Fields32)
   with Ghost  => Static,
        Global => null,
        Pre    => H0_Realizes (C, L, F) and then H0_Length (L) <= 2**31,
        Post   => Logical_Hash
                    (Blake2b.No_Bytes, C, H0_Original (L), H0_Length (L), 64)
                  = Blake2b.Spec.Hash
                      (Serialised (C, L, F), Blake2b.No_Bytes, 64);

   --  The same for a call's arguments: H0_Hash is Spec.Hash of the
   --  serialised H0 input whenever it is at most 2**31 bytes.
   procedure Lemma_H0_Spec_Hash
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Call_Length (P, S, K, X) <= 2**31,
        Post   => H0_Hash (Parallelism, Tag_Length, Memory, Passes, Version,
                           Kind, P, S, K, X)
                  = Blake2b.Spec.Hash
                      (Serialised
                         (Call_Contents (Parallelism, Tag_Length, Memory,
                                         Passes, Version, Kind, P, S, K, X),
                          Lengths_Of (P, S, K, X),
                          Fields_Of (Parallelism, Tag_Length, Memory,
                                     Passes, Version, Kind, P, S, K, X)),
                       Blake2b.No_Bytes, 64);

end Argon2id.H0_Model;
