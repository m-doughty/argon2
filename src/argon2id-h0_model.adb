--  Copyright (c) 2026, Matt Doughty
--  SPDX-License-Identifier: BSD-3-Clause

with Blake2b.Streaming.Consistency;

--  The proofs of the H0 model. Static ghost code: proved by GNATprove,
--  never compiled.

package body Argon2id.H0_Model
  with SPARK_Mode
is

   procedure Lemma_Field_Piece (L : Input_Lengths; Id : Field_Id) is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", H0_Original);
   begin
      null;
   end Lemma_Field_Piece;

   procedure Lemma_Input_Piece (L : Input_Lengths; Id : Input_Id) is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", H0_Original);
   begin
      null;
   end Lemma_Input_Piece;

   --  Inside field Id's piece, Byte_At is the field's byte.
   procedure Lemma_Field_At
     (C   : Contents;
      L   : Input_Lengths;
      F   : Fields32;
      Id  : Field_Id;
      Pos : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => H0_Realizes (C, L, F)
                  and then Pos >= Field_Start (L, Id)
                  and then Pos - Field_Start (L, Id) <= 3,
        Post   => Byte_At (C, H0_Original (L), H0_Length (L), Pos)
                  = LE_Byte (F (Id), Pos - Field_Start (L, Id))
   is
   begin
      Lemma_Field_Piece (L, Id);
      Lemma_Absolute
        (C, H0_Original (L), H0_Length (L), Pos, Field_Piece (Id));
   end Lemma_Field_At;

   --  Inside input Id's piece, Byte_At is the input's byte.
   procedure Lemma_Input_At
     (C   : Contents;
      L   : Input_Lengths;
      Id  : Input_Id;
      Pos : I64)
   with Ghost  => Static,
        Global => null,
        Pre    => Has_Contents (C)
                  and then Pos >= Input_Start (L, Id)
                  and then Pos - Input_Start (L, Id) < L (Id),
        Post   => Byte_At (C, H0_Original (L), H0_Length (L), Pos)
                  = C (Id, Pos - Input_Start (L, Id))
   is
   begin
      Lemma_Input_Piece (L, Id);
      Lemma_Absolute
        (C, H0_Original (L), H0_Length (L), Pos, Input_Piece (Id));
   end Lemma_Input_At;

   procedure Lemma_Byte_Position
     (C   : Contents;
      L   : Input_Lengths;
      F   : Fields32;
      Pos : I64) is
   begin
      if Pos >= H0_Length (L) then
         Lemma_Padding (C, H0_Original (L), H0_Length (L), Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 4 then
         Lemma_Field_At (C, L, F, 0, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 8 then
         Lemma_Field_At (C, L, F, 1, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 12 then
         Lemma_Field_At (C, L, F, 2, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 16 then
         Lemma_Field_At (C, L, F, 3, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 20 then
         Lemma_Field_At (C, L, F, 4, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 24 then
         Lemma_Field_At (C, L, F, 5, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 28 then
         Lemma_Field_At (C, L, F, 6, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 28 + L (10) then
         Lemma_Input_At (C, L, 10, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 32 + L (10) then
         Lemma_Field_At (C, L, F, 7, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 32 + L (10) + L (11) then
         Lemma_Input_At (C, L, 11, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 36 + L (10) + L (11) then
         Lemma_Field_At (C, L, F, 8, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 36 + L (10) + L (11) + L (12) then
         Lemma_Input_At (C, L, 12, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      elsif Pos < 40 + L (10) + L (11) + L (12) then
         Lemma_Field_At (C, L, F, 9, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      else
         Lemma_Input_At (C, L, 13, Pos);
         pragma Assert
           (Byte_At (C, H0_Original (L), H0_Length (L), Pos)
            = H0_Byte (C, L, F, Pos));
      end if;
   end Lemma_Byte_Position;

   procedure Lemma_All_Positions
     (C : Contents;
      L : Input_Lengths;
      F : Fields32) is
   begin
      for Pos in I64 range 0 .. Max_Length + 127 loop
         Lemma_Byte_Position (C, L, F, Pos);
         pragma Loop_Invariant
           (for all Q in I64 range 0 .. Pos =>
              Byte_At (C, H0_Original (L), H0_Length (L), Q)
              = H0_Byte (C, L, F, Q));
      end loop;
   end Lemma_All_Positions;

   procedure Lemma_Extremes is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", H0_Original);
   begin
      null;
   end Lemma_Extremes;

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
   is
      --  Off, Src and From appear only in the contract.
      pragma Unreferenced (Off, Src, From);
   begin
      for J in I64 range 0 .. Data'Length - 1 loop
         Lemma_Absolute (C, M, Length, At_Pos + J, I);
         pragma Loop_Invariant
           (for all Q in I64 range 0 .. J =>
              Data (Data'First + Q) = Byte_At (C, M, Length, At_Pos + Q));
      end loop;
   end Lemma_Slice;

   procedure Lemma_Fields_Of
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Fields_Of);
   begin
      null;
   end Lemma_Fields_Of;

   procedure Lemma_Field_Byte
     (F          : Fields32;
      P, S, K, X : Byte_Array;
      Id         : Field_Id)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", H0_Contents);
   begin
      null;
   end Lemma_Field_Byte;

   procedure Lemma_Input_Byte
     (F          : Fields32;
      P, S, K, X : Byte_Array;
      Id         : Input_Id)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", H0_Contents);
   begin
      null;
   end Lemma_Input_Byte;

   procedure Lemma_Contents
     (F          : Fields32;
      P, S, K, X : Byte_Array) is
   begin
      for Id in Field_Id loop
         Lemma_Field_Byte (F, P, S, K, X, Id);
         pragma Loop_Invariant
           (for all I in Field_Id range 0 .. Id =>
              (for all J in Source_Position range 0 .. 3 =>
                 H0_Contents (F, P, S, K, X) (I, J) = LE_Byte (F (I), J)));
      end loop;
   end Lemma_Contents;

   --  One byte of a call's contents: a field's byte ...
   procedure Lemma_Call_Field_Byte
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Id         : Field_Id;
      J          : Source_Position)
   with Ghost  => Static,
        Global => null,
        Pre    => J <= 3,
        Post   => Call_Contents (Parallelism, Tag_Length, Memory, Passes,
                                 Version, Kind, P, S, K, X) (Id, J)
                  = LE_Byte
                      (Fields_Of (Parallelism, Tag_Length, Memory, Passes,
                                  Version, Kind, P, S, K, X) (Id), J)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", H0_Contents);
   begin
      null;
   end Lemma_Call_Field_Byte;

   --  ... or an input's byte.
   procedure Lemma_Call_Input_Byte
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Id         : Input_Id;
      J          : Source_Position)
   with Ghost  => Static,
        Global => null,
        Post   => Call_Contents (Parallelism, Tag_Length, Memory, Passes,
                                 Version, Kind, P, S, K, X) (Id, J)
                  = Selected_Byte (Id, P, S, K, X, J)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", H0_Contents);
   begin
      null;
   end Lemma_Call_Input_Byte;

   --  A field's four bytes, and a run of an input's bytes, as bytes of a
   --  call's contents, collected one at a time in a small proof context.
   procedure Lemma_Field_Run
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
        Post   => (for all J in I64 range 0 .. 3 =>
                     Data (Data'First + J)
                     = Call_Contents
                         (Parallelism, Tag_Length, Memory, Passes, Version,
                          Kind, P, S, K, X) (Id, J))
   is
   begin
      for J in I64 range 0 .. 3 loop
         pragma Assert
           (Data (Data'First + J)
            = LE_Byte
                (Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                            Kind, P, S, K, X) (Id), J));
         Lemma_Call_Field_Byte
           (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
            P, S, K, X, Id, J);
         pragma Loop_Invariant
           (for all Q in I64 range 0 .. J =>
              Data (Data'First + Q)
              = Call_Contents
                  (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
                   P, S, K, X) (Id, Q));
      end loop;
   end Lemma_Field_Run;

   procedure Lemma_Input_Run
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
        Post   => (for all J in I64 range 0 .. Data'Length - 1 =>
                     Data (Data'First + J)
                     = Call_Contents
                         (Parallelism, Tag_Length, Memory, Passes, Version,
                          Kind, P, S, K, X) (Id, Off + J))
   is
   begin
      for J in I64 range 0 .. Data'Length - 1 loop
         pragma Assert
           (Data (Data'First + J) = Selected_Byte (Id, P, S, K, X, Off + J));
         Lemma_Call_Input_Byte
           (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
            P, S, K, X, Id, Off + J);
         pragma Loop_Invariant
           (for all Q in I64 range 0 .. J =>
              Data (Data'First + Q)
              = Call_Contents
                  (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
                   P, S, K, X) (Id, Off + Q));
      end loop;
   end Lemma_Input_Run;

   procedure Lemma_Chunk_At
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Pos        : Offset;
      Data       : Blake2b.Byte_Array)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Chunk_At);
   begin
      null;
   end Lemma_Chunk_At;

   --  Realizes for a call's message is Chunk_At.
   procedure Lemma_Chunk_Of
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Pos        : Offset;
      Data       : Blake2b.Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => Pos <= Call_Length (P, S, K, X)
                  and then Realizes
                             (Call_Contents (Parallelism, Tag_Length, Memory,
                                             Passes, Version, Kind,
                                             P, S, K, X),
                              Call_Pieces (P, S, K, X),
                              Call_Length (P, S, K, X),
                              Pos, Data),
        Post   => Chunk_At (Parallelism, Tag_Length, Memory, Passes, Version,
                            Kind, P, S, K, X, Pos, Data)
   is
      pragma Annotate
        (GNATprove, Unhide_Info, "Expression_Function_Body", Chunk_At);
   begin
      null;
   end Lemma_Chunk_Of;

   procedure Lemma_Field_Chunk
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Id         : Field_Id;
      Data       : Blake2b.Byte_Array)
   is
   begin
      Lemma_Field_Piece (Lengths_Of (P, S, K, X), Id);
      Lemma_Field_Run
        (Parallelism, Tag_Length, Memory, Passes, Version, Kind, P, S, K, X,
         Id, Data);
      Lemma_Slice
        (Call_Contents (Parallelism, Tag_Length, Memory, Passes, Version,
                        Kind, P, S, K, X),
         Call_Pieces (P, S, K, X),
         Call_Length (P, S, K, X),
         Field_Piece (Id), 0, Field_Start (Lengths_Of (P, S, K, X), Id),
         Id, 0, Data);
      Lemma_Chunk_Of
        (Parallelism, Tag_Length, Memory, Passes, Version, Kind, P, S, K, X,
         Field_Start (Lengths_Of (P, S, K, X), Id), Data);
   end Lemma_Field_Chunk;

   procedure Lemma_Input_Chunk
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array;
      Id         : Input_Id;
      Off        : Offset;
      Data       : Blake2b.Byte_Array)
   is
   begin
      Lemma_Input_Piece (Lengths_Of (P, S, K, X), Id);
      Lemma_Input_Run
        (Parallelism, Tag_Length, Memory, Passes, Version, Kind, P, S, K, X,
         Id, Off, Data);
      Lemma_Slice
        (Call_Contents (Parallelism, Tag_Length, Memory, Passes, Version,
                        Kind, P, S, K, X),
         Call_Pieces (P, S, K, X),
         Call_Length (P, S, K, X),
         Input_Piece (Id), Off,
         Input_Start (Lengths_Of (P, S, K, X), Id) + Off, Id, Off, Data);
      Lemma_Chunk_Of
        (Parallelism, Tag_Length, Memory, Passes, Version, Kind, P, S, K, X,
         Input_Start (Lengths_Of (P, S, K, X), Id) + Off, Data);
   end Lemma_Input_Chunk;

   procedure Lemma_Spec_Hash
     (C : Contents;
      L : Input_Lengths;
      F : Fields32) is
   begin
      for Pos in I64 range 0 .. H0_Length (L) - 1 loop
         Lemma_Byte_Position (C, L, F, Pos);
         pragma Loop_Invariant
           (for all Q in I64 range 0 .. Pos =>
              Serialised (C, L, F) (Q)
              = Byte_At (C, H0_Original (L), H0_Length (L), Q));
      end loop;
      pragma Assert
        (Realizes
           (C, H0_Original (L), H0_Length (L), 0, Serialised (C, L, F)));
      Blake2b.Streaming.Consistency.Lemma_Consistent
        (Blake2b.No_Bytes, C, H0_Original (L), H0_Length (L),
         Serialised (C, L, F), 64);
   end Lemma_Spec_Hash;

   --  A call's length fields are its input lengths.
   procedure Lemma_Fields_Consistent
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Post   => Consistent
                    (Lengths_Of (P, S, K, X),
                     Fields_Of (Parallelism, Tag_Length, Memory, Passes,
                                Version, Kind, P, S, K, X))
   is
   begin
      Lemma_Fields_Of
        (Parallelism, Tag_Length, Memory, Passes, Version, Kind, P, S, K, X);
      pragma Assert
        (Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
                    P, S, K, X) (6) = U32 (P'Length)
         and then Fields_Of (Parallelism, Tag_Length, Memory, Passes,
                             Version, Kind, P, S, K, X) (7) = U32 (S'Length)
         and then Fields_Of (Parallelism, Tag_Length, Memory, Passes,
                             Version, Kind, P, S, K, X) (8) = U32 (K'Length)
         and then Fields_Of (Parallelism, Tag_Length, Memory, Passes,
                             Version, Kind, P, S, K, X) (9)
                  = U32 (X'Length));
      pragma Assert
        (Lengths_Of (P, S, K, X) (10) = P'Length
         and then Lengths_Of (P, S, K, X) (11) = S'Length
         and then Lengths_Of (P, S, K, X) (12) = K'Length
         and then Lengths_Of (P, S, K, X) (13) = X'Length);
   end Lemma_Fields_Consistent;

   --  H0_Hash is the logical hash it names.
   procedure Lemma_H0_Hash
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array)
   with Ghost  => Static,
        Global => null,
        Post   => H0_Hash (Parallelism, Tag_Length, Memory, Passes, Version,
                           Kind, P, S, K, X)
                  = Logical_Hash
                      (Blake2b.No_Bytes,
                       Call_Contents (Parallelism, Tag_Length, Memory,
                                      Passes, Version, Kind, P, S, K, X),
                       H0_Original (Lengths_Of (P, S, K, X)),
                       H0_Length (Lengths_Of (P, S, K, X)), 64)
   is
   begin
      null;
   end Lemma_H0_Hash;

   --  Transitivity of array equality, in a small proof context.
   procedure Lemma_Eq_Trans (A, B, C : Blake2b.Byte_Array)
   with Ghost  => Static,
        Global => null,
        Pre    => A = B and then B = C,
        Post   => A = C
   is
   begin
      null;
   end Lemma_Eq_Trans;

   procedure Lemma_H0_Spec_Hash
     (Parallelism, Tag_Length, Memory, Passes, Version, Kind : U32;
      P, S, K, X : Byte_Array) is
   begin
      Lemma_Fields_Consistent
        (Parallelism, Tag_Length, Memory, Passes, Version, Kind, P, S, K, X);
      Lemma_Contents
        (Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
                    P, S, K, X),
         P, S, K, X);
      Lemma_Spec_Hash
        (Call_Contents (Parallelism, Tag_Length, Memory, Passes, Version,
                        Kind, P, S, K, X),
         Lengths_Of (P, S, K, X),
         Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
                    P, S, K, X));
      Lemma_H0_Hash
        (Parallelism, Tag_Length, Memory, Passes, Version, Kind, P, S, K, X);
      Lemma_Eq_Trans
        (H0_Hash (Parallelism, Tag_Length, Memory, Passes, Version, Kind,
                  P, S, K, X),
         Logical_Hash
           (Blake2b.No_Bytes,
            Call_Contents (Parallelism, Tag_Length, Memory, Passes,
                           Version, Kind, P, S, K, X),
            H0_Original (Lengths_Of (P, S, K, X)),
            H0_Length (Lengths_Of (P, S, K, X)), 64),
         Blake2b.Spec.Hash
           (Serialised
              (Call_Contents (Parallelism, Tag_Length, Memory, Passes,
                              Version, Kind, P, S, K, X),
               Lengths_Of (P, S, K, X),
               Fields_Of (Parallelism, Tag_Length, Memory, Passes, Version,
                          Kind, P, S, K, X)),
            Blake2b.No_Bytes, 64));
   end Lemma_H0_Spec_Hash;

end Argon2id.H0_Model;
