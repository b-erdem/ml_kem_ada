--  FIPS 203 §4.2.1 ByteEncode_d / ByteDecode_d for the widths ML-KEM
--  uses (d = 1, 4, 10, 12).
--
--  Every encoder and decoder carries a full byte-level functional
--  postcondition (the exact bit-packing equations of its body, stated
--  per index), so the round-trip theorems
--     ByteDecode_d (ByteEncode_d (A)) = A
--  in ML_KEM.Serialize.Properties compose by contract alone.  The
--  former postconditions of the encoders ("every byte <= 255") were
--  vacuous for a byte type and have been replaced.

package ML_KEM.Serialize is

   pragma Pure;
   pragma SPARK_Mode;

   procedure ByteEncode12 (A : Polynomial; R : out Byte_Array_384)
     with
       Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. Q - 1),
       Post =>
         (for all I in 0 .. 127 =>
            R (3 * I) = U8 (U16 (A (2 * I)) and 16#FF#)
            and then R (3 * I + 1) =
              U8 (Interfaces.Shift_Right (U16 (A (2 * I)), 8)
                  or Interfaces.Shift_Left
                       (U16 (A (2 * I + 1)) and 16#F#, 4))
            and then R (3 * I + 2) =
              U8 (Interfaces.Shift_Right (U16 (A (2 * I + 1)), 4)));

   procedure ByteDecode12 (A : Byte_Array_384; R : out Polynomial)
     with Post =>
       (for all I in 0 .. N - 1 => R (I) in 0 .. 4095)
       and then
       (for all I in 0 .. 127 =>
          R (2 * I) =
            I16 (U16 (A (3 * I))
                 or Interfaces.Shift_Left
                      (U16 (A (3 * I + 1) and 16#0F#), 8))
          and then R (2 * I + 1) =
            I16 (Interfaces.Shift_Right (U16 (A (3 * I + 1)), 4)
                 or Interfaces.Shift_Left (U16 (A (3 * I + 2)), 4)));

   procedure ByteEncode1 (A : Polynomial; R : out Byte_Array_32)
     with
       Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. 1),
       Post =>
         (for all I in 0 .. 31 =>
            R (I) = (U8 (A (8 * I))
                     or Interfaces.Shift_Left (U8 (A (8 * I + 1)), 1)
                     or Interfaces.Shift_Left (U8 (A (8 * I + 2)), 2)
                     or Interfaces.Shift_Left (U8 (A (8 * I + 3)), 3)
                     or Interfaces.Shift_Left (U8 (A (8 * I + 4)), 4)
                     or Interfaces.Shift_Left (U8 (A (8 * I + 5)), 5)
                     or Interfaces.Shift_Left (U8 (A (8 * I + 6)), 6)
                     or Interfaces.Shift_Left (U8 (A (8 * I + 7)), 7)));

   procedure ByteDecode1 (A : Byte_Array_32; R : out Polynomial)
     with Post =>
       (for all I in 0 .. N - 1 => R (I) in 0 .. 1)
       and then
       (for all I in 0 .. 31 =>
          (for all J in 0 .. 7 =>
             R (8 * I + J) =
               I16 (Interfaces.Shift_Right (U16 (A (I)), J) and 1)));

   procedure ByteEncode4 (A : Polynomial; R : out Byte_Array_128)
     with
       Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. 15),
       Post =>
         (for all I in 0 .. 127 =>
            R (I) = (U8 (A (2 * I))
                     or Interfaces.Shift_Left (U8 (A (2 * I + 1)), 4)));

   procedure ByteDecode4 (A : Byte_Array_128; R : out Polynomial)
     with Post =>
       (for all I in 0 .. N - 1 => R (I) in 0 .. 15)
       and then
       (for all I in 0 .. 127 =>
          R (2 * I) = I16 (A (I) and 16#0F#)
          and then R (2 * I + 1) =
            I16 (Interfaces.Shift_Right (A (I), 4)));

   procedure ByteEncode10 (A : Polynomial; R : out Byte_Array_320)
     with
       Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. 1023),
       Post =>
         (for all I in 0 .. 31 =>
            R (10 * I) = U8 (U16 (A (8 * I)) and 16#FF#)
            and then R (10 * I + 1) =
              U8 ((Interfaces.Shift_Right (U16 (A (8 * I)), 8)
                   or Interfaces.Shift_Left (U16 (A (8 * I + 1)), 2))
                  and 16#FF#)
            and then R (10 * I + 2) =
              U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 1)), 6)
                   or Interfaces.Shift_Left (U16 (A (8 * I + 2)), 4))
                  and 16#FF#)
            and then R (10 * I + 3) =
              U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 2)), 4)
                   or Interfaces.Shift_Left (U16 (A (8 * I + 3)), 6))
                  and 16#FF#)
            and then R (10 * I + 4) =
              U8 (Interfaces.Shift_Right (U16 (A (8 * I + 3)), 2))
            and then R (10 * I + 5) = U8 (U16 (A (8 * I + 4)) and 16#FF#)
            and then R (10 * I + 6) =
              U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 4)), 8)
                   or Interfaces.Shift_Left (U16 (A (8 * I + 5)), 2))
                  and 16#FF#)
            and then R (10 * I + 7) =
              U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 5)), 6)
                   or Interfaces.Shift_Left (U16 (A (8 * I + 6)), 4))
                  and 16#FF#)
            and then R (10 * I + 8) =
              U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 6)), 4)
                   or Interfaces.Shift_Left (U16 (A (8 * I + 7)), 6))
                  and 16#FF#)
            and then R (10 * I + 9) =
              U8 (Interfaces.Shift_Right (U16 (A (8 * I + 7)), 2)));

   procedure ByteDecode10 (A : Byte_Array_320; R : out Polynomial)
     with Post =>
       (for all I in 0 .. N - 1 => R (I) in 0 .. 1023)
       and then
       (for all I in 0 .. 31 =>
          R (8 * I) =
            I16 (U16 (A (10 * I))
                 or Interfaces.Shift_Left
                      (U16 (A (10 * I + 1) and 16#03#), 8))
          and then R (8 * I + 1) =
            I16 (Interfaces.Shift_Right (U16 (A (10 * I + 1)), 2)
                 or Interfaces.Shift_Left
                      (U16 (A (10 * I + 2) and 16#0F#), 6))
          and then R (8 * I + 2) =
            I16 (Interfaces.Shift_Right (U16 (A (10 * I + 2)), 4)
                 or Interfaces.Shift_Left
                      (U16 (A (10 * I + 3) and 16#3F#), 4))
          and then R (8 * I + 3) =
            I16 (Interfaces.Shift_Right (U16 (A (10 * I + 3)), 6)
                 or Interfaces.Shift_Left (U16 (A (10 * I + 4)), 2))
          and then R (8 * I + 4) =
            I16 (U16 (A (10 * I + 5))
                 or Interfaces.Shift_Left
                      (U16 (A (10 * I + 6) and 16#03#), 8))
          and then R (8 * I + 5) =
            I16 (Interfaces.Shift_Right (U16 (A (10 * I + 6)), 2)
                 or Interfaces.Shift_Left
                      (U16 (A (10 * I + 7) and 16#0F#), 6))
          and then R (8 * I + 6) =
            I16 (Interfaces.Shift_Right (U16 (A (10 * I + 7)), 4)
                 or Interfaces.Shift_Left
                      (U16 (A (10 * I + 8) and 16#3F#), 4))
          and then R (8 * I + 7) =
            I16 (Interfaces.Shift_Right (U16 (A (10 * I + 8)), 6)
                 or Interfaces.Shift_Left (U16 (A (10 * I + 9)), 2)));

end ML_KEM.Serialize;
