--  Round-trip lemma bodies.  Pattern per width d: encode, decode,
--  then a three-rung ladder --
--    1. per-group bitvector identity: the decoder's byte expression,
--       with the encoder's byte equations substituted, collapses to
--       the original coefficient;
--    2. per-group coefficient recovery;
--    3. recombination to all N indices, stated in division form
--       (R (c*(K/c) + K mod c)) so the quantifier instantiates.

package body ML_KEM.Serialize.Properties
  with SPARK_Mode
is

   procedure Lemma_Round_Trip_12 (A : Polynomial) is
      B : Byte_Array_384;
      R : Polynomial;
   begin
      ByteEncode12 (A, B);
      ByteDecode12 (B, R);
      --  Instantiation loop: at each (symbolic) I the two contracts
      --  instantiate directly and the reassembly identity is a single
      --  unquantified bitvector goal.
      for I in 0 .. 127 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
              R (2 * J) = A (2 * J)
              and then R (2 * J + 1) = A (2 * J + 1));
         declare
            T0 : constant U16 := U16 (A (2 * I)) with Ghost;
            T1 : constant U16 := U16 (A (2 * I + 1)) with Ghost;
            B0 : constant U8  := B (3 * I) with Ghost;
            B1 : constant U8  := B (3 * I + 1) with Ghost;
            B2 : constant U8  := B (3 * I + 2) with Ghost;
         begin
            pragma Assert (T0 <= 4095 and T1 <= 4095);
            pragma Assert (B0 = U8 (T0 and 16#FF#));
            pragma Assert
              (B1 = U8 (Interfaces.Shift_Right (T0, 8)
                        or Interfaces.Shift_Left (T1 and 16#F#, 4)));
            pragma Assert (B2 = U8 (Interfaces.Shift_Right (T1, 4)));
            pragma Assert (U16 (B0) = (T0 and 16#FF#));
            pragma Assert
              (U16 (B1 and 16#0F#) = Interfaces.Shift_Right (T0, 8));
            pragma Assert
              ((U16 (B0)
                or Interfaces.Shift_Left (U16 (B1 and 16#0F#), 8))
               = T0);
            pragma Assert
              (Interfaces.Shift_Right (U16 (B1), 4) = (T1 and 16#F#));
            pragma Assert
              (U16 (B2) = Interfaces.Shift_Right (T1, 4));
            pragma Assert
              ((Interfaces.Shift_Right (U16 (B1), 4)
                or Interfaces.Shift_Left (U16 (B2), 4))
               = T1);
         end;
         pragma Assert (R (2 * I) = A (2 * I));
         pragma Assert (R (2 * I + 1) = A (2 * I + 1));
      end loop;
      pragma Assert
        (for all I in 0 .. 127 =>
           R (2 * I) = A (2 * I)
           and then R (2 * I + 1) = A (2 * I + 1));
      for K in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. K - 1 => R (J) = A (J));
         pragma Assert
           (if K mod 2 = 0 then K = 2 * (K / 2)
            else K = 2 * (K / 2) + 1);
         pragma Assert (R (K) = A (K));
      end loop;
      pragma Assert (for all K in 0 .. N - 1 => R (K) = A (K));
   end Lemma_Round_Trip_12;

   procedure Lemma_Round_Trip_1 (A : Polynomial) is
      B : Byte_Array_32;
      R : Polynomial;
   begin
      ByteEncode1 (A, B);
      ByteDecode1 (B, R);
      --  Rung 1: extracting bit J of the packed byte yields bit J.
      pragma Assert
        (for all I in 0 .. 31 =>
           (for all J in 0 .. 7 =>
              (Interfaces.Shift_Right (U16 (B (I)), J) and 1)
              = U16 (A (8 * I + J))));
      --  Rung 2.
      pragma Assert
        (for all I in 0 .. 31 =>
           (for all J in 0 .. 7 => R (8 * I + J) = A (8 * I + J)));
      --  Rung 3.
      pragma Assert
        (for all K in 0 .. N - 1 =>
           K / 8 in 0 .. 31 and then K mod 8 in 0 .. 7
           and then K = 8 * (K / 8) + K mod 8);
      pragma Assert
        (for all K in 0 .. N - 1 =>
           R (8 * (K / 8) + K mod 8) = A (8 * (K / 8) + K mod 8));
      pragma Assert (for all K in 0 .. N - 1 => R (K) = A (K));
   end Lemma_Round_Trip_1;

   procedure Lemma_Round_Trip_4 (A : Polynomial) is
      B : Byte_Array_128;
      R : Polynomial;
   begin
      ByteEncode4 (A, B);
      ByteDecode4 (B, R);
      pragma Assert (for all I in 0 .. 127 => R (2 * I) = A (2 * I));
      pragma Assert
        (for all I in 0 .. 127 => R (2 * I + 1) = A (2 * I + 1));
      pragma Assert
        (for all K in 0 .. N - 1 =>
           R (2 * (K / 2)) = A (2 * (K / 2))
           and then R (2 * (K / 2) + 1) = A (2 * (K / 2) + 1));
      pragma Assert
        (for all K in 0 .. N - 1 =>
           (if K mod 2 = 0 then K = 2 * (K / 2)
            else K = 2 * (K / 2) + 1));
      pragma Assert (for all K in 0 .. N - 1 => R (K) = A (K));
   end Lemma_Round_Trip_4;

   procedure Lemma_Round_Trip_10 (A : Polynomial) is
      B : Byte_Array_320;
      R : Polynomial;
   begin
      ByteEncode10 (A, B);
      ByteDecode10 (B, R);
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              (for all J in 0 .. 7 =>
                 R (8 * P + J) = A (8 * P + J)));
         declare
            T0 : constant U16 := U16 (A (8 * I)) with Ghost;
            T1 : constant U16 := U16 (A (8 * I + 1)) with Ghost;
            C0 : constant U8  := B (10 * I) with Ghost;
            C1 : constant U8  := B (10 * I + 1) with Ghost;
         begin
            pragma Assert (T0 <= 1023 and T1 <= 1023);
            pragma Assert (C0 = U8 (T0 and 16#FF#));
            pragma Assert
              (C1 = U8 ((Interfaces.Shift_Right (T0, 8)
                         or Interfaces.Shift_Left (T1, 2)) and 16#FF#));
            pragma Assert (U16 (C0) = (T0 and 16#FF#));
            pragma Assert
              (U16 (C1 and 16#03#) = Interfaces.Shift_Right (T0, 8));
            pragma Assert
              ((U16 (C0)
                or Interfaces.Shift_Left (U16 (C1 and 16#03#), 8))
               = T0);
         end;
         pragma Assert
           ((Interfaces.Shift_Right (U16 (B (10 * I + 1)), 2)
             or Interfaces.Shift_Left
                  (U16 (B (10 * I + 2) and 16#0F#), 6))
            = U16 (A (8 * I + 1)));
         pragma Assert
           ((Interfaces.Shift_Right (U16 (B (10 * I + 2)), 4)
             or Interfaces.Shift_Left
                  (U16 (B (10 * I + 3) and 16#3F#), 4))
            = U16 (A (8 * I + 2)));
         pragma Assert
           ((Interfaces.Shift_Right (U16 (B (10 * I + 3)), 6)
             or Interfaces.Shift_Left (U16 (B (10 * I + 4)), 2))
            = U16 (A (8 * I + 3)));
         declare
            T4 : constant U16 := U16 (A (8 * I + 4)) with Ghost;
            T5 : constant U16 := U16 (A (8 * I + 5)) with Ghost;
            C5 : constant U8  := B (10 * I + 5) with Ghost;
            C6 : constant U8  := B (10 * I + 6) with Ghost;
         begin
            pragma Assert (T4 <= 1023 and T5 <= 1023);
            pragma Assert (C5 = U8 (T4 and 16#FF#));
            pragma Assert
              (C6 = U8 ((Interfaces.Shift_Right (T4, 8)
                         or Interfaces.Shift_Left (T5, 2)) and 16#FF#));
            pragma Assert (U16 (C5) = (T4 and 16#FF#));
            pragma Assert
              (U16 (C6 and 16#03#) = Interfaces.Shift_Right (T4, 8));
            pragma Assert
              ((U16 (C5)
                or Interfaces.Shift_Left (U16 (C6 and 16#03#), 8))
               = T4);
         end;
         pragma Assert
           ((Interfaces.Shift_Right (U16 (B (10 * I + 6)), 2)
             or Interfaces.Shift_Left
                  (U16 (B (10 * I + 7) and 16#0F#), 6))
            = U16 (A (8 * I + 5)));
         pragma Assert
           ((Interfaces.Shift_Right (U16 (B (10 * I + 7)), 4)
             or Interfaces.Shift_Left
                  (U16 (B (10 * I + 8) and 16#3F#), 4))
            = U16 (A (8 * I + 6)));
         pragma Assert
           ((Interfaces.Shift_Right (U16 (B (10 * I + 8)), 6)
             or Interfaces.Shift_Left (U16 (B (10 * I + 9)), 2))
            = U16 (A (8 * I + 7)));
         pragma Assert (R (8 * I) = A (8 * I));
         pragma Assert (R (8 * I + 1) = A (8 * I + 1));
         pragma Assert (R (8 * I + 2) = A (8 * I + 2));
         pragma Assert (R (8 * I + 3) = A (8 * I + 3));
         pragma Assert (R (8 * I + 4) = A (8 * I + 4));
         pragma Assert (R (8 * I + 5) = A (8 * I + 5));
         pragma Assert (R (8 * I + 6) = A (8 * I + 6));
         pragma Assert (R (8 * I + 7) = A (8 * I + 7));
         pragma Assert
           (for all J in 0 .. 7 => R (8 * I + J) = A (8 * I + J));
      end loop;
      pragma Assert
        (for all I in 0 .. 31 =>
           (for all J in 0 .. 7 => R (8 * I + J) = A (8 * I + J)));
      for K in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. K - 1 => R (J) = A (J));
         pragma Assert
           (K / 8 in 0 .. 31 and then K mod 8 in 0 .. 7
            and then K = 8 * (K / 8) + K mod 8);
         pragma Assert (R (K) = A (K));
      end loop;
      pragma Assert (for all K in 0 .. N - 1 => R (K) = A (K));
   end Lemma_Round_Trip_10;

end ML_KEM.Serialize.Properties;
