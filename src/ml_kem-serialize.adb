package body ML_KEM.Serialize is
   pragma SPARK_Mode (On);

   procedure ByteEncode12 (A : Polynomial; R : out Byte_Array_384) is
      T0 : U16;
      T1 : U16;
   begin
      R := [others => 0];
      for I in 0 .. 127 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
              R (3 * J) = U8 (U16 (A (2 * J)) and 16#FF#)
              and then R (3 * J + 1) =
                U8 (Interfaces.Shift_Right (U16 (A (2 * J)), 8)
                    or Interfaces.Shift_Left
                         (U16 (A (2 * J + 1)) and 16#F#, 4))
              and then R (3 * J + 2) =
                U8 (Interfaces.Shift_Right (U16 (A (2 * J + 1)), 4)));
         T0 := U16 (A (2 * I));
         T1 := U16 (A (2 * I + 1));
         R (3 * I)     := U8 (T0 and 16#FF#);
         R (3 * I + 1) := U8 (Interfaces.Shift_Right (T0, 8)
                               or Interfaces.Shift_Left (T1 and 16#F#, 4));
         R (3 * I + 2) := U8 (Interfaces.Shift_Right (T1, 4));
         pragma Assert (R (3 * I) <= 255);
         pragma Assert (R (3 * I + 1) <= 255);
         pragma Assert (R (3 * I + 2) <= 255);
      end loop;
   end ByteEncode12;

   procedure ByteDecode12 (A : Byte_Array_384; R : out Polynomial) is
   begin
      R := [others => 0];
      for I in 0 .. 127 loop
         pragma Loop_Invariant
           (for all J in 0 .. 2 * I - 1 => R (J) in 0 .. 4095);
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
              R (2 * J) =
                I16 (U16 (A (3 * J))
                     or Interfaces.Shift_Left
                          (U16 (A (3 * J + 1) and 16#0F#), 8))
              and then R (2 * J + 1) =
                I16 (Interfaces.Shift_Right (U16 (A (3 * J + 1)), 4)
                     or Interfaces.Shift_Left (U16 (A (3 * J + 2)), 4)));
         R (2 * I) :=
           I16 (U16 (A (3 * I))
                or Interfaces.Shift_Left (U16 (A (3 * I + 1) and 16#0F#), 8));
         R (2 * I + 1) :=
           I16 (Interfaces.Shift_Right (U16 (A (3 * I + 1)), 4)
                or Interfaces.Shift_Left (U16 (A (3 * I + 2)), 4));
         pragma Assert (R (2 * I) in 0 .. 4095);
         pragma Assert (R (2 * I + 1) in 0 .. 4095);
      end loop;
   end ByteDecode12;

   procedure ByteEncode1 (A : Polynomial; R : out Byte_Array_32) is
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
              R (J) = (U8 (A (8 * J))
                       or Interfaces.Shift_Left (U8 (A (8 * J + 1)), 1)
                       or Interfaces.Shift_Left (U8 (A (8 * J + 2)), 2)
                       or Interfaces.Shift_Left (U8 (A (8 * J + 3)), 3)
                       or Interfaces.Shift_Left (U8 (A (8 * J + 4)), 4)
                       or Interfaces.Shift_Left (U8 (A (8 * J + 5)), 5)
                       or Interfaces.Shift_Left (U8 (A (8 * J + 6)), 6)
                       or Interfaces.Shift_Left (U8 (A (8 * J + 7)), 7)));
         R (I) := U8 (A (8 * I))
                  or Interfaces.Shift_Left (U8 (A (8 * I + 1)), 1)
                  or Interfaces.Shift_Left (U8 (A (8 * I + 2)), 2)
                  or Interfaces.Shift_Left (U8 (A (8 * I + 3)), 3)
                  or Interfaces.Shift_Left (U8 (A (8 * I + 4)), 4)
                  or Interfaces.Shift_Left (U8 (A (8 * I + 5)), 5)
                  or Interfaces.Shift_Left (U8 (A (8 * I + 6)), 6)
                  or Interfaces.Shift_Left (U8 (A (8 * I + 7)), 7);
      end loop;
   end ByteEncode1;

   procedure ByteDecode1 (A : Byte_Array_32; R : out Polynomial) is
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 8 * I - 1 => R (J) in 0 .. 1);
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              (for all J in 0 .. 7 =>
                 R (8 * P + J) =
                   I16 (Interfaces.Shift_Right (U16 (A (P)), J) and 1)));
         for J in 0 .. 7 loop
            pragma Loop_Invariant
              (for all K in 0 .. 8 * I + J - 1 => R (K) in 0 .. 1);
            pragma Loop_Invariant
              (for all P in 0 .. I - 1 =>
                 (for all K in 0 .. 7 =>
                    R (8 * P + K) =
                      I16 (Interfaces.Shift_Right (U16 (A (P)), K)
                           and 1)));
            pragma Loop_Invariant
              (for all K in 0 .. J - 1 =>
                 R (8 * I + K) =
                   I16 (Interfaces.Shift_Right (U16 (A (I)), K) and 1));
            R (8 * I + J) :=
              I16 (Interfaces.Shift_Right (U16 (A (I)), J) and 1);
            pragma Assert (R (8 * I + J) in 0 .. 1);
         end loop;
      end loop;
   end ByteDecode1;

   procedure ByteEncode4 (A : Polynomial; R : out Byte_Array_128) is
   begin
      R := [others => 0];
      for I in 0 .. 127 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
              R (J) = (U8 (A (2 * J))
                       or Interfaces.Shift_Left (U8 (A (2 * J + 1)), 4)));
         R (I) := U8 (A (2 * I))
                  or Interfaces.Shift_Left (U8 (A (2 * I + 1)), 4);
      end loop;
   end ByteEncode4;

   procedure ByteDecode4 (A : Byte_Array_128; R : out Polynomial) is
   begin
      R := [others => 0];
      for I in 0 .. 127 loop
         pragma Loop_Invariant
           (for all J in 0 .. 2 * I - 1 => R (J) in 0 .. 15);
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
              R (2 * J) = I16 (A (J) and 16#0F#)
              and then R (2 * J + 1) =
                I16 (Interfaces.Shift_Right (A (J), 4)));
         R (2 * I)     := I16 (A (I) and 16#0F#);
         R (2 * I + 1) := I16 (Interfaces.Shift_Right (A (I), 4));
         pragma Assert (R (2 * I) in 0 .. 15);
         pragma Assert (R (2 * I + 1) in 0 .. 15);
      end loop;
   end ByteDecode4;

   procedure ByteEncode10 (A : Polynomial; R : out Byte_Array_320) is
      T : array (0 .. 7) of U16 := [others => 0];
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P) = U8 (U16 (A (8 * P)) and 16#FF#));
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P + 1) =
                U8 ((Interfaces.Shift_Right (U16 (A (8 * P)), 8)
                     or Interfaces.Shift_Left (U16 (A (8 * P + 1)), 2))
                    and 16#FF#));
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P + 2) =
                U8 ((Interfaces.Shift_Right (U16 (A (8 * P + 1)), 6)
                     or Interfaces.Shift_Left (U16 (A (8 * P + 2)), 4))
                    and 16#FF#));
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P + 3) =
                U8 ((Interfaces.Shift_Right (U16 (A (8 * P + 2)), 4)
                     or Interfaces.Shift_Left (U16 (A (8 * P + 3)), 6))
                    and 16#FF#));
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P + 4) =
                U8 (Interfaces.Shift_Right (U16 (A (8 * P + 3)), 2)));
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P + 5) = U8 (U16 (A (8 * P + 4)) and 16#FF#));
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P + 6) =
                U8 ((Interfaces.Shift_Right (U16 (A (8 * P + 4)), 8)
                     or Interfaces.Shift_Left (U16 (A (8 * P + 5)), 2))
                    and 16#FF#));
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P + 7) =
                U8 ((Interfaces.Shift_Right (U16 (A (8 * P + 5)), 6)
                     or Interfaces.Shift_Left (U16 (A (8 * P + 6)), 4))
                    and 16#FF#));
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P + 8) =
                U8 ((Interfaces.Shift_Right (U16 (A (8 * P + 6)), 4)
                     or Interfaces.Shift_Left (U16 (A (8 * P + 7)), 6))
                    and 16#FF#));
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (10 * P + 9) =
                U8 (Interfaces.Shift_Right (U16 (A (8 * P + 7)), 2)));
         --  Frame hint: this iteration writes only R (10*I .. 10*I+9),
         --  strictly above every index the invariant constrains.
         pragma Assert (for all P in 0 .. I - 1 => 10 * P + 9 < 10 * I);
         for J in 0 .. 7 loop
            pragma Loop_Invariant
              (for all K in 0 .. J - 1 => T (K) = U16 (A (8 * I + K)));
            T (J) := U16 (A (8 * I + J));
         end loop;
         pragma Assert (for all K in 0 .. 7 => T (K) = U16 (A (8 * I + K)));
          R (10 * I)     := U8 (T (0) and 16#FF#);
          R (10 * I + 1) := U8 ((Interfaces.Shift_Right (T (0), 8)
                                 or Interfaces.Shift_Left (T (1), 2)) and 16#FF#);
          R (10 * I + 2) := U8 ((Interfaces.Shift_Right (T (1), 6)
                                 or Interfaces.Shift_Left (T (2), 4)) and 16#FF#);
          R (10 * I + 3) := U8 ((Interfaces.Shift_Right (T (2), 4)
                                 or Interfaces.Shift_Left (T (3), 6)) and 16#FF#);
          R (10 * I + 4) := U8 (Interfaces.Shift_Right (T (3), 2));
          R (10 * I + 5) := U8 (T (4) and 16#FF#);
          R (10 * I + 6) := U8 ((Interfaces.Shift_Right (T (4), 8)
                                 or Interfaces.Shift_Left (T (5), 2)) and 16#FF#);
          R (10 * I + 7) := U8 ((Interfaces.Shift_Right (T (5), 6)
                                 or Interfaces.Shift_Left (T (6), 4)) and 16#FF#);
          R (10 * I + 8) := U8 ((Interfaces.Shift_Right (T (6), 4)
                                 or Interfaces.Shift_Left (T (7), 6)) and 16#FF#);
          R (10 * I + 9) := U8 (Interfaces.Shift_Right (T (7), 2));
          --  Bridge each written byte back to its A-form (substituting
          --  T (K) = U16 (A (8*I+K))) so the content invariant and the
          --  postcondition re-establish by direct congruence.
          pragma Assert (R (10 * I) = U8 (U16 (A (8 * I)) and 16#FF#));
          pragma Assert
            (R (10 * I + 1) =
               U8 ((Interfaces.Shift_Right (U16 (A (8 * I)), 8)
                    or Interfaces.Shift_Left (U16 (A (8 * I + 1)), 2))
                   and 16#FF#));
          pragma Assert
            (R (10 * I + 2) =
               U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 1)), 6)
                    or Interfaces.Shift_Left (U16 (A (8 * I + 2)), 4))
                   and 16#FF#));
          pragma Assert
            (R (10 * I + 3) =
               U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 2)), 4)
                    or Interfaces.Shift_Left (U16 (A (8 * I + 3)), 6))
                   and 16#FF#));
          pragma Assert
            (R (10 * I + 4) =
               U8 (Interfaces.Shift_Right (U16 (A (8 * I + 3)), 2)));
          pragma Assert
            (R (10 * I + 5) = U8 (U16 (A (8 * I + 4)) and 16#FF#));
          pragma Assert
            (R (10 * I + 6) =
               U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 4)), 8)
                    or Interfaces.Shift_Left (U16 (A (8 * I + 5)), 2))
                   and 16#FF#));
          pragma Assert
            (R (10 * I + 7) =
               U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 5)), 6)
                    or Interfaces.Shift_Left (U16 (A (8 * I + 6)), 4))
                   and 16#FF#));
          pragma Assert
            (R (10 * I + 8) =
               U8 ((Interfaces.Shift_Right (U16 (A (8 * I + 6)), 4)
                    or Interfaces.Shift_Left (U16 (A (8 * I + 7)), 6))
                   and 16#FF#));
          pragma Assert
            (R (10 * I + 9) =
               U8 (Interfaces.Shift_Right (U16 (A (8 * I + 7)), 2)));
      end loop;
   end ByteEncode10;

   procedure ByteDecode10 (A : Byte_Array_320; R : out Polynomial) is
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 8 * I - 1 => R (J) in 0 .. 1023);
         pragma Loop_Invariant
           (for all P in 0 .. I - 1 =>
              R (8 * P) =
                I16 (U16 (A (10 * P))
                     or Interfaces.Shift_Left
                          (U16 (A (10 * P + 1) and 16#03#), 8))
              and then R (8 * P + 1) =
                I16 (Interfaces.Shift_Right (U16 (A (10 * P + 1)), 2)
                     or Interfaces.Shift_Left
                          (U16 (A (10 * P + 2) and 16#0F#), 6))
              and then R (8 * P + 2) =
                I16 (Interfaces.Shift_Right (U16 (A (10 * P + 2)), 4)
                     or Interfaces.Shift_Left
                          (U16 (A (10 * P + 3) and 16#3F#), 4))
              and then R (8 * P + 3) =
                I16 (Interfaces.Shift_Right (U16 (A (10 * P + 3)), 6)
                     or Interfaces.Shift_Left (U16 (A (10 * P + 4)), 2))
              and then R (8 * P + 4) =
                I16 (U16 (A (10 * P + 5))
                     or Interfaces.Shift_Left
                          (U16 (A (10 * P + 6) and 16#03#), 8))
              and then R (8 * P + 5) =
                I16 (Interfaces.Shift_Right (U16 (A (10 * P + 6)), 2)
                     or Interfaces.Shift_Left
                          (U16 (A (10 * P + 7) and 16#0F#), 6))
              and then R (8 * P + 6) =
                I16 (Interfaces.Shift_Right (U16 (A (10 * P + 7)), 4)
                     or Interfaces.Shift_Left
                          (U16 (A (10 * P + 8) and 16#3F#), 4))
              and then R (8 * P + 7) =
                I16 (Interfaces.Shift_Right (U16 (A (10 * P + 8)), 6)
                     or Interfaces.Shift_Left (U16 (A (10 * P + 9)), 2)));
         R (8 * I) :=
           I16 (U16 (A (10 * I))
                or Interfaces.Shift_Left (U16 (A (10 * I + 1) and 16#03#), 8));
         R (8 * I + 1) :=
           I16 (Interfaces.Shift_Right (U16 (A (10 * I + 1)), 2)
                or Interfaces.Shift_Left (U16 (A (10 * I + 2) and 16#0F#), 6));
         R (8 * I + 2) :=
           I16 (Interfaces.Shift_Right (U16 (A (10 * I + 2)), 4)
                or Interfaces.Shift_Left (U16 (A (10 * I + 3) and 16#3F#), 4));
         R (8 * I + 3) :=
           I16 (Interfaces.Shift_Right (U16 (A (10 * I + 3)), 6)
                or Interfaces.Shift_Left (U16 (A (10 * I + 4)), 2));
         R (8 * I + 4) :=
           I16 (U16 (A (10 * I + 5))
                or Interfaces.Shift_Left (U16 (A (10 * I + 6) and 16#03#), 8));
         R (8 * I + 5) :=
           I16 (Interfaces.Shift_Right (U16 (A (10 * I + 6)), 2)
                or Interfaces.Shift_Left (U16 (A (10 * I + 7) and 16#0F#), 6));
         R (8 * I + 6) :=
           I16 (Interfaces.Shift_Right (U16 (A (10 * I + 7)), 4)
                or Interfaces.Shift_Left (U16 (A (10 * I + 8) and 16#3F#), 4));
         R (8 * I + 7) :=
           I16 (Interfaces.Shift_Right (U16 (A (10 * I + 8)), 6)
                or Interfaces.Shift_Left (U16 (A (10 * I + 9)), 2));
         pragma Assert (for all J in 0 .. 7 => R (8 * I + J) in 0 .. 1023);
      end loop;
   end ByteDecode10;

end ML_KEM.Serialize;
