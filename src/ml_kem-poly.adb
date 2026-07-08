with ML_KEM.Reduce;
with Interfaces;

package body ML_KEM.Poly is
   pragma SPARK_Mode (On);

   --  Per-coefficient lemmas for Decompress_Du / Decompress_Dv.
   --
   --  FIPS 203 Algorithm 5: Decompress_d(y) = round_to_nearest_int(y * q / 2^d)
   --  Implementation (avoids floating point): (y * q + 2^(d-1)) / 2^d.
   --
   --  Input: y in [0, 2^d - 1].
   --  Output: result in [0, q - 1] (since y * q + 2^(d-1) < 2^d * q).
   --
   --  These expression functions encapsulate the per-coefficient
   --  reasoning; SPARK proves the postcondition via linear-arithmetic
   --  bound chasing (V <= 2^d - 1 implies V*Q + 2^(d-1) < 2^d * Q,
   --  which after div-by-2^d gives result < Q).

   function Decompress_Du_Coeff (V : U32) return I16 is
     (I16 ((I32 (V) * I32 (Q) + 512) / 1024))
     with Pre  => V < 1024,
          Post => Decompress_Du_Coeff'Result in 0 .. Q - 1;

   function Decompress_Dv_Coeff (V : U32) return I16 is
     (I16 ((I32 (V) * I32 (Q) + 8) / 16))
     with Pre  => V < 16,
          Post => Decompress_Dv_Coeff'Result in 0 .. Q - 1;

   --  ML-KEM-1024 Du = 11 / Dv = 5 variants of the per-coefficient
   --  decompression formula. Same idea: (V * Q + 2**(d-1)) / 2**d.
   function Decompress_11_Coeff (V : U32) return I16 is
     (I16 ((I32 (V) * I32 (Q) + 1024) / 2048))
     with Pre  => V < 2048,
          Post => Decompress_11_Coeff'Result in 0 .. Q - 1;

   function Decompress_5_Coeff (V : U32) return I16 is
     (I16 ((I32 (V) * I32 (Q) + 16) / 32))
     with Pre  => V < 32,
          Post => Decompress_5_Coeff'Result in 0 .. Q - 1;

   procedure Poly_Reduce (R : in out Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => R (J) in -Q_Half .. Q_Half);
         R (I) := Reduce.Barrett_Reduce (R (I));
         pragma Assert (R (I) in -Q_Half .. Q_Half);
      end loop;
   end Poly_Reduce;

   procedure Poly_Add (R : in out Polynomial; B : Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              R (K) = R'Loop_Entry (K) + B (K));
         pragma Loop_Invariant
           (for all K in I .. N - 1 => R (K) = R'Loop_Entry (K));
         R (I) := R (I) + B (I);
      end loop;
   end Poly_Add;

   procedure Poly_Sub (R : in out Polynomial; B : Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              R (K) = R'Loop_Entry (K) - B (K));
         pragma Loop_Invariant
           (for all K in I .. N - 1 => R (K) = R'Loop_Entry (K));
         R (I) := R (I) - B (I);
      end loop;
   end Poly_Sub;

   procedure Poly_ToMont (R : in out Polynomial) is
      F : constant I16 := 1353;
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => R (J) in -Q .. Q);
         R (I) := Reduce.FqMul (R (I), F);
         pragma Assert (R (I) in -Q .. Q);
      end loop;
   end Poly_ToMont;

   procedure Compress_Du (A : Polynomial; R : out Byte_Array_320) is
      T : array (0 .. 7) of U16;
      U : I16;
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 10 * I - 1 => R (J) <= 255);
         for J in 0 .. 7 loop
            U := A (8 * I + J);
            T (J) := U16 (((U32 (U) * 1024 + U32 (Q / 2)) / U32 (Q)) mod 1024);
         end loop;
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
      end loop;
   end Compress_Du;

   procedure Decompress_Du (A : Byte_Array_320; R : out Polynomial) is
      --  Each iteration extracts eight 10-bit values from a 10-byte
      --  block and decompresses each one. We use addition (not OR)
      --  because the bits don't overlap: the byte and the masked
      --  shifted neighbour occupy disjoint bit ranges, so OR equals
      --  sum, and SPARK's linear arithmetic handles the bound proof
      --  for sums but not for OR (without bit-vector reasoning).
      V0, V1, V2, V3, V4, V5, V6, V7 : U32;
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 8 * I - 1 => R (J) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all J in 8 * I .. N - 1 => R (J) = 0);

         V0 := U32 (A (10 * I))
               + 256 * U32 (A (10 * I + 1) and 16#03#);
         V1 := U32 (Interfaces.Shift_Right (A (10 * I + 1), 2))
               + 64 * U32 (A (10 * I + 2) and 16#0F#);
         V2 := U32 (Interfaces.Shift_Right (A (10 * I + 2), 4))
               + 16 * U32 (A (10 * I + 3) and 16#3F#);
         V3 := U32 (Interfaces.Shift_Right (A (10 * I + 3), 6))
               + 4 * U32 (A (10 * I + 4));
         V4 := U32 (A (10 * I + 5))
               + 256 * U32 (A (10 * I + 6) and 16#03#);
         V5 := U32 (Interfaces.Shift_Right (A (10 * I + 6), 2))
               + 64 * U32 (A (10 * I + 7) and 16#0F#);
         V6 := U32 (Interfaces.Shift_Right (A (10 * I + 7), 4))
               + 16 * U32 (A (10 * I + 8) and 16#3F#);
         V7 := U32 (Interfaces.Shift_Right (A (10 * I + 8), 6))
               + 4 * U32 (A (10 * I + 9));

         R (8 * I)     := Decompress_Du_Coeff (V0);
         R (8 * I + 1) := Decompress_Du_Coeff (V1);
         R (8 * I + 2) := Decompress_Du_Coeff (V2);
         R (8 * I + 3) := Decompress_Du_Coeff (V3);
         R (8 * I + 4) := Decompress_Du_Coeff (V4);
         R (8 * I + 5) := Decompress_Du_Coeff (V5);
         R (8 * I + 6) := Decompress_Du_Coeff (V6);
         R (8 * I + 7) := Decompress_Du_Coeff (V7);
      end loop;
   end Decompress_Du;

   procedure Compress_Dv (A : Polynomial; R : out Byte_Array_128) is
      T : array (0 .. 7) of U16;
      U : I16;
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 4 * I - 1 => R (J) <= 255);
         for J in 0 .. 7 loop
            U := A (8 * I + J);
            T (J) := U16 (((U32 (U) * 16 + U32 (Q / 2)) / U32 (Q)) mod 16);
         end loop;
         R (4 * I)     := U8 (T (0))
                          or U8 (Interfaces.Shift_Left (T (1), 4));
         R (4 * I + 1) := U8 (T (2))
                          or U8 (Interfaces.Shift_Left (T (3), 4));
         R (4 * I + 2) := U8 (T (4))
                          or U8 (Interfaces.Shift_Left (T (5), 4));
         R (4 * I + 3) := U8 (T (6))
                          or U8 (Interfaces.Shift_Left (T (7), 4));
      end loop;
   end Compress_Dv;

   procedure Decompress_Dv (A : Byte_Array_128; R : out Polynomial) is
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 8 * I - 1 => R (J) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all J in 8 * I .. N - 1 => R (J) = 0);

         R (8 * I)     := Decompress_Dv_Coeff (U32 (A (4 * I) and 16#0F#));
         R (8 * I + 1) := Decompress_Dv_Coeff
           (U32 (Interfaces.Shift_Right (A (4 * I), 4)));
         R (8 * I + 2) := Decompress_Dv_Coeff (U32 (A (4 * I + 1) and 16#0F#));
         R (8 * I + 3) := Decompress_Dv_Coeff
           (U32 (Interfaces.Shift_Right (A (4 * I + 1), 4)));
         R (8 * I + 4) := Decompress_Dv_Coeff (U32 (A (4 * I + 2) and 16#0F#));
         R (8 * I + 5) := Decompress_Dv_Coeff
           (U32 (Interfaces.Shift_Right (A (4 * I + 2), 4)));
         R (8 * I + 6) := Decompress_Dv_Coeff (U32 (A (4 * I + 3) and 16#0F#));
         R (8 * I + 7) := Decompress_Dv_Coeff
           (U32 (Interfaces.Shift_Right (A (4 * I + 3), 4)));
      end loop;
   end Decompress_Dv;

   --  ML-KEM-1024 11-bit packing.  Each iteration takes 8
   --  coefficients in [0, Q-1], computes their 11-bit compressed
   --  value via the FIPS 203 rounded formula, and packs them into
   --  11 bytes.  The bit layout (LSB first across bytes) is:
   --
   --    byte 0  : T0[ 7: 0]
   --    byte 1  : T0[10: 8] | T1[ 4: 0] << 3
   --    byte 2  : T1[10: 5] | T2[ 1: 0] << 6
   --    byte 3  : T2[ 9: 2]
   --    byte 4  : T2[10]    | T3[ 6: 0] << 1
   --    byte 5  : T3[10: 7] | T4[ 3: 0] << 4
   --    byte 6  : T4[10: 4] | T5[   0]  << 7
   --    byte 7  : T5[ 8: 1]
   --    byte 8  : T5[10: 9] | T6[ 5: 0] << 2
   --    byte 9  : T6[10: 6] | T7[ 2: 0] << 5
   --    byte 10 : T7[10: 3]
   procedure Compress_11 (A : Polynomial; R : out Byte_Array_352) is
      T : array (0 .. 7) of U16;
      U : I16;
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 11 * I - 1 => R (J) <= 255);
         for J in 0 .. 7 loop
            U := A (8 * I + J);
            T (J) := U16 (((U32 (U) * 2048 + U32 (Q / 2)) / U32 (Q)) mod 2048);
         end loop;
         R (11 * I)     := U8 (T (0) and 16#FF#);
         R (11 * I + 1) := U8 ((Interfaces.Shift_Right (T (0), 8)
                                or Interfaces.Shift_Left (T (1), 3)) and 16#FF#);
         R (11 * I + 2) := U8 ((Interfaces.Shift_Right (T (1), 5)
                                or Interfaces.Shift_Left (T (2), 6)) and 16#FF#);
         R (11 * I + 3) := U8 (Interfaces.Shift_Right (T (2), 2) and 16#FF#);
         R (11 * I + 4) := U8 ((Interfaces.Shift_Right (T (2), 10)
                                or Interfaces.Shift_Left (T (3), 1)) and 16#FF#);
         R (11 * I + 5) := U8 ((Interfaces.Shift_Right (T (3), 7)
                                or Interfaces.Shift_Left (T (4), 4)) and 16#FF#);
         R (11 * I + 6) := U8 ((Interfaces.Shift_Right (T (4), 4)
                                or Interfaces.Shift_Left (T (5), 7)) and 16#FF#);
         R (11 * I + 7) := U8 (Interfaces.Shift_Right (T (5), 1) and 16#FF#);
         R (11 * I + 8) := U8 ((Interfaces.Shift_Right (T (5), 9)
                                or Interfaces.Shift_Left (T (6), 2)) and 16#FF#);
         R (11 * I + 9) := U8 ((Interfaces.Shift_Right (T (6), 6)
                                or Interfaces.Shift_Left (T (7), 5)) and 16#FF#);
         R (11 * I + 10) := U8 (Interfaces.Shift_Right (T (7), 3) and 16#FF#);
      end loop;
   end Compress_11;

   procedure Decompress_11 (A : Byte_Array_352; R : out Polynomial) is
      V0, V1, V2, V3, V4, V5, V6, V7 : U32;
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 8 * I - 1 => R (J) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all J in 8 * I .. N - 1 => R (J) = 0);

         V0 := U32 (A (11 * I))
               + 256 * U32 (A (11 * I + 1) and 16#07#);
         V1 := U32 (Interfaces.Shift_Right (A (11 * I + 1), 3))
               + 32 * U32 (A (11 * I + 2) and 16#3F#);
         V2 := U32 (Interfaces.Shift_Right (A (11 * I + 2), 6))
               + 4 * U32 (A (11 * I + 3))
               + 1024 * U32 (A (11 * I + 4) and 16#01#);
         V3 := U32 (Interfaces.Shift_Right (A (11 * I + 4), 1))
               + 128 * U32 (A (11 * I + 5) and 16#0F#);
         V4 := U32 (Interfaces.Shift_Right (A (11 * I + 5), 4))
               + 16 * U32 (A (11 * I + 6) and 16#7F#);
         V5 := U32 (Interfaces.Shift_Right (A (11 * I + 6), 7))
               + 2 * U32 (A (11 * I + 7))
               + 512 * U32 (A (11 * I + 8) and 16#03#);
         V6 := U32 (Interfaces.Shift_Right (A (11 * I + 8), 2))
               + 64 * U32 (A (11 * I + 9) and 16#1F#);
         V7 := U32 (Interfaces.Shift_Right (A (11 * I + 9), 5))
               + 8 * U32 (A (11 * I + 10));

         R (8 * I)     := Decompress_11_Coeff (V0);
         R (8 * I + 1) := Decompress_11_Coeff (V1);
         R (8 * I + 2) := Decompress_11_Coeff (V2);
         R (8 * I + 3) := Decompress_11_Coeff (V3);
         R (8 * I + 4) := Decompress_11_Coeff (V4);
         R (8 * I + 5) := Decompress_11_Coeff (V5);
         R (8 * I + 6) := Decompress_11_Coeff (V6);
         R (8 * I + 7) := Decompress_11_Coeff (V7);
      end loop;
   end Decompress_11;

   --  ML-KEM-1024 5-bit packing.  Each iteration takes 8 coefficients
   --  in [0, Q-1], computes their 5-bit compressed value, and packs
   --  them into 5 bytes:
   --
   --    byte 0 : T0[4:0] | T1[2:0] << 5
   --    byte 1 : T1[4:3] | T2[4:0] << 2 | T3[0]   << 7
   --    byte 2 : T3[4:1] | T4[3:0] << 4
   --    byte 3 : T4[4]   | T5[4:0] << 1 | T6[1:0] << 6
   --    byte 4 : T6[4:2] | T7[4:0] << 3
   procedure Compress_5 (A : Polynomial; R : out Byte_Array_160) is
      T : array (0 .. 7) of U16;
      U : I16;
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 5 * I - 1 => R (J) <= 255);
         for J in 0 .. 7 loop
            U := A (8 * I + J);
            T (J) := U16 (((U32 (U) * 32 + U32 (Q / 2)) / U32 (Q)) mod 32);
         end loop;
         R (5 * I)     := U8 ((T (0) or Interfaces.Shift_Left (T (1), 5))
                              and 16#FF#);
         R (5 * I + 1) := U8 ((Interfaces.Shift_Right (T (1), 3)
                               or Interfaces.Shift_Left (T (2), 2)
                               or Interfaces.Shift_Left (T (3), 7))
                              and 16#FF#);
         R (5 * I + 2) := U8 ((Interfaces.Shift_Right (T (3), 1)
                               or Interfaces.Shift_Left (T (4), 4))
                              and 16#FF#);
         R (5 * I + 3) := U8 ((Interfaces.Shift_Right (T (4), 4)
                               or Interfaces.Shift_Left (T (5), 1)
                               or Interfaces.Shift_Left (T (6), 6))
                              and 16#FF#);
         R (5 * I + 4) := U8 ((Interfaces.Shift_Right (T (6), 2)
                               or Interfaces.Shift_Left (T (7), 3))
                              and 16#FF#);
      end loop;
   end Compress_5;

   procedure Decompress_5 (A : Byte_Array_160; R : out Polynomial) is
      V0, V1, V2, V3, V4, V5, V6, V7 : U32;
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 8 * I - 1 => R (J) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all J in 8 * I .. N - 1 => R (J) = 0);

         V0 := U32 (A (5 * I) and 16#1F#);
         V1 := U32 (Interfaces.Shift_Right (A (5 * I), 5))
               + 8 * U32 (A (5 * I + 1) and 16#03#);
         V2 := U32 (Interfaces.Shift_Right (A (5 * I + 1), 2)
                    and 16#1F#);
         V3 := U32 (Interfaces.Shift_Right (A (5 * I + 1), 7))
               + 2 * U32 (A (5 * I + 2) and 16#0F#);
         V4 := U32 (Interfaces.Shift_Right (A (5 * I + 2), 4))
               + 16 * U32 (A (5 * I + 3) and 16#01#);
         V5 := U32 (Interfaces.Shift_Right (A (5 * I + 3), 1)
                    and 16#1F#);
         V6 := U32 (Interfaces.Shift_Right (A (5 * I + 3), 6))
               + 4 * U32 (A (5 * I + 4) and 16#07#);
         V7 := U32 (Interfaces.Shift_Right (A (5 * I + 4), 3));

         R (8 * I)     := Decompress_5_Coeff (V0);
         R (8 * I + 1) := Decompress_5_Coeff (V1);
         R (8 * I + 2) := Decompress_5_Coeff (V2);
         R (8 * I + 3) := Decompress_5_Coeff (V3);
         R (8 * I + 4) := Decompress_5_Coeff (V4);
         R (8 * I + 5) := Decompress_5_Coeff (V5);
         R (8 * I + 6) := Decompress_5_Coeff (V6);
         R (8 * I + 7) := Decompress_5_Coeff (V7);
      end loop;
   end Decompress_5;

   procedure Poly_ToggleNeg (R : in out Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
               R (J) in I16'Range and then R (J) = -R'Loop_Entry (J));
         pragma Assert (R (I) > I16'First);
         R (I) := -R (I);
      end loop;
   end Poly_ToggleNeg;

   procedure Poly_FromMsg (Msg : Byte_Array_32; R : out Polynomial) is
      Half_Q : constant I16 := I16 ((Q + 1) / 2);
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 8 * I - 1 =>
               R (J) = 0 or else R (J) = Half_Q);
         for J in 0 .. 7 loop
            pragma Loop_Invariant
              (for all K in 0 .. 8 * I + J - 1 =>
                  R (K) = 0 or else R (K) = Half_Q);
            R (8 * I + J) :=
              (if (Msg (I) and Interfaces.Shift_Left (U8 (1), J)) /= 0
               then Half_Q else 0);
         end loop;
      end loop;
   end Poly_FromMsg;

   procedure Poly_ToMsg (A : Polynomial; R : out Byte_Array_32) is
      V : I32;
      F : I32;
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         for J in 0 .. 7 loop
            V := 2 * I32 (A (8 * I + J)) + 1665;
            F := V / I32 (Q);
            if V < 0 and then V rem I32 (Q) /= 0 then
               F := F - 1;
            end if;
            if F mod 2 = 1 then
               R (I) := R (I) or Interfaces.Shift_Left (U8 (1), J);
            end if;
         end loop;
      end loop;
   end Poly_ToMsg;

   procedure Poly_Freeze (R : in out Polynomial) is
   begin
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => R (J) in 0 .. Q - 1);
         R (I) := Freeze (R (I));
         pragma Assert (R (I) in 0 .. Q - 1);
      end loop;
   end Poly_Freeze;

end ML_KEM.Poly;
