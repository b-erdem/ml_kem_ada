package ML_KEM.Poly is

   pragma Pure;
   pragma SPARK_Mode;

   procedure Poly_Reduce (R : in out Polynomial)
     with Post => (for all I in 0 .. N - 1 => R (I) in -Q_Half .. Q_Half);

   procedure Poly_Add (R : in out Polynomial; B : Polynomial)
     with Pre  => (for all I in 0 .. N - 1 =>
                     I32 (R (I)) + I32 (B (I)) in I32 (I16'First) .. I32 (I16'Last)),
          Post => (for all I in 0 .. N - 1 => R (I) = R'Old (I) + B (I));

   procedure Poly_Sub (R : in out Polynomial; B : Polynomial)
     with Pre  => (for all I in 0 .. N - 1 =>
                     I32 (R (I)) - I32 (B (I)) in I32 (I16'First) .. I32 (I16'Last)),
          Post => (for all I in 0 .. N - 1 => R (I) = R'Old (I) - B (I));

   procedure Poly_ToMont (R : in out Polynomial)
     with Post => (for all I in 0 .. N - 1 => R (I) in -Q .. Q);

   --  10-bit / 4-bit compression for ML-KEM-512 and ML-KEM-768
   --  (Du = 10, Dv = 4).
   procedure Compress_Du (A : Polynomial; R : out Byte_Array_320)
     with
       Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. Q - 1);

   procedure Decompress_Du (A : Byte_Array_320; R : out Polynomial)
     with Post => (for all I in 0 .. N - 1 =>
                     R (I) in 0 .. Q - 1);

   procedure Compress_Dv (A : Polynomial; R : out Byte_Array_128)
     with
       Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. Q - 1);

   procedure Decompress_Dv (A : Byte_Array_128; R : out Polynomial)
     with Post => (for all I in 0 .. N - 1 =>
                     R (I) in 0 .. Q - 1);

   --  11-bit / 5-bit compression for ML-KEM-1024 (Du = 11, Dv = 5).
   --  Each block packs 8 d-bit coefficients into d bytes (88 / 40
   --  bits respectively); 32 blocks per polynomial.
   procedure Compress_11 (A : Polynomial; R : out Byte_Array_352)
     with
       Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. Q - 1);

   procedure Decompress_11 (A : Byte_Array_352; R : out Polynomial)
     with Post => (for all I in 0 .. N - 1 =>
                     R (I) in 0 .. Q - 1);

   procedure Compress_5 (A : Polynomial; R : out Byte_Array_160)
     with
       Pre  => (for all I in 0 .. N - 1 => A (I) in 0 .. Q - 1);

   procedure Decompress_5 (A : Byte_Array_160; R : out Polynomial)
     with Post => (for all I in 0 .. N - 1 =>
                     R (I) in 0 .. Q - 1);

   procedure Poly_ToggleNeg (R : in out Polynomial)
     with Pre  => (for all I in 0 .. N - 1 => R (I) > I16'First),
          Post => (for all I in 0 .. N - 1 =>
                      R (I) = -R'Old (I));

   procedure Poly_FromMsg (Msg : Byte_Array_32; R : out Polynomial)
     with Post => (for all I in 0 .. N - 1 =>
                     R (I) = 0 or else R (I) = I16 ((Q + 1) / 2));

   procedure Poly_ToMsg (A : Polynomial; R : out Byte_Array_32);

   procedure Poly_Freeze (R : in out Polynomial)
     with Post => (for all I in 0 .. N - 1 => R (I) in 0 .. Q - 1);

end ML_KEM.Poly;
