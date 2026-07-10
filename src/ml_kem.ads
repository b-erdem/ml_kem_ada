with Interfaces;
with Ml_Kem_Config;

package ML_KEM is

   pragma Pure;
   pragma SPARK_Mode;

   use type Ml_Kem_Config.Parameter_Set_Kind;

   use type Interfaces.Integer_16;
   use type Interfaces.Integer_32;
   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;

   subtype I16 is Interfaces.Integer_16;
   subtype I32 is Interfaces.Integer_32;
   subtype U8  is Interfaces.Unsigned_8;
   subtype U16 is Interfaces.Unsigned_16;
   subtype U32 is Interfaces.Unsigned_32;
   subtype U64 is Interfaces.Unsigned_64;

   Q : constant := 3329;
   N : constant := 256;

   Sym_Bytes : constant := 32;

   type Polynomial is array (0 .. N - 1) of I16;
   type Byte_Array is array (Natural range <>) of U8;

   subtype Byte_Array_32  is Byte_Array (0 .. 31);
   subtype Byte_Array_64  is Byte_Array (0 .. 63);
   subtype Byte_Array_128 is Byte_Array (0 .. 127);
   subtype Byte_Array_160 is Byte_Array (0 .. 159);
   subtype Byte_Array_192 is Byte_Array (0 .. 191);
   subtype Byte_Array_320 is Byte_Array (0 .. 319);
   subtype Byte_Array_352 is Byte_Array (0 .. 351);
   subtype Byte_Array_384 is Byte_Array (0 .. 383);

   Q_Half : constant := (Q - 1) / 2;

   subtype Coeff_Barrett is I16 range -Q_Half .. Q_Half;
   subtype Coeff_Positive is I16 range 0 .. Q - 1;
   subtype Coeff_CBD2 is I16 range -2 .. 2;
   subtype Coeff_CBD3 is I16 range -3 .. 3;

   Q_Inv : constant U16 := 62209;
   Mont  : constant := 2285;

   ----------------------------------------------------------------------
   --  Parameter-set-specific constants
   --
   --  Switched at build time via the Alire crate configuration variable
   --  `parameter_set` (default ML_KEM_768).  See alire.toml's
   --  `[configuration.variables]` block; per-build the generated file
   --  `config/ml_kem_config.ads` exposes
   --  `Parameter_Set : constant := ML_KEM_512 | ML_KEM_768 | ML_KEM_1024`.
   --
   --  All five constants below are derived statically from that one
   --  enumerated value, so each build proves a single parameter set's
   --  worth of VCs.  Current FIPS 203 parameter sets:
   --
   --      ML-KEM-512  : K=2, Eta1=3, Eta2=2, Du=10, Dv=4 (Cat. I)
   --      ML-KEM-768  : K=3, Eta1=2, Eta2=2, Du=10, Dv=4 (Cat. III)
   --      ML-KEM-1024 : K=4, Eta1=2, Eta2=2, Du=11, Dv=5 (Cat. V)
   ----------------------------------------------------------------------

   ML_KEM_K    : constant := (case Ml_Kem_Config.Parameter_Set is
     when Ml_Kem_Config.Ml_Kem_512  => 2,
     when Ml_Kem_Config.Ml_Kem_768  => 3,
     when Ml_Kem_Config.Ml_Kem_1024 => 4);

   ML_KEM_Eta1 : constant := (case Ml_Kem_Config.Parameter_Set is
     when Ml_Kem_Config.Ml_Kem_512  => 3,
     when Ml_Kem_Config.Ml_Kem_768  => 2,
     when Ml_Kem_Config.Ml_Kem_1024 => 2);

   ML_KEM_Eta2 : constant := 2;  --  same across all sets

   ML_KEM_Du   : constant := (case Ml_Kem_Config.Parameter_Set is
     when Ml_Kem_Config.Ml_Kem_512  => 10,
     when Ml_Kem_Config.Ml_Kem_768  => 10,
     when Ml_Kem_Config.Ml_Kem_1024 => 11);

   ML_KEM_Dv   : constant := (case Ml_Kem_Config.Parameter_Set is
     when Ml_Kem_Config.Ml_Kem_512  => 4,
     when Ml_Kem_Config.Ml_Kem_768  => 4,
     when Ml_Kem_Config.Ml_Kem_1024 => 5);

   Poly_Bytes_12 : constant := 384;
   --  Per-polynomial byte sizes after Du / Dv compression.  For
   --  ML-KEM-512 / 768: Poly_Bytes_Du = 320, Poly_Bytes_Dv = 128.
   --  For ML-KEM-1024:   Poly_Bytes_Du = 352, Poly_Bytes_Dv = 160.
   Poly_Bytes_Du : constant := ML_KEM_Du * N / 8;
   Poly_Bytes_Dv : constant := ML_KEM_Dv * N / 8;
   --  Legacy aliases for the ML-KEM-512 / 768 sizes (kept for
   --  back-compat with existing call sites that hard-code the
   --  768 sizes; new code uses Poly_Bytes_Du / Poly_Bytes_Dv).
   Poly_Bytes_10 : constant := 320;
   Poly_Bytes_4  : constant := 128;
   Poly_Bytes_1  : constant := 32;

   Indcpa_PK_Bytes : constant := Poly_Bytes_12 * ML_KEM_K + Sym_Bytes;
   Indcpa_SK_Bytes : constant := Poly_Bytes_12 * ML_KEM_K;
   CT_Bytes        : constant := Poly_Bytes_Du * ML_KEM_K + Poly_Bytes_Dv;

   PK_Bytes : constant := Indcpa_PK_Bytes;
   SK_Bytes : constant := Indcpa_SK_Bytes + PK_Bytes + Sym_Bytes + Sym_Bytes;

   type Poly_Vector is array (0 .. ML_KEM_K - 1) of Polynomial;
   type Poly_Matrix is array (0 .. ML_KEM_K - 1) of Poly_Vector;

   function Load32_LE (B0, B1, B2, B3 : U8) return U32 is
     (U32 (B0)
      or Interfaces.Shift_Left (U32 (B1), 8)
      or Interfaces.Shift_Left (U32 (B2), 16)
      or Interfaces.Shift_Left (U32 (B3), 24));

   function Load24_LE (B0, B1, B2 : U8) return U32 is
     (U32 (B0)
      or Interfaces.Shift_Left (U32 (B1), 8)
      or Interfaces.Shift_Left (U32 (B2), 16));

   function U16_To_I32 (U : U16) return I32 is
     (if U <= 32767 then I32 (U) else I32 (U) - 2**16);

   function Freeze (X : I16) return Coeff_Positive is
     (I16 (I32 (X) mod I32 (Q)))
     with Post => Freeze'Result in 0 .. Q - 1;

end ML_KEM;
