package ML_KEM.CBD is

   pragma Pure;
   pragma SPARK_Mode;

   procedure CBD2 (R : out Polynomial; Buf : Byte_Array_128)
     with Post => (for all I in 0 .. N - 1 => R (I) in -2 .. 2);

   procedure CBD3 (R : out Polynomial; Buf : Byte_Array_192)
     with Post => (for all I in 0 .. N - 1 => R (I) in -3 .. 3);

   --  Parameter-set-aware noise sampling for the secret-key noise
   --  vector (eta1).  The buffer must be sized to the static
   --  ML_KEM_Eta1 * N / 4 bytes; this matches Byte_Array_128 for
   --  ML-KEM-768 / 1024 (Eta1 = 2) and Byte_Array_192 for ML-KEM-512
   --  (Eta1 = 3).
   procedure Sample_Eta1 (R : out Polynomial; Buf : Byte_Array)
     with Pre  => Buf'First = 0
                  and then Buf'Length = ML_KEM_Eta1 * N / 4,
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -ML_KEM_Eta1 .. ML_KEM_Eta1);

end ML_KEM.CBD;
