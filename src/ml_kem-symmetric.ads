with SHA3;

package ML_KEM.Symmetric is

   pragma Pure;
   pragma SPARK_Mode;

   XOF_Rate : constant := 168;

   procedure Hash_G (Data : Byte_Array; Result : out Byte_Array_64)
     with Pre => Data'First >= 0
                 and then Data'Last < Natural'Last;

   procedure Hash_H (Data : Byte_Array; Result : out Byte_Array_32)
     with Pre => Data'First >= 0
                 and then Data'Last < Natural'Last;

   procedure PRF
     (Seed   : Byte_Array_32;
      Nonce  : U8;
      Result : out Byte_Array)
     with Pre => Result'First >= 0
                 and then Result'Last < Natural'Last;

   procedure XOF_Absorb
      (S      : out SHA3.Sponge_State;
       Seed   : Byte_Array_32;
       X, Y   : U8)
     with Post => S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes
                  and then S.Rate = XOF_Rate;

   procedure XOF_Squeeze
     (S      : in out SHA3.Sponge_State;
      Result : out Byte_Array)
     with Pre => Result'First >= 0
                 and then Result'Last < Natural'Last
                 and then S.Byte_Pos < S.Rate
                 and then S.Rate < SHA3.State_Bytes,
          Post => S.Byte_Pos < S.Rate
                  and then S.Rate < SHA3.State_Bytes
                  and then S.Rate = S.Rate'Old;

end ML_KEM.Symmetric;
