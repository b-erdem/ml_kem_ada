package ML_KEM.Verify is

   pragma Pure;
   pragma SPARK_Mode;

   function Verify (A, B : Byte_Array) return U8
     with Pre => A'Length = B'Length
                 and then A'First >= Natural'First
                 and then B'First >= Natural'First
                 and then A'Last <= Natural'Last
                 and then B'Last <= Natural'Last;

   procedure CMOV
     (R        : in out Byte_Array;
      A        : Byte_Array;
      Condition : U8)
     with Pre => R'Length = A'Length
                 and then R'First >= Natural'First
                 and then A'First >= Natural'First;

end ML_KEM.Verify;
