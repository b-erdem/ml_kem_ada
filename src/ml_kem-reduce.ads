package ML_KEM.Reduce is

   pragma Pure;
   pragma SPARK_Mode;

   function Montgomery_Reduce (A : I32) return I16
     with
       Pre  => A in -(Q * 2**15) .. (Q * 2**15 - 1),
       Post => Montgomery_Reduce'Result in -Q .. Q;

   function Barrett_Reduce (A : I16) return I16
     with
       Post => Barrett_Reduce'Result in -Q_Half .. Q_Half;

   function FqMul (A, B : I16) return I16
     with
       Pre  => I32 (A) * I32 (B) in -(Q * 2**15) .. (Q * 2**15 - 1),
       Post => FqMul'Result in -Q .. Q;

end ML_KEM.Reduce;
