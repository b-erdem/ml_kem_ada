package ML_KEM.Sampling is

   pragma Pure;
   pragma SPARK_Mode;

   procedure RejUniform
     (Buf     :     Byte_Array;
      Buf_Len :     Natural;
      R       : in out Polynomial;
      R_Len   : in out Natural)
     with Pre  => Buf'First = 0
                  and then Buf'Last < Natural'Last
                  and then Buf_Len <= Buf'Length
                  and then Buf_Len <= Natural'Last - 3
                  and then R_Len <= N
                  and then (for all I in 0 .. R_Len - 1 =>
                              R (I) in 0 .. Q - 1)
                  and then (for all I in R_Len .. N - 1 => R (I) = 0),
          Post => R_Len >= R_Len'Old
                  and then R_Len <= N
                  and then (for all I in 0 .. R_Len - 1 =>
                              R (I) in 0 .. Q - 1)
                  and then (for all I in R_Len .. N - 1 => R (I) = 0);

end ML_KEM.Sampling;
