with Interfaces;

package body ML_KEM.Sampling is
   pragma SPARK_Mode (On);

   procedure RejUniform
     (Buf     :     Byte_Array;
      Buf_Len :     Natural;
      R       : in out Polynomial;
      R_Len   : in out Natural)
   is
      Val0, Val1 : U16;
      Idx : Natural := R_Len;
      Pos : Natural := 0;
   begin
      while Idx < N and then Pos + 3 <= Buf_Len loop
         pragma Loop_Invariant (Idx >= R_Len and then Idx <= N);
         pragma Loop_Invariant (Pos <= Buf_Len);
         pragma Loop_Invariant (Pos + 3 <= Buf_Len);
         pragma Loop_Invariant (Buf_Len <= Buf'Length);
         pragma Loop_Invariant (Pos + 2 <= Buf'Last);
         pragma Loop_Invariant
           (for all I in 0 .. R_Len - 1 => R (I) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all I in R_Len .. Idx - 1 => R (I) in 0 .. Q - 1);
         pragma Loop_Invariant
           (for all I in Idx .. N - 1 => R (I) = 0);
         Val0 := (U16 (Buf (Pos))
                  or Interfaces.Shift_Left (U16 (Buf (Pos + 1)), 8))
                 and 16#FFF#;
         Val1 := Interfaces.Shift_Right (U16 (Buf (Pos + 1)), 4)
                 or Interfaces.Shift_Left (U16 (Buf (Pos + 2)), 4);
         Pos  := Pos + 3;
         if Val0 < U16 (Q) then
            R (Idx) := I16 (Val0);
            Idx := Idx + 1;
         end if;
         if Idx < N and then Val1 < U16 (Q) then
            R (Idx) := I16 (Val1);
            Idx := Idx + 1;
         end if;
      end loop;
      R_Len := Idx;
   end RejUniform;

end ML_KEM.Sampling;
