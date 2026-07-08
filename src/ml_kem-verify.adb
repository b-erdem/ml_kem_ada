with Interfaces;

package body ML_KEM.Verify is
   pragma SPARK_Mode (On);

   function Verify (A, B : Byte_Array) return U8 is
      D : Interfaces.Unsigned_32 := 0;
   begin
      for I in A'Range loop
         pragma Loop_Invariant (D = 0 or D > 0);
         pragma Assert
           (B'First + (I - A'First) >= B'First
            and then B'First + (I - A'First) <= B'Last);
         D := D or Interfaces.Unsigned_32
           (A (I) xor B (B'First + (I - A'First)));
      end loop;
      D := D or Interfaces.Shift_Right (D, 16);
      D := D or Interfaces.Shift_Right (D, 8);
      D := D or Interfaces.Shift_Right (D, 4);
      D := D or Interfaces.Shift_Right (D, 2);
      D := D or Interfaces.Shift_Right (D, 1);
      return U8 ((not D) and 1);
   end Verify;

   procedure CMOV
     (R         : in out Byte_Array;
      A         : Byte_Array;
      Condition : U8)
   is
      Mask : constant U8 := -Condition;
   begin
      for I in R'Range loop
         pragma Assert
           (A'First + (I - R'First) >= A'First
            and then A'First + (I - R'First) <= A'Last);
         R (I) := (R (I) and (not Mask))
           or (A (A'First + (I - R'First)) and Mask);
      end loop;
   end CMOV;

end ML_KEM.Verify;
