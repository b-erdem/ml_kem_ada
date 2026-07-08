package body ML_KEM.Wipe is

   pragma SPARK_Mode (On);

   procedure Wipe_Byte_Array (X : in out Byte_Array) is
   begin
      for I in X'Range loop
         pragma Loop_Invariant
           (for all J in X'First .. I - 1 => X (J) = 0);
         X (I) := 0;
      end loop;
   end Wipe_Byte_Array;

   procedure Wipe_Polynomial (X : in out Polynomial) is
   begin
      for I in X'Range loop
         pragma Loop_Invariant
           (for all J in X'First .. I - 1 => X (J) = 0);
         X (I) := 0;
      end loop;
   end Wipe_Polynomial;

   procedure Wipe_Poly_Vector (X : in out Poly_Vector) is
   begin
      for I in X'Range loop
         pragma Loop_Invariant
           (for all II in X'First .. I - 1 =>
              (for all J in X (II)'Range => X (II) (J) = 0));
         Wipe_Polynomial (X (I));
      end loop;
   end Wipe_Poly_Vector;

end ML_KEM.Wipe;
