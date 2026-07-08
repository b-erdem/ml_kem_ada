package body ML_KEM.CBD is
   pragma SPARK_Mode (On);

   Mask2 : constant U32 := 16#55555555#;
   Mask3 : constant U32 := 16#00249249#;

   procedure CBD2 (R : out Polynomial; Buf : Byte_Array_128) is
      T : U32;
      D : U32;
      A : I16;
      B : I16;
   begin
      R := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. 8 * I - 1 => R (J) in -2 .. 2);
         T := Load32_LE (Buf (4 * I), Buf (4 * I + 1),
                         Buf (4 * I + 2), Buf (4 * I + 3));
         D := (T and Mask2) + (Interfaces.Shift_Right (T, 1) and Mask2);
         for J in 0 .. 7 loop
            pragma Loop_Invariant
              (for all K in 0 .. 8 * I + J - 1 => R (K) in -2 .. 2);
            A := I16 (Interfaces.Shift_Right (D, 4 * J) and 16#3#);
            B := I16 (Interfaces.Shift_Right (D, 4 * J + 2) and 16#3#);
            R (8 * I + J) := A - B;
            pragma Assert (R (8 * I + J) in -2 .. 2);
         end loop;
      end loop;
   end CBD2;

   procedure CBD3 (R : out Polynomial; Buf : Byte_Array_192) is
      T : U32;
      D : U32;
      A : I16;
      B : I16;
   begin
      R := [others => 0];
      for I in 0 .. 63 loop
         pragma Loop_Invariant
           (for all J in 0 .. 4 * I - 1 => R (J) in -3 .. 3);
         T := Load24_LE (Buf (3 * I), Buf (3 * I + 1), Buf (3 * I + 2));
         D := (T and Mask3)
              + (Interfaces.Shift_Right (T, 1) and Mask3)
              + (Interfaces.Shift_Right (T, 2) and Mask3);
         for J in 0 .. 3 loop
            pragma Loop_Invariant
              (for all K in 0 .. 4 * I + J - 1 => R (K) in -3 .. 3);
            A := I16 (Interfaces.Shift_Right (D, 6 * J) and 16#7#);
            B := I16 (Interfaces.Shift_Right (D, 6 * J + 3) and 16#7#);
            R (4 * I + J) := A - B;
            pragma Assert (R (4 * I + J) in -3 .. 3);
         end loop;
      end loop;
   end CBD3;

   procedure Sample_Eta1 (R : out Polynomial; Buf : Byte_Array) is
      --  Static dispatch on ML_KEM_Eta1.  Both branches are present
      --  in the source but only one is reachable for any given
      --  parameter-set build; GNAT at -O2 folds the constant and
      --  emits only the live branch.
   begin
      if ML_KEM_Eta1 = 2 then
         CBD2 (R, Byte_Array_128 (Buf));
      else  --  ML_KEM_Eta1 = 3
         CBD3 (R, Byte_Array_192 (Buf));
      end if;
   end Sample_Eta1;

end ML_KEM.CBD;
