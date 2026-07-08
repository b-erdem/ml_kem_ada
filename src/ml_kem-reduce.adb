package body ML_KEM.Reduce is
   pragma SPARK_Mode (On);

   V_Barrett : constant := 20159;

    function Montgomery_Reduce (A : I32) return I16 is
       A_Low : constant U16 := U16 (A mod 2**16);
       T_U16 : constant U16 := A_Low * Q_Inv;
       T_S32 : constant I32 :=
         I32 (Interfaces.Unsigned_32 (T_U16))
         - (if T_U16 > 16#7FFF# then 2**16 else 0);
       R     : I32;
    begin
       R := (A - T_S32 * Q) / 2**16;
      if A - T_S32 * Q < 0 and then (A - T_S32 * Q) rem 2**16 /= 0 then
          R := R - 1;
       end if;
       pragma Assert (R in -Q .. Q);
       return I16 (R);
    end Montgomery_Reduce;

    function Barrett_Reduce (A : I16) return I16 is
       R : I32;
       T : I32;
    begin
       R := V_Barrett * I32 (A) + 2**25;
       T := R / 2**26;
       if R < 0 and then R rem 2**26 /= 0 then
          T := T - 1;
       end if;
       pragma Assert (T in -10 .. 10);
       T := T * Q;
       pragma Assert (T in -10 * Q .. 10 * Q);
       return I16 (I32 (A) - T);
    end Barrett_Reduce;

   function FqMul (A, B : I16) return I16 is
   begin
      return Montgomery_Reduce (I32 (A) * I32 (B));
   end FqMul;

end ML_KEM.Reduce;
