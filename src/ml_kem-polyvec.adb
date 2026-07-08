with ML_KEM.NTT;
with ML_KEM.Poly;

package body ML_KEM.PolyVec is
   pragma SPARK_Mode (On);

   procedure PolyVec_Add (R : in out ML_KEM.Poly_Vector; B : ML_KEM.Poly_Vector) is
   begin
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (K) (J) = R'Loop_Entry (K) (J) + B (K) (J)));
         pragma Loop_Invariant
           (for all K in I .. ML_KEM_K - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (K) (J) = R'Loop_Entry (K) (J)));
         Poly.Poly_Add (R (I), B (I));
      end loop;
   end PolyVec_Add;

    procedure PolyVec_NTT (R : in out ML_KEM.Poly_Vector) is
    begin
       for I in 0 .. ML_KEM_K - 1 loop
          pragma Loop_Invariant
            (for all K in 0 .. I - 1 =>
               (for all J in 0 .. N - 1 =>
                  R (K) (J) in -Q_Half .. Q_Half));
          pragma Loop_Invariant
            (for all K in I .. ML_KEM_K - 1 =>
               (for all J in 0 .. N - 1 => R (K) (J) in -Q .. Q));
          NTT.NTT (R (I));
          Poly.Poly_Reduce (R (I));
       end loop;
    end PolyVec_NTT;

   procedure PolyVec_InvNTT (R : in out ML_KEM.Poly_Vector) is
   begin
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 => R (K) (J) in -Q .. Q));
         pragma Loop_Invariant
           (for all K in I .. ML_KEM_K - 1 =>
              (for all J in 0 .. N - 1 =>
                 R (K) (J) in -(2 * Q) .. (2 * Q)));
         NTT.InvNTT (R (I));
      end loop;
   end PolyVec_InvNTT;

   procedure PolyVec_Basemul_Acc
     (R    : in out Polynomial;
      A    : ML_KEM.Poly_Vector;
      B    : ML_KEM.Poly_Vector)
   is
      T : Polynomial;
   begin
      NTT.BaseMul (R, A (0), B (0));
      --  After first BaseMul: |R(I)| <= 2Q (BaseMul postcondition).

      for I in 1 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. N - 1 =>
              I32 (R (J)) in -I32 (I * 2 * Q) .. I32 (I * 2 * Q));

         NTT.BaseMul (T, A (I), B (I));
         --  T in -2Q..2Q. R + T fits in I16:
         --    max |R+T| <= I*2Q + 2Q = (I+1)*2Q
         --  with I <= ML_KEM_K - 1 = 2: max = 6Q = 19_974 < I16'Last.
         Poly.Poly_Add (R, T);
      end loop;

      --  After loop: |R(I)| <= ML_KEM_K * 2Q = 6Q (for K=3).
      Poly.Poly_Reduce (R);
      --  After Barrett reduce: R(I) in -Q_Half..Q_Half, satisfies post.
   end PolyVec_Basemul_Acc;

   procedure PolyVec_Reduce (R : in out ML_KEM.Poly_Vector) is
   begin
      for I in 0 .. ML_KEM_K - 1 loop
         Poly.Poly_Reduce (R (I));
      end loop;
   end PolyVec_Reduce;

   procedure PolyVec_Freeze (R : in out ML_KEM.Poly_Vector) is
   begin
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 =>
               (for all K in 0 .. N - 1 => R (J) (K) in 0 .. Q - 1));
         Poly.Poly_Freeze (R (I));
      end loop;
   end PolyVec_Freeze;

end ML_KEM.PolyVec;
