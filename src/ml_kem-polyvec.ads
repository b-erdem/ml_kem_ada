with ML_KEM.NTT;

package ML_KEM.PolyVec is

   pragma Pure;
   pragma SPARK_Mode;

   procedure PolyVec_Add (R : in out ML_KEM.Poly_Vector; B : ML_KEM.Poly_Vector)
     with Pre  => (for all I in 0 .. ML_KEM_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        I32 (R (I) (J)) + I32 (B (I) (J))
                        in I32 (I16'First) .. I32 (I16'Last))),
          Post => (for all I in 0 .. ML_KEM_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) = R'Old (I) (J) + B (I) (J)));

   procedure PolyVec_NTT (R : in out ML_KEM.Poly_Vector)
     with Pre  => (for all I in 0 .. ML_KEM_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) in -Q .. Q)),
          Post => (for all I in 0 .. ML_KEM_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) in -Q_Half .. Q_Half));

   procedure PolyVec_InvNTT (R : in out ML_KEM.Poly_Vector)
     with Pre  => (for all I in 0 .. ML_KEM_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) in -(2 * Q) .. (2 * Q))),
          Post => (for all I in 0 .. ML_KEM_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        R (I) (J) in -Q .. Q));

   procedure PolyVec_Basemul_Acc
     (R    : in out Polynomial;
      A    : ML_KEM.Poly_Vector;
      B    : ML_KEM.Poly_Vector)
     with Pre  => (for all I in 0 .. ML_KEM_K - 1 =>
                     (for all J in 0 .. N - 1 =>
                        A (I) (J) in -(2 * Q) .. (2 * Q)))
                  and then (for all I in 0 .. ML_KEM_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 B (I) (J) in -(2 * Q) .. (2 * Q))),
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -Q_Half .. Q_Half);

   procedure PolyVec_Reduce (R : in out ML_KEM.Poly_Vector);

   procedure PolyVec_Freeze (R : in out ML_KEM.Poly_Vector)
     with Post => (for all I in 0 .. ML_KEM_K - 1 =>
                     (for all J in 0 .. N - 1 => R (I) (J) in 0 .. Q - 1));

end ML_KEM.PolyVec;
