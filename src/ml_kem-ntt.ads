package ML_KEM.NTT is

   pragma Pure;
   pragma SPARK_Mode;

   --  Forward NTT bound analysis.
   --
   --  Each butterfly (R[j], R[j+len]) := (R[j] + t, R[j] - t) where
   --  t = FqMul(zeta, R[j+len]) and FqMul postcondition gives |t| <= Q.
   --  So bound grows by Q per butterfly layer. With initial bound B0
   --  the bound after 7 layers is B0 + 7Q. With B0 = Q the final
   --  bound is 8Q = 26632 < 2^15 = 32768, so all intermediate values
   --  fit in I16 and all FqMul preconditions hold.
   --
   --  The input precondition R(I) in -Q .. Q covers all call sites:
   --  - CBD output (range -Eta..Eta, ie -2..2 for ML-KEM-768)
   --  - Decompress_Du / Decompress_Dv output (0..Q-1)
   --  - any Barrett-reduced or Freeze'd polynomial.

   NTT_Bound : constant := 8 * Q;
   --  Max |R(I)| after a full forward NTT starting from |R(I)| <= Q.

   procedure NTT (R : in out Polynomial)
     with Pre  => (for all I in 0 .. N - 1 => R (I) in -Q .. Q),
          Post => (for all I in 0 .. N - 1 => R (I) in -NTT_Bound .. NTT_Bound);

   --  Inverse NTT bound analysis.
   --
   --  Each layer applies Barrett to one half of the butterfly output and
   --  FqMul to the other, so after every layer the bound is max(Q_Half, Q) = Q.
   --  The intermediate sum R(J) + R(J+Len) before Barrett needs to fit
   --  in I16; with |R| <= Q before the layer (or 2Q before the very first
   --  layer that uses BaseMul output), the sum is at most 2Q + Q = 3Q
   --  for the worst case, well within I16.
   --
   --  Final scaling by F_InvNTT = 1441 uses FqMul which yields |R(I)| <= Q.

   InvNTT_Input_Bound : constant := 2 * Q;
   --  Conservative pre: BaseMul output is bounded by 2Q.

   procedure InvNTT (R : in out Polynomial)
     with Pre  => (for all I in 0 .. N - 1 =>
                     R (I) in -InvNTT_Input_Bound .. InvNTT_Input_Bound),
          Post => (for all I in 0 .. N - 1 => R (I) in -Q .. Q);

   --  BaseMul: pointwise multiplication in NTT domain over Z_q[X]/(X^2 - zeta).
   --
   --  Input bound: |A(I)|, |B(I)| <= 2Q. This covers
   --   * PolyVec_NTT output (Barrett-reduced, in -Q_Half..Q_Half)
   --   * raw ByteDecode12 output [0, 4095] from Unpack_PK / Unpack_SK
   --     (4095 < 2Q = 6658 in this parameter set), and
   --   * Decompress output (in [0, Q-1]).
   --
   --  FqMul precondition: |A*B| <= (2Q)*(2Q) = 4*Q^2 = 44_372_032
   --  which is well below Q*2**15 = 109_051_904.
   --
   --  Output bound: each output is the sum of two FqMul results (each in
   --  -Q..Q), so |R(I)| <= 2Q.

   BaseMul_Input_Bound : constant := 2 * Q;
   BaseMul_Bound       : constant := 2 * Q;

   procedure BaseMul (R : out Polynomial; A, B : Polynomial)
     with Pre  => (for all I in 0 .. N - 1 =>
                     A (I) in -BaseMul_Input_Bound .. BaseMul_Input_Bound)
                  and then (for all I in 0 .. N - 1 =>
                     B (I) in -BaseMul_Input_Bound .. BaseMul_Input_Bound),
          Post => (for all I in 0 .. N - 1 =>
                     R (I) in -BaseMul_Bound .. BaseMul_Bound);

end ML_KEM.NTT;
