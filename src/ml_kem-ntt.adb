with ML_KEM.NTT_Zetas;
with ML_KEM.Reduce;

package body ML_KEM.NTT is
   pragma SPARK_Mode (On);

   F_InvNTT : constant I16 := 1441;

   --  Single butterfly: t = FqMul(zeta, R(J_Plus_Len)); then
   --  R(J_Plus_Len) := R(J) - t; R(J) := R(J) + t.
   --
   --  Bound contract: if all coefficients are in -B_In..B_In then:
   --   * FqMul precondition |zeta*R(J_Plus_Len)| <= (Q-1)*B_In holds
   --     iff (Q-1)*B_In <= Q*2**15 - 1, equivalent to B_In <= 32_775
   --     so B_In <= 8Q = 26_632 fits.
   --   * After the butterfly R(J), R(J_Plus_Len) are in -(B_In+Q)..(B_In+Q)
   --     (FqMul output is in -Q..Q so R(J) +- t is in -(B_In+Q)..(B_In+Q)).
   --   * Other coefficients are unchanged.
   procedure Butterfly
     (R          : in out Polynomial;
      J          : Natural;
      J_Plus_Len : Natural;
      Zeta       : NTT_Zetas.Zeta_Type;
      B_In       : I16)
     with Pre  => J < J_Plus_Len
                  and then J_Plus_Len < N
                  and then B_In in Q .. 7 * Q
                  and then (for all I in 0 .. N - 1 =>
                              R (I) in -(B_In + Q) .. (B_In + Q))
                  and then R (J) in -B_In .. B_In
                  and then R (J_Plus_Len) in -B_In .. B_In,
          Post => (for all I in 0 .. N - 1 =>
                     (if I = J or I = J_Plus_Len then
                        R (I) in -(B_In + Q) .. (B_In + Q)
                      else
                        R (I) = R'Old (I)));

   procedure Butterfly
     (R          : in out Polynomial;
      J          : Natural;
      J_Plus_Len : Natural;
      Zeta       : NTT_Zetas.Zeta_Type;
      B_In       : I16)
   is
      T : I16;
   begin
      T := Reduce.FqMul (Zeta, R (J_Plus_Len));
      R (J_Plus_Len) := R (J) - T;
      R (J) := R (J) + T;
   end Butterfly;

   procedure NTT (R : in out Polynomial) is
      Len   : Natural := 128;
      Start : Natural;
      K_Idx : Natural := 1;
      Bound : I16 := Q;
      --  Bound on |R(I)| at the start of each outer (Len) iteration.
      --  Initially Q (input precondition). Each butterfly produces
      --  R(j) +- t with |t| <= Q (FqMul postcondition), so after one
      --  full layer Bound grows by Q. After 7 layers we're at 8Q =
      --  NTT_Bound, well below 2^15 = 32768.
   begin
      while Len >= 2 loop
         pragma Loop_Invariant (Len in 2 | 4 | 8 | 16 | 32 | 64 | 128);
         pragma Loop_Invariant (K_Idx in 1 | 2 | 4 | 8 | 16 | 32 | 64);
         pragma Loop_Invariant (K_Idx * Len = 128);
         pragma Loop_Invariant
           ((Len = 128 and Bound = 1 * Q) or
            (Len = 64  and Bound = 2 * Q) or
            (Len = 32  and Bound = 3 * Q) or
            (Len = 16  and Bound = 4 * Q) or
            (Len = 8   and Bound = 5 * Q) or
            (Len = 4   and Bound = 6 * Q) or
            (Len = 2   and Bound = 7 * Q));
         pragma Loop_Invariant
           (for all I in 0 .. N - 1 => R (I) in -Bound .. Bound);

         Start := 0;
         while Start < N loop
            pragma Loop_Invariant (Len in 2 | 4 | 8 | 16 | 32 | 64 | 128);
            pragma Loop_Invariant (Start mod (2 * Len) = 0);
            pragma Loop_Invariant (Start <= N);
            pragma Loop_Invariant (Start + 2 * Len <= N);
            pragma Loop_Invariant (K_Idx * Len = 128 + Start / 2);
            pragma Loop_Invariant (K_Idx in 1 .. 127);
            pragma Loop_Invariant (Bound in Q .. 7 * Q);
            --  Already-processed segments: positions [0, Start-1] are
            --  in the looser post-layer bound -(Bound+Q)..(Bound+Q).
            pragma Loop_Invariant
              (for all I in 0 .. Start - 1 =>
                 R (I) in -(Bound + Q) .. (Bound + Q));
            --  Untouched segments: positions [Start, N-1] are still
            --  in the original layer-entry bound -Bound..Bound.
            pragma Loop_Invariant
              (for all I in Start .. N - 1 => R (I) in -Bound .. Bound);
            pragma Loop_Variant (Increases => Start);

            --  Process one segment [Start, Start+2*Len-1] in place.
            --  Each butterfly touches J and J+Len, both fresh.
            for J in Start .. Start + Len - 1 loop
               pragma Loop_Invariant (J in Start .. Start + Len - 1);
               pragma Loop_Invariant (J + Len <= N - 1);
               pragma Loop_Invariant (K_Idx in 1 .. 127);
               pragma Loop_Invariant (Bound in Q .. 7 * Q);
               --  Prior segments still in the post bound.
               pragma Loop_Invariant
                 (for all I in 0 .. Start - 1 =>
                    R (I) in -(Bound + Q) .. (Bound + Q));
               --  Low half already processed in this segment.
               pragma Loop_Invariant
                 (for all I in Start .. J - 1 =>
                    R (I) in -(Bound + Q) .. (Bound + Q));
               --  High half already processed in this segment.
               pragma Loop_Invariant
                 (for all I in Start + Len .. J + Len - 1 =>
                    R (I) in -(Bound + Q) .. (Bound + Q));
               --  Low half still pending (includes current J).
               pragma Loop_Invariant
                 (for all I in J .. Start + Len - 1 =>
                    R (I) in -Bound .. Bound);
               --  High half still pending (includes current J+Len).
               pragma Loop_Invariant
                 (for all I in J + Len .. Start + 2 * Len - 1 =>
                    R (I) in -Bound .. Bound);
               --  Subsequent segments untouched.
               pragma Loop_Invariant
                 (for all I in Start + 2 * Len .. N - 1 =>
                    R (I) in -Bound .. Bound);
               --  Loose universal bound for Butterfly precondition.
               pragma Loop_Invariant
                 (for all I in 0 .. N - 1 =>
                    R (I) in -(Bound + Q) .. (Bound + Q));

               Butterfly (R, J, J + Len, NTT_Zetas.Zetas (K_Idx), Bound);
            end loop;

            K_Idx := K_Idx + 1;
            Start := Start + 2 * Len;
         end loop;

         Len := Len / 2;
         Bound := Bound + Q;
      end loop;
   end NTT;

   --  Inverse butterfly: T := R(J); R(J) := Barrett(T + R(J+Len));
   --  R(J+Len) := R(J+Len) - T; R(J+Len) := FqMul(Zeta, R(J+Len)).
   --
   --  Bound contract: input both positions in -B_In..B_In with
   --  2*B_In <= I16'Last. After: R(J) in -Q_Half..Q_Half (Barrett),
   --  R(J+Len) in -Q..Q (FqMul). So both end up in -Q..Q.
   procedure InvButterfly
     (R          : in out Polynomial;
      J          : Natural;
      J_Plus_Len : Natural;
      Zeta       : NTT_Zetas.Zeta_Type;
      B_In       : I16)
     with Pre  => J < J_Plus_Len
                  and then J_Plus_Len < N
                  and then B_In in Q .. 2 * Q
                  and then R (J) in -B_In .. B_In
                  and then R (J_Plus_Len) in -B_In .. B_In,
          Post => R (J) in -Q .. Q
                  and then R (J_Plus_Len) in -Q .. Q
                  and then (for all I in 0 .. N - 1 =>
                              (if I /= J and I /= J_Plus_Len then
                                 R (I) = R'Old (I)));

   procedure InvButterfly
     (R          : in out Polynomial;
      J          : Natural;
      J_Plus_Len : Natural;
      Zeta       : NTT_Zetas.Zeta_Type;
      B_In       : I16)
   is
      T : I16 := R (J);
   begin
      --  T + R(J+Len) fits in I16: |T + R(J+Len)| <= 2*B_In <= 4Q = 13_316.
      R (J) := Reduce.Barrett_Reduce (T + R (J_Plus_Len));
      R (J_Plus_Len) := R (J_Plus_Len) - T;
      --  After subtraction |R(J+Len)| <= 2*B_In. FqMul precondition:
      --    |Zeta * R(J+Len)| <= (Q-1) * 2*B_In <= (Q-1)*4Q = 44_372_032
      --  < Q*2**15 = 109_051_904.
      R (J_Plus_Len) := Reduce.FqMul (Zeta, R (J_Plus_Len));
   end InvButterfly;

   procedure InvNTT (R : in out Polynomial) is
      Len   : Natural := 2;
      Start : Natural;
      K_Idx : Natural := 127;
      Bound : I16 := InvNTT_Input_Bound;
      --  Bound on |R(I)| at the start of each outer (Len) iteration.
      --  Initially InvNTT_Input_Bound = 2Q (BaseMul accumulator output).
      --  After the first layer every coefficient went through Barrett or
      --  FqMul, so all |R(I)| <= Q; from layer 2 onward Bound stays at Q.
   begin
      while Len <= 128 loop
         pragma Loop_Invariant (Len in 2 | 4 | 8 | 16 | 32 | 64 | 128);
         pragma Loop_Invariant (K_Idx in 1 | 3 | 7 | 15 | 31 | 63 | 127);
         pragma Loop_Invariant ((K_Idx + 1) * Len = 256);
         pragma Loop_Invariant (Bound in Q .. InvNTT_Input_Bound);
         pragma Loop_Invariant
           (for all I in 0 .. N - 1 => R (I) in -Bound .. Bound);

         Start := 0;
         while Start < N loop
            pragma Loop_Invariant (Len in 2 | 4 | 8 | 16 | 32 | 64 | 128);
            pragma Loop_Invariant (Start mod (2 * Len) = 0);
            pragma Loop_Invariant (Start <= N);
            pragma Loop_Invariant (Start + 2 * Len <= N);
            pragma Loop_Invariant ((K_Idx + 1) * Len = 256 - Start / 2);
            pragma Loop_Invariant (K_Idx in 1 .. 127);
            pragma Loop_Invariant (Bound in Q .. InvNTT_Input_Bound);
            --  Prior segments processed by InvButterfly: |.| <= Q.
            pragma Loop_Invariant
              (for all I in 0 .. Start - 1 => R (I) in -Q .. Q);
            --  Untouched suffix still at layer-entry bound.
            pragma Loop_Invariant
              (for all I in Start .. N - 1 => R (I) in -Bound .. Bound);
            pragma Loop_Variant (Increases => Start);

            for J in Start .. Start + Len - 1 loop
               pragma Loop_Invariant (J in Start .. Start + Len - 1);
               pragma Loop_Invariant (J + Len <= N - 1);
               pragma Loop_Invariant (K_Idx in 1 .. 127);
               pragma Loop_Invariant (Bound in Q .. InvNTT_Input_Bound);
               --  Prior segments fully processed.
               pragma Loop_Invariant
                 (for all I in 0 .. Start - 1 => R (I) in -Q .. Q);
               --  Low half processed in current segment.
               pragma Loop_Invariant
                 (for all I in Start .. J - 1 => R (I) in -Q .. Q);
               --  High half processed in current segment.
               pragma Loop_Invariant
                 (for all I in Start + Len .. J + Len - 1 => R (I) in -Q .. Q);
               --  Low half pending (includes current J).
               pragma Loop_Invariant
                 (for all I in J .. Start + Len - 1 =>
                    R (I) in -Bound .. Bound);
               --  High half pending (includes current J+Len).
               pragma Loop_Invariant
                 (for all I in J + Len .. Start + 2 * Len - 1 =>
                    R (I) in -Bound .. Bound);
               --  Subsequent segments untouched.
               pragma Loop_Invariant
                 (for all I in Start + 2 * Len .. N - 1 =>
                    R (I) in -Bound .. Bound);

               InvButterfly (R, J, J + Len, NTT_Zetas.Zetas (K_Idx), Bound);
            end loop;

            K_Idx := K_Idx - 1;
            Start := Start + 2 * Len;
         end loop;

         --  Whole array now in -Q..Q after this layer.
         Bound := Q;
         Len := Len * 2;
      end loop;

      for J in 0 .. N - 1 loop
         pragma Loop_Invariant
           (for all I in J .. N - 1 => R (I) in -Q .. Q);
         pragma Loop_Invariant
           (for all I in 0 .. J - 1 => R (I) in -Q .. Q);
         --  FqMul precondition: |R(J) * F_InvNTT| <= Q * 1441 = 4_797_089
         --  < Q * 2**15.
         R (J) := Reduce.FqMul (R (J), F_InvNTT);
      end loop;
   end InvNTT;

   procedure BaseMul (R : out Polynomial; A, B : Polynomial) is
      Zeta : NTT_Zetas.Zeta_Type;
      M0   : I16;  --  FqMul (A(4i+1), B(4i+1)),  in [-Q, Q]
      M1   : I16;  --  FqMul (A(4i),   B(4i)),    in [-Q, Q]
      M2   : I16;  --  FqMul (A(4i+3), B(4i+3)),  in [-Q, Q]
      M3   : I16;  --  FqMul (A(4i+2), B(4i+2)),  in [-Q, Q]
      M4   : I16;  --  FqMul (A(4i),   B(4i+1)),  in [-Q, Q]
      M5   : I16;  --  FqMul (A(4i+1), B(4i)),    in [-Q, Q]
      M6   : I16;  --  FqMul (A(4i+2), B(4i+3)),  in [-Q, Q]
      M7   : I16;  --  FqMul (A(4i+3), B(4i+2)),  in [-Q, Q]
   begin
      R := [others => 0];
      for I in 0 .. 63 loop
         pragma Loop_Invariant
           (for all J in 0 .. 4 * I - 1 =>
              R (J) in -BaseMul_Bound .. BaseMul_Bound);

         Zeta := NTT_Zetas.Zetas (64 + I);

         --  All eight FqMul preconditions follow from inputs in
         --  -Q_Half .. Q_Half: |a*b| <= Q_Half**2 = 2_768_896 which
         --  is well below Q * 2**15 = 109_051_904.
         M0 := Reduce.FqMul (A (4 * I + 1), B (4 * I + 1));
         M1 := Reduce.FqMul (A (4 * I),     B (4 * I));
         M2 := Reduce.FqMul (A (4 * I + 3), B (4 * I + 3));
         M3 := Reduce.FqMul (A (4 * I + 2), B (4 * I + 2));
         M4 := Reduce.FqMul (A (4 * I),     B (4 * I + 1));
         M5 := Reduce.FqMul (A (4 * I + 1), B (4 * I));
         M6 := Reduce.FqMul (A (4 * I + 2), B (4 * I + 3));
         M7 := Reduce.FqMul (A (4 * I + 3), B (4 * I + 2));

         --  Outer FqMul preconditions: |Mk * Zeta| <= Q * (Q-1) =
         --  11_078_912 < Q * 2**15. Mk is bounded by the FqMul
         --  postcondition; Zeta is bounded by the Zeta_Type subtype.
         R (4 * I) := Reduce.FqMul (M0, Zeta) + M1;
         R (4 * I + 1) := M4 + M5;
         R (4 * I + 2) := Reduce.FqMul (M2, -Zeta) + M3;
         R (4 * I + 3) := M6 + M7;
      end loop;
   end BaseMul;

end ML_KEM.NTT;
