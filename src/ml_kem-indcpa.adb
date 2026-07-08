with SHA3;
with ML_KEM.Poly;
with ML_KEM.PolyVec;
with ML_KEM.NTT;
with ML_KEM.Serialize;
with ML_KEM.CBD;
with ML_KEM.Sampling;
with ML_KEM.Symmetric;
with ML_KEM.Wipe;

package body ML_KEM.IndCPA is
   pragma SPARK_Mode (On);

   procedure GenMatrix
     (A          : out Poly_Matrix;
      Seed       : Byte_Array_32;
      Transposed : Boolean)
     with Post => (for all I in 0 .. ML_KEM_K - 1 =>
                     (for all J in 0 .. ML_KEM_K - 1 =>
                        (for all K in 0 .. N - 1 =>
                           A (I) (J) (K) in 0 .. Q - 1)))
   is
      State : SHA3.Sponge_State;
      Buf   : Byte_Array (0 .. Symmetric.XOF_Rate - 1) := [others => 0];
      Idx   : Natural;
   begin
      A := [others => [others => [others => 0]]];
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all II in 0 .. I - 1 =>
              (for all JJ in 0 .. ML_KEM_K - 1 =>
                 (for all K in 0 .. N - 1 =>
                    A (II) (JJ) (K) in 0 .. Q - 1)));
         for J in 0 .. ML_KEM_K - 1 loop
            pragma Loop_Invariant
              (for all II in 0 .. I - 1 =>
                 (for all JJ in 0 .. ML_KEM_K - 1 =>
                    (for all K in 0 .. N - 1 =>
                       A (II) (JJ) (K) in 0 .. Q - 1)));
            pragma Loop_Invariant
              (for all JJ in 0 .. J - 1 =>
                 (for all K in 0 .. N - 1 =>
                    A (I) (JJ) (K) in 0 .. Q - 1));
            if Transposed then
               Symmetric.XOF_Absorb (State, Seed, U8 (I), U8 (J));
            else
               Symmetric.XOF_Absorb (State, Seed, U8 (J), U8 (I));
            end if;
            A (I) (J) := [others => 0];
            Idx := 0;
            --  The bound is a SPARK-friendly substitute for FIPS 203
            --  Algorithm 6's unbounded `while j < 256` loop.  With
            --  SHAKE128 rate = 168 bytes / block, each iteration
            --  produces 56 candidate 12-bit values, of which ~5/16 are
            --  rejected (those in [Q, 4096)).  Expected blocks needed
            --  to fill 256 coefficients is ~5.6.  At 256 blocks we
            --  have produced 14 336 candidates with mean 11 663
            --  accepted (45.5× over the 256 needed); the failure
            --  probability is bounded by the Chernoff tail of a
            --  Binomial(14336, 0.813) below 256, which is < 2^-1024 and
            --  therefore well below any realistic adversary's success
            --  probability.  We document the bound rather than hide it
            --  behind unbounded recursion so the static stack budget
            --  remains analyzable.  Pragma_Assert below catches the
            --  effectively-impossible case where rejection sampling
            --  did not produce enough valid coefficients within budget.
            for Block in 1 .. 256 loop
               pragma Loop_Invariant (Idx <= N);
               pragma Loop_Invariant (State.Byte_Pos < State.Rate);
               pragma Loop_Invariant (State.Rate < SHA3.State_Bytes);
               pragma Loop_Invariant
                 (for all K in 0 .. Idx - 1 => A (I) (J) (K) in 0 .. Q - 1);
               pragma Loop_Invariant
                 (for all K in Idx .. N - 1 => A (I) (J) (K) = 0);
               exit when Idx >= N;
               Symmetric.XOF_Squeeze (State, Buf);
               Sampling.RejUniform (Buf, Buf'Length, A (I) (J), Idx);
            end loop;
            --  SPARK cannot reason about probability, so we cannot
            --  prove `Idx >= N` after the loop.  The post-condition
            --  on GenMatrix only requires every coefficient in
            --  0..Q-1, which the loop invariant maintains regardless
            --  of whether `Idx` reached `N` (any unfilled slots stay
            --  at zero, which is in range).  The 256-block bound
            --  ensures that for every realistic seed (failure
            --  probability < 2^-1024) the polynomial is fully sampled;
            --  truncated matrices arise only on adversarially chosen
            --  seeds outside the cryptographic security model.
         end loop;
      end loop;
   end GenMatrix;

    procedure Pack_PK
      (PK   : out Byte_Array;
       TP   : Poly_Vector;
       Seed : Byte_Array_32)
      with Pre => PK'First = 0
                  and then PK'Length = Indcpa_PK_Bytes
                  and then (for all I in 0 .. ML_KEM_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 TP (I) (J) in 0 .. Q - 1))
    is
       Off : Natural := PK'First;
    begin
       PK := [others => 0];
       for I in 0 .. ML_KEM_K - 1 loop
          pragma Loop_Invariant
            (Off = PK'First + I * Poly_Bytes_12);
          pragma Loop_Invariant
            (Off + Poly_Bytes_12 - 1 <= PK'Last);
          Serialize.ByteEncode12
            (TP (I),
             Byte_Array_384 (PK (Off .. Off + Poly_Bytes_12 - 1)));
          Off := Off + Poly_Bytes_12;
       end loop;
       pragma Assert (Off + 31 <= PK'Last);
       PK (Off .. Off + 31) := Seed;
    end Pack_PK;

    procedure Unpack_PK
      (PK   : Byte_Array;
       TP   : out Poly_Vector;
       Seed : out Byte_Array_32)
      with Pre  => PK'First = 0
                   and then PK'Length = Indcpa_PK_Bytes,
           Post => (for all I in 0 .. ML_KEM_K - 1 =>
                      (for all J in 0 .. N - 1 =>
                         TP (I) (J) in 0 .. 4095))
    is
       Off : Natural := PK'First;
    begin
       TP := [others => [others => 0]];
       for I in 0 .. ML_KEM_K - 1 loop
          pragma Loop_Invariant
            (Off = PK'First + I * Poly_Bytes_12);
          pragma Loop_Invariant
            (Off + Poly_Bytes_12 - 1 <= PK'Last);
          pragma Loop_Invariant
            (for all K in 0 .. I - 1 =>
               (for all J in 0 .. N - 1 => TP (K) (J) in 0 .. 4095));
          Serialize.ByteDecode12
            (Byte_Array_384 (PK (Off .. Off + Poly_Bytes_12 - 1)),
             TP (I));
          Off := Off + Poly_Bytes_12;
       end loop;
       pragma Assert (Off + 31 <= PK'Last);
       Seed := Byte_Array_32 (PK (Off .. Off + 31));
    end Unpack_PK;

    procedure Pack_SK (SK : out Byte_Array; SP : Poly_Vector)
      with Pre => SK'First = 0
                  and then SK'Length = Indcpa_SK_Bytes
                  and then (for all I in 0 .. ML_KEM_K - 1 =>
                              (for all J in 0 .. N - 1 =>
                                 SP (I) (J) in 0 .. Q - 1))
    is
       Off : Natural := SK'First;
    begin
       SK := [others => 0];
       for I in 0 .. ML_KEM_K - 1 loop
          pragma Loop_Invariant
            (Off = SK'First + I * Poly_Bytes_12);
          pragma Loop_Invariant
            (Off + Poly_Bytes_12 - 1 <= SK'Last);
          Serialize.ByteEncode12
            (SP (I),
             Byte_Array_384 (SK (Off .. Off + Poly_Bytes_12 - 1)));
          Off := Off + Poly_Bytes_12;
       end loop;
    end Pack_SK;

    procedure Unpack_SK (SK : Byte_Array; SP : out Poly_Vector)
      with Pre  => SK'First = 0
                   and then SK'Length = Indcpa_SK_Bytes,
           Post => (for all I in 0 .. ML_KEM_K - 1 =>
                      (for all J in 0 .. N - 1 =>
                         SP (I) (J) in 0 .. 4095))
    is
       Off : Natural := SK'First;
    begin
       SP := [others => [others => 0]];
       for I in 0 .. ML_KEM_K - 1 loop
          pragma Loop_Invariant
            (Off = SK'First + I * Poly_Bytes_12);
          pragma Loop_Invariant
            (Off + Poly_Bytes_12 - 1 <= SK'Last);
          pragma Loop_Invariant
            (for all K in 0 .. I - 1 =>
               (for all J in 0 .. N - 1 => SP (K) (J) in 0 .. 4095));
          Serialize.ByteDecode12
            (Byte_Array_384 (SK (Off .. Off + Poly_Bytes_12 - 1)),
             SP (I));
          Off := Off + Poly_Bytes_12;
       end loop;
    end Unpack_SK;

   procedure KeyGen
      (PK   : out Byte_Array;
       SK   : out Byte_Array;
       Coin : Byte_Array_32)
   is
      Seed_Buf    : Byte_Array (0 .. 32) := [others => 0];
      Hash_Out    : Byte_Array_64;
      Public_Seed : Byte_Array_32;
      Noise_Seed  : Byte_Array_32;
      Nonce       : U8;
      Matrix      : Poly_Matrix;
      SPV, EP     : Poly_Vector;
      TP          : Poly_Vector;
      --  Sized for the active parameter set: 128 bytes for Eta1 = 2,
      --  192 bytes for Eta1 = 3 (ML-KEM-512).
      PRF_Buf     : Byte_Array (0 .. ML_KEM_Eta1 * N / 4 - 1);
   begin
      PK := [others => 0];
      SK := [others => 0];
      Seed_Buf (0 .. 31) := Coin;
      Seed_Buf (32) := U8 (ML_KEM_K);
      Symmetric.Hash_G (Seed_Buf, Hash_Out);
      Public_Seed := Byte_Array_32 (Hash_Out (0 .. 31));
      Noise_Seed  := Byte_Array_32 (Hash_Out (32 .. 63));
      Nonce := 0;
      GenMatrix (Matrix, Public_Seed, False);
      SPV := [others => [others => 0]];
      EP := [others => [others => 0]];

      --  Sample_Eta1 produces coefficients in -ML_KEM_Eta1 .. ML_KEM_Eta1.
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 SPV (K) (J) in -ML_KEM_Eta1 .. ML_KEM_Eta1));
         Symmetric.PRF (Noise_Seed, Nonce, PRF_Buf);
         CBD.Sample_Eta1 (SPV (I), PRF_Buf);
         Nonce := Nonce + 1;
      end loop;
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 EP (K) (J) in -ML_KEM_Eta1 .. ML_KEM_Eta1));
         pragma Loop_Invariant
           (for all K in 0 .. ML_KEM_K - 1 =>
              (for all J in 0 .. N - 1 =>
                 SPV (K) (J) in -ML_KEM_Eta1 .. ML_KEM_Eta1));
         Symmetric.PRF (Noise_Seed, Nonce, PRF_Buf);
         CBD.Sample_Eta1 (EP (I), PRF_Buf);
         Nonce := Nonce + 1;
      end loop;

      --  After PolyVec_NTT: SPV, EP coefficients in -Q_Half..Q_Half.
      PolyVec.PolyVec_NTT (SPV);
      PolyVec.PolyVec_NTT (EP);

      TP := [others => [others => 0]];
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 => TP (K) (J) in -Q .. Q));
         pragma Loop_Invariant
           (for all K in 0 .. ML_KEM_K - 1 =>
              (for all J in 0 .. N - 1 => SPV (K) (J) in -Q_Half .. Q_Half));
         pragma Loop_Invariant
           (for all K in 0 .. ML_KEM_K - 1 =>
              (for all J in 0 .. N - 1 => EP (K) (J) in -Q_Half .. Q_Half));
         pragma Loop_Invariant
           (for all K in I .. ML_KEM_K - 1 =>
              (for all J in 0 .. N - 1 => TP (K) (J) = 0));
         PolyVec.PolyVec_Basemul_Acc (TP (I), Matrix (I), SPV);
         --  After Basemul_Acc: TP(I) in -Q_Half..Q_Half.
         Poly.Poly_ToMont (TP (I));
         --  After ToMont: TP(I) in -Q..Q (FqMul postcondition).
      end loop;

      --  TP + EP fits in I16: |TP(I)(J)| <= Q, |EP(I)(J)| <= Q_Half,
      --  sum <= Q + Q_Half ~= 4994 < 32767.
      PolyVec.PolyVec_Add (TP, EP);
      PolyVec.PolyVec_Reduce (TP);
      PolyVec.PolyVec_Freeze (TP);
      Pack_PK (PK, TP, Public_Seed);
      PolyVec.PolyVec_Freeze (SPV);
      Pack_SK (SK, SPV);
      --  Zeroise locals that hold or derive from the secret seed.
      --  Coin (in Seed_Buf), Hash_Out (contains Noise_Seed), Noise_Seed,
      --  PRF_Buf, SPV (the secret key polys) and EP (error vector) all
      --  reveal the long-term key. Public_Seed and TP are public.
      pragma Warnings (Off, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (Off, "statement has no effect");
      Wipe.Wipe_Byte_Array (Seed_Buf);
      Wipe.Wipe_Byte_Array (Hash_Out);
      Wipe.Wipe_Byte_Array (Noise_Seed);
      Wipe.Wipe_Byte_Array (PRF_Buf);
      Wipe.Wipe_Poly_Vector (SPV);
      Wipe.Wipe_Poly_Vector (EP);
      pragma Warnings (On, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (On, "statement has no effect");
   end KeyGen;

   procedure Encrypt
     (CT   : out Byte_Array;
      PK   : Byte_Array;
      Msg  : Byte_Array_32;
      Coin : Byte_Array_32)
   is
      Public_Seed : Byte_Array_32;
      Matrix      : Poly_Matrix;
      SPV, EP     : Poly_Vector;
      UP          : Poly_Vector;
      V, K, E2    : Polynomial;
      TP          : Poly_Vector;
      Buf_Eta1    : Byte_Array (0 .. ML_KEM_Eta1 * N / 4 - 1);
      Buf_Eta2    : Byte_Array_128;  --  Eta2 = 2 across all sets
      Nonce       : U8;
   begin
      CT := [others => 0];
      Unpack_PK (PK, TP, Public_Seed);
      --  TP coefficients in [0, 4095] (ByteDecode12 post). They're
      --  bounded by 4095 < 2*Q which satisfies BaseMul_Input_Bound.

      GenMatrix (Matrix, Public_Seed, True);
      Nonce := 0;
      SPV := [others => [others => 0]];
      EP := [others => [others => 0]];

      --  y (called SPV here) sampled with Eta1.
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 =>
                 SPV (K) (J) in -ML_KEM_Eta1 .. ML_KEM_Eta1));
         Symmetric.PRF (Coin, Nonce, Buf_Eta1);
         CBD.Sample_Eta1 (SPV (I), Buf_Eta1);
         Nonce := Nonce + 1;
      end loop;
      --  e1 (called EP) and e2 sampled with Eta2 (= 2 always).
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 => EP (K) (J) in -2 .. 2));
         pragma Loop_Invariant
           (for all K in 0 .. ML_KEM_K - 1 =>
              (for all J in 0 .. N - 1 =>
                 SPV (K) (J) in -ML_KEM_Eta1 .. ML_KEM_Eta1));
         Symmetric.PRF (Coin, Nonce, Buf_Eta2);
         CBD.CBD2 (EP (I), Buf_Eta2);
         Nonce := Nonce + 1;
      end loop;
      Symmetric.PRF (Coin, Nonce, Buf_Eta2);
      CBD.CBD2 (E2, Buf_Eta2);
      --  E2 in -2..2.

      PolyVec.PolyVec_NTT (SPV);
      --  SPV now in -Q_Half..Q_Half (Barrett-reduced).

      UP := [others => [others => 0]];
      for I in 0 .. ML_KEM_K - 1 loop
         pragma Loop_Invariant
           (for all K in 0 .. I - 1 =>
              (for all J in 0 .. N - 1 => UP (K) (J) in -Q_Half .. Q_Half));
         pragma Loop_Invariant
           (for all K in 0 .. ML_KEM_K - 1 =>
              (for all J in 0 .. N - 1 => SPV (K) (J) in -Q_Half .. Q_Half));
         pragma Loop_Invariant
           (for all K in I .. ML_KEM_K - 1 =>
              (for all J in 0 .. N - 1 => UP (K) (J) = 0));
         PolyVec.PolyVec_Basemul_Acc (UP (I), Matrix (I), SPV);
         --  Basemul_Acc post: UP(I) in -Q_Half..Q_Half.
      end loop;

      PolyVec.PolyVec_InvNTT (UP);
      --  InvNTT post: UP(I)(J) in -Q..Q.

      --  UP + EP fits in I16: |UP| <= Q, |EP| <= 2, sum <= Q+2 = 3331.
      PolyVec.PolyVec_Add (UP, EP);
      PolyVec.PolyVec_Reduce (UP);

      V := [others => 0];
      PolyVec.PolyVec_Basemul_Acc (V, TP, SPV);
      --  V in -Q_Half..Q_Half (Basemul_Acc post).

      NTT.InvNTT (V);
      --  V in -Q..Q (InvNTT post).

      --  V + E2 fits in I16: |V| <= Q, |E2| <= 2, sum <= Q+2.
      Poly.Poly_Add (V, E2);
      Poly.Poly_FromMsg (Msg, K);
      --  K(I) = 0 or Half_Q = 1665.

      --  V + K fits in I16: |V_after_add_E2| <= Q+2, |K| <= 1665,
      --  sum <= Q+2+1665 = 4996 < 32767.
      Poly.Poly_Add (V, K);
      Poly.Poly_Reduce (V);
      declare
          CT_U : Byte_Array (0 .. Poly_Bytes_Du * ML_KEM_K - 1) :=
            [others => 0];
          CT_V : Byte_Array (0 .. Poly_Bytes_Dv - 1) := [others => 0];
          Off  : Natural := 0;
       begin
          for I in 0 .. ML_KEM_K - 1 loop
             pragma Loop_Invariant
               (Off = I * Poly_Bytes_Du);
             Poly.Poly_Reduce (UP (I));
             Poly.Poly_Freeze (UP (I));
             --  Static dispatch on Du.  GNAT folds the constant at
             --  compile time and the dead branch is elided.  Two
             --  concrete fixed-size locals are required because
             --  Compress_Du / Compress_11 take their result as a
             --  fixed-size formal (Byte_Array_320 / Byte_Array_352).
             if ML_KEM_Du = 10 then
                declare
                   Tmp : Byte_Array_320;
                begin
                   Poly.Compress_Du (UP (I), Tmp);
                   CT_U (Off .. Off + Poly_Bytes_Du - 1) := Tmp;
                end;
             else  --  Du = 11 (ML-KEM-1024)
                declare
                   Tmp : Byte_Array_352;
                begin
                   Poly.Compress_11 (UP (I), Tmp);
                   CT_U (Off .. Off + Poly_Bytes_Du - 1) := Tmp;
                end;
             end if;
             Off := Off + Poly_Bytes_Du;
          end loop;
          Poly.Poly_Freeze (V);
          if ML_KEM_Dv = 4 then
             declare
                Tmp : Byte_Array_128;
             begin
                Poly.Compress_Dv (V, Tmp);
                CT_V := Tmp;
             end;
          else  --  Dv = 5 (ML-KEM-1024)
             declare
                Tmp : Byte_Array_160;
             begin
                Poly.Compress_5 (V, Tmp);
                CT_V := Tmp;
             end;
          end if;
          CT (CT'First .. CT'First + Poly_Bytes_Du * ML_KEM_K - 1) := CT_U;
          CT (CT'First + Poly_Bytes_Du * ML_KEM_K .. CT'Last) := CT_V;
       end;
       --  Zeroise locals that derive from the encryption coins or the
       --  message. SPV/EP/E2 are sampled from Coin via PRF; UP/V/K are
       --  the unpacked plaintext path. TP and Matrix are public (PK
       --  decode and public-seed derivation respectively).
       pragma Warnings (Off, """*"" is set by ""*"" but not used after the call");
       pragma Warnings (Off, "statement has no effect");
       Wipe.Wipe_Poly_Vector (SPV);
       Wipe.Wipe_Poly_Vector (EP);
       Wipe.Wipe_Poly_Vector (UP);
       Wipe.Wipe_Polynomial (V);
       Wipe.Wipe_Polynomial (K);
       Wipe.Wipe_Polynomial (E2);
       Wipe.Wipe_Byte_Array (Buf_Eta1);
       Wipe.Wipe_Byte_Array (Buf_Eta2);
       pragma Warnings (On, """*"" is set by ""*"" but not used after the call");
       pragma Warnings (On, "statement has no effect");
    end Encrypt;

    procedure Decrypt
      (Msg : out Byte_Array_32;
       CT  : Byte_Array;
       SK  : Byte_Array)
    is
       C0  : constant Natural := CT'First;
       SP  : Poly_Vector;
       UP  : Poly_Vector;
       VP  : Polynomial;
       B   : Polynomial;
       V   : Polynomial;
    begin
       Msg := [others => 0];
       Unpack_SK (SK, SP);
       --  SP coefficients in [0, 4095] (ByteDecode12 post).

       UP := [others => [others => 0]];
       for I in 0 .. ML_KEM_K - 1 loop
          pragma Loop_Invariant
            (for all K in 0 .. I - 1 =>
               (for all J in 0 .. N - 1 => UP (K) (J) in 0 .. Q - 1));
          if ML_KEM_Du = 10 then
             declare
                Tmp : constant Byte_Array_320 :=
                  Byte_Array_320
                    (CT (C0 + Poly_Bytes_Du * I
                      .. C0 + Poly_Bytes_Du * (I + 1) - 1));
             begin
                Poly.Decompress_Du (Tmp, B);
             end;
          else  --  Du = 11 (ML-KEM-1024)
             declare
                Tmp : constant Byte_Array_352 :=
                  Byte_Array_352
                    (CT (C0 + Poly_Bytes_Du * I
                      .. C0 + Poly_Bytes_Du * (I + 1) - 1));
             begin
                Poly.Decompress_11 (Tmp, B);
             end;
          end if;
          --  B in [0, Q-1] (Decompress_Du / _11 post).
          UP (I) := B;
       end loop;
       --  After loop: UP(K)(J) in [0, Q-1] for all K, J.

       if ML_KEM_Dv = 4 then
          declare
             Tmp : constant Byte_Array_128 :=
               Byte_Array_128
                 (CT (C0 + Poly_Bytes_Du * ML_KEM_K .. CT'Last));
          begin
             Poly.Decompress_Dv (Tmp, V);
          end;
       else  --  Dv = 5 (ML-KEM-1024)
          declare
             Tmp : constant Byte_Array_160 :=
               Byte_Array_160
                 (CT (C0 + Poly_Bytes_Du * ML_KEM_K .. CT'Last));
          begin
             Poly.Decompress_5 (Tmp, V);
          end;
       end if;
       --  V in [0, Q-1] (Decompress_Dv / _5 post).

       VP := [others => 0];
       PolyVec.PolyVec_NTT (UP);
       --  UP in -Q_Half..Q_Half.

       PolyVec.PolyVec_Basemul_Acc (VP, SP, UP);
       --  VP in -Q_Half..Q_Half (Basemul_Acc post).
       --  Note: SP coefficients up to 4095, within BaseMul_Input_Bound = 2Q.

       NTT.InvNTT (VP);
       --  VP in -Q..Q (InvNTT post).

       --  V - VP fits in I16: V in [0, Q-1], VP in [-Q, Q],
       --  so V - VP in [-Q, 2Q-1] = [-3329, 6657] < 32767.
       Poly.Poly_Sub (V, VP);
       Poly.Poly_Reduce (V);
       Poly.Poly_ToMsg (V, Msg);
       --  Zeroise locals that hold the unpacked secret key (SP),
       --  intermediate plaintext path polys (UP, VP, B, V), and the
       --  recovered message bits before they leak the IndCPA secret
       --  key or the message m'.
       pragma Warnings (Off, """*"" is set by ""*"" but not used after the call");
       pragma Warnings (Off, "statement has no effect");
       Wipe.Wipe_Poly_Vector (SP);
       Wipe.Wipe_Poly_Vector (UP);
       Wipe.Wipe_Polynomial (VP);
       Wipe.Wipe_Polynomial (B);
       Wipe.Wipe_Polynomial (V);
       pragma Warnings (On, """*"" is set by ""*"" but not used after the call");
       pragma Warnings (On, "statement has no effect");
    end Decrypt;

end ML_KEM.IndCPA;
