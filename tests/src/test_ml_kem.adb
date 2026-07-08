with Ada.Text_IO;
with Ada.Command_Line;
with SHA3;
with ML_KEM;
with ML_KEM.Reduce;
with ML_KEM.CBD;
with ML_KEM.Serialize;
with ML_KEM.Poly;
with ML_KEM.NTT;
with ML_KEM.PolyVec;
with ML_KEM.IndCPA;
with ML_KEM.Symmetric;
with ML_KEM.KEM;

procedure Test_ML_KEM is

   use Ada.Text_IO;
   use type ML_KEM.I16;
   use type ML_KEM.I32;
   use type ML_KEM.U8;
   use type ML_KEM.Polynomial;
   use type ML_KEM.Byte_Array;

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   procedure Check (Name : String; Condition : Boolean) is
   begin
      if Condition then
         Pass_Count := Pass_Count + 1;
      else
         Put_Line ("FAIL: " & Name);
         Fail_Count := Fail_Count + 1;
      end if;
   end Check;

   Zero_Poly : constant ML_KEM.Polynomial := [others => 0];

begin
   Put_Line ("=== ML-KEM Phase 1 + 2 Tests ===");
   New_Line;

   declare
      V : ML_KEM.I16;
   begin
      V := ML_KEM.Reduce.Barrett_Reduce (0);
      Check ("Barrett_Reduce(0) = 0", V = 0);

      V := ML_KEM.Reduce.Barrett_Reduce (ML_KEM.Q);
      Check ("Barrett_Reduce(Q) = 0", V = 0);

      V := ML_KEM.Reduce.Barrett_Reduce (ML_KEM.I16 (1));
      Check ("Barrett_Reduce(1) = 1", V = 1);

      V := ML_KEM.Reduce.Barrett_Reduce (-1);
      Check ("Barrett_Reduce(-1) = -1", V = -1);

      V := ML_KEM.Reduce.Barrett_Reduce (ML_KEM.I16 (ML_KEM.Q - 1));
      Check ("Barrett_Reduce(Q-1) = -1", V = -1);

      V := ML_KEM.Reduce.Barrett_Reduce (ML_KEM.I16 (ML_KEM.Q + 1));
      Check ("Barrett_Reduce(Q+1) = 1", V = 1);
   end;

   declare
      V : ML_KEM.I16;
   begin
      V := ML_KEM.Reduce.Montgomery_Reduce (0);
      Check ("Montgomery_Reduce(0) = 0", V = 0);

      V := ML_KEM.Reduce.Montgomery_Reduce
             (ML_KEM.I32 (ML_KEM.Mont) * ML_KEM.I32 (1));
      Check ("Montgomery_Reduce(Mont*1) = 1", V = 1);
   end;

   declare
      Buf : constant ML_KEM.Byte_Array_128 := [others => 0];
      R   : ML_KEM.Polynomial;
   begin
      ML_KEM.CBD.CBD2 (R, Buf);
      Check ("CBD2(zeros) = zero poly", R = Zero_Poly);
   end;

   declare
      Buf : constant ML_KEM.Byte_Array_192 := [others => 0];
      R   : ML_KEM.Polynomial;
   begin
      ML_KEM.CBD.CBD3 (R, Buf);
      Check ("CBD3(zeros) = zero poly", R = Zero_Poly);
   end;

   declare
      A : constant ML_KEM.Polynomial := [others => ML_KEM.I16 (100)];
      B : ML_KEM.Byte_Array_384;
      R : ML_KEM.Polynomial;
   begin
      ML_KEM.Serialize.ByteEncode12 (A, B);
      ML_KEM.Serialize.ByteDecode12 (B, R);
      Check ("ByteEncode12/Decode12 roundtrip",
             (for all I in 0 .. ML_KEM.N - 1 => R (I) = 100));
   end;

   declare
      A : constant ML_KEM.Polynomial := [others => 1];
      B : ML_KEM.Byte_Array_32;
      R : ML_KEM.Polynomial;
   begin
      ML_KEM.Serialize.ByteEncode1 (A, B);
      Check ("ByteEncode1 all-ones",
             B = ML_KEM.Byte_Array_32'(others => 16#FF#));
      ML_KEM.Serialize.ByteDecode1 (B, R);
      Check ("ByteDecode1 roundtrip",
             (for all I in 0 .. ML_KEM.N - 1 => R (I) = 1));
   end;

   declare
      A : constant ML_KEM.Polynomial :=
            [0 => 5, 1 => 10, others => 0];
      B : ML_KEM.Byte_Array_128;
      R : ML_KEM.Polynomial;
   begin
      ML_KEM.Serialize.ByteEncode4 (A, B);
      ML_KEM.Serialize.ByteDecode4 (B, R);
      Check ("ByteEncode4/Decode4 roundtrip idx0", R (0) = 5);
      Check ("ByteEncode4/Decode4 roundtrip idx1", R (1) = 10);
   end;

   declare
      A : constant ML_KEM.Polynomial :=
            [0 => 100, 1 => 500, 2 => 999, others => 0];
      B : ML_KEM.Byte_Array_320;
      R : ML_KEM.Polynomial;
   begin
      ML_KEM.Serialize.ByteEncode10 (A, B);
      ML_KEM.Serialize.ByteDecode10 (B, R);
      Check ("ByteEncode10/Decode10 roundtrip idx0", R (0) = 100);
      Check ("ByteEncode10/Decode10 roundtrip idx1", R (1) = 500);
      Check ("ByteEncode10/Decode10 roundtrip idx2", R (2) = 999);
   end;

   declare
      A : ML_KEM.Polynomial := [others => ML_KEM.I16 (ML_KEM.Q)];
   begin
      ML_KEM.Poly.Poly_Reduce (A);
      Check ("Poly_Reduce(Q) -> 0",
             (for all I in 0 .. ML_KEM.N - 1 => A (I) = 0));
   end;

   declare
      A : ML_KEM.Polynomial := [others => ML_KEM.I16 (100)];
      B : ML_KEM.Polynomial := [others => ML_KEM.I16 (200)];
   begin
      ML_KEM.Poly.Poly_Add (A, B);
      Check ("Poly_Add",
             (for all I in 0 .. ML_KEM.N - 1 => A (I) = 300));
   end;

   declare
      A : ML_KEM.Polynomial := [others => ML_KEM.I16 (500)];
      B : ML_KEM.Polynomial := [others => ML_KEM.I16 (200)];
   begin
      ML_KEM.Poly.Poly_Sub (A, B);
      Check ("Poly_Sub",
             (for all I in 0 .. ML_KEM.N - 1 => A (I) = 300));
   end;

   declare
      A : ML_KEM.Polynomial := [others => ML_KEM.I16 (ML_KEM.Q)];
   begin
      ML_KEM.Poly.Poly_ToMont (A);
      Check ("Poly_ToMount",
             (for all I in 0 .. ML_KEM.N - 1 =>
                A (I) in -ML_KEM.Q .. ML_KEM.Q));
   end;

   declare
      A : ML_KEM.Polynomial := [others => ML_KEM.I16 (1)];
      Orig : constant ML_KEM.Polynomial := A;
   begin
      ML_KEM.NTT.NTT (A);
      Check ("NTT(non-zero) changes poly", A /= Orig);
      ML_KEM.NTT.InvNTT (A);
      ML_KEM.Poly.Poly_Reduce (A);
      Check ("NTT roundtrip * R: constant poly",
             (for all I in 0 .. ML_KEM.N - 1 =>
                 ML_KEM.Reduce.FqMul (A (I), 1) = 1));
   end;

   declare
      A : ML_KEM.Polynomial := [0 => 100, 1 => -50, others => 0];
   begin
      ML_KEM.NTT.NTT (A);
      ML_KEM.NTT.InvNTT (A);
      ML_KEM.Poly.Poly_Reduce (A);
      Check ("NTT roundtrip * R: idx0",
             ML_KEM.Reduce.FqMul (A (0), 1) = 100);
      Check ("NTT roundtrip * R: idx1",
             ML_KEM.Reduce.FqMul (A (1), 1) = -50);
      Check ("NTT roundtrip * R: idx2",
             ML_KEM.Reduce.FqMul (A (2), 1) = 0);
   end;

   declare
      A : ML_KEM.Polynomial := [others => 0];
      B : ML_KEM.Polynomial := [others => 0];
      R : ML_KEM.Polynomial;
   begin
      ML_KEM.NTT.BaseMul (R, A, B);
      Check ("BaseMul(zero, zero) = zero",
             (for all I in 0 .. ML_KEM.N - 1 => R (I) = 0));
   end;

   declare
      A : ML_KEM.Poly_Vector := (others => [others => 0]);
      B : ML_KEM.Poly_Vector := (others => [others => 0]);
      R : ML_KEM.Polynomial;
   begin
      R := [others => 0];
      ML_KEM.PolyVec.PolyVec_Basemul_Acc (R, A, B);
      Check ("PolyVec_Basemul_Acc(zero) = zero",
             (for all I in 0 .. ML_KEM.N - 1 => R (I) = 0));
   end;

   declare
      A : ML_KEM.Polynomial := [others => 0];
      A_Copy : constant ML_KEM.Polynomial := A;
   begin
      ML_KEM.Poly.Poly_ToggleNeg (A);
      Check ("Poly_ToggleNeg",
             (for all I in 0 .. ML_KEM.N - 1 => A (I) = -A_Copy (I)));
   end;

   New_Line;
   Put_Line ("=== Phase 3: IndCPA Tests ===");
   New_Line;

   declare
      Msg_In : constant ML_KEM.Byte_Array_32 :=
        [0 => 16#FF#, 1 => 16#AB#, others => 0];
      P : ML_KEM.Polynomial;
      Msg_Out : ML_KEM.Byte_Array_32;
   begin
      ML_KEM.Poly.Poly_FromMsg (Msg_In, P);
      Check ("FromMsg: coeff 0 = 1665", P (0) = 1665);
      Check ("FromMsg: coeff 10 = 0", P (10) = 0);
      Check ("FromMsg: coeff 9 = 1665",
             P (9) = 1665);
      ML_KEM.Poly.Poly_ToMsg (P, Msg_Out);
      Check ("ToMsg roundtrip",
             (for all I in 0 .. 31 => Msg_In (I) = Msg_Out (I)));
   end;

   declare
      A : ML_KEM.Polynomial := [others => 1665];
      R : ML_KEM.Byte_Array_128;
      B : ML_KEM.Polynomial;
   begin
      ML_KEM.Poly.Compress_Dv (A, R);
      ML_KEM.Poly.Decompress_Dv (R, B);
      Check ("Compress_Dv roundtrip 1665",
             (for all I in 0 .. ML_KEM.N - 1 => B (I) > 1664));
   end;

   declare
      Coin : constant ML_KEM.Byte_Array_32 := [others => 42];
      PK   : ML_KEM.Byte_Array (0 .. ML_KEM.Indcpa_PK_Bytes - 1);
      SK   : ML_KEM.Byte_Array (0 .. ML_KEM.Indcpa_SK_Bytes - 1);
   begin
      ML_KEM.IndCPA.KeyGen (PK, SK, Coin);
      Check ("KeyGen: PK non-trivial",
            (for some I in PK'Range => PK (I) /= 0));
      Check ("KeyGen: SK non-trivial",
            (for some I in SK'Range => SK (I) /= 0));
      declare
         Msg : constant ML_KEM.Byte_Array_32 := [0 => 16#FF#, others => 0];
         Rand : constant ML_KEM.Byte_Array_32 := [others => 7];
         CT  : ML_KEM.Byte_Array (0 .. ML_KEM.CT_Bytes - 1);
      begin
         ML_KEM.IndCPA.Encrypt (CT, PK, Msg, Rand);
         Check ("Encrypt: CT non-trivial",
                (for some I in CT'Range => CT (I) /= 0));
         declare
            Msg2 : ML_KEM.Byte_Array_32;
         begin
            ML_KEM.IndCPA.Decrypt (Msg2, CT, SK);
            Check ("Decrypt roundtrip (coin=42)",
                   (for all I in Msg'Range => Msg (I) = Msg2 (I)));
         end;
      end;
   end;

   declare
      Coin : constant ML_KEM.Byte_Array_32 :=
        [0 => 1, 1 => 2, others => 99];
      PK   : ML_KEM.Byte_Array (0 .. ML_KEM.Indcpa_PK_Bytes - 1);
      SK   : ML_KEM.Byte_Array (0 .. ML_KEM.Indcpa_SK_Bytes - 1);
   begin
      ML_KEM.IndCPA.KeyGen (PK, SK, Coin);
      declare
         Msg : constant ML_KEM.Byte_Array_32 :=
           [0 => 16#FF#, others => 0];
         Rand : constant ML_KEM.Byte_Array_32 := [others => 16#55#];
         CT  : ML_KEM.Byte_Array (0 .. ML_KEM.CT_Bytes - 1);
      begin
         ML_KEM.IndCPA.Encrypt (CT, PK, Msg, Rand);
         declare
            Msg2 : ML_KEM.Byte_Array_32;
         begin
            ML_KEM.IndCPA.Decrypt (Msg2, CT, SK);
            Check ("Decrypt roundtrip (0xFF msg)",
                   (for all I in Msg'Range => Msg (I) = Msg2 (I)));
         end;
      end;
      declare
         Msg : constant ML_KEM.Byte_Array_32 :=
           [0 => 16#AB#, 1 => 16#CD#, others => 0];
         Rand : constant ML_KEM.Byte_Array_32 := [others => 16#55#];
         CT  : ML_KEM.Byte_Array (0 .. ML_KEM.CT_Bytes - 1);
      begin
         ML_KEM.IndCPA.Encrypt (CT, PK, Msg, Rand);
         declare
            Msg2 : ML_KEM.Byte_Array_32;
         begin
            ML_KEM.IndCPA.Decrypt (Msg2, CT, SK);
            Check ("Decrypt roundtrip (0xAB_CD msg)",
                   (for all I in Msg'Range => Msg (I) = Msg2 (I)));
         end;
      end;
   end;

   New_Line;
   Put_Line ("=== Phase 4: KEM Tests ===");
   New_Line;

   declare
      Seed : constant ML_KEM.Byte_Array_64 := [others => 42];
      PK   : ML_KEM.Byte_Array (0 .. ML_KEM.PK_Bytes - 1);
      SK   : ML_KEM.Byte_Array (0 .. ML_KEM.SK_Bytes - 1);
   begin
      ML_KEM.KEM.KeyGen (PK, SK, Seed);
      Check ("KEM KeyGen: PK non-trivial",
             (for some I in PK'Range => PK (I) /= 0));
      Check ("KEM KeyGen: SK non-trivial",
             (for some I in SK'Range => SK (I) /= 0));
      declare
         M  : constant ML_KEM.Byte_Array_32 := [others => 16#AB#];
         CT : ML_KEM.Byte_Array (0 .. ML_KEM.CT_Bytes - 1);
         SS_Enc : ML_KEM.Byte_Array_32;
         SS_Dec : ML_KEM.Byte_Array_32;
      begin
         ML_KEM.KEM.Encapsulate (CT, SS_Enc, PK, M);
         Check ("Encapsulate: CT non-trivial",
                (for some I in CT'Range => CT (I) /= 0));
         ML_KEM.KEM.Decapsulate (SS_Dec, CT, SK);
         Check ("KEM roundtrip (seed=42)",
                (for all I in 0 .. 31 => SS_Enc (I) = SS_Dec (I)));
      end;
   end;

   declare
      Seed : constant ML_KEM.Byte_Array_64 :=
        [0 => 1, 1 => 2, others => 99];
      PK   : ML_KEM.Byte_Array (0 .. ML_KEM.PK_Bytes - 1);
      SK   : ML_KEM.Byte_Array (0 .. ML_KEM.SK_Bytes - 1);
   begin
      ML_KEM.KEM.KeyGen (PK, SK, Seed);
      declare
         M  : constant ML_KEM.Byte_Array_32 := [0 => 16#FF#, others => 0];
         CT : ML_KEM.Byte_Array (0 .. ML_KEM.CT_Bytes - 1);
         SS_Enc : ML_KEM.Byte_Array_32;
         SS_Dec : ML_KEM.Byte_Array_32;
      begin
         ML_KEM.KEM.Encapsulate (CT, SS_Enc, PK, M);
         ML_KEM.KEM.Decapsulate (SS_Dec, CT, SK);
         Check ("KEM roundtrip (seed=[1,2,99...])",
                (for all I in 0 .. 31 => SS_Enc (I) = SS_Dec (I)));
      end;
      declare
         M  : constant ML_KEM.Byte_Array_32 :=
           [0 => 16#AB#, 1 => 16#CD#, others => 0];
         CT : ML_KEM.Byte_Array (0 .. ML_KEM.CT_Bytes - 1);
         SS_Enc : ML_KEM.Byte_Array_32;
         SS_Dec : ML_KEM.Byte_Array_32;
      begin
         ML_KEM.KEM.Encapsulate (CT, SS_Enc, PK, M);
         ML_KEM.KEM.Decapsulate (SS_Dec, CT, SK);
         Check ("KEM roundtrip (msg=0xAB_CD)",
                (for all I in 0 .. 31 => SS_Enc (I) = SS_Dec (I)));
      end;
   end;

   --  FIPS 203 §7.2 input-validation tests for Valid_Encaps_Key.
   declare
      Seed : ML_KEM.Byte_Array_64 := [others => 16#5A#];
      PK   : ML_KEM.Byte_Array (0 .. ML_KEM.PK_Bytes - 1);
      SK   : ML_KEM.Byte_Array (0 .. ML_KEM.SK_Bytes - 1);
   begin
      ML_KEM.KEM.KeyGen (PK, SK, Seed);
      Check ("Valid_Encaps_Key: freshly generated PK is valid",
             ML_KEM.KEM.Valid_Encaps_Key (PK));

      --  Wrong length must be rejected.
      declare
         Short_PK : ML_KEM.Byte_Array (0 .. ML_KEM.PK_Bytes - 2) :=
           [others => 0];
      begin
         Check ("Valid_Encaps_Key: short PK rejected",
                not ML_KEM.KEM.Valid_Encaps_Key (Short_PK));
      end;

      --  Force a coefficient out of range. Bytes 0..2 encode the first
      --  two coefficients of t(0) as: c0 = b0 | (b1 & 0x0F) << 8 and
      --  c1 = (b1 >> 4) | (b2 << 4). Setting b0=0xFF, b1=0xFF makes
      --  c0 = 0x0FFF = 4095 > Q-1 = 3328.
      declare
         Bad_PK : ML_KEM.Byte_Array (0 .. ML_KEM.PK_Bytes - 1) := PK;
      begin
         Bad_PK (0) := 16#FF#;
         Bad_PK (1) := 16#FF#;
         Check ("Valid_Encaps_Key: out-of-range coeff rejected",
                not ML_KEM.KEM.Valid_Encaps_Key (Bad_PK));
      end;

      --  Encapsulate_Checked: happy path round-trips and reports Ok.
      declare
         M      : constant ML_KEM.Byte_Array_32 :=
           [0 => 16#11#, 1 => 16#22#, others => 0];
         CT     : ML_KEM.Byte_Array (0 .. ML_KEM.CT_Bytes - 1);
         SS_Enc : ML_KEM.Byte_Array_32;
         SS_Dec : ML_KEM.Byte_Array_32;
         Ok     : Boolean;
      begin
         ML_KEM.KEM.Encapsulate_Checked (CT, SS_Enc, Ok, PK, M);
         Check ("Encapsulate_Checked: Ok on valid PK", Ok);
         ML_KEM.KEM.Decapsulate (SS_Dec, CT, SK);
         Check ("Encapsulate_Checked: roundtrip matches",
                (for all I in 0 .. 31 => SS_Enc (I) = SS_Dec (I)));
      end;

      --  Encapsulate_Checked: malformed PK is rejected; CT and SS
      --  zeroed; Ok is False.
      declare
         M      : constant ML_KEM.Byte_Array_32 := [others => 16#33#];
         Bad_PK : ML_KEM.Byte_Array (0 .. ML_KEM.PK_Bytes - 1) := PK;
         CT     : ML_KEM.Byte_Array (0 .. ML_KEM.CT_Bytes - 1) :=
           [others => 16#FF#];
         SS_Enc : ML_KEM.Byte_Array_32 := [others => 16#FF#];
         Ok     : Boolean := True;
      begin
         Bad_PK (0) := 16#FF#;
         Bad_PK (1) := 16#FF#;
         ML_KEM.KEM.Encapsulate_Checked (CT, SS_Enc, Ok, Bad_PK, M);
         Check ("Encapsulate_Checked: not Ok on bad PK", not Ok);
         Check ("Encapsulate_Checked: CT zeroed on bad PK",
                (for all I in CT'Range => CT (I) = 0));
         Check ("Encapsulate_Checked: SS zeroed on bad PK",
                (for all I in SS_Enc'Range => SS_Enc (I) = 0));
      end;
   end;

   New_Line;
   Put_Line ("Passed:" & Natural'Image (Pass_Count)
             & "  Failed:" & Natural'Image (Fail_Count));

   if Fail_Count > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_ML_KEM;
