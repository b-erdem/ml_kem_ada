with ML_KEM.IndCPA;
with ML_KEM.Symmetric;
with ML_KEM.Verify;
with ML_KEM.Wipe;

package body ML_KEM.KEM is
   pragma SPARK_Mode (On);

   --  Returns U16 value 1 if X >= Q else 0, in constant time.
   --  Trick: the modular subtraction (Q - 1 - X) wraps when X >= Q,
   --  setting bit 15. Right-shifting by 15 isolates that bit. Q-1
   --  fits in 12 bits, X in [0, 4095], so no overflow concerns
   --  beyond the intended modular wrap.
   function Coeff_Out_Of_Range (X : U16) return U16 is
     (Interfaces.Shift_Right (U16 (Q - 1) - X, 15))
     with Pre  => X <= 4095,
          Post => Coeff_Out_Of_Range'Result in 0 .. 1
                  and then (Coeff_Out_Of_Range'Result = 0) = (X < Q);

   function Valid_Encaps_Key (PK : Byte_Array) return Boolean is
      Bad : U16 := 0;
      C0, C1 : U16;
      B0, B1, B2 : U16;
   begin
      if PK'Length /= PK_Bytes then
         return False;
      end if;
      --  PK = (t-vector | rho). t-vector is ML_KEM_K * 384 bytes,
      --  encoding 256 12-bit coefficients per polynomial, packed as
      --  3 bytes per 2 coefficients. We decode each pair and OR a
      --  sticky failure bit. The trailing 32-byte rho is the public
      --  seed and has no modulus constraint.
      for I in 0 .. ML_KEM_K * (N / 2) - 1 loop
         pragma Loop_Invariant (Bad in 0 .. 1);
         B0 := U16 (PK (3 * I));
         B1 := U16 (PK (3 * I + 1));
         B2 := U16 (PK (3 * I + 2));
         C0 := B0 or Interfaces.Shift_Left (B1 and 16#000F#, 8);
         C1 := Interfaces.Shift_Right (B1, 4)
               or Interfaces.Shift_Left (B2, 4);
         Bad := Bad or Coeff_Out_Of_Range (C0)
                    or Coeff_Out_Of_Range (C1);
      end loop;
      return Bad = 0;
   end Valid_Encaps_Key;

   procedure Copy_Bytes
     (Dst : out Byte_Array; Src : Byte_Array)
   is
   begin
      Dst := [others => 0];
      for I in Dst'Range loop
         pragma Loop_Invariant
           (for all J in Dst'First .. I - 1 =>
               Dst (J) = Src (Src'First + (J - Dst'First)));
         Dst (I) := Src (Src'First + (I - Dst'First));
      end loop;
   end Copy_Bytes;

   procedure KeyGen
     (PK   : out Byte_Array;
      SK   : out Byte_Array;
      Seed : Byte_Array_64)
   is
      Indcpa_SK : Byte_Array (0 .. Indcpa_SK_Bytes - 1);
      H_Pk      : Byte_Array_32;
   begin
      PK := [others => 0];
      SK := [others => 0];
      IndCPA.KeyGen (PK, Indcpa_SK, Byte_Array_32 (Seed (0 .. 31)));
      Copy_Bytes (SK (SK'First .. SK'First + Indcpa_SK_Bytes - 1),
                  Indcpa_SK);
      Copy_Bytes
        (SK (SK'First + Indcpa_SK_Bytes
             .. SK'First + Indcpa_SK_Bytes + PK_Bytes - 1),
         PK);
      Symmetric.Hash_H (PK, H_Pk);
      Copy_Bytes
        (SK (SK'First + Indcpa_SK_Bytes + PK_Bytes
             .. SK'First + Indcpa_SK_Bytes + PK_Bytes + 31),
         H_Pk);
      Copy_Bytes
        (SK (SK'First + Indcpa_SK_Bytes + PK_Bytes + 32
             .. SK'First + Indcpa_SK_Bytes + PK_Bytes + 63),
         Seed (32 .. 63));
      --  Indcpa_SK is a copy of the IndCPA secret-key polynomials.
      --  Wipe before scope end. (PK and H_Pk are public.) The
      --  pragma Warnings disables the legitimate "set but not used"
      --  diagnostic for these intentional wipes — they exist
      --  precisely to overwrite secrets before stack reuse, and the
      --  Wipe procedures live in a separate compilation unit with
      --  Inline => False so the optimizer cannot prove them dead at
      --  -O2 without LTO. Builds using LTO must additionally pass
      --  `-fno-builtin-memset` or call `explicit_bzero(3)`.
      pragma Warnings (Off, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (Off, "statement has no effect");
      Wipe.Wipe_Byte_Array (Indcpa_SK);
      pragma Warnings (On, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (On, "statement has no effect");
   end KeyGen;

   procedure Encapsulate
     (CT : out Byte_Array;
      SS : out Byte_Array_32;
      PK : Byte_Array;
      M  : Byte_Array_32)
   is
      Buf : Byte_Array_64;
      KR  : Byte_Array_64;
   begin
      Buf := [others => 0];
      Buf (0 .. 31) := M;
      Symmetric.Hash_H (PK, Byte_Array_32 (Buf (32 .. 63)));
      Symmetric.Hash_G (Buf, KR);
      IndCPA.Encrypt (CT, PK, M, Byte_Array_32 (KR (32 .. 63)));
      SS := Byte_Array_32 (KR (0 .. 31));
      --  KR holds (K || coins); Buf holds (m || H(pk)). Both reveal
      --  the established shared secret, so wipe before scope end.
      pragma Warnings (Off, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (Off, "statement has no effect");
      Wipe.Wipe_Byte_Array (KR);
      Wipe.Wipe_Byte_Array (Buf);
      pragma Warnings (On, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (On, "statement has no effect");
   end Encapsulate;

   procedure Encapsulate_Checked
     (CT : out Byte_Array;
      SS : out Byte_Array_32;
      Ok : out Boolean;
      PK : Byte_Array;
      M  : Byte_Array_32)
   is
   begin
      if not Valid_Encaps_Key (PK) then
         CT := [others => 0];
         SS := [others => 0];
         Ok := False;
         return;
      end if;
      Encapsulate (CT, SS, PK, M);
      Ok := True;
   end Encapsulate_Checked;

   procedure Decapsulate
     (SS : out Byte_Array_32;
      CT : Byte_Array;
      SK : Byte_Array)
   is
      Sk_Off    : constant Natural := SK'First;
      Pk_Off    : constant Natural := Sk_Off + Indcpa_SK_Bytes;
      Hp_Off    : constant Natural := Pk_Off + PK_Bytes;
      Z_Off     : constant Natural := Hp_Off + Sym_Bytes;
      Indcpa_SK : Byte_Array (0 .. Indcpa_SK_Bytes - 1);
      Indcpa_PK : Byte_Array (0 .. PK_Bytes - 1);
      Buf       : Byte_Array_64;
      KR        : Byte_Array_64;
      CMP       : Byte_Array (0 .. CT_Bytes - 1);
      Fail      : U8;
      Tmp       : Byte_Array_32;
   begin
      Buf := [others => 0];
      Copy_Bytes (Indcpa_SK, SK (Sk_Off .. Sk_Off + Indcpa_SK_Bytes - 1));
      Copy_Bytes (Indcpa_PK, SK (Pk_Off .. Pk_Off + PK_Bytes - 1));
      IndCPA.Decrypt
        (Byte_Array_32 (Buf (0 .. 31)), CT, Indcpa_SK);
      Buf (32 .. 63) := SK (Hp_Off .. Hp_Off + 31);
      Symmetric.Hash_G (Buf, KR);
      IndCPA.Encrypt
        (CMP, Indcpa_PK,
         Byte_Array_32 (Buf (0 .. 31)),
         Byte_Array_32 (KR (32 .. 63)));
      Fail := Verify.Verify (CT, CMP);
      Symmetric.PRF (Byte_Array_32 (SK (Z_Off .. Z_Off + 31)), 0, Tmp);
      SS := Byte_Array_32 (KR (0 .. 31));
      Verify.CMOV (SS, Tmp, 1 - Fail);
      --  Indcpa_SK is a local copy of the IndCPA secret-key polynomials.
      --  Buf holds (m' || H(pk)), KR holds (K' || coins'), Tmp is the
      --  rejection-secret K_bar. All reveal the shared secret or
      --  long-term key material; wipe before scope end. Indcpa_PK and
      --  CMP are public, so no need to wipe.
      pragma Warnings (Off, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (Off, "statement has no effect");
      Wipe.Wipe_Byte_Array (Indcpa_SK);
      Wipe.Wipe_Byte_Array (Buf);
      Wipe.Wipe_Byte_Array (KR);
      Wipe.Wipe_Byte_Array (Tmp);
      pragma Warnings (On, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (On, "statement has no effect");
   end Decapsulate;

end ML_KEM.KEM;
