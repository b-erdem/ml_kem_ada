with SHA3.Wipe;

package body ML_KEM.Symmetric is
   pragma SPARK_Mode (On);

   function To_SHA3 (A : Byte_Array) return SHA3.Byte_Array
     with Post => To_SHA3'Result'First = A'First
                  and then To_SHA3'Result'Last = A'Last
   is
      R : SHA3.Byte_Array (A'Range) := [others => 0];
   begin
      for I in A'Range loop
         pragma Loop_Invariant
           (for all J in A'First .. I - 1 => R (J) = SHA3.U8 (A (J)));
         R (I) := SHA3.U8 (A (I));
      end loop;
      return R;
   end To_SHA3;

   procedure Hash_G (Data : Byte_Array; Result : out Byte_Array_64) is
      S_Result : SHA3.Byte_Array_64;
   begin
      Result := [others => 0];
      SHA3.SHA3_512 (To_SHA3 (Data), S_Result);
      for I in 0 .. 63 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => Result (J) = U8 (S_Result (J)));
         Result (I) := U8 (S_Result (I));
      end loop;
   end Hash_G;

   procedure Hash_H (Data : Byte_Array; Result : out Byte_Array_32) is
      S_Result : SHA3.Byte_Array_32;
   begin
      Result := [others => 0];
      SHA3.SHA3_256 (To_SHA3 (Data), S_Result);
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => Result (J) = U8 (S_Result (J)));
         Result (I) := U8 (S_Result (I));
      end loop;
   end Hash_H;

   procedure PRF
     (Seed   : Byte_Array_32;
      Nonce  : U8;
      Result : out Byte_Array)
   is
      Nonce_Data : SHA3.Byte_Array (0 .. 32) := [others => 0];
      S_Result   : SHA3.Byte_Array (Result'Range);
   begin
      Result := [others => 0];
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => Nonce_Data (J) = SHA3.U8 (Seed (J)));
         Nonce_Data (I) := SHA3.U8 (Seed (I));
      end loop;
      Nonce_Data (32) := SHA3.U8 (Nonce);
      SHA3.SHAKE256 (Nonce_Data, S_Result);
      for I in Result'Range loop
         pragma Loop_Invariant
           (for all J in Result'First .. I - 1 => Result (J) = U8 (S_Result (J)));
         Result (I) := U8 (S_Result (I));
      end loop;
      --  Nonce_Data contains a copy of the secret PRF key (Seed) and
      --  S_Result holds the PRF output that becomes secret CBD noise.
      --  Both must be wiped before they leak via stack reuse.
      pragma Warnings (Off, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (Off, "statement has no effect");
      SHA3.Wipe.Wipe_Byte_Array (Nonce_Data);
      SHA3.Wipe.Wipe_Byte_Array (S_Result);
      pragma Warnings (On, """*"" is set by ""*"" but not used after the call");
      pragma Warnings (On, "statement has no effect");
   end PRF;

   procedure XOF_Absorb
      (S      : out SHA3.Sponge_State;
       Seed   : Byte_Array_32;
       X, Y   : U8)
   is
      Data : SHA3.Byte_Array (0 .. 33) := [others => 0];
   begin
      for I in 0 .. 31 loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => Data (J) = SHA3.U8 (Seed (J)));
         Data (I) := SHA3.U8 (Seed (I));
      end loop;
      Data (32) := SHA3.U8 (X);
      Data (33) := SHA3.U8 (Y);
      SHA3.Init (S, SHA3.SHAKE128_Rate, SHA3.SHAKE_Domain);
      SHA3.Absorb (S, Data);
   end XOF_Absorb;

   procedure XOF_Squeeze
     (S      : in out SHA3.Sponge_State;
      Result : out Byte_Array)
   is
      S_Result : SHA3.Byte_Array (Result'Range);
   begin
      Result := [others => 0];
      SHA3.Squeeze (S, S_Result);
      for I in Result'Range loop
         pragma Loop_Invariant
           (for all J in Result'First .. I - 1 => Result (J) = U8 (S_Result (J)));
         Result (I) := U8 (S_Result (I));
      end loop;
   end XOF_Squeeze;

end ML_KEM.Symmetric;
