with Interfaces;

package ML_KEM.KEM is

   pragma Pure;
   pragma SPARK_Mode;

   use type Interfaces.Unsigned_8;

   procedure KeyGen
     (PK   : out Byte_Array;
      SK   : out Byte_Array;
      Seed : Byte_Array_64)
     with
       Pre  => PK'First = 0 and then SK'First = 0
               and then PK'Length = PK_Bytes
               and then SK'Length = SK_Bytes;
   --  (The former postcondition "every PK byte <= 255" was vacuous
   --  for a byte type and has been removed; KeyGen's guarantees are
   --  memory/arithmetic safety and full initialization of PK and SK,
   --  both proved.  Functional conformance is validated against
   --  test vectors.)

   --  FIPS 203 §7.2 input check for the encapsulation key.
   --  Returns True iff PK has the correct length and every decoded
   --  polynomial coefficient is < Q. Runs in constant time over the
   --  whole PK byte string regardless of where the first invalid
   --  coefficient (if any) is located, so the rejection decision
   --  does not leak position information about a malformed PK to a
   --  timing observer.
   function Valid_Encaps_Key (PK : Byte_Array) return Boolean
     with Pre => PK'First = 0;

   procedure Encapsulate
     (CT : out Byte_Array;
      SS : out Byte_Array_32;
      PK : Byte_Array;
      M  : Byte_Array_32)
     with
       Pre  => PK'First = 0 and then CT'First = 0
               and then PK'Length = PK_Bytes
               and then CT'Length = CT_Bytes;

   --  FIPS 203 §7.2-conforming Encapsulate: validates the public-key
   --  modulus before encrypting. On a malformed PK (wrong length or
   --  any decoded coefficient ≥ Q), the procedure sets `Ok` to False
   --  and zeroes CT and SS without invoking the IndCPA path. The
   --  validity check itself runs in constant time (see
   --  `Valid_Encaps_Key`); the only timing observable to an attacker
   --  is whether the IndCPA encrypt path executed at all, which the
   --  attacker can already learn from the validity outcome they sent.
   --
   --  Callers receiving PK from untrusted sources should prefer this
   --  over the unchecked `Encapsulate` above. The unchecked variant
   --  is retained for back-compatibility with v0.1.x deployments.
   procedure Encapsulate_Checked
     (CT : out Byte_Array;
      SS : out Byte_Array_32;
      Ok : out Boolean;
      PK : Byte_Array;
      M  : Byte_Array_32)
     with
       Pre  => PK'First = 0 and then CT'First = 0
               and then PK'Length = PK_Bytes
               and then CT'Length = CT_Bytes;

   procedure Decapsulate
     (SS : out Byte_Array_32;
      CT : Byte_Array;
      SK : Byte_Array)
     with
       Pre  => SK'First = 0 and then CT'First = 0
               and then SK'Length = SK_Bytes
               and then CT'Length = CT_Bytes;

end ML_KEM.KEM;
