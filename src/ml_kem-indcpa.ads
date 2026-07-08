with Interfaces;

package ML_KEM.IndCPA is

   pragma Pure;
   pragma SPARK_Mode;

   use type Interfaces.Unsigned_8;

    procedure KeyGen
      (PK     : out Byte_Array;
       SK     : out Byte_Array;
       Coin   : Byte_Array_32)
      with
        Pre  => PK'First = 0
                and then SK'First = 0
                and then PK'Length = ML_KEM.Indcpa_PK_Bytes
                and then SK'Length = ML_KEM.Indcpa_SK_Bytes;

    procedure Encrypt
      (CT     : out Byte_Array;
       PK     : Byte_Array;
       Msg    : Byte_Array_32;
       Coin   : Byte_Array_32)
      with
        Pre  => PK'First = 0
                and then CT'First = 0
                and then PK'Length = ML_KEM.Indcpa_PK_Bytes
                and then CT'Length = ML_KEM.CT_Bytes;

    procedure Decrypt
      (Msg    : out Byte_Array_32;
       CT     : Byte_Array;
       SK     : Byte_Array)
      with
        Pre  => SK'First = 0
                and then CT'First = 0
                and then SK'Length = ML_KEM.Indcpa_SK_Bytes
                and then CT'Length = ML_KEM.CT_Bytes;

end ML_KEM.IndCPA;
