--  Memory wiping for sensitive intermediate data.
--
--  At the end of each top-level operation (KeyGen / Encapsulate /
--  Decapsulate), any local variable that contained a portion of the
--  secret seed, the recovered shared secret, or an intermediate
--  polynomial derived from secret material should be overwritten
--  with zero before going out of scope. The Wipe procedures below
--  do that.
--
--  The bodies are in a separate compilation unit and the spec
--  carries `Inline => False` so that the compiler cannot see the
--  body at the call site and prove the writes dead. With -O2 and
--  no whole-program LTO this gives a robust zeroisation guarantee;
--  if your build uses LTO, add `-fno-builtin-memset` or call
--  `explicit_bzero(3)` instead.

package ML_KEM.Wipe is

   pragma Pure;
   pragma SPARK_Mode;

   procedure Wipe_Byte_Array (X : in out Byte_Array)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in X'Range => X (I) = 0);

   procedure Wipe_Polynomial (X : in out Polynomial)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in X'Range => X (I) = 0);

   procedure Wipe_Poly_Vector (X : in out Poly_Vector)
     with Inline => False,
          Always_Terminates => True,
          Post => (for all I in X'Range =>
                     (for all J in X (I)'Range => X (I) (J) = 0));

end ML_KEM.Wipe;
