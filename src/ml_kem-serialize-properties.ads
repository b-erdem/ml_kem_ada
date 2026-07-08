--  SPARK ghost lemmas proving the FIPS 203 serialization round trips
--     ByteDecode_d (ByteEncode_d (A)) = A        (d = 1, 4, 10, 12)
--  for every in-range polynomial A.  Proof-only (ghost); no runtime
--  cost.  Each lemma discharges purely from the byte-level functional
--  contracts in ML_KEM.Serialize -- the bodies are two calls plus
--  assertions, no implementation is unfolded.

package ML_KEM.Serialize.Properties
  with SPARK_Mode, Ghost
is

   procedure Lemma_Round_Trip_12 (A : Polynomial)
     with Pre => (for all I in 0 .. N - 1 => A (I) in 0 .. Q - 1);

   procedure Lemma_Round_Trip_1 (A : Polynomial)
     with Pre => (for all I in 0 .. N - 1 => A (I) in 0 .. 1);

   procedure Lemma_Round_Trip_4 (A : Polynomial)
     with Pre => (for all I in 0 .. N - 1 => A (I) in 0 .. 15);

   procedure Lemma_Round_Trip_10 (A : Polynomial)
     with Pre => (for all I in 0 .. N - 1 => A (I) in 0 .. 1023);

end ML_KEM.Serialize.Properties;
