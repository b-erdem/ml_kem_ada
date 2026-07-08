# Parameter set roadmap for `ml_kem_ada`

FIPS 203 specifies three ML-KEM parameter sets:

| Set         | NIST cat. | K | η₁ | η₂ | du | dv | PK bytes | SK bytes | CT bytes |
|-------------|:---------:|:-:|:--:|:--:|:--:|:--:|---------:|---------:|---------:|
| ML-KEM-512  |    I      | 2 | 3  | 2  | 10 | 4  |    800   |  1632    |   768    |
| ML-KEM-768  |   III     | 3 | 2  | 2  | 10 | 4  |   1184   |  2400    |  1088    |
| ML-KEM-1024 |    V      | 4 | 2  | 2  | 11 | 5  |   1568   |  3168    |  1568    |

## Current support (v0.3.0-pre)

| Set         | Build  | Round-trip | FIPS-byte-size |
|-------------|:------:|:----------:|:--------------:|
| ML-KEM-512  |  ✅    |  ✅ 55/55  |       ✅        |
| ML-KEM-768  |  ✅    |  ✅ 55/55  |       ✅        |
| ML-KEM-1024 |  ✅    |  ✅ 55/55  |       ✅        |

Switch sets via the Alire crate configuration variable `parameter_set`
(set in `alire.toml`'s `[configuration.values]` block of the importing
crate, or by editing `config/ml_kem_ada_config.ads` directly).
Default is ML-KEM-768.

All three FIPS 203 parameter sets are fully supported. Per-set byte
sizes match the FIPS 203 specification:
- ML-KEM-512:  PK = 800,  SK = 1632, CT = 768
- ML-KEM-768:  PK = 1184, SK = 2400, CT = 1088
- ML-KEM-1024: PK = 1568, SK = 3168, CT = 1568

## v0.2 — single-set baseline (current)

The parameter constants live in a clearly-marked block at the top of
[`src/ml_kem.ads`](../src/ml_kem.ads):

```ada
ML_KEM_K    : constant := 3;
ML_KEM_Eta1 : constant := 2;
ML_KEM_Eta2 : constant := 2;
ML_KEM_Du   : constant := 10;
ML_KEM_Dv   : constant := 4;
```

Every derived size (`Indcpa_PK_Bytes`, `CT_Bytes`, …) is computed from
those five constants. The arithmetic primitives — NTT, BaseMul,
Reduce, Compress/Decompress — operate on the parameter-independent
shape `Polynomial = array (0 .. N - 1) of I16` with N = 256 and Q =
3329 across all three sets, so they need no per-set specialisation.

## v0.3 — generic-package design

The plan is to lift the five constants out of the parent package and
into a generic that the parameter-set crates instantiate:

```ada
generic
   K, Eta1, Eta2, Du, Dv : Positive;
package ML_KEM.Generic_KEM is
   --  re-derives Indcpa_PK_Bytes, CT_Bytes, Poly_Vector, etc.
   --  from the formal parameters; the original ml_kem-{kem,indcpa,
   --  polyvec,sampling,cbd,symmetric,verify,wipe}.{ads,adb} stay,
   --  but ML_KEM_K becomes K, ML_KEM_Eta1 becomes Eta1, and so on.
end ML_KEM.Generic_KEM;
```

Then three child packages:

```ada
--  ml_kem-k512.ads
package ML_KEM.K512 is new ML_KEM.Generic_KEM
  (K => 2, Eta1 => 3, Eta2 => 2, Du => 10, Dv => 4);

--  ml_kem-k768.ads
package ML_KEM.K768 is new ML_KEM.Generic_KEM
  (K => 3, Eta1 => 2, Eta2 => 2, Du => 10, Dv => 4);

--  ml_kem-k1024.ads
package ML_KEM.K1024 is new ML_KEM.Generic_KEM
  (K => 4, Eta1 => 2, Eta2 => 2, Du => 11, Dv => 5);
```

Users opt in to one (or several) at the call site:

```ada
with ML_KEM.K768;
package body My_Protocol is
   PK : ML_KEM.K768.Byte_Array (0 .. ML_KEM.K768.PK_Bytes - 1);
   …
   ML_KEM.K768.KEM.KeyGen (PK, SK, Seed);
end My_Protocol;
```

## ML-KEM-1024 implementation (landed in v0.3.0-pre)

`src/ml_kem-poly.adb` now implements `Compress_11`, `Decompress_11`,
`Compress_5`, and `Decompress_5` alongside the existing 10-bit / 4-bit
routines. Each variant takes 8 d-bit coefficients per block:

- `Compress_11` / `Decompress_11`: 8 × 11 = 88 bits → 11 bytes; 32
  blocks per polynomial (352 bytes total).
- `Compress_5` / `Decompress_5`: 8 × 5 = 40 bits → 5 bytes; 32
  blocks per polynomial (160 bytes total).

The bit layouts are the FIPS 203 standard ones (LSB-first packing
across bytes within a block); see the top-of-routine comments in
`ml_kem-poly.adb` for the explicit per-byte mappings.

`ml_kem-indcpa.adb` `Encrypt` / `Decrypt` dispatch on the static
`ML_KEM_Du` / `ML_KEM_Dv` constants:

```ada
if ML_KEM_Du = 10 then
   declare Tmp : Byte_Array_320; begin
      Poly.Compress_Du (UP (I), Tmp); … end;
else  --  Du = 11
   declare Tmp : Byte_Array_352; begin
      Poly.Compress_11 (UP (I), Tmp); … end;
end if;
```

GNAT folds the constant at compile time and elides the dead branch
at -O2; the source-level branch is needed because Compress_Du and
Compress_11 take different fixed-size formals. Same pattern for
Decompress and for the Dv = 4 / Dv = 5 split.

`Poly_Bytes_Du = ML_KEM_Du * N / 8` and `Poly_Bytes_Dv = ML_KEM_Dv *
N / 8` are the per-set runtime byte counts; `CT_Bytes` derives from
them.

## Future migration tasks (genericisation, v0.4)

1. **Refactor `ml_kem-cbd.adb` so that `CBD2` and `CBD3` are exposed
   side-by-side.** ML-KEM-512 needs CBD3 (Eta1 = 3); the other sets
   only ever call CBD2. The current code has both functions but only
   CBD2 is wired into IndCPA. Wire CBD3 conditional on Eta1 = 3.

2. **Generalise `ml_kem-poly.adb`'s Compress/Decompress to take Du
   and Dv as runtime arguments.** Currently each compression width
   has a dedicated procedure; a generic-instantiation form of these
   keeps the per-set body smaller.

3. **Hoist the five parameter-set constants into a generic
   `ML_KEM.Generic_KEM` package** as described above. This is the
   biggest change — it touches every file that mentions `ML_KEM_K`,
   `ML_KEM_Eta1`, `ML_KEM_Eta2`, `ML_KEM_Du`, or `ML_KEM_Dv` (currently
   `ml_kem.ads`, `ml_kem-kem.{ads,adb}`, `ml_kem-indcpa.{ads,adb}`,
   `ml_kem-polyvec.{ads,adb}`).

4. **Add `ml_kem-k512.ads`, `ml_kem-k768.ads`, `ml_kem-k1024.ads`
   instantiations** plus their KAT vectors. The CBD3 path needs its
   own KATs (currently we test ML-KEM-768 only, which uses CBD2
   throughout).

5. **Update `Valid_Encaps_Key`** — the per-set PK byte length needs
   to come from the generic, not the global `PK_Bytes` constant.

6. **Re-prove SPARK at level=2 across all three instantiations.** Each
   instantiation generates its own VCs.

7. **Re-run the ct_harness empirical CT verification** for each set —
   the cache-CT result depends on K and the polynomial sizes.

## Estimated effort

- Steps 1–2 (decoupling Compress/Decompress and CBD): ~half-day each.
- Step 3 (genericisation): 1–2 days. Most of that is mechanical
  rename-and-pass-through; the SPARK proof effort is bounded by the
  one-shot validation run.
- Step 4 (instantiations + KATs): half-day, bottlenecked by KAT
  acquisition (NIST CAVP vectors for 512 / 1024).
- Steps 5–7: another day.

Total: ~5 working days for a single engineer. Lower for someone with
existing ML-KEM-512/1024 KAT corpora.

## Why not in v0.2

The constant-time work in v0.2 (FORS / WOTS rewrite for `slh_dsa_ada`
and the `Encapsulate_Checked` / GenMatrix changes here) is the
release-blocker. Multi-parameter-set support is convenience: users
who need ML-KEM-512 or ML-KEM-1024 today can edit the five constants
in [`src/ml_kem.ads`](../src/ml_kem.ads) and rebuild — every other
file is parameter-set-agnostic. v0.3 turns that one-shot edit into a
proper generic.
