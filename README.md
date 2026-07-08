# ml_kem_ada

[![CI](https://github.com/b-erdem/ml_kem_ada/actions/workflows/ci.yml/badge.svg)](https://github.com/b-erdem/ml_kem_ada/actions/workflows/ci.yml) [![License: GPL-3.0-only / commercial](https://img.shields.io/badge/license-GPL--3.0--only%20%7C%20commercial-blue.svg)](COMMERCIAL-LICENSE.md) [![SPARK: 2204/2204 proved](https://img.shields.io/badge/SPARK%20proof-2204%2F2204%20VCs%2C%200%20assume-brightgreen.svg)](SECURITY.md)

A ML-KEM ([FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf))
implementation for Ada 2022, formally verified with
[SPARK](https://www.adacore.com/about-spark).

The post-quantum key encapsulation mechanism — including the 7-layer
Cooley-Tukey NTT, Barrett and Montgomery reduction, basemul, IndCPA, and FO
transform — is **100% SPARK-proved at level 2** with **zero `pragma Assume`
statements**.

To our knowledge this is the first ML-KEM implementation in any language
that achieves type safety with no proof escape hatches at all. The proof
techniques used are documented in [PROOF_NOTES.md](PROOF_NOTES.md) for
re-use in similar lattice / ARX cryptography work.

## Key properties

- **Formally verified** — 2204 proof obligations at level 2, 0 unproved, 0 `pragma Assume`
- **All three FIPS 203 parameter sets** (selected at build time via the
  `parameter_set` Alire crate configuration variable; default ML-KEM-768):
  - **ML-KEM-512** — NIST Category I
  - **ML-KEM-768** — NIST Category III (default)
  - **ML-KEM-1024** — NIST Category V
- **Built on [sha3_ada](https://github.com/b-erdem/sha3_ada)** for SHA-3, SHAKE128, SHAKE256
- **No heap allocation** — `pragma Pure`, stack-only
- **55 test cases pass** — Phase 1 unit tests through Phase 4 KEM round-trip,
  across all three parameter sets

## Status

| Property | Status |
|---|---|
| Type safety (overflow, range, bounds) | ✅ Proved (SPARK level 2, 2204/2204 VCs) |
| Termination | ✅ Proved (all public subprograms verified) |
| Functional correctness vs FIPS 203 | ✅ Tested with KEM round-trip and KAT-style vectors |
| Constant-time execution | ✅ Empirically verified (`KEM.Decapsulate`, Welch *t* = -1.27, cache-CT byte-identical at LLd) |
| FIPS 203 §7.2 input validation | ✅ `Valid_Encaps_Key` + `Encapsulate_Checked` (FIPS-conforming variant) |
| All FIPS 203 parameter sets | ✅ ML-KEM-512 / 768 / 1024 |
| FIPS 140-3 validated | ❌ Not validated |

## Installation

```toml
[[depends-on]]
ml_kem_ada = "~1.0"
sha3_ada   = "~1.0"

[[pins]]
ml_kem_ada = { url = "https://github.com/b-erdem/ml_kem_ada" }
sha3_ada   = { url = "https://github.com/b-erdem/sha3_ada" }
```

## Quick start

```ada
with ML_KEM;
with ML_KEM.KEM;

procedure Demo is
   --  Seed: 64 bytes of high-entropy randomness from your CSPRNG.
   Seed : ML_KEM.Byte_Array_64 := (others => 0);
   PK   : ML_KEM.Byte_Array (0 .. ML_KEM.PK_Bytes - 1);
   SK   : ML_KEM.Byte_Array (0 .. ML_KEM.SK_Bytes - 1);

   M    : ML_KEM.Byte_Array_32 := (others => 0);  --  fill from CSPRNG
   CT   : ML_KEM.Byte_Array (0 .. ML_KEM.CT_Bytes - 1);
   SS_A : ML_KEM.Byte_Array_32;
   SS_B : ML_KEM.Byte_Array_32;
begin
   --  Bob:
   ML_KEM.KEM.KeyGen (PK, SK, Seed);

   --  Alice:
   ML_KEM.KEM.Encapsulate (CT, SS_A, PK, M);

   --  Bob:
   ML_KEM.KEM.Decapsulate (SS_B, CT, SK);

   --  SS_A = SS_B (32-byte shared secret).
end Demo;
```

## Building & testing

```bash
alr build
cd tests && alr build && ./obj/test_ml_kem
```

## Formal verification

```bash
alr exec -- gnatprove -P ml_kem_ada.gpr -j0 --level=2
```

Expected: 2204/2204 checks proved at level=2, 0 unproved, 0 `pragma Assume`.

## Proof techniques

[PROOF_NOTES.md](PROOF_NOTES.md) documents the ten proof techniques used,
including:

- Type-level bounds for the precomputed `Zetas` table.
- Bound tracking via a regular `I16` variable across NTT layers.
- The 6-piece segment invariant for distinguishing pending vs. processed
  positions inside butterfly loops.
- Helper `Butterfly` / `InvButterfly` procedures with framing conditions.
- Disjoint-bit OR rewritten as ADD for `Decompress` proofs.
- Lemma functions for bit-packing primitives.

These techniques are reusable for other lattice or NTT-based primitives.

## License

Dual-licensed:

- **GPL-3.0-only** — see [LICENSE](LICENSE). Free for open-source use;
  distributed derivative works must be GPL-licensed too.
- **Commercial license** for proprietary/closed-source products —
  see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) or contact
  <baris@erdem.dev>.
