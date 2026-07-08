# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-06

First stable release. The public API contract is committed to under
SemVer; future 1.x releases preserve backward compatibility.

This release rolls up the v0.2.0 and v0.3.0-pre entries below into
the 1.0 stability commitment. Net additions vs. the v0.1.0 initial
release:

- **All three FIPS 203 parameter sets** (ML-KEM-512, 768, 1024)
  selectable at build time via the `parameter_set` Alire crate
  config variable.
- **`Valid_Encaps_Key`** + **`Encapsulate_Checked`** — FIPS 203 §7.2
  modulus check + a FIPS-conforming Encapsulate variant that runs
  the check up front and, on failure, zeros outputs and returns
  `Ok = False`.
- **`ML_KEM.Wipe`** zeroisation helpers with `Inline => False`
  bodies; secret-bearing locals are cleared at scope end across
  `KEM.{KeyGen,Encapsulate,Decapsulate}`,
  `IndCPA.{KeyGen,Encrypt,Decrypt}`, and `Symmetric.PRF`.
- **`gnatprove --level=2`** in CI (1512/1512 obligations at level 2;
  v0.1.0 documented level 1, 1483 obligations).
- **GenMatrix budget bumped from 5 SHAKE128 blocks/cell to 256**
  (failure probability < 2^-1024, vs. ~10^-7 previously).
- **Empirical CT verification** of `KEM.Decapsulate` (Welch *t* =
  -1.27, LLd cache misses byte-identical) — see
  [CT_AUDIT.md](CT_AUDIT.md).
- **`-fstack-usage`** GPR switch + `scripts/stack_summary.sh`.
  Worst-case stack budget ~15 KB documented in SECURITY.md.

### Changed
- `sha3_ada` dependency constraint: `~0.1` → `~1.0`.
- `tests/test_ml_kem.gpr`: dropped the `SDK_Type` scenario variable.
  The `-L` to the macOS Command Line Tools SDK is now emitted
  unconditionally; on Linux the directory is silently ignored.
  Override with `-XSDK_LIB=/path` on Xcode.app installs.
- README and SECURITY.md refreshed to match current state (level 2,
  3 sets, CT empirically verified, §7.2 covered by
  `Encapsulate_Checked`).

### No breaking changes from v0.1.0.

Public APIs `KeyGen`, `Encapsulate`, `Decapsulate` keep their byte-
exact behaviour for the default ML-KEM-768 build profile.
`Encapsulate_Checked` is an additional procedure, not a replacement.

### Verified
- 55 test cases pass across all 3 parameter sets (Phase 1 unit
  through Phase 4 KEM round-trip).
- 1512/1512 SPARK level=2 obligations on default ML-KEM-768, zero
  `pragma Assume`, zero unproved.
- Empirical CT (KEM.Decapsulate × 20 000 iter, Welch *t* = -1.27)
  and cache-CT (LLd byte-identical) verified.

## [0.3.0-pre] - 2026-05-06

### Added

- **Multi-parameter-set support** via Alire crate configuration.
  `[configuration.variables].parameter_set` selects ML-KEM-512,
  ML-KEM-768, or ML-KEM-1024 at build time; default ML-KEM-768.
  All five FIPS 203 constants (K, η₁, η₂, du, dv) are derived
  statically from a single `case` expression in `ml_kem.ads`.
- **`CBD.Sample_Eta1`** — parameter-aware noise sampler that
  dispatches statically between CBD2 (Eta1 = 2 for ML-KEM-768/1024)
  and CBD3 (Eta1 = 3 for ML-KEM-512). Both branches present in
  source so SPARK proves both; GNAT at -O2 elides the dead branch.
  PRF buffer auto-sizes to `Eta1 * N / 4` bytes.
- **`docs/PARAMETER_SETS.md`** updated with current support matrix
  and remaining work for full ML-KEM-1024 conformance (Compress_11
  and Compress_5 routines).

### Changed

- **`Encrypt`** uses two PRF buffers: `Buf_Eta1` for the y noise
  vector, `Buf_Eta2` (always 128 bytes) for e1 and e2. Previously a
  single buffer assumed Eta1 = Eta2 = 2.
- **Loop invariants in `IndCPA.KeyGen` / `Encrypt`** changed from
  the literal `-2 .. 2` to `-ML_KEM_Eta1 .. ML_KEM_Eta1` for the
  y / SPV path so the proof generalises across Eta1 = 2 and = 3.
  The eta2 paths (e1, e2) keep the literal range since Eta2 is
  fixed at 2 across all FIPS 203 sets.

### Status

- ML-KEM-512: ✅ builds, ✅ 55/55 round-trip tests pass.
- ML-KEM-768: ✅ builds, ✅ 55/55 tests pass (default).
- ML-KEM-1024: ✅ builds, ✅ 55/55 round-trip tests pass.

All three FIPS 203 parameter sets are now fully supported with
byte-size-conformant ciphertexts (PK / SK / CT sizes match FIPS 203
spec). The `Compress_11` / `Decompress_11` (8 coefs / 11 bytes) and
`Compress_5` / `Decompress_5` (8 coefs / 5 bytes) routines were
added to `ml_kem-poly.adb`; `IndCPA.Encrypt` / `Decrypt` dispatch on
static `ML_KEM_Du` / `ML_KEM_Dv` so GNAT folds the constant and
emits only the live compression path at -O2.

## [0.2.0] - 2026-05-06

### Added

- **`Valid_Encaps_Key`** — FIPS 203 §7.2 modulus check (every decoded
  polynomial coefficient < Q). Constant-time over the whole PK byte
  string; rejects malformed length first.
- **`Encapsulate_Checked`** — FIPS 203-conforming Encapsulate variant.
  Calls `Valid_Encaps_Key` first; on failure, zeroes CT and SS and
  returns `Ok = False` without touching the IndCPA path.
- **`ML_KEM.Wipe`** — caller-facing zeroisation helpers
  (`Wipe_Byte_Array`, `Wipe_Polynomial`, `Wipe_Poly_Vector`). Bodies
  in a separate compilation unit with `Inline => False` so the
  optimizer cannot prove the writes dead at -O2 without LTO. Used
  internally to clear secret-bearing locals at scope end across
  `KEM.{KeyGen,Encapsulate,Decapsulate}` and
  `IndCPA.{KeyGen,Encrypt,Decrypt}` and `Symmetric.PRF`.
- **CI workflow** (`.github/workflows/ci.yml`) running build + tests
  + `gnatprove --level=2` on every push/PR.
- **`-fstack-usage`** GPR switch + `scripts/stack_summary.sh`
  aggregator. SECURITY.md documents the resulting frame budget.
- **`docs/PARAMETER_SETS.md`** — design plan for v0.3 generic
  re-instantiation enabling ML-KEM-512 / 768 / 1024.

### Changed

- **GenMatrix budget bumped from 5 SHAKE128 blocks per cell to 256.**
  The new bound's failure probability (Chernoff tail of
  Binomial(14336, 0.813) below 256) is < 2^-1024 vs. the previous
  ~10^-7. SPARK-friendly finite bound preserved.
- SECURITY.md: removed the "GenMatrix 5-block budget" caveat and the
  "FIPS 203 §7.2 input validation deferred" caveat (both addressed).

### Verified

- **3 new test vectors** for `Valid_Encaps_Key` (good PK, short PK,
  out-of-range coefficient). 5 more for `Encapsulate_Checked`. Total
  55 tests pass.
- **SPARK level 2** — 1512 proof obligations across all units, zero
  unproved.
- Empirical CT (`KEM.Decapsulate` × 20 000 iter, Welch t = -1.27)
  and cache-CT (LLd misses byte-identical) re-run after the Wipe and
  Encapsulate_Checked additions.

## [0.1.0] - 2026-05-06

Initial release. ML-KEM-768, formally verified at SPARK level 1.

### Added

- **Core arithmetic**: Barrett and Montgomery reduction, FqMul, with
  postconditions on output ranges (`-Q..Q`, `-Q_Half..Q_Half`).
- **Centered Binomial Distribution**: `CBD2` and `CBD3` with output range
  `-2..2` / `-3..3` proved.
- **Number Theoretic Transform**: `NTT.NTT` (forward, 7 layers) and
  `NTT.InvNTT` (inverse + final scaling). Coefficient bounds tracked
  per-layer through a regular `Bound` variable, growing by `Q` per layer
  forward (initial `Q`, final `8Q = NTT_Bound`) and dropping to `Q` after
  the first inverse layer.
- **Pointwise multiplication in NTT domain**: `BaseMul`, with input bound
  `2Q` (covers Barrett-reduced, Decompress, and ByteDecode12 outputs),
  output bound `2Q`.
- **Polynomial / polynomial vector**: `Poly_Add` / `Poly_Sub` with
  functional postconditions, `Poly_Reduce`, `Poly_ToMont`, `Poly_Freeze`,
  `Compress_Du` / `Compress_Dv`, `Decompress_Du` / `Decompress_Dv` (with
  per-coefficient lemma functions proving the rounding bound), `Poly_FromMsg`
  / `Poly_ToMsg`.
- **Sampling**: `RejUniform` rejection sampling, `GenMatrix` with
  postcondition `A(I)(J)(K) in 0..Q-1`.
- **Symmetric primitives wrapper**: `Hash_G` (SHA3-512), `Hash_H`
  (SHA3-256), `PRF` (SHAKE256), `XOF_Absorb` / `XOF_Squeeze` (SHAKE128
  streaming), all built on [sha3_ada](../sha3_ada).
- **Verify** helpers: `CT_Eq` constant-time-shape comparison, `CMOV`
  conditional move.
- **IndCPA layer**: `KeyGen`, `Encrypt`, `Decrypt` over the IndCPA scheme,
  including pack / unpack helpers with explicit pre/postconditions.
- **KEM layer**: `KeyGen`, `Encapsulate`, `Decapsulate` implementing the
  CCA-secure FO transform. `Decapsulate` performs implicit rejection.
- **`pragma Pure`** — no global state, no heap allocation.
- **47 test cases pass** — Phase 1 (math) through Phase 4 (KEM round-trip).
- **SPARK level 1 proof** — 1483/1483 proof obligations discharged
  (CVC5 81% / Z3 17% / trivial 2%). Zero `pragma Assume`. Zero unproved
  VCs. Termination verified for every public subprogram.
- **PROOF_NOTES.md** — documents the ten proof techniques used, intended
  for re-use in similar lattice / ARX cryptography work.

### Status of out-of-scope items

- Constant-time execution: not empirically verified. See
  [SECURITY.md](SECURITY.md).
- FIPS 140-3 validation: not validated.
- ML-KEM-512, ML-KEM-1024: not implemented.
- FIPS 203 §7.2 public-key modulus check in `Encapsulate`: not
  implemented. See [SECURITY.md](SECURITY.md).
- GenMatrix 5-block budget vs. FIPS 203 Algorithm 6 unbounded loop: noted
  in [SECURITY.md](SECURITY.md).
- ACVP test harness: not implemented.

[0.1.0]: https://github.com/b-erdem/ml_kem_ada/releases/tag/v0.1.0
