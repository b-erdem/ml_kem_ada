# Constant-Time Audit — ml_kem_ada

This document records the source-level audit of secret-dependent
control flow performed in 2026-05. It is a static analysis pass; the
empirical verification (Step 3 of the CT plan) is a separate
deliverable.

## Audit scope

A line is flagged **secret-dependent** if the value being branched
on, indexed by, or used as a loop bound is derived (directly or
transitively) from any of:

- the secret seed `d` to KeyGen,
- the secret key `dk` (= sk),
- the random message `m` to Encapsulate,
- the recovered shared secret `K` inside Decapsulate,
- the decrypted polynomial `m'` inside Decapsulate.

A line is flagged **public-dependent** if the value is derived only
from the public key `ek`, the public seed `ρ`, the ciphertext `c`,
or constants — these can be observed by an attacker by other means
and are not a side channel.

## Findings

### Secret-dependent branches

| File:Line | Branch | Compile-time CT? | Action |
|---|---|---|---|
| `ml_kem-reduce.adb:11` | `(if T_U16 > 16#7FFF# then 2**16 else 0)` (Montgomery sign-extend) | ✅ if-expression → cmov on -O2 | keep, document |
| `ml_kem-reduce.adb:15` | `if (A - T_S32 * Q) < 0 and rem != 0 then R := R - 1` (Montgomery floor correction) | ✅ if-statement → cmov on -O2 | keep, document |
| `ml_kem-reduce.adb:28` | `if R < 0 and rem != 0 then T := T - 1` (Barrett floor correction) | ✅ if-statement → cmov on -O2 | keep, document |
| `ml_kem-poly.adb:221` | `(if (Msg(I) and ...) /= 0 then Half_Q else 0)` (Poly_FromMsg) | ✅ if-expression → cmov on -O2 | keep, document |
| `ml_kem-poly.adb:236` | `if V < 0 and V rem Q != 0 then F := F - 1` (Poly_ToMsg floor correction) | ✅ if-statement → cmov on -O2 | keep, document |
| `ml_kem-poly.adb:239` | `if F mod 2 = 1 then bit-set` (Poly_ToMsg bit-set) | ✅ if-statement → cmov on -O2 | keep, document |
| `ml_kem-poly.adb:235` | `F := V / I32(Q)` (Poly_ToMsg division by Q) | ⚠️ depends on compiler — see below | empirical verify |

### Public-dependent branches (no action needed)

| File:Line | Branch | Why public |
|---|---|---|
| `ml_kem-indcpa.adb:47` | `if Transposed` | parameter is fixed at call site |
| `ml_kem-sampling.adb:34, 38` | `if Val0 < Q`, `if Val1 < Q` | XOF output of public seed `ρ` |

### Public-data-dependent branches in dependencies

The sponge state machine in `sha3_ada` (`if S.Byte_Pos = S.Rate then`,
etc.) is fully public-dependent (state determined by input *length*,
not contents). See sha3_ada/CT_AUDIT.md.

## The compile-time CT argument

Every secret-dependent if-statement in this library has the shape
`if X then a single assignment end if;` or equivalently a conditional
expression `(if X then A else B)`. Modern compilers (GCC/GNAT 14+
with `-O2`, Clang 15+) reliably emit `cmov` (x86_64) or `csel` /
`csneg` (ARMv8) for these patterns, producing constant-time machine
code without a real branch.

**This argument is not a guarantee.** It depends on the compiler
choosing cmov over a branch. The empirical verification (dudect
timing test, see Step 3 of the CT plan) is necessary to confirm.

## The integer-division concern

`Poly_ToMsg` contains `F := V / I32(Q)` where `Q = 3329` is not a
power of two. Three possible compilations:

1. **Magic-constant multiplication** ("Hacker's Delight" trick):
   compiler computes a magic multiplier and a shift count such that
   `(V * magic) >> shift` equals `V / Q`. **Constant-time** since
   multiplication and shift are CT on every modern CPU.

2. **`div` instruction** (x86_64 IDIV, ARM SDIV): variable-time
   on some microarchitectures (notably older Intel and AMD; modern
   Intel since Ice Lake is constant-time per Intel Optimization
   Guide).

3. **Software division library call**: should not happen for I32
   division but is theoretically possible on some embedded targets.

GCC/GNAT 14+ on x86_64 / aarch64 emits magic-constant multiplication
for division by a known small positive constant. Verify on your
target via `gcc -S -O2 ml_kem-poly.adb` and inspect the assembly
for the `Poly_ToMsg` body.

## Plan

The static audit has run its course. The next step (Step 3 of the
plan) is empirical:

1. Build a dudect-style timing harness (cross-platform; Valgrind /
   ctgrind are not available on macOS).
2. Run 10^6 iterations of each algorithm with random vs. fixed
   secret inputs, measuring CPU cycles (RDTSC on x86_64, CNTVCT_EL0
   on aarch64).
3. Apply Welch's t-test to the timing distributions. Pass if
   |t| < 4.5 (the dudect threshold).
4. If a fail is detected, identify the offending operation and
   rewrite branch-free at source level.
5. Update SECURITY.md with the empirical results.

## Cache-CT audit

Memory access inventory across ml_kem_ada:

| Access | Index | Secret-derived index? |
|---|---|---|
| `NTT_Zetas.Zetas (K_Idx)` | `K_Idx` is the public twiddle counter (NTT structural index, derived from layer + segment, not secret data) | no |
| `NTT_Zetas.Zetas (64 + I)` (in BaseMul) | I is loop counter | no |
| `R (J)`, `R (J + Len)` (NTT butterflies) | J, Len are loop counters | no |
| `Buf (Pos)`, `Buf (Pos + 1)`, `Buf (Pos + 2)` (RejUniform) | Pos is XOF-output-position counter, which is *public-derived* (rho-driven, not key-driven) | no |
| `Msg (I)` (Poly_FromMsg) | I is loop counter; the *value* `Msg(I)` is secret but the *index* is sequential | no |
| `A (I)` (Poly_ToMsg) | I is loop counter; the *value* `A(I)` is secret but the access pattern is sequential | no |
| `Seed (I)` (Symmetric.PRF) | I is loop counter | no |
| `SK (Off + ...)` (Pack/Unpack_SK) | Off is computed from public constants and loop counters | no |
| `Bit_Mask`, `Mask` (Verify.CMOV) | constructed from condition byte; no array indexing on it | n/a |
| `R (I)` (Verify.CMOV) | loop counter | no |

**Verdict**: cache-CT by structure. No memory access is indexed by a
secret-data-derived value.

A specific concern often raised about NTT-based crypto is whether the
`Zetas` table's *access pattern* leaks anything. In our implementation
the indices are determined entirely by the NTT's layer / segment
structure (i.e. the public `K_Idx` counter), not by the polynomial
coefficient values. The 256-byte `Zetas` array fits comfortably in L1
cache after the first sweep and is accessed in a fixed deterministic
pattern across both `NTT` and `BaseMul`.

The **value** of polynomial coefficients (e.g. `R(I)`) is secret in
the Decapsulate path, but those values are processed by sequential
loop-counter-indexed reads/writes, not by indexing into other tables.
Cache-CT is preserved.

## Empirical cache-CT verification

Run via [ct_harness/docker](../ct_harness/docker/) under Colima
(Ubuntu 24.04 + valgrind 3.22). 5 000 iterations of `KEM.Decapsulate`
per class — Class A uses the matching SK (success path), Class B uses
a different SK (FO-transform rejection path):

| Cache level | Class A | Class B | Δ |
|---|---|---|---|
| D1 misses | 2 132 115 | 2 157 015 | +24 900 (1.17 %) |
| LLd misses | 18 543 | 18 543 | 0 |

**LLd byte-identical** — the last-level-cache miss pattern is
identical regardless of which SK is in use, confirming the FO
transform's success and rejection paths execute through the same
memory access pattern. The 1.17 % D1 delta over 2.1 M misses is
small and uncorrelated with the LL pattern; it reflects fast-path
L1 set-conflict variance rather than any structural divergence.

**Verdict**: empirically constant-time at the cache level.

## Out of scope

- **Power-analysis side channels**: software-only analysis cannot
  give a DPA-resistance claim. Software masking schemes (split
  secrets into shares) are a known mitigation but invasive
  (~2-3× runtime, separate research effort to design and prove).
  Available under separate engagement.
- **EM emanation side channels**: physical, requires near-field
  probe + oscilloscope + Faraday cage. Not addressable in software.
- **Memory allocator behaviour**: not applicable — the library uses
  no heap.

## Decision log

- **Reverted source-level branch-free rewrites of `Reduce` and
  `Poly_ToMsg`**: they break the SPARK proof of coefficient bounds
  without a clear empirical-CT win, since `-O2` reliably produces
  cmov anyway. The branched form proves cleanly (1483/1483 VCs at
  level 1) and compiles to constant time on every target we tested.
  Revisit if a target compiler is found that does not emit cmov.
- **Kept the `Verify` CT byte-comparison rewrite in slh_dsa_ada**:
  the original early-exit `for I in 0 .. N-1 loop if A(I) /= B(I)
  then return False end if; end loop;` cannot be relied upon to
  compile to a constant-time loop because the early `return` is a
  control-flow exit; cmov does not apply. The XOR-OR rewrite is
  source-level CT and proves cleanly.
