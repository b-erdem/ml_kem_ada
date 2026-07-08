# SPARK Proof Techniques for ML-KEM-768

This document collects the proof techniques used to formally verify the
type safety of [ml_kem_ada](.) at SPARK Level 1, eliminating all 39
`pragma Assume` statements that the initial implementation relied on.

**Why publish this?** As of 2026-05, no SPARK implementation of ML-KEM
exists; the closest verified work is libcrux (Rust → F\*) which uses a
different proof platform. The techniques below are reusable for any
ARX/lattice cryptography project in SPARK.

## Contents

1. [Type-level bounds for constant tables](#1-type-level-bounds-for-constant-tables)
2. [Bound tracking via a regular variable](#2-bound-tracking-via-a-regular-variable)
3. [The 6-piece segment invariant](#3-the-6-piece-segment-invariant)
4. [Helper procedures with bound contracts](#4-helper-procedures-with-bound-contracts)
5. [Disjoint-bit OR rewritten as ADD](#5-disjoint-bit-or-rewritten-as-add)
6. [Lemma functions for bit-packing primitives](#6-lemma-functions-for-bit-packing-primitives)
7. [Functional postconditions to chain bounds](#7-functional-postconditions-to-chain-bounds)
8. [Always_Terminates aspect cascade](#8-always_terminates-aspect-cascade)
9. [Multiplicative invariants in nested loops](#9-multiplicative-invariants-in-nested-loops)
10. [What we did *not* prove](#10-what-we-did-not-prove)

## 1. Type-level bounds for constant tables

The `Zetas` table contains 128 precomputed Montgomery-domain twiddle
factors, each in `[-1659, 1653]`. The original code stored these as
`array (0..127) of I16`, leaving the full 16-bit range visible to
gnatprove. Every product `Zeta * R(j+len)` then required either a
`pragma Assume` to bound the result inside `Q*2^15`, or per-element
case analysis (which CVC5 doesn't do).

The fix is a one-line change:

```ada
subtype Zeta_Type is I16 range -(Q - 1) .. (Q - 1);
Zetas : constant array (0 .. 127) of Zeta_Type := [...];
```

Now SPARK uses `|Zeta| < Q` as a type-level fact for free, and
`(Q-1) * (Bound + Q) < Q*2^15` is a routine linear-arithmetic check.

This pattern works for any precomputed table whose mathematical bound
is tighter than the host integer type. NIST CAVP test vectors should
be the source of truth for the bound.

## 2. Bound tracking via a regular variable

The forward NTT is a 7-layer Cooley-Tukey butterfly:

```
Layer k (0..6): R[j], R[j+len] = R[j] + t, R[j] - t
                where t = FqMul(zeta, R[j+len]) in [-Q, Q]
```

Each layer can grow `|R(i)|` by at most `Q` (FqMul postcondition).
With initial bound `B0`, the bound after 7 layers is `B0 + 7Q`.

Rather than encode this growth in a `Layer : Natural` ghost variable
and chase `2**Layer = ...`, we use a regular `Bound : I16` variable
that gets `Bound := Bound + Q` at the bottom of each outer iteration.
SPARK tracks it as a normal program variable.

```ada
procedure NTT (R : in out Polynomial) is
   Bound : I16 := Q;
begin
   while Len >= 2 loop
      pragma Loop_Invariant (Bound in Q .. 7 * Q);
      pragma Loop_Invariant
        (for all I in 0 .. N - 1 => R (I) in -Bound .. Bound);
      ...
      Bound := Bound + Q;
   end loop;
   --  Postcondition: R(I) in -8Q..8Q (Bound has incremented to 8Q).
end NTT;
```

The `Bound in Q..7*Q` invariant is needed at the *top* of each
iteration; the post-loop value `8*Q` is derivable by SPARK from the
last increment.

For the inverse NTT we use the same idea but with a fixed-point bound:
each layer's butterfly Barrett-reduces one half and FqMul-reduces the
other, so `Bound` drops to `Q` after the first layer regardless of
input. The body just sets `Bound := Q` unconditionally at the end.

## 3. The 6-piece segment invariant

Inside the inner butterfly loop `for J in Start .. Start + Len - 1`,
each iteration touches positions `J` and `J + Len`. SPARK needs to
know that:

* Positions in prior segments `[0, Start - 1]` are at the post-layer
  bound `(Bound + Q)`.
* Positions in `[Start, J - 1]` (low half processed in this segment)
  are at `(Bound + Q)`.
* Positions in `[Start + Len, J + Len - 1]` (high half processed in
  this segment) are at `(Bound + Q)`.
* Positions in `[J, Start + Len - 1]` (low half pending — including
  the current `J`) are still at the entry `Bound`.
* Positions in `[J + Len, Start + 2*Len - 1]` (high half pending —
  including the current `J + Len`) are still at `Bound`.
* Positions in `[Start + 2*Len, N - 1]` (subsequent segments) are
  still at `Bound`.

That's 6 separate Loop_Invariant clauses. We also keep one *loose*
universal bound `R(I) in -(Bound + Q)..(Bound + Q)` as a
post-condition for the Butterfly precondition (which only needs the
loose bound).

Why 6 pieces and not fewer? Because the **tight** `R(J), R(J+Len) in
-Bound..Bound` is what allows the FqMul precondition to use the small
`(Q-1) * Bound` product, rather than the looser `(Q-1) * (Bound + Q)`
which would blow the budget for large layers. Distinguishing the
pending half from the processed half is essential.

## 4. Helper procedures with bound contracts

Rather than verify the butterfly arithmetic inline (where it appears
in two slightly different forms — forward and inverse), we extract a
`Butterfly` procedure with explicit pre/post:

```ada
procedure Butterfly
  (R : in out Polynomial; J, J_Plus_Len : Natural;
   Zeta : NTT_Zetas.Zeta_Type; B_In : I16)
  with Pre  => J < J_Plus_Len
              and J_Plus_Len < N
              and B_In in Q .. 7 * Q
              and (for all I in 0..N-1 => R(I) in -(B_In+Q)..(B_In+Q))
              and R(J) in -B_In..B_In
              and R(J_Plus_Len) in -B_In..B_In,
       Post => (for all I in 0..N-1 =>
                 (if I = J or I = J_Plus_Len then
                     R(I) in -(B_In + Q)..(B_In + Q)
                  else
                     R(I) = R'Old(I)));
```

The `R(I) = R'Old(I)` framing condition is critical: it says the
butterfly *only* modifies the two named positions. Without it, the
caller's segment invariant (above) would be invalidated by every
butterfly call.

`InvButterfly` has a similar shape; its post is tighter because each
output is either a Barrett or FqMul result (`R(I) in -Q..Q`).

## 5. Disjoint-bit OR rewritten as ADD

In `Decompress_Du`, ten-bit values are extracted from packed bytes:

```ada
V := U32 (A (10 * I))
     or Interfaces.Shift_Left (U32 (A (10 * I + 1) and 16#03#), 8);
```

Mathematically `V` is in `[0, 1023]`. But CVC5 doesn't reason about
bit-vector OR by default, so it can't prove `V < 1024` from this form.

The fix: rewrite OR as ADD when the bits don't overlap. Here
`A(10*I)` occupies bits 0..7 and `(A(10*I+1) and 0x03) << 8` occupies
bits 8..9, so their OR equals their sum:

```ada
V := U32 (A (10 * I))
     + 256 * U32 (A (10 * I + 1) and 16#03#);
```

Now SPARK derives `V <= 255 + 256 * 3 = 1023` by linear arithmetic,
the precondition of the per-coefficient lemma function (next section).

## 6. Lemma functions for bit-packing primitives

Decompression maps a `d`-bit value `v` to `(v * Q + 2^(d-1)) / 2^d`.
The result is always in `[0, Q-1]`, but proving this for each of the
8 different bit-extraction patterns separately would be tedious.

The fix: a single expression-function lemma:

```ada
function Decompress_Du_Coeff (V : U32) return I16 is
  (I16 ((I32 (V) * I32 (Q) + 512) / 1024))
  with Pre  => V < 1024,
       Post => Decompress_Du_Coeff'Result in 0 .. Q - 1;
```

Then the Decompress body extracts the 8 ten-bit values into named
locals (using ADD-not-OR per §5) and calls the lemma 8 times. The
single contract is proved once, and the 8 callers each just need
their `V < 1024` precondition checked.

This also documents the FIPS 203 formula precisely. A reader sees the
`(v * Q + 2^(d-1)) / 2^d` shape in one place rather than 8.

## 7. Functional postconditions to chain bounds

`Poly_Add (R, B)` originally had only a precondition that the sum
fits in `I16`. To prove the bound on the *result* of an accumulator
loop (`PolyVec_Basemul_Acc` in our case), the caller needs to know
that `R(I)` after the call equals `R'Old(I) + B(I)`.

Adding this as a postcondition costs nothing and unlocks downstream
bound proofs:

```ada
procedure Poly_Add (R : in out Polynomial; B : Polynomial)
  with Pre  => (for all I in 0..N-1 =>
                  I32(R(I)) + I32(B(I)) in I16'Range),
       Post => (for all I in 0..N-1 => R(I) = R'Old(I) + B(I));
```

The body needs a Loop_Invariant to make this provable in isolation:

```ada
for I in 0 .. N - 1 loop
   pragma Loop_Invariant
     (for all K in 0..I-1 => R(K) = R'Loop_Entry(K) + B(K));
   pragma Loop_Invariant
     (for all K in I..N-1 => R(K) = R'Loop_Entry(K));
   R(I) := R(I) + B(I);
end loop;
```

Same pattern for `Poly_Sub`. The `'Loop_Entry` attribute is essential
— `R'Old` would refer to the procedure entry, but we need the value
from before the loop body started.

## 8. Always_Terminates aspect cascade

In SPARK 2025, procedures must declare `Always_Terminates => True` to
be callable from contexts that need termination (e.g., from a
function whose own termination is implicit). For ml_kem we propagated
`Always_Terminates` only where downstream proofs needed it; many
internal procedures have static-bounded loops and prove termination
trivially without the aspect, but the cascade through `Verify` (a
function) does require explicit aspects on transitive callees.

Same pattern was needed in the [slh_dsa_ada](../slh_dsa_ada) sibling
to fix 3 termination VCs in `Verify`.

## 9. Multiplicative invariants in nested loops

The forward NTT outer loop has a relation `K_Idx * Len = 128` that
holds at the top of every layer (Len ∈ {128, 64, ..., 2} corresponds
to K_Idx ∈ {1, 2, 4, ..., 64}). Inside the middle loop, the relation
strengthens to `K_Idx * Len = 128 + Start / 2`.

These multiplicative invariants are at the edge of CVC5's ability —
they prove, but slowly. We help by also enumerating the discrete
Len/K_Idx values:

```ada
pragma Loop_Invariant (Len in 2 | 4 | 8 | 16 | 32 | 64 | 128);
pragma Loop_Invariant (K_Idx in 1 | 2 | 4 | 8 | 16 | 32 | 64);
pragma Loop_Invariant (K_Idx * Len = 128);
```

The first two are decidable case-by-case; the third combined with
either gives the prover more options. For inverse NTT the relation
is `(K_Idx + 1) * Len = 256`.

The structural assumes that GLM had originally — `K_Idx <= 127` and
`J + Len <= N - 1` — fall out of these invariants combined with
`Start mod (2 * Len) = 0` and `Start + 2 * Len <= N` (the latter
holds because `2 * Len` divides `N = 256`).

## 10. What we did *not* prove

Type safety — no overflow, no array out-of-bounds, no division by
zero — is fully proved.

What is *not* proved (and would require substantially more work):

* **Functional correctness**, i.e. that `Decapsulate(Encapsulate(...))`
  recovers the original shared secret. This needs an algebraic theory
  of `Z_q[X]/(X^256+1)` and the NTT-domain ring isomorphism. Out of
  scope for SPARK without a custom theory.
* **Constant-time execution**. SPARK does not model timing.
  `Verify.CMOV` and `Verify.Verify` are written in a constant-time
  shape, but compiler optimisations could reorder them. Adding
  `pragma Inspection_Point` on secret-dependent values would be
  conservative.
* **The 5-block budget in `GenMatrix`** is a deviation from FIPS 203
  Algorithm 6 (which loops indefinitely until 256 valid samples).
  Probability of failure is statistically negligible but nonzero.
  See the inline comment in `ml_kem-indcpa.adb`.

## References

- FIPS 203 (ML-KEM): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- pq-crystals/kyber (reference C implementation): https://github.com/pq-crystals/kyber
- libcrux (Rust → F\* verification): https://github.com/cryspen/libcrux
- SPARK 2014 Reference Manual: https://docs.adacore.com/spark2014-docs/html/lrm/
- SPARKNaCl (technique source for crypto in SPARK): https://github.com/rod-chapman/SPARKNaCl
