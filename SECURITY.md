# Security Policy & Threat Model

## Reporting Vulnerabilities

Report security issues privately via GitHub Security Advisories or email
`baris@erdem.dev`. Do not open public issues for vulnerabilities.

Disclosure SLA: acknowledgement within 7 days, fix or mitigation within 90
days for high-severity issues.

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | ✅ |

## Threat Model

`ml_kem_ada` implements ML-KEM (all three FIPS 203 parameter sets:
ML-KEM-512, ML-KEM-768, ML-KEM-1024), a lattice-based key
encapsulation mechanism. The trust boundary is the public key:
`Decapsulate` may be called on adversarially-chosen ciphertexts.

### What SPARK proves (level 2)

All 1512 proof obligations are discharged at level 2, guaranteeing
**absence of**:

| Class | Coverage |
|---|---|
| Buffer overflows | Array index checks throughout NTT, BaseMul, IndCPA, KEM |
| Integer overflows | All intermediate I32 products and I16 sums proved in-range |
| Range violations | Subtype checks on coefficients, indices, byte positions |
| Uninitialized reads | Flow analysis on Sponge_State, polynomial vectors, output buffers |
| Non-termination | All public subprograms verified `Always_Terminates` |

These guarantees hold for **all possible inputs** — not just tested ones.
Zero `pragma Assume` statements. The proof has no escape hatches.

The 7-layer Cooley-Tukey NTT, BaseMul, and the IndCPA arithmetic are
verified end-to-end. The proof techniques are documented in
[PROOF_NOTES.md](PROOF_NOTES.md).

### Out of scope

#### Constant-time execution

**Static analysis**: see [CT_AUDIT.md](CT_AUDIT.md). Seven secret-dependent
branches identified, all in the form `if X then a single statement` or
`(if X then A else B)` patterns that GCC/GNAT 14+ at -O2 reliably emit
as `cmov` (no real branch). The integer division by Q in `Poly_ToMsg`
compiles to magic-constant multiplication on modern compilers (also CT).

**Empirical verification** with [ct_harness](../ct_harness):

| Test | Class A | Class B | Iterations | Welch t | Verdict |
|---|---|---|---|---|---|
| `KEM.Decapsulate` | matching SK (success path) | other SK (rejection path) | 20 000 | -1.27 | PASS |

The mean of 322 µs differed by 0.99 % between classes; the FO transform
correctly executes both paths in lockstep with `Verify.CMOV` selecting the
output.

**Cache-CT (data-dependent memory access)**: audited statically and
verified empirically. See [CT_AUDIT.md](CT_AUDIT.md).

| Cache level | Class A (matching SK) | Class B (other SK) | Δ |
|---|---|---|---|
| D1 misses | 2 132 115 | 2 157 015 | +24 900 (1.17 %) |
| LLd misses | 18 543 | 18 543 | **0** |

5 000 iterations of `KEM.Decapsulate` per class under cachegrind 3.22.
**Last-level-data cache misses byte-identical** — the FO transform's
success and rejection paths execute through the same memory access
pattern at the cache level. The 1.17 % L1 D-cache delta over 2.1 M
misses is fast-path set-conflict variance only, with no observable
LL effect. **Verdict**: cache-CT.

**Out of scope:**
- Hardware side channels (power, EM).
- Cross-platform reproducibility of the empirical timing result.
  Re-run `bin/ct_ml_kem_decap` on your target after every toolchain
  change.

#### FIPS 140-3

Not FIPS 140-3 validated. CAVP / CMVP validation paths available under
separate engagement.

#### FIPS 203 §7.2 input validation

`ML_KEM.KEM.Valid_Encaps_Key (PK)` performs the modulus check required
by FIPS 203 §7.2 — every decoded polynomial coefficient must be < Q.
The check runs in constant time over the whole PK byte string (no
early exit on the first invalid coefficient), so timing observation
of the validator does not leak position information about a malformed
key. Wrong-length inputs are also rejected.

`Encapsulate` itself does not invoke `Valid_Encaps_Key` automatically
(this preserves the original wire-compatible API). Callers receiving
a public key from an untrusted source should use
`ML_KEM.KEM.Encapsulate_Checked` instead — the FIPS-conforming
variant that calls `Valid_Encaps_Key` first and, on failure, zeros
both ciphertext and shared-secret outputs and returns `Ok = False`
without touching the IndCPA path. The split lets safety-critical
callers pick the variant that matches their threat model without
breaking existing code.

A malformed public key that decodes to coefficient values ≥ q will
still produce *some* ciphertext when fed directly to `Encapsulate`
(the IndCPA arithmetic remains type-safe), but the ciphertext is not
guaranteed to behave correctly under decapsulation; treat it as
undefined.

#### GenMatrix 256-block budget

`IndCPA.GenMatrix` uses a budget of 256 SHAKE128 squeeze blocks per
matrix entry where FIPS 203 Algorithm 6 specifies a `while j < 256`
loop with no explicit bound.  At SHAKE128 rate = 168 bytes per block,
256 blocks generate 14 336 candidate 12-bit values, of which the
expected number passing the `< Q` rejection check is ~11 663.  The
probability that fewer than 256 of them survive (Chernoff tail of
Binomial(14336, 0.813) below 256) is below 2^-1024, well outside any
realistic adversary's success budget.

The bound exists so that SPARK can prove termination and downstream
users can compute a static stack budget; the alternative — a true
unbounded loop with infinite-state termination reasoning — would cost
both.  An adversarially chosen public seed that triggers the rare
truncation case would produce a partially zeroed polynomial and a
keypair that simply fails round-trip; it cannot leak the secret key
or the established shared secret.

#### Implicit rejection randomness

`Decapsulate` performs implicit rejection (returns a pseudorandom value
on ciphertext decryption failure, rather than aborting). The pseudorandom
value is derived from the secret-key field `Z`. This is the FIPS 203
default and provides IND-CCA2 security; applications should not branch on
the decapsulation outcome in a way that distinguishes successful vs.
failed decryption.

### Runtime hardening

The library GPR enables:
- `-gnato` — overflow checks (defense-in-depth beyond SPARK proofs)
- `-gnatVa` — validity checks on all parameters
- `-fstack-usage` — emits per-function `.su` files alongside object
  files; cost-free at runtime, useful for sizing stacks in
  resource-constrained deployments.

Internal SPARK contracts (`Pre`/`Post`) are **proof-only** and not checked
at runtime. Enable `-gnata` in your application's GPR to enforce public
API preconditions at runtime.

### Stack budget

Per-function frame sizes (GNAT 15.2, x86_64 macOS, `-O2`), top entries:

| Function           | Frame  | Notes                                  |
|--------------------|-------:|----------------------------------------|
| IndCPA.Encrypt     | 13 888 | dominant frame: matrix + polyvecs      |
| IndCPA.KeyGen      |  9 696 |                                        |
| IndCPA.Decrypt     |  4 720 |                                        |
| KEM.Decapsulate    |  3 712 | calls IndCPA.Decrypt (4 720)           |
| KEM.KeyGen         |  1 296 | calls IndCPA.KeyGen (9 696)            |
| PolyVec.Basemul_Acc|    560 |                                        |
| GenMatrix          |    528 |                                        |
| KEM.Encapsulate    |    208 | calls IndCPA.Encrypt (13 888)          |

Worst-case call chains (hand-traced):

- `KEM.Encapsulate` → `IndCPA.Encrypt` → `PolyVec.Basemul_Acc`
  ≈ **15 KB**.
- `KEM.KeyGen` → `IndCPA.KeyGen` → `GenMatrix` ≈ **12 KB**.
- `KEM.Decapsulate` → `IndCPA.Decrypt` then `IndCPA.Encrypt`
  (sequentially, not nested) ≈ **15 KB** peak.

Run `scripts/stack_summary.sh .` after `alr build` to regenerate the
table on your target. For deployments where the worst-case stack budget
must be lower, the IndCPA frames are dominated by `Poly_Vector` and
`Poly_Matrix` arrays — moving those to heap or a static work area
(at the cost of allocator dependence) can drop the worst-case to ~3 KB.

## Known limitations

- **No domain separation between use cases.** Higher-level protocols
  (TLS 1.3 hybrid, CSfC) typically combine ML-KEM with a classical KEM
  via concatenation; that combination is the protocol's responsibility,
  not this library's.
- **No NIST ACVP test harness.** The library is tested against KAT-style
  vectors and an internal round-trip suite. CAVP submission requires an
  ACVP server interface; not implemented.
- **No `pragma Inspection_Point` barriers.** See constant-time note above.
