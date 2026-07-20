# ML-KEM-768 Production Provider Bakeoff (Frozen Before Migration)

**Frozen:** 2026-07-15  
**Packet:** AQCMF 006  
**Scope:** the ML-KEM component of Citadel's hybrid X25519 + ML-KEM-768 v1 provider  
**Claim boundary:** local algorithm-conformance and engineering evidence only; not FIPS 140 validation or independent review

## Candidates

| Candidate | Exact version | Why included |
|---|---:|---|
| RustCrypto `ml-kem` | 0.3.2 | Current pure-Rust FIPS 203 implementation; deterministic hazmat hook, key validation, and zeroization feature |
| AWS `aws-lc-rs` | 1.17.1 | Actively maintained implementation with a stronger organizational assurance story and an ML-KEM API |
| Cryspen `libcrux-ml-kem` | 0.0.9 | Existing independent comparison implementation with formal-verification evidence and deterministic APIs |

The abandoned `pqcrypto-mlkem 0.1.1` production chain is the control, not an eligible winner.

## Hard gates

A candidate is ineligible if any applicable gate fails:

1. The exact production version is not identified and locked.
2. Its production dependency chain has an unmaintained/abandoned RustSec advisory.
3. Final FIPS 203 ML-KEM-768 key generation, encapsulation, and decapsulation vectors cannot be exercised through the same implementation selected for release.
4. It fails any checked-in final-standard vector, including implicit-rejection decapsulation cases.
5. It fails 10,000 randomized release-provider round trips, wrong-key checks, malformed-length checks, or public-key validation checks.
6. It breaks v1 key/ciphertext sizes or the retained v1 decryption corpus.
7. The full locked Ubuntu judge fails, or two unchanged-source judge runs disagree.

## Weighted score (only after hard gates)

| Criterion | Weight | Measurement |
|---|---:|---|
| Direct conformance | 30 | exact-vector coverage through selected implementation |
| Maintenance/supply chain | 20 | current release activity, advisory status, dependency removal |
| Assurance | 20 | audit, formal verification, constant-time evidence, transparent limitations |
| Citadel integration | 15 | v1 compatibility, minimal unsafe/FFI surface, reproducible Ubuntu build |
| Key handling | 10 | input validation, implicit rejection, zeroization, secret serialization behavior |
| Performance | 5 | release-mode functional benchmark; no security choice from speed alone |

Ties are resolved in favor of stronger independent assurance, then the smaller production dependency/FFI surface.

## Pre-migration evidence

- Before migration, `pqcrypto-mlkem 0.1.1` was in production and pulled the unmaintained PQClean chain (RUSTSEC-2026-0161, -0162, -0163).
- Existing 60-vector ACVP coverage runs through `libcrux-ml-kem`, not the production provider. That is useful differential evidence but does not satisfy direct production-provider conformance.
- `aws-lc-rs 1.17.1` exposes ML-KEM-768 key generation, serialization, encapsulation, and decapsulation. Its public API does not provide the complete deterministic keygen/encapsulation hook needed by this packet's direct full-vector gate.
- `libcrux-ml-kem 0.0.9` passes the existing vectors and has formal-verification evidence, but it is not the current upstream release and earlier Citadel timing experiments did not justify restoring it as production.
- RustCrypto `ml-kem 0.3.2` was released 2026-07-12, validates encoded keys, provides an explicit testing-only deterministic encapsulation feature, and provides optional zeroization. Its maintainers explicitly state that the crate has never been independently audited.

## Provisional selection

RustCrypto `ml-kem 0.3.2` is the provisional winner because it is the only candidate that combines a current maintained release, direct deterministic final-vector access, a pure-Rust production graph, validation, and zeroization while retaining an API for the v1 expanded key form.

This selection becomes final only if every hard gate passes. The lack of independent audit remains a release limitation even if all local gates pass.

## Post-freeze timing screen

After the three preregistered candidates reproduced the repository's known
key-value-dependent x86-64 timing behavior, `fips203 0.4.3` was added as a
screening-only fourth implementation. It was not allowed to change the frozen
criteria or displace a preregistered candidate without clearing every gate.

- Its same-key dudect control passed at `|t| = 2.79`.
- Four independent key-A/key-B runs produced `|t| = 6.88`, `4.35`, `23.95`,
  and `83.70`; it therefore did not produce a stable timing pass.
- Its latest crate release is experimental, has no independent audit cited by
  upstream, and is older than the selected RustCrypto release.

The screen does not change the selection. Across all tested implementations,
the key-value diagnostic remains a documented platform/provider limitation;
it is not evidence that one candidate has a conventional secret-dependent
branch. Citadel therefore makes no constant-time-validation or side-channel-
hardening claim. Attacker-controlled input classes and the service response
boundary remain the release-relevant timing checks described in `TIMING.md`.

## Primary references

- NIST FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- RustCrypto `ml-kem 0.3.2`: https://docs.rs/ml-kem/0.3.2/ml_kem/
- AWS-LC-RS ML-KEM API: https://docs.rs/aws-lc-rs/1.17.1/aws_lc_rs/kem/
- Cryspen Rust libcrux: https://github.com/pq-code-package/rust-libcrux
