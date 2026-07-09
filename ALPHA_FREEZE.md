# Citadel V3 — Alpha Freeze

**Tag:** `citadel-v3-alpha-001`  
**Date:** 2026-05-01  
**Status:** Internal alpha — do not deploy to production

---

## Locked Claim

> Hybrid post-quantum encryption + signing + key management using X25519 + ML-KEM-768
> (NIST FIPS 203) for encryption and ML-DSA-65 (NIST FIPS 204) for post-quantum digital
> signatures, with AES-256-GCM, HKDF-SHA256, stateful replay protection (for decryption),
> enforced 4-level key hierarchy (Root → Domain → KEK → DEK/SigningKey), and the
> Citadel Native Assertion (CNA) format — a post-quantum JWT replacement with ML-DSA-65
> signed public claims and optional ML-KEM-768 encrypted sealed claims.

---

## What this version proves

- Correct hybrid PQC crypto (X25519 + ML-KEM-768) with known-answer tests
- ML-DSA-65 (NIST FIPS 204) signing — keygen, sign, verify on raw bytes (citadel-signer)
- Signing keys managed in the Citadel hierarchy (Kek → SigningKey, seed wrapped by KEK)
- Citadel Native Assertion (CNA) format — signed assertions with expiry and assertion_id
- Replay protection survives server restart (FileReplayStore, file-backed)
- 4-level key hierarchy enforced (Root → Domain → KEK → DEK/SigningKey)
- Fail-closed behavior: errors deny operations, not silently permit them
- API endpoints for sign, verify, and verifying-key distribution
- API key management with tamper-evident audit chain
- FFI bindings (C, Python, Java) with ownership documentation

## MSRV

- citadel-envelope, citadel-core, citadel-api, citadel-cli, citadel-ffi: Rust 1.74+
- citadel-keystore, citadel-signer: **Rust 1.85+** (required by ml-dsa 0.1.0-rc.8)

## What this version does NOT claim

- Production-grade deployment
- Independent security audit
- FIPS certification
- HSM-grade key protection
- Side-channel resistance (inherited from dependencies, not independently verified)
- Formal verification
- Multi-node replay safety (requires Redis backend — documented)

## Next gates before production

1. External security review (at minimum one competent Rust/crypto reviewer)
2. ml-kem crate reaches stable/audited designation (currently "experimental")
3. NIST ACVP vector validation for ML-KEM-768
4. Production smoke test under adversarial conditions
5. Penetration test against live API

---

**Do not remove this file without completing the above gates.**
