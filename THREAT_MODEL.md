# Citadel V3 — Threat Model

**Version:** citadel-v3-0.2.0
**Status:** Unaudited. Claims here are design-level and test-validated, not independently verified.

---

## What this system is

A hybrid post-quantum encryption envelope and key management system. It wraps
plaintext using a hybrid KEM, AES-256-GCM (AEAD), and HKDF-SHA256 (KDF),
enforces a 4-level key hierarchy, and provides stateful replay protection.

Two wire suites are supported, selected by the suite byte and additively staged
(the second never alters the first's bytes):

- **`0xA3` (default, frozen):** X25519 + ML-KEM-768 — NIST PQ category 3.
- **`0xA4` (CNSA-aligned):** P-384 + ML-KEM-1024 — NIST PQ category 5. Same
  envelope codec, KDF, AEAD, and header; only the KEM provider varies. Added under
  packets 033/034 with its own KATs, formal proof, and timing characterization
  (see the corresponding sections below).

---

## What Citadel V3 protects against

### Confirmed by tests (328+ passing, 0 failures)

| Threat | Protection | Test |
|--------|-----------|------|
| Replay attack (same ciphertext submitted twice) | Stateful nonce tracking — second attempt rejected | `p066_fail_closed_replay_store_denies_decrypt` |
| Replay attack across server restart | FileReplayStore persists nonces to disk | Live test confirmed |
| Ciphertext tampering (any bit flip) | AES-256-GCM authentication tag | `bit_flip_anywhere_fails`, `every_byte_is_authenticated` |
| Wrong key | KEM decapsulation fails — implicit rejection | `wrong_key_fails`, `wrong_key_rejected` |
| Wrong AAD (authentication context) | AEAD tag verification fails | `wrong_aad_fails`, `aad_binding_enforced` |
| Wrong context string | HKDF domain separation — different derived key | `context_isolation`, `context_binding_enforced` |
| Truncated/malformed ciphertext | Structured parsing fails safely | `truncated_fails`, `truncated_ciphertext_rejected` |
| Random garbage as ciphertext | Does not panic, returns error | `decryption_never_panics_on_garbage` |
| Key hierarchy violation (revoked parent) | Hierarchy check blocks child key access | `revoked_kek_blocks_dek_decrypt` |
| Corrupted ciphertext poisoning replay slot | Replay slot only marked after successful decrypt | `p089_corrupted_ciphertext_does_not_poison_replay_slot` |
| Malformed API input | Structured rejection before crypto operations | `it_malformed_json_returns_4xx` |
| Auth brute force / key spam | Rate limiter (20 rps default, configurable) | `it_rate_limit_activates_under_spam` |
| Auth failures leaving no evidence | Written to tamper-evident JSONL audit chain | `AuthFailed` in AuditAction |
| Replay store deleted mid-run | Store recreates safely, in-memory state preserved | `file_store_recreates_after_deletion` |
| Quantum attack on key exchange | ML-KEM-768 (`0xA3`) / ML-KEM-1024 (`0xA4`), NIST FIPS 203 — security holds even if the classical arm is broken | Hybrid KEM design; combiner secrecy machine-checked (see Formal verification below) |
| Attacker-varied ciphertext timing | dudect passes all attacker-controlled classes (both suites; `0xA4` P-384 remote/ciphertext class `|t|` ≤ 2.9) | `timing_sidechannel` bench suite |
| ACVP vector correctness | `0xA3`: 60/60 NIST vectors byte-identical through the RustCrypto production provider, plus a libcrux differential. `0xA4`: NIST ACVP ML-KEM-1024 + Wycheproof P-384 ECDH KATs, provenance-verified | `nist_acvp_kat`, `acvp_libcrux_kat`, `acvp_mlkem1024`, `wycheproof_p384_ecdh` |
| Cross-suite / downgrade confusion (`0xA3`↔`0xA4`) | Exact total-length + `kem_ct_len` re-check rejects a bare flip before AEAD; suite byte + recipient-key hash bound into KDF+AAD reject a length-consistent forgery | `wire_v2::p3c_cross_suite_tests`, `v2_vector_a4` |
| Corrupted classical ephemeral (X25519 / P-384) | Authentication fails; `0xA4` also SEC1-validates the P-384 point (on-curve, not-identity) before use | `corrupted_x25519_ephemeral_rejected`, `kem_p384` validation tests |
| Corrupted AEAD tag | Authentication fails | `corrupted_aead_tag_rejected` |

---

## What Citadel V3 does NOT yet claim

These are explicit non-goals or unverified properties:

### Key-material timing independence

ML-KEM-768 decapsulation shows a small key-value-dependent timing distribution
on the tested x86-64 host. The isolated final-private-byte class crossed the
screen in both the RustCrypto release provider and libcrux while random-label
controls passed; an independent monotonic-clock sample corroborated a tiny
distribution effect. This is retained as a local/co-resident side-channel
limitation, not attributed to a proved root cause. Fixed-server-key,
attacker-controlled ciphertext, tag, and AAD classes pass the frozen dudect
screen. See the Packet 012 receipt and `TIMING.md` for scope and wording.

For the `0xA4` P-384 arm (packet 036): the shipped ECDH path is designed and
implemented constant-time (`p384` 0.14.0 uses `subtle` + constant-time formulas; the
shared secret is computed via the constant-time `Mul`, no `_vartime` on the path —
source-verified). The vendor does not assess generated-assembly constant-timeness, and
our well-powered dudect of the key-material class is inconclusive on the available noisy
box (straddles the noise floor; the ML-KEM positive control is detected decisively). Because
dudect is one-sided (it can reject constant-time, never prove it), the claim's ceiling is
the same independent-audit gate as the ML-KEM provider, not a timing run. The attacker-
controlled / remote P-384 class passes (`|t|` ≤ 2.9).

### Formal verification (scope-limited — see below)
The **hybrid-combiner secrecy theorem** is machine-checked in CryptoVerif 2.12 for
**both suites and both arms** (`gauntlet/tier12_combiner_proof/`): if the surviving
component KEM is IND-CCA2, the KDF-derived key is secret even if the other component
is fully broken. `0xA3`: X25519 and ML-KEM-768 arms (packets 016/017), verified at the
full-faithful CCA level with an explicit SHA3-256 collision term. `0xA4`: P-384 and
ML-KEM-1024 arms (packet 033 P5), both `RESULT Proved secrecy of K`, exit 0, no `admit`.
An independent falsification audit (packet 019-R) ran 8+ probes and found no cryptographic
façade.

**This is a proof of the abstract combiner (random-oracle KDF model), not of the Rust
implementation.** The model↔code gap is covered by the other gauntlet tiers (ACVP/Wycheproof
KATs, proptest, fuzz, Miri, ctgrind), not by these proofs. No other component (key hierarchy,
replay store, API layer) is formally verified; those rest on tests, vectors, and code review.

### Audit certification
The system has not been independently audited. No third party has reviewed the
implementation for security flaws.

### HSM-grade key protection
Keys at rest are protected by AES-256-GCM wrapping under CITADEL_MASTER_KEY.
CITADEL_MASTER_KEY is loaded from an environment variable — not from an HSM,
TPM, or hardware security boundary. Key material exists in process memory
during operations.

### Multi-node replay safety (without Redis)
The FileReplayStore is safe for single-node deployments. Multiple API instances
sharing a file replay store are NOT supported — race conditions can allow
replay. Multi-node replay safety requires the Redis backend
(`CITADEL_REPLAY_STORE=redis`).

### Network-level attack resistance
Citadel is not a transport security protocol. It does not replace TLS/HPKE
for interactive sessions. MITM, downgrade, and traffic analysis attacks at
the network layer are out of scope.

### FIPS validation
The primitives used (ML-KEM-768, AES-256-GCM, HKDF-SHA256) follow NIST
standards. Citadel itself has not undergone FIPS 140-3 validation.

---

## Attacker model

### In scope

- Attacker can observe all ciphertexts in transit and at rest
- Attacker can modify ciphertexts and feed them to the decryptor
- Attacker can attempt replay of previously captured ciphertexts
- Attacker has access to a quantum computer (ML-KEM-768 provides resistance)
- Attacker can send malformed, truncated, or garbage inputs to the API
- Attacker can attempt API key brute force
- Attacker can vary ciphertext content per query (timing classes validated)

### Out of scope

- Attacker with physical access to the server (CITADEL_MASTER_KEY in memory)
- Attacker who has compromised CITADEL_MASTER_KEY (system is broken by definition)
- Local co-resident side-channel attacker (timing, cache, power) unless dedicated tenancy is used
- Attacker with root access to the deployment host

---

## Crypto primitive status

| Primitive | Algorithm | Standard | Crate | Version | Status |
|-----------|-----------|----------|-------|---------|--------|
| KEM classical (`0xA3`) | X25519 ECDH | RFC 7748 | x25519-dalek | 2.x | Stable |
| KEM classical (`0xA4`) | P-384 ECDH | NIST SP 800-186 / SEC1 | p384 | =0.14.0 | RustCrypto pure Rust; `subtle` + constant-time formulas, generated assembly not vendor-assessed; not independently audited |
| KEM post-quantum (`0xA3`) | ML-KEM-768 | NIST FIPS 203 | ml-kem | =0.3.2 | RustCrypto pure Rust; not independently audited |
| KEM post-quantum (`0xA4`) | ML-KEM-1024 | NIST FIPS 203 | ml-kem | =0.3.2 | RustCrypto pure Rust; not independently audited |
| AEAD | AES-256-GCM | NIST SP 800-38D | aes-gcm | 0.10 | Stable |
| KDF | HKDF-SHA256 | RFC 5869 | hkdf | 0.12 | Stable |
| MAC (API auth) | HMAC-SHA256 | RFC 2104 | hmac | 0.12 | Stable |
| Signing (optional) | ML-DSA-65 | NIST FIPS 204 | ml-dsa | =0.1.0-rc.9 | RustCrypto (pure Rust) |

**Hybrid security guarantee:** An attacker must break BOTH the classical arm (X25519
for `0xA3`, P-384 for `0xA4`) AND the post-quantum arm (ML-KEM-768 / ML-KEM-1024) to
recover the shared secret. If either primitive is compromised (by cryptanalysis or
implementation flaw), the other still protects the plaintext. This is the property
machine-checked by the combiner proofs (see Formal verification).

---

## Service boundary protections

| Protection | Implementation |
|-----------|---------------|
| Opaque errors | All decrypt failures return identical error type and HTTP status |
| Response floor | Deadline-style minimum response time prevents timing cliff |
| Rate limiting | Three-tier (per-key, per-domain, global) with configurable thresholds |
| No raw KEM endpoint | Decapsulation is never exposed independently of the authenticated envelope |
| Audit logging | All auth failures and key lifecycle events logged to tamper-evident JSONL |

---

## Intended use

Citadel V3 is appropriate for:
- Hybrid PQC encryption for data at rest and in transit (within TLS)
- Key management with hierarchy, rotation, and lifecycle enforcement
- Backing a PQC migration assessment/reporting pipeline
- Internal tooling where the threat model above is acceptable

Not appropriate for (without further work):
- Regulated environments (FIPS, PCI-DSS, HIPAA) without audit
- Deployments requiring local co-resident side-channel resistance
- Multi-node deployments without Redis replay backend

---

*See [TIMING.md](../../TIMING.md) for the complete timing validation model.*
*See [SECURITY.md](SECURITY.md) for the security policy and disclosure process.*
*See [PROVIDER_DECISION_LOG.md](../../PROVIDER_DECISION_LOG.md) for ML-KEM provider history.*
