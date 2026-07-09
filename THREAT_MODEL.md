# Citadel V3 — Threat Model

**Version:** citadel-v3-alpha-001  
**Status:** Unaudited alpha. Claims here are design-level, not independently verified.

---

## What this system is

A hybrid post-quantum encryption envelope and key management system. It wraps
plaintext using X25519 + ML-KEM-768 (hybrid KEM), AES-256-GCM (AEAD), and
HKDF-SHA256 (KDF), enforces a 4-level key hierarchy, and provides stateful
replay protection.

---

## What Citadel V3 protects against

### Confirmed by tests (178 passing, 0 failures)

| Threat | Protection | Test |
|--------|-----------|------|
| Replay attack (same ciphertext submitted twice) | Stateful nonce tracking — second attempt rejected | `p066_fail_closed_replay_store_denies_decrypt` |
| Replay attack across server restart | FileReplayStore persists nonces to disk | Live test confirmed |
| Ciphertext tampering (any bit flip) | AES-256-GCM authentication tag | `bit_flip_anywhere_fails`, `every_byte_is_authenticated` |
| Wrong key | KEM decapsulation fails — implicit rejection | `wrong_key_fails`, `mlkem768_wrong_key_produces_different_secret` |
| Wrong AAD (authentication context) | AEAD tag verification fails | `wrong_aad_fails` |
| Wrong context string | HKDF domain separation — different derived key | `context_isolation` |
| Truncated/malformed ciphertext | Structured parsing fails safely | `truncated_fails`, `p160_truncated_blob_must_fail_not_panic` |
| Random garbage as ciphertext | Does not panic, returns error | `decryption_never_panics_on_garbage` |
| Key hierarchy violation (revoked parent) | Hierarchy check blocks child key access | `revoked_kek_blocks_dek_decrypt` |
| Corrupted ciphertext poisoning replay slot | Replay slot only marked after successful decrypt | `p089_corrupted_ciphertext_does_not_poison_replay_slot` |
| Malformed API input | Structured rejection before crypto operations | `it_malformed_json_returns_4xx` |
| Auth brute force / key spam | Rate limiter (20 rps default, configurable) | `it_rate_limit_activates_under_spam` |
| Auth failures leaving no evidence | Written to tamper-evident JSONL audit chain | `AuthFailed` in AuditAction |
| Replay store deleted mid-run | Store recreates safely, in-memory state preserved | `file_store_recreates_after_deletion` |
| Quantum attack on key exchange | ML-KEM-768 (NIST FIPS 203) — security holds even if X25519 broken | Hybrid KEM design |

---

## What Citadel V3 does NOT yet claim

These are explicit non-goals or unverified properties:

### Side-channel resistance
Constant-time behavior is inherited from dependencies (`x25519-dalek`, `ml-kem`,
`aes-gcm`, `subtle`). These crates aim for constant-time operation, but Citadel
has not independently verified constant-time behavior across all code paths or
platforms. Cache-timing, branch-timing, and power analysis attacks are outside
this threat model.

### Formal verification
No part of Citadel V3 has been formally verified. Correctness claims rest on
tests and code review, not mathematical proof.

### Audit certification
The system has not been independently audited. The ml-kem 0.2.2 dependency
carries an "experimental" designation. No third party has reviewed the
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

### Out of scope

- Attacker with physical access to the server (CITADEL_MASTER_KEY in memory)
- Attacker who has compromised CITADEL_MASTER_KEY (system is broken by definition)
- Side-channel attacker (timing, cache, power)
- Attacker with root access to the deployment host

---

## Crypto primitive status

| Primitive | Algorithm | Standard | Crate | Status |
|-----------|-----------|----------|-------|--------|
| KEM (classical) | X25519 ECDH | RFC 7748 | x25519-dalek 2.x | Stable |
| KEM (post-quantum) | ML-KEM-768 | NIST FIPS 203 | ml-kem 0.2.2 | Experimental |
| AEAD | AES-256-GCM | NIST SP 800-38D | aes-gcm 0.10 | Stable |
| KDF | HKDF-SHA256 | RFC 5869 | hkdf 0.12 | Stable |
| MAC (API auth) | HMAC-SHA256 | RFC 2104 | hmac 0.12 | Stable |

**Hybrid security guarantee:** An attacker must break BOTH X25519 AND ML-KEM-768
to recover the shared secret. If either primitive is compromised (by cryptanalysis
or implementation flaw), the other still protects the plaintext.

---

## Intended use (alpha stage)

Citadel V3 alpha is appropriate for:
- Proof-of-concept hybrid PQC encryption demonstrations
- Internal tooling where the threat model above is acceptable
- Backing a PQC migration assessment/reporting pipeline
- Development and testing of systems that will use PQC encryption

Not appropriate for:
- Production deployment of sensitive data without independent review
- Regulated environments (FIPS, PCI-DSS, HIPAA) without audit
- Public-facing services handling private keys

---

*See [SECURITY_GUARANTEES.md](SECURITY_GUARANTEES.md) for detailed per-feature claims.*  
*See [ALPHA_FREEZE.md](ALPHA_FREEZE.md) for version freeze conditions.*
